"""Recognize modem patches from their generated Z180 code, not archive history."""
import re

from .millennium_callin_standalone import DATA_TIMEOUT


def addr(value):
    return value.to_bytes(2, 'little')


def inbound_mode(rom, board, wrappers):
    if len(wrappers) != 1:
        return None
    wrapper = wrappers[0]
    # Both the common and banked ring handlers write CR1 and then CR0
    # through the same veneer, before setting the wrapper's answer flag.
    setup = (rb'\x2e\x01\x1e([\x08\x98])\xcd(..)\x2e\x00\x1e([\x1a\x3a\xba])\xcd\2'
             rb'\x3e\xa5\x32' + re.escape(wrapper['flag']))
    patterns = {(m[1][0], m[3][0], wrapper['mode'][0]) for m in re.finditer(setup, rom, re.S)}
    if len(patterns) != 1:
        return None
    return {
        (0x08, 0x1a, 0x1a): 'bell212a',
        **({(0x08, 0x3a, 0x3a): 'bell103'} if board == 'mtr1' else {
            (0x08, 0xba, 0xba): 'v21',
            (0x98, 0x1a, 0x1a): 'v22',
            (0x98, 0x1a, 0x5a): 'v22bis',
        }),
    }.get(patterns.pop())


# These CALLs replace the native CR0 transmit and CR1 mark writes. For
# outbound V.22 the mark write is the only hook (stock rate and CR0).
OUTBOUND_HOOK = re.compile(rb'\x1e(?P<value>[\x1b\x88])\x2e(?P<reg>[\x00\x01])\xcd(?P<entry>..)', re.S)
COMPACT_ENTRY = re.compile(rb'\xf5\xcd(..)\x30\x02\x1e([\x3b\xbb\x98])\xf1\xc3..', re.S)
QAM_ENTRY = re.compile(
    rb'\xf5\xcd(..)\xd2..\x3a..\xfe\x0b\xd2..\xf1\x1e\x1b\xc3(..)'
    rb'\xf1\xc3..\xf5\xcd\1\xd2..\xf1\x1e\x5b\xc3\2', re.S)
NATIVE_TTY_GUARD = re.compile(rb'\x3a(..)\xb7\x28\x02([\x37\x00])\xc9', re.S)
BANKED_TTY_GUARD = re.compile(
    rb'\x3a\x8c\xff\xfe\xa5\x20\x12\x3a\x8d\xff\xfe\x5a\x20\x0b'
    rb'\x3a\x8e\xff\xd6\x02\xfe\x03\x30\x02([\x37\xb7])\xc9')
NCC_GUARD = re.compile(rb'\x3a(..)\xd6\x06\xfe\x08\xc9', re.S)


def outbound_modes(rom, board, mappings, wrappers, tty_offset, tty_kind):
    if len(mappings) != 1:
        return {}
    mapping = mappings[0]
    ba, ca = (mapping & 15) << 12, (mapping >> 4) << 12
    tty_flags = set()
    if tty_kind == 'native':
        route = rb'\x3a(..)\xb7\x28\x06\xe5\xcd' + re.escape(addr(tty_offset)) + rb'\xe1\xc9'
        tty_flags = {m[1] for m in re.finditer(route, rom, re.S)}
    wrapper = wrappers[0] if len(wrappers) == 1 else None
    control = rom[:0xc0000] if board == 'mtr2' else rom
    data_states = {m[1] for m in DATA_TIMEOUT.finditer(control)}
    found = {}
    for hook in OUTBOUND_HOOK.finditer(control):
        kind = (hook['value'][0], hook['reg'][0])
        if kind not in ((0x1b, 0), (0x88, 1)):
            continue
        entry = int.from_bytes(hook['entry'], 'little')
        if entry < ba:
            deltas = (0,)
        elif entry < ca and board == 'mtr1':
            page = (hook.start() - ba) & ~0xfff
            deltas = range(max(0, page - (ca - ba) + 0x1000), page + 1, 0x1000)
        else:
            continue
        for delta in deltas:
            at = delta + entry
            limit = delta + ca if entry >= ba else ba
            compact = COMPACT_ENTRY.match(control, at, limit)
            qam = QAM_ENTRY.match(control, at, limit) if not compact and board == 'mtr2' else None
            match = compact or qam
            if match is None:
                continue
            if qam:
                mode = 'v22bis' if kind == (0x1b, 0) else None
            else:
                mode = {
                    ('mtr1', (0x1b, 0), 0x3b): 'bell103',
                    ('mtr2', (0x1b, 0), 0xbb): 'v21',
                    ('mtr2', (0x88, 1), 0x98): 'v22',
                }.get((board, kind, compact[2][0]))
            # The V.22bis mark helper follows the QAM code and isn't a
            # standalone V.22 patch. Its selector is not adjacent to it.
            if mode is None:
                continue
            selector = delta + int.from_bytes(match[1], 'little')
            if not max(delta, at - 39) <= selector < at:
                continue
            cursor = selector
            if wrapper and control[cursor:cursor + 6] == b'\x3a' + wrapper['flag'] + b'\xfe\xa5\xc8':
                cursor += 6
            targets = []
            if tty_kind == 'cnb_banked':
                guard = BANKED_TTY_GUARD.match(control, cursor, at)
                if guard is None:
                    continue
                if guard[1] == b'\x37':
                    targets.append('outbound_tty')
                cursor = guard.end()
            elif tty_kind == 'native':
                guard = NATIVE_TTY_GUARD.match(control, cursor, at)
                if guard is None or tty_flags != {guard[1]}:
                    continue
                if guard[2] == b'\x37':
                    targets.append('outbound_tty')
                cursor = guard.end()
            guard = NCC_GUARD.fullmatch(control, cursor, at)
            if guard and guard[1] in data_states:
                targets.append('outbound_ncc')
            elif control[cursor:at] != b'\xb7\xc9':
                continue
            for target in targets:
                found.setdefault(target, set()).add((mode, selector))
    return {target: next(iter(matches))[0] for target, matches in found.items() if len(matches) == 1}
