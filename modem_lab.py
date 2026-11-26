"""Build lab-only modem register probes; this is not a negotiated-link test."""
import argparse
from hashlib import sha256
from pathlib import Path
import re

from .audit_modem_uart import NCC_UART, audit
from .catalog import MTR1_MMU, MTR2_MMU, OUTBOUND_LAB_MODES, ModemModel, ModemTarget, check_modem_model, identify, recognized_call_in
from .emulator import Emulator, require, scenario, verify
from .millennium_callin_standalone import ANSWER_MARK, DATA_TIMEOUT, Assembler, load_rom, patch_discovered, write_patch


# CR0: FSK, answer, transmit enabled. The V.21 bit pattern is common
# to both chips, but without bit 7 this selects Bell 103 or V.23.
ANSWER_CR0 = {('mtr2', 'v21'): 0xba,
              ('mtr1', 'bell103'): 0x3a, ('mtr2', 'v22'): 0x1a,
              ('mtr2', 'v22bis'): 0x1a}


def uart_rates(report, mode):
    setup = report['shared_ncc_tty_uart_300_candidate']
    stock = int(setup['stock_cntlb'], 16)
    if mode == 'v22bis':
        dph = report['dph_uart_signature_matches']
        # IODEFS.INC uses the same clock source and halves the ASCI divisor
        # for 2400. Not every ROM includes the separate data-port dialer.
        faster = {0x0b: 0x0a, 0x0c: 0x0b}.get(stock)
        if faster is None or (dph and (len(dph) != 1 or
                (int(dph[0]['cntlb_1200'], 16), int(dph[0]['cntlb_2400'], 16)) != (stock, faster))):
            raise ValueError('no consistent 2400 bit/s UART divisor')
        return stock, faster, 2400
    if mode == 'v22':
        return stock, stock, 1200
    return stock, int(setup['candidate_cntlb'], 16), 300


def build(chips, mode, *, targets=None):
    if targets is not None:
        targets = [ModemTarget(target) for target in targets]
    if targets and ModemTarget.INBOUND_NCC not in targets:
        return build_outbound_only(chips, mode, set(targets))
    check_modem_model(identify(chips)['terminal_revision'], mode, None)
    default, manifest = patch_discovered(chips)
    board = manifest['layout']['board']
    try:
        cr0 = ANSWER_CR0[board, mode]
    except KeyError:
        raise ValueError(f'{mode} is not supported by the assumed {board} modem') from None
    image = bytearray(default)
    report = audit(default)
    if report['shared_ncc_tty_uart_300_candidate'] is None:
        raise ValueError('unambiguous stock NCC/TTY UART setup not found')
    routine = NCC_UART.search(default)
    uart = routine.start('cntlb') - 1  # LD A,rate; OUT0 (CNTLB1),A
    changes = manifest['patches']

    psk = mode in ('v22', 'v22bis')
    data_cr0 = 0x5a if mode == 'v22bis' else cr0
    # For PSK, start in the low-speed modulation with unscrambled mark.
    # The native data path ends mark transmission. For the V.22bis probe,
    # force QAM there, without claiming S1 exchange or training.
    edits = [('2e001e1acd', 3, cr0), ('20021e1af1c3', 3, data_cr0)]
    if psk:
        edits.append(('2e011e08cd', 3, 0x98))
    for signature, immediate, value in edits:
        anchor = bytes.fromhex(signature)
        hits = []
        for change in changes:
            if change['label'] not in ('fixed_callin_module', 'banked_ring_module'):
                continue
            code = bytes.fromhex(change['replacement'])
            pos = code.find(anchor)
            if pos != -1:
                if code.find(anchor, pos + 1) != -1:
                    raise ValueError('ambiguous generated modem register write')
                hits.append((change, code, pos + immediate))
        if len(hits) != 1:
            raise ValueError('missing or ambiguous generated modem register write')
        change, code, pos = hits[0]
        off = change['offset'] + pos
        image[off] = value
        change['replacement'] = (code[:pos] + bytes([value]) + code[pos + 1:]).hex()

    fixed = next(c for c in changes if c['label'] == 'fixed_callin_module')
    stub_addr = fixed['offset'] + len(fixed['replacement']) // 2
    layout = manifest['layout']
    stock_rate, answer_rate, bps = uart_rates(report, mode)
    # Preserve flags and all other registers; A has the same role as in
    # stock setup. No change to the UART-off branch or TTY/NCC callers.
    stub = (b'\xf5\x3a' + layout['answer_flag'].to_bytes(2, 'little')
            + bytes([0xfe, ANSWER_MARK, 0x20, 7])
            + bytes([0xf1, 0x3e, answer_rate, 0xed, 0x39, 0x03, 0xc9])
            + bytes([0xf1, 0x3e, stock_rate, 0xed, 0x39, 0x03, 0xc9]))
    if board == 'mtr2':
        common_end = (MTR2_MMU[1] & 15) << 12
    else:
        matches = list(MTR1_MMU.finditer(default))
        if len(matches) != 1:
            raise ValueError('ambiguous MTR1 common ROM limit')
        common_end = (matches[0][1][0] & 15) << 12

    def add_patch(at, expected, replacement, label):
        end = at + len(expected)
        if (at < 0 or len(expected) != len(replacement) or default[at:end] != expected
                or any(at < c['offset'] + len(c['expected']) // 2 and c['offset'] < end for c in changes)):
            raise ValueError(f'unsafe or overlapping {label} at {at:#x}')
        image[at:end] = replacement
        changes.append(dict(offset=at, label=label, expected=expected.hex(), replacement=replacement.hex()))

    if stub_addr + len(stub) > common_end:
        raise ValueError('no adjacent common ROM space for guarded UART stub')
    fill = bytes.fromhex(fixed['expected'][:2])
    add_patch(stub_addr, fill * len(stub), stub, 'lab_guarded_uart_stub')
    add_patch(uart, bytes([0x3e, stock_rate, 0xed, 0x39, 0x03]),
              b'\xcd' + stub_addr.to_bytes(2, 'little') + b'\0\0', 'lab_shared_uart_hook')
    image = bytes(image)
    manifest.update(output_sha256=sha256(image).hexdigest(), modem_mode=mode,
                    modem_targets=[ModemTarget.INBOUND_NCC], audio_negotiation_verified=False,
                    scope=('lab PSK register probe; negotiation not implemented' if psk else
                           'lab inbound FSK only; ordinary NCC and TTY retain stock rate'),
                    answer_cr0=cr0, data_cr0=data_cr0, answer_cr1=0x98 if psk else None,
                    uart=dict(setup_rom_offset=routine.start(), answer_bps=bps,
                              answer_cntlb=answer_rate, stock_cntlb=stock_rate))
    if targets and set(targets) != {ModemTarget.INBOUND_NCC}:
        return add_outbound(chips, image, manifest, set(targets), common_end, fill)
    return image, manifest


def add_outbound(chips, inbound, manifest, targets, common_end, fill, *, origin_override=None,
                 placement_bank=None, placement_limit=None):
    """Compose scoped originate register changes onto the input image."""
    mode = manifest['modem_mode']
    if mode not in OUTBOUND_LAB_MODES:
        raise ValueError('no outbound lab settings for this mode')
    stock = b''.join(chips)
    firmware = identify(chips)
    tty = firmware['tty_rx_offset']
    banked_tty = firmware['tty_rx_kind'] == 'cnb_banked'
    tty_flag = None
    if banked_tty:
        tty_flag = '8eff'  # phase byte, validated with the banked receiver signature
    elif tty is not None:
        route = rb'\x3a(..)\xb7\x28\x06\xe5\xcd' + re.escape(tty.to_bytes(2, 'little')) + rb'\xe1\xc9'
        matches = list(re.finditer(route, stock, re.S))
        if len(matches) != 1 or not 0x8000 <= int.from_bytes(matches[0][1], 'little') < 0xffff:
            raise ValueError('could not identify a unique native TTY active flag')
        tty_flag = matches[0][1].hex()
    if ModemTarget.OUTBOUND_TTY in targets and tty_flag is None:
        raise ValueError('outbound TTY requires a recognized TTY receiver and routing hook')
    want_ncc = ModemTarget.OUTBOUND_NCC in targets
    want_tty = ModemTarget.OUTBOUND_TTY in targets
    layout, changes = manifest['layout'], manifest['patches']
    uart_stub = next((c for c in changes if c['label'] == 'lab_guarded_uart_stub'), None)
    uart_hook = next(c for c in changes if c['label'] == 'lab_shared_uart_hook')
    tx_hooks = [c for c in changes if c['label'] == 'preserve_answer_modem_mode']
    if not tx_hooks or len({c['replacement'] for c in tx_hooks}) != 1:
        raise ValueError('no unambiguous native transmit hooks')
    psk = mode in ('v22', 'v22bis')
    writer_call = b'\xcd' + layout['write'].to_bytes(2, 'little')
    def preceding_cr1(hook, value):
        off = hook['offset']
        return stock[off-11:off-4] == bytes([0x1e, value, 0x2e, 1]) + writer_call

    mark_sites = [c['offset'] - 7 for c in tx_hooks if preceding_cr1(c, 0x88)]
    data_sites = [c['offset'] for c in tx_hooks if preceding_cr1(c, 0x08)]
    if psk and (len(mark_sites) != 1 or len(data_sites) != 1):
        raise ValueError('unambiguous native DPSK mark/data transition not found')
    origin = (uart_stub['offset'] + len(bytes.fromhex(uart_stub['replacement']))
              if uart_stub else layout['outbound_origin'])
    if origin_override is not None:
        origin = origin_override
    def addr(value):
        return value.to_bytes(2, 'little').hex()

    # Carry means the originate profile applies. CP on an unsigned range
    # checks both bounds, and the inbound path keeps its original wrapper.
    bank_delta = (placement_bank or 0) << 12
    asm = Assembler(origin - bank_delta)
    asm.label('selected')
    if 'answer_flag' in layout:
        asm.emit(f'3a {addr(layout["answer_flag"])} fe {ANSWER_MARK:02x} c8')
    if banked_tty:
        # CNB phase 2 starts the outgoing TTY call; phases 3/4 own the
        # serial transport. Require the same two-byte magic as the receiver.
        asm.emit('3a 8c ff fe a5 20 12 3a 8d ff fe 5a 20 0b')
        asm.emit(f'3a {tty_flag} d6 02 fe 03 30 02 {"37" if want_tty else "b7"} c9')
    elif tty_flag:
        # If TTY is active, return immediately. OR A already cleared carry.
        asm.emit(f'3a {tty_flag} b7 28 02 {"37" if want_tty else "00"} c9')
    if want_ncc:
        # The native NCC data task enters these states after dialing or once
        # connected, not while idle or emitting the digits.
        asm.emit(f'3a {addr(layout["data"])} d6 06 fe 08 c9')
    else:
        asm.emit('b7 c9')
    select = f'f5 cd {addr(asm.labels["selected"])}'
    redirects = []
    if mode == 'v22bis':
        asm.label('tx')
        asm.emit(select)
        asm.jump('d2', 'tx_stock')
        asm.emit(f'3a {addr(layout["data"])} fe 0b')
        asm.jump('d2', 'qam_write')
        asm.emit(f'f1 1e 1b c3 {addr(layout["write"])}')
        asm.label('tx_stock')
        asm.emit('f1 c3 ' + tx_hooks[0]['replacement'][2:])
        asm.label('tx_data')
        asm.emit(select)
        asm.jump('d2', 'tx_stock')
        asm.label('qam_write')
        asm.emit(f'f1 1e 5b c3 {addr(layout["write"])}')
    elif not psk:
        # The original writer (or inbound wrapper) accepts E unchanged for
        # stock calls, so both paths can tail-jump to exactly the same entry.
        asm.label('tx')
        asm.emit(f'{select} 30 02 1e {manifest["answer_cr0"] | 1:02x} f1 c3 '
                 + tx_hooks[0]['replacement'][2:])
    if mode != 'v22':
        redirects.extend((c, 'tx_data' if mode == 'v22bis' and c['offset'] in data_sites else 'tx')
                         for c in tx_hooks)
    if psk:
        asm.label('mark')
        asm.emit(f'{select} 30 02 1e 98 f1 c3 {addr(layout["write"])}')
    if mode != 'v22':  # same 1200 bit/s line rate as stock
        asm.label('uart')
        asm.emit(f'{select} 30 07 f1 3e {manifest["uart"]["answer_cntlb"]:02x} ed3903 c9')
        if uart_stub:
            asm.emit(f'f1 c3 {addr(uart_stub["offset"])}')
        else:
            asm.emit(f'f1 3e {manifest["uart"]["stock_cntlb"]:02x} ed3903 c9')
        redirects.insert(0, (uart_hook, 'uart'))
    elif uart_stub is None:
        changes.remove(uart_hook)
        for hook in tx_hooks:
            changes.remove(hook)

    code = asm.finish()
    padding = fill * len(code)
    end = origin + len(code)
    def fits(start, limit=common_end, expected_fill=fill):
        stop = start + len(code)
        return (stop <= limit and inbound[start:stop] == expected_fill * len(code) and
                not any(start < c['offset'] + len(c['expected']) // 2 and c['offset'] < stop for c in changes))

    if not fits(origin) and banked_tty and uart_stub and origin_override is None:
        # The CNB call-in module uses a bounded interior window. The shared
        # bank-0 tail is separate; relocate only our generated helper.
        tail = (len(inbound[:common_end].rstrip(fill)) + 15) & ~15
        if fits(tail):
            return add_outbound(chips, inbound, manifest, targets, common_end, fill, origin_override=tail)
    if not fits(origin) and origin_override is None and uart_stub and firmware['terminal_revision'] == 'mtr1':
        # A helper can live in the modem bank only if every redirected call
        # runs in that bank. Confirm the UART entry via its native veneer.
        bank = layout['writer_bank']
        delta = bank << 12
        uart_entry = manifest['uart']['setup_rom_offset'] - delta
        mmu = list(MTR1_MMU.finditer(stock))
        if len(mmu) == 1 and common_end <= uart_entry < (mmu[0][1][0] >> 4) << 12:
            bank_end = delta + ((mmu[0][1][0] >> 4) << 12)
            veneer = (b'\xcd' + layout['bank_call'].to_bytes(2, 'little')
                      + uart_entry.to_bytes(2, 'little') + bytes([bank]))
            # Include the existing mark write even when the UART is unchanged.
            sites = [uart_hook['offset'], *(c['offset'] for c in tx_hooks), *mark_sites]
            if (stock[:common_end].count(veneer) == 1
                    and all(delta + common_end <= site <= bank_end - 5 for site in sites)):
                bank_fill = stock[bank_end-1:bank_end]
                if bank_fill in (b'\0', b'\xff'):
                    bank_start = delta + common_end
                    tail = (bank_start + len(stock[bank_start:bank_end].rstrip(bank_fill)) + 15) & ~15
                    if fits(tail, bank_end, bank_fill):
                        return add_outbound(chips, inbound, manifest, targets, common_end, bank_fill,
                                            origin_override=tail, placement_bank=bank, placement_limit=bank_end)
    if not fits(origin, common_end if placement_limit is None else placement_limit):
        raise ValueError('no verified ROM space for outbound modem code')
    image = bytearray(inbound)
    image[origin:end] = code
    changes.append(dict(offset=origin, label='lab_outbound_selector', expected=padding.hex(), replacement=code.hex()))
    if psk:
        off = mark_sites[0]
        if any(off < c['offset'] + len(c['expected']) // 2 and c['offset'] < off + 3 for c in changes):
            raise ValueError('outbound mark hook overlaps an existing patch')
        mark = dict(offset=off, label='lab_outbound_mark_hook', expected=writer_call.hex(),
                    replacement=writer_call.hex())
        changes.append(mark)
        redirects.append((mark, 'mark'))
    for hook, entry in redirects:
        off = hook['offset']
        before = bytes.fromhex(hook['replacement'])
        if inbound[off:off + len(before)] != before:
            raise ValueError('outbound composition does not match the hook')
        tail = b'\0\0' if entry == 'uart' else b''
        after = b'\xcd' + asm.labels[entry].to_bytes(2, 'little') + tail
        image[off:off + len(after)] = after
        hook['replacement'] = after.hex()
    image = bytes(image)
    manifest.update(output_sha256=sha256(image).hexdigest(), modem_targets=sorted(targets),
                    scope='selected modem register settings; peer negotiation unverified',
                    lab_outbound=dict(selector=asm.labels['selected'], rom_offset=origin, bank=placement_bank,
                                      bytes=len(code), tx=asm.labels.get('tx'),
                                      uart=asm.labels.get('uart'), tty_kind=firmware['tty_rx_kind'],
                                      tty_flag=int.from_bytes(bytes.fromhex(tty_flag), 'little')
                                      if tty_flag else None))
    return image, manifest


def build_outbound_only(chips, mode, targets):
    """Find native originate hooks without requiring any ring or call-in hooks."""
    rom = b''.join(chips)
    firmware = identify(chips)
    if firmware['demo']:
        raise ValueError('demo firmware is excluded from patching')
    board = firmware['terminal_revision']
    check_modem_model(board, mode, None)
    if mode not in OUTBOUND_LAB_MODES or (board, mode) not in ANSWER_CR0:
        raise ValueError('no outbound probe for this board and mode')
    installed = recognized_call_in(rom)
    if len(installed) > 1:
        raise ValueError('ambiguous existing call-in code')
    existing = installed[0] if installed else None
    mmu = ([MTR2_MMU] if board == 'mtr2' else [m[0] for m in MTR1_MMU.finditer(rom)])
    if len(mmu) != 1:
        raise ValueError('ambiguous common ROM mapping')
    ba, ca = (mmu[0][1] & 15) << 12, (mmu[0][1] >> 4) << 12
    report = audit(rom)
    if report['shared_ncc_tty_uart_300_candidate'] is None:
        if existing is not None:
            raise ValueError('existing call-in build already changes UART setup; combine targets from the original ROM')
        raise ValueError('unambiguous stock NCC/TTY UART setup not found')
    stock_rate, new_rate, bps = uart_rates(report, mode)
    routine = NCC_UART.search(rom)
    control = rom[:0xc0000] if board == 'mtr2' else rom
    timeouts = list(DATA_TIMEOUT.finditer(control))
    if board == 'mtr2' and len(timeouts) > 1:
        seize = rb'\x21\x40\0\xe5\xcd..\xe1\xb7\xca..\xcd..\x3e\x01\x32..'
        timeouts = [m for m in timeouts if re.search(seize, control[m.end():m.end()+0x110], re.S)]
    data = {int.from_bytes(m[1], 'little') for m in timeouts}
    if len(data) != 1 or not ca <= next(iter(data)) < 0xffff:
        raise ValueError('unambiguous native data call state not found')
    target = existing.start() if existing is not None else None
    tx = list(re.finditer(rb'\x1e\x1b\x2e\0(\xcd(..))\xc9', control, re.S))
    choices = []
    for m in tx:
        addr = int.from_bytes(m[2], 'little')
        if existing is not None:
            if addr != target:
                continue
            addr = int.from_bytes(existing['writer'], 'little')
        delta = (m.start() - ba) & ~0xfff
        for bank in range(max(0, delta - (ca - ba)), delta + 1, 0x1000):
            if (ba <= addr < ca and bank + ba <= m.start() < bank + ca
                    and re.match(rb'(?:\xcb\x25){4}\xcd..\x3a', control[bank + addr:bank + addr + 12], re.S)):
                choices.append((addr, bank))
    if len(set(choices)) != 1:
        raise ValueError('unambiguous native modem writer not found')
    writer, bank = choices[0]
    native = b'\xcd' + (writer if target is None else target).to_bytes(2, 'little')
    pattern = rb'\x1e\x1b\x2e\0(' + re.escape(native) + rb')'
    hooks = [bank + ba + m.start(1) for m in re.finditer(pattern, control[bank + ba:bank + ca], re.S)]
    if len(hooks) < 3 or b'\x1e\xa3\x2e\0' + native in control[bank + ba:bank + ca]:
        raise ValueError('unsupported native transmit branches')
    fill = rom[ba-1:ba]
    if fill not in (b'\0', b'\xff'):
        raise ValueError('common ROM has no supported tail padding')
    origin = (len(rom[:ba].rstrip(fill)) + 15) & ~15
    changes = [dict(offset=o, label='preserve_answer_modem_mode', expected=native.hex(), replacement=native.hex())
               for o in hooks]
    uart_at = routine.start('cntlb') - 1
    uart_old = rom[uart_at:uart_at + 5].hex()
    changes.append(dict(offset=uart_at, label='lab_shared_uart_hook', expected=uart_old, replacement=uart_old))
    manifest = dict(profile=f'{board}-outbound-lab', input_sha256=sha256(rom).hexdigest(), rom_size=len(rom),
                    layout=dict(board=board, data=data.pop(), write=writer, outbound_origin=origin),
                    patches=changes, experimental=True, physical_hardware_verified=False,
                    audio_negotiation_verified=False, modem_mode=mode, answer_cr0=ANSWER_CR0[board, mode],
                    uart=dict(setup_rom_offset=routine.start(), answer_bps=bps,
                              answer_cntlb=new_rate, stock_cntlb=stock_rate))
    if existing is not None:
        manifest['layout']['answer_flag'] = int.from_bytes(existing['flag'], 'little')
        manifest['preserved_existing_call_in'] = True
    return add_outbound(chips, rom, manifest, targets, ba, fill)


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xa001 if crc & 1 else 0)
    return crc


def verify_ncc_transmit(emu, manifest, board):
    """Check native NCC transmit and receive over the emulated serial link."""
    emu.clock = emu.call('state')['board']['clockHz']
    results = []
    for mode in (2, 3):
        cursor = scenario(emu, manifest['layout'], mode, 3, board, **modem_expectations(manifest))
        tx = []
        for _ in range(20):
            emu.run(100)
            for event in emu.call('events', since=cursor):
                if event['type'] == 'serial.tx' and event['channel'] == 1:
                    tx.append(event)
                cursor = max(cursor, event['id'])
            if len(tx) >= 3 and len(tx) >= tx[2]['value'] + 1:
                break
        require(len(tx) >= 6, 'no complete NCC transmit frame after carrier')
        tx = tx[:tx[2]['value'] + 1]
        require(len(tx) >= 6 and len(tx) == tx[2]['value'] + 1, 'invalid NCC frame length')
        frame = bytes(t['value'] for t in tx)
        require(frame[0] == 2 and frame[-1] == 3 and int.from_bytes(frame[-3:-1], 'little') == crc16(frame[:-3]),
                'invalid NCC frame delimiters or CRC')
        ports = bytes.fromhex(emu.call('ports')['hex'])
        require(ports[1] == 0x64 and ports[3] == manifest['uart']['answer_cntlb'],
                'native NCC did not use the call-in UART profile')
        average_cycles = (tx[-1]['cycle'] - tx[0]['cycle']) / (len(tx) - 1)
        modeled_bps = round(10 * emu.clock / average_cycles)
        if board == 'mtr2':
            expected = manifest['uart'].get('answer_bps', 300)
            require(abs(modeled_bps - expected) <= expected * 0.05, 'MTR2 emulator UART timing does not match profile')
        # A peer CLEAR must go through the ASCI receiver and NCC parser.
        # Keep carrier asserted so carrier loss cannot satisfy this check.
        header = bytes([2, 0x20, 5])  # START, CLEAR, length excluding START
        clear = header + crc16(header).to_bytes(2, 'little') + b'\x03'
        layout = manifest['layout']

        def active():
            return emu.read(layout['answer_flag'])[0] == ANSWER_MARK and bool(
                emu.call('state')['devices']['relays'] & 1)

        def send(frame):
            emu.call('devices', {'type': 'serial', 'data': {'channel': 1, 'hex': frame.hex()}})

        emu.run(50)  # let the last transmitted character finish
        require(active(), 'call released before a peer response')
        emu.call('snapshots', {'name': 'lab-before-peer-clear'})
        # First try an otherwise identical frame with an invalid CRC, then
        # restore the call so a NACK or retry cannot affect the valid test.
        send(clear[:3] + bytes([clear[3] ^ 1]) + clear[4:])
        emu.run(300)
        require(active(), 'firmware released the call on a corrupted CLEAR frame')
        emu.call('snapshots/restore', {'name': 'lab-before-peer-clear'})
        send(clear)
        for _ in range(10):
            emu.run(100)
            if (emu.read(layout['answer_flag']) == b'\0' and emu.read(layout['data']) == b'\0'
                    and not emu.call('state')['devices']['relays'] & 1):
                break
        else:
            raise ValueError('firmware did not release the call after a valid NCC CLEAR')
        results.append(dict(rings=1 if mode == 2 else 3, frame_bytes=len(frame),
                            crc_valid=True, modeled_bps=modeled_bps,
                            timing_checked=board == 'mtr2', bad_clear_crc_rejected=True,
                            peer_clear_released_modem=True))
    return results


def modem_expectations(manifest):
    return {key: manifest[key] for key in ('answer_cr0', 'data_cr0', 'answer_cr1') if key in manifest}


def verify_candidate(image, manifest, url):
    if ModemTarget.INBOUND_NCC not in manifest['modem_targets']:
        raise ValueError('the lab verifier requires an inbound target')
    report = verify(image, manifest, 3, url)
    # Isolated subroutine test, not a TTY session. Execute the stock UART
    # enable path up to (but not including) its final interrupt-helper jump.
    emu = Emulator(url)
    ncc_tx = verify_ncc_transmit(emu, manifest, report['board'])
    emu.call('snapshots/restore', {'name': 'patcher-boot'})
    uart = manifest['uart']
    physical = uart['setup_rom_offset']
    routine = image[physical:physical + 20]
    flag = manifest['layout']['answer_flag']
    try:
        mmu = emu.call('state')['mmu']
        bank_base, common_base = (mmu['cbar'] & 15) << 12, (mmu['cbar'] >> 4) << 12
        outbound = manifest.get('lab_outbound', {})
        start = physical
        if physical + len(routine) > bank_base:
            # Map the ROM routine into the test CPU's bank window, preserving
            # its page offset. This test stops before following an absolute jump.
            page = outbound.get('bank')
            if page is None:
                page = (physical - bank_base) >> 12
            start = physical - (page << 12)
            require(0 <= page <= 0xff and bank_base <= start and start + len(routine) <= common_base,
                    'shared UART routine cannot fit in the MMU bank window')
            emu.call('ports', {'port': 0x39, 'value': page})
        require(emu.read(start, len(routine)) == routine, 'shared UART routine did not map correctly')
        require(common_base <= flag < 0x10000, 'answer flag is outside common RAM')
        tty_flag = outbound.get('tty_flag')
        targets = manifest['modem_targets'] if outbound else []
        cases = [(0, 0, 0, uart['stock_cntlb']), (ANSWER_MARK, 0, 0, uart['answer_cntlb']),
                 (0, 12, 0, uart['answer_cntlb'] if 'outbound_ncc' in targets else uart['stock_cntlb'])]
        if tty_flag is not None:
            phase = 2 if outbound.get('tty_kind') == 'cnb_banked' else 1
            cases.append((0, 12, phase, uart['answer_cntlb'] if 'outbound_tty' in targets else uart['stock_cntlb']))
        cases.append((0, 0, 0, uart['stock_cntlb']))
        for mark, data, tty, expected in cases:
            fields = [(flag, mark), (manifest['layout']['data'], data), (tty_flag, tty)]
            if outbound.get('tty_kind') == 'cnb_banked':
                fields.extend([(0xff8c, 0xa5 if tty else 0), (0xff8d, 0x5a if tty else 0)])
            for address, value in fields:
                if address is None:
                    continue
                require(common_base <= address < 0x10000 and address + (mmu['cbr'] << 12) >=
                        (0xc0000 if report['board'] == 'mtr2' else 0x40000), 'UART fixture address is not RAM')
                emu.call('memory', {'space': 'logical', 'address': address, 'hex': f'{value:02x}'})
            emu.call('registers', {'pc': start, 'l': 1})
            for _ in range(48):
                result = emu.call('run', {'cycles': 1000, 'instructions': 1})
                require(not result['execution']['fault'], 'shared UART setup did not execute')
                if result['state']['cpu']['pc'] == start + len(routine):
                    break
            else:
                raise ValueError('shared UART routine did not reach its return path')
            ports = bytes.fromhex(emu.call('ports')['hex'])
            require(ports[1] == 0x64 and ports[3] == expected, 'shared UART selected the wrong rate')
    finally:
        emu.call('snapshots/restore', {'name': 'patcher-boot'})
    return dict(report, carrier_source='emulator_injected',
                uart_setup_executed=True, uart_cntlb=uart['answer_cntlb'],
                stock_uart_restored=True, native_ncc_tx=ncc_tx,
                audio_negotiation_tested=False, tty_session_tested=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['v21', 'bell103', 'v22', 'v22bis'])
    parser.add_argument('roms', nargs='+', type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--verify-url', help='private Go emulator on a shared filesystem')
    parser.add_argument('--outbound-ncc', action='store_true', help='also patch T→Manager calls')
    parser.add_argument('--outbound-tty', action='store_true', help='also patch outgoing TTY service calls')
    parser.add_argument('--modem-model', type=ModemModel, choices=list(ModemModel))
    args = parser.parse_args()
    try:
        targets = [ModemTarget.INBOUND_NCC]
        if args.outbound_ncc:
            targets.append(ModemTarget.OUTBOUND_NCC)
        if args.outbound_tty:
            targets.append(ModemTarget.OUTBOUND_TTY)
        chips = [load_rom(p) for p in args.roms]
        check_modem_model(identify(chips)['terminal_revision'], args.mode, args.modem_model)
        image, manifest = build(chips, args.mode, targets=targets)
        if args.modem_model is not None:
            manifest['declared_modem_model'] = args.modem_model
        if args.verify_url:
            manifest['lab_verification'] = verify_candidate(image, manifest, args.verify_url)
        write_patch(args.output_dir, f'{args.roms[0].stem}_{args.mode}_lab.bin', image, manifest)
    except (ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
