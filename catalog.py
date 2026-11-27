"""ROM identification and patch registry; filenames are not hardware evidence."""
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from hashlib import sha256
import re
from typing import Callable

from .millennium_callin_standalone import decode_ihex, is_demo_rom, patch_discovered


ROM_ID = re.compile(rb'(?:(?P<code>[0-9]{2}))?<(?P<edition>[A-Z0-9]{7})(?P<revision>V[0-9]+\.[0-9]+)'
                    rb'(?=ABCDEFG1234\x00|[A-Z0-9]{6}\x00V[0-9]+\.[0-9]+|\x00)')
MTR1_MMU = re.compile(rb'\x3e([\x85\x96])\xed\x39\x3a\x3e(.)\xed\x39\x38\x11', re.S)
MTR2_MMU = b'\x3e\x85\xed\x39\x3a\x3e\xb8\xed\x39\x38\x11'
MTR2_RESET = b'\xf3\x0e\x01\xc3\x12\x01\xff\xff'
# Compiled TTY receive routine: reset the count, recognize STX, advance
# the receive state, then read the packet length. RAM addresses vary.
TTY_RX = re.compile(
    rb'\xdd\xe5\xdd\x21\0\0\xdd\x39\x3a(?P<state>..)\x18.\xaf\x32..'
    rb'\x3e\x02\xdd\x6e\x04\x95\xc2..\x3e\x01\x32(?P=state)\xc3..'
    rb'\xdd\x7e\x04\x3c\x32..\x3e\x02\x32(?P=state)', re.S,
)
CALL_IN_WRAPPER = re.compile(rb'\xf5\x3a(?P<flag>..)\xfe\xa5\x20\x02\x1e[\x1a\x5a\x3a\xba]\xf1\xc3(?P<writer>..)'
                             rb'(?P<release>\xf5\xaf\x32(?P=flag)\xf1\xc3(?P=writer))', re.S)


def banked_tty_receiver(rom):
    """Recognize the CNB TTY port by following the IRQ jump and bank veneer."""
    irq = rb'\xc3(..)\x28\x08\xed\x38\x01\xe6\xf7\xed\x39\x01\xaf\x32..\x3a..\xe6\x80'
    receiver = (rb'\xf5\xc5\xd5\xe5\xdd\xe5\xdd\x21\0\0\xdd\x39'
                rb'\x3a..\xfe\x01\xc2(?P<fallback>..)\x3a\x8c\xff\xfe\xa5\xc2(?P=fallback)'
                rb'\x3a\x8d\xff\xfe\x5a\xc2(?P=fallback)\x3a\x8e\xff\xfe\x03\xda(?P=fallback)'
                rb'\xfe\x05\xd2(?P=fallback)')
    hits = set()
    for m in re.finditer(irq, rom, re.S):
        entry = int.from_bytes(m[1], 'little')
        if entry >= 0x5000 or rom[entry:entry + 3] != b'\xcd\xfb\x43':
            continue
        logical = int.from_bytes(rom[entry + 3:entry + 5], 'little')
        offset = logical + (rom[entry + 5] << 12)
        if 0x5000 <= logical < 0x8000 and re.match(receiver, rom[offset:offset + 64], re.S):
            hits.add(offset)
    return hits.pop() if len(hits) == 1 else None


def recognized_call_in(rom):
    return [m for m in CALL_IN_WRAPPER.finditer(rom[:0x5000]) if
            b'\x1e\x19\x2e\x00\xcd' + m.start('release').to_bytes(2, 'little') in rom]
# Edition labels documented by the muccc/millennium archive. These describe
# the firmware variant, not the physical phone or its EEPROM configuration.
EDITION_TYPES = {'NQA1X01': 'CPC', 'NPE1S01': 'coin-basic', '06CBBX1': 'card-only',
                 'NAJ2S05': 'desk', 'NOA1X04': 'TTY', 'NOK1X03': 'TTY', 'NNA1F02': 'TTY'}


def identify(chips):
    rom = b''.join(chips)
    common = rom[:0x5000]
    hits = list(ROM_ID.finditer(common))
    match = hits[0] if len({m.groups() for m in hits}) == 1 else None
    edition, revision, code = (None, None, None)
    if match:
        edition, revision = (match[k].decode('ascii') for k in ('edition', 'revision'))
        code = match['code'].decode('ascii') if match['code'] else None
    board = None
    # MTR1 startup code can sit above the header scan window (12AAV08).
    if len(rom) == 0x40000 and any(
        ((m[1][0] >> 4) + m[2][0]) << 12 == 0x40000 for m in MTR1_MMU.finditer(rom)
    ):
        board = 'mtr1'
    elif len(rom) == 0x100000 and MTR2_MMU in common and rom[0xc0000:0xc0008] == MTR2_RESET:
        board = 'mtr2'
    tty_rx = TTY_RX.search(common) if board is not None else None
    banked_tty = banked_tty_receiver(rom) if board == 'mtr1' and not tty_rx else None
    call_in = board is not None and bool(recognized_call_in(rom))
    return dict(firmware_version=edition, firmware_revision=revision,
                terminal_type=EDITION_TYPES.get(edition),
                terminal_type_source='archive_edition_label' if edition in EDITION_TYPES else None,
                header_variant_code=code,
                terminal_revision=board, version_offset=match.start('edition') if match else None,
                tty_rx_offset=tty_rx.start() if tty_rx else banked_tty,
                tty_rx_kind='native' if tty_rx else 'cnb_banked' if banked_tty is not None else None,
                call_in_detected=call_in, demo=is_demo_rom(rom),
                image_sha256=sha256(rom).hexdigest(), image_size=len(rom))


def decode_upload(data, encoding):
    return decode_ihex(data) if encoding == 'ihex' else data


class ModemTarget(StrEnum):
    INBOUND_NCC = 'inbound_ncc'
    OUTBOUND_NCC = 'outbound_ncc'
    OUTBOUND_TTY = 'outbound_tty'


OUTBOUND_LAB_MODES = ('v21', 'bell103', 'v22', 'v22bis')


class ModemModel(StrEnum):
    SSI_212L = '73k212l'
    SSI_212SL_IP = '73k212sl-ip'
    SSI_222BL = '73k222bl'
    SSI_324L = '73k324l'


def check_modem_model(board, mode, model):
    if mode not in (*OUTBOUND_LAB_MODES, 'bell212a'):
        return
    if board == 'mtr1' and mode not in ('bell103', 'bell212a'):
        raise ValueError('MTR1 assumes a 73K212SL-IP and supports only Bell 212A and Bell 103')
    if model is not None:
        allowed = (ModemModel.SSI_324L,) if board == 'mtr2' else (
            ModemModel.SSI_212L, ModemModel.SSI_212SL_IP)
        if model not in allowed:
            raise ValueError('selected modem model is not supported for this board and mode')


@dataclass(frozen=True)
class Patch:
    label: str
    build: Callable
    platforms: tuple[str, ...]
    modem_mode: str | None = None
    verification_available: bool = True

    def metadata(self, key, *, firmware=None, outbound=None, call_in_error=None):
        data = dict(id=key, label=self.label, platforms=list(self.platforms), experimental=True,
                    verification_available=self.verification_available and call_in_error is None)
        if self.modem_mode is not None:
            tty_detected = firmware is not None and firmware['tty_rx_offset'] is not None
            def option(target):
                if outbound is not None and target in outbound:
                    reason = outbound[target]
                elif self.modem_mode not in OUTBOUND_LAB_MODES:
                    reason = 'Bell 212A already uses stock outbound settings'
                elif target == ModemTarget.OUTBOUND_TTY and firmware is not None and not tty_detected:
                    reason = 'no supported TTY receive signature found in this ROM'
                else:
                    reason = 'upload a ROM to check outbound compatibility'
                return dict(available=reason is None, reason=reason)
            data.update(modem_mode=self.modem_mode, modem_targets={
                ModemTarget.INBOUND_NCC: dict(available=call_in_error is None, reason=call_in_error,
                                          detected=bool(firmware and firmware['call_in_detected'])),
                ModemTarget.OUTBOUND_NCC: option(ModemTarget.OUTBOUND_NCC),
                ModemTarget.OUTBOUND_TTY: option(ModemTarget.OUTBOUND_TTY),
            })
        return data

    def check_targets(self, targets):
        if targets is None:
            return
        if self.modem_mode is None:
            raise ValueError('this patch does not accept modem targets')
        if not targets or len(set(targets)) != len(targets):
            raise ValueError('select at least one modem target and list each target only once')
        if targets != [ModemTarget.INBOUND_NCC] and self.modem_mode not in OUTBOUND_LAB_MODES:
            raise ValueError('Bell 212A already uses stock outbound settings')

    def check_verification_targets(self, targets):
        self.check_targets(targets)
        if not self.verification_available or ModemTarget.INBOUND_NCC not in targets:
            raise ValueError('queued verification requires inbound_ncc; use /builds for outbound-only builds')

    def check_platform(self, firmware):
        if firmware['demo']:
            raise ValueError('demo firmware is excluded from patching')
        platform = firmware['terminal_revision']
        if platform is None:
            raise ValueError('could not identify the ROM platform as MTR1 or MTR2')
        if platform not in self.platforms:
            supported = ', '.join(self.platforms).upper()
            raise ValueError(f'{self.label} supports {supported}, not {platform.upper()}')

    def apply(self, chips, firmware=None, *, targets=None):
        self.check_targets(targets)
        firmware = identify(chips) if firmware is None else firmware
        self.check_platform(firmware)
        if self.modem_mode is not None and firmware['call_in_detected'] and (
                targets is None or ModemTarget.INBOUND_NCC in targets):
            raise ValueError('call-in code already detected; omit inbound_ncc to preserve it')
        if targets and targets != [ModemTarget.INBOUND_NCC]:
            return self.build(chips, targets=targets)
        return self.build(chips)


def build_modem_lab(chips, *, mode, targets=None):
    from .modem_lab import build

    return build(chips, mode, targets=targets)


PATCHES = {'modem_bell212a': Patch('Bell 212A', patch_discovered, ('mtr1', 'mtr2'), 'bell212a')}
for mode, label, platforms in (
    ('v21', 'V.21', ('mtr2',)),
    ('bell103', 'Bell 103', ('mtr1',)),
    ('v22', 'V.22', ('mtr2',)),
    ('v22bis', 'V.22bis register probe (no training)', ('mtr2',)),
):
    PATCHES[f'modem_{mode}'] = Patch(f'{label} (lab only)', partial(build_modem_lab, mode=mode),
                                         platforms, modem_mode=mode)
