"""ROM identification and patch registry; filenames are not hardware evidence."""
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Callable

from .millennium_callin_standalone import decode_ihex, patch_discovered


ROM_ID = re.compile(rb'(?:(?P<code>[0-9]{2}))?<(?P<edition>[A-Z0-9]{7})(?P<revision>V[0-9]+\.[0-9]+)'
                    rb'(?=ABCDEFG1234\x00|[A-Z0-9]{6}\x00V[0-9]+\.[0-9]+|\x00)')
MTR1_MMU = re.compile(rb'\x3e([\x85\x96])\xed\x39\x3a\x3e(.)\xed\x39\x38\x11', re.S)
MTR2_MMU = b'\x3e\x85\xed\x39\x3a\x3e\xb8\xed\x39\x38\x11'
MTR2_RESET = b'\xf3\x0e\x01\xc3\x12\x01\xff\xff'
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
    return dict(firmware_version=edition, firmware_revision=revision,
                terminal_type=EDITION_TYPES.get(edition),
                terminal_type_source='archive_edition_label' if edition in EDITION_TYPES else None,
                header_variant_code=code,
                terminal_revision=board, version_offset=match.start('edition') if match else None,
                image_sha256=sha256(rom).hexdigest(), image_size=len(rom))


def decode_upload(data, encoding):
    return decode_ihex(data) if encoding == 'ihex' else data


@dataclass(frozen=True)
class Patch:
    label: str
    build: Callable
    platforms: tuple[str, ...]

    def metadata(self, key):
        return dict(id=key, label=self.label, platforms=list(self.platforms), experimental=True)

    def check_platform(self, firmware):
        platform = firmware['terminal_revision']
        if platform is None:
            raise ValueError('could not identify the ROM platform as MTR1 or MTR2')
        if platform not in self.platforms:
            supported = ', '.join(self.platforms).upper()
            raise ValueError(f'{self.label} supports {supported}, not {platform.upper()}')

    def apply(self, chips, firmware=None):
        self.check_platform(identify(chips) if firmware is None else firmware)
        return self.build(chips)


PATCHES = {'call_in': Patch('Inbound modem call-in', patch_discovered, ('mtr1', 'mtr2'))}
