"""Find stock NCC and DPH UART setup code in a decoded control ROM; never write it."""
import argparse
import json
from pathlib import Path
import re


# NCCASM.ASM:_ncc_setuart. The disable branch skips the three UART writes
# and lands on XOR A. Both paths tail-jump to the same interrupt helper.
NCC_UART = re.compile(
    rb'\xf3\x7d\xa7\x28\x12'
    rb'\x3e(?P<stat>.)\xed\x39\x05\x3e(?P<cntla>.)\xed\x39\x01'
    rb'\x3e(?P<cntlb>.)\xed\x39\x03\xc3(?P<exit>..)\xaf\xed\x39\x05\xc3(?P=exit)',
    re.S,
)
# DPHDRV.ASM:_dph_init_uart. Rate selection precedes parity selection and
# the CNTLB1 write. IODEFS.INC gives a different divisor for each build clock.
DPH_UART = re.compile(
    rb'\xf3\x7d\xe6\x01\x28.\x7d\xe6\x02\x28\x04'
    rb'\x0e(?P<cntlb_2400>.)\x18\x02\x0e(?P<cntlb_1200>.)'
    rb'\x7d\xe6\x04\x28\x03\x79\x18\x03\x79\xf6.\xed\x39\x03',
    re.S,
)


def audit(image):
    def matches(pattern, fields):
        return [dict(rom_offset=hex(m.start()), **{key: hex(m[key][0]) for key in fields})
                for m in pattern.finditer(image)]

    shared = matches(NCC_UART, ('stat', 'cntla', 'cntlb'))
    rate_candidate = None
    if len(shared) == 1:
        setup = shared[0]
        stock = int(setup['cntlb'], 16)
        if (setup['stat'], setup['cntla'], stock) in (('0x8', '0x64', 0x0b), ('0x8', '0x64', 0x0c)):
            # SS=3 (or 4) becomes SS=5 (or 6): four times the divisor.
            # Keep the clock-source and frame-format bits unchanged.
            rate_candidate = {'stock_bps': 1200, 'candidate_bps': 300,
                              'stock_cntlb': hex(stock), 'candidate_cntlb': hex(stock + 2)}

    return {
        'ncc_uart_signature_matches': shared,
        'shared_ncc_tty_uart_300_candidate': rate_candidate,
        'dph_uart_signature_matches': matches(DPH_UART, ('cntlb_1200', 'cntlb_2400')),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rom', type=Path, nargs='+', help='single control ROM or MTR2 flash0 then flash1')
    args = parser.parse_args()
    chips = [path.read_bytes() for path in args.rom]
    if list(map(len, chips)) not in ([0x40000], [0x100000], [0x80000, 0x80000]):
        parser.error('expected a 256 KiB ROM, a merged 1 MiB ROM, or two 512 KiB chips')
    print(json.dumps(audit(b''.join(chips)), indent=2))


if __name__ == '__main__':
    main()
