"""Call-in verification through the upstream Go emulator HTTP API."""
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener


class VerificationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


class Emulator:
    def __init__(self, url):
        self.url = url.rstrip('/')
        self.http = build_opener(ProxyHandler({}))
        self.deadline = monotonic() + 180

    def call(self, route, body=None, **query):
        remaining = self.deadline - monotonic()
        require(remaining > 0, 'emulator verification timed out')
        url = f'{self.url}/api/{route}' + ('?' + urlencode(query) if query else '')
        req = Request(url, data=None if body is None else json.dumps(body).encode(),
                      headers={'Content-Type': 'application/json'})
        try:
            with self.http.open(req, timeout=min(15, remaining)) as response:
                data = response.read(8 * 1024 * 1024 + 1)
            require(len(data) <= 8 * 1024 * 1024, 'emulator response too large')
            return json.loads(data)
        except HTTPError as error:
            raise VerificationError(f'emulator {route}: HTTP {error.code}') from error

    def run(self, ms):
        remaining = ms * self.clock // 1000
        while remaining > 0:
            result = self.call('run', {'cycles': min(remaining, 100_000_000), 'instructions': 5_000_000})
            e = result['execution']
            require(e['reason'] == 'budget' and not e['fault'] and e['cycles'] > 0,
                    f"emulator stopped: {e['reason']} ({e['fault']})")
            remaining -= e['cycles']
        return result['state']

    def read(self, address, length=1):
        return bytes.fromhex(self.call('memory', space='logical', address=address, length=length)['hex'])

    def line(self, **data):
        self.call('devices', {'type': 'line', 'data': data})

    def modem_control(self):
        return self.call('snapshot')['devices']['modem']['controls'][0]


def verify(image, manifest, rings, url):
    emu = Emulator(url)
    p = manifest['layout']
    board = p['board']
    if board == 'mtr1' and b'<NPE1S01V' in image[:0x5000]:
        board = 'mtr1-coin-basic'
    with TemporaryDirectory(dir=os.environ.get('FIRMWARE_VERIFY_DIR', '/verify')) as folder:
        # Both containers see this path; it is never derived from client data.
        path = Path(folder) / 'candidate.bin'
        path.write_bytes(image)
        emu.call('pause', {})
        emu.call('ncc', {'mode': 'off'})
        emu.call('load', {'path': str(path), 'board': board})
        state = emu.call('state')
        require(state['firmware']['sha256'] == manifest['output_sha256'], 'emulator loaded the wrong ROM')
        emu.clock = state['board']['clockHz']
        state = emu.run(8000)
        require(any(row.strip() for row in state['display']), 'no boot display')
        emu.call('snapshots', {'name': 'patcher-boot'})
        for mode in (2, 3, 0, 1):
            try:
                modem = {key: manifest[key] for key in ('answer_cr0', 'data_cr0', 'answer_cr1') if key in manifest}
                scenario(emu, p, mode, rings, board, **modem)
            except VerificationError as error:
                raise VerificationError(f'mode {mode}: {error}') from error
    return dict(engine='millennium-go-http', boot=True, board=board, immediate_rings=1,
                delayed_rings=rings, carrier_accepted_in_both=True, no_pickup_modes=[0, 1],
                provisioning='emulator_ram_only', carrier_source='emulator_injected',
                audio_negotiation_tested=False)


def scenario(emu, p, mode, rings, board, *, answer_cr0=0x1a, data_cr0=None, answer_cr1=None):
    emu.call('snapshots/restore', {'name': 'patcher-boot'})
    state = emu.call('state')
    mmu = state['mmu']
    ca, ram = (mmu['cbar'] >> 4) << 12, 0xc0000 if board == 'mtr2' else 0x40000

    def where(key):
        a = p.get(key)
        require(type(a) is int and max(0x8000, ca) <= a <= 0xffff, f'no confirmed RAM address for {key}')
        return a

    def read(key, length=1):
        return int.from_bytes(emu.read(where(key), length), 'little')

    def put(key, value, length=1, offset=0):
        a = where(key) + offset
        require(a + length <= 0x10000 and a + (mmu['cbr'] << 12) >= ram
                and a + length + (mmu['cbr'] << 12) <= 0x100000, f'{key} is not mapped to RAM')
        value %= 1 << (length * 8)
        emu.call('memory', {'space': 'logical', 'address': a, 'hex': value.to_bytes(length, 'little').hex()})

    require(read('answer_flag') == 0, 'answer scratch occupied after boot')
    for key in 'offhook ncc data busy seized ring_state answer_flag ring_count ring_block'.split():
        put(key, 0)
    put('pending', 0, 2)
    put('carrier_delay', 10, 2)
    for index, value in [(3, 0x0a0a01), (4, 0x140301)]:
        if not any(emu.read(where('dr_config') + 3 * index, 3)):
            put('dr_config', value, 3, 3 * index)
    put('guard_timestamp', read('clock_word', 2) - 300, 2)
    put('mode', mode | rings << 8, 2)
    put('ui', read('ui') | 0x20)
    put('installed_word', 0x1f2e, 2)
    put('ring_enabled', 1)
    if board == 'mtr2':
        ports = bytes.fromhex(emu.call('ports')['hex'])
        emu.call('ports', {'port': 0x40, 'value': ports[0x40] | 0x10})
    event_id = emu.call('state')['eventId']

    def no_pickup(state):
        nonlocal event_id
        events = emu.call('events', since=event_id)
        event_id = state['eventId']
        require(not (state['devices']['relays'] & 1) and not any(
            e['type'] == 'relays' and e['value'] & 1 for e in events), 'modem relay seized during no-pickup interval')
        require(read('data') == read('answer_flag') == 0 and emu.modem_control() != answer_cr0,
                'modem entered answer mode during no-pickup interval')

    count = 1 if mode == 2 else rings
    for n in range(1, count + 1):
        emu.line(ring=True)
        state = emu.run(400)
        if mode >= 2 and n == count:
            break
        if mode == 3:
            require(read('ring_count') == n, f'ring {n} was not counted')
        no_pickup(state)
        emu.line(ring=False)
        no_pickup(emu.run(900))
    if mode < 2:
        return
    require(read('data') == 10 and read('ncc') == 1 and read('busy') & 2
            and read('pending', 2) & 0x20 and read('answer_flag') == 0xa5 and read('ring_enabled') == 0
            and state['devices']['relays'] & 3 == 3 and not state['devices']['dialed']
            and emu.modem_control() == answer_cr0, f'ring {count} did not reach native call-in setup')
    before_carrier = state['eventId']
    if answer_cr1 is not None:
        require(emu.call('snapshot')['devices']['modem']['controls'][1] == answer_cr1,
                'modem did not enter the expected startup pattern')
    emu.line(ring=False, carrier=True, dialTone=False)
    for _ in range(125):
        emu.run(8)
        if read('data') == 12:
            require(emu.modem_control() == (answer_cr0 if data_cr0 is None else data_cr0),
                    'modem did not enter the expected data mode after carrier')
            return before_carrier
    raise VerificationError('native data task did not accept simulated carrier')
