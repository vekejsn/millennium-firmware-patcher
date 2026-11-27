from contextlib import closing
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from .api import MAX_BODY, create_app
from .catalog import MTR2_MMU, MTR2_RESET, Patch, identify
from .jobs import process_one, send_one, store_build
from .millennium_callin_standalone import NCC_SETUP, patch_discovered
from .modem_lab import uart_rates


FIRMWARE = Path(__file__).resolve().parents[1] / 'firmware_analysis'


class ApiTest(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(TemporaryDirectory())
        self.db = Path(directory) / 'archive.sqlite3'
        self.client = self.enterContext(TestClient(create_app(self.db)))

    def rom(self, file):
        path = FIRMWARE / file
        if not path.is_file():
            self.skipTest(f'local ROM missing: {file}')
        return path.read_bytes()

    def upload(self, *files):
        r = self.client.post('/sessions', files=[('files', item) for item in files])
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def test_demo_roms_are_archived_but_cannot_be_patched(self):
        directory = 'Millennium Firmwares/'
        merged = self.rom(directory + 'NLA1X06-demo.bin')
        chips = [self.rom(directory + f'NLA1X06-demo-f{i}.BIN') for i in (1, 2)]
        self.assertEqual(b''.join(chips), merged)
        production = self.rom(directory + 'NLA1X06V1.3.bin')
        control = self.upload(('demo-in-name-only.bin', production))
        self.assertFalse(control['firmware']['demo'])
        self.assertIn('modem_bell212a', [p['id'] for p in control['applicable_patches']])
        for files in ((merged,), chips):
            session = self.upload(*[(f'rom{i}.bin', chip) for i, chip in enumerate(files)])
            self.assertTrue(session['firmware']['demo'])
            self.assertEqual(session['applicable_patches'], [])
            url = '/sessions/' + session['session_id']
            with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
                for action, request in (('builds', {'patches': ['modem_bell212a']}),
                                        ('jobs', {'patches': ['modem_bell212a']}),
                                        ('builds', {'patches': ['modem_v21'],
                                                    'modem_targets': ['outbound_ncc']})):
                    response = self.client.post(url + '/' + action, json=request)
                    self.assertEqual(response.status_code, 422, response.text)
                    self.assertIn('demo firmware', response.json()['detail'])
            for i, chip in enumerate(files):
                self.assertEqual(self.client.get(f'{url}/originals/{i}').content, chip)
        with self.assertRaisesRegex(ValueError, 'demo firmware'):
            patch_discovered(chips)

    def test_mtr1_call_in_can_split_into_confirmed_ring_bank(self):
        original = self.rom('06CNB03.bin')
        stock = bytearray(original)
        # Occupy the documented CNB window so discovery must use a split.
        self.assertEqual(stock[0x1360], 0)
        stock[0x1360] = 0x42
        image, manifest = patch_discovered([bytes(stock)])
        layout = manifest['layout']
        delta = layout['ring_bank'] << 12
        patches = {p['label']: p for p in manifest['patches']}
        common = patches['fixed_callin_module']
        ring = patches['banked_ring_module']
        self.assertEqual(image[0x1360], 0x42)
        self.assertLessEqual(common['offset'] + len(bytes.fromhex(common['replacement'])), 0x5000)
        self.assertEqual(ring['offset'] - delta, layout['ring_origin'])
        for label in ('first_ring', 'later_ring'):
            hook = patches[label]
            call = bytes.fromhex(hook['replacement'])
            self.assertEqual(call[0], 0xcd)
            self.assertIn(int.from_bytes(call[1:3], 'little') + delta,
                          range(ring['offset'], ring['offset'] + len(bytes.fromhex(ring['replacement']))))
        stock[0x4fef] = 0x42  # leave only 16 bytes of common padding
        with self.assertRaisesRegex(ValueError, 'insufficient common ROM space'):
            patch_discovered([bytes(stock)])

    def test_mtr2_ncc_setup_uses_dispatcher_to_break_tie(self):
        stock = self.rom('Millennium Firmwares/NLA1X05V1.3.bin')
        _, reference = patch_discovered([stock])
        setup = next(NCC_SETUP.finditer(stock[:0xc0000]))
        continuation = stock[setup.end():setup.end() + 13]
        # A second state machine also sets a state byte and the busy flag.
        # Only the primary dispatcher branches back to the same continuation.
        decoy = bytes.fromhex('3e013200903a0190f6023201903a0090b73a0190e602b7')
        at = 0xbfff0 - len(decoy) - len(continuation)
        synthetic = bytearray(stock)
        synthetic[at:at + len(decoy)] = decoy
        _, manifest = patch_discovered([bytes(synthetic)])
        self.assertEqual(manifest['layout']['ncc'], reference['layout']['ncc'])
        self.assertEqual(manifest['layout']['busy'], reference['layout']['busy'])
        synthetic[at:at + len(decoy) + len(continuation)] = decoy[:13] + continuation + decoy[13:]
        with self.assertRaisesRegex(ValueError, 'NCC setup missing or ambiguous'):
            patch_discovered([bytes(synthetic)])

    def test_applicable_patches_follow_detected_platform_and_rom_checks(self):
        # 12AAV08 puts this signature at 0x56b7, beyond the header window.
        mtr1 = (bytes(0x56b7) + bytes.fromhex('3e96ed393a3e37ed393811')).ljust(0x40000, b'\0')
        mtr2 = (MTR2_MMU.ljust(0xc0000, b'\0') + MTR2_RESET).ljust(0x100000, b'\0')

        def reject(_chips):
            raise ValueError('required hook is missing')

        registry = {
            'mtr1_only': Patch('MTR1 only', lambda chips: None, ('mtr1',)),
            'mtr2_only': Patch('MTR2 only', lambda chips: None, ('mtr2',)),
            'both': Patch('Both', lambda chips: None, ('mtr1', 'mtr2')),
            'missing_hook': Patch('Missing hook', reject, ('mtr1', 'mtr2')),
        }
        with patch.dict('firmware_patcher.catalog.PATCHES', registry, clear=True), \
                patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
            self.assertEqual(self.client.get('/patches').json(), [p.metadata(k) for k, p in registry.items()])
            for rom, board, wrong in ((mtr1, 'mtr1', 'mtr2_only'), (mtr2, 'mtr2', 'mtr1_only')):
                data = self.upload(('renamed.bin', rom))
                url = '/sessions/' + data['session_id']
                self.assertEqual(data['firmware']['terminal_revision'], board)
                self.assertEqual([p['id'] for p in data['applicable_patches']], [board + '_only', 'both'])
                self.assertEqual(self.client.get(url + '/patches').json(), data['applicable_patches'])
                self.assertEqual(data['patches']['missing_hook']['reason'], 'required hook is missing')
                for action in ('builds', 'jobs'):
                    result = self.client.post(url + '/' + action, json={'patches': [wrong]})
                    self.assertEqual(result.status_code, 422, result.text)
                    self.assertIn(f'not {board.upper()}', result.json()['detail'])
            self.assertEqual(self.upload(('unknown.bin', b'unknown'))['applicable_patches'], [])

    def test_cors_allows_cross_origin_requests_without_credentials(self):
        origin = 'https://frontend.example'
        preflight = self.client.options('/sessions', headers={
            'Origin': origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Content-Type',
        })
        self.assertEqual(preflight.status_code, 200)
        self.assertEqual(preflight.headers['access-control-allow-origin'], '*')
        self.assertIn('POST', preflight.headers['access-control-allow-methods'])
        response = self.client.get('/firmwares', headers={'Origin': origin})
        self.assertEqual(response.headers['access-control-allow-origin'], '*')
        self.assertNotIn('access-control-allow-credentials', response.headers)

    def test_tty_detection_uses_code_not_the_filename_or_edition(self):
        parser = bytes.fromhex('dde5dd210000dd393af586186eaf32f3863e02dd6e0495c29e11'
                               '3e0132f586c39e11dd7e043c32f4863e0232f586')
        mmu = bytes.fromhex('3e85ed393a3e38ed393811')
        registry = {'modem_bell212a': Patch('Bell 212A', lambda chips: None, ('mtr1',), 'bell212a')}
        with patch.dict('firmware_patcher.catalog.PATCHES', registry, clear=True):
            for code, offset in ((b'', None), (parser, len(mmu)),
                                 (parser[:-2] + b'\0\0', None)):
                rom = (mmu + code).ljust(0x40000, b'\0')
                session = self.upload(('TTY.bin', rom))
                self.assertEqual(session['firmware']['tty_rx_offset'], offset)
                tty = session['applicable_patches'][0]['modem_targets']['outbound_tty']
                self.assertFalse(tty['available'])
                self.assertIn('stock outbound', tty['reason'])

    def test_modem_picker_and_target_validation(self):
        stock = self.rom('06CNB03.bin')
        result = self.upload(('stock.bin', stock))
        url = '/sessions/' + result['session_id']
        options = {p['modem_mode']: p for p in self.client.get(url + '/patches').json()}
        self.assertEqual(set(options), {'bell212a', 'bell103'})
        all_modes = {p['modem_mode']: p for p in self.client.get('/patches').json()}
        self.assertEqual(all_modes['v21']['platforms'], ['mtr2'])
        self.assertEqual(all_modes['v22']['platforms'], ['mtr2'])
        self.assertEqual(all_modes['v22bis']['platforms'], ['mtr2'])
        bell103 = options['bell103']
        self.assertTrue(bell103['verification_available'])
        targets = bell103['modem_targets']
        self.assertTrue(targets['inbound_ncc']['available'])
        self.assertTrue(targets['outbound_tty']['available'])
        self.assertEqual(result['firmware']['tty_rx_kind'], 'cnb_banked')
        self.assertEqual(result['firmware']['tty_rx_offset'], 0x38146)
        response = self.client.post(url + '/builds', json={'patches': [bell103['id']], 'modem_targets': ['inbound_ncc', 'outbound_tty']})
        self.assertEqual(response.status_code, 201, response.text)
        request = {'patches': [bell103['id']], 'modem_targets': ['inbound_ncc']}
        for mode in ('v21', 'v22'):
            for model in (None, '73k222bl'):
                rejected = self.client.post(url + '/builds', json={
                    'patches': [f'modem_{mode}'], 'modem_model': model})
                self.assertEqual(rejected.status_code, 422, rejected.text)
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
            response = self.client.post(url + '/jobs', json=dict(request, modem_targets=['outbound_ncc']))
            self.assertEqual(response.status_code, 422, response.text)
            self.assertIn('requires inbound_ncc', response.json()['detail'])
        response = self.client.post(url + '/builds', json=request)
        self.assertEqual(response.status_code, 201, response.text)
        build = response.json()
        self.assertEqual(build['manifest']['modem_targets'], ['inbound_ncc'])
        self.assertEqual(build['patches'], ['modem_bell103'])
        for legacy in ({'patches': ['call_in']}, {'patches': ['call_in_bell103_lab']},
                       {'patches': ['modem_bell103'], 'modem_targets': ['call_in']}):
            rejected = self.client.post(url + '/builds', json=legacy)
            self.assertEqual(rejected.status_code, 422, rejected.text)
        self.assertEqual(build['manifest']['modem_mode'], 'bell103')
        self.assertFalse(build['manifest']['audio_negotiation_verified'])
        image = self.client.get(build['download_url']).content
        self.assertEqual(sha256(image).hexdigest(), build['manifest']['output_sha256'])
        self.assertEqual(self.client.get(url + '/originals/0').content, stock)

    def test_73k212sl_ip_filters_patch_options_and_builds(self):
        rom = self.rom('06CNB03.bin')
        model = '73k212sl-ip'
        response = self.client.post('/sessions', params={'modem_model': model}, files={'files': ('stock.bin', rom)})
        self.assertEqual(response.status_code, 201, response.text)
        session = response.json()
        url = '/sessions/' + session['session_id']
        self.assertEqual({p['modem_mode'] for p in session['applicable_patches']}, {'bell212a', 'bell103'})
        self.assertEqual(self.client.get(url + '/patches', params={'modem_model': model}).json(),
                         session['applicable_patches'])
        for patch_id, status in (('modem_bell212a', 201), ('modem_bell103', 201),
                                 ('modem_v21', 422), ('modem_v22', 422)):
            response = self.client.post(url + '/builds', json={'patches': [patch_id], 'modem_model': model})
            self.assertEqual(response.status_code, status, response.text)

    def test_v22bis_rate_without_data_port_dialer(self):
        for stock, faster in ((0x0b, 0x0a), (0x0c, 0x0b)):
            report = {'shared_ncc_tty_uart_300_candidate': {'stock_cntlb': hex(stock)},
                      'dph_uart_signature_matches': []}
            self.assertEqual(uart_rates(report, 'v22bis'), (stock, faster, 2400))
            report['dph_uart_signature_matches'].append({'cntlb_1200': hex(stock), 'cntlb_2400': hex(stock)})
            with self.assertRaisesRegex(ValueError, 'no consistent 2400'):
                uart_rates(report, 'v22bis')

    def test_v22_family_outbound_options(self):
        chips = [self.rom(f'Millennium Firmwares/NOA1X01V1.3-f{i}.BIN') for i in (0, 1)]
        session = self.upload(*[(f'chip{i}.bin', chip) for i, chip in enumerate(chips)])
        url = '/sessions/' + session['session_id']
        modes = {p['modem_mode']: p for p in session['applicable_patches']}
        self.assertNotIn('bell103', modes)
        for mode, rate in (('v22', 1200), ('v22bis', 2400)):
            option = modes[mode]
            self.assertTrue(option['modem_targets']['outbound_ncc']['available'])
            self.assertTrue(option['modem_targets']['outbound_tty']['available'])
            for targets in (['outbound_ncc'], ['inbound_ncc', 'outbound_ncc', 'outbound_tty']):
                response = self.client.post(url + '/builds', json={'patches': [option['id']], 'modem_targets': targets})
                self.assertEqual(response.status_code, 201, response.text)
                manifest = response.json()['manifest']
                self.assertEqual(manifest['uart']['answer_bps'], rate)
                self.assertFalse(manifest['audio_negotiation_verified'])
                self.assertTrue(any(p['label'] == 'lab_outbound_mark_hook' for p in manifest['patches']))

    def test_compose_outbound_targets_after_call_in(self):
        chips = [self.rom(f'Millennium Firmwares/NOA1X01V1.3-f{i}.BIN') for i in (0, 1)]
        session = self.upload(*[(f'chip{i}.bin', chip) for i, chip in enumerate(chips)])
        url = '/sessions/' + session['session_id']
        lab = next(p for p in session['applicable_patches'] if p['id'] == 'modem_v21')
        self.assertTrue(lab['modem_targets']['outbound_ncc']['available'])
        self.assertTrue(lab['modem_targets']['outbound_tty']['available'])
        for targets in (['inbound_ncc'], ['inbound_ncc', 'outbound_ncc'], ['inbound_ncc', 'outbound_tty'],
                        ['inbound_ncc', 'outbound_tty', 'outbound_ncc']):
            response = self.client.post(url + '/builds', json={'patches': [lab['id']], 'modem_targets': targets})
            self.assertEqual(response.status_code, 201, response.text)
            build = response.json()
            manifest = build['manifest']
            self.assertEqual(manifest['modem_targets'], sorted(targets))
            self.assertEqual('lab_outbound' in manifest, len(targets) > 1)
            replay = bytearray(b''.join(chips))
            for p in manifest['patches']:
                old, new = bytes.fromhex(p['expected']), bytes.fromhex(p['replacement'])
                i = p['offset']
                self.assertEqual(replay[i:i+len(old)], old, p['label'])
                replay[i:i+len(old)] = new
            self.assertEqual(self.client.get(build['download_url']).content, replay)

    def test_outbound_only_does_not_install_or_replace_call_in(self):
        stock = self.rom('06CNB03.bin')
        request = {'patches': ['modem_bell103'], 'modem_targets': ['outbound_ncc']}
        session = self.upload(('stock.bin', stock))
        url = '/sessions/' + session['session_id']
        result = self.client.post(url + '/builds', json=request)
        self.assertEqual(result.status_code, 201, result.text)
        outbound = self.client.get(result.json()['download_url']).content
        self.assertFalse(identify([outbound])['call_in_detected'])

        result = self.client.post(url + '/builds', json={'patches': ['modem_bell212a']})
        self.assertEqual(result.status_code, 201, result.text)
        incoming = self.client.get(result.json()['download_url']).content
        session = self.upload(('already-patched.bin', incoming))
        self.assertTrue(session['firmware']['call_in_detected'])
        lab = next(p for p in session['applicable_patches'] if p['id'] == 'modem_bell103')
        self.assertFalse(lab['modem_targets']['inbound_ncc']['available'])
        self.assertTrue(lab['modem_targets']['outbound_ncc']['available'])
        result = self.client.post('/sessions/' + session['session_id'] + '/builds', json=request)
        self.assertEqual(result.status_code, 201, result.text)
        self.assertTrue(result.json()['manifest']['preserved_existing_call_in'])
        self.assertTrue(identify([self.client.get(result.json()['download_url']).content])['call_in_detected'])

    def test_compact_outbound_hooks_fit_06cnb03(self):
        rom = self.rom('06CNB03.bin')
        session = self.upload(('stock.bin', rom))
        response = self.client.post('/sessions/' + session['session_id'] + '/builds', json={
            'patches': ['modem_bell103'], 'modem_targets': ['inbound_ncc', 'outbound_ncc', 'outbound_tty'],
        })
        self.assertEqual(response.status_code, 201, response.text)
        helper = response.json()['manifest']['lab_outbound']
        self.assertEqual(helper['selector'], 0x4fa0)
        self.assertLessEqual(helper['selector'] + helper['bytes'], 0x5000)

    def test_mtr1_preservation_build_and_restart(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        result = self.upload(('not-the-firmware-version.bin', rom))
        self.assertEqual(result['firmware']['firmware_version'], '06CNB03')
        self.assertEqual(result['firmware']['firmware_revision'], 'V1.0')
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT firmware_version, firmware_revision FROM sessions WHERE id = ?',
                                          (result['session_id'],)).fetchone(), ('06CNB03', 'V1.0'))
        self.assertEqual(result['firmware']['terminal_revision'], 'mtr1')
        self.assertTrue(result['patches']['modem_bell212a']['available'])
        self.assertEqual(result['session_id'], self.upload(('rename.bin', rom))['session_id'])
        session = '/sessions/' + result['session_id']
        self.assertEqual(self.client.get('/patches').json()[0]['id'], 'modem_bell212a')
        for patches in ([], ['string_edit'], ['modem_bell212a', 'modem_bell212a']):
            r = self.client.post(session + '/builds', json={'patches': patches})
            self.assertEqual(r.status_code, 422, r.text)
        r = self.client.post(session + '/builds', json={'patches': ['modem_bell212a']})
        self.assertEqual(r.status_code, 201, r.text)
        build = r.json()
        original_hash = sha256(rom).hexdigest()
        output_hash = build['manifest']['output_sha256']
        catalog = self.client.get('/firmwares').json()
        self.assertEqual(len(catalog), 1)
        self.assertEqual((catalog[0]['version'], catalog[0]['revision']), ('06CNB03', 'V1.0'))
        self.assertEqual({b['hash'] for b in catalog[0]['binaries']}, {original_hash, output_hash})
        self.assertTrue(all(b['updated_at'].endswith('Z') for b in catalog[0]['binaries']))
        self.assertEqual(self.client.get('/firmwares/' + original_hash).content, rom)
        self.assertEqual(self.client.get('/firmwares/' + output_hash).content,
                         self.client.get(build['download_url']).content)
        self.assertEqual(self.client.get('/firmwares/' + 'a'*64).status_code, 404)
        with TestClient(create_app(self.db)) as restarted:
            self.assertEqual(restarted.get(session).json(), result)
            self.assertEqual(restarted.get(session + '/originals/0').content, rom)
            self.assertEqual(restarted.get(session + '/builds/' + build['build_id']).json(), build)
            image = restarted.get(build['download_url']).content
            self.assertNotEqual(image, rom)
            self.assertEqual(len(image), len(rom))
            self.assertEqual(sha256(image).hexdigest(), build['manifest']['output_sha256'])

    def test_mtr2_split_matches_merged_build(self):
        a, b = [self.rom(f'Millennium Firmwares/NSA1X03V1.3-f{i}.BIN') for i in (1, 2)]
        split = self.upload(('flash0.bin', a), ('flash1.bin', b))
        merged = self.upload(('merged.bin', a+b))
        self.assertEqual(split['firmware'], merged['firmware'])
        self.assertEqual(split['firmware']['terminal_revision'], 'mtr2')
        self.assertEqual(split['firmware']['firmware_version'], 'NSA1X03')
        self.assertNotEqual(split['session_id'], merged['session_id'])
        reversed_chips = self.upload(('flash1.bin', b), ('flash0.bin', a))
        self.assertFalse(reversed_chips['patches']['modem_bell212a']['available'])
        outputs = []
        for record in (split, merged):
            r = self.client.post('/sessions/' + record['session_id'] + '/builds', json={'patches': ['modem_bell212a']})
            self.assertEqual(r.status_code, 201, r.text)
            outputs.append(self.client.get(r.json()['download_url']).content)
        self.assertEqual(*outputs)
        self.assertEqual(outputs[0][0x80000:], b)

    def test_metadata_and_unknown_archival(self):
        identity = identify([b'05<NQA1X01V1.3ABCDEFG1234\0'])
        self.assertEqual(identity['terminal_type'], 'CPC')
        self.assertEqual(identity['header_variant_code'], '05')
        self.assertIsNone(identity['terminal_revision'])
        for name, image in [('unknown.bin', b'mystery bytes'), ('bad.hex', b':invalid')]:
            data = self.upload((name, image))
            self.assertFalse(data['patches']['modem_bell212a']['available'])
            url = '/sessions/' + data['session_id']
            self.assertEqual(self.client.get(url + '/originals/0').content, image)
            self.assertEqual(self.client.post(url + '/builds', json={'patches': ['modem_bell212a']}).status_code, 422)
        self.assertEqual(self.client.get('/sessions/' + 'a'*64).status_code, 404)
        self.assertEqual(self.client.post('/sessions', content=b'x'*(MAX_BODY+1)).status_code, 413)

    def test_catalog_tracks_upload_and_build_roles_without_duplicate_hashes(self):
        stock = b'02<NLA1X05V1.3ABCDEFG1234\0stock'
        patched = stock + b'patched'
        stock_hash = sha256(stock).hexdigest()
        patched_hash = sha256(patched).hexdigest()
        session = self.upload(('stock.bin', stock))['session_id']
        with closing(sqlite3.connect(self.db)) as conn, conn:
            store_build(conn, session, ['modem_bell212a'], patched, {'output_sha256': patched_hash})
            store_build(conn, session, ['call_in'], patched, {'output_sha256': patched_hash})
            store_build(conn, session, ['modem_bell212a'], patched,
                        {'output_sha256': patched_hash, 'verification': {'boot': True}})

        def catalog_roles():
            groups = self.client.get('/firmwares').json()
            self.assertEqual(len(groups), 1)
            group = groups[0]
            self.assertEqual((group['version'], group['revision']), ('NLA1X05', 'V1.3'))
            self.assertEqual(len(group['binaries']), 2)
            entries = {entry['hash']: entry for entry in group['binaries']}
            self.assertEqual(set(entries[stock_hash]), {'hash', 'updated_at', 'provenance'})
            self.assertEqual(entries[patched_hash]['applied_patches'], ['call_in', 'modem_bell212a'])
            return {digest: entry['provenance'] for digest, entry in entries.items()}

        self.assertEqual(catalog_roles(), {stock_hash: 'source', patched_hash: 'patched'})
        for digest, provenance, content in ((stock_hash, 'source', stock), (patched_hash, 'patched', patched)):
            response = self.client.get('/firmwares/' + digest)
            self.assertEqual(response.content, content)
            self.assertEqual(response.headers['content-disposition'],
                             f'attachment; filename="{provenance}-NLA1X05-V1.3.bin"')
        self.upload(('patched.bin', patched))
        self.assertEqual(catalog_roles(), {stock_hash: 'source', patched_hash: 'source_and_patched'})
        self.assertEqual(self.client.get('/firmwares/' + patched_hash).headers['content-disposition'],
                         'attachment; filename="source_and_patched-NLA1X05-V1.3.bin"')

    def test_download_by_hash_names_unidentified_firmware(self):
        data = b'unidentified dump'
        self.upload(('unnamed.bin', data))
        response = self.client.get('/firmwares/' + sha256(data).hexdigest())
        self.assertEqual(response.content, data)
        self.assertEqual(response.headers['content-disposition'],
                         'attachment; filename="source-unknown-unknown.bin"')

    def test_queued_build_and_notification(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        session = self.upload(('rom.bin', rom))['session_id']
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1', 'FIRMWARE_EMAIL_ENABLED': '1'}):
            r = self.client.post(f'/sessions/{session}/jobs', json={'patches': ['modem_bell212a'], 'notify': True})
        self.assertEqual(r.status_code, 202, r.text)
        url = r.headers['Location']
        self.assertEqual(self.client.get(url).json()['status'], 'queued')

        def verifier(image, manifest, rings, url_arg):
            self.assertEqual(rings, 3)
            self.assertEqual(self.client.get(url).json()['status'], 'verifying')
            self.assertEqual(sha256(image).hexdigest(), manifest['output_sha256'])
            return {'boot': True}

        with closing(sqlite3.connect(self.db)) as conn:
            self.assertTrue(process_one(conn, 'unused', verifier))
            with patch('firmware_patcher.jobs.notify') as notify:
                send_one(conn)
                notify.assert_called_once_with(r.json()['job_id'], 'succeeded')
        status = self.client.get(url).json()
        self.assertEqual((status['status'], status['notification']), ('succeeded', 'sent'))
        self.assertTrue(status['build']['manifest']['verification']['boot'])

    def test_queued_bell103_runs_lab_verifier_on_selected_targets(self):
        rom = self.rom('06CNB03.bin')
        session = self.upload(('rom.bin', rom))['session_id']
        targets = ['inbound_ncc', 'outbound_ncc', 'outbound_tty']
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
            response = self.client.post(f'/sessions/{session}/jobs', json={
                'patches': ['modem_bell103'], 'modem_targets': targets, 'rings': 4,
            })
        self.assertEqual(response.status_code, 202, response.text)
        url = response.json()['status_url']
        self.assertEqual(self.client.get(url).json()['modem_targets'], targets)

        def check(image, manifest, rings, emulator_url):
            self.assertEqual(manifest['modem_targets'], targets)
            self.assertEqual(manifest['uart']['answer_bps'], 300)
            self.assertEqual(sha256(image).hexdigest(), manifest['output_sha256'])
            self.assertEqual((rings, emulator_url), (4, 'unused'))
            self.assertEqual(self.client.get(url).json()['status'], 'verifying')
            return {'boot': True, 'audio_negotiation_tested': False}

        with closing(sqlite3.connect(self.db)) as conn, patch('firmware_patcher.jobs.verify_candidate', side_effect=check) as lab:
            self.assertTrue(process_one(conn, 'unused'))
            lab.assert_called_once()
        status = self.client.get(url).json()
        self.assertEqual(status['status'], 'succeeded', status)
        self.assertFalse(status['build']['manifest']['verification']['audio_negotiation_tested'])

    def test_failed_verification_has_no_build(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        session = self.upload(('rom.bin', rom))['session_id']
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
            job = self.client.post(f'/sessions/{session}/jobs', json={'patches': ['modem_bell212a']}).json()
        with closing(sqlite3.connect(self.db)) as conn:
            def fail(*args):
                raise ValueError('no boot display')
            self.assertTrue(process_one(conn, 'unused', fail))
            self.assertEqual(conn.execute('SELECT count(*) FROM builds').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT stage, session_id, job_id, message FROM error_log').fetchone(),
                             ('verifying', session, job['job_id'], 'no boot display'))
        status = self.client.get(job['status_url']).json()
        self.assertEqual(status['status'], 'failed')
        self.assertIn('no boot display', status['error'])

    def test_legacy_archive_backfills_from_original_header(self):
        db = self.db.with_name('legacy.sqlite3')
        with closing(sqlite3.connect(db)) as conn, conn:
            conn.executescript('''
                CREATE TABLE blobs (sha TEXT PRIMARY KEY, data BLOB NOT NULL);
                CREATE TABLE sessions (id TEXT PRIMARY KEY, sources TEXT NOT NULL);
            ''')
            for session_id, data, encoding in [('a'*64, b'07<NPA1S01V1.0\0', 'binary'),
                                               ('b'*64, b':malformed', 'ihex')]:
                digest = sha256(data).hexdigest()
                sources = [{'sha256': digest, 'encoding': encoding, 'name': 'unrelated-name.bin',
                            'index': 0, 'size': len(data)}]
                conn.execute('INSERT INTO blobs VALUES (?, ?)', (digest, data))
                conn.execute('INSERT INTO sessions VALUES (?, ?)', (session_id, json.dumps(sources)))
        with TestClient(create_app(db)) as migrated:
            url = '/sessions/' + 'a'*64
            self.assertEqual(migrated.get(url).json()['firmware']['firmware_version'], 'NPA1S01')
            self.assertEqual(migrated.get(url + '/originals/0').content, b'07<NPA1S01V1.0\0')
            self.assertIsNone(migrated.get('/firmwares').json()[0]['binaries'][0]['updated_at'])
        with closing(sqlite3.connect(db)) as conn:
            self.assertEqual(conn.execute('SELECT firmware_version, firmware_revision FROM sessions ORDER BY id').fetchall(),
                             [('NPA1S01', 'V1.0'), (None, None)])


if __name__ == '__main__':
    unittest.main()
