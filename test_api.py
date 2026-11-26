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

    def test_applicable_patches_follow_detected_platform_and_rom_checks(self):
        mtr1 = bytes.fromhex('3e85ed393a3e38ed393811').ljust(0x40000, b'\0')
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

    def test_mtr1_preservation_build_and_restart(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        result = self.upload(('not-the-firmware-version.bin', rom))
        self.assertEqual(result['firmware']['firmware_version'], '06CNB03')
        self.assertEqual(result['firmware']['firmware_revision'], 'V1.0')
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT firmware_version, firmware_revision FROM sessions WHERE id = ?',
                                          (result['session_id'],)).fetchone(), ('06CNB03', 'V1.0'))
        self.assertEqual(result['firmware']['terminal_revision'], 'mtr1')
        self.assertTrue(result['patches']['call_in']['available'])
        self.assertEqual(result['session_id'], self.upload(('rename.bin', rom))['session_id'])
        session = '/sessions/' + result['session_id']
        self.assertEqual(self.client.get('/patches').json()[0]['id'], 'call_in')
        for patches in ([], ['string_edit'], ['call_in', 'call_in']):
            r = self.client.post(session + '/builds', json={'patches': patches})
            self.assertEqual(r.status_code, 422, r.text)
        r = self.client.post(session + '/builds', json={'patches': ['call_in']})
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
        self.assertFalse(reversed_chips['patches']['call_in']['available'])
        outputs = []
        for record in (split, merged):
            r = self.client.post('/sessions/' + record['session_id'] + '/builds', json={'patches': ['call_in']})
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
            self.assertFalse(data['patches']['call_in']['available'])
            url = '/sessions/' + data['session_id']
            self.assertEqual(self.client.get(url + '/originals/0').content, image)
            self.assertEqual(self.client.post(url + '/builds', json={'patches': ['call_in']}).status_code, 422)
        self.assertEqual(self.client.get('/sessions/' + 'a'*64).status_code, 404)
        self.assertEqual(self.client.post('/sessions', content=b'x'*(MAX_BODY+1)).status_code, 413)

    def test_catalog_tracks_upload_and_build_roles_without_duplicate_hashes(self):
        stock = b'02<NLA1X05V1.3ABCDEFG1234\0stock'
        patched = stock + b'patched'
        stock_hash = sha256(stock).hexdigest()
        patched_hash = sha256(patched).hexdigest()
        session = self.upload(('stock.bin', stock))['session_id']
        with closing(sqlite3.connect(self.db)) as conn, conn:
            store_build(conn, session, ['call_in'], patched, {'output_sha256': patched_hash})

        def catalog_roles():
            groups = self.client.get('/firmwares').json()
            self.assertEqual(len(groups), 1)
            group = groups[0]
            self.assertEqual((group['version'], group['revision']), ('NLA1X05', 'V1.3'))
            self.assertEqual(len(group['binaries']), 2)
            for entry in group['binaries']:
                self.assertEqual(set(entry), {'hash', 'updated_at', 'provenance'})
            return {entry['hash']: entry['provenance'] for entry in group['binaries']}

        self.assertEqual(catalog_roles(), {stock_hash: 'source', patched_hash: 'patched'})
        self.upload(('patched.bin', patched))
        self.assertEqual(catalog_roles(), {stock_hash: 'source', patched_hash: 'source_and_patched'})

    def test_queued_build_and_notification(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        session = self.upload(('rom.bin', rom))['session_id']
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1', 'FIRMWARE_EMAIL_ENABLED': '1'}):
            r = self.client.post(f'/sessions/{session}/jobs', json={'patches': ['call_in'], 'notify': True})
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

    def test_failed_verification_has_no_build(self):
        rom = self.rom('06CNB03_UART_recovery.bin')
        session = self.upload(('rom.bin', rom))['session_id']
        with patch.dict('os.environ', {'FIRMWARE_QUEUE_ENABLED': '1'}):
            job = self.client.post(f'/sessions/{session}/jobs', json={'patches': ['call_in']}).json()
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
