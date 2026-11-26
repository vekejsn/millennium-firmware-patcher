"""Submit local ROM fixtures to a running patch service. No third-party dependencies."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from time import monotonic, sleep
from urllib.request import Request, urlopen
from uuid import uuid4


def smoke(url, path, rings):
    def request(route, body=None, content_type='application/json'):
        with urlopen(Request(url.rstrip('/') + route, data=body,
                             headers={'Content-Type': content_type}), timeout=15) as result:
            return result.read()

    boundary = uuid4().hex
    original = path.read_bytes()
    prefix = f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="stock.bin"\r\n\r\n'
    session = json.loads(request('/sessions', prefix.encode() + original + f'\r\n--{boundary}--\r\n'.encode(),
                                 'multipart/form-data; boundary=' + boundary))
    job = json.loads(request(f"/sessions/{session['session_id']}/jobs",
                             json.dumps({'patches': ['call_in'], 'rings': rings}).encode()))
    print(path.name, job['status_url'], flush=True)
    deadline = monotonic() + 210
    while monotonic() < deadline:
        result = json.loads(request(job['status_url']))
        if result['status'] == 'failed':
            raise SystemExit(result['error'])
        if result['status'] == 'succeeded':
            build = result['build']
            artifact = request(build['download_url'])
            assert sha256(artifact).hexdigest() == build['manifest']['output_sha256']
            assert artifact != original
            assert request(f"/sessions/{session['session_id']}/originals/0") == original
            print(json.dumps(build['manifest']['verification'], sort_keys=True), flush=True)
            return
        sleep(1)
    raise SystemExit('timed out waiting for queued job')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', default='http://127.0.0.1:8001')
    parser.add_argument('--rings', default=3, type=int)
    parser.add_argument('roms', type=Path, nargs='+')
    args = parser.parse_args()
    for rom in args.roms:
        smoke(args.url, rom, args.rings)
