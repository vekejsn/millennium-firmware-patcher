"""Local-first FastAPI service. Run with uvicorn firmware_patcher.api:app."""
from contextlib import contextmanager, asynccontextmanager
from enum import StrEnum
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
from typing import Annotated
from secrets import token_hex

from fastapi import FastAPI, File, HTTPException, Path as PathParam, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from .catalog import PATCHES, decode_upload, identify
from .jobs import SCHEMA, store_build
from .archive import ERROR_SCHEMA, record_error, save_blob


MAX_FILE = 3 * 1024 * 1024  # dense 1 MiB Intel HEX fits; decoded size is checked separately
MAX_BODY = 2 * MAX_FILE + 64 * 1024
ID = Annotated[str, PathParam(pattern=r'^[0-9a-f]{64}$')]
VERSION_FIELDS = ('firmware_version', 'firmware_revision')


class FirmwareProvenance(StrEnum):
    SOURCE = 'source'
    PATCHED = 'patched'
    SOURCE_AND_PATCHED = 'source_and_patched'


class CatalogBinary(BaseModel):
    hash: str
    updated_at: str | None
    provenance: FirmwareProvenance


class CatalogGroup(BaseModel):
    version: str | None
    revision: str | None
    binaries: list[CatalogBinary]


class BodyLimit:
    """Count bytes before multipart parsing, including bodies without Content-Length."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope['method'] != 'POST':
            return await self.app(scope, receive, send)
        parts, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            part = message.get('body', b'')
            size += len(part)
            if size > MAX_BODY:
                return await JSONResponse({'detail': 'request body too large'}, 413)(scope, receive, send)
            if part:
                parts.append(part)
            if not message.get('more_body'):
                break
        buffered = iter(parts or [b''])
        remaining = len(parts) or 1

        async def replay():
            nonlocal remaining
            if not remaining:
                return await receive()
            remaining -= 1
            return {'type': 'http.request', 'body': next(buffered), 'more_body': remaining > 0}

        return await self.app(scope, replay, send)


class BuildRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    patches: list[Annotated[str, Field(min_length=1, max_length=40)]] = Field(min_length=1, max_length=16)


class JobRequest(BuildRequest):
    rings: int = Field(default=3, ge=2, le=10)
    notify: bool = False


def session_digest(uploads):
    h = sha256(b'millennium-upload-v1\0')
    for encoding, data in uploads:
        h.update(encoding.encode('ascii') + b'\0' + sha256(data).digest())
    return h.hexdigest()


def describe(uploads):
    try:
        chips = [decode_upload(data, encoding) for encoding, data in uploads]
    except ValueError as error:
        return dict(firmware=None, patches={key: {'available': False, 'reason': str(error)} for key in PATCHES})
    capabilities = {}
    for key, patch in PATCHES.items():
        try:
            patch.build(chips)
        except ValueError as error:
            capabilities[key] = dict(available=False, reason=str(error))
        else:
            capabilities[key] = dict(available=True, reason=None)
    return dict(firmware=identify(chips), patches=capabilities)


def version_fields(firmware):
    return tuple((firmware or {}).get(field) for field in VERSION_FIELDS)


def migrate_session_versions(conn):
    """Backfill old archives from original bytes without changing IDs or builds."""
    conn.execute('BEGIN IMMEDIATE')
    columns = {row[1] for row in conn.execute('PRAGMA table_info(sessions)')}
    missing = [field for field in VERSION_FIELDS if field not in columns]
    if not missing:
        return
    for field in missing:
        conn.execute(f'ALTER TABLE sessions ADD COLUMN {field} TEXT')
    for session_id, sources in conn.execute('SELECT id, sources FROM sessions'):
        try:
            chips = [decode_upload(conn.execute('SELECT data FROM blobs WHERE sha = ?', (s['sha256'],)).fetchone()[0],
                                   s['encoding']) for s in json.loads(sources)]
        except ValueError:  # malformed HEX was still archived; leave its identity unknown
            continue
        conn.execute('UPDATE sessions SET firmware_version = ?, firmware_revision = ? WHERE id = ?',
                     (*version_fields(identify(chips)), session_id))


def binary(data, name):
    return Response(data, media_type='application/octet-stream',
                    headers={'Content-Disposition': f'attachment; filename="{name}"',
                             'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store'})


def create_app(database=None):
    db = Path(database if database is not None else os.environ.get('FIRMWARE_PATCHER_DB',
              Path(__file__).with_name('data') / 'firmware.sqlite3')).resolve()

    @contextmanager
    def connect():
        conn = sqlite3.connect(db)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @asynccontextmanager
    async def lifespan(_app):
        db.parent.mkdir(parents=True, exist_ok=True)
        with connect() as conn:
            conn.executescript('''
                CREATE TABLE IF NOT EXISTS blobs (sha TEXT PRIMARY KEY, data BLOB NOT NULL, updated_at TEXT);
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY, sources TEXT NOT NULL,
                    firmware_version TEXT, firmware_revision TEXT);
                CREATE TABLE IF NOT EXISTS builds (
                    session TEXT NOT NULL, id TEXT NOT NULL, sha TEXT NOT NULL, info TEXT NOT NULL,
                    PRIMARY KEY (session, id));
            ''')
            migrate_session_versions(conn)
            if 'updated_at' not in {row[1] for row in conn.execute('PRAGMA table_info(blobs)')}:
                conn.execute('ALTER TABLE blobs ADD COLUMN updated_at TEXT')
        with connect() as conn:
            conn.executescript(SCHEMA + ERROR_SCHEMA)
        yield

    app = FastAPI(title='Millennium Firmware Patcher', version='0.1.0', lifespan=lifespan)
    app.add_middleware(BodyLimit)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_methods=['*'],
        allow_headers=['*'],
        expose_headers=['Content-Disposition', 'Location', 'Retry-After'],
    )

    @app.exception_handler(Exception)
    def unexpected_error(request: Request, error: Exception):
        route = getattr(request.scope.get('route'), 'path', 'unknown route')
        logging.error('Unhandled API error on %s', route, exc_info=error)
        try:
            with connect() as conn:
                record_error(conn, 'api', f'{request.method} {route}: {type(error).__name__}')
        except sqlite3.Error:
            logging.exception('Could not write error to the archive database')
        return JSONResponse({'detail': 'internal server error'}, status_code=500)

    @app.get('/health')
    def health():
        return {'status': 'ok'}

    @app.post('/sessions/{session_id}/jobs', status_code=202)
    def enqueue(session_id: ID, request: JobRequest):
        source_rows(session_id)
        if len(request.patches) != 1 or request.patches[0] not in PATCHES:
            raise HTTPException(422, 'select exactly one registered patch')
        if os.environ.get('FIRMWARE_QUEUE_ENABLED') != '1':
            raise HTTPException(503, 'verification worker not configured')
        if request.notify and os.environ.get('FIRMWARE_EMAIL_ENABLED') != '1':
            raise HTTPException(422, 'email notifications are not configured')
        job = token_hex(32)
        with connect() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','patching','verifying')").fetchone()[0] >= 32:
                raise HTTPException(429, 'verification queue is full')
            conn.execute('INSERT INTO jobs (id,session,patch,rings,notification) VALUES (?,?,?,?,?)',
                         (job, session_id, request.patches[0], request.rings, 'pending' if request.notify else 'not_requested'))
        return JSONResponse(dict(job_id=job, status='queued', status_url=f'/jobs/{job}'),
                            status_code=202, headers={'Location': f'/jobs/{job}', 'Retry-After': '1'})

    @app.get('/jobs/{job_id}')
    def job_status(job_id: ID):
        with connect() as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute('''SELECT id AS job_id,session AS session_id,patch,rings,status,created_at,updated_at,
                                  build_id,error,notification FROM jobs WHERE id=?''', (job_id,)).fetchone()
        if row is None:
            raise HTTPException(404, 'job not found')
        result = dict(row)
        if result['build_id']:
            result['build'] = get_build(result['session_id'], result['build_id'])
        return result

    def session_row(session_id):
        with connect() as conn:
            result = conn.execute('SELECT sources, firmware_version, firmware_revision FROM sessions WHERE id = ?',
                                  (session_id,)).fetchone()
        if not result:
            raise HTTPException(404, 'session not found')
        return json.loads(result[0]), result[1:]

    def source_rows(session_id):
        return session_row(session_id)[0]

    def get_blob(digest):
        with connect() as conn:
            row = conn.execute('SELECT data FROM blobs WHERE sha = ?', (digest,)).fetchone()
        if row is None:
            raise HTTPException(404, 'firmware hash not found')
        return row[0]

    @app.get('/firmwares', response_model=list[CatalogGroup])
    def list_firmwares():
        with connect() as conn:
            rows = conn.execute('''
                WITH catalog(version, revision, sha, is_source, is_patched) AS (
                  SELECT s.firmware_version, s.firmware_revision, json_extract(source.value, '$.sha256'), 1, 0
                    FROM sessions s, json_each(s.sources) AS source
                  UNION ALL
                  SELECT s.firmware_version, s.firmware_revision, b.sha, 0, 1
                    FROM builds b JOIN sessions s ON s.id = b.session
                )
                SELECT version, revision, catalog.sha, blobs.updated_at, MAX(is_source), MAX(is_patched)
                  FROM catalog JOIN blobs ON blobs.sha = catalog.sha
                 GROUP BY version, revision, catalog.sha, blobs.updated_at
                 ORDER BY version IS NULL, version, revision, blobs.updated_at DESC, catalog.sha
            ''').fetchall()
        groups = {}
        for version, revision, digest, updated_at, source, patched in rows:
            group = groups.setdefault((version, revision), dict(version=version, revision=revision, binaries=[]))
            if source and patched:
                provenance = FirmwareProvenance.SOURCE_AND_PATCHED
            elif patched:
                provenance = FirmwareProvenance.PATCHED
            else:
                provenance = FirmwareProvenance.SOURCE
            group['binaries'].append(dict(hash=digest, updated_at=updated_at, provenance=provenance))
        return list(groups.values())

    @app.get('/firmwares/{digest}')
    def download_by_hash(digest: ID):
        return binary(get_blob(digest), digest)

    def session_info(session_id, sources, versions, description):
        if description['firmware'] is not None:
            description['firmware'].update(zip(VERSION_FIELDS, versions))
        return dict(session_id=session_id, sources=sources, **description)

    @app.get('/patches')
    def list_patches():
        return [{'id': key, 'label': patch.label, 'experimental': True} for key, patch in PATCHES.items()]

    @app.post('/sessions', status_code=201)
    def upload(files: Annotated[list[UploadFile], File(description='ROM, or two control chips in flash0/flash1 order')]):
        if len(files) not in (1, 2):
            raise HTTPException(422, 'upload one image or two control chips (flash0 then flash1)')
        uploads = []
        sources = []
        for index, file in enumerate(files):
            data = file.file.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                raise HTTPException(413, 'file too large')
            if not data:
                raise HTTPException(422, 'empty firmware file')
            # Keep names as metadata only. Never use them as paths or headers.
            name = re.split(r'[/\\]', file.filename or '')[-1][:255] or f'chip{index}.bin'
            encoding = 'ihex' if name.lower().endswith('.hex') else 'binary'
            if encoding == 'binary' and len(data) > 0x100000:
                raise HTTPException(413, 'binary ROM exceeds 1 MiB')
            uploads.append((encoding, data))
            sources.append(dict(index=index, name=name, encoding=encoding, size=len(data),
                                sha256=sha256(data).hexdigest()))
        session_id = session_digest(uploads)
        description = describe(uploads)
        with connect() as conn:
            for src, (_, data) in zip(sources, uploads):
                save_blob(conn, src['sha256'], data)
            conn.execute('''INSERT OR IGNORE INTO sessions (id, sources, firmware_version, firmware_revision)
                            VALUES (?, ?, ?, ?)''',
                         (session_id, json.dumps(sources), *version_fields(description['firmware'])))
        sources, versions = session_row(session_id)
        return session_info(session_id, sources, versions, description)

    @app.get('/sessions/{session_id}')
    def get_session(session_id: ID):
        sources, versions = session_row(session_id)
        return session_info(session_id, sources, versions,
                            describe([(s['encoding'], get_blob(s['sha256'])) for s in sources]))

    @app.get('/sessions/{session_id}/originals/{index}')
    def download_original(session_id: ID, index: Annotated[int, PathParam(ge=0, le=1)]):
        sources = source_rows(session_id)
        if index >= len(sources):
            raise HTTPException(404, 'original not found')
        src = sources[index]
        extension = 'hex' if src['encoding'] == 'ihex' else 'bin'
        return binary(get_blob(src['sha256']), f'original-{index}.{extension}')

    @app.post('/sessions/{session_id}/builds', status_code=201)
    def create_build(session_id: ID, request: BuildRequest):
        sources = source_rows(session_id)
        if len(set(request.patches)) != len(request.patches):
            raise HTTPException(422, 'duplicate patch selection')
        if any(key not in PATCHES for key in request.patches):
            raise HTTPException(422, 'unknown patch selection; see GET /patches')
        # Until a patch defines how it composes with other patches, never
        # silently stack builders that independently assume a stock image.
        if len(request.patches) != 1:
            raise HTTPException(422, 'these patches cannot be combined')
        try:
            chips = [decode_upload(get_blob(s['sha256']), s['encoding']) for s in sources]
            image, manifest = PATCHES[request.patches[0]].build(chips)
        except ValueError as error:
            with connect() as conn:
                record_error(conn, 'patching', str(error), session_id=session_id)
            raise HTTPException(422, str(error)) from error
        with connect() as conn:
            return store_build(conn, session_id, request.patches, image, manifest)

    def find_build(session_id, build_id):
        with connect() as conn:
            result = conn.execute('SELECT sha, info FROM builds WHERE session = ? AND id = ?',
                                  (session_id, build_id)).fetchone()
        if not result:
            raise HTTPException(404, 'build not found')
        return result

    @app.get('/sessions/{session_id}/builds/{build_id}')
    def get_build(session_id: ID, build_id: ID):
        return json.loads(find_build(session_id, build_id)[1])

    @app.get('/sessions/{session_id}/builds/{build_id}/rom')
    def download_build(session_id: ID, build_id: ID):
        digest, _ = find_build(session_id, build_id)
        return binary(get_blob(digest), f'millennium-{build_id[:12]}.bin')

    return app


app = create_app()
