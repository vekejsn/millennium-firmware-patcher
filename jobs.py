"""SQLite-backed queue and single-worker processing for the private emulator."""
from contextlib import closing
from email.message import EmailMessage
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import smtplib
import sqlite3
import ssl
from time import sleep

from .catalog import PATCHES, decode_upload
from .emulator import verify
from .archive import record_error, save_blob


SCHEMA = '''CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY, session TEXT NOT NULL, patch TEXT NOT NULL, rings INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, build_id TEXT, error TEXT,
    notification TEXT NOT NULL DEFAULT 'not_requested'
); CREATE INDEX IF NOT EXISTS jobs_status ON jobs (status, created_at);'''


def store_build(conn, session_id, patches, image, manifest):
    info = dict(session_id=session_id, patches=patches, manifest=manifest)
    build_id = sha256(json.dumps(info, sort_keys=True).encode()).hexdigest()
    info.update(build_id=build_id, download_url=f'/sessions/{session_id}/builds/{build_id}/rom')
    save_blob(conn, manifest['output_sha256'], image)
    conn.execute('INSERT OR IGNORE INTO builds VALUES (?, ?, ?, ?)',
                 (session_id, build_id, manifest['output_sha256'], json.dumps(info)))
    return info


def notify(job, status):
    msg = EmailMessage()
    msg['From'] = os.environ['SMTP_FROM']
    msg['To'] = os.environ['SMTP_TO']
    msg['Subject'] = f'Millennium patch job {status}'
    path = f'/jobs/{job}'
    base = os.environ.get('PUBLIC_API_URL', 'http://127.0.0.1:8001').rstrip('/')
    msg.set_content(f'Patch job {status}.\n\nStatus and results: {base}{path}\n')
    with smtplib.SMTP(os.environ['SMTP_HOST'], int(os.environ.get('SMTP_PORT', '587')), timeout=10) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        if os.environ.get('SMTP_USER'):
            smtp.login(os.environ['SMTP_USER'], os.environ['SMTP_PASSWORD'])
        if smtp.send_message(msg):
            raise RuntimeError('SMTP recipient refused')


def process_one(conn, emulator_url, verifier=verify):
    row = conn.execute('''UPDATE jobs SET status='patching', updated_at=CURRENT_TIMESTAMP
                         WHERE id=(SELECT id FROM jobs WHERE status='queued' ORDER BY created_at,rowid LIMIT 1)
                         RETURNING id,session,patch,rings''').fetchone()
    conn.commit()
    if row is None:
        return False
    job, session, patch, rings = row
    phase = 'patching'
    try:
        sources = json.loads(conn.execute('SELECT sources FROM sessions WHERE id=?', (session,)).fetchone()[0])
        chips = [decode_upload(conn.execute('SELECT data FROM blobs WHERE sha=?', (s['sha256'],)).fetchone()[0],
                               s['encoding']) for s in sources]
        selected = PATCHES.get(patch)
        if selected is None:
            raise ValueError('unknown patch selection; submit a new job using GET /patches')
        if not selected.verification_available:
            raise ValueError('lab probe is not eligible for queued verification')
        image, manifest = selected.apply(chips)
        with conn:
            conn.execute("UPDATE jobs SET status='verifying', updated_at=CURRENT_TIMESTAMP WHERE id=?", (job,))
        phase = 'verifying'
        manifest['verification'] = verifier(image, manifest, rings, emulator_url)
        with conn:
            build = store_build(conn, session, [patch], image, manifest)
            conn.execute("UPDATE jobs SET status='succeeded', build_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (build['build_id'], job))
    except Exception as error:
        detail = str(error)[:500] if isinstance(error, ValueError) else 'worker or emulator unavailable; see worker log'
        if not isinstance(error, ValueError):
            logging.exception('job %s failed during %s', job, phase)
        with conn:
            record_error(conn, phase, str(error) if isinstance(error, ValueError) else type(error).__name__,
                         session_id=session, job_id=job)
            conn.execute("UPDATE jobs SET status='failed', error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                         (f'{phase}: {detail}', job))
    return True


def send_one(conn):
    row = conn.execute('''UPDATE jobs SET notification='sending' WHERE id=(SELECT id FROM jobs
                        WHERE notification='pending' AND status IN ('succeeded','failed') ORDER BY updated_at LIMIT 1)
                        RETURNING id,status,session''').fetchone()
    conn.commit()
    if row is None:
        return
    job, status, session = row
    error_type = None
    try:
        notify(job, status)
        delivery = 'sent'
    except Exception as error:
        error_type = type(error).__name__  # SMTP responses may contain addresses or credentials.
        delivery = 'failed'
    with conn:
        if error_type:
            record_error(conn, 'notification', error_type, session_id=session, job_id=job)
        conn.execute('UPDATE jobs SET notification=? WHERE id=?', (delivery, job))


def main():
    import fcntl  # worker runs in the Linux container
    db = Path(os.environ['FIRMWARE_PATCHER_DB'])
    with db.with_suffix('.worker.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(sqlite3.connect(db, timeout=20)) as conn:
            with conn:
                conn.execute("UPDATE jobs SET status='queued', updated_at=CURRENT_TIMESTAMP WHERE status IN ('patching','verifying')")
                conn.execute("UPDATE jobs SET notification='unknown' WHERE notification='sending'")
            while True:
                busy = process_one(conn, os.environ.get('EMULATOR_URL', 'http://127.0.0.1:8787'))
                send_one(conn)
                if not busy:
                    sleep(0.5)


if __name__ == '__main__':
    main()
