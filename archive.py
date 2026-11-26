"""Shared SQLite helpers for saved bytes and operational errors."""
import logging


ERROR_SCHEMA = '''CREATE TABLE IF NOT EXISTS error_log (
    id INTEGER PRIMARY KEY, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    stage TEXT NOT NULL, session_id TEXT, job_id TEXT, message TEXT NOT NULL
);'''


def save_blob(conn, digest, data):
    conn.execute('''INSERT INTO blobs (sha, data, updated_at)
                    VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                    ON CONFLICT(sha) DO UPDATE SET updated_at=excluded.updated_at''', (digest, data))


def record_error(conn, stage, message, *, session_id=None, job_id=None):
    message = ' '.join(message.split())[:500]
    logging.warning('%s failed (session=%s job=%s): %s', stage, session_id, job_id, message)
    conn.execute('INSERT INTO error_log (stage,session_id,job_id,message) VALUES (?,?,?,?)',
                 (stage, session_id, job_id, message))
