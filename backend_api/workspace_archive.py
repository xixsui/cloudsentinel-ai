"""Versioned data-only archives. Never executes SQL/schema supplied by an archive."""
import hashlib
import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ai_module.database import Database
from ai_module.scan_history import ScanHistory
from ai_module.remediation_tracker import RemediationTracker
from ai_module.advisor_v07 import _init_history, _init_feedback
from ai_module.scan_snapshots import initialize

LIMIT = 20 * 1024 * 1024
TABLES = ('findings', 'scan_runs', 'scan_observations', 'scan_finding_links',
          'scan_snapshot_runs', 'scan_finding_snapshots', 'remediation_cases',
          'remediation_activity', 'ai_analysis', 'advisor_runs_v07',
          'advisor_feedback_v09', 'incidents', 'incident_activity')


def prepare(path):
    db = Database(path)
    ScanHistory(path)
    RemediationTracker(path)
    _init_history(db)
    _init_feedback(db)
    with sqlite3.connect(path) as con:
        initialize(con)


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def export_data(path):
    prepare(path)
    with sqlite3.connect(path) as con:
        con.row_factory = sqlite3.Row
        con.execute('BEGIN')
        tables = {name: [dict(row) for row in con.execute(f'SELECT * FROM {name}')]
                  for name in TABLES}
    result = {'format': 'cloudsentinel-workspace', 'version': 1,
              'created_at': datetime.now(timezone.utc).isoformat(), 'tables': tables}
    if len(encode(result)) > LIMIT:
        raise ValueError('Workspace exceeds the 20 MB archive limit. Use a private offline database backup.')
    return result


def validate(data):
    if not isinstance(data, dict) or set(data) != {'format', 'version', 'created_at', 'tables'}:
        raise ValueError('Invalid workspace archive structure.')
    if data['format'] != 'cloudsentinel-workspace' or type(data['version']) is not int or data['version'] != 1:
        raise ValueError('Unsupported archive format or version.')
    if not isinstance(data['created_at'], str):
        raise ValueError('Invalid archive date.')
    datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
    raw = encode(data)
    if len(raw) > LIMIT:
        raise ValueError('Archive exceeds 20 MB.')
    tables = data['tables']
    if not isinstance(tables, dict) or set(tables) != set(TABLES):
        raise ValueError('Archive tables do not match this version.')
    # Apply to a disposable database built solely from trusted application schema.
    with tempfile.TemporaryDirectory(prefix='cloudsentinel-validate-') as folder:
        path = Path(folder) / 'validation.db'
        prepare(path)
        with sqlite3.connect(path) as con:
            total = 0
            for name in TABLES:
                rows = tables[name]
                if not isinstance(rows, list):
                    raise ValueError('Invalid archive rows.')
                total += len(rows)
                if total > 100000:
                    raise ValueError('Archive exceeds 100,000 records.')
                columns = [r[1] for r in con.execute(f'PRAGMA table_info({name})')]
                for row in rows:
                    if not isinstance(row, dict) or set(row) != set(columns):
                        raise ValueError('Archive columns do not match this version.')
                    if any(type(v) not in (str, int, float, type(None)) for v in row.values()):
                        raise ValueError('Invalid archive field type.')
                insert(con, name, rows, columns)
            if con.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('Archive contains invalid references.')
        db = Database(path)
        db.get_findings()
        db.get_incidents()
        for row in tables['ai_analysis']:
            db.get_analysis(row['finding_id'])
        history = ScanHistory(path)
        for row in tables['scan_runs']:
            history.get(row['id'])
        from ai_module.models import Finding
        from ai_module.remediation_tracker import STATES
        for row in tables['scan_finding_snapshots']:
            Finding.model_validate_json(row['payload'])
        for row in tables['advisor_runs_v07']:
            if not isinstance(json.loads(row['payload']), dict):
                raise ValueError('Invalid analysis payload.')
        for row in tables['remediation_cases']:
            if row['state'] not in STATES:
                raise ValueError('Invalid remediation state.')
    return {'counts': {name: len(tables[name]) for name in TABLES},
            'created_at': data['created_at'], 'sha256': hashlib.sha256(raw).hexdigest()}


def insert(con, name, rows, columns):
    con.executemany(f'INSERT INTO {name} ({",".join(columns)}) VALUES ({",".join("?" for _ in columns)})',
                    [[row[c] for c in columns] for row in rows])


def restore(path, data, digest):
    preview = validate(data)
    if preview['sha256'] != digest:
        raise ValueError('Archive changed. Preview it again before restoring.')
    prepare(path)
    # Private, data-only recovery copy outside the project. Created before mutation.
    backup_dir = Path.home() / '.local/share/cloudsentinel/recovery'
    backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, backup = tempfile.mkstemp(prefix='before-restore-', suffix='.json', dir=backup_dir)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encode(export_data(path)))
        with sqlite3.connect(path) as con:
            con.execute('BEGIN IMMEDIATE')
            for name in reversed(TABLES):
                con.execute(f'DELETE FROM {name}')
            for name in TABLES:
                columns = [r[1] for r in con.execute(f'PRAGMA table_info({name})')]
                insert(con, name, data['tables'][name], columns)
            con.execute('DELETE FROM ai_cache')
            if con.execute("SELECT 1 FROM sqlite_master WHERE name='web_scan_jobs'").fetchone():
                con.execute('DELETE FROM web_scan_jobs')
    except Exception:
        # Keep the recovery copy even when restore rolls back.
        raise
    return {'restored': preview['counts']['findings'], 'recovery_file': str(backup)}
