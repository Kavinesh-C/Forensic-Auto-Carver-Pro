import os
import sqlite3
import io
import json
import tempfile
import shutil

import pytest
import importlib.util
import sys

# Import the app module by file path to avoid import errors under pytest
spec = importlib.util.spec_from_file_location('fac_app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
fac_app = importlib.util.module_from_spec(spec)
sys.modules['fac_app'] = fac_app
spec.loader.exec_module(fac_app)

app = fac_app.app
DB_FILE = getattr(fac_app, 'DB_FILE', None)
SESSION_FOLDER = app.config.get('SESSION_FOLDER')
_get_db_conn = fac_app._get_db_conn

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Use a temp DB and session folder for test isolation
    tmp_db = tmp_path / "test_fac_data.db"
    tmp_session = tmp_path / "session_files"
    tmp_session.mkdir()

    monkeypatch.setenv('FLASK_ENV', 'testing')
    app.config['TESTING'] = True
    # override paths
    app.config['SESSION_FOLDER'] = str(tmp_session)
    # initialize a fresh DB file for testing
    conn = sqlite3.connect(str(tmp_db))
    conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, path TEXT, size_bytes INTEGER, created_at TEXT, session_id TEXT, extra TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started_at TEXT, ended_at TEXT, active INTEGER)')
    conn.commit()
    conn.close()

    # monkeypatch the DB access function on the loaded fac_app module to use tmp_db
    def _get_tmp_db_conn():
        return sqlite3.connect(str(tmp_db))
    monkeypatch.setattr(fac_app, '_get_db_conn', _get_tmp_db_conn)
    # also override DB_FILE if referenced
    try:
        setattr(fac_app, 'DB_FILE', str(tmp_db))
    except Exception:
        pass

    with app.test_client() as c:
        yield c


def test_reporting_saves_html(client, tmp_path):
    # Ensure session has csrf token
    with client.session_transaction() as sess:
        sess['csrf_token'] = 'testtoken'

    # Ensure app believes an evidence file is uploaded so reporting proceeds
    fac_app.uploaded_files_db.clear()
    fac_app.uploaded_files_db['evidence.img'] = {'path': 'evidence.img', 'hash_info': {}, 'encryption_status': {}}

    data = {
        'case_name': 'TestCase',
        'case_number': '123',
        'examiner_name': 'Tester',
        'report_format': 'html',
        'include_carved': 'on',
        'include_deleted': 'on'
    }

    rv = client.post('/reporting', data=data, follow_redirects=True)
    assert rv.status_code in (200, 302)

    # Check session folder for saved report
    files = os.listdir(app.config['SESSION_FOLDER'])
    assert any('Report_TestCase' in f for f in files)

    # Check DB for a record
    conn = _get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT filename, file_type FROM files WHERE filename LIKE '%Report_TestCase%'")
    rows = cur.fetchall()
    conn.close()
    assert len(rows) >= 1
