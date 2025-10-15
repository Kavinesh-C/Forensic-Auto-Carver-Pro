import os
import io
import sqlite3
import tempfile
import importlib.util
import sys
import pytest
from pathlib import Path

# Load app module by path
spec = importlib.util.spec_from_file_location('fac_app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
fac_app = importlib.util.module_from_spec(spec)
sys.modules['fac_app'] = fac_app
spec.loader.exec_module(fac_app)
app = fac_app.app

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Setup temp folders
    base = tmp_path / 'root'
    base.mkdir()
    upload = base / 'Upload Files'
    upload.mkdir()

    # create a source file in upload root
    src = upload / 'evidence_from_db.img'
    src.write_bytes(b'testdata')

    # Create a simple DB and insert a files record
    db_path = tmp_path / 'fac_data_test.db'
    conn = sqlite3.connect(str(db_path))
    conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, path TEXT, size_bytes INTEGER, created_at TEXT, session_id TEXT, extra TEXT)')
    conn.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started_at TEXT, ended_at TEXT, active INTEGER, session_path TEXT)')
    # insert file record
    conn.execute('INSERT INTO files (filename, file_type, path, size_bytes, created_at) VALUES (?,?,?,?,?)', (
        'evidence_from_db.img', 'evidence', str(src), os.path.getsize(src), 'now'
    ))
    conn.commit()
    conn.close()

    # Monkeypatch app config and DB helper
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = str(upload)

    def _get_tmp_db_conn():
        return sqlite3.connect(str(db_path))

    monkeypatch.setattr(fac_app, '_get_db_conn', _get_tmp_db_conn)
    monkeypatch.setattr(fac_app, 'DB_FILE', str(db_path))

    with app.test_client() as c:
        yield c


def test_load_to_upload_by_id(client):
    # Need CSRF token from session
    with client.session_transaction() as sess:
        token = sess.get('csrf_token')
        if not token:
            # force token creation
            sess['csrf_token'] = fac_app.secrets.token_hex(16)
            token = sess['csrf_token']

    # find the file id from DB
    conn = sqlite3.connect(client.application.config.get('TESTING') and fac_app.DB_FILE or '')
    conn = sqlite3.connect(fac_app.DB_FILE)
    cur = conn.cursor()
    cur.execute('SELECT id, path FROM files WHERE filename=?', ('evidence_from_db.img',))
    row = cur.fetchone()
    assert row is not None
    fid = row[0]
    srcpath = row[1]
    conn.close()

    # create a separate destination folder to simulate upload target
    dest_dir = client.application.config['UPLOAD_FOLDER']
    # make sure destination doesn't already have a conflict file
    dest_path = os.path.join(dest_dir, 'evidence_from_db.img')
    if os.path.exists(dest_path):
        os.remove(dest_path)

    # POST to endpoint with file_id
    data = {'file_id': str(fid), 'csrf_token': token}
    rv = client.post('/api/fs/load_to_upload', data=data, headers={'X-CSRF-Token': token})
    assert rv.status_code == 200
    j = rv.get_json()
    assert j.get('ok') is True
    assert 'filename' in j

    # verify file copied
    copied = os.path.join(dest_dir, j['filename'])
    assert os.path.exists(copied)
    # contents match source
    assert open(copied, 'rb').read() == open(srcpath, 'rb').read()
