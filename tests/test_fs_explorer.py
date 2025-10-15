import os
import io
import sqlite3
import tempfile
import zipfile
import importlib.util
import sys

import pytest

# Load app module by path
spec = importlib.util.spec_from_file_location('fac_app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
fac_app = importlib.util.module_from_spec(spec)
sys.modules['fac_app'] = fac_app
spec.loader.exec_module(fac_app)
app = fac_app.app

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Create temporary root folders similar to allowed roots
    upload_root = tmp_path / "Upload Files"
    session_root = tmp_path / "Session Files"
    upload_root.mkdir()
    session_root.mkdir()

    # create a nested session folder
    sess = session_root / "Session_20251014_123000"
    sess.mkdir()
    nested = sess / "Carved"
    nested.mkdir()
    # create files
    f1 = nested / "file1.txt"
    f1.write_text('hello')
    f2 = upload_root / "evidence.img"
    f2.write_text('evidence')

    # monkeypatch app config
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = str(upload_root)
    app.config['SESSION_FOLDER'] = str(session_root)

    # monkeypatch allowed roots helper to use these roots via app.config
    def _get_tmp_db_conn():
        # create a temp db
        tmp_db_path = str(tmp_path / 'test.db')
        conn = sqlite3.connect(tmp_db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, path TEXT, size_bytes INTEGER, created_at TEXT, session_id TEXT, extra TEXT)')
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started_at TEXT, ended_at TEXT, active INTEGER, session_path TEXT)')
        conn.commit()
        return conn

    monkeypatch.setattr(fac_app, '_get_db_conn', _get_tmp_db_conn)
    # also override DB_FILE if referenced
    try:
        setattr(fac_app, 'DB_FILE', str(tmp_path / 'test.db'))
    except Exception:
        pass

    with app.test_client() as c:
        yield c


def test_fs_explorer_and_zip_download(client):
    # Browse the session root
    rv = client.get('/fs_explorer?browse_root=Session_20251014_123000')
    # Should return 400 since display name doesn't match root basename; instead pass root as basename of session root
    assert rv.status_code in (200, 400, 403)

    # Use actual root path
    root_display = os.path.basename(app.config['SESSION_FOLDER'])
    rv = client.get(f'/fs_explorer?browse_root={root_display}')
    assert rv.status_code == 200

    # Download ZIP of the session root
    rv2 = client.get(f'/download_folder_zip?browse_root={root_display}&browse_folder=Session_20251014_123000')
    assert rv2.status_code == 200
    # Ensure returned content is a zip
    z = zipfile.ZipFile(io.BytesIO(rv2.data))
    names = z.namelist()
    assert any('file1.txt' in n for n in names)
