import io
import os
import tempfile
import pytest
import importlib.util
import sys
from pathlib import Path


def load_app_module():
    # load the app.py from repo root explicitly to avoid import issues on Windows paths with spaces
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location('app', str(root / 'app.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules['app'] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def client(tmp_path, monkeypatch):
    # point SESSION_FOLDER and roots to a temp dir for isolation
    base = tmp_path / "root"
    base.mkdir()
    monkeypatch.setenv('TESTING', '1')

    # Prepare temp folders before loading app module
    for d in ['Upload Files','Carved Files','Decrypted Files','Encrypted Files','Deleted Files','Session Files']:
        p = base / d
        p.mkdir(parents=True, exist_ok=True)

    # Load app module fresh
    app_module = load_app_module()
    app = app_module.app

    # now override paths
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = str(base / 'Upload Files')
    app.config['CARVED_FOLDER'] = str(base / 'Carved Files')
    app.config['DECRYPTED_FOLDER'] = str(base / 'Decrypted Files')
    app.config['ENCRYPTED_FOLDER'] = str(base / 'Encrypted Files')
    app.config['DELETED_RECOVERY_FOLDER'] = str(base / 'Deleted Files')
    app.config['SESSION_FOLDER'] = str(base / 'Session Files')

    # use a temp DB
    tmpdb = str(tmp_path / 'fac_data_test.db')
    app_module.DB_FILE = tmpdb
    app_module.init_db()

    with app.test_client() as c:
        yield c


def test_full_flow(client, tmp_path):
    root = 'Upload Files'
    # hit explorer to set up session and get CSRF token
    r = client.get('/fs_explorer')
    # extract csrf token from session cookie by calling a simple endpoint that returns it
    from importlib import import_module
    app_mod = import_module('app')
    csrf = None
    try:
        # the test client maintains cookie-based session; we can call a small helper URL if needed
        with client.session_transaction() as sess:
            csrf = sess.get('csrf_token')
    except Exception:
        csrf = None
    assert csrf is not None
    # create folder
    r = client.post('/api/fs/mkdir', data={'root': root, 'path': '', 'name': 'myfolder', 'csrf_token': csrf}, headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200
    j = r.get_json()
    assert j.get('created')

    # upload a text file into folder
    data = {
        'root': root,
        'path': 'myfolder'
    }
    file_content = b'Hello world!\nThis is a test file.\n'
    data['file'] = (io.BytesIO(file_content), 'test.txt')
    r = client.post('/api/fs/upload', data=data, content_type='multipart/form-data', headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200
    j = r.get_json()
    assert j.get('uploaded')

    # info
    r = client.get('/api/fs/info?root=Upload Files&path=myfolder/test.txt')
    assert r.status_code == 200
    info = r.get_json()
    assert info.get('name') == 'test.txt'

    # preview
    r = client.get('/api/fs/preview?root=Upload Files&path=myfolder/test.txt')
    assert r.status_code == 200
    p = r.get_json()
    assert 'Hello world' in p.get('preview', '')

    # rename
    r = client.post('/api/fs/rename', data={'root': root, 'old': 'myfolder/test.txt', 'new': 'myfolder/test_renamed.txt', 'csrf_token': csrf}, headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200
    jr = r.get_json()
    assert jr.get('renamed')

    # delete file
    r = client.post('/api/fs/delete', data={'root': root, 'path': 'myfolder/test_renamed.txt', 'csrf_token': csrf}, headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200
    jd = r.get_json()
    assert jd.get('deleted')

    # delete folder
    r = client.post('/api/fs/delete', data={'root': root, 'path': 'myfolder', 'csrf_token': csrf}, headers={'X-CSRF-Token': csrf})
    assert r.status_code == 200
    jd = r.get_json()
    assert jd.get('deleted')
