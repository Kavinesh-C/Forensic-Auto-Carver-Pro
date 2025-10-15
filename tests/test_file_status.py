import os
import json
import sqlite3
import importlib.util
import sys
import pytest

# Load app module as fac_app (same pattern as other tests)
spec = importlib.util.spec_from_file_location('fac_app', os.path.join(os.path.dirname(__file__), '..', 'app.py'))
fac_app = importlib.util.module_from_spec(spec)
sys.modules['fac_app'] = fac_app
spec.loader.exec_module(fac_app)
app = fac_app.app


@pytest.fixture
def client(tmp_path, monkeypatch):
    # create a temp sqlite DB and ensure files table exists with status
    db_path = str(tmp_path / 'fac_test.db')
    def _get_tmp_db_conn():
        conn = sqlite3.connect(db_path)
        conn.execute('CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, file_type TEXT, path TEXT, size_bytes INTEGER, created_at TEXT, session_id TEXT, status TEXT DEFAULT "saved")')
        conn.commit()
        return conn

    monkeypatch.setattr(fac_app, '_get_db_conn', _get_tmp_db_conn)
    try:
        setattr(fac_app, 'DB_FILE', db_path)
    except Exception:
        pass

    # configure app
    app.config['TESTING'] = True
    # ensure upload/session folders
    sess_dir = tmp_path / 'sessions'
    sess_dir.mkdir()
    monkeypatch.setattr(fac_app, 'SESSION_FOLDER', str(sess_dir))

    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess['csrf_token'] = 'testtoken'
            sess['analysis_session_id'] = 'testsess'
            sess['can_edit_status'] = True
        # initialize DB
        conn = _get_tmp_db_conn(); conn.close()
        yield c


def test_single_status_update_ok(client):
    conn = fac_app._get_db_conn(); cur = conn.cursor()
    cur.execute('INSERT INTO files (filename, file_type, path, size_bytes, session_id, status) VALUES (?,?,?,?,?,?)', ('f1.txt','file','/tmp/f1',123,'s1','saved'))
    fid = cur.lastrowid
    conn.commit(); conn.close()

    res = client.post('/api/file_status', data={'file_id': fid, 'status': 'processing', 'csrf_token': 'testtoken'})
    assert res.status_code == 200
    j = res.get_json(); assert j.get('ok')

    conn = fac_app._get_db_conn(); cur = conn.cursor(); cur.execute('SELECT status FROM files WHERE id = ?', (fid,)); r = cur.fetchone(); conn.close()
    assert r[0] == 'processing'


def test_single_status_invalid_status(client):
    conn = fac_app._get_db_conn(); cur = conn.cursor(); cur.execute('INSERT INTO files (filename, file_type, path, size_bytes, session_id, status) VALUES (?,?,?,?,?,?)', ('f2.txt','file','/tmp/f2',10,'s1','saved'))
    fid = cur.lastrowid; conn.commit(); conn.close()
    res = client.post('/api/file_status', data={'file_id': fid, 'status': 'badstatus', 'csrf_token': 'testtoken'})
    assert res.status_code == 400
    j = res.get_json(); assert j.get('error') == 'invalid_status'


def test_bulk_update(client):
    conn = fac_app._get_db_conn(); cur = conn.cursor(); ids = []
    for i in range(3):
        cur.execute('INSERT INTO files (filename, file_type, path, size_bytes, session_id, status) VALUES (?,?,?,?,?,?)', (f'bf{i}.txt','file',f'/tmp/bf{i}', i, 's1', 'saved'))
        ids.append(cur.lastrowid)
    conn.commit(); conn.close()

    payload = {'file_ids': ids, 'status': 'waiting'}
    res = client.post('/api/file_status_bulk', data=json.dumps(payload), content_type='application/json', headers={'X-CSRF-Token': 'testtoken'})
    assert res.status_code == 200
    j = res.get_json(); assert j.get('ok'); assert j.get('updated') == 3

    conn = fac_app._get_db_conn(); cur = conn.cursor(); cur.execute('SELECT DISTINCT status FROM files WHERE id IN ({seq})'.format(seq=','.join(['?']*len(ids))), tuple(ids)); rows = cur.fetchall(); conn.close()
    assert len(rows) == 1 and rows[0][0] == 'waiting'
