import os, sqlite3, json
import sys
import os
# ensure workspace root is on sys.path so we can import app.py as a module
workspace = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if workspace not in sys.path:
    sys.path.insert(0, workspace)
import app

# Prepare a test sqlite DB path
target_db = os.path.join(workspace, 'test_target.db')
# Ensure file exists
open(target_db, 'a').close()

cfg = {'conn': target_db, 'engine': 'sqlite', 'conn_details': {'path': target_db}}
print('Calling create_default_folder_entries_for_db with', target_db)
app.create_default_folder_entries_for_db(cfg, dbid='test123')

# Inspect the target DB
conn = sqlite3.connect(target_db)
cur = conn.cursor()
try:
    cur.execute("SELECT filename, file_type, path, extra FROM files WHERE file_type='folder'")
    rows = cur.fetchall()
    print(f'Found {len(rows)} folder rows:')
    for r in rows:
        print(r)
except Exception as e:
    print('Error querying target DB:', e)
finally:
    conn.close()

# Also inspect the application DB for fallback entries
app_db = app.DB_FILE
print('\nChecking application DB at', app_db)
conn2 = sqlite3.connect(app_db)
cur2 = conn2.cursor()
try:
    cur2.execute("SELECT filename, file_type, path, extra FROM files WHERE extra LIKE '%test123%' OR (file_type='folder' AND filename IN ('Upload Files','Encrypted Files','Decrypted Files','Session Files'))")
    rows2 = cur2.fetchall()
    print(f'Application DB returned {len(rows2)} rows:')
    for r in rows2:
        print(r)
except Exception as e:
    print('Error querying app DB:', e)
finally:
    conn2.close()
