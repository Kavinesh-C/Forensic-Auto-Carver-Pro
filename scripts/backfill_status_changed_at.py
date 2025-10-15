#!/usr/bin/env python3
"""Backfill `status_changed_at` in the files table from JSON audit.log status_change events.

Usage:
  python backfill_status_changed_at.py --preview
  python backfill_status_changed_at.py --apply

By default the script will look for the DB at ../fac_data.db and audit.log in the repo root.
You can pass --db and --audit to override.
When applying, the script will create a timestamped backup of the DB before modifying it.
"""
import argparse
import json
import os
import sqlite3
import shutil
import datetime
import sys


def parse_args():
    p = argparse.ArgumentParser(description='Backfill status_changed_at from audit.log')
    p.add_argument('--db', help='Path to SQLite DB (files table)', default=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'fac_data.db')))
    p.add_argument('--audit', help='Path to audit log (JSONL)', default=os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'audit.log')))
    p.add_argument('--preview', action='store_true', help='Preview only (no DB changes)')
    p.add_argument('--apply', action='store_true', help='Apply changes to DB (will backup DB first)')
    return p.parse_args()


def read_audit(audit_path):
    """Read audit log and return map file_id -> latest ISO timestamp (string)."""
    latest = {}
    if not os.path.exists(audit_path):
        print('Audit log not found at', audit_path)
        return latest
    with open(audit_path, 'r', encoding='utf-8') as fh:
        for i, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                # ignore malformed lines
                continue
            action = obj.get('action')
            if action != 'status_change':
                continue
            ts = obj.get('ts')
            details = obj.get('details') or {}
            fid = details.get('file_id') or details.get('id')
            if fid is None:
                # some older events may only have path/target; skip those for safety
                continue
            try:
                # normalize to int when possible
                fid = int(fid)
            except Exception:
                # leave as-is (string) if cannot convert
                pass
            # keep latest ts per file id
            if not ts:
                continue
            prev = latest.get(fid)
            if not prev or ts > prev:
                latest[fid] = ts
    return latest


def backup_db(db_path):
    t = datetime.datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    bak = db_path + f'.bak.{t}'
    shutil.copy2(db_path, bak)
    return bak


def apply_backfill(db_path, mapping):
    if not os.path.exists(db_path):
        raise FileNotFoundError('DB not found: ' + db_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        # Ensure column exists
        cur.execute("PRAGMA table_info(files)")
        cols = [r[1] for r in cur.fetchall()]
        if 'status_changed_at' not in cols:
            raise RuntimeError('files table does not have status_changed_at column')

        updates = 0
        for fid, ts in mapping.items():
            # Only update rows where status_changed_at is NULL or empty
            cur.execute('SELECT status_changed_at FROM files WHERE id = ?', (fid,))
            row = cur.fetchone()
            if not row:
                continue
            cur_val = row[0]
            if cur_val and str(cur_val).strip():
                # skip already populated
                continue
            cur.execute('UPDATE files SET status_changed_at = ? WHERE id = ?', (ts, fid))
            updates += 1
        conn.commit()
        return updates
    finally:
        conn.close()


def main():
    args = parse_args()
    print('DB:', args.db)
    print('Audit log:', args.audit)

    mapping = read_audit(args.audit)
    print('Found status_change events for', len(mapping), 'unique file_ids')
    if len(mapping) > 0:
        # show a small sample
        sample = list(mapping.items())[:10]
        print('Sample (file_id -> ts):')
        for fid, ts in sample:
            print(' ', fid, '->', ts)

    if args.preview or not args.apply:
        print('\nPreview mode: no DB changes made. To apply changes, re-run with --apply')

    if args.apply:
        if not os.path.exists(args.db):
            print('DB file not found:', args.db)
            sys.exit(1)
        print('Creating DB backup...')
        bak = backup_db(args.db)
        print('Backup created at', bak)
        print('Applying updates...')
        updated = apply_backfill(args.db, mapping)
        print('Updated', updated, 'rows')


if __name__ == '__main__':
    main()
