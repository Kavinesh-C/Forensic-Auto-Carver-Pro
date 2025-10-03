import os
import re
import zipfile
import mimetypes
import time
from flask import Flask, render_template_string, request, redirect, url_for, flash, jsonify, Response, send_from_directory, make_response, send_file, session
from werkzeug.utils import secure_filename
from PIL import Image
import io
import threading
import pytsk3
import hashlib
import math
import magic
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
import base64
import datetime
import gzip
import json
import csv
import xml.etree.ElementTree as ET
import mmap
from multiprocessing.dummy import Pool
import sqlite3
import tempfile

# --- NEW: Database Integration ---
try:
    from flask_sqlalchemy import SQLAlchemy
except ImportError:
    SQLAlchemy = None
    print("Warning: 'Flask-SQLAlchemy' is not installed. Database features will be disabled. Install with: pip install Flask-SQLAlchemy")

try:
    import psycopg2
except ImportError:
    psycopg2 = None
    print("Warning: 'psycopg2-binary' is not installed. PostgreSQL support will be disabled. Install with: pip install psycopg2-binary")

# --- Optional Dependency Handling ---
try:
    from weasyprint import HTML
except ImportError:
    HTML = None

try:
    import docx
except ImportError:
    docx = None

try:
    from Evtx.Evtx import Evtx
except ImportError:
    Evtx = None
    print("Warning: 'python-evtx' is not installed. .evtx log parsing will not be available. Install with: pip install python-evtx")

try:
    import openpyxl
except ImportError:
    openpyxl = None
    print("Warning: 'openpyxl' is not installed. .xlsx parsing will not be available. Install with: pip install openpyxl")

try:
    import pptx
except ImportError:
    pptx = None
    print("Warning: 'python-pptx' is not installed. .pptx parsing will not be available. Install with: pip install python-pptx")

try:
    import rarfile
except ImportError:
    rarfile = None
    print("Warning: 'rarfile' is not installed. .rar parsing will not be available. Install with: pip install rarfile")

try:
    import py7zr
except ImportError:
    py7zr = None
    print("Warning: 'py7zr' is not installed. .7z parsing will not be available. Install with: pip install py7zr")

# --- Application Setup ---
app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['MAX_CONTENT_LENGTH'] = None  # No limit on request body size

# Increase other limits for large file handling
app.config['MAX_COOKIE_SIZE'] = 10 * 1024 * 1024  # 
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

# Write a small sentinel file at import time so we can verify which file the WSGI process loaded.
try:
    _loaded_path = os.path.join(APP_ROOT, 'app_loaded.log')
    with open(_loaded_path, 'a', encoding='utf-8') as _lf:
        _lf.write('\n' + '='*80 + '\n')
        _lf.write(f'App module imported from: {os.path.abspath(__file__)}\n')
        _lf.write(f'Import time: {repr(__import__("datetime").datetime.now())}\n')
except Exception:
    pass

# --- MODIFIED: Paths set to be inside the main project folder ---
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'uploads')
CARVED_FOLDER = r'D:\Forensic Auto Carver\carved_files'
DECRYPTED_FOLDER = os.path.join(APP_ROOT, 'decrypted_files')
ENCRYPTED_FOLDER = os.path.join(APP_ROOT, 'encrypted_files')
DELETED_RECOVERY_FOLDER = os.path.join(APP_ROOT, 'deleted_files')

# Path for the password dictionary
DICTIONARY_FILE = 'common_passwords.txt'

# Apply folder paths to the Flask app config
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['CARVED_FOLDER'] = CARVED_FOLDER
app.config['DECRYPTED_FOLDER'] = DECRYPTED_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER
app.config['DICTIONARY_FILE'] = DICTIONARY_FILE
app.config['DELETED_RECOVERY_FOLDER'] = DELETED_RECOVERY_FOLDER

# --- Database Configuration ---
DB_STORAGE_LIMIT_GB = 50
DB_STORAGE_LIMIT_BYTES = DB_STORAGE_LIMIT_GB * 1024 * 1024 * 1024

if SQLAlchemy and psycopg2:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kavin@localhost:5432/Autoamted_File_carving_System'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)
else:
    db = None

# Create all necessary directories when the app starts
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['CARVED_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECRYPTED_FOLDER'], exist_ok=True)
os.makedirs(app.config['ENCRYPTED_FOLDER'], exist_ok=True)
os.makedirs(app.config['DELETED_RECOVERY_FOLDER'], exist_ok=True)

# --- Populate in-memory deleted_files_db from on-disk files at startup ---
def populate_deleted_files_db_from_disk():
    """Scan the deleted recovery folder and populate the in-memory `deleted_files_db`.

    This helps the web UI show files that were recovered on disk before the server started.
    """
    global deleted_files_db
    try:
        deleted_files_db.clear()
    except Exception:
        deleted_files_db = {}

    recovery_dir = app.config.get('DELETED_RECOVERY_FOLDER', os.path.join(APP_ROOT, 'deleted_files'))
    try:
        for fname in sorted(os.listdir(recovery_dir)):
            fpath = os.path.join(recovery_dir, fname)
            if not os.path.isfile(fpath):
                continue
            try:
                info = get_enhanced_file_info(fpath)
            except Exception:
                info = {'mime_type': 'application/octet-stream', 'file_type': 'Unknown', 'thumbnail': None, 'size_bytes': os.path.getsize(fpath) if os.path.exists(fpath) else 0, 'size_kb': '0'}

            try:
                mtime = datetime.datetime.fromtimestamp(os.path.getmtime(fpath)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                mtime = 'Unknown'

            try:
                ctime = datetime.datetime.fromtimestamp(os.path.getctime(fpath)).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                ctime = 'Unknown'

            deleted_files_db[os.path.basename(fpath)] = {
                'inode': None,
                'name': os.path.basename(fpath),
                'size': info.get('size_bytes', 0),
                'size_kb': info.get('size_kb', '0'),
                'mtime': mtime,
                'ctime': ctime,
                'file_type': info.get('mime_type', 'application/octet-stream'),
                'thumbnail': info.get('thumbnail'),
                'path': fpath
            }
    except Exception as e:
        app.logger.debug(f"populate_deleted_files_db_from_disk: error scanning folder: {e}")

# Run initial population so the UI sees recovered files already on disk
try:
    populate_deleted_files_db_from_disk()
except Exception:
    pass

def get_encrypted_files():
    """Get list of encrypted files with their sizes."""
    encrypted_files = []
    try:
        for filename in os.listdir(app.config['ENCRYPTED_FOLDER']):
            if filename.endswith('.enc'):
                filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
                if os.path.isfile(filepath):
                    size = os.path.getsize(filepath)
                    size_str = format_bytes(size)
                    encrypted_files.append({
                        'filename': filename,
                        'size': size_str,
                        'path': filepath
                    })
    except Exception as e:
        print(f"Error listing encrypted files: {e}")
    
    return encrypted_files

@app.route('/rescan_deleted_files', methods=['GET', 'POST'])
def rescan_deleted_files():
    """HTTP endpoint to trigger a rescanning of the deleted recovery folder and populate the in-memory DB."""
    try:
        populate_deleted_files_db_from_disk()
        return jsonify({'success': True, 'files': len(deleted_files_db), 'message': 'Rescan complete.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if not os.path.exists(DICTIONARY_FILE):
    with open(DICTIONARY_FILE, 'w') as f:
        f.write("password\n123456\nadmin\n12345\n12345678\nletmein\nqwerty\npassword1\n")

# --- NEW: Database Model ---
if db:
    class EvidenceFile(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        filename = db.Column(db.String(255), nullable=False)
        filepath = db.Column(db.String(512), nullable=False, unique=True)
        filesize = db.Column(db.BigInteger, nullable=False)
        upload_date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
        upload_in_progress = db.Column(db.Boolean, default=False)

        def __repr__(self):
            return f'<EvidenceFile {self.filename}>'

    class EvidenceFileChunk(db.Model):
        __tablename__ = 'evidence_file_chunk'
        id = db.Column(db.Integer, primary_key=True)
        evidence_id = db.Column(db.Integer, db.ForeignKey('evidence_file.id', ondelete='CASCADE'), nullable=False)
        chunk_index = db.Column(db.Integer, nullable=False)
        data = db.Column(db.LargeBinary, nullable=False)

        evidence = db.relationship('EvidenceFile', backref=db.backref('chunks', cascade='all, delete-orphan'))

    # create tables if they don't exist
    try:
        db.create_all()
    except Exception:
        # Ignore DB creation errors at startup (user may not have DB perms)
        pass

    # Ensure schema changes for existing installations (add new columns / tables)
    try:
        from sqlalchemy import inspect, text
        # Run schema fixes inside the Flask application context so the
        # engine/session are available and permissioned properly.
        with app.app_context():
            inspector = inspect(db.engine)

            # Add missing upload_in_progress column if it doesn't exist
            cols = inspector.get_columns('evidence_file') if inspector.has_table('evidence_file') else []
            col_names = [c['name'] for c in cols]
            if 'upload_in_progress' not in col_names:
                try:
                    db.session.execute(text('ALTER TABLE evidence_file ADD COLUMN upload_in_progress boolean DEFAULT false'))
                    db.session.commit()
                except Exception:
                    try:
                        db.session.rollback()
                    except Exception:
                        pass

            # Ensure chunk table exists
            if not inspector.has_table('evidence_file_chunk'):
                try:
                    EvidenceFileChunk.__table__.create(bind=db.engine, checkfirst=True)
                except Exception:
                    pass
    except Exception:
        # If inspection fails, continue without blocking startup
        pass

        def __repr__(self):
            return f'<EvidenceFile {self.filename}>'

# --- In-Memory Databases & Caches ---
uploaded_files_db = {}
carved_files_db = {}
deleted_files_db = {}
sorted_carved_keys = []
sorted_deleted_inodes = []

# Update your status dictionaries at the top of the file
carving_status = {
    "progress": 0, "current_offset": "0x00000000", "files_found": 0,
    "complete": False, "found_files_list": [], "time_remaining_str": "N/A",
    "start_time": None, "estimated_total_time": None, "elapsed_time": "0s"
}

deleted_scan_status = {
    "in_progress": False, 
    "files_found": 0, 
    "complete": False, 
    "message": "Scan has not started.",
    "errors": [], 
    "time_remaining_str": "N/A",
    "start_time": None,
    "estimated_total_time": None,
    "elapsed_time": "0s",
    "scan_methods": {
        "directory_walk": 0,
        "inode_scan": 0,
        "file_slack": 0,
        "unallocated_space": 0,
        "recycle_bin": 0
    }
}

upload_status = {
    "in_progress": False,
    "progress": 0,
    "filename": None,
    "start_time": None,
    "estimated_total_time": None,
    "elapsed_time": "0s",
    "time_remaining_str": "Calculating...",
    "total_bytes": 0,
    "bytes_uploaded": 0,
    "upload_speed": 0,
    "last_update_time": None,
    "complete": False,
    "error": None
}
# --- Status Dictionaries for Background Tasks ---

decryption_status = {
    "in_progress": False, "complete": False, "message": "", "attempts": 0, "success": False,
    "filename": None, "progress": 0, "total_attempts": 0
}

hashing_status = {
    "in_progress": False, "progress": 0, "complete": False, "hashes": {}
}

strings_status = {
    "in_progress": False, "complete": False, "progress": 0, "strings_found": 0, "preview": []
}

# --- Signatures and Patterns ---
CUSTOM_ENC_HEADER = b'FCPE_V1_'  # Forensic Carver Pro Encryption, Version 1

ENCRYPTION_SIGNATURES = {
    'AES_ENCRYPTED': {'header': b'Salted__', 'description': 'OpenSSL AES encrypted file'},
    'BITLOCKER': {'header': b'-FVE-FS-', 'description': 'BitLocker encrypted volume'},
    'VERACRYPT': {'header': b'VERA', 'description': 'VeraCrypt encrypted container'},
    'PGP': {'header': b'\x85\x01\x0c', 'description': 'PGP encrypted file'},
    '7Z_ENCRYPTED': {'header': b'7z\xbc\xaf'"'\x27\x1c', 'description': '7-Zip encrypted archive'},
    'ZIP_ENCRYPTED': {'header': b'PK\x03\x04', 'description': 'ZIP encrypted archive (needs password)'},
    'RAR_ENCRYPTED': {'header': b'Rar!\x1a\x07', 'description': 'RAR encrypted archive'},
    'FERNET_ENCRYPTED': {'header': CUSTOM_ENC_HEADER, 'description': 'Forensic Carver Pro Encrypted File'},
}

# --- Optimized & Consolidated File Signatures ---
FILE_SIGNATURES = {
    'Image Files': {
        'JPEG': {'header': b'\xff\xd8\xff\xe0', 'footer': b'\xff\xd9', 'extension': '.jpeg', 'max_size': 20 * 1024 * 1024},
        'JPG': {'header': b'\xff\xd8\xff\xe0', 'footer': b'\xff\xd9', 'extension': '.jpg', 'max_size': 20 * 1024 * 1024},
        'PNG': {'header': b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', 'footer': b'\x49\x45\x4e\x44\xae\x42\x60\x82', 'extension': '.png'},
        'GIF': {'header': b'\x47\x49\x46\x38', 'footer': b'\x00\x3b', 'extension': '.gif'},
        'TIFF (Intel)': {'header': b'\x49\x49\x2a\x00', 'max_size': 30*1024*1024, 'extension': '.tiff'},
        'TIFF (Motorola)': {'header': b'\x4d\x4d\x00\x2a', 'max_size': 30*1024*1024, 'extension': '.tiff'},
        'BMP': {'header': b'\x42\x4d', 'max_size': 30*1024*1024, 'extension': '.bmp'},
        'ICO': {'header': b'\x00\x00\x01\x00', 'max_size': 1*1024*1024, 'extension': '.ico'},
    },
    'Document Files': {
        'PDF': {'header': b'\x25\x50\x44\x46', 'footer': b'\x25\x25\x45\x4f\x46', 'extension': '.pdf'},
        'DOCX': {'header': b'\x50\x4b\x03\x04', 'footer': b'\x50\x4b\x05\x06', 'extension': '.docx'},
        'XLSX': {'header': b'\x50\x4b\x03\x04', 'footer': b'\x50\x4b\x05\x06', 'extension': '.xlsx'},
        'PPTX': {'header': b'\x50\x4b\x03\x04', 'footer': b'\x50\x4b\x05\x06', 'extension': '.pptx'},
