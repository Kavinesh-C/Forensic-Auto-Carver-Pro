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
APP_ROOT = os.path.dirname(os.path.abspath(__file__))

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
DB_STORAGE_LIMIT_GB = 20
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

# Add upload timing
upload_status = {
    "in_progress": False,
    "progress": 0,
    "filename": None,
    "start_time": None,
    "estimated_total_time": None,
    "elapsed_time": "0s",
    "time_remaining_str": "N/A"
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
    '7Z_ENCRYPTED': {'header': b'7z\xbc\xaf\x27\x1c', 'description': '7-Zip encrypted archive'},
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
        'RTF': {'header': b'\x7b\x5c\x72\x74\x66', 'footer': b'\x7d', 'extension': '.rtf'},
        'DOC': {'header': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'max_size': 20*1024*1024, 'extension': '.doc'},
    },
    'Archive Files': {
        'ZIP': {'header': b'\x50\x4b\x03\x04', 'footer': b'\x50\x4b\x05\x06', 'extension': '.zip'},
        'RAR': {'header': b'\x52\x61\x72\x21\x1a\x07\x00', 'max_size': 1024*1024*1024, 'extension': '.rar'},
        '7Z': {'header': b'\x37\x7a\xbc\xaf\x27\x1c', 'max_size': 1024*1024*1024, 'extension': '.7z'},
        'GZIP': {'header': b'\x1f\x8b', 'max_size': 1024*1024*1024, 'extension': '.gz'},
    },
    'Audio Files': {
        'MP3': {'headers': [b'\x49\x44\x33', b'\xff\xfb'], 'extension': '.mp3'},
        'WAV': {'header': b'\x52\x49\x46\x46', 'max_size': 100*1024*1024, 'extension': '.wav'},
        'FLAC': {'header': b'\x66\x4c\x61\x43', 'max_size': 100*1024*1024, 'extension': '.flac'},
    },
    'Video Files': {
        'MP4 / MOV': {'header': b'\x66\x74\x79\x70', 'offset': 4, 'extension': '.mp4'},
        'AVI': {'header': b'\x52\x49\x46\x46', 'max_size': 2048*1024*1024, 'extension': '.avi'},
    },
    'Executable Files': {
        'EXE': {'header': b'\x4d\x5a', 'max_size': 50*1024*1024, 'extension': '.exe'},
        'ELF': {'header': b'\x7f\x45\x4c\x46', 'max_size': 50*1024*1024, 'extension': '.elf'},
    },
    'Database Files': {
        'SQLite': {'header': b'\x53\x51\x4c\x69\x74\x65\x20\x66\x6f\x72\x6d\x61\x74\x20\x33\x00', 'max_size': 100*1024*1024, 'extension': '.sqlite'},
    },
    'Windows Log Files': {
        'Windows Event Log (EVTX)': {'header': b'\x45\x6c\x66\x46\x69\x6c\x65\x00', 'extension': '.evtx'},
        'Windows Registry Hive (REGF)': { 'header': b'\x72\x65\x67\x66', 'max_size': 500 * 1024 * 1024, 'extension': '.dat' },
    },
}

LOG_OS_OPTIONS = {
    "Windows": [".log", ".evtx", ".txt", ".csv", ".json", ".xml"],
    "Linux": [".log", ".txt", ".json", ".xml", ".csv", ".gz", ".zip", ""],
    "macOS": [".logarchive", ".gz", ".tracev3", ".log"]
}

EVENT_OS_OPTIONS = {
    "Windows": [".evtx", ".evt"],
    "Linux": ["/var/log/syslog", "/var/log/auth.log", "/var/log/kern.log",
              "/var/log/dmesg", "/var/log/wtmp", "/var/log/btmp"],
    "macOS": [".logarchive", ".asl", ".ips", ".spin", ".diag", ".log"]
}

# --- NEW: Cryptographic Functions ---
SALT_SIZE = 16
ITERATIONS = 480_000

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a secure encryption key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))
def calculate_time_estimations(status_dict, current_progress, total_items=None):
    """Calculate time estimations for long-running processes."""
    if not status_dict.get("start_time"):
        status_dict["start_time"] = time.time()
        status_dict["last_update_time"] = time.time()
        return "Calculating..."
    
    current_time = time.time()
    elapsed = current_time - status_dict["start_time"]
    status_dict["elapsed_time"] = format_time(elapsed)
    
    # Update only every 2 seconds to reduce CPU usage
    if current_time - status_dict.get("last_update_time", 0) < 2:
        return status_dict.get("time_remaining_str", "Calculating...")
    
    status_dict["last_update_time"] = current_time
    
    if current_progress > 0:
        if total_items and total_items > 0:
            # Based on total items
            progress_percent = min(current_progress / total_items, 0.99)  # Cap at 99%
            if progress_percent > 0.01:  # Wait until we have meaningful progress
                estimated_total = elapsed / progress_percent
                estimated_remaining = estimated_total - elapsed
                status_dict["time_remaining_str"] = format_time(max(0, estimated_remaining))
                status_dict["estimated_total_time"] = format_time(estimated_total)
            else:
                status_dict["time_remaining_str"] = "Calculating..."
        else:
            # Based on progress percentage
            progress_percent = current_progress / 100.0
            if progress_percent > 0.01:
                estimated_total = elapsed / progress_percent
                estimated_remaining = estimated_total - elapsed
                status_dict["time_remaining_str"] = format_time(max(0, estimated_remaining))
                status_dict["estimated_total_time"] = format_time(estimated_total)
            else:
                status_dict["time_remaining_str"] = "Calculating..."
    else:
        status_dict["time_remaining_str"] = "Calculating..."
    
    return status_dict["time_remaining_str"]

def calculate_upload_time_estimations(bytes_uploaded, total_bytes, start_time):
    """Calculate upload time estimations."""
    if bytes_uploaded <= 0 or total_bytes <= 0:
        return "0s", "Calculating...", "Calculating..."
    
    elapsed = time.time() - start_time
    elapsed_str = format_time(elapsed)
    
    if bytes_uploaded > 0:
        upload_speed = bytes_uploaded / elapsed  # bytes per second
        remaining_bytes = total_bytes - bytes_uploaded
        if upload_speed > 0:
            remaining_time = remaining_bytes / upload_speed
            remaining_str = format_time(remaining_time)
            total_estimated_str = format_time(elapsed + remaining_time)
        else:
            remaining_str = "Calculating..."
            total_estimated_str = "Calculating..."
    else:
        remaining_str = "Calculating..."
        total_estimated_str = "Calculating..."
    
    return elapsed_str, remaining_str, total_estimated_str

def update_process_timing(status_dict, current_value, total_value=None, value_type="bytes"):
    """Update timing information for any process."""
    if not status_dict.get("start_time"):
        status_dict["start_time"] = time.time()
    
    current_time = time.time()
    
    # Always update elapsed time
    elapsed = current_time - status_dict["start_time"]
    status_dict["elapsed_time"] = format_time(elapsed)
    
    # Update progress based on value type
    if value_type == "bytes" and total_value and total_value > 0:
        progress_percent = (current_value / total_value) * 100
        status_dict["progress"] = min(progress_percent, 99)  # Cap at 99% until complete
    elif value_type == "items" and total_value and total_value > 0:
        progress_percent = (current_value / total_value) * 100
        status_dict["progress"] = min(progress_percent, 99)
    elif value_type == "percentage":
        status_dict["progress"] = current_value
    
    # Calculate time remaining (update every 3 seconds to reduce load)
    if current_time - status_dict.get("last_update_time", 0) >= 3:
        if current_value > 0:
            if total_value and total_value > 0:
                # Based on known total
                progress_ratio = current_value / total_value
                if progress_ratio > 0.01:  # Wait for meaningful progress
                    estimated_total = elapsed / progress_ratio
                    estimated_remaining = estimated_total - elapsed
                    status_dict["time_remaining_str"] = format_time(max(0, estimated_remaining))
                    status_dict["estimated_total_time"] = format_time(estimated_total)
                else:
                    status_dict["time_remaining_str"] = "Calculating..."
            else:
                # Based on progress percentage
                progress_ratio = status_dict["progress"] / 100.0
                if progress_ratio > 0.01:
                    estimated_total = elapsed / progress_ratio
                    estimated_remaining = estimated_total - elapsed
                    status_dict["time_remaining_str"] = format_time(max(0, estimated_remaining))
                    status_dict["estimated_total_time"] = format_time(estimated_total)
                else:
                    status_dict["time_remaining_str"] = "Calculating..."
        else:
            status_dict["time_remaining_str"] = "Calculating..."
        
        status_dict["last_update_time"] = current_time
    
    return status_dict

def custom_encrypt_file(file_path: str, original_filename: str, password: str, output_dir: str):
    """Encrypts a file and saves it with a .enc extension in the specified directory."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        salt = os.urandom(SALT_SIZE)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        output_filename = f"{original_filename}.enc"
        output_path = os.path.join(output_dir, output_filename)
        
        with open(output_path, 'wb') as f:
            f.write(CUSTOM_ENC_HEADER)
            f.write(salt)
            f.write(encrypted_data)
        
        return True, f"Success! Encrypted file saved as {output_filename}", output_filename
    
    except Exception as e:
        return False, f"An error occurred during encryption: {e}", None

def extract_strings_preview(filepath):
    """Provides a basic preview by extracting printable strings from a binary file."""
    output = ["[INFO] This is a preview of printable strings found in the binary file.\n"]
    try:
        with open(filepath, 'rb') as f:
            content = f.read(2 * 1024 * 1024)

        printable_chars = re.compile(b"([%s]{4,})" % b" -~")
        strings = [match.group(0).decode('ascii', 'ignore') for match in printable_chars.finditer(content)]
        output.extend(strings)
        if len(content) == 2 * 1024 * 1024:
            output.append("\n\n--- [STRING PREVIEW TRUNCATED AT 2MB] ---")
        return "\n".join(output)
    except Exception as e:
        return f"[ERROR] Could not process binary file: {e}"

def get_enhanced_file_info(filepath):
    """Get enhanced file information including thumbnails and file types."""
    try:
        mime_type = magic.from_file(filepath, mime=True)
        file_size = os.path.getsize(filepath)
        
        # Generate thumbnail for images
        thumbnail = None
        if mime_type.startswith('image/'):
            thumbnail = create_thumbnail_data_uri(filepath)
        
        # Determine file category
        file_type = "Unknown"
        if mime_type.startswith('image/'):
            file_type = "Image"
        elif mime_type.startswith('video/'):
            file_type = "Video"
        elif mime_type.startswith('audio/'):
            file_type = "Audio"
        elif mime_type.startswith('text/'):
            file_type = "Text"
        elif 'pdf' in mime_type:
            file_type = "PDF"
        elif 'zip' in mime_type or 'archive' in mime_type:
            file_type = "Archive"
        elif 'executable' in mime_type:
            file_type = "Executable"
        elif 'document' in mime_type:
            file_type = "Document"
        
        return {
            'mime_type': mime_type,
            'file_type': file_type,
            'thumbnail': thumbnail,
            'size_bytes': file_size,
            'size_kb': f"{file_size / 1024:.2f}"
        }
    except Exception as e:
        return {
            'mime_type': 'application/octet-stream',
            'file_type': 'Unknown',
            'thumbnail': None,
            'size_bytes': 0,
            'size_kb': '0'
        }
    
def get_active_evidence_path():
    if not uploaded_files_db: 
        return None
    file_details = next(iter(uploaded_files_db.values()))
    decrypted_path = file_details.get('encryption_status', {}).get('decrypted_path')
    if decrypted_path and os.path.exists(decrypted_path):
        return decrypted_path
    return file_details.get('path')

# --- NEW: Database Management Function ---
def check_and_manage_storage(new_file_size):
    """Checks storage and removes old files if the 20GB limit is exceeded."""
    if not db: 
        return

    total_size = db.session.query(db.func.sum(EvidenceFile.filesize)).scalar() or 0
    if total_size + new_file_size > DB_STORAGE_LIMIT_BYTES:
        app.logger.warning(f"Storage limit ({DB_STORAGE_LIMIT_GB} GB) exceeded. Clearing old files.")

        while total_size + new_file_size > DB_STORAGE_LIMIT_BYTES:
            oldest_file = EvidenceFile.query.order_by(EvidenceFile.upload_date.asc()).first()
            if oldest_file:
                try:
                    os.remove(oldest_file.filepath)
                    app.logger.info(f"Removed old evidence file: {oldest_file.filename}")
                except OSError as e:
                    app.logger.error(f"Error removing file {oldest_file.filepath}: {e}")

                total_size -= oldest_file.filesize
                db.session.delete(oldest_file)
                db.session.commit()
            else:
                break  # No more files to delete

# --- Helper Functions ---
def format_time(seconds):
    """Formats seconds into a human-readable string like '1h 5m 30s'."""
    if seconds is None or seconds < 0:
        return "Calculating..."
    if seconds < 1:
        return "0s"

    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")

    return " ".join(parts)

def create_thumbnail_data_uri(filepath):
    """Generates a base64-encoded PNG thumbnail for image files."""
    try:
        with Image.open(filepath) as img:
            img.thumbnail((100, 100))
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
            return f"data:image/png;base64,{img_str}"
    except (IOError, OSError):
        return None

def format_hex_view(data_bytes, start_offset=0):
    """Formats a byte string into a standard hex view format."""
    lines = []
    for i in range(0, len(data_bytes), 16):
        chunk = data_bytes[i:i+16]
        offset_str = f"0x{(start_offset + i):08X}"
        hex_str = ' '.join(f'{b:02X}' for b in chunk)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        lines.append(f"{offset_str}  {hex_str:<47} {ascii_str}")
    return '\n'.join(lines)

def is_valid_mp3_stream(data, start_offset=0, frames_to_check=5):
    """Checks for a sequence of valid, contiguous MP3 frames."""
    BITRATE_MAP = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
    SAMPLERATE_MAP = [44100, 48000, 32000, 0]

    current_offset = start_offset
    frames_found = 0

    while frames_found < frames_to_check:
        if current_offset + 4 > len(data):
            break

        header_bytes = data[current_offset : current_offset + 4]

        is_mpeg1_layer3 = (header_bytes[0] == 0xFF and (header_bytes[1] & 0xE0) == 0xE0 and
                         ((header_bytes[1] >> 3) & 3) == 1 and ((header_bytes[1] >> 1) & 3) == 1)

        if not is_mpeg1_layer3:
            break

        bitrate_bits = (header_bytes[2] >> 4) & 15
        samplerate_bits = (header_bytes[2] >> 2) & 3
        padding_bit = (header_bytes[2] >> 1) & 1

        bitrate = BITRATE_MAP[bitrate_bits] * 1000
        sample_rate = SAMPLERATE_MAP[samplerate_bits]

        if bitrate == 0 or sample_rate == 0:
            break

        frame_size = int((144 * bitrate / sample_rate) + padding_bit)

        if frame_size <= 1:
            break

        current_offset += frame_size
        frames_found += 1

    return frames_found >= frames_to_check

# --- Log Parsing Helpers ---
def parse_text_log(filepath, max_lines=10000):
    lines = []
    with open(filepath, "r", errors="ignore") as f:
        for i, line in enumerate(f):
            if i >= max_lines:
                lines.append(f"\n--- [File truncated at {max_lines} lines] ---\n")
                break
            lines.append(line)
    return "".join(lines)

def parse_csv_log(filepath, max_rows=10000):
    output = []
    with open(filepath, newline="", errors="ignore") as csvfile:
        reader = csv.reader(csvfile)
        for i, row in enumerate(reader):
            if i >= max_rows:
                output.append(f"\n--- [File truncated at {max_rows} rows] ---\n")
                break
            output.append(",".join(row))
    return "\n".join(output)

def parse_json_log(filepath, max_bytes=1048576):
    with open(filepath, "r", errors="ignore") as f:
        content = f.read(max_bytes)
        try:
            data = json.loads(content)
            output = json.dumps(data, indent=4)
            if len(content) == max_bytes:
                output += f"\n\n--- [File preview truncated at {max_bytes} bytes] ---\n"
            return output
        except json.JSONDecodeError:
            return f"[INFO] Could not parse as a single JSON object. Displaying raw text preview.\n\n{content}\n\n--- [File preview truncated at {max_bytes} bytes] ---\n"

def parse_xml_log(filepath, max_elements=10000):
    output = []
    count = 0
    try:
        for event, elem in ET.iterparse(filepath, events=('start',)):
            if count >= max_elements:
                output.append(f"\n--- [File truncated at {max_elements} XML elements] ---\n")
                break
            text = elem.text.strip() if elem.text else ""
            output.append(f"<{elem.tag}> {text}")
            count += 1
            elem.clear()
        return "\n".join(output)
    except ET.ParseError as e:
        return f"[ERROR] Failed to parse XML: {e}\n\nShowing raw text preview instead:\n\n{parse_text_log(filepath, max_lines=500)}"

def parse_evtx_log(filepath, max_records=5000):
    if Evtx is None: 
        return "[ERROR] The 'python-evtx' library is required to parse .evtx files."
    output = []
    try:
        with Evtx(filepath) as log:
            for i, record in enumerate(log.records()):
                if i >= max_records:
                    output.append(f"\n\n--- [File truncated at {max_records} records] ---\n")
                    break
                output.append(record.xml())
    except Exception as e:
        return f"[ERROR] Failed to parse EVTX file: {e}"
    return "\n\n".join(output)

# --- Forensic & Encryption Functions ---
def calculate_entropy(data):
    """Calculates the Shannon entropy of a byte string."""
    if not data: 
        return 0
    byte_counts = [0] * 256
    for byte in data: 
        byte_counts[byte] += 1
    entropy = 0
    total_bytes = len(data)
    for count in byte_counts:
        if count > 0:
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
    return entropy

def detect_encryption(filepath):
    """Detects encryption based on file headers and entropy."""
    try:
        with open(filepath, 'rb') as f: 
            header = f.read(512)
        for enc_type, sig_info in ENCRYPTION_SIGNATURES.items():
            if sig_info.get('header') and header.startswith(sig_info['header']):
                if enc_type == 'ZIP_ENCRYPTED':
                    try:
                        with zipfile.ZipFile(filepath) as zf:
                            if not any(e.flag_bits & 0x1 for e in zf.infolist()): 
                                continue
                    except Exception: 
                        continue
                return {'encrypted': True, 'encryption_type': enc_type, 'description': sig_info['description']}
        entropy = calculate_entropy(header)
        if entropy > 7.5:
            return {'encrypted': True, 'encryption_type': 'UNKNOWN', 'description': f'High entropy ({entropy:.2f}) suggests encryption'}
    except Exception as e:
        print(f"Error in detect_encryption: {e}")
    return {'encrypted': False, 'encryption_type': None, 'description': 'No encryption detected'}

def perform_forensic_analysis(file_path):
    """Performs a high-level analysis of a disk image file."""
    results, partition_info = [], []
    try:
        with open(file_path, 'rb') as f: 
            header = f.read(4096)
        if header[510:512] == b'\x55\xaa': 
            results.append("✓ MBR Partition Table detected")
        if b'EFI PART' in header[512:1024]: 
            results.append("✓ GPT Partition Table detected")
        if b'FAT32' in header[0x52:0x5A]: 
            results.append("✓ FAT32 File System detected")
        elif b'NTFS' in header[0x03:0x07]: 
            results.append("✓ NTFS File System detected")
        elif b'\x53\xEF' in header[1024+56:1024+58]: 
            results.append("✓ EXT File System Superblock detected")
        if b'-FVE-FS-' in header: 
            results.append("⚠ BitLocker encryption detected")
        try:
            img_handle = pytsk3.Img_Info(file_path)
            volume = pytsk3.Volume_Info(img_handle)
            if volume:
                vstype_map = {
                    pytsk3.TSK_VS_TYPE_DETECT: "Auto-detect", 
                    pytsk3.TSK_VS_TYPE_DOS: "DOS",
                    pytsk3.TSK_VS_TYPE_BSD: "BSD", 
                    pytsk3.TSK_VS_TYPE_SUN: "Sun",
                    pytsk3.TSK_VS_TYPE_MAC: "Mac", 
                    pytsk3.TSK_VS_TYPE_GPT: "GPT",
                    pytsk3.TSK_VS_TYPE_UNSUPP: "Unsupported",
                }
                results.append(f"✓ Partition Table Type: {vstype_map.get(volume.info.vstype, 'Unknown')}")
                for part in volume:
                    if part.flags != pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                        partition_info.append({"addr": part.addr, "desc": part.desc.decode('utf-8', 'ignore'), "start": part.start, "len": part.len})
        except IOError: 
            results.append("ℹ️ No partition table found or image is a single volume.")
        except Exception as e: 
            results.append(f"❌ Error reading partitions: {e}")
        file_size = os.path.getsize(file_path)
        results.append(f"📊 File Size: {file_size/(1024*1024*1024):.2f} GB" if file_size > 1024**3 else f"📊 File Size: {file_size/(1024*1024):.2f} MB")
        results.append(f"📈 Header Entropy: {calculate_entropy(header):.2f} (High entropy > 7.5 may suggest encryption)")
    except Exception as e: 
        results.append(f"❌ Analysis error: {str(e)}")
    return results, partition_info

def calculate_hashes_threaded(file_path):
    """Calculates MD5, SHA1, and SHA256 hashes in a background thread."""
    hashing_status.update({"in_progress": True, "progress": 0, "complete": False, "hashes": {}})
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    CHUNK_SIZE = 4 * 1024 * 1024
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            bytes_read = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk: 
                    break
                bytes_read += len(chunk)
                md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
                hashing_status["progress"] = int((bytes_read / file_size) * 100) if file_size > 0 else 100
        final_hashes = {'MD5': md5.hexdigest(), 'SHA-1': sha1.hexdigest(), 'SHA-256': sha256.hexdigest()}
        hashing_status.update({"in_progress": False, "complete": True, "hashes": final_hashes})
        filename = os.path.basename(file_path)
        if filename in uploaded_files_db:
            uploaded_files_db[filename]['hash_info'] = final_hashes
            uploaded_files_db[filename]['hashing_complete'] = True
    except Exception as e:
        print(f"Error during hashing: {e}")
        hashing_status.update({"in_progress": False, "complete": True, "error": str(e)})

def extract_strings_threaded(filepath):
    """Extracts all printable strings from a file in a background thread."""
    strings_status.update({"in_progress": True, "complete": False, "progress": 0, "strings_found": 0, "preview": []})
    min_len = 4
    try:
        with open(filepath, 'rb') as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            file_size = len(mm)
            printable_chars = re.compile(b"([%s]{%d,})" % (b" -~", min_len))
            last_update_pos = 0
            for match in printable_chars.finditer(mm):
                pos = match.start()
                if pos > last_update_pos + (file_size // 100):
                    strings_status['progress'] = int((pos / file_size) * 100)
                    last_update_pos = pos

                strings_status['strings_found'] += 1
                if len(strings_status['preview']) < 100:
                    strings_status['preview'].append(match.group(0).decode('ascii', 'ignore'))

    except Exception as e:
        print(f"Error during strings extraction: {e}")
    strings_status.update({"in_progress": False, "complete": True, "progress": 100})

def attempt_decryption(filepath, encryption_type, password=None):
    """Orchestrates the decryption process in a background thread."""
    filename = os.path.basename(filepath)
    decryption_status.update({
        "in_progress": True, "complete": False, "message": "Starting decryption...",
        "success": False, "filename": filename, "progress": 0, "attempts": 0
    })
    if filename in uploaded_files_db: 
        uploaded_files_db[filename]['encryption_status']['decrypting'] = True
    decrypted_path = os.path.join(app.config['DECRYPTED_FOLDER'], f"decrypted_{filename}")

    passwords_to_try = []
    is_user_pwd = bool(password)
    if is_user_pwd:
        passwords_to_try.append(password)
    else:
        try:
            with open(app.config['DICTIONARY_FILE'], 'r') as f:
                passwords_to_try.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            decryption_status['message'] = "Password dictionary file not found."
            passwords_to_try = ["password", "123456", "admin"]

    total_passwords = len(passwords_to_try)
    if total_passwords == 0 and is_user_pwd:
        total_passwords = 1

    decryption_status['total_attempts'] = total_passwords

    success = False
    if "ZIP" in encryption_type: 
        success = crack_zip_with_passwords(filepath, decrypted_path, passwords_to_try, is_user_pwd, total_passwords)
    elif "AES" in encryption_type: 
        success = crack_openssl_aes_with_passwords(filepath, decrypted_path, passwords_to_try, is_user_pwd, total_passwords)
    elif "FERNET" in encryption_type: 
        success = crack_fernet_with_passwords(filepath, decrypted_path, passwords_to_try, is_user_pwd, total_passwords)
    else: 
        decryption_status['message'] = f"Automated decryption for '{encryption_type}' is not supported."

    decryption_status.update({'in_progress': False, 'complete': True, 'success': success, 'progress': 100})
    
    if success:
        decryption_status['message'] = "Decryption successful!"
        if filename in uploaded_files_db:
            uploaded_files_db[filename]['encryption_status']['decrypted_path'] = decrypted_path
            uploaded_files_db[filename]['encryption_status']['description'] = "File successfully decrypted."
    elif "Trying password" in decryption_status.get('message', '') or decryption_status.get('message') == "Starting decryption...":
        decryption_status['message'] = "Decryption failed. All password attempts were incorrect."

    if filename in uploaded_files_db:
        uploaded_files_db[filename]['encryption_status']['decrypting'] = False

def crack_zip_with_passwords(filepath, output_path, passwords_to_try, is_user_pwd, total_passwords):
    """Attempts to decrypt a ZIP file using a list of passwords."""
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            if not any(e.flag_bits & 0x1 for e in zf.infolist()):
                decryption_status['message'] = "Archive does not appear to be password-protected."

        for i, pwd in enumerate(passwords_to_try):
            progress = int(((i + 1) / total_passwords) * 100) if total_passwords > 0 else 50
            is_first_try_user = (i == 0 and is_user_pwd)
            decryption_status.update({
                "attempts": i + 1,
                "message": f"Trying password: {'●' * len(pwd) if is_first_try_user else f'dictionary entry #{i+1}'}",
                "progress": progress
            })
            
            try:
                with zipfile.ZipFile(filepath, 'r') as zf:
                    with tempfile.TemporaryDirectory() as temp_dir:
                        zf.extractall(path=temp_dir, pwd=pwd.encode())
                        extracted_items = os.listdir(temp_dir)
                        if extracted_items:
                            source_path = os.path.join(temp_dir, extracted_items[0])
                            if os.path.isfile(source_path):
                                shutil.copy(source_path, output_path)
                            return True
                        return True

            except (RuntimeError, zipfile.BadZipFile):
                continue
            except Exception as e:
                print(f"An unexpected error occurred during ZIP extraction: {e}")
                continue
                
    except Exception as e:
        error_message = f"Could not process as a ZIP file. Error: {e}"
        decryption_status['message'] = error_message
        print(f"ZIP cracking error: {error_message}")
        
    return False

def derive_openssl_key_iv(password, salt, key_length=32, iv_length=16):
    """Derives AES key and IV from password and salt, mimicking OpenSSL's method."""
    key_iv = b''; prev_hash = b''
    while len(key_iv) < key_length + iv_length:
        hasher = hashlib.md5()
        if prev_hash: 
            hasher.update(prev_hash)
        hasher.update(password); hasher.update(salt)
        prev_hash = hasher.digest()
        key_iv += prev_hash
    return key_iv[:key_length], key_iv[key_length:key_length + iv_length]

def crack_openssl_aes_with_passwords(filepath, output_path, passwords_to_try, is_user_pwd, total_passwords):
    """Attempts to decrypt an OpenSSL AES file using a list of passwords."""
    CHUNK_SIZE = 4 * 1024 * 1024
    try:
        with open(filepath, 'rb') as f_in:
            if f_in.read(8) != b'Salted__':
                decryption_status['message'] = "File is not in OpenSSL salted format."
                return False
            salt = f_in.read(8)

        for i, pwd_str in enumerate(passwords_to_try):
            progress = int(((i + 1) / total_passwords) * 100) if total_passwords > 0 else 50
            pwd = pwd_str.encode('utf-8')
            is_first_try_user = (i == 0 and is_user_pwd)
            decryption_status.update({
                "attempts": i + 1,
                "message": f"Trying password: {'●' * len(pwd_str) if is_first_try_user else f'dictionary entry #{i+1}'}",
                "progress": progress
            })

            temp_path = None
            try:
                key, iv = derive_openssl_key_iv(pwd, salt)
                decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
                
                with open(filepath, 'rb') as f_in_inner, tempfile.NamedTemporaryFile(mode='wb', delete=False) as temp_f:
                    temp_path = temp_f.name
                    f_in_inner.seek(16)
                    while True:
                        chunk = f_in_inner.read(CHUNK_SIZE)
                        if not chunk: 
                            break
                        temp_f.write(decryptor.update(chunk))
                    temp_f.write(decryptor.finalize())

                os.rename(temp_path, output_path)
                return True
            except ValueError:
                if temp_path and os.path.exists(temp_path): 
                    os.remove(temp_path)
                continue
            except Exception as e:
                if temp_path and os.path.exists(temp_path): 
                    os.remove(temp_path)
                continue
                
    except Exception as e:
        error_message = f"Could not process as an AES file. Error: {e}"
        decryption_status['message'] = error_message
        print(f"AES cracking error: {error_message}")
        
    return False

def crack_fernet_with_passwords(filepath, output_path, passwords_to_try, is_user_pwd, total_passwords):
    """Attempts to decrypt a Fernet encrypted file using a list of passwords."""
    try:
        with open(filepath, 'rb') as f_in:
            header = f_in.read(len(CUSTOM_ENC_HEADER))
            if header != CUSTOM_ENC_HEADER:
                decryption_status['message'] = "File is not a valid Forensic Carver encrypted file."
                return False
            
            salt = f_in.read(SALT_SIZE)
            encrypted_data = f_in.read()

        for i, pwd_str in enumerate(passwords_to_try):
            progress = int(((i + 1) / total_passwords) * 100) if total_passwords > 0 else 50
            is_first_try_user = (i == 0 and is_user_pwd)
            decryption_status.update({
                "attempts": i + 1,
                "message": f"Trying password: {'●' * len(pwd_str) if is_first_try_user else f'dictionary entry #{i+1}'}",
                "progress": progress
            })

            try:
                key = derive_key(pwd_str, salt)
                fernet = Fernet(key)
                decrypted_data = fernet.decrypt(encrypted_data)

                with open(output_path, 'wb') as f_out:
                    f_out.write(decrypted_data)
                return True

            except InvalidToken:
                continue
            except Exception as e:
                print(f"An unexpected error occurred during Fernet decryption: {e}")
                continue
                
    except Exception as e:
        error_message = f"Could not process as a Fernet file. Error: {e}"
        decryption_status['message'] = error_message
        print(f"Fernet cracking error: {error_message}")
        
    return False

def extract_docx_text(filepath):
    """Extracts all text from a .docx file."""
    if not docx:
        return "[ERROR] The 'python-docx' library is required to preview .docx files. Please run: pip install python-docx"
    try:
        doc = docx.Document(filepath)
        return '\n'.join([para.text for para in doc.paragraphs])
    except Exception as e:
        return f"[ERROR] Could not parse DOCX file: {e}"

# --- NEW PREVIEW HELPER FUNCTIONS ---
def extract_xlsx_text(filepath):
    """Extracts all text from a .xlsx file."""
    if not openpyxl:
        return "[ERROR] The 'openpyxl' library is required to preview .xlsx files. Please run: pip install openpyxl"
    try:
        workbook = openpyxl.load_workbook(filepath, read_only=True, data_only=True)
        full_text = []
        for sheet_name in workbook.sheetnames:
            full_text.append(f"--- Sheet: {sheet_name} ---\n")
            sheet = workbook[sheet_name]
            for row in sheet.iter_rows():
                row_text = [str(cell.value) if cell.value is not None else "" for cell in row]
                if any(row_text):
                    full_text.append(", ".join(row_text))
        return '\n'.join(full_text)
    except Exception as e:
        return f"[ERROR] Could not parse XLSX file: {e}"

def extract_pptx_text(filepath):
    """Extracts all text from a .pptx file."""
    if not pptx:
        return "[ERROR] The 'python-pptx' library is required to preview .pptx files. Please run: pip install python-pptx"
    try:
        presentation = pptx.Presentation(filepath)
        full_text = []
        for i, slide in enumerate(presentation.slides):
            full_text.append(f"--- Slide {i+1} ---\n")
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    full_text.append(shape.text)
        return '\n'.join(full_text)
    except Exception as e:
        return f"[ERROR] Could not parse PPTX file: {e}"

def list_archive_contents(filepath):
    """Lists the contents of various archive formats."""
    output = [f"--- Contents of {os.path.basename(filepath)} ---\n"]
    mime_type = magic.from_file(filepath, mime=True)

    try:
        if mime_type == 'application/zip':
            with zipfile.ZipFile(filepath, 'r') as zf:
                for info in zf.infolist():
                    output.append(f"{'d' if info.is_dir() else '-'} {info.date_time}\t{info.file_size}\t{info.filename}")
        elif mime_type == 'application/vnd.rar':
            if not rarfile: 
                return "[ERROR] The 'rarfile' library is required. Install with: pip install rarfile"
            with rarfile.RarFile(filepath, 'r') as rf:
                for info in rf.infolist():
                     output.append(f"{'d' if info.is_dir() else '-'} {info.date_time}\t{info.file_size}\t{info.filename}")
        elif mime_type == 'application/x-7z-compressed':
            if not py7zr: 
                return "[ERROR] The 'py7zr' library is required. Install with: pip install py7zr"
            with py7zr.SevenZipFile(filepath, 'r') as szf:
                for name in szf.getnames():
                    output.append(name)
        elif mime_type == 'application/gzip':
            try:
                with gzip.open(filepath, 'rt', errors='ignore') as gf:
                    output.append("Decompressed content preview:\n\n")
                    content_lines = [next(gf) for _ in range(1000)]
                    output.extend(content_lines)
                    if len(content_lines) == 1000:
                        output.append("\n--- [Preview truncated at 1000 lines] ---")
            except Exception as e:
                return f"[ERROR] Could not decompress GZIP file as text: {e}. It may be a compressed binary."
        else:
            return f"[INFO] Archive preview for '{mime_type}' is not supported."
        return "".join(output)
    except Exception as e:
        return f"[ERROR] Could not read archive: {e}"
def preview_deleted_file(filepath, filename):
    """Provides preview for deleted files similar to carved files."""
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        
        if not content:
            return "File is empty or could not be read."
        
        mime_type = magic.from_buffer(content, mime=True)
        data_url = f"data:{mime_type};base64,{base64.b64encode(content).decode('utf-8')}"
        
        # For small files, create text preview
        if len(content) <= 2 * 1024 * 1024:  # 2MB limit for preview
            if mime_type.startswith('text/'):
                try:
                    text_content = content.decode('utf-8', errors='ignore')
                    return render_template_string(
                        VIEW_FILE_CONTENT,
                        filename=filename,
                        mime_type=mime_type,
                        text_content=text_content,
                        is_carved=False,
                        content=content
                    )
                except:
                    pass
            
            # For images, PDFs, etc. - use embedded preview
            if mime_type.startswith(('image/', 'application/pdf', 'audio/', 'video/')):
                return render_template_string(
                    VIEW_FILE_CONTENT,
                    filename=filename,
                    mime_type=mime_type,
                    data_url=data_url,
                    is_carved=False,
                    content=content
                )
        
        # Fallback: hex preview for first 2KB
        hex_preview = format_hex_view(content[:2048])
        return render_template_string(
            VIEW_FILE_CONTENT,
            filename=filename,
            mime_type=mime_type,
            text_content=f"File too large for full preview. Hex preview (first 2KB):\n\n{hex_preview}",
            is_carved=False,
            content=content
        )
        
    except Exception as e:
        return f"Error previewing file: {str(e)}"
   
def preview_sqlite_db(filepath):
    """Previews tables and data from an SQLite database file."""
    try:
        con = sqlite3.connect(f"file:{filepath}?mode=ro", uri=True)
        cur = con.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cur.fetchall()
        output = ["--- SQLite Database Preview ---\n"]
        if not tables:
            return "Database contains no tables."

        for table_name_tuple in tables:
            table_name = table_name_tuple[0]
            output.append(f"\n-- Table: {table_name} (first 5 rows) --\n")
            cur.execute(f'PRAGMA table_info("{table_name}");')
            headers = [col[1] for col in cur.fetchall()]
            output.append(" | ".join(headers))
            output.append("-" * (sum(len(h) for h in headers) + 3*len(headers)))

            cur.execute(f'SELECT * FROM "{table_name}" LIMIT 5;')
            rows = cur.fetchall()
            for row in rows:
                output.append(" | ".join(map(str, row)))
        con.close()
        return "\n".join(output)
    except Exception as e:
        return f"[ERROR] Could not read SQLite database: {e}"

def preview_executable(filepath):
    """Provides a basic preview of an executable by extracting strings."""
    output = ["[INFO] This is a basic preview showing printable strings from the first 1MB of the file.\n"]
    try:
        with open(filepath, 'rb') as f:
            content = f.read(1024 * 1024)

        printable_chars = re.compile(b"([%s]{4,})" % b" -~")
        strings = [match.group(0).decode('ascii', 'ignore') for match in printable_chars.finditer(content)]
        output.extend(strings)
        return "\n".join(output)
    except Exception as e:
        return f"[ERROR] Could not process executable file: {e}"

def validate_and_deduplicate_file(content, seen_hashes, min_size=128):
    """
    Strict validation: Check if file is non-empty, meets minimum size, and is not a duplicate.
    Returns (is_valid, content_hash)
    """
    if not content or len(content) < min_size:
        return False, None
    
    content_hash = hashlib.md5(content).hexdigest()
    if content_hash in seen_hashes:
        return False, content_hash
    
    return True, content_hash

# --- Carving & Recovery Engines ---
def _validate_and_extract_file(mm, file_start_pos, sig_options, seen_hashes, file_size_limit):
    """Validates a data chunk with strict deduplication and empty file checking."""
    sig = sig_options[0]
    name = sig['name']
    MIN_FILE_SIZE = 128

    # --- Strategy 1: RIFF Containers (WAV, AVI) ---
    if name in ['WAV', 'AVI']:
        try:
            if file_start_pos + 12 < file_size_limit and mm[file_start_pos+8:file_start_pos+12] in [b'WAVE', b'AVI ']:
                file_size_from_header = int.from_bytes(mm[file_start_pos+4:file_start_pos+8], 'little')
                total_size = file_size_from_header + 8

                if total_size > 32:
                    end_pos = file_start_pos + total_size
                    content = mm[file_start_pos:end_pos]
                    
                    # Add validation
                    if content and len(content) >= MIN_FILE_SIZE:
                        content_hash = hashlib.md5(content[:4096]).hexdigest()
                        if content_hash not in seen_hashes:
                            seen_hashes.add(content_hash)
                            return content, sig, content_hash
        except Exception:
            pass

    # --- Strategy 2: Parse MP4/MOV Container Structure ---
    elif name == 'MP4 / MOV':
        try:
            current_offset = file_start_pos
            total_size = 0
            box_count = 0
            while current_offset + 8 < file_size_limit and box_count < 500:
                box_size = int.from_bytes(mm[current_offset:current_offset+4], 'big')
                box_type = mm[current_offset+4:current_offset+8]
                if box_size < 8 or not box_type.isalnum(): 
                    break
                total_size += box_size
                current_offset += box_size
                box_count += 1
            if total_size > 16384:
                end_pos = min(file_start_pos + total_size, file_size_limit)
                content = mm[file_start_pos:end_pos]
                if b'moov' in content or b'mdat' in content:
                    # Add validation
                    if content and len(content) >= MIN_FILE_SIZE:
                        content_hash = hashlib.md5(content[:4096]).hexdigest()
                        if content_hash not in seen_hashes:
                            seen_hashes.add(content_hash)
                            return content, sig, content_hash
        except Exception:
            pass

    # --- Strategy 3: Parse MP3 Frame Stream with Tolerance and ID3 Skipping ---
    elif name == 'MP3':
        audio_start_offset = file_start_pos
        if mm[file_start_pos:file_start_pos+3] == b'ID3':
            try:
                id3_size_bytes = mm[file_start_pos+6:file_start_pos+10]
                id3_size = (id3_size_bytes[0] << 21) | (id3_size_bytes[1] << 14) | (id3_size_bytes[2] << 7) | id3_size_bytes[3]
                audio_start_offset = file_start_pos + id3_size + 10
            except IndexError: 
                return None, None, None

        BITRATE_MAP = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
        SAMPLERATE_MAP = [44100, 48000, 32000, 0]
        current_offset = audio_start_offset
        total_size = 0
        invalid_frames_in_a_row = 0
        MAX_INVALID_FRAMES = 10

        while current_offset + 4 < file_size_limit:
            header_bytes = mm[current_offset : current_offset + 4]
            is_mpeg_frame = (header_bytes[0] == 0xFF and (header_bytes[1] & 0xE0) == 0xE0)
            if not is_mpeg_frame:
                invalid_frames_in_a_row += 1
                if invalid_frames_in_a_row >= MAX_INVALID_FRAMES: 
                    break
                current_offset += 1
                continue
            invalid_frames_in_a_row = 0
            try:
                samplerate_bits = (header_bytes[2] >> 2) & 3
                sample_rate = SAMPLERATE_MAP[samplerate_bits]
                bitrate_bits = (header_bytes[2] >> 4) & 15
                bitrate = BITRATE_MAP[bitrate_bits] * 1000
                padding_bit = (header_bytes[2] >> 1) & 1
                if bitrate == 0 or sample_rate == 0: 
                    raise ValueError("Invalid frame")
                frame_size = int((144 * bitrate / sample_rate) + padding_bit)
                if frame_size <= 1: 
                    raise ValueError("Invalid frame")
                total_size += frame_size
                current_offset += frame_size
            except (ValueError, IndexError):
                invalid_frames_in_a_row += 1
                if invalid_frames_in_a_row >= MAX_INVALID_FRAMES: 
                    break
                current_offset += 1

        if total_size > 4096:
            end_pos = audio_start_offset + total_size
            content = mm[file_start_pos:end_pos]
            # Add validation
            if content and len(content) >= MIN_FILE_SIZE:
                content_hash = hashlib.md5(content[:8192]).hexdigest()
                if content_hash not in seen_hashes:
                    seen_hashes.add(content_hash)
                    return content, sig, content_hash

    # --- Strategy 4: Basic Header/Footer Matching (JPEG, PNG, PDF, etc.) ---
    elif sig.get('footer'):
        search_limit = min(file_start_pos + sig.get('max_size', 50*1024*1024), file_size_limit)
        header_len = len(sig.get('header', sig.get('headers', [b''])[0]))
        footer_pos = mm.find(sig['footer'], file_start_pos + header_len, search_limit)
        if footer_pos != -1:
            end_pos = footer_pos + len(sig['footer'])
            content = mm[file_start_pos:end_pos]
            MIN_SIZES = {'.jpeg': 2048, '.png': 256, '.zip': 128, '.pdf': 1024, '.docx': 4096}
            
            # Add validation with file format-specific minimum sizes
            min_size = MIN_SIZES.get(sig['extension'], MIN_FILE_SIZE)
            if content and len(content) >= min_size:
                content_hash = hashlib.md5(content[:4096]).hexdigest()
                if content_hash in seen_hashes: 
                    return None, None, None
                try:
                    if sig['extension'] in ['.jpeg', '.png', '.gif']: 
                        Image.open(io.BytesIO(content)).verify()
                    elif sig['extension'] in ['.docx', '.xlsx', '.pptx', '.zip']:
                        with zipfile.ZipFile(io.BytesIO(content)) as zf:
                            if zf.testzip() is not None: 
                                return None, None, None
                    elif sig['extension'] == '.pdf':
                        if not content.strip().endswith(b'%%EOF'): 
                            return None, None, None
                    
                    # Final validation check before returning
                    if content_hash not in seen_hashes:
                        seen_hashes.add(content_hash)
                        return content, sig, content_hash
                except Exception:
                    return None, None, None

    return None, None, None
# --- NEW, CORRECTED CARVER ---
def simple_file_carver(filepath, selected_types):
    """High-speed carver that eliminates empty files and duplicates."""
    global carving_status
    
    # Initialize status
    carving_status.update({
        "progress": 0, "current_offset": "0x00000000", "files_found": 0,
        "complete": False, "found_files_list": [], "error": None,
         "start_time": time.time(), 
        "estimated_total_time": None, 
        "elapsed_time": "0s",
        "last_update_time": time.time(),
        "bytes_processed": 0,
        "total_bytes": os.path.getsize(filepath)
    })
    
    output_dir = app.config['CARVED_FOLDER']
    file_counter = 0
    seen_hashes = set()
    MIN_FILE_SIZE = 128  # Minimum file size to consider valid

    # Enhanced directory clearing with better error handling
    try:
        os.makedirs(output_dir, exist_ok=True)
        for item_name in os.listdir(output_dir):
            item_path = os.path.join(output_dir, item_name)
            try:
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:
                print(f"Warning: Could not remove {item_path}: {e}")
    except Exception as e:
        error_msg = f"Permission Error: Could not clear old results in {output_dir}. Details: {e}"
        carving_status.update({"error": error_msg, "complete": True})
        return

    # Filter signatures based on selection
    signatures_to_find = {}
    for category, types in FILE_SIGNATURES.items():
        for name, sig in types.items():
            if name in selected_types:
                signatures_to_find[name] = sig

    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                for name, sig in signatures_to_find.items():
                    headers = sig.get('headers', [])
                    if sig.get('header') and sig['header'] not in headers:
                        headers.append(sig['header'])
                    
                    for header in headers:
                        if not header:
                            continue
                            
                        current_pos = 0
                        while current_pos < file_size:
                            found_pos = mm.find(header, current_pos)
                            if found_pos == -1:
                                break
                            
                            # Extract file data
                            file_data = extract_file_data(mm, found_pos, sig, file_size)
                            
                            # STRICT VALIDATION: Skip empty files and files below minimum size
                            if not file_data or len(file_data) < MIN_FILE_SIZE:
                                current_pos = found_pos + 1
                                continue
                            
                            # STRICT DEDUPLICATION: Calculate content hash
                            content_hash = hashlib.md5(file_data).hexdigest()
                            if content_hash in seen_hashes:
                                current_pos = found_pos + 1
                                continue
                            seen_hashes.add(content_hash)
                            
                            file_counter += 1
                            
                            # Save file with metadata
                            if save_carved_file(file_data, found_pos, name, sig, file_counter, output_dir):
                                # Update status
                                update_carving_status(file_counter, found_pos, file_data, file_size, name)
                            
                            current_pos = found_pos + 1
                            
    except Exception as e:
        carving_status["error"] = f"Carving process error: {e}"
        print(f"Error during carving: {e}")
    finally:
       carving_status.update({
            "progress": 100, 
            "complete": True,
            "elapsed_time": format_time(time.time() - carving_status["start_time"]),
            "time_remaining_str": "Complete",
            "estimated_total_time": format_time(time.time() - carving_status["start_time"])
        })
    print(f"Carving complete. Found {carving_status['files_found']} valid, non-duplicate files.")
       
def extract_file_data(mm, found_pos, sig, file_size):
    """Extract file data based on signature rules with strict validation."""
    footer = sig.get('footer')
    max_size = sig.get('max_size', 10 * 1024 * 1024)
    
    if footer:
        search_limit = min(found_pos + sig.get('max_size', 50 * 1024 * 1024), file_size)
        end_pos = mm.find(footer, found_pos + len(sig.get('header', b'')), search_limit)
        if end_pos != -1:
            file_data = mm[found_pos: end_pos + len(footer)]
            # Validate file size and content
            if len(file_data) >= 128:  # Minimum valid file size
                return file_data
    else:
        file_data = mm[found_pos: min(found_pos + max_size, file_size)]
        if len(file_data) >= 128:  # Minimum valid file size
            return file_data
    
    return b''

def extract_file_data(mm, found_pos, sig, file_size):
    """Extract file data based on signature rules."""
    footer = sig.get('footer')
    max_size = sig.get('max_size', 10 * 1024 * 1024)
    
    if footer:
        search_limit = min(found_pos + sig.get('max_size', 50 * 1024 * 1024), file_size)
        end_pos = mm.find(footer, found_pos + len(sig.get('header', b'')), search_limit)
        if end_pos != -1:
            return mm[found_pos: end_pos + len(footer)]
    else:
        return mm[found_pos: min(found_pos + max_size, file_size)]
    
    return b''

def save_carved_file(file_data, found_pos, name, sig, file_counter, output_dir):
    """Save carved file with proper naming convention."""
    try:
        offset_hex = f"{found_pos:08X}"
        size_bytes = len(file_data)
        safe_name = name.lower().replace(' ', '_').replace('/', '_')
        extension = sig.get('extension', '.bin')
        filename = f"{file_counter}-{offset_hex}-{size_bytes}-{safe_name}{extension}"
        
        save_path = os.path.join(output_dir, filename)
        with open(save_path, 'wb') as out_file:
            out_file.write(file_data)
        return True
    except Exception as e:
        print(f"Error saving file {filename}: {e}")
        return False

def update_carving_status(file_counter, found_pos, file_data, file_size, name):
    """Update the global carving status."""
    global carving_status
    offset_hex = f"{found_pos:08X}"
    
    file_info = {
        "name": f"{file_counter}-{offset_hex}-{len(file_data)}-{name}",
        "offset": f"0x{offset_hex}",
        "hex_preview": format_hex_view(file_data[:256])
    }
    
    carving_status.update({
        "files_found": file_counter,
        "current_offset": f"0x{offset_hex}",
        "progress": int((found_pos / file_size) * 100) if file_size > 0 else 0
    })
    carving_status["found_files_list"].append(file_info)

def _scan_partition_worker(args):
    """Worker function for parallel partition scanning with deep scan and deduplication."""
    filepath, part_info, fs_offset = args
    found_files = {}
    errors = []
    seen_hashes = set()

    try:
        img = pytsk3.Img_Info(filepath)
        fs = pytsk3.FS_Info(img, offset=fs_offset)

        def process_deleted_file(fs_object, recovery_method):
            """Helper to process, hash, and add a unique, non-empty deleted file."""
            try:
                if not fs_object.info or not fs_object.info.meta or fs_object.info.meta.size <= 0:
                    return

                content_preview = fs_object.read_random(0, min(4096, fs_object.info.meta.size))
                if not content_preview:
                    return

                file_hash = hashlib.md5(content_preview).hexdigest()
                if file_hash in seen_hashes:
                    return

                seen_hashes.add(file_hash)

                name_str = fs_object.info.name.name.decode('utf-8', 'ignore') if fs_object.info.name else "orphaned_file"
                inode = str(fs_object.info.meta.addr)

                file_info = {
                    'inode': inode, 'name': name_str, 'size': fs_object.info.meta.size,
                    'mtime': datetime.datetime.fromtimestamp(fs_object.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S'),
                    'ctime': datetime.datetime.fromtimestamp(fs_object.info.meta.ctime).strftime('%Y-%m-%d %H:%M:%S'),
                    'recovery_method': recovery_method,
                    'file_type': magic.from_buffer(content_preview, mime=True),
                    'fs_offset': fs_offset
                }
                found_files[inode] = file_info
            except Exception as e:
                pass

        # --- Scan Strategy 1: Directory Walk ---
        def directory_walk(directory, parent_path):
            for fs_object in directory:
                try:
                    name_info = fs_object.info.name
                    if not name_info or name_info.name in [b'.', b'..']:
                        continue

                    full_path = f"{parent_path.rstrip('/')}/{name_info.name.decode('utf-8', 'ignore')}"
                    is_deleted_recycled = '$Recycle.Bin' in full_path or 'RECYCLED' in full_path or '/.Trash' in full_path
                    is_deleted_unalloc = hasattr(fs_object.info.meta, 'flags') and (fs_object.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC)

                    if is_deleted_recycled or is_deleted_unalloc:
                        process_deleted_file(fs_object, 'Recycle Bin' if is_deleted_recycled else 'Metadata')

                    if fs_object.info.meta and fs_object.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                        directory_walk(fs_object.as_directory(), full_path)
                except Exception:
                    continue

        directory_walk(fs.open_dir(path="/"), "/")

        # --- Scan Strategy 2: Deep Inode Scan ---
        last_inode = fs.info.last_inum
        for inode_num in range(fs.info.first_inum, last_inode + 1):
            try:
                fs_file = fs.open_meta(inode=inode_num)
                if fs_file.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC and str(inode_num) not in found_files:
                    process_deleted_file(fs_file, 'Deep Inode Scan')
            except (IOError, AttributeError):
                continue

    except IOError as e:
        errors.append(f"Could not open filesystem on partition {part_info['desc']}: {e}")

    return found_files, errors

# --- Find and REPLACE your 'scan_for_deleted_files_engine' function with this new version ---

def recover_deleted_files_engine(filepath):
    """Advanced deleted files recovery with multiple scanning methods like Autopsy."""
    global deleted_scan_status
    
    # Initialize global status if not exists
    if 'deleted_scan_status' not in globals():
        deleted_scan_status = {}
    
    deleted_scan_status.update({
        "in_progress": True, 
        "complete": False, 
        "files_found": 0, 
        "message": "Starting advanced deleted files recovery...",
        "scan_methods": {
            "directory_walk": 0,
            "inode_scan": 0,
            "file_slack": 0,
            "unallocated_space": 0,
            "recycle_bin": 0
        }
    })

    recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    seen_hashes = set()
    MIN_FILE_SIZE = 128
    
    # Initialize database for storing file info
    deleted_files_db = {}
    
    # Clear previous results
    try:
        for item in os.listdir(recovery_dir):
            item_path = os.path.join(recovery_dir, item)
            if os.path.isfile(item_path):
                os.unlink(item_path)
    except Exception as e:
        deleted_scan_status["message"] = f"Error clearing old files: {e}"
        deleted_scan_status["in_progress"] = False
        return

    total_recovered = 0
    
    # Status update function
    def update_status(method, count=1):
        nonlocal total_recovered
        total_recovered += count
        deleted_scan_status["files_found"] = total_recovered
        deleted_scan_status["scan_methods"][method] += count
        deleted_scan_status["message"] = f"Recovered {total_recovered} files... ({method})"

    def process_deleted_file(fs_object, recovery_method, fs_offset=0):
        try:
            if not fs_object.info or not fs_object.info.meta or fs_object.info.meta.size <= 0:
                return

            # Get offset information if available
            file_offset = "Unknown"
            if hasattr(fs_object.info.meta, 'addr'):
                file_offset = f"0x{fs_object.info.meta.addr:08X}"
            
            content_preview = fs_object.read_random(0, min(4096, fs_object.info.meta.size))
            if not content_preview:
                return

            file_hash = hashlib.md5(content_preview).hexdigest()
            if file_hash in seen_hashes:
                return

            seen_hashes.add(file_hash)

            name_str = fs_object.info.name.name.decode('utf-8', 'ignore') if (fs_object.info.name and hasattr(fs_object.info.name, 'name')) else "orphaned_file"
            inode = str(fs_object.info.meta.addr) if hasattr(fs_object.info.meta, 'addr') else "unknown"

            try:
                file_type = magic.from_buffer(content_preview, mime=True)
            except:
                file_type = "unknown"

            file_info = {
                'inode': inode,
                'name': name_str,
                'size': fs_object.info.meta.size,
                'offset': file_offset,
                'offset_decimal': fs_object.info.meta.addr if hasattr(fs_object.info.meta, 'addr') else 0,
                'mtime': datetime.datetime.fromtimestamp(fs_object.info.meta.mtime).strftime('%Y-%m-%d %H:%M:%S') if fs_object.info.meta.mtime else 'Unknown',
                'ctime': datetime.datetime.fromtimestamp(fs_object.info.meta.ctime).strftime('%Y-%m-%d %H:%M:%S') if fs_object.info.meta.ctime else 'Unknown',
                'recovery_method': recovery_method,
                'file_type': file_type,
                'fs_offset': fs_offset
            }
            
            # Save the actual file content
            try:
                full_content = fs_object.read_random(0, min(fs_object.info.meta.size, 100*1024*1024))  # Limit to 100MB
                safe_filename = f"deleted_{inode}_{secure_filename(name_str)}"
                save_path = os.path.join(recovery_dir, safe_filename)
                
                with open(save_path, 'wb') as f:
                    f.write(full_content)
                
                # Store in database with offset info
                deleted_files_db[safe_filename] = file_info
                update_status(recovery_method)
                
            except Exception as e:
                print(f"Error saving deleted file: {e}")
        except Exception as e:
            print(f"Error processing deleted file: {e}")

    try:
        img_handle = pytsk3.Img_Info(filepath)
        
        # Method 1: Directory Walk (Deleted entries)
        def deep_directory_scan(fs, directory, path="/"):
            try:
                for f in directory:
                    if not hasattr(f.info, 'meta') or f.info.meta is None:
                        continue
                    
                    # Check if file is deleted
                    is_deleted = not (f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                    is_file = f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
                    has_name = hasattr(f.info, 'name') and f.info.name is not None
                    
                    if is_deleted and is_file and has_name and f.info.name.name not in [b'.', b'..']:
                        process_deleted_file(f, "directory_walk")
                    
                    # Recursively scan subdirectories
                    if (f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and 
                        has_name and f.info.name.name not in [b'.', b'..']):
                        try:
                            deep_directory_scan(fs, f.as_directory(), 
                                              f"{path}/{f.info.name.name.decode('utf-8', 'ignore')}")
                        except (IOError, AttributeError):
                            continue
            except Exception as e:
                pass

        # Method 2: Deep Inode Scan
        def deep_inode_scan(fs):
            try:
                last_inode = fs.info.last_inum
                for inode_num in range(fs.info.first_inum, last_inode + 1):
                    try:
                        fs_file = fs.open_meta(inode=inode_num)
                        
                        # Check if inode is unallocated (deleted) but has content
                        if (fs_file.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC and 
                            fs_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and 
                            fs_file.info.meta.size > MIN_FILE_SIZE):
                            process_deleted_file(fs_file, "inode_scan")
                    except (IOError, AttributeError):
                        continue
            except Exception as e:
                pass

        # Method 3: File Slack Space Recovery
        def recover_file_slack(fs, directory, path="/"):
            try:
                for f in directory:
                    if not hasattr(f.info, 'meta') or f.info.meta is None:
                        continue
                    
                    # Check allocated files for slack space
                    is_allocated = (f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                    is_file = f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
                    
                    if is_allocated and is_file and f.info.meta.size > 0:
                        try:
                            # Calculate potential slack space
                            block_size = fs.info.block_size
                            actual_size = f.info.meta.size
                            blocks_used = (actual_size + block_size - 1) // block_size
                            slack_size = (blocks_used * block_size) - actual_size
                            
                            if slack_size > MIN_FILE_SIZE:
                                # Read slack space from end of file
                                slack_content = f.read_random(actual_size, slack_size)
                                
                                if slack_content and len(slack_content) >= MIN_FILE_SIZE:
                                    content_hash = hashlib.md5(slack_content).hexdigest()
                                    if content_hash not in seen_hashes:
                                        seen_hashes.add(content_hash)
                                        
                                        original_name = f.info.name.name.decode('utf-8', 'ignore') if hasattr(f.info, 'name') else f"file_{f.info.meta.addr}"
                                        safe_filename = secure_filename(f"slack_{f.info.meta.addr}_{original_name}")
                                        save_path = os.path.join(recovery_dir, safe_filename)
                                        
                                        with open(save_path, 'wb') as out_file:
                                            out_file.write(slack_content)
                                        
                                        update_status("file_slack")
                        except Exception:
                            continue
                    
                    # Recursively scan subdirectories
                    if (f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and 
                        hasattr(f.info, 'name') and f.info.name.name not in [b'.', b'..']):
                        try:
                            recover_file_slack(fs, f.as_directory(), 
                                            f"{path}/{f.info.name.name.decode('utf-8', 'ignore')}")
                        except (IOError, AttributeError):
                            continue
            except Exception as e:
                pass

        # Method 4: Recycle Bin/Trash Recovery
        def recover_recycle_bin(fs, directory, path="/"):
            try:
                for f in directory:
                    if not hasattr(f.info, 'meta') or f.info.meta is None:
                        continue
                    
                    current_path = f"{path}/{f.info.name.name.decode('utf-8', 'ignore')}" if hasattr(f.info, 'name') else path
                    
                    # Check for recycle bin directories
                    is_recycle_bin = any(keyword in current_path.upper() for keyword in 
                                       ['$RECYCLE.BIN', 'RECYCLED', '.TRASH', 'RECYCLE.BIN'])
                    
                    if is_recycle_bin and f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
                        process_deleted_file(f, "recycle_bin")
                    
                    # Recursively scan subdirectories
                    if f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and hasattr(f.info, 'name'):
                        try:
                            recover_recycle_bin(fs, f.as_directory(), current_path)
                        except (IOError, AttributeError):
                            continue
            except Exception as e:
                pass

        # Execute all recovery methods
        try:
            # Try to handle partition table first
            volume = pytsk3.Volume_Info(img_handle)
            for part in volume:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                    try:
                        fs_offset = part.start * volume.info.block_size
                        fs = pytsk3.FS_Info(img_handle, offset=fs_offset)
                        
                        deleted_scan_status["message"] = f"Scanning partition {part.desc}..."
                        
                        # Run all recovery methods
                        deep_directory_scan(fs, fs.open_dir(path="/"))
                        deep_inode_scan(fs)
                        recover_file_slack(fs, fs.open_dir(path="/"))
                        recover_recycle_bin(fs, fs.open_dir(path="/"))
                        
                    except IOError:
                        continue
        except IOError:
            # Try as single filesystem
            try:
                fs = pytsk3.FS_Info(img_handle, offset=0)
                deleted_scan_status["message"] = "Scanning as single filesystem..."
                
                deep_directory_scan(fs, fs.open_dir(path="/"))
                deep_inode_scan(fs)
                recover_file_slack(fs, fs.open_dir(path="/"))
                recover_recycle_bin(fs, fs.open_dir(path="/"))
                
            except IOError as e:
                deleted_scan_status["message"] = f"Error opening filesystem: {e}"

        deleted_scan_status["message"] = f"Recovery complete! Found {total_recovered} files using multiple methods."
        deleted_scan_status["complete"] = True
        
    except Exception as e:
        deleted_scan_status["message"] = f"A critical error occurred: {e}"
        deleted_scan_status["complete"] = True
        
    deleted_scan_status["in_progress"] = False
    return deleted_files_db  # Return the database of recovered files
    # --- Reporting Helper Functions ---
def generate_docx_report_data(case_details, evidence_file, carved_files, deleted_files, now):
    """Generate a DOCX report for the forensic case."""
    if docx is None: 
        return None
    from docx.shared import Inches
    doc = docx.Document()
    doc.add_heading('Forensic Report', 0)
    doc.add_paragraph(f"Generated by ForensicCarver Pro on {now.strftime('%Y-%m-%d %H:%M:%S')}")
    doc.add_heading('Case Details', level=1)
    table = doc.add_table(rows=3, cols=2)
    table.style = 'Light List'
    table.cell(0, 0).text = 'Case Name'
    table.cell(0, 1).text = case_details.get('name', '')
    table.cell(1, 0).text = 'Case Number'
    table.cell(1, 1).text = case_details.get('number', '')
    table.cell(2, 0).text = 'Examiner'
    table.cell(2, 1).text = case_details.get('examiner', '')

    for filename, details in evidence_file.items():
        doc.add_heading(f"Data Source: {filename}", level=1)
        t = doc.add_table(rows=4, cols=2)
        t.style = 'Light List'
        t.cell(0, 0).text = 'File Size'
        t.cell(0, 1).text = str(details.get('size_mb', '')) + " MB"
        t.cell(1, 0).text = 'MD5 Hash'
        t.cell(1, 1).text = details.get('hash_info', {}).get('MD5', 'N/A')
        t.cell(2, 0).text = 'SHA-1 Hash'
        t.cell(2, 1).text = details.get('hash_info', {}).get('SHA-1', 'N/A')
        t.cell(3, 0).text = 'SHA-256 Hash'
        t.cell(3, 1).text = details.get('hash_info', {}).get('SHA-256', 'N/A')
        doc.add_heading('Partition Information', level=2)
        if details.get('partition_info'):
            ptable = doc.add_table(rows=1, cols=4)
            ptable.style = 'Light List'
            hdr_cells = ptable.rows[0].cells
            hdr_cells[0].text = 'Index'
            hdr_cells[1].text = 'Description'
            hdr_cells[2].text = 'Start Sector'
            hdr_cells[3].text = 'Length (Sectors)'
            for part in details['partition_info']:
                row_cells = ptable.add_row().cells
                row_cells[0].text = str(part.get('addr', ''))
                row_cells[1].text = str(part.get('desc', ''))
                row_cells[2].text = str(part.get('start', ''))
                row_cells[3].text = str(part.get('len', ''))
        else:
            doc.add_paragraph("No partition data found.")

    doc.add_heading(f"Carved Files ({len(carved_files)} found)", level=1)
    ctable = doc.add_table(rows=1, cols=4)
    ctable.style = 'Light List'
    ctable.rows[0].cells[0].text = 'ID'
    ctable.rows[0].cells[1].text = 'Filename'
    ctable.rows[0].cells[2].text = 'Offset'
    ctable.rows[0].cells[3].text = 'Size (KB)'
    for file in sorted(carved_files.values(), key=lambda x: x.get('id', 0)):
        row = ctable.add_row().cells
        row[0].text = str(file.get('id', ''))
        row[1].text = file.get('name', '')
        row[2].text = file.get('offset', '')
        row[3].text = file.get('size_kb', '')

    doc.add_heading(f"Deleted File Entries ({len(deleted_files)} found)", level=1)
    dtable = doc.add_table(rows=1, cols=6)
    dtable.style = 'Light List'
    dtable.rows[0].cells[0].text = 'Inode'
    dtable.rows[0].cells[1].text = 'Filename'
    dtable.rows[0].cells[2].text = 'Size (Bytes)'
    dtable.rows[0].cells[3].text = 'Modified'
    dtable.rows[0].cells[4].text = 'Accessed'
    dtable.rows[0].cells[5].text = 'Created'
    for inode, file in deleted_files.items():
        row = dtable.add_row().cells
        row[0].text = str(file.get('inode', ''))
        row[1].text = file.get('name', '')
        row[2].text = str(file.get('size', ''))
        row[3].text = file.get('mtime', '')
        row[4].text = file.get('atime', '')
        row[5].text = file.get('ctime', '')

    buffer = io.BytesIO()
    doc.save(buffer)
    buffer.seek(0)
    return buffer

def generate_csv_zip_report_data(case_details, evidence_file, carved_files, deleted_files):
    """Generate a ZIP file containing CSV reports for the case."""
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        case_csv = io.StringIO()
        writer = csv.writer(case_csv)
        writer.writerow(['Case Name', 'Case Number', 'Examiner'])
        writer.writerow([case_details.get('name', ''), case_details.get('number', ''), case_details.get('examiner', '')])
        zf.writestr('case_details.csv', case_csv.getvalue())

        evidence_csv = io.StringIO()
        writer = csv.writer(evidence_csv)
        writer.writerow(['Filename', 'Size (MB)', 'MD5', 'SHA-1', 'SHA-256'])
        for filename, details in evidence_file.items():
            writer.writerow([
                filename,
                details.get('size_mb', ''),
                details.get('hash_info', {}).get('MD5', ''),
                details.get('hash_info', {}).get('SHA-1', ''),
                details.get('hash_info', {}).get('SHA-256', ''),
            ])
        zf.writestr('evidence_files.csv', evidence_csv.getvalue())

        carved_csv = io.StringIO()
        writer = csv.writer(carved_csv)
        writer.writerow(['ID', 'Filename', 'Offset', 'Size (KB)'])
        for file in sorted(carved_files.values(), key=lambda x: x.get('id', 0)):
            writer.writerow([file.get('id', ''), file.get('name', ''), file.get('offset', ''), file.get('size_kb', ''),])
        zf.writestr('carved_files.csv', carved_csv.getvalue())

        deleted_csv = io.StringIO()
        writer = csv.writer(deleted_csv)
        writer.writerow(['Inode', 'Filename', 'Size (Bytes)', 'Modified', 'Accessed', 'Created'])
        for inode, file in deleted_files.items():
            writer.writerow([file.get('inode', ''), file.get('name', ''), file.get('size', ''), file.get('mtime', ''), file.get('atime', ''), file.get('ctime', ''),])
        zf.writestr('deleted_files.csv', deleted_csv.getvalue())

    memory_file.seek(0)
    return memory_file

# --- HTML TEMPLATES ---
BASE_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ForensicCarver Pro</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { 
            background-color: #111827; 
            color: #d1d5db; 
            font-family: 'Inter', sans-serif; 
        }
        .sidebar { 
            background-color: #1f2937; 
        }
        .sidebar a { 
            border-left: 3px solid transparent; 
            transition: all 0.2s ease-in-out; 
        }
        .sidebar a.active { 
            border-left-color: #3b82f6; 
            background-color: #374151; 
            color: white; 
        }
        .card { 
            background-color: #1f2937; 
            border: 1px solid #374151; 
            box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1); 
        }
        .btn-primary, .btn-secondary, .btn-green, .bg-red-600 { 
            transition: all 0.2s ease-in-out; 
        }
        .btn-primary:hover, .btn-secondary:hover, .btn-green:hover, .bg-red-600:hover { 
            opacity: 0.9; 
            transform: translateY(-1px); 
        }
        .btn-primary { 
            background-color: #3b82f6; 
            color: white; 
        }
        .btn-secondary { 
            background-color: #4b5563; 
            color: white; 
        }
        .btn-green { 
            background-color: #10b981; 
            color: white; 
        }
        .hex-view { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0d1117; 
            border: 1px solid #374151; 
        }
        .log-view { 
            font-family: 'Courier New', Courier, monospace; 
            background-color: #0d1117; 
            color: #d1d5db; 
            border: 1px solid #374151; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
        }
        .encryption-badge { 
            background-color: #ef4444; 
            color: white; 
            padding: 2px 8px; 
            border-radius: 4px; 
            font-size: 0.75rem; 
            font-weight: bold; 
        }
        .decryption-badge { 
            background-color: #10b981; 
            color: white; 
            padding: 2px 8px; 
            border-radius: 4px; 
            font-size: 0.75rem; 
            font-weight: bold; 
        }
        .decrypting-badge { 
            background-color: #f59e0b; 
            color: white; 
            padding: 2px 8px; 
            border-radius: 4px; 
            font-size: 0.75rem; 
            font-weight: bold; 
        }
        .modal { 
            display: none; 
            position: fixed; 
            z-index: 1000; 
            left: 0; 
            top: 0; 
            width: 100%; 
            height: 100%; 
            background-color: rgba(0,0,0,0.7); 
        }
        .modal-content { 
            background-color: #1f2937; 
            margin: 15% auto; 
            padding: 20px; 
            border: 1px solid #374151; 
            width: 50%; 
            border-radius: 8px; 
            box-shadow: 0 4px 8px 0 rgba(0,0,0,0.2); 
        }
        .close { 
            color: #aaa; 
            float: right; 
            font-size: 28px; 
            font-weight: bold; 
            cursor: pointer; 
        }
        .close:hover { 
            color: white; 
        }
    </style>
    <link rel="stylesheet" href="https://rsms.me/inter/inter.css">
</head>
<body class="flex h-screen">
    <aside class="sidebar w-64 p-4 space-y-2 flex-shrink-0 overflow-y-auto">
        <div class="text-white text-2xl font-bold mb-8">
            ForensicCarver <span class="text-blue-500">Pro</span>
            <p class="text-xs font-normal text-gray-400">Digital Evidence Analysis</p>
        </div>
        <a href="{{ url_for('evidence_upload') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'evidence_upload' %}active{% endif %}">Evidence & Upload</a>
        <a href="{{ url_for('encryption_page') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'encryption_page' %}active{% endif %}">File Encryption</a>
        {% if uploaded_files_db %}
        <a href="{{ url_for('decryption_page', filename=(uploaded_files_db.keys()|first)) if uploaded_files_db and uploaded_files_db[(uploaded_files_db.keys()|first)].encryption_status.encrypted else '#' }}" class="block p-3 rounded-lg {% if uploaded_files_db and uploaded_files_db[(uploaded_files_db.keys()|first)].encryption_status.encrypted %} hover:bg-gray-700 {% else %} text-gray-600 cursor-not-allowed {% endif %} {% if request.endpoint == 'decryption_page' or request.endpoint == 'decryption_progress' %}active{% endif %}">Decryption</a>
        <a href="{{ url_for('forensic_analysis') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'forensic_analysis' %}active{% endif %}">Forensic Analysis</a>
        <a href="{{ url_for('auto_carving_setup') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'auto_carving_setup' %}active{% endif %}">Auto Carving</a>
        <a href="{{ url_for('recovered_files') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'recovered_files' %}active{% endif %}">Recovered Files</a>
        <a href="{{ url_for('deleted_files_status_page') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'deleted_files_status_page' or request.endpoint == 'deleted_files' %}active{% endif %}">Deleted Files</a>
        <a href="{{ url_for('log_file_viewer') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'log_file_viewer' %}active{% endif %}">Log File Viewer</a>
        <a href="{{ url_for('event_log_viewer') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'event_log_viewer' %}active{% endif %}">Event Log Viewer</a>
        <a href="{{ url_for('reporting') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'reporting' %}active{% endif %}">Reporting</a>
        <a href="{{ url_for('manual_carving') }}" class="block p-3 rounded-lg hover:bg-gray-700 {% if request.endpoint == 'manual_carving' %}active{% endif %}">Manual Carving</a>
        {% endif %}
        <div class="pt-4 text-xs text-gray-500">Version 4.3.0<br>Licensed to: Forensics Lab</div>
    </aside>
    
    <main class="flex-1 p-8 overflow-y-auto">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="bg-{% if category == 'success' %}green{% else %}blue{% endif %}-600 text-white p-4 rounded-lg mb-4">
                        {{ message | safe }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        {{ content|safe }}
    </main>
    
    <div id="uploadConfirmModal" class="modal">
        <div class="modal-content">
            <h2 class="text-xl font-semibold text-white mb-4">Confirm Large File Upload</h2>
            <p id="uploadConfirmText" class="text-gray-300 mb-6"></p>
            <div class="flex justify-end space-x-4">
                <button id="confirmCancelBtn" class="btn-secondary px-4 py-2 rounded-lg">Cancel</button>
                <button id="confirmOkBtn" class="btn-primary px-4 py-2 rounded-lg">Continue</button>
            </div>
        </div>
    </div>
    
    <div id="uploadCompleteModal" class="modal">
        <div class="modal-content">
            <h2 class="text-xl font-semibold text-white mb-4">Upload Complete</h2>
            <p class="text-gray-300 mb-6">File has been uploaded and is ready for analysis.</p>
            <div class="flex justify-end">
                <button id="closeUploadModalBtn" class="btn-green px-4 py-2 rounded-lg">OK</button>
            </div>
        </div>
    </div>
</body>
</html>
"""

DECRYPTION_PROGRESS_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-2">Decryption in Progress</h1>
<p class="text-gray-400 mb-8">Attempting to decrypt <strong class="font-mono text-blue-400">{{ filename }}</strong>. Please wait.</p>
<div class="card p-6 rounded-lg">
    <div class="flex justify-between items-center mb-4">
        <h2 id="status-header" class="text-xl font-semibold text-white">Initializing...</h2>
        <span id="progress-percent" class="font-bold text-blue-400">0%</span>
    </div>
    <div class="w-full bg-gray-700 rounded-full h-4">
        <div id="progress-bar" class="bg-blue-600 h-4 rounded-full transition-all duration-500" style="width: 0%"></div>
    </div>
    <p class="text-sm text-gray-400 mt-2">Status: <span id="status-message" class="text-yellow-400">Starting process...</span></p>
    <p class="text-sm text-gray-400 mt-1">Attempts: <span id="attempts-count">0 / 0</span></p>
</div>

<div id="result-container" class="mt-8 text-center hidden">
    <div id="result-card" class="card p-8 rounded-lg inline-block">
        <h2 id="result-title" class="text-2xl font-bold mb-4"></h2>
        <p id="result-message" class="text-gray-300 mb-6"></p>
        <a id="result-button" href="#" class="btn-primary px-8 py-3 rounded-lg font-semibold">Continue</a>
    </div>
</div>

<script>
function updateProgress() {
    fetch('/decryption_status')
        .then(response => response.json())
        .then(data => {
            if (!data.filename) return;

            const progressBar = document.getElementById('progress-bar');
            const progressPercent = document.getElementById('progress-percent');
            const statusHeader = document.getElementById('status-header');
            const statusMessage = document.getElementById('status-message');
            const attemptsCount = document.getElementById('attempts-count');
            
            progressBar.style.width = data.progress + '%';
            progressPercent.textContent = data.progress + '%';
            statusMessage.textContent = data.message;
            attemptsCount.textContent = `${data.attempts} / ${data.total_attempts}`;

            if (data.in_progress) {
                statusHeader.textContent = "Decryption Running...";
                setTimeout(updateProgress, 1000);
            } else if (data.complete) {
                const resultContainer = document.getElementById('result-container');
                const resultCard = document.getElementById('result-card');
                const resultTitle = document.getElementById('result-title');
                const resultMessage = document.getElementById('result-message');
                const resultButton = document.getElementById('result-button');
                
                resultContainer.classList.remove('hidden');

                if (data.success) {
                    statusHeader.textContent = "Decryption Successful!";
                    progressPercent.textContent = '100%';
                    progressBar.style.width = '100%';
                    progressBar.classList.remove('bg-blue-600');
                    progressBar.classList.add('bg-green-600');
                    statusMessage.textContent = "File decrypted successfully.";
                    
                    resultCard.classList.add('border', 'border-green-500');
                    resultTitle.textContent = "✅ Success!";
                    resultTitle.classList.add('text-green-400');
                    resultMessage.textContent = "The evidence file has been decrypted. You can now proceed with the analysis.";
                    resultButton.href = "{{ url_for('forensic_analysis') }}";
                    resultButton.textContent = "Go to Analysis";
                } else {
                    statusHeader.textContent = "Decryption Failed";
                    progressBar.classList.remove('bg-blue-600');
                    progressBar.classList.add('bg-red-600');
                    statusMessage.textContent = data.message;
                    
                    resultCard.classList.add('border', 'border-red-500');
                    resultTitle.textContent = "❌ Failed";
                    resultTitle.classList.add('text-red-400');
                    resultMessage.textContent = "Could not decrypt the file with the provided passwords. You can return to the decryption page to try again.";
                    resultButton.href = "{{ url_for('decryption_page', filename=filename) }}";
                    resultButton.textContent = "Try Again";
                }
            }
        });
}
document.addEventListener('DOMContentLoaded', updateProgress);
</script>
"""

EVIDENCE_UPLOAD_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Evidence File Management</h1>
<p class="text-gray-400 mb-8">Upload new evidence or load an existing file from the database for analysis.</p>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
    <div class="space-y-8">
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Upload New Evidence File</h2>
            <p class="text-xs text-gray-400 mb-4">Supported formats: .dd, .e01, .mem, .raw, .img, .vmdk</p>
            <form id="upload-form" method="post" enctype="multipart/form-data" class="border-2 border-dashed border-gray-600 rounded-lg p-12 text-center">
                <p class="mb-4">Drop evidence file here or click to browse</p>
                <input type="file" name="file" class="hidden" id="file-input">
                <label for="file-input" class="btn-primary px-6 py-2 rounded-lg cursor-pointer">Select File</label>
                <button type="submit" class="btn-green px-6 py-2 rounded-lg ml-4">Upload</button>
            </form>
        </div>
        
        {% if db_files %}
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Load Existing Evidence from Database</h2>
            <div class="space-y-2 max-h-60 overflow-y-auto">
            {% for db_file in db_files %}
                <div class="p-2 border-b border-gray-700 flex justify-between items-center">
                    <div>
                        <p class="font-mono text-sm">{{ db_file.filename }}</p>
                        <p class="text-xs text-gray-400">{{ "%.2f"|format(db_file.filesize / (1024*1024)) }} MB | Added: {{ db_file.upload_date.strftime('%Y-%m-%d %H:%M') }}</p>
                    </div>
                    <div class="flex space-x-2">
                        <a href="{{ url_for('load_evidence', file_id=db_file.id) }}" class="btn-secondary px-3 py-1 text-xs rounded-lg">Load</a>
                        <a href="{{ url_for('remove_from_db', file_id=db_file.id) }}" onclick="return confirm('Are you sure you want to permanently delete this file?');" class="bg-red-600 text-white px-3 py-1 text-xs rounded-lg">Remove</a>
                    </div>
                </div>
            {% endfor %}
            </div>
        </div>
        {% endif %}
    </div>
    
    <!-- MOVED: Currently Loaded Evidence section to the right column -->
    <div class="space-y-8">
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Currently Loaded Evidence</h2>
            {% if uploaded_files %}
                <div class="space-y-2">
                {% for filename, details in uploaded_files.items() %}
                    <div class="p-2 border-b border-gray-700" id="file-status-{{ loop.index0 }}">
                        <div class="flex justify-between items-center">
                            <div>
                                <span class="font-mono">{{ filename }}</span> <span>({{ details.size_mb }} MB)</span>
                                <span id="decryption-badge-{{ loop.index0 }}" class="ml-2">
                                    {% if details.encryption_status.decrypted_path %}<span class="decryption-badge">DECRYPTED</span>
                                    {% elif details.encryption_status.decrypting %}<span class="decrypting-badge">DECRYPTING...</span>
                                    {% elif details.encryption_status.encrypted %}<span class="encryption-badge">ENCRYPTED</span>
                                    {% endif %}
                                </span>
                            </div>
                            <div class="flex space-x-2">
                                <a href="{{ url_for('remove_file', filename=filename) }}" class="bg-red-600 text-white px-3 py-1 text-xs rounded-lg">Unload</a>
                            </div>
                        </div>
                        <div id="decryption-status-text-{{ loop.index0 }}" class="text-xs text-gray-400 mt-2 pl-2">
                        {% if details.encryption_status.encrypted and not details.encryption_status.decrypted_path %}
                            Encryption: {{ details.encryption_status.description }} - <a href="{{ url_for('decryption_page', filename=filename) }}" class="text-blue-400 hover:underline">Go to Decryption Page</a>
                        {% elif details.encryption_status.decrypting %}
                             <span class="text-yellow-400">Decryption in progress...</span>
                        {% endif %}
                        </div>
                    </div>
                {% endfor %}
                </div>
                
                <!-- ADDED: Clear Session button in Currently Loaded Evidence section -->
                <div class="mt-6 pt-4 border-t border-gray-700">
                    <a href="{{ url_for('clear_session') }}" onclick="return confirm('This will clear ALL recovered files and analysis data. Continue?');" class="bg-red-600 text-white px-6 py-3 rounded-lg w-full text-center block hover:bg-red-700 transition-colors">Clear Session</a>
                </div>
                
                <!-- REMOVED: Quick Actions section from here (moved to Session Management) -->
            {% else %}
                <p class="text-gray-500">No evidence file is currently loaded for analysis.</p>
            {% endif %}
        </div>
        
        <!-- ADDED: Session Management section in the right column -->
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Session Management</h2>
            <div class="flex flex-col space-y-4">
                <a href="{{ url_for('forensic_analysis') }}" class="btn-primary px-6 py-3 rounded-lg text-center">Start Analysis</a>
                <a href="{{ url_for('auto_carving_setup') }}" class="btn-green px-6 py-3 rounded-lg text-center">Go to Auto Carving</a>
                <!-- REMOVED: Clear Session button from here (moved to Currently Loaded Evidence) -->
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('upload-form');
    const fileInput = document.getElementById('file-input');
    const submitButton = uploadForm.querySelector('button[type="submit"]');

    const progressContainer = document.getElementById('progress-container');
    const progressBar = document.getElementById('progress-bar');
    const progressText = document.getElementById('progress-text');
    const progressLabel = document.getElementById('progress-label');
    
    // Modals
    const uploadCompleteModal = document.getElementById('uploadCompleteModal');
    const closeUploadModalBtn = document.getElementById('closeUploadModalBtn');
    const uploadConfirmModal = document.getElementById('uploadConfirmModal');
    const confirmCancelBtn = document.getElementById('confirmCancelBtn');
    const confirmOkBtn = document.getElementById('confirmOkBtn');
    const uploadConfirmText = document.getElementById('uploadConfirmText');

    let fileToUpload = null;

    if (closeUploadModalBtn) {
        closeUploadModalBtn.onclick = function() {
            uploadCompleteModal.style.display = "none";
            window.location.reload();
        }
    }
    
    if (confirmCancelBtn) {
        confirmCancelBtn.onclick = function() {
            uploadConfirmModal.style.display = "none";
            resetUploadButton();
        }
    }
    
    if (confirmOkBtn) {
        confirmOkBtn.onclick = function() {
            uploadConfirmModal.style.display = "none";
            if(fileToUpload) {
                performUpload(fileToUpload);
            }
        }
    }

    uploadForm.addEventListener('submit', function(e) {
        e.preventDefault();
        if (!fileInput.files || fileInput.files.length === 0) {
            alert('Please select a file to upload.');
            return;
        }
        const file = fileInput.files[0];
        const fileSizeGB = file.size / (1024 * 1024 * 1024);
        submitButton.disabled = true;
        submitButton.textContent = 'Uploading...';
        progressContainer.classList.remove('hidden');
        if (fileSizeGB > 1) {
            fileToUpload = file;
            uploadConfirmText.textContent = `You are uploading a large file (${fileSizeGB.toFixed(2)} GB). This may take a significant amount of time. Do you want to continue?`;
            uploadConfirmModal.style.display = 'block';
        } else {
            performUpload(file);
        }
    });

    function resetUploadButton() {
        submitButton.disabled = false;
        submitButton.textContent = 'Upload';
        progressContainer.classList.add('hidden');
        fileInput.value = '';
    }
    
    function performUpload(file) {
        const formData = new FormData();
        formData.append('file', file);
        const xhr = new XMLHttpRequest();
        xhr.open('POST', '{{ url_for("evidence_upload") }}', true);
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable) {
                const percentComplete = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = percentComplete + '%';
                const loadedMB = (e.loaded / (1024*1024)).toFixed(2);
                const totalMB = (e.total / (1024*1024)).toFixed(2);
                progressText.textContent = `${percentComplete}% (${loadedMB} MB / ${totalMB} MB)`;
                if(percentComplete === 100) {
                    progressLabel.textContent = "Upload complete. Server is now processing the file...";
                }
            }
        });
        xhr.onload = function() {
            if (xhr.status === 200 || xhr.status === 302) {
                window.location.href = xhr.responseURL;
            } else {
                alert(`An error occurred during the upload: ${xhr.statusText}`);
                resetUploadButton();
            }
        };
        xhr.onerror = function() {
            alert('An error occurred. Please check your network connection and try again.');
            resetUploadButton();
        };
        xhr.send(formData);
    }

    function updateDecryptionStatus() {
        fetch('/decryption_status')
            .then(response => response.json())
            .then(data => {
                if (!data.filename) return;
                const fileElements = document.querySelectorAll('[id^=file-status-]');
                let fileIndex = -1;
                fileElements.forEach((el, index) => {
                    const monoElement = el.querySelector('.font-mono');
                    if (monoElement && monoElement.textContent === data.filename) {
                        fileIndex = index;
                    }
                });
                if (fileIndex === -1) return;
                
                const badge = document.getElementById(`decryption-badge-${fileIndex}`);
                const statusText = document.getElementById(`decryption-status-text-${fileIndex}`);
                if (data.in_progress) {
                    badge.innerHTML = '<span class="decrypting-badge">DECRYPTING...</span>';
                    statusText.innerHTML = `<span class="text-yellow-400">Status: ${data.message} (Attempt ${data.attempts})</span>`;
                    setTimeout(updateDecryptionStatus, 1000);
                } else if (data.complete) {
                    if (data.success) {
                        badge.innerHTML = '<span class="decryption-badge">DECRYPTED</span>';
                        statusText.innerHTML = '<span class="text-green-400">Decryption was successful! Reloading...</span>';
                        setTimeout(() => window.location.reload(), 1500);
                    } else {
                        badge.innerHTML = '<span class="encryption-badge">ENCRYPTED</span>';
                        statusText.innerHTML = `<span class="text-red-400">${data.message} - <a href="${window.location.href.replace('evidence_upload', 'decryption/' + data.filename)}" class="text-blue-400 hover:underline">Try again</a></span>`;
                    }
                }
            });
    }

    {% if uploaded_files_db %}
        {% for filename, details in uploaded_files_db.items() %}
            {% if details.encryption_status.decrypting %}
                updateDecryptionStatus();
            {% endif %}
        {% endfor %}
    {% endif %}
});
</script>
"""

ENCRYPTION_PAGE_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">File Encryption</h1>
<p class="text-gray-400 mb-8">Upload a file and provide a password to encrypt it using AES-256 with a derived key (PBKDF2-HMAC-SHA256).</p>

{% if message %}
<div class="card p-6 rounded-lg mb-8 border {% if success %}border-green-500{% else %}border-red-500{% endif %}">
    <h2 class="text-xl font-semibold {% if success %}text-green-400{% else %}text-red-400{% endif %} mb-4">
        {% if success %}✅ Encryption Successful{% else %}❌ Encryption Failed{% endif %}
    </h2>
    <p class="text-gray-300 mb-6">{{ message.split('. ')[0] + '.' }}</p>
    {% if success and encrypted_filename %}
    <div class="text-center">
        <a href="{{ url_for('download_encrypted', filename=encrypted_filename) }}" class="btn-primary inline-block px-8 py-3 rounded-lg font-semibold">
            Download {{ encrypted_filename }}
        </a>
    </div>
    {% endif %}
</div>
{% endif %}

<div class="card p-6 rounded-lg">
    <h2 class="text-xl font-semibold text-white mb-4">Encrypt a New File</h2>
    <form action="{{ url_for('encryption_page') }}" method="post" enctype="multipart/form-data" class="space-y-6">
        <div>
            <label for="file" class="block text-sm font-medium text-gray-300">Select File to Encrypt</label>
            <input type="file" name="file" id="file" required class="mt-1 block w-full text-gray-300 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100">
        </div>
        <div>
            <label for="password" class="block text-sm font-medium text-gray-300">Encryption Password</label>
            <input type="password" name="password" id="password" required class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white">
        </div>
        <div class="pt-2">
            <button type="submit" class="btn-green w-full py-2 rounded-lg font-semibold">Encrypt File</button>
        </div>
    </form>
</div>
"""
DECRYPTION_PAGE_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">File Decryption</h1>
<p class="text-gray-400 mb-8">The loaded evidence file <strong class="font-mono">{{ filename }}</strong> appears to be encrypted.</p>
<div class="card p-6 rounded-lg">
    <form action="{{ url_for('decryption_page', filename=filename) }}" method="post" class="space-y-6">
        <div>
            <label for="force_type" class="block text-sm font-medium text-gray-300">Decryption Method</label>
            <select name="force_type" id="force_type" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 h-10 text-white">
                <option value="auto" selected>Auto-Detect (Current: {{ file_info.encryption_status.encryption_type }})</option>
                <option value="ZIP_ENCRYPTED">Force ZIP Decryption</option>
                <option value="AES_ENCRYPTED">Force OpenSSL AES Decryption</option>
                <option value="FERNET_ENCRYPTED">Force Fernet Decryption</option>
            </select>
            <p class="mt-2 text-xs text-gray-400">If Auto-Detect fails, manually select the suspected file type.</p>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8 pt-4 border-t border-gray-700">
            <div>
                <h2 class="text-xl font-semibold text-white mb-4">1. Decrypt with Password</h2>
                <div class="space-y-4">
                    <div>
                        <label for="password" class="block text-sm font-medium text-gray-300">Password</label>
                        <input type="password" name="password" id="password" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white">
                    </div>
                    <button type="submit" name="action" value="with_password" class="btn-primary w-full py-2 rounded-lg font-semibold">Decrypt with Provided Password</button>
                </div>
            </div>
            <div>
                <h2 class="text-xl font-semibold text-white mb-4">2. Automated Decryption</h2>
                 <p class="text-sm text-gray-400 mb-4">Attempt decryption using the password dictionary file.</p>
                <button type="submit" name="action" value="auto_decrypt" class="btn-secondary w-full py-2 rounded-lg font-semibold">Start Automated Attempt</button>
            </div>
        </div>
    </form>
</div>
"""

TEXT_PREVIEW_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Viewing Text: {{ filename }}</title>
    <style>
        body, html { 
            margin: 0; 
            padding: 0; 
            height: 100%; 
            background-color: #111827; 
            color: white; 
            font-family: sans-serif; 
        }
        pre { 
            margin: 20px; 
            background-color: #1f2937; 
            color: #d1d5db; 
            height: calc(100vh - 40px); 
            overflow: auto; 
            padding: 20px; 
            box-sizing: border-box; 
            font-family: monospace; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            border-radius: 8px; 
            border: 1px solid #374151; 
        }
    </style>
</head>
<body>
    <pre>{{ text_content }}</pre>
</body>
</html>
"""

FORENSIC_ANALYSIS_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Forensic Analysis</h1>
<p class="text-gray-400 mb-8">High-level analysis of the uploaded evidence file.</p>
<div class="card p-6 rounded-lg">
{% if not uploaded_files %}
    <p class="text-gray-500">No file uploaded. Please upload an evidence file to begin analysis.</p>
{% else %}
    {% for filename, details in uploaded_files.items() %}
    <h2 class="text-2xl font-semibold text-white mb-6">Analysis for: <span class="font-mono">{{ filename }}</span></h2>
    <div class="space-y-8">
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">File Status</h3>
            <div class="text-gray-300">
                {% if details.encryption_status.encrypted %}
                    {% if details.encryption_status.decrypted_path %}
                        <p><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-green-600 text-green-100">DECRYPTED</span> - Analysis is being performed on the decrypted version of the file.</p>
                    {% else %}
                        <p><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-red-600 text-red-100">ENCRYPTED</span> - <span class="text-yellow-400">Warning:</span> Analysis results may be inaccurate. Please <a href="{{ url_for('decryption_page', filename=filename) }}" class="text-blue-400 hover:underline">decrypt the file</a> first.</p>
                        <p class="text-sm text-gray-400 mt-1">Detected Type: {{ details.encryption_status.description }}</p>
                    {% endif %}
                {% else %}
                    <p><span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-sm font-medium bg-gray-600 text-gray-100">NOT ENCRYPTED</span> - The file does not appear to be encrypted.</p>
                {% endif %}
            </div>
        </div>

        <div>
            <h3 class="text-lg font-semibold text-white mb-2">General Information (from file header)</h3>
            <ul class="list-disc list-inside text-gray-300 space-y-1">
            {% for result in details.forensic_results %}
                <li>{{ result }}</li>
            {% endfor %}
            </ul>
        </div>
        
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Partition Map</h3>
            {% if details.partition_info %}
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-gray-800">
                        <tr class="border-b border-gray-700">
                            <th class="p-2">Index</th>
                            <th class="p-2">Description</th>
                            <th class="p-2">Start Sector</th>
                            <th class="p-2">Length (Sectors)</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for part in details.partition_info %}
                        <tr class="border-b border-gray-700 hover:bg-gray-800">
                            <td class="p-2 font-mono">{{ part.addr }}</td>
                            <td class="p-2">{{ part.desc }}</td>
                            <td class="p-2 font-mono">{{ part.start }}</td>
                            <td class="p-2 font-mono">{{ part.len }}</td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <p class="text-gray-500">No partition data found in the evidence file header.</p>
            {% endif %}
        </div>
        
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Full File Hashes</h3>
            <div id="hash-progress-container" class="my-2" {% if details.hashing_complete %}style="display: none;"{% endif %}>
                <div class="w-full bg-gray-700 rounded-full h-4">
                    <div id="hash-progress-bar" class="bg-blue-600 h-4 rounded-full transition-all duration-500" style="width: 0%"></div>
                </div>
                <p id="hash-progress-text" class="text-sm text-gray-400 mt-2 text-center">Initializing...</p>
            </div>
            <div id="hash-results-container" {% if not details.hashing_complete %}class="hidden"{% endif %}>
                <ul class="list-disc list-inside text-gray-300 space-y-1 font-mono text-sm">
                    <li><strong>MD5:</strong> <span id="hash-md5">{{ details.hash_info.MD5 or 'Calculating...' }}</span></li>
                    <li><strong>SHA-1:</strong> <span id="hash-sha1">{{ details.hash_info['SHA-1'] or 'Calculating...' }}</span></li>
                    <li><strong>SHA-256:</strong> <span id="hash-sha256">{{ details.hash_info['SHA-256'] or 'Calculating...' }}</span></li>
                </ul>
            </div>
        </div>

        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Deep Scan Tools</h3>
            <div class="card p-4 rounded-lg bg-gray-800 border-gray-600">
                <div class="flex items-center justify-between">
                    <div>
                        <h4 class="font-semibold text-white">Strings Analysis</h4>
                        <p class="text-sm text-gray-400">Extract all printable strings from the evidence file.</p>
                    </div>
                    <button id="start-strings-btn" class="btn-primary px-4 py-2 rounded-lg text-sm">Run Analysis</button>
                </div>
                <div id="strings-analysis-container" class="mt-4 hidden">
                    <div class="w-full bg-gray-700 rounded-full h-4 mb-2">
                        <div id="strings-progress-bar" class="bg-blue-600 h-4 rounded-full transition-all duration-500" style="width: 0%"></div>
                    </div>
                    <p id="strings-progress-text" class="text-sm text-gray-400 text-center mb-4">Initializing...</p>
                    <h5 class="text-sm font-semibold text-white mb-2">Strings Preview (first 100 found):</h5>
                    <div class="log-view p-2 rounded-lg text-xs overflow-auto h-48">
                        <pre id="strings-preview"></pre>
                    </div>
                </div>
            </div>
        </div>
        
    </div>
    {% endfor %}
{% endif %}
</div>

<script>
function updateHashingProgress() {
    fetch('/hashing_status')
        .then(response => response.json())
        .then(data => {
            const progressBar = document.getElementById('hash-progress-bar');
            const progressText = document.getElementById('hash-progress-text');
            const progressContainer = document.getElementById('hash-progress-container');
            const resultsContainer = document.getElementById('hash-results-container');

            if (data.complete) {
                progressContainer.style.display = 'none';
                resultsContainer.style.display = 'block';
                document.getElementById('hash-md5').textContent = data.hashes.MD5 || 'N/A';
                document.getElementById('hash-sha1').textContent = data.hashes['SHA-1'] || 'N/A';
                document.getElementById('hash-sha256').textContent = data.hashes['SHA-256'] || 'N/A';
            } else if (data.in_progress) {
                progressContainer.style.display = 'block';
                resultsContainer.style.display = 'none';
                progressBar.style.width = data.progress + '%';
                progressText.textContent = `Hashing... ${data.progress}% complete`;
                setTimeout(updateHashingProgress, 2000);
            } else {
                progressText.textContent = 'Hashing has not started or was interrupted.';
            }
        });
}

function updateStringsProgress() {
    fetch('/strings_status')
        .then(response => response.json())
        .then(data => {
            const btn = document.getElementById('start-strings-btn');
            const analysisContainer = document.getElementById('strings-analysis-container');
            const progressBar = document.getElementById('strings-progress-bar');
            const progressText = document.getElementById('strings-progress-text');
            const preview = document.getElementById('strings-preview');

            if (data.in_progress) {
                analysisContainer.style.display = 'block';
                btn.disabled = true;
                btn.textContent = 'Running...';
                progressBar.style.width = data.progress + '%';
                progressText.textContent = `Scanning... ${data.progress}% complete | Found: ${data.strings_found} strings`;
                preview.textContent = data.preview.join('\\n');
                setTimeout(updateStringsProgress, 1500);
            } else if (data.complete) {
                analysisContainer.style.display = 'block';
                progressBar.style.width = '100%';
                progressText.textContent = `Scan Complete. Found ${data.strings_found} strings.`;
                preview.textContent = data.preview.join('\\n');
                btn.disabled = false;
                btn.textContent = 'Run Again';
            }
        });
}

document.addEventListener('DOMContentLoaded', () => {
    {% if hashing_in_progress %}
    updateHashingProgress();
    {% endif %}

    const startStringsBtn = document.getElementById('start-strings-btn');
    if(startStringsBtn) {
        startStringsBtn.addEventListener('click', () => {
            fetch('/start_strings_analysis')
                .then(response => response.json())
                .then(data => {
                    if(data.status === 'started') {
                        updateStringsProgress();
                    } else {
                        alert('Could not start strings analysis: ' + data.error);
                    }
                });
        });
    }
});
</script>
"""

VIEW_FILE_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Viewing: {{ filename }}</title>
    <style>
        body, html { 
            margin: 0; 
            padding: 0; 
            height: 100%; 
            background-color: #111827; 
            color: white; 
            font-family: sans-serif; 
            overflow: hidden;
        }
        .header {
            background-color: #1f2937;
            padding: 15px 20px;
            border-bottom: 1px solid #374151;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 1.5em;
            color: #3b82f6;
        }
        .header-actions {
            display: flex;
            gap: 10px;
        }
        .btn {
            padding: 8px 16px;
            border-radius: 5px;
            text-decoration: none;
            font-weight: bold;
            transition: background-color 0.2s;
        }
        .btn-secondary {
            background-color: #4b5563;
            color: white;
        }
        .btn-primary {
            background-color: #3b82f6;
            color: white;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .content-area {
            height: calc(100vh - 70px);
            display: flex;
            flex-direction: column;
        }
        embed, iframe, img, video, audio { 
            width: 100%; 
            height: 100%; 
            border: none; 
            flex-grow: 1;
        }
        pre { 
            margin: 0;
            background-color: #1f2937; 
            color: #d1d5db; 
            height: 100%; 
            overflow: auto; 
            padding: 20px; 
            box-sizing: border-box; 
            font-family: 'Courier New', monospace; 
            white-space: pre-wrap; 
            word-wrap: break-word; 
            flex-grow: 1;
        }
        .fallback-message {
            padding: 40px;
            text-align: center;
            color: white;
            font-family: sans-serif;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }
        .file-info {
            background-color: #1f2937;
            padding: 10px 20px;
            border-bottom: 1px solid #374151;
            font-size: 0.9em;
            color: #9ca3af;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Viewing: {{ filename }}</h1>
        <div class="header-actions">
            <a href="{{ url_for('recovered_files') if is_carved else url_for('deleted_files') }}" class="btn btn-secondary">Back to List</a>
            <a href="{{ url_for('download_carved_file', filename=filename) if is_carved else url_for('download_deleted_file', filename=filename) }}" class="btn btn-primary">Download</a>
        </div>
    </div>
    
    <div class="file-info">
        File Type: {{ mime_type }} | 
        Size: {{ (content|length if content else 0) }} bytes
    </div>
    
    <div class="content-area">
        {% if mime_type.startswith('image/') %}
            <img src="{{ data_url }}" alt="Preview of {{ filename }}">
        {% elif mime_type == 'application/pdf' %}
            <iframe src="{{ data_url }}"></iframe>
        {% elif mime_type.startswith('audio/') %}
            <audio controls>
                <source src="{{ data_url }}" type="{{ mime_type }}">
                Your browser does not support the audio element.
            </audio>
        {% elif mime_type.startswith('video/') %}
            <video controls>
                <source src="{{ data_url }}" type="{{ mime_type }}">
                Your browser does not support the video element.
            </video>
        {% elif text_content is defined %}
            <pre>{{ text_content }}</pre>
        {% else %}
            <div class="fallback-message">
                <h2>Preview Not Available</h2>
                <p>Direct preview for '{{ mime_type }}' is not supported.</p>
                <a href="{{ url_for('download_carved_file', filename=filename) if is_carved else url_for('download_deleted_file', filename=filename) }}" 
                   class="btn btn-primary" style="margin-top: 20px;">
                    Download File
                </a>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

AUTO_CARVING_SETUP_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Automatic File Carving Setup</h1>
<p class="text-gray-400 mb-8">Select file types for automated carving based on file signatures.</p>
<form method="post" action="{{ form_action_url }}">
<div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <div class="lg:col-span-2">
        <div class="card p-6 rounded-lg">
            <div class="flex justify-between items-center mb-4 pb-4 border-b border-gray-700">
                <h2 class="text-xl font-semibold text-white">Select File Types</h2>
                <div class="flex items-center space-x-4">
                    <span id="selected-count" class="bg-blue-600 text-white px-3 py-1 rounded-full text-sm font-medium">0 selected</span>
                    <button type="button" id="select-all-btn" class="btn-secondary px-3 py-1 text-xs rounded-lg">Select All</button>
                    <button type="button" id="deselect-all-btn" class="btn-secondary px-3 py-1 text-xs rounded-lg">Deselect All</button>
                </div>
            </div>
            {% for category, types in signatures.items() %}
            <h3 class="text-lg font-semibold {{ colors[loop.index0 % colors|length] }} mt-6 mb-2 border-b border-gray-700 pb-1">{{ category }}</h3>
            <div class="grid grid-cols-2 md:grid-cols-3 gap-4">
                {% for name, sig in types.items() %}
                <div class="flex items-center">
                    <input type="checkbox" name="file_types" value="{{ name }}" id="{{ name }}" class="file-type-checkbox h-4 w-4 rounded bg-gray-700 border-gray-600 text-blue-600 focus:ring-blue-500">
                    <label for="{{ name }}" class="ml-3 text-white cursor-pointer">{{ name }}</label>
                </div>
                {% endfor %}
            </div>
            {% endfor %}
        </div>
    </div>
    <div class="lg:col-span-1">
        <div class="card p-6 rounded-lg sticky top-8">
            <h3 class="text-lg font-semibold text-white mb-4">Begin Carving</h3>
            <p class="text-gray-400 text-sm mb-4">Once you have selected the desired file types, start the carving process.</p>
            <button type="submit" class="btn-green w-full py-3 rounded-lg font-semibold">Start Auto Carving</button>
        </div>
    </div>
</div>
</form>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const checkboxes = document.querySelectorAll('.file-type-checkbox');
    const counter = document.getElementById('selected-count');
    
    function updateCounter() {
        const selectedCount = document.querySelectorAll('.file-type-checkbox:checked').length;
        counter.textContent = `${selectedCount} selected`;
    }
    
    checkboxes.forEach(checkbox => checkbox.addEventListener('change', updateCounter));
    
    document.getElementById('select-all-btn').addEventListener('click', () => {
        checkboxes.forEach(checkbox => checkbox.checked = true);
        updateCounter();
    });

    document.getElementById('deselect-all-btn').addEventListener('click', () => {
        checkboxes.forEach(checkbox => checkbox.checked = false);
        updateCounter();
    });

    updateCounter();
});
</script>
"""

AUTO_CARVING_PROCESS_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-2">Automatic File Carving in Progress</h1>
<p class="text-gray-400 mb-8">Scanning evidence file for selected file types.</p>
<div class="card p-6 rounded-lg">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold text-white">Carving Progress</h2>
        <span id="progress-percent" class="font-bold text-blue-400">0% Complete</span>
    </div>
    <div class="w-full bg-gray-700 rounded-full h-4">
        <div id="progress-bar" class="bg-blue-600 h-4 rounded-full transition-all duration-500" style="width: 0%"></div>
    </div>
    <p class="text-sm text-gray-400 mt-2">Processing offset: <span id="current-offset">0x00000000</span> | Found: <span id="files-found">0</span> files</p>
    <!-- Add this after the progress bar -->
<p class="text-sm text-gray-400 mt-2">
    Elapsed: <span id="elapsed-time">0s</span> | 
    Remaining: <span id="time-remaining">Calculating...</span> |
    Total Estimated: <span id="total-estimated">Calculating...</span>
</p>
    <div id="error-container" class="mt-4 p-4 bg-red-900 border border-red-500 rounded-lg text-sm text-red-200 hidden">
        <h3 class="font-bold mb-2">An Error Occurred</h3>
        <p id="error-message"></p>
    </div>
</div>
<div class="card p-6 rounded-lg mt-8">
    <h2 class="text-xl font-semibold text-white mb-4">Live Hex Preview of Found Files</h2>
    <div id="live-hex-view" class="hex-view p-4 rounded-lg text-sm overflow-y-auto max-h-[40rem]">
        <p class="text-gray-500">Waiting for files to be found...</p>
    </div>
</div>
<div class="mt-8 flex justify-between items-center">
    <h3 class="text-xl font-semibold text-white">Found Files (<span id="total-found-count">0</span>)</h3>
    <div class="flex space-x-4">
        <a href="{{ url_for('auto_carving_setup') }}" class="btn-secondary px-6 py-2 rounded-lg">Back to Setup</a>
        <a href="{{ url_for('recovered_files') }}" id="view-recovered-btn" class="btn-primary px-6 py-2 rounded-lg opacity-50 pointer-events-none">View Recovered Files</a>
    </div>
</div>

<script>
function updateProgress() {
    fetch('/carving_status')
        .then(response => response.json())
        .then(data => {
            document.getElementById('progress-bar').style.width = data.progress + '%';
            const progressPercent = document.getElementById('progress-percent');
            progressPercent.innerText = data.progress + '% Complete';
            document.getElementById('current-offset').innerText = data.current_offset;
            document.getElementById('files-found').innerText = data.files_found;
            document.getElementById('total-found-count').innerText = data.files_found;
            // In the updateProgress function, add:
document.getElementById('elapsed-time').textContent = data.elapsed_time || '0s';
document.getElementById('time-remaining').textContent = data.time_remaining_str || 'Calculating...';
if (data.estimated_total_time) {
    document.getElementById('total-estimated').textContent = data.estimated_total_time;
}  
            
            const liveHexView = document.getElementById('live-hex-view');
            const recentFiles = data.found_files_list.slice(-5).reverse();
            if (recentFiles.length > 0) {
                let fullHexContent = '';
                recentFiles.forEach(file => {
                    fullHexContent += `<p class="text-xs text-green-400">${file.name} @ ${file.offset}</p><pre>${file.hex_preview}</pre><hr class="border-gray-600 my-2">`;
                });
                liveHexView.innerHTML = fullHexContent;
            }

            const errorContainer = document.getElementById('error-container');
            const errorMessage = document.getElementById('error-message');
            if (data.error) {
                errorMessage.textContent = data.error;
                errorContainer.classList.remove('hidden');
                progressPercent.className = 'font-bold text-red-400';
                progressPercent.innerText = 'Scan Failed';
                document.getElementById('progress-bar').classList.add('bg-red-600');
            }

            if (data.complete) {
                if (!data.error) {
                    progressPercent.className = 'font-bold text-green-400';
                    progressPercent.innerText = 'Scan Complete';
                }
                const viewBtn = document.getElementById('view-recovered-btn');
                viewBtn.classList.remove('opacity-50', 'pointer-events-none');
            } else {
                setTimeout(updateProgress, 1000);
            }
        });
}
document.addEventListener('DOMContentLoaded', updateProgress);
</script>
"""

RECOVERED_FILES_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Recovered Carved Files</h1>
<div class="card p-6 rounded-lg">
    <form action="{{ url_for('download_zip') }}" method="post">
        <input type="hidden" name="file_type" value="carved">
        <div class="flex justify-between items-center mb-4">
            <h2 class="text-xl font-semibold text-white">Recovered Files ({{ total_files }} found)</h2>
            {% if total_files > 0 %}
            <button type="submit" class="btn-primary px-4 py-2 rounded-lg text-sm">Download Selected as ZIP</button>
            {% endif %}
        </div>
        {% if carved_files %}
            <table class="w-full text-left">
                <thead>
                    <tr class="border-b border-gray-700">
                        <th class="p-2 w-10"><input type="checkbox" id="select-all-carved" class="h-4 w-4 rounded bg-gray-700 border-gray-600"></th>
                        <th class="p-2">ID</th>
                        <th class="p-2">Filename</th>
                        <th class="p-2">Offset</th>
                        <th class="p-2">Size</th>
                        <th class="p-2">Actions</th>
                    </tr>
                </thead>
                <tbody>
                {% for file in carved_files %}
                    <tr class="border-b border-gray-700 hover:bg-gray-800">
                        <td class="p-2"><input type="checkbox" name="selected_files" value="{{ file.name }}" class="h-4 w-4 rounded bg-gray-700 border-gray-600 file-checkbox"></td>
                        <td class="p-2">{{ file.id }}</td>
                        <td class="p-2 font-mono break-all">{{ file.name }}</td>
                        <td class="p-2 font-mono">{{ file.offset }}</td>
                        <td class="p-2 font-mono">{{ "%.2f KB"|format(file.size_bytes / 1024) if file.size_bytes else 'N/A' }}</td>
                        <td class="p-2 flex space-x-2">
                            <a href="{{ url_for('view_carved_file', filename=file.name) }}" target="_blank" class="btn-secondary px-3 py-1 text-xs rounded-lg">View</a>
                            <a href="{{ url_for('hex_view_carved', filename=file.name) }}" target="_blank" class="btn-green px-3 py-1 text-xs rounded-lg">Hex View</a>
                            <a href="{{ url_for('download_carved_file', filename=file.name) }}" class="btn-primary px-3 py-1 text-xs rounded-lg">Download</a>
                        </td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
            
            <div class="mt-6 flex justify-center items-center space-x-2 text-gray-400">
                {% if page > 1 %}
                    <a href="{{ url_for('recovered_files', page=page-1) }}" class="px-3 py-1 rounded-md bg-gray-800 hover:bg-gray-700">&laquo; Prev</a>
                {% endif %}
                
                {% for p in range(1, total_pages + 1) %}
                    {% if p == page %}
                        <span class="px-3 py-1 rounded-md bg-blue-600 text-white">{{ p }}</span>
                    {% else %}
                        <a href="{{ url_for('recovered_files', page=p) }}" class="px-3 py-1 rounded-md bg-gray-800 hover:bg-gray-700">{{ p }}</a>
                    {% endif %}
                {% endfor %}

                {% if page < total_pages %}
                    <a href="{{ url_for('recovered_files', page=page+1) }}" class="px-3 py-1 rounded-md bg-gray-800 hover:bg-gray-700">Next &raquo;</a>
                {% endif %}
            </div>
        {% else %}
            <div class="text-center p-8">
                <p class="text-gray-500 text-lg mb-4">No files recovered yet.</p>
                <div class="text-sm text-gray-400">
                    <p>Possible reasons:</p>
                    <ul class="list-disc list-inside mt-2">
                        <li>Carving process has not been run</li>
                        <li>Carving process is still in progress</li>
                        <li>No files of the selected types were found</li>
                        <li>Session was cleared unexpectedly</li>
                    </ul>
                </div>
                <div class="mt-4">
                    <a href="{{ url_for('auto_carving_setup') }}" class="btn-primary px-4 py-2 rounded-lg">Go to Auto Carving</a>
                </div>
            </div>
        {% endif %}
    </form>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const selectAll = document.getElementById('select-all-carved');
    if(selectAll) {
        selectAll.addEventListener('change', function(e) {
            document.querySelectorAll('.file-checkbox').forEach(function(checkbox) {
                checkbox.checked = e.target.checked;
            });
        });
    }
});
</script>
"""
MANUAL_CARVING_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Manual File Carving</h1>
<p class="text-gray-400 mb-8">Manually search for and extract data blocks from the evidence file using hex patterns or offsets.</p>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
    <div class="card p-6 rounded-lg">
        <h2 class="text-xl font-semibold text-white mb-4">Search for Data</h2>
        
        <div class="space-y-6">
            <div>
                <h3 class="text-lg font-semibold text-white mb-2">1. Search for Hex Pattern</h3>
                <form id="search-hex-form" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-300">Hex Pattern (e.g., FF D8 FF E0)</label>
                        <input type="text" id="hex-term" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white font-mono" placeholder="Enter hex values without spaces">
                    </div>
                    <button type="submit" class="btn-primary w-full py-2 rounded-lg">Search Pattern</button>
                </form>
                <div id="hex-result" class="mt-4 hidden"></div>
            </div>

            <div class="pt-4 border-t border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-2">2. Search for Text String</h3>
                <form id="search-text-form" class="space-y-4">
                    <div>
                        <label class="block text-sm font-medium text-gray-300">Text String</label>
                        <input type="text" id="text-term" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white" placeholder="Enter text to search for">
                    </div>
                    <button type="submit" class="btn-primary w-full py-2 rounded-lg">Search Text</button>
                </form>
                <div id="text-result" class="mt-4 hidden"></div>
            </div>

            <div class="pt-4 border-t border-gray-700">
                <h3 class="text-lg font-semibold text-white mb-2">3. Find Block Between Headers/Footers</h3>
                <form id="search-block-form" class="space-y-4">
                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-300">Header Pattern</label>
                            <input type="text" id="header-term" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white font-mono" placeholder="Hex or text">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-300">Footer Pattern</label>
                            <input type="text" id="footer-term" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white font-mono" placeholder="Hex or text">
                        </div>
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-300">Search Type</label>
                        <select id="block-search-type" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white">
                            <option value="hex">Hex</option>
                            <option value="text">Text</option>
                        </select>
                    </div>
                    <button type="submit" class="btn-primary w-full py-2 rounded-lg">Find Block</button>
                </form>
                <div id="block-result" class="mt-4 hidden"></div>
            </div>
        </div>
    </div>

    <div class="card p-6 rounded-lg">
        <h2 class="text-xl font-semibold text-white mb-4">Manual Carve Data</h2>
        
        <form action="{{ url_for('perform_manual_carve') }}" method="post" class="space-y-4">
            <div>
                <label class="block text-sm font-medium text-gray-300">Start Offset (decimal or hex with 0x)</label>
                <input type="text" name="start_offset" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white font-mono" placeholder="e.g., 1024 or 0x400" required>
            </div>
            
            <div>
                <label class="block text-sm font-medium text-gray-300">Length (bytes)</label>
                <input type="number" name="length" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white" placeholder="Number of bytes to extract" required min="1">
            </div>
            
            <button type="submit" class="btn-green w-full py-2 rounded-lg font-semibold">Carve Data</button>
        </form>

        <div class="mt-6 p-4 bg-gray-800 rounded-lg">
            <h3 class="text-lg font-semibold text-white mb-2">Quick Reference</h3>
            <ul class="text-sm text-gray-400 space-y-1">
                <li>• JPEG: FF D8 FF E0 ... FF D9</li>
                <li>• PNG: 89 50 4E 47 0D 0A 1A 0A</li>
                <li>• PDF: 25 50 44 46</li>
                <li>• ZIP: 50 4B 03 04</li>
                <li>• GIF: 47 49 46 38</li>
            </ul>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    // Hex search
    document.getElementById('search-hex-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const term = document.getElementById('hex-term').value.trim();
        if (!term) return;
        
        fetch('/find_in_file', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `term=${encodeURIComponent(term)}&type=hex`
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('hex-result');
            if (data.offset !== -1) {
                resultDiv.innerHTML = `<div class="p-3 bg-green-900 border border-green-500 rounded-lg">
                    <p class="text-green-300">Found at offset: <span class="font-mono">0x${data.offset.toString(16).toUpperCase()}</span> (${data.offset} decimal)</p>
                    <button onclick="fillOffset(${data.offset})" class="mt-2 btn-secondary px-3 py-1 text-xs">Use this offset</button>
                </div>`;
            } else {
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-500 rounded-lg">
                    <p class="text-red-300">Pattern not found. ${data.error || ''}</p>
                </div>`;
            }
            resultDiv.classList.remove('hidden');
        });
    });

    // Text search
    document.getElementById('search-text-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const term = document.getElementById('text-term').value.trim();
        if (!term) return;
        
        fetch('/find_in_file', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `term=${encodeURIComponent(term)}&type=text`
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('text-result');
            if (data.offset !== -1) {
                resultDiv.innerHTML = `<div class="p-3 bg-green-900 border border-green-500 rounded-lg">
                    <p class="text-green-300">Found at offset: <span class="font-mono">0x${data.offset.toString(16).toUpperCase()}</span> (${data.offset} decimal)</p>
                    <button onclick="fillOffset(${data.offset})" class="mt-2 btn-secondary px-3 py-1 text-xs">Use this offset</button>
                </div>`;
            } else {
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-500 rounded-lg">
                    <p class="text-red-300">Text not found. ${data.error || ''}</p>
                </div>`;
            }
            resultDiv.classList.remove('hidden');
        });
    });

    // Block search
    document.getElementById('search-block-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const header = document.getElementById('header-term').value.trim();
        const footer = document.getElementById('footer-term').value.trim();
        const type = document.getElementById('block-search-type').value;
        
        if (!header || !footer) return;
        
        fetch('/find_block', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: `header_term=${encodeURIComponent(header)}&footer_term=${encodeURIComponent(footer)}&type=${type}`
        })
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('block-result');
            if (data.status === 'success') {
                resultDiv.innerHTML = `<div class="p-3 bg-green-900 border border-green-500 rounded-lg">
                    <p class="text-green-300">Block found:</p>
                    <p class="text-green-300">Start: <span class="font-mono">0x${data.start_offset.toString(16).toUpperCase()}</span></p>
                    <p class="text-green-300">Length: <span class="font-mono">${data.length} bytes</span></p>
                    <div class="mt-2 space-x-2">
                        <button onclick="fillOffsetAndLength(${data.start_offset}, ${data.length})" class="btn-secondary px-3 py-1 text-xs">Use these values</button>
                    </div>
                </div>`;
            } else {
                resultDiv.innerHTML = `<div class="p-3 bg-red-900 border border-red-500 rounded-lg">
                    <p class="text-red-300">Block not found. ${data.message || ''}</p>
                </div>`;
            }
            resultDiv.classList.remove('hidden');
        });
    });
});

function fillOffset(offset) {
    document.querySelector('input[name="start_offset"]').value = offset;
}

function fillOffsetAndLength(offset, length) {
    document.querySelector('input[name="start_offset"]').value = offset;
    document.querySelector('input[name="length"]').value = length;
}
</script>
"""

LOG_VIEWER_TEMPLATE = """
<h1 class="text-3xl font-bold text-white mb-4">{{ title }}</h1>
<p class="text-gray-400 mb-8">{{ description }}</p>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
    <div class="lg:col-span-1">
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Select Log Type</h2>
            <form method="post" class="space-y-6">
                <div>
                    <label class="block text-sm font-medium text-gray-300">Operating System</label>
                    <select id="os-select" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white">
                        <option value="">Select OS</option>
                        {% for os_name in os_options.keys() %}
                        <option value="{{ os_name }}">{{ os_name }}</option>
                        {% endfor %}
                    </select>
                </div>
                
                <div>
                    <label class="block text-sm font-medium text-gray-300">Log Format</label>
                    <select name="log_ext" id="log-ext-select" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white">
                        <option value="">Select after choosing OS</option>
                    </select>
                </div>
                
                <button type="submit" class="btn-primary w-full py-2 rounded-lg font-semibold">Parse Log</button>
            </form>
            
            <div class="mt-6 p-4 bg-gray-800 rounded-lg">
                <h3 class="text-lg font-semibold text-white mb-2">Current File</h3>
                <p class="text-sm text-gray-400 break-all">{{ evidence_filename }}</p>
            </div>
        </div>
    </div>
    
    <div class="lg:col-span-2">
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Log Content</h2>
            {% if log_content %}
            <div class="log-view p-4 rounded-lg overflow-auto max-h-[70vh]">
                <pre>{{ log_content }}</pre>
            </div>
            {% else %}
            <div class="text-center p-8 text-gray-500">
                <p>Select a log type and click "Parse Log" to view content.</p>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const osSelect = document.getElementById('os-select');
    const logExtSelect = document.getElementById('log-ext-select');
    
    const osOptions = {{ os_options|tojson }};
    
    osSelect.addEventListener('change', function() {
        const selectedOS = this.value;
        logExtSelect.innerHTML = '<option value="">Select log format</option>';
        
        if (selectedOS && osOptions[selectedOS]) {
            osOptions[selectedOS].forEach(function(format) {
                const option = document.createElement('option');
                option.value = format;
                option.textContent = format;
                logExtSelect.appendChild(option);
            });
        }
    });
});
</script>
"""

ENHANCED_DELETED_STATUS_TEMPLATE = """
<!-- Enhanced Deleted Files Recovery Interface -->
<div class="grid grid-cols-1 lg:grid-cols-4 gap-8">
    <div class="lg:col-span-1">
        <div class="card p-6 rounded-lg">
            <h2 class="text-xl font-semibold text-white mb-4">Recovery Control</h2>
            
            <!-- Enhanced Start Button with Status -->
            {% if not deleted_scan_status.in_progress %}
            <a href="{{ url_for('start_strict_deleted_recovery') }}" 
               class="btn-green w-full py-3 rounded-lg font-semibold text-center block mb-4 hover:bg-green-700 transition-colors">
                🚀 Start Strict Automatic Recovery
            </a>
            {% else %}
            <button class="bg-yellow-600 text-white w-full py-3 rounded-lg font-semibold mb-4 cursor-not-allowed">
                ⏳ Recovery In Progress...
            </button>
            {% endif %}
            
            <!-- Real-time Validation Statistics -->
            <div class="p-3 bg-gray-800 rounded-lg mb-4">
                <h3 class="font-semibold text-white mb-2">Validation Statistics</h3>
                <div class="grid grid-cols-2 gap-2 text-xs">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Total Scanned:</span>
                        <span id="total-scanned" class="text-white font-mono">{{ deleted_scan_status.validation_stats.total_scanned if deleted_scan_status.validation_stats else 0 }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Empty Rejected:</span>
                        <span id="empty-rejected" class="text-red-400 font-mono">{{ deleted_scan_status.validation_stats.empty_rejected if deleted_scan_status.validation_stats else 0 }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Duplicate Rejected:</span>
                        <span id="duplicate-rejected" class="text-yellow-400 font-mono">{{ deleted_scan_status.validation_stats.duplicate_rejected if deleted_scan_status.validation_stats else 0 }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Invalid Rejected:</span>
                        <span id="invalid-rejected" class="text-orange-400 font-mono">{{ deleted_scan_status.validation_stats.invalid_rejected if deleted_scan_status.validation_stats else 0 }}</span>
                    </div>
                    <div class="flex justify-between col-span-2 border-t border-gray-700 pt-1">
                        <span class="text-gray-400 font-semibold">Valid Recovered:</span>
                        <span id="valid-recovered" class="text-green-400 font-semibold font-mono">{{ deleted_scan_status.validation_stats.valid_recovered if deleted_scan_status.validation_stats else 0 }}</span>
                    </div>
                </div>
            </div>

            <!-- Enhanced Timing Information -->
            <div class="p-3 bg-gray-800 rounded-lg mb-4">
                <h3 class="font-semibold text-white mb-2">⏱️ Timing Information</h3>
                <div class="space-y-1 text-xs">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Elapsed:</span>
                        <span id="elapsed-time" class="text-white font-mono">{{ deleted_scan_status.elapsed_time if deleted_scan_status.elapsed_time else "0s" }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Remaining:</span>
                        <span id="time-remaining" class="text-white font-mono">{{ deleted_scan_status.time_remaining_str if deleted_scan_status.time_remaining_str else "Calculating..." }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Total Estimated:</span>
                        <span id="total-estimated" class="text-white font-mono">{{ deleted_scan_status.estimated_total_time if deleted_scan_status.estimated_total_time else "Calculating..." }}</span>
                    </div>
                </div>
            </div>

            <!-- Progress Visualization -->
            <div class="mb-4">
                <div class="flex justify-between text-sm text-gray-400 mb-2">
                    <span>Recovery Progress</span>
                    <span id="progress-percent">0%</span>
                </div>
                <div class="w-full bg-gray-700 rounded-full h-3">
                    <div id="progress-bar" class="bg-blue-600 h-3 rounded-full transition-all duration-500" style="width: 0%"></div>
                </div>
            </div>

            <!-- Recovery Methods Summary -->
            <div class="p-3 bg-gray-800 rounded-lg">
                <h3 class="font-semibold text-white mb-2">🔍 Scan Methods</h3>
                <div class="space-y-2 text-sm">
                    <div class="flex justify-between">
                        <span class="text-gray-400">Directory Walk:</span>
                        <span id="method-dir" class="text-white font-mono bg-blue-600 px-2 py-1 rounded text-xs">{{ deleted_scan_status.scan_methods.directory_walk }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Inode Scan:</span>
                        <span id="method-inode" class="text-white font-mono bg-green-600 px-2 py-1 rounded text-xs">{{ deleted_scan_status.scan_methods.inode_scan }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">File Slack:</span>
                        <span id="method-slack" class="text-white font-mono bg-yellow-600 px-2 py-1 rounded text-xs">{{ deleted_scan_status.scan_methods.file_slack }}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-gray-400">Recycle Bin:</span>
                        <span id="method-recycle" class="text-white font-mono bg-purple-600 px-2 py-1 rounded text-xs">{{ deleted_scan_status.scan_methods.recycle_bin }}</span>
                    </div>
                </div>
            </div>

            <!-- Status Message -->
            <div id="status-message" class="mt-4 p-3 rounded-lg text-sm 
                {% if deleted_scan_status.in_progress %}bg-blue-900 text-blue-200 border border-blue-700
                {% elif deleted_scan_status.complete %}bg-green-900 text-green-200 border border-green-700
                {% else %}bg-gray-800 text-gray-400 border border-gray-700{% endif %}">
                <div class="font-semibold mb-1">
                    {% if deleted_scan_status.in_progress %}🔄 {% elif deleted_scan_status.complete %}✅ {% else %}⏸️ {% endif %}
                    Status
                </div>
                <div id="status-text">{{ deleted_scan_status.message }}</div>
            </div>
        </div>
    </div>

    <div class="lg:col-span-3">
        <div class="card p-6 rounded-lg">
            <div class="flex justify-between items-center mb-6">
                <h2 class="text-xl font-semibold text-white">📁 Recovered Files</h2>
                <div class="flex items-center space-x-3">
                    <span class="bg-blue-600 text-white px-3 py-1 rounded-full text-sm font-medium">
                        {{ recovered_files|length }} files recovered
                    </span>
                    {% if recovered_files %}
                    <form action="{{ url_for('download_zip') }}" method="post" class="inline">
                        <input type="hidden" name="file_type" value="deleted_recovered">
                        {% for file in recovered_files %}
                        <input type="hidden" name="selected_files" value="{{ file.name }}">
                        {% endfor %}
                        <button type="submit" class="btn-primary px-4 py-2 rounded-lg text-sm hover:bg-blue-700 transition-colors">
                            📥 Download All as ZIP
                        </button>
                    </form>
                    {% endif %}
                </div>
            </div>

            {% if recovered_files %}
            <!-- Files Table -->
            <div class="overflow-x-auto">
                <table class="min-w-full bg-gray-800 rounded-lg overflow-hidden">
                    <thead class="bg-gray-700">
                        <tr>
                            <th class="text-left py-3 px-4 text-white font-semibold">ID</th>
                            <th class="text-left py-3 px-4 text-white font-semibold">Filename</th>
                            <th class="text-left py-3 px-4 text-white font-semibold">Size</th>
                            <th class="text-left py-3 px-4 text-white font-semibold">Type</th>
                            <th class="text-left py-3 px-4 text-white font-semibold">Recovery Method</th>
                            <th class="text-left py-3 px-4 text-white font-semibold">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for file in recovered_files %}
                        <tr class="border-b border-gray-600 hover:bg-gray-750 transition-colors">
                            <td class="py-3 px-4 text-gray-300 font-mono">{{ file.id }}</td>
                            <td class="py-3 px-4 text-gray-300">
                                <div class="flex items-center space-x-3">
                                    {% if file.thumbnail %}
                                    <img src="{{ file.thumbnail }}" class="w-8 h-8 object-cover rounded" alt="Thumbnail" onerror="this.style.display='none'">
                                    {% endif %}
                                    <div>
                                        <div class="font-medium">{{ file.name|truncate(30) }}</div>
                                        <div class="text-xs text-gray-500">{{ file.mtime if file.mtime else 'Unknown date' }}</div>
                                    </div>
                                </div>
                            </td>
                            <td class="py-3 px-4 text-gray-300 font-mono">{{ file.size_kb }} KB</td>
                            <td class="py-3 px-4 text-gray-300">
                                <span class="px-2 py-1 bg-gray-600 rounded text-xs">{{ file.file_type }}</span>
                            </td>
                            <td class="py-3 px-4 text-gray-300">
                                <span class="px-2 py-1 bg-blue-600 rounded text-xs">{{ file.recovery_method }}</span>
                            </td>
                            <td class="py-3 px-4">
                                <div class="flex space-x-2">
                                    <a href="{{ url_for('view_deleted_file', filename=file.name) }}" target="_blank" 
                                       class="btn-secondary px-3 py-1 text-xs rounded hover:bg-gray-600 transition-colors">👁️ View</a>
                                    <a href="{{ url_for('download_deleted_file', filename=file.name) }}" 
                                       class="btn-primary px-3 py-1 text-xs rounded hover:bg-blue-700 transition-colors">📥 Download</a>
                                    <a href="{{ url_for('hex_view_deleted', filename=file.name) }}" target="_blank"
                                       class="btn-green px-3 py-1 text-xs rounded hover:bg-green-700 transition-colors">🔢 Hex</a>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <!-- Empty State -->
            <div class="text-center py-12 text-gray-500">
                <div class="mb-4">
                    <svg class="w-16 h-16 mx-auto text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                    </svg>
                </div>
                <p class="text-lg mb-2">No deleted files recovered yet</p>
                <p class="text-sm text-gray-400 mb-6">Start the automatic recovery process to scan for deleted files using multiple forensic methods</p>
                
                {% if not deleted_scan_status.in_progress %}
                <a href="{{ url_for('start_strict_deleted_recovery') }}" 
                   class="btn-green px-6 py-3 rounded-lg font-semibold hover:bg-green-700 transition-colors inline-flex items-center">
                    <svg class="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                    </svg>
                    Start Automatic Recovery
                </a>
                {% else %}
                <div class="text-yellow-400 text-sm">
                    ⏳ Recovery process is currently running...
                </div>
                {% endif %}
            </div>
            {% endif %}
        </div>
    </div>
</div>

<!-- Enhanced JavaScript for Real-time Updates -->
<script>
// Enhanced progress tracking with better error handling
function updateRecoveryProgress() {
    fetch('/deleted_scan_status')
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            console.log('Recovery status update:', data);
            
            // Update validation statistics
            if (data.validation_stats) {
                document.getElementById('total-scanned').textContent = data.validation_stats.total_scanned || 0;
                document.getElementById('empty-rejected').textContent = data.validation_stats.empty_rejected || 0;
                document.getElementById('duplicate-rejected').textContent = data.validation_stats.duplicate_rejected || 0;
                document.getElementById('invalid-rejected').textContent = data.validation_stats.invalid_rejected || 0;
                document.getElementById('valid-recovered').textContent = data.validation_stats.valid_recovered || 0;
            }
            
            // Update timing information
            if (data.elapsed_time) {
                document.getElementById('elapsed-time').textContent = data.elapsed_time;
            }
            if (data.time_remaining_str) {
                document.getElementById('time-remaining').textContent = data.time_remaining_str;
            }
            if (data.estimated_total_time) {
                document.getElementById('total-estimated').textContent = data.estimated_total_time;
            }
            
            // Update progress bar
            const progressBar = document.getElementById('progress-bar');
            const progressPercent = document.getElementById('progress-percent');
            
            if (data.in_progress) {
                // Calculate progress based on methods completed
                const totalMethods = 4; // directory_walk, inode_scan, file_slack, recycle_bin
                const completedMethods = Object.values(data.scan_methods || {}).filter(val => val > 0).length;
                const progress = Math.min(95, (completedMethods / totalMethods) * 100); // Cap at 95% until complete
                
                progressBar.style.width = progress + '%';
                progressPercent.textContent = Math.round(progress) + '%';
                progressBar.className = 'bg-blue-600 h-3 rounded-full transition-all duration-500';
            }
            
            // Update method counters
            if (data.scan_methods) {
                document.getElementById('method-dir').textContent = data.scan_methods.directory_walk || 0;
                document.getElementById('method-inode').textContent = data.scan_methods.inode_scan || 0;
                document.getElementById('method-slack').textContent = data.scan_methods.file_slack || 0;
                document.getElementById('method-recycle').textContent = data.scan_methods.recycle_bin || 0;
            }
            
            // Update status message
            const statusText = document.getElementById('status-text');
            const statusMessage = document.getElementById('status-message');
            
            if (data.message) {
                statusText.textContent = data.message;
            }
            
            if (data.in_progress) {
                statusMessage.className = 'mt-4 p-3 rounded-lg text-sm bg-blue-900 text-blue-200 border border-blue-700';
                // Continue polling
                setTimeout(updateRecoveryProgress, 2000);
            } else if (data.complete) {
                progressBar.style.width = '100%';
                progressBar.className = 'bg-green-600 h-3 rounded-full transition-all duration-500';
                progressPercent.textContent = '100%';
                statusMessage.className = 'mt-4 p-3 rounded-lg text-sm bg-green-900 text-green-200 border border-green-700';
                
                // Refresh page to show results after completion
                if (data.files_found > 0) {
                    setTimeout(() => {
                        window.location.reload();
                    }, 3000);
                }
            } else if (data.error) {
                statusMessage.className = 'mt-4 p-3 rounded-lg text-sm bg-red-900 text-red-200 border border-red-700';
                statusText.textContent = 'Error: ' + (data.error || 'Unknown error occurred');
            }
        })
        .catch(error => {
            console.error('Error fetching recovery status:', error);
            document.getElementById('status-text').textContent = 'Error connecting to server: ' + error.message;
            // Retry after 5 seconds on error
            setTimeout(updateRecoveryProgress, 5000);
        });
}

// Start polling if recovery is in progress
document.addEventListener('DOMContentLoaded', function() {
    {% if deleted_scan_status.in_progress %}
    console.log('Starting recovery progress monitoring...');
    updateRecoveryProgress();
    {% endif %}
    
    // Add click handler for the start button to show immediate feedback
    const startButton = document.querySelector('a[href*="start_strict_deleted_recovery"]');
    if (startButton) {
        startButton.addEventListener('click', function(e) {
            const button = this;
            const originalText = button.innerHTML;
            
            button.innerHTML = '🔄 Starting...';
            button.classList.add('opacity-50', 'cursor-not-allowed');
            
            // Revert after 3 seconds if still on same page
            setTimeout(() => {
                if (button.innerHTML === '🔄 Starting...') {
                    button.innerHTML = originalText;
                    button.classList.remove('opacity-50', 'cursor-not-allowed');
                }
            }, 3000);
        });
    }
});
</script>
"""
REPORTING_PAGE_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Forensic Reporting</h1>
<p class="text-gray-400 mb-8">Generate comprehensive reports of your forensic analysis findings.</p>

<div class="card p-6 rounded-lg">
    <h2 class="text-xl font-semibold text-white mb-6">Create New Report</h2>
    
    <form method="post" class="space-y-8">
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div>
                <label class="block text-sm font-medium text-gray-300">Case Name</label>
                <input type="text" name="case_name" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white" placeholder="e.g., Company Investigation" required>
            </div>
            
            <div>
                <label class="block text-sm font-medium text-gray-300">Case Number</label>
                <input type="text" name="case_number" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white" placeholder="e.g., CASE-2024-001" required>
            </div>
            
            <div>
                <label class="block text-sm font-medium text-gray-300">Examiner Name</label>
                <input type="text" name="examiner_name" class="mt-1 block w-full bg-gray-800 border-gray-600 rounded-md shadow-sm p-2 text-white" placeholder="Your name" required>
            </div>
        </div>
        
        <div>
            <label class="block text-sm font-medium text-gray-300">Report Format</label>
            <div class="mt-2 grid grid-cols-2 md:grid-cols-4 gap-4">
                <label class="relative flex cursor-pointer rounded-lg border bg-gray-800 p-4 focus:outline-none">
                    <input type="radio" name="report_format" value="html" class="sr-only" checked>
                    <span class="flex flex-1">
                        <span class="flex flex-col">
                            <span class="block text-sm font-medium text-white">HTML</span>
                            <span class="mt-1 flex text-xs text-gray-400">Web format with images</span>
                        </span>
                    </span>
                    <svg class="h-5 w-5 text-blue-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                    </svg>
                </label>
                
                <label class="relative flex cursor-pointer rounded-lg border bg-gray-800 p-4 focus:outline-none">
                    <input type="radio" name="report_format" value="pdf" class="sr-only">
                    <span class="flex flex-1">
                        <span class="flex flex-col">
                            <span class="block text-sm font-medium text-white">PDF</span>
                            <span class="mt-1 flex text-xs text-gray-400">Printable document</span>
                        </span>
                    </span>
                    <svg class="h-5 w-5 text-blue-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                    </svg>
                </label>
                
                <label class="relative flex cursor-pointer rounded-lg border bg-gray-800 p-4 focus:outline-none">
                    <input type="radio" name="report_format" value="docx" class="sr-only">
                    <span class="flex flex-1">
                        <span class="flex flex-col">
                            <span class="block text-sm font-medium text-white">DOCX</span>
                            <span class="mt-1 flex text-xs text-gray-400">Word document</span>
                        </span>
                    </span>
                    <svg class="h-5 w-5 text-blue-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                    </svg>
                </label>
                
                <label class="relative flex cursor-pointer rounded-lg border bg-gray-800 p-4 focus:outline-none">
                    <input type="radio" name="report_format" value="csv" class="sr-only">
                    <span class="flex flex-1">
                        <span class="flex flex-col">
                            <span class="block text-sm font-medium text-white">CSV (ZIP)</span>
                            <span class="mt-1 flex text-xs text-gray-400">Spreadsheet data</span>
                        </span>
                    </span>
                    <svg class="h-5 w-5 text-blue-600" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd" />
                    </svg>
                </label>
            </div>
        </div>
        
        <div class="pt-4 border-t border-gray-700">
            <button type="submit" class="btn-green w-full py-3 rounded-lg font-semibold text-lg">Generate Report</button>
        </div>
    </form>
</div>

<div class="card p-6 rounded-lg mt-8">
    <h2 class="text-xl font-semibold text-white mb-4">Report Contents</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Case Information</h3>
            <ul class="text-gray-400 space-y-1 text-sm">
                <li>• Case details and examiner information</li>
                <li>• Report generation timestamp</li>
                <li>• Software version and configuration</li>
            </ul>
        </div>
        
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Evidence Analysis</h3>
            <ul class="text-gray-400 space-y-1 text-sm">
                <li>• Loaded evidence file information</li>
                <li>• File hashes (MD5, SHA-1, SHA-256)</li>
                <li>• Forensic analysis results</li>
                <li>• Partition information</li>
            </ul>
        </div>
        
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Recovery Results</h3>
            <ul class="text-gray-400 space-y-1 text-sm">
                <li>• Carved files listing with offsets</li>
                <li>• File preview thumbnails (images)</li>
                <li>• Recovery statistics</li>
            </ul>
        </div>
        
        <div>
            <h3 class="text-lg font-semibold text-white mb-2">Deleted Files</h3>
            <ul class="text-gray-400 space-y-1 text-sm">
                <li>• Recovered deleted files listing</li>
                <li>• Metadata (timestamps, sizes)</li>
                <li>• Recovery method information</li>
            </ul>
        </div>
    </div>
</div>
"""

REPORT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Report - {{ case_details.name }}</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            line-height: 1.6; 
            color: #333; 
            max-width: 1200px; 
            margin: 0 auto; 
            padding: 20px; 
            background-color: #f9f9f9;
        }
        .header { 
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 10px; 
            margin-bottom: 30px; 
            text-align: center;
        }
        .section { 
            background: white; 
            padding: 25px; 
            margin-bottom: 25px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            border-left: 4px solid #2a5298;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 15px 0; 
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #f2f2f2; 
            font-weight: 600; 
        }
        .thumbnail { 
            max-width: 100px; 
            max-height: 100px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            padding: 2px; 
        }
        .badge { 
            display: inline-block; 
            padding: 3px 8px; 
            border-radius: 4px; 
            font-size: 0.8em; 
            font-weight: bold; 
        }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .footer { 
            text-align: center; 
            margin-top: 40px; 
            padding: 20px; 
            color: #666; 
            font-size: 0.9em; 
            border-top: 1px solid #ddd;
        }
        .hex-preview { 
            font-family: 'Courier New', monospace; 
            font-size: 0.8em; 
            background: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px; 
            overflow-x: auto; 
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Digital Forensic Analysis Report</h1>
        <h2>Case: {{ case_details.name }}</h2>
        <p>Generated on {{ now.strftime('%Y-%m-%d at %H:%M:%S') }}</p>
    </div>

    <div class="section">
        <h2>Case Information</h2>
        <table>
            <tr><th>Case Name</th><td>{{ case_details.name }}</td></tr>
            <tr><th>Case Number</th><td>{{ case_details.number }}</td></tr>
            <tr><th>Examiner</th><td>{{ case_details.examiner }}</td></tr>
            <tr><th>Report Date</th><td>{{ now.strftime('%Y-%m-%d %H:%M:%S') }}</td></tr>
            <tr><th>Software</th><td>ForensicCarver Pro v4.3.0</td></tr>
        </table>
    </div>

    {% for filename, details in evidence_file.items() %}
    <div class="section">
        <h2>Evidence File: {{ filename }}</h2>
        
        <h3>File Information</h3>
        <table>
            <tr><th>File Size</th><td>{{ details.size_mb }} MB</td></tr>
            <tr><th>MD5 Hash</th><td>{{ details.hash_info.MD5 or 'Calculating...' }}</td></tr>
            <tr><th>SHA-1 Hash</th><td>{{ details.hash_info['SHA-1'] or 'Calculating...' }}</td></tr>
            <tr><th>SHA-256 Hash</th><td>{{ details.hash_info['SHA-256'] or 'Calculating...' }}</td></tr>
            <tr><th>Encryption Status</th>
                <td>
                    {% if details.encryption_status.encrypted %}
                        <span class="badge badge-warning">ENCRYPTED</span> - {{ details.encryption_status.description }}
                        {% if details.encryption_status.decrypted_path %}
                            <span class="badge badge-success">(Decrypted)</span>
                        {% endif %}
                    {% else %}
                        <span class="badge badge-success">Not Encrypted</span>
                    {% endif %}
                </td>
            </tr>
        </table>

        <h3>Forensic Analysis</h3>
        <ul>
            {% for result in details.forensic_results %}
            <li>{{ result }}</li>
            {% endfor %}
        </ul>

        {% if details.partition_info %}
        <h3>Partition Information</h3>
        <table>
            <tr><th>Index</th><th>Description</th><th>Start Sector</th><th>Length (Sectors)</th></tr>
            {% for part in details.partition_info %}
            <tr>
                <td>{{ part.addr }}</td>
                <td>{{ part.desc }}</td>
                <td>{{ part.start }}</td>
                <td>{{ part.len }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}
    </div>
    {% endfor %}

    {% if carved_files %}
    <div class="section">
        <h2>Carved Files Recovery ({{ carved_files|length }} files found)</h2>
        <table>
            <tr><th>ID</th><th>Filename</th><th>Offset</th><th>Size</th><th>Preview</th></tr>
            {% for filename, info in carved_files.items() %}
            <tr>
                <td>{{ info.id }}</td>
                <td>{{ filename }}</td>
                <td>{{ info.offset }}</td>
                <td>{{ "%.2f KB"|format(info.size_bytes / 1024) if info.size_bytes else 'N/A' }}</td>
                <td>
                    {% if info.thumbnail_uri %}
                    <img src="{{ info.thumbnail_uri }}" class="thumbnail" alt="Preview">
                    {% else %}
                    <em>No preview</em>
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    {% if deleted_files %}
    <div class="section">
        <h2>Deleted Files Recovery ({{ deleted_files|length }} entries found)</h2>
        <table>
            <tr><th>Inode</th><th>Filename</th><th>Size</th><th>Modified</th><th>Recovery Method</th></tr>
            {% for inode, file in deleted_files.items() %}
            <tr>
                <td>{{ file.inode }}</td>
                <td>{{ file.name }}</td>
                <td>{{ file.size }} bytes</td>
                <td>{{ file.mtime }}</td>
                <td>{{ file.recovery_method }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}

    <div class="footer">
        <p>This report was automatically generated by ForensicCarver Pro.</p>
        <p>Confidential - For authorized personnel only.</p>
    </div>
</body>
</html>
"""

HEX_VIEW_CARVED_FILE_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Hex View: {{ filename }}</h1>
<div class="flex justify-between items-center mb-4">
    <a href="{{ url_for('view_carved_file', filename=filename) }}" class="btn-secondary px-4 py-2 rounded-lg">Back to File View</a>
    <a href="{{ url_for('download_carved_file', filename=filename) }}" class="btn-primary px-4 py-2 rounded-lg">Download File</a>
</div>

<div class="card p-6 rounded-lg">
    <div class="hex-view p-4 rounded-lg overflow-x-auto">
        <pre class="font-mono text-sm leading-tight">{{ hex_content }}</pre>
    </div>
</div>
"""

DELETED_RECOVERY_PROCESS_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-2">Deleted Files Recovery in Progress</h1>
<p class="text-gray-400 mb-8">Scanning evidence file for deleted files and metadata.</p>

<div class="card p-6 rounded-lg">
    <div class="flex justify-between items-center mb-4">
        <h2 class="text-xl font-semibold text-white">Recovery Progress</h2>
        <span id="status-badge" class="px-3 py-1 bg-yellow-600 text-white rounded-full text-sm font-medium">Running</span>
    </div>
    
    <div id="progress-container">
        <p class="text-sm text-gray-400 mb-2">Status: <span id="status-message">Starting recovery process...</span></p>
        <p class="text-sm text-gray-400">Files found: <span id="files-found">0</span></p>
        
        <div class="mt-4 w-full bg-gray-700 rounded-full h-2">
            <div id="progress-bar" class="bg-blue-600 h-2 rounded-full transition-all duration-500" style="width: 0%"></div>
        </div>
    </div>
    
    <div id="error-container" class="mt-4 p-4 bg-red-900 border border-red-500 rounded-lg text-sm text-red-200 hidden">
        <h3 class="font-bold mb-2">An Error Occurred</h3>
        <p id="error-message"></p>
    </div>
    
    <div id="success-container" class="mt-4 p-4 bg-green-900 border border-green-500 rounded-lg text-sm text-green-200 hidden">
        <h3 class="font-bold mb-2">Recovery Complete</h3>
        <p id="success-message"></p>
    </div>
</div>

<div class="mt-8 flex justify-center">
    <a href="{{ url_for('deleted_files') }}" id="view-results-btn" class="btn-primary px-6 py-3 rounded-lg opacity-50 pointer-events-none">View Recovered Files</a>
</div>

<script>
function updateRecoveryProgress() {
    fetch('/deleted_scan_status')
        .then(response => response.json())
        .then(data => {
            const statusMessage = document.getElementById('status-message');
            const filesFound = document.getElementById('files-found');
            const progressBar = document.getElementById('progress-bar');
            const statusBadge = document.getElementById('status-badge');
            const errorContainer = document.getElementById('error-container');
            const successContainer = document.getElementById('success-container');
            const viewResultsBtn = document.getElementById('view-results-btn');

            statusMessage.textContent = data.message;
            filesFound.textContent = data.files_found;

            // Update progress bar based on status
            if (data.in_progress) {
                progressBar.style.width = '70%'; // Indeterminate progress
                statusBadge.className = 'px-3 py-1 bg-yellow-600 text-white rounded-full text-sm font-medium';
                statusBadge.textContent = 'Running';
                setTimeout(updateRecoveryProgress, 2000);
            } else if (data.complete) {
                progressBar.style.width = '100%';
                progressBar.classList.remove('bg-blue-600');
                progressBar.classList.add('bg-green-600');
                statusBadge.className = 'px-3 py-1 bg-green-600 text-white rounded-full text-sm font-medium';
                statusBadge.textContent = 'Complete';
                
                successContainer.classList.remove('hidden');
                document.getElementById('success-message').textContent = 
                    `Recovery completed successfully. Found ${data.files_found} files.`;
                
                viewResultsBtn.classList.remove('opacity-50', 'pointer-events-none');
            }

            if (data.message && data.message.toLowerCase().includes('error')) {
                errorContainer.classList.remove('hidden');
                document.getElementById('error-message').textContent = data.message;
                statusBadge.className = 'px-3 py-1 bg-red-600 text-white rounded-full text-sm font-medium';
                statusBadge.textContent = 'Error';
            }
        })
        .catch(error => {
            console.error('Error fetching recovery status:', error);
            document.getElementById('status-message').textContent = 'Error checking recovery status';
            document.getElementById('error-container').classList.remove('hidden');
            document.getElementById('error-message').textContent = error.toString();
        });
}

// Start polling for progress updates
document.addEventListener('DOMContentLoaded', function() {
    updateRecoveryProgress();
});
</script>
"""

DELETED_FILES_CONTENT = """
<h1 class="text-3xl font-bold text-white mb-4">Recovered Deleted Files</h1>
<p class="text-gray-400 mb-8">Files recovered from deleted space and file system metadata.</p>

<div class="card p-6 rounded-lg">
    {% if deleted_files %}
    <div class="overflow-x-auto">
        <table class="min-w-full">
            <thead>
                <tr class="border-b border-gray-600">
                    <th class="text-left py-3 px-4 text-white font-semibold">Inode</th>
                    <th class="text-left py-3 px-4 text-white font-semibold">Filename</th>
                    <th class="text-left py-3 px-4 text-white font-semibold">Size</th>
                    <th class="text-left py-3 px-4 text-white font-semibold">Modified</th>
                    <th class="text-left py-3 px-4 text-white font-semibold">Recovery Method</th>
                    <th class="text-left py-3 px-4 text-white font-semibold">Actions</th>
                </tr>
            </thead>
            <tbody>
                {% for inode, file in deleted_files.items() %}
                <tr class="border-b border-gray-700 hover:bg-gray-800">
                    <td class="py-3 px-4 text-gray-300 font-mono">{{ file.inode }}</td>
                    <td class="py-3 px-4 text-gray-300">{{ file.name }}</td>
                    <td class="py-3 px-4 text-gray-300">{{ file.size }} bytes</td>
                    <td class="py-3 px-4 text-gray-300">{{ file.mtime }}</td>
                    <td class="py-3 px-4 text-gray-300">
                        <span class="px-2 py-1 bg-blue-600 rounded text-xs">{{ file.recovery_method }}</span>
                    </td>
                    <td class="py-3 px-4">
                        <div class="flex space-x-2">
                            <a href="{{ url_for('view_deleted_file', inode=inode) }}" class="btn-secondary px-3 py-1 text-xs">View</a>
                            <a href="{{ url_for('download_deleted_file', inode=inode) }}" class="btn-primary px-3 py-1 text-xs">Download</a>
                        </div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    
    <div class="mt-4 text-sm text-gray-400">
        Total recovered files: {{ deleted_files|length }}
    </div>
    {% else %}
    <div class="text-center py-8 text-gray-500">
        <p>No deleted files have been recovered yet.</p>
        <a href="{{ url_for('deleted_files_status_page') }}" class="btn-primary mt-4 inline-block px-4 py-2">Start Recovery Process</a>
    </div>
    {% endif %}
</div>
"""

def get_active_evidence_path():
    """
    Gets the correct path for analysis. 
    Returns the decrypted path if it exists, otherwise the original path.
    Returns None if no file is loaded.
    """
    if not uploaded_files_db:
        return None
    
    file_details = next(iter(uploaded_files_db.values()))
    
    decrypted_path = file_details.get('encryption_status', {}).get('decrypted_path')
    if decrypted_path and os.path.exists(decrypted_path):
        return decrypted_path
    
    return file_details.get('path')

# --- Helper functions for loading and clearing data ---

def _clear_all_session_data():
    """Clears all in-memory data and temporary result files."""
    global carving_status, deleted_scan_status, decryption_status, hashing_status, strings_status, uploaded_files_db, deleted_files_db, sorted_deleted_inodes
    
    uploaded_files_db.clear()
    deleted_files_db.clear()
    sorted_deleted_inodes = []
    
    if not carving_status.get("complete"):
        carving_status = {
            "progress": 0, "current_offset": "0x00000000", "files_found": 0,
            "complete": False, "found_files_list": [], "time_remaining_str": "N/A"
        }
    
    deleted_scan_status = {
        "in_progress": False, "files_found": 0, "complete": False, "message": "Scan has not started.",
        "errors": [], "time_remaining_str": "N/A"
    }
    decryption_status = {
        "in_progress": False, "complete": False, "message": "", "attempts": 0, "success": False, "filename": None
    }
    hashing_status = {
        "in_progress": False, "progress": 0, "complete": False, "hashes": {}
    }
    strings_status = {
        "in_progress": False, "complete": False, "progress": 0, "strings_found": 0, "preview": []
    }
    
    # NEW: Clear the carved files directory
    carved_dir = app.config['CARVED_FOLDER']
    try:
        if os.path.exists(carved_dir):
            for filename in os.listdir(carved_dir):
                file_path = os.path.join(carved_dir, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            print(f"Cleared carved files directory: {carved_dir}")
    except Exception as e:
        print(f"Error clearing carved files directory: {e}")
    
    # NEW: Clear the deleted recovery directory
    deleted_recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    try:
        if os.path.exists(deleted_recovery_dir):
            for filename in os.listdir(deleted_recovery_dir):
                file_path = os.path.join(deleted_recovery_dir, filename)
                if os.path.isfile(file_path):
                    os.unlink(file_path)
            print(f"Cleared deleted recovery directory: {deleted_recovery_dir}")
    except Exception as e:
        print(f"Error clearing deleted recovery directory: {e}")
    
    # Remove any JSON result files
    for json_file in ['carved_results.json', 'deleted_results.json']:
        if os.path.exists(json_file):
            try:
                os.remove(json_file)
            except Exception as e:
                print(f"Error removing {json_file}: {e}")

def _generate_preview_response(content, filename, data_url, file_info=None):
    """Analyzes file content and returns the appropriate Flask response for previewing."""
    if not content:
        return "Cannot preview an empty file.", 400

    mime_type = magic.from_buffer(content, mime=True)
    text_content = None
    
    # For images, PDFs, and media files - use embedded preview
    if mime_type.startswith('image/'):
        return render_template_string(VIEW_FILE_CONTENT, 
                                    filename=filename, 
                                    mime_type=mime_type, 
                                    data_url=data_url,
                                    is_carved=True,
                                    file_info=file_info or {})
    
    if mime_type == 'application/pdf':
        return render_template_string(VIEW_FILE_CONTENT, 
                                    filename=filename, 
                                    mime_type=mime_type, 
                                    data_url=data_url,
                                    is_carved=True,
                                    file_info=file_info or {})
    
    if mime_type.startswith(('audio/', 'video/')):
        return render_template_string(VIEW_FILE_CONTENT, 
                                    filename=filename, 
                                    mime_type=mime_type, 
                                    data_url=data_url,
                                    is_carved=True,
                                    file_info=file_info or {})

    # For text-based and other files - extract content for preview
    temp_file_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tf:
            tf.write(content)
            temp_file_path = tf.name

        if mime_type.startswith('text/'):
            text_content = parse_text_log(temp_file_path)
        elif mime_type == 'application/rtf' or filename.lower().endswith('.rtf'):
            text_content = parse_text_log(temp_file_path)
        elif 'openxmlformats-officedocument.wordprocessingml' in mime_type:
            text_content = extract_docx_text(temp_file_path)
        elif 'openxmlformats-officedocument.spreadsheetml' in mime_type:
            text_content = extract_xlsx_text(temp_file_path)
        elif 'openxmlformats-officedocument.presentationml' in mime_type:
            text_content = extract_pptx_text(temp_file_path)
        elif any(t in mime_type for t in ['zip', 'rar', 'x-7z-compressed', 'gzip']):
            text_content = list_archive_contents(temp_file_path)
        elif 'sqlite' in mime_type:
            text_content = preview_sqlite_db(temp_file_path)
        elif 'eventlog' in mime_type or filename.lower().endswith('.evtx'):
            text_content = parse_evtx_log(temp_file_path)
        elif 'executable' in mime_type or 'x-dosexec' in mime_type or filename.lower().endswith(('.exe', '.dll', '.elf')):
            text_content = preview_executable(temp_file_path)
        elif filename.lower().endswith('.doc'):
            text_content = extract_strings_preview(temp_file_path)
        elif filename.lower().endswith('.dat') and content[:4] == b'regf':
            text_content = extract_strings_preview(temp_file_path)
        else:
            # Fallback for unknown types - show hex preview
            text_content = format_hex_view(content[:2000])  # Show first 2000 bytes as hex

        if text_content is not None:
            return render_template_string(VIEW_FILE_CONTENT, 
                                        filename=filename, 
                                        mime_type=mime_type, 
                                        text_content=text_content,
                                        is_carved=True,
                                        file_info=file_info or {})
    except Exception as e:
        print(f"Error during preview generation for {filename}: {e}")
        # Fallback to hex view if parsing fails
        text_content = f"Error parsing file: {e}\n\nHex preview:\n{format_hex_view(content[:2000])}"
        return render_template_string(VIEW_FILE_CONTENT, 
                                    filename=filename, 
                                    mime_type=mime_type, 
                                    text_content=text_content,
                                    is_carved=True,
                                    file_info=file_info or {})
    finally:
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    # Ultimate fallback
    return render_template_string(VIEW_FILE_CONTENT, 
                                filename=filename, 
                                mime_type=mime_type, 
                                text_content="File preview not available",
                                is_carved=True,
                                file_info=file_info or {})

def _load_file_into_session(filename, filepath):
    """Loads file metadata into the session and starts background analysis."""
    encryption_info = detect_encryption(filepath)
    forensic_results, partition_info = perform_forensic_analysis(filepath)

    uploaded_files_db[filename] = {
        "path": filepath, "size_mb": f"{os.path.getsize(filepath) / (1024*1024):.2f}",
        "encryption_status": {
            "encrypted": encryption_info.get('encrypted'), "encryption_type": encryption_info.get('encryption_type'),
            "description": encryption_info.get('description'), "decrypting": False, "decrypted_path": None
        },
        "forensic_results": forensic_results, "partition_info": partition_info,
        "hash_info": {}, "hashing_complete": False
    }
    threading.Thread(target=calculate_hashes_threaded, args=(filepath,)).start()
    return encryption_info['encrypted']

def determine_recovery_method(filename):
    """Determine recovery method from filename pattern."""
    filename_lower = filename.lower()
    if 'dirwalk' in filename_lower or 'directory' in filename_lower:
        return "Directory Walk"
    elif 'inode' in filename_lower or 'orphan' in filename_lower:
        return "Inode Scan"
    elif 'slack' in filename_lower:
        return "File Slack"
    elif 'recycle' in filename_lower or 'recycled' in filename_lower:
        return "Recycle Bin"
    elif 'deep' in filename_lower:
        return "Deep Scan"
    else:
        return "Unknown Method"

# --- STRICT AUTOMATIC DELETED FILES RECOVERY ---
def strict_deleted_files_recovery_engine(filepath):
    """Autopsy-like automatic deleted files recovery with strict validation."""
    global deleted_scan_status
    
    deleted_scan_status.update({
        "in_progress": True, 
        "complete": False, 
        "files_found": 0, 
        "message": "Starting strict automatic recovery...",
        "scan_methods": {
            "directory_walk": 0,
            "inode_scan": 0,
            "file_slack": 0,
            "unallocated_space": 0,
            "recycle_bin": 0
        },
        "validation_stats": {
            "total_scanned": 0,
            "empty_rejected": 0,
            "duplicate_rejected": 0,
            "invalid_rejected": 0,
            "valid_recovered": 0
        }
    })

    recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    seen_hashes = set()
    MIN_FILE_SIZE = 512  # Increased minimum size to avoid tiny files
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
    
    # Clear previous results
    try:
        for item in os.listdir(recovery_dir):
            item_path = os.path.join(recovery_dir, item)
            if os.path.isfile(item_path):
                os.unlink(item_path)
    except Exception as e:
        deleted_scan_status["message"] = f"Error clearing old files: {e}"
        deleted_scan_status["in_progress"] = False
        return

    total_recovered = 0
    
    def validate_and_save_file(content, original_name, recovery_method, fs_object=None):
        """STRICT validation: Check file size, content, and duplicates before saving."""
        nonlocal total_recovered, seen_hashes
        
        deleted_scan_status["validation_stats"]["total_scanned"] += 1
        
        # 1. Check for empty content
        if not content or len(content) < MIN_FILE_SIZE:
            deleted_scan_status["validation_stats"]["empty_rejected"] += 1
            return False
        
        # 2. Check file size limit
        if len(content) > MAX_FILE_SIZE:
            deleted_scan_status["validation_stats"]["invalid_rejected"] += 1
            return False
        
        # 3. Calculate content hash for deduplication
        content_hash = hashlib.sha256(content).hexdigest()
        if content_hash in seen_hashes:
            deleted_scan_status["validation_stats"]["duplicate_rejected"] += 1
            return False
        
        # 4. Validate file structure based on type
        if not validate_file_structure(content, original_name):
            deleted_scan_status["validation_stats"]["invalid_rejected"] += 1
            return False
        
        # 5. All checks passed - save the file
        try:
            # Generate unique filename with metadata
            safe_filename = generate_recovery_filename(
                original_name, recovery_method, total_recovered + 1, fs_object
            )
            save_path = os.path.join(recovery_dir, safe_filename)
            
            with open(save_path, 'wb') as out_file:
                out_file.write(content)
            
            # Add to seen hashes to prevent duplicates
            seen_hashes.add(content_hash)
            total_recovered += 1
            deleted_scan_status["validation_stats"]["valid_recovered"] += 1
            
            return True
        except Exception as e:
            print(f"Error saving recovered file: {e}")
            return False

    def validate_file_structure(content, filename):
        """Validate file structure based on file type signatures."""
        try:
            # Check for valid file headers
            if len(content) < 8:  # Too short for any meaningful file
                return False
            
            # Common file signature validation
            file_signatures = {
                b'\xff\xd8\xff': 'JPEG',
                b'\x89PNG\r\n\x1a\n': 'PNG',
                b'%PDF': 'PDF',
                b'PK\x03\x04': 'ZIP/DOCX',
                b'\x25\x50\x44\x46': 'PDF',
                b'\x47\x49\x46\x38': 'GIF',
                b'BM': 'BMP',
                b'RIFF': 'WAV/AVI',
            }
            
            # Check if content starts with known file signature
            for signature, file_type in file_signatures.items():
                if content.startswith(signature):
                    return True
            
            # For files without clear signatures, check entropy
            entropy = calculate_entropy(content[:4096])  # Check first 4KB
            if entropy < 1.0 or entropy > 7.5:  # Suspicious entropy values
                return False
                
            return True  # Accept files that pass basic checks
            
        except Exception:
            return False

    def generate_recovery_filename(original_name, recovery_method, file_id, fs_object=None):
        """Generate informative filename for recovered files."""
        # Clean the original filename
        clean_name = re.sub(r'[^\w\.-]', '_', original_name)
        
        # Add metadata
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        method_abbr = recovery_method[:4].upper()
        
        if fs_object and hasattr(fs_object.info, 'meta'):
            inode = f"i{fs_object.info.meta.addr}"
        else:
            inode = "i0000"
        
        return f"rec_{file_id:04d}_{method_abbr}_{inode}_{clean_name}"

    def update_recovery_status(method, validated=True):
        """Update recovery status with validation info."""
        nonlocal total_recovered
        
        if validated:
            total_recovered += 1
            deleted_scan_status["files_found"] = total_recovered
            deleted_scan_status["scan_methods"][method] += 1
        
        # Update status message with validation stats
        stats = deleted_scan_status["validation_stats"]
        status_msg = (
            f"Recovered: {total_recovered} | "
            f"Scanned: {stats['total_scanned']} | "
            f"Rejected - Empty: {stats['empty_rejected']}, "
            f"Duplicate: {stats['duplicate_rejected']}, "
            f"Invalid: {stats['invalid_rejected']}"
        )
        deleted_scan_status["message"] = status_msg

    # Main recovery logic
    try:
        img_handle = pytsk3.Img_Info(filepath)
        
        def strict_directory_walk(fs, directory, path="/"):
            """Strict directory walking with validation."""
            try:
                for f in directory:
                    if not hasattr(f.info, 'meta') or f.info.meta is None:
                        continue
                    
                    # Check if file is deleted and valid for recovery
                    is_deleted = not (f.info.meta.flags & pytsk3.TSK_FS_META_FLAG_ALLOC)
                    is_file = f.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG
                    has_name = hasattr(f.info, 'name') and f.info.name is not None
                    
                    if is_deleted and is_file and has_name and f.info.name.name not in [b'.', b'..']:
                        try:
                            if MIN_FILE_SIZE < f.info.meta.size <= MAX_FILE_SIZE:
                                content = f.read_random(0, min(f.info.meta.size, MAX_FILE_SIZE))
                                
                                if validate_and_save_file(
                                    content, 
                                    f.info.name.name.decode('utf-8', 'ignore'),
                                    'directory_walk',
                                    f
                                ):
                                    update_recovery_status("directory_walk", True)
                                
                        except Exception as e:
                            continue
                    
                    # Recursive directory scanning
                    if (f.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and 
                        has_name and f.info.name.name not in [b'.', b'..']):
                        try:
                            strict_directory_walk(fs, f.as_directory(), 
                                                f"{path}/{f.info.name.name.decode('utf-8', 'ignore')}")
                        except (IOError, AttributeError):
                            continue
            except Exception as e:
                pass

        def strict_inode_scan(fs):
            """Strict inode scanning with validation."""
            try:
                last_inode = fs.info.last_inum
                for inode_num in range(fs.info.first_inum, last_inode + 1):
                    try:
                        fs_file = fs.open_meta(inode=inode_num)
                        
                        if (fs_file.info.meta.flags & pytsk3.TSK_FS_META_FLAG_UNALLOC and 
                            fs_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG and 
                            MIN_FILE_SIZE < fs_file.info.meta.size <= MAX_FILE_SIZE):
                            
                            try:
                                content = fs_file.read_random(0, min(fs_file.info.meta.size, MAX_FILE_SIZE))
                                
                                # Generate name for orphaned files
                                name = f"orphan_inode_{inode_num}"
                                if hasattr(fs_file.info, 'name') and fs_file.info.name:
                                    orig_name = fs_file.info.name.name.decode('utf-8', 'ignore')
                                    if orig_name not in ['.', '..']:
                                        name = orig_name
                                
                                if validate_and_save_file(content, name, 'inode_scan', fs_file):
                                    update_recovery_status("inode_scan", True)
                                    
                            except Exception:
                                continue
                    except (IOError, AttributeError):
                        continue
            except Exception as e:
                pass

        # Execute recovery methods
        try:
            volume = pytsk3.Volume_Info(img_handle)
            for part in volume:
                if part.flags != pytsk3.TSK_VS_PART_FLAG_UNALLOC:
                    try:
                        fs_offset = part.start * volume.info.block_size
                        fs = pytsk3.FS_Info(img_handle, offset=fs_offset)
                        
                        deleted_scan_status["message"] = f"Scanning partition {part.desc}..."
                        
                        # Run strict recovery methods
                        strict_directory_walk(fs, fs.open_dir(path="/"))
                        strict_inode_scan(fs)
                        
                    except IOError:
                        continue
        except IOError:
            # Try as single filesystem
            try:
                fs = pytsk3.FS_Info(img_handle, offset=0)
                deleted_scan_status["message"] = "Scanning as single filesystem..."
                
                strict_directory_walk(fs, fs.open_dir(path="/"))
                strict_inode_scan(fs)
                
            except IOError as e:
                deleted_scan_status["message"] = f"Error opening filesystem: {e}"

        # Final status update
        stats = deleted_scan_status["validation_stats"]
        final_msg = (
            f"Recovery complete! "
            f"Recovered: {total_recovered} valid files. "
            f"Scanned: {stats['total_scanned']} | "
            f"Rejected: {stats['empty_rejected'] + stats['duplicate_rejected'] + stats['invalid_rejected']} "
            f"(Empty: {stats['empty_rejected']}, Duplicate: {stats['duplicate_rejected']}, Invalid: {stats['invalid_rejected']})"
        )
        deleted_scan_status["message"] = final_msg
        deleted_scan_status["complete"] = True
        
    except Exception as e:
        deleted_scan_status["message"] = f"A critical error occurred: {e}"
        deleted_scan_status["complete"] = True
        
    deleted_scan_status["in_progress"] = False

# --- UPDATE THE ROUTE TO USE STRICT RECOVERY ---
@app.route('/start_strict_deleted_recovery')
def start_strict_deleted_recovery():
    """Starts the strict automatic deleted files recovery process."""
    if not uploaded_files_db:
        flash("Please upload an evidence file first.", "error")
        return redirect(url_for('evidence_upload'))
    
    if deleted_scan_status.get("in_progress"):
        flash("Deleted files recovery is already in progress.", "info")
        return redirect(url_for('deleted_files_status_page'))
    
    filepath = get_active_evidence_path()
    if not filepath:
        flash("Could not determine evidence file path.", "error")
        return redirect(url_for('evidence_upload'))
    
    # Reset status and start strict recovery
    deleted_scan_status.update({
        "in_progress": True, 
        "complete": False, 
        "files_found": 0, 
        "message": "Starting strict automatic recovery...",
        "scan_methods": {
            "directory_walk": 0,
            "inode_scan": 0,
            "file_slack": 0,
            "unallocated_space": 0,
            "recycle_bin": 0
        },
        "validation_stats": {
            "total_scanned": 0,
            "empty_rejected": 0,
            "duplicate_rejected": 0,
            "invalid_rejected": 0,
            "valid_recovered": 0
        }
    })
    
    # Clear previous results
    recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    try:
        for item in os.listdir(recovery_dir):
            item_path = os.path.join(recovery_dir, item)
            if os.path.isfile(item_path):
                os.unlink(item_path)
    except Exception as e:
        flash(f"Error clearing old files: {e}", "warning")
    
    # Start the strict recovery in a background thread
    threading.Thread(target=strict_deleted_files_recovery_engine, args=(filepath,)).start()
    
    flash("Started strict automatic recovery process with duplicate and empty file filtering.", "success")
    return redirect(url_for('deleted_files_status_page'))

# --- Flask Routes ---
@app.route('/')
def index():
    return redirect(url_for('evidence_upload'))

@app.route('/upload_status')
def upload_status_endpoint():
    """Get current upload status with timing information."""
    return jsonify(upload_status)

@app.route('/carving_status')
def carving_status_endpoint():
    """Get current carving status with timing information."""
    return jsonify(carving_status)



@app.route('/all_process_status')
def all_process_status():
    """Get status of all background processes with timing."""
    return jsonify({
        "upload": upload_status,
        "carving": carving_status,
        "deleted_recovery": deleted_scan_status,
        "decryption": decryption_status,
        "hashing": hashing_status,
        "strings": strings_status
    })

@app.route('/deleted_recovery')
def deleted_recovery():
    """Redirect to the deleted files recovery status page"""
    return redirect(url_for('deleted_files_status_page'))

@app.route('/start_deleted_recovery')
def start_deleted_recovery():
    """Starts the deleted files recovery process"""
    if not uploaded_files_db:
        flash("Please upload an evidence file first.", "error")
        return redirect(url_for('evidence_upload'))
    
    if deleted_scan_status.get("in_progress"):
        flash("Deleted files recovery is already in progress.", "info")
        return redirect(url_for('deleted_files_status_page'))
    
    filepath = get_active_evidence_path()
    if not filepath:
        flash("Could not determine evidence file path.", "error")
        return redirect(url_for('evidence_upload'))
    
    # Reset status and start recovery
    deleted_scan_status.update({
        "in_progress": True, 
        "complete": False, 
        "files_found": 0, 
        "message": "Starting recovery process...",
        "errors": []
    })
    
    # Clear previous results
    recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    try:
        for item in os.listdir(recovery_dir):
            item_path = os.path.join(recovery_dir, item)
            if os.path.isfile(item_path):
                os.unlink(item_path)
    except Exception as e:
        flash(f"Error clearing old files: {e}", "warning")
    
    # Start the recovery in a background thread
    threading.Thread(target=recover_deleted_files_engine, args=(filepath,)).start()
    
    return redirect(url_for('deleted_files_status_page'))

# --- FIX: ADDED THE MISSING evidence_upload ROUTE ---
@app.route('/evidence_upload', methods=['GET', 'POST'])
def evidence_upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)
        
        if file:
            # Initialize upload timing
            upload_status.update({
                "in_progress": True,
                "filename": file.filename,
                "start_time": time.time(),
                "last_update_time": time.time(),
                "progress": 0,
                "bytes_uploaded": 0,
                "total_bytes": 0,
                "elapsed_time": "0s",
                "time_remaining_str": "Calculating..."
            })
            
            # Clear previous session data
            _clear_all_session_data()
            
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            if os.path.exists(filepath):
                flash(f"A file named '{filename}' already exists on disk. Please remove it or rename the new file.", 'error')
                upload_status["in_progress"] = False
                return redirect(url_for('evidence_upload'))

            if db and EvidenceFile.query.filter_by(filename=filename).first():
                flash(f"A file named '{filename}' already exists in the database. Please remove it or rename the new file.", 'error')
                upload_status["in_progress"] = False
                return redirect(url_for('evidence_upload'))

            # Get file size for progress tracking
            file.seek(0, 2)  # Seek to end to get size
            file_size = file.tell()
            file.seek(0)  # Reset to beginning
            upload_status["total_bytes"] = file_size
            
            # Save file with progress tracking
            bytes_written = 0
            chunk_size = 64 * 1024  # 64KB chunks
            
            with open(filepath, 'wb') as f:
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    bytes_written += len(chunk)
                    
                    # Update upload progress
                    upload_status["bytes_uploaded"] = bytes_written
                    upload_status["progress"] = (bytes_written / file_size) * 100
                    
                    # Update timing every second
                    if time.time() - upload_status["last_update_time"] >= 1:
                        elapsed, remaining, total_est = calculate_upload_time_estimations(
                            bytes_written, file_size, upload_status["start_time"]
                        )
                        upload_status["elapsed_time"] = elapsed
                        upload_status["time_remaining_str"] = remaining
                        upload_status["estimated_total_time"] = total_est
                        upload_status["last_update_time"] = time.time()

            # Final timing update
            upload_status.update({
                "in_progress": False,
                "progress": 100,
                "elapsed_time": format_time(time.time() - upload_status["start_time"]),
                "time_remaining_str": "Complete",
                "estimated_total_time": format_time(time.time() - upload_status["start_time"])
            })
            
            file_size = os.path.getsize(filepath)

            if db:
                check_and_manage_storage(file_size)
                new_evidence = EvidenceFile(filename=filename, filepath=filepath, filesize=file_size)
                db.session.add(new_evidence)
                db.session.commit()
                return redirect(url_for('load_evidence', file_id=new_evidence.id, new_upload=True))
            else:
                is_encrypted = _load_file_into_session(filename, filepath)
                flash(f"Successfully uploaded '{filename}' for analysis (non-persistent).", "success")
                if is_encrypted:
                    return redirect(url_for('decryption_page', filename=filename))
                return redirect(url_for('forensic_analysis'))
    
    # GET request - show upload form with timing information
    db_files = []
    if db:
        try:
            db_files = EvidenceFile.query.order_by(EvidenceFile.upload_date.desc()).all()
        except Exception as e:
            flash(f"Database connection error: {e}. Running in non-persistent mode.", "error")
    
    content = render_template_string(EVIDENCE_UPLOAD_CONTENT, uploaded_files=uploaded_files_db, db_files=db_files)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/encryption_page', methods=['GET', 'POST'])
def encryption_page():
    if request.method == 'POST':
        if 'file' not in request.files or not request.form.get('password'):
            content = render_template_string(
                ENCRYPTION_PAGE_CONTENT, 
                success=False, 
                message='Error: Both a file and a password are required.'
            )
            return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

        file = request.files['file']
        password = request.form['password']

        if file.filename == '':
            content = render_template_string(
                ENCRYPTION_PAGE_CONTENT, 
                success=False, 
                message='Error: Please select a file to encrypt.'
            )
            return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

        original_filename = secure_filename(file.filename)
        temp_filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_encrypt_{original_filename}")
        file.save(temp_filepath)

        success, message, encrypted_filename = custom_encrypt_file(
            temp_filepath,
            original_filename,
            password, 
            app.config['ENCRYPTED_FOLDER']
        )
        
        os.remove(temp_filepath)

        content = render_template_string(
            ENCRYPTION_PAGE_CONTENT,
            success=success,
            message=message,
            encrypted_filename=encrypted_filename
        )
        return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

    content = render_template_string(ENCRYPTION_PAGE_CONTENT)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/load_evidence/<int:file_id>')
def load_evidence(file_id):
    # NEW: Clear previous session data BEFORE loading new evidence
    _clear_all_session_data()
    
    new_upload = request.args.get('new_upload', False)

    evidence = None
    if db and file_id != -1:
        evidence = EvidenceFile.query.get(file_id)
    
    if evidence:
        filename = evidence.filename
        filepath = evidence.filepath
        is_encrypted = _load_file_into_session(filename, filepath)
        
        if new_upload:
            flash(f"Successfully uploaded and loaded '{filename}' for analysis.", "success")
        else:
            flash(f"Loaded evidence file '{filename}' from database. Previous session cleared.", "success")

        if is_encrypted:
            return redirect(url_for('decryption_page', filename=filename))
        else:
            return redirect(url_for('forensic_analysis'))
    else:
        if uploaded_files_db:
            return redirect(url_for('forensic_analysis'))
        flash("Could not load the specified evidence file.", "error")
        return redirect(url_for('evidence_upload'))
    
@app.route('/remove_file/<filename>')
def remove_file(filename):
    if filename in uploaded_files_db:
        _clear_all_session_data()
        flash(f'File {filename} unloaded from session.', 'success')
    return redirect(url_for('evidence_upload'))

@app.route('/remove_from_db/<int:file_id>')
def remove_from_db(file_id):
    if not db:
        flash("Database functionality is not enabled.", "error")
        return redirect(url_for('evidence_upload'))

    evidence_to_remove = EvidenceFile.query.get(file_id)

    if evidence_to_remove:
        try:
            if evidence_to_remove.filename in uploaded_files_db:
                _clear_all_session_data()
                flash(f"Unloaded '{evidence_to_remove.filename}' from the current session.", "info")

            if os.path.exists(evidence_to_remove.filepath):
                os.remove(evidence_to_remove.filepath)
            
            db.session.delete(evidence_to_remove)
            db.session.commit()
            flash(f"Successfully removed '{evidence_to_remove.filename}' from the database and disk.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred while removing the file: {e}", "error")
    else:
        flash("File not found in the database.", "error")
    
    return redirect(url_for('evidence_upload'))

@app.route('/decryption/<filename>', methods=['GET', 'POST'])
def decryption_page(filename):
    if filename not in uploaded_files_db:
        flash("File not found or not loaded.", 'error')
        return redirect(url_for('evidence_upload'))
    
    file_info = uploaded_files_db[filename]
    if not file_info['encryption_status']['encrypted']:
        flash(f"'{filename}' is not encrypted.", "info")
        return redirect(url_for('forensic_analysis'))

    if request.method == 'POST':
        password = request.form.get('password')
        action = request.form.get('action')
        forced_type = request.form.get('force_type')

        if action == 'with_password' and not password:
            flash("Password field must be filled to use 'Decrypt with Provided Password'.", 'error')
            return redirect(url_for('decryption_page', filename=filename))
        
        pwd_to_try = password if action == 'with_password' else None
        
        effective_type = file_info['encryption_status']['encryption_type']
        if forced_type and forced_type != 'auto':
            effective_type = forced_type
        
        if not effective_type:
            effective_type = 'FERNET_ENCRYPTED'
            flash("No encryption type auto-detected. Attempting Fernet decryption.", "info")

        threading.Thread(
            target=attempt_decryption,
            args=(
                file_info['path'], 
                effective_type,
                pwd_to_try
            )
        ).start()
        
        return redirect(url_for('decryption_progress', filename=filename))

    content = render_template_string(DECRYPTION_PAGE_CONTENT, filename=filename, file_info=file_info)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/decryption_progress/<filename>')
def decryption_progress(filename):
    if filename not in uploaded_files_db:
        flash("File not found or not loaded.", 'error')
        return redirect(url_for('evidence_upload'))
    
    content = render_template_string(DECRYPTION_PROGRESS_CONTENT, filename=filename)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/forensic_analysis')
def forensic_analysis():
    hashing_in_progress = False
    if not uploaded_files_db:
        flash("Please upload or load an evidence file to begin analysis.", "warning")
        return redirect(url_for('evidence_upload'))

    first_file_details = next(iter(uploaded_files_db.values()))
    if not first_file_details.get('hashing_complete', False):
        hashing_in_progress = True
            
    content = render_template_string(FORENSIC_ANALYSIS_CONTENT, 
                                     uploaded_files=uploaded_files_db, 
                                     hashing_in_progress=hashing_in_progress)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/start_strings_analysis')
def start_strings_analysis():
    if not uploaded_files_db:
        return jsonify({"status": "error", "error": "No evidence file uploaded."})
    if strings_status.get("in_progress"):
        return jsonify({"status": "error", "error": "Strings analysis is already in progress."})
    
    filepath = get_active_evidence_path()
    if not filepath:
        return jsonify({"status": "error", "error": "Could not determine evidence file path."})

    threading.Thread(target=extract_strings_threaded, args=(filepath,)).start()
    return jsonify({"status": "started"})

@app.route('/auto_carving_setup', methods=['GET'])
def auto_carving_setup():
    if not uploaded_files_db:
        flash("Please upload or load an evidence file first.", "warning")
        return redirect(url_for('evidence_upload'))
    
    colors = ['text-sky-400', 'text-emerald-400', 'text-amber-400', 'text-rose-400', 'text-violet-400', 'text-teal-400', 'text-cyan-400', 'text-lime-400', 'text-pink-400', 'text-indigo-400']
    
    content = render_template_string(
        AUTO_CARVING_SETUP_CONTENT, 
        signatures=FILE_SIGNATURES, 
        colors=colors,
        form_action_url=url_for('run_auto_carving')
    )
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/auto_carving_process')
def auto_carving_process():
    if not uploaded_files_db:
        flash("No evidence file is currently loaded.", "warning")
        return redirect(url_for('evidence_upload'))
    content = render_template_string(AUTO_CARVING_PROCESS_CONTENT)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/recovered_files')
def recovered_files():
    if not uploaded_files_db:
        flash("No evidence file is currently loaded. Please start a new session.", "warning")
        return redirect(url_for('evidence_upload'))

    recovered_files_map = {}
    carved_dir = app.config['CARVED_FOLDER']
    
    try:
        pattern = re.compile(r"^(\d+)-([0-9A-Fa-f]{8})-(\d+)-(.+)$")
        for filename in os.listdir(carved_dir):
            match = pattern.match(filename)
            if match:
                file_id = int(match.group(1))
                offset_hex = match.group(2)
                size_bytes = int(match.group(3))
                
                file_info = {
                    "id": file_id,
                    "name": filename,
                    "offset": f"0x{offset_hex}",
                    "size_bytes": size_bytes
                }
                recovered_files_map[file_id] = file_info
    except FileNotFoundError:
        pass
    except Exception as e:
        flash(f"Error scanning recovery directory: {e}", "error")

    sorted_file_ids = sorted(recovered_files_map.keys())
    
    page = request.args.get('page', 1, type=int)
    PER_PAGE = 20
    total_files = len(sorted_file_ids)
    start_index = (page - 1) * PER_PAGE
    end_index = start_index + PER_PAGE
    
    ids_on_page = sorted_file_ids[start_index:end_index]
    files_on_page = [recovered_files_map.get(id) for id in ids_on_page]
    
    total_pages = max(1, (total_files + PER_PAGE - 1) // PER_PAGE)

    content = render_template_string(RECOVERED_FILES_CONTENT, 
                                     carved_files=files_on_page, 
                                     total_files=total_files,
                                     page=page, 
                                     total_pages=total_pages)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

# (The rest of your routes from manual_carving onwards remain the same...)
# ... PASTE THE REST OF YOUR ROUTES HERE, STARTING FROM @app.route('/manual_carving') ...

@app.route('/manual_carving')
def manual_carving():
    if not uploaded_files_db:
        flash("Please upload an evidence file first to use the manual carver.", "error")
        return redirect(url_for('evidence_upload'))
    content = render_template_string(MANUAL_CARVING_CONTENT)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/log_file_viewer', methods=['GET', 'POST'])
def log_file_viewer():
    if not uploaded_files_db:
        flash("Please upload an evidence file first to use the log viewer.", "error")
        return redirect(url_for('evidence_upload'))

    evidence_filename = list(uploaded_files_db.keys())[0]
    log_content = None

    if request.method == 'POST':
        filepath = get_active_evidence_path()
        if not filepath:
            flash("Could not determine evidence file path.", "error")
            return redirect(url_for('log_file_viewer'))

        log_ext = request.form.get('log_ext', '').lower()
        try:
            if not log_ext and '.' in evidence_filename:
                log_ext = '.' + evidence_filename.rsplit('.', 1)[1].lower()
            if log_ext in [".log", ".txt"] or log_ext.startswith('/var/log/'):
                log_content = parse_text_log(filepath)
            elif log_ext == ".csv":
                log_content = parse_csv_log(filepath)
            elif log_ext == ".json":
                log_content = parse_json_log(filepath)
            elif log_ext == ".xml":
                log_content = parse_xml_log(filepath)
            elif log_ext in [".evt", ".evtx"]:
                log_content = parse_evtx_log(filepath)
            else:
                log_content = f"[INFO] Format '{log_ext}' requires specialized handling. Displaying raw text.\n\n"
                log_content += parse_text_log(filepath)
        except Exception as e:
            log_content = f"[ERROR] Failed to parse file as '{log_ext}'. It may be part of a larger disk image.\n\nDetails: {e}"

    template_vars = {
        "title": "Log File Viewer",
        "description": "Analyze the loaded evidence file by parsing it as a specific log type.",
        "os_options": LOG_OS_OPTIONS,
        "log_content": log_content,
        "evidence_filename": evidence_filename
    }
    content = render_template_string(LOG_VIEWER_TEMPLATE, **template_vars)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/event_log_viewer', methods=['GET', 'POST'])
def event_log_viewer():
    if not uploaded_files_db:
        flash("Please upload an evidence file first to use the event log viewer.", "error")
        return redirect(url_for('evidence_upload'))

    evidence_filename = list(uploaded_files_db.keys())[0]
    log_content = None
    
    if request.method == 'POST':
        filepath = get_active_evidence_path()
        if not filepath:
            flash("Could not determine evidence file path.", "error")
            return redirect(url_for('event_log_viewer'))

        log_ext = request.form.get('log_ext', '').lower()
        try:
            if not log_ext and '.' in evidence_filename:
                log_ext = '.' + evidence_filename.rsplit('.', 1)[1].lower()
            if log_ext in [".evtx", ".evt"]:
                log_content = parse_evtx_log(filepath)
            elif log_ext.startswith("/var/log/") or log_ext in [".log", ".txt", ".asl"]:
                log_content = parse_text_log(filepath)
            else:
                log_content = f"[INFO] Format '{log_ext}' requires external tools. Displaying as plain text.\n\n"
                log_content += parse_text_log(filepath)
        except Exception as e:
            log_content = f"[ERROR] Failed to parse file as '{log_ext}'. It may be part of a larger disk image.\n\nDetails: {e}"

    template_vars = {
        "title": "Event Log Viewer",
        "description": "Analyze the loaded evidence file by parsing it as a specific event log type.",
        "os_options": EVENT_OS_OPTIONS,
        "log_content": log_content,
        "evidence_filename": evidence_filename
    }
    content = render_template_string(LOG_VIEWER_TEMPLATE, **template_vars)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/reporting', methods=['GET', 'POST'])
def reporting():
    if not uploaded_files_db:
        flash("Please upload an evidence file first to generate a report.", "error")
        return redirect(url_for('evidence_upload'))

    if request.method == 'POST':
        case_details = {
            "name": request.form.get('case_name', 'N/A'),
            "number": request.form.get('case_number', 'N/A'),
            "examiner": request.form.get('examiner_name', 'N/A')
        }
        report_format = request.form.get('report_format')
        now = datetime.datetime.now()
        safe_case_name = secure_filename(case_details['name'])

        try:
            with open('carved_results.json', 'r') as f: 
                report_carved_files = json.load(f)
        except: 
            report_carved_files = {}
        try:
            with open('deleted_results.json', 'r') as f: 
                report_deleted_files = json.load(f)
        except: 
            report_deleted_files = {}

        if report_format == 'html':
            for filename, info in report_carved_files.items():
                filepath = os.path.join(app.config['CARVED_FOLDER'], filename)
                info['thumbnail_uri'] = create_thumbnail_data_uri(filepath)
            
            report_html = render_template_string(
                REPORT_TEMPLATE, case_details=case_details, evidence_file=uploaded_files_db,
                carved_files=report_carved_files, deleted_files=report_deleted_files, now=now
            )
            response = make_response(report_html)
            response.headers['Content-Disposition'] = f"attachment; filename=Report_{safe_case_name}.html"
            return response

        elif report_format == 'pdf':
            if not HTML:
                flash("PDF generation requires the 'weasyprint' library. Please run: pip install weasyprint", "error")
                return redirect(url_for('reporting'))
            
            for filename, info in report_carved_files.items():
                filepath = os.path.join(app.config['CARVED_FOLDER'], filename)
                info['thumbnail_uri'] = create_thumbnail_data_uri(filepath)

            report_html = render_template_string(
                REPORT_TEMPLATE, case_details=case_details, evidence_file=uploaded_files_db,
                carved_files=report_carved_files, deleted_files=report_deleted_files, now=now
            )
            pdf_bytes = HTML(string=report_html).write_pdf()
            response = make_response(pdf_bytes)
            response.headers['Content-Disposition'] = f"attachment; filename=Report_{safe_case_name}.pdf"
            response.headers['Content-Type'] = 'application/pdf'
            return response
            
        elif report_format == 'docx':
            docx_buffer = generate_docx_report_data(case_details, uploaded_files_db, report_carved_files, report_deleted_files, now)
            if not docx_buffer:
                flash("DOCX generation requires the 'python-docx' library. Please run: pip install python-docx", "error")
                return redirect(url_for('reporting'))
            return send_file(docx_buffer, download_name=f'Report_{safe_case_name}.docx', as_attachment=True)
            
        elif report_format == 'csv':
            zip_buffer = generate_csv_zip_report_data(case_details, uploaded_files_db, report_carved_files, report_deleted_files)
            return send_file(zip_buffer, download_name=f'Report_{safe_case_name}_CSV.zip', as_attachment=True, mimetype='application/zip')

    content = render_template_string(REPORTING_PAGE_CONTENT, now=datetime.datetime.now())
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)

@app.route('/deleted_files_status_page')
def deleted_files_status_page():
    """Enhanced deleted files recovery status page with multiple scanning methods."""
    if not uploaded_files_db:
        flash("Please upload an evidence file first.", "warning")
        return redirect(url_for('evidence_upload'))
    
    # Ensure scan_methods exists in deleted_scan_status
    if 'scan_methods' not in deleted_scan_status:
        deleted_scan_status['scan_methods'] = {
            "directory_walk": 0,
            "inode_scan": 0,
            "file_slack": 0,
            "unallocated_space": 0,
            "recycle_bin": 0
        }
    
    # Get recovered files with enhanced info
    recovered_files = []
    recovery_dir = app.config['DELETED_RECOVERY_FOLDER']
    
    try:
        for i, filename in enumerate(os.listdir(recovery_dir), 1):
            filepath = os.path.join(recovery_dir, filename)
            if os.path.isfile(filepath):
                file_info = get_enhanced_file_info(filepath)
                recovery_method = determine_recovery_method(filename)
                
                recovered_files.append({
                    "id": i,
                    "name": filename,
                    "size_kb": file_info['size_kb'],
                    "file_type": file_info['file_type'],
                    "thumbnail": file_info['thumbnail'],
                    "recovery_method": recovery_method
                })
    except FileNotFoundError:
        pass  # Directory doesn't exist yet
    
    content = render_template_string(ENHANCED_DELETED_STATUS_TEMPLATE,
                                    deleted_scan_status=deleted_scan_status,
                                    recovered_files=recovered_files)
    return render_template_string(BASE_TEMPLATE, content=content, uploaded_files_db=uploaded_files_db)



@app.route('/decryption_status')
def decryption_status_endpoint():
    return jsonify(decryption_status)

@app.route('/hashing_status')
def hashing_status_endpoint():
    return jsonify(hashing_status)

@app.route('/strings_status')
def strings_status_endpoint():
    return jsonify(strings_status)

@app.route('/deleted_files')
def deleted_files():
    """Redirect to the status page where files are now displayed"""
    return redirect(url_for('deleted_files_status_page'))

@app.route('/deleted_scan_status')
def deleted_scan_status_endpoint():
    return jsonify({
        "in_progress": deleted_scan_status["in_progress"],
        "complete": deleted_scan_status["complete"], 
        "files_found": deleted_scan_status["files_found"],
        "message": deleted_scan_status["message"],
        "scan_methods": deleted_scan_status.get("scan_methods", {}),
        "files": deleted_files_db
    })

@app.route('/hex_view_carved/<filename>')
def hex_view_carved(filename):
    if not uploaded_files_db:
        flash("No evidence file is loaded.", "error")
        return redirect(url_for('evidence_upload'))

    s_filename = secure_filename(filename)
    filepath = os.path.join(app.config['CARVED_FOLDER'], s_filename)

    if not os.path.exists(filepath):
        flash(f"Carved file '{s_filename}' not found.", "error")
        return redirect(url_for('recovered_files'))

    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        hex_content = format_hex_view(content)
        content_html = render_template_string(HEX_VIEW_CARVED_FILE_CONTENT, filename=s_filename, hex_content=hex_content)
        return render_template_string(BASE_TEMPLATE, content=content_html, uploaded_files_db=uploaded_files_db)
    except Exception as e:
        flash(f"Error reading file '{s_filename}': {e}", "error")
        return redirect(url_for('recovered_files'))

@app.route('/download_carved_file/<filename>')
def download_carved_file(filename):
    return send_from_directory(app.config['CARVED_FOLDER'], secure_filename(filename), as_attachment=True)

@app.route('/serve_file_data/<type>/<path:filename>')
def serve_file_data(type, filename):
    s_filename = secure_filename(filename)
    if type == 'carved':
        return send_from_directory(app.config['CARVED_FOLDER'], s_filename)
    elif type == 'deleted_recovered':
        return send_from_directory(app.config['DELETED_RECOVERY_FOLDER'], s_filename)
    elif type == 'deleted':
        try:
            inode = int(filename)
            if not uploaded_files_db or inode not in deleted_files_db: 
                return "File not found", 404
            file_info = deleted_files_db[inode]
            filepath = get_active_evidence_path()
            img = pytsk3.Img_Info(filepath)
            fs = pytsk3.FS_Info(img, offset=file_info['fs_offset'])
            fs_file = fs.open_meta(inode=inode)
            content = fs_file.read_random(0, file_info['size'])
            mime_type, _ = mimetypes.guess_type(file_info['name'])
            mime_type = mime_type or 'application/octet-stream'
            return Response(content, mimetype=mime_type)
        except Exception as e: 
            return f"Error serving file data: {e}", 500
        
    return "Invalid file type", 400

@app.route('/view_carved_file/<filename>')
def view_carved_file(filename):
    s_filename = secure_filename(filename)
    filepath = os.path.join(app.config['CARVED_FOLDER'], s_filename)
    if not os.path.exists(filepath):
        return "File not found", 404
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read()
    except Exception as e:
        return f"Error reading file: {e}", 500
    
    data_url = url_for('serve_file_data', type='carved', filename=s_filename)
    return _generate_preview_response(content, s_filename, data_url, file_info={"name": s_filename})

@app.route('/view_deleted_file/<filename>')
def view_deleted_file(filename):
    """View deleted file with preview similar to carved files."""
    try:
        filepath = os.path.join(app.config['DELETED_RECOVERY_FOLDER'], filename)
        if not os.path.exists(filepath):
            return "File not found.", 404
        
        return preview_deleted_file(filepath, filename)
        
    except Exception as e:
        return f"Error viewing file: {str(e)}", 500
    
@app.route('/hex_view_fallback/<filename>')
def hex_view_fallback(filename):
    """Fallback hex view for files that can't be previewed normally"""
    s_filename = secure_filename(filename)
    filepath = os.path.join(app.config['CARVED_FOLDER'], s_filename)
    
    if not os.path.exists(filepath):
        return "File not found", 404
    
    try:
        with open(filepath, 'rb') as f:
            content = f.read(5000)  # Read first 5000 bytes for preview
        hex_content = format_hex_view(content)
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Hex View: {s_filename}</title>
            <style>
                body {{ background: #111827; color: white; font-family: monospace; padding: 20px; }}
                pre {{ background: #1f2937; padding: 20px; border-radius: 5px; }}
                .header {{ display: flex; justify-content: space-between; margin-bottom: 20px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h2>Hex View: {s_filename}</h2>
                <a href="{{ url_for('recovered_files') }}">Back</a>
            </div>
            <pre>{hex_content}</pre>
            <p>Showing first {len(content)} bytes of file</p>
        </body>
        </html>
        """
    except Exception as e:
        return f"Error reading file: {e}", 500
    
@app.route('/hex_view_deleted/<filename>')
def hex_view_deleted(filename):
    if not uploaded_files_db:
        flash("No evidence file is loaded.", "error")
        return redirect(url_for('evidence_upload'))

    s_filename = secure_filename(filename)
    filepath = os.path.join(app.config['DELETED_RECOVERY_FOLDER'], s_filename)

    if not os.path.exists(filepath):
        flash(f"Recovered file '{s_filename}' not found.", "error")
        return redirect(url_for('deleted_files'))

    try:
        with open(filepath, 'rb') as f:
            content = f.read()
        hex_content = format_hex_view(content)
        content_html = render_template_string(HEX_VIEW_CARVED_FILE_CONTENT, filename=s_filename, hex_content=hex_content)
        return render_template_string(BASE_TEMPLATE, content=content_html, uploaded_files_db=uploaded_files_db)
    except Exception as e:
        flash(f"Error reading file '{s_filename}': {e}", "error")
        return redirect(url_for('deleted_files'))

@app.route('/download_deleted_file/<filename>')
def download_deleted_file(filename):
    return send_from_directory(app.config['DELETED_RECOVERY_FOLDER'], secure_filename(filename), as_attachment=True)

@app.route('/download_zip', methods=['POST'])
def download_zip():
    if not uploaded_files_db:
        flash("No evidence file loaded.", "error")
        return redirect(url_for('evidence_upload'))

    selected_files = request.form.getlist('selected_files')
    file_type = request.form.get('file_type')

    if not selected_files:
        flash("No files were selected for download.", "warning")
        return redirect(url_for('deleted_files' if file_type in ['deleted', 'deleted_recovered'] else 'recovered_files'))

    memory_file = io.BytesIO()
    zip_filename = f"{file_type}_files_{datetime.datetime.now():%Y%m%d%H%M%S}.zip"

    try:
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            if file_type == 'carved':
                for filename in selected_files:
                    filepath = os.path.join(app.config['CARVED_FOLDER'], secure_filename(filename))
                    if os.path.exists(filepath):
                        zf.write(filepath, arcname=secure_filename(filename))
            
            elif file_type == 'deleted_recovered':
                for filename in selected_files:
                    filepath = os.path.join(app.config['DELETED_RECOVERY_FOLDER'], secure_filename(filename))
                    if os.path.exists(filepath):
                        zf.write(filepath, arcname=secure_filename(filename))
        
        memory_file.seek(0)
        return send_file(memory_file, download_name=zip_filename, as_attachment=True, mimetype='application/zip')
    except Exception as e:
        flash(f"Error creating ZIP file: {e}", "error")
        return redirect(url_for('deleted_files' if file_type in ['deleted', 'deleted_recovered'] else 'recovered_files'))

@app.route('/find_in_file', methods=['POST'])
def find_in_file():
    filepath = get_active_evidence_path()
    if not filepath:
        return jsonify({"offset": -1, "error": "No file uploaded"})
    
    term = request.form.get('term')
    search_type = request.form.get('type')
    start_offset = request.form.get('start_offset', 0, type=int)

    try:
        search_bytes = bytes.fromhex(term.replace(" ", "")) if search_type == 'hex' else term.encode()
    except ValueError:
        return jsonify({"offset": -1, "error": "Invalid Hex sequence."})
    
    try:
        with open(filepath, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                found_pos = mm.find(search_bytes, start_offset)
                return jsonify({"offset": found_pos})
    except Exception as e:
        return jsonify({"offset": -1, "error": str(e)})

@app.route('/run_auto_carving', methods=['POST'])
def run_auto_carving():
    """
    Handles the file carving process based on user-selected file types.
    """
    global carving_status, carved_files_db, sorted_carved_keys

    image_path = get_active_evidence_path()
    if not image_path:
        flash('Error: Evidence file path is missing or invalid. Please re-upload the file.', 'error')
        return redirect(url_for('evidence_upload'))

    selected_types = request.form.getlist('file_types')
    if not selected_types:
        flash('Error: Please select at least one file type to carve.', 'error')
        return redirect(url_for('auto_carving_setup'))

    threading.Thread(target=simple_file_carver, args=(image_path, selected_types)).start()
    return redirect(url_for('auto_carving_process'))

@app.route('/find_block', methods=['POST'])
def find_block():
    filepath = get_active_evidence_path()
    if not filepath:
        return jsonify({"status": "error", "message": "No file uploaded"})
    
    header_term = request.form.get('header_term')
    footer_term = request.form.get('footer_term')
    search_type = request.form.get('type')

    try:
        header_bytes = bytes.fromhex(header_term.replace(" ", "")) if search_type == 'hex' else header_term.encode()
        footer_bytes = bytes.fromhex(footer_term.replace(" ", "")) if search_type == 'hex' else footer_term.encode()
    except ValueError:
        return jsonify({"status": "error", "message": "Invalid Hex sequence."})
    
    try:
        with open(filepath, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                header_pos = mm.find(header_bytes, 0)
                if header_pos != -1:
                    footer_pos = mm.find(footer_bytes, header_pos + len(header_bytes))
                    if footer_pos != -1:
                        block_len = (footer_pos + len(footer_bytes)) - header_pos
                        return jsonify({"status": "success", "start_offset": header_pos, "length": block_len})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

    return jsonify({"status": "not_found"})

@app.route('/clear_session')
def clear_session():
    """Manual session clearing endpoint"""
    _clear_all_session_data()
    flash("Session cleared successfully. All recovered files and analysis data have been removed.", "success")
    return redirect(url_for('evidence_upload'))

@app.route('/perform_manual_carve', methods=['POST'])
def perform_manual_carve():
    global sorted_carved_keys
    filepath = get_active_evidence_path()
    if not filepath:
        flash("No evidence file is loaded.", "error")
        return redirect(url_for('manual_carving'))

    try:
        start_offset = int(request.form.get('start_offset', 0))
        length = int(request.form.get('length', 0))
    except (ValueError, TypeError):
        flash("Invalid offset or length. Please enter numbers only.", "error")
        return redirect(url_for('manual_carving'))

    if length <= 0:
        flash("Length must be a positive number.", "error")
        return redirect(url_for('manual_carving'))

    file_size = os.path.getsize(filepath)

    if start_offset >= file_size:
        flash("Start offset is beyond the end of the file.", "error")
        return redirect(url_for('manual_carving'))

    with open(filepath, 'rb') as f:
        f.seek(start_offset)
        data_to_carve = f.read(min(length, file_size - start_offset))

    carved_filename = f"manual_carve_{start_offset}_{length}.dat"
    save_path = os.path.join(app.config['CARVED_FOLDER'], carved_filename)
    with open(save_path, 'wb') as out_f:
        out_f.write(data_to_carve)
    
    max_id = max([f['id'] for f in carved_files_db.values()] or [0])
    file_id = max_id + 1
    carved_files_db[carved_filename] = {"id": file_id, "name": carved_filename, "offset": f"0x{start_offset:08X}", "size_kb": f"{len(data_to_carve)/1024:.2f} KB"}
    sorted_carved_keys.append(carved_filename)

    flash(f"Successfully carved {len(data_to_carve)} bytes to '{carved_filename}'.", "success")
    return redirect(url_for('recovered_files'))

if __name__ == '__main__':
    app.run(debug=True)