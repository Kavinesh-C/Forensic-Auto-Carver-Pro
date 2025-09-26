# Forensic Carver Pro


![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)
![Framework](https://img.shields.io/badge/Framework-Flask-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Forensic Carver Pro is a powerful, web-based digital evidence analysis and file carving tool built with Python and Flask. It provides a user-friendly interface for uploading disk images, performing high-level forensic analysis, automatically carving files based on signatures, and recovering deleted file entries from a file system.

---

## 📸 Screenshots

A quick look at the Forensic Carver Pro interface.

The intuitive Evidence Upload dashboard, where you can drag and drop disk images to begin your analysis.
<img width="1907" height="866" alt="Screenshot 2025-09-23 083950" src="https://github.com/user-attachments/assets/db3a42f8-5a98-4ad8-913f-17b436ae4687" />

The Auto Carving interface, allowing you to select specific file types for high-speed, signature-based recovery.
<img width="1896" height="852" alt="Screenshot 2025-09-23 103332" src="https://github.com/user-attachments/assets/a49f5ae1-d8a6-419b-b70b-68443ac5388e" />

The Deleted File Recovery module in action, scanning a filesystem for deleted entries and displaying real-time status.
<img width="1889" height="847" alt="Screenshot 2025-09-23 103529" src="https://github.com/user-attachments/assets/4c7606f6-d491-4313-8a4b-169cd6aa4a61" />

Easily generate comprehensive case reports in various formats (HTML, PDF, etc.) from the Reporting screen.
<img width="1906" height="841" alt="Screenshot 2025-09-23 103545" src="https://github.com/user-attachments/assets/4ca4efe0-31d8-42ac-b0ad-ab5c8042dc78" />

The powerful Manual Carving tool, featuring a built-in hex viewer for precise data extraction by offset or signature.
<img width="1888" height="861" alt="Screenshot 2025-09-23 103556" src="https://github.com/user-attachments/assets/f9f0eb2c-a82e-4328-9a83-eaef45819cd6" />

---

## ✨ Key Features

* **Persistent Evidence Database**: Uses PostgreSQL to store and manage evidence file metadata, allowing you to load past cases instantly.
* **Automatic Storage Management**: Automatically manages a 20GB storage limit, removing the oldest evidence files to make space for new ones.
* **Performance Optimized**: Heavy operations like hashing, string extraction, and carving are automatically monkey-patched with faster, optimized versions via fast_patch.py when running in production.
* * **Evidence File Upload**: Supports large disk images (`.dd`, `.e01`, `.img`, `.raw`, etc.) with a real-time progress bar for uploads.
* **Forensic Analysis**: Detects partition tables (MBR, GPT), file systems (NTFS, FAT32, EXT), and calculates full-file hashes (MD5, SHA-1, SHA-256).
* **High-Accuracy Automated File Carving**:
  * Signature-based carving for a wide variety of file types (images, documents, archives, media).
  * Optimized for speed on large files like MP4s and MP3s using intelligent boundary detection.
  * Strictly prevents carving empty and duplicate files for reliable results.
* **Deleted File Recovery**: Scans file system metadata using `pytsk3` to recover deleted file entries.
* **Manual Carving & Hex Viewer**: Built-in hex viewer to manually inspect evidence files, search for text/hex values, and carve by offset and length.
* **Log & Event Viewer**: Parse and view logs from Windows, Linux, or macOS directly in the interface.
* **Comprehensive Reporting**: Generate detailed reports in **HTML, PDF, DOCX, CSV** formats summarizing all findings.
* **Encryption / Decryption Detection**: Detects encrypted files and volumes (BitLocker, OpenSSL AES, etc.) and attempts decryption.

---

## 🛠️ Technology Stack

* **Backend**: Python, Flask
* **Database**: PostgreSQL 
* **Frontend**: HTML, Tailwind CSS  
* **Core Libraries**:
  * `pytsk3`: File system analysis and deleted file recovery
  * `Flask-SQLAlchemy & psycopg2-binary`: Database ORM and connection
  * `Pillow`: Image processing and validation
  * `cryptography`: Decryption utility
  * `python-magic-bin`: Accurate file type identification
  * `watchdog`: For automatic server reloading in development
* **Deployment**: Apache HTTP Server with `mod_wsgi`

---

## 🚀 Getting Started

### Prerequisites

* Python 3.9 or higher
* `pip` (Python package installer)
* Apache HTTP Server 2.4 (for production deployment on Windows)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/Forensic-Carver-Pro.git
   cd Forensic-Carver-Pro
``
2. **Create and activate a virtual environment:**

   * On Windows:

     ```bash
     python -m venv venv
     venv\Scripts\activate
     ```
   * On macOS/Linux:

     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```
4. **Configure the Database:**

    Create a new database in PostgreSQL (e.g., Autoamted_File_carving_System).

    Open app.py and edit the SQLALCHEMY_DATABASE_URI line with your PostgreSQL username, password, and database name:Example: postgresql://<user>:<password>@<host>:<port>/<dbname>

    ```bash
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kavin@localhost:5432/Autoamted_File_carving_System'
    ```
5.Initialize the Database Tables:

   Run the create_tables.py script once to create the necessary tables in your database.
    
    ```bash
    
    python create_tables.py
    
    ```
---

## ▶️ How to Run

### 1. Development Server (For Quick Testing)

1. Ensure the `if __name__ == '__main__':` block in `app.py` is set as:

   ```python
   if __name__ == '__main__':
       app.run(debug=True, host='0.0.0.0', port=5000)
   ```
2. Run the app:

   ```bash
   python app.py
   ```
3. Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

### 2. Production Deployment (Apache on Windows)

#### Step 1: Configure Apache with `mod_wsgi`

Run:

```bash
mod_wsgi-express module-config
```

Copy the three output lines into `C:\Apache24\conf\httpd.conf`, e.g.:

```apache
LoadFile "c:/python39/python39.dll"
LoadModule wsgi_module "c:/python39/lib/site-packages/mod_wsgi/server/mod_wsgi.cp39-win_amd64.pyd"
WSGIPythonHome "c:/python39"
```

#### Step 2: Create WSGI Entry Point

In your project folder, create **`run.wsgi`**:

```python
import sys
import os

project_home = os.path.dirname(os.path.abspath(__file__))
if project_home not in sys.path:
    sys.path.insert(0, project_home)

from app import app as application
```

#### Step 3: Configure Apache Virtual Host

At the end of `httpd.conf`:

```apache
<VirtualHost *:8080>
    ServerName forensic-carver.local

    WSGIScriptAlias / "D:/Forensic Auto Carver/run.wsgi"
    WSGIApplicationGroup %{GLOBAL}

    <Directory "D:/Forensic Auto Carver">
        Require all granted
    </Directory>

    ErrorLog "D:/Forensic Auto Carver/logs/error.log"
    CustomLog "D:/Forensic Auto Carver/logs/access.log" common
</VirtualHost>
```

#### Step 4: Create Logs Folder

In `D:\Forensic Auto Carver`, create a folder named **`logs`**.

#### Step 5: Restart Apache

```bash
httpd -k restart
```

Visit: **[http://localhost:8080](http://localhost:8080)**

---

## 📂 Project Structure

```
Forensic-Carver-Pro/
├── venv/
├── carved_files/
├── decrypted_files/
├── deleted_files/
├── encrypted_files/
├── logs/
├── uploads/
├── app.py                  # Main Flask application
├── fast_patch.py           # Performance optimization patches
├── create_tables.py        # Database initialization script
├── watcher.py              # File watcher for auto-reload
├── run.wsgi                # WSGI entry point for Apache
├── start_dev_server.bat    # Script to start the development environment
├── requirements.txt
└── README.md

```
---
## 📦 requirements.txt

For quick setup, here’s the `requirements.txt` you can copy into your project:

```text
Flask
pytsk3
Pillow
python-magic-bin
cryptography
weasyprint
python-docx
mod_wsgi
Flask-SQLAlchemy
psycopg2-binary
watchdog
```

```

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---