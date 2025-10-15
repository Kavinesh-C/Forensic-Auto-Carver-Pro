# Forensic Carver Pro

![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)

![Framework](https://img.shields.io/badge/Framework-Flask-green.svg)

![License](https://img.shields.io/badge/License-MIT-yellow.svg)

Forensic Carver Pro is a powerful, web-based digital evidence analysis and file carving tool built with Python and Flask. It provides a user-friendly interface for uploading disk images, performing high-level forensic analysis, automatically carving files based on signatures, and recovering deleted file entries from a file system.

[cite\_start]The application is designed for performance, using a robust WSGI loader that automatically applies runtime performance patches for CPU-intensive tasks[cite: 17, 19]. It also features a persistent PostgreSQL database for evidence management and a streamlined development environment with auto-reloading capabilities.

-----

## 📸 Screenshots

A quick look at the Forensic Carver Pro interface.

The intuitive Evidence Upload dashboard, where you can drag and drop disk images to begin your analysis.
<img width="1891" height="841" alt="image" src="https://github.com/user-attachments/assets/969e7a29-4449-4088-918d-93f4923f37e4" />

The Auto Carving interface, allowing you to select specific file types for high-speed, signature-based recovery.
<img width="1883" height="849" alt="image" src="https://github.com/user-attachments/assets/0b185e34-5d9a-4e49-a121-a9425d4a833d" />

The Deleted File Recovery module in action, scanning a filesystem for deleted entries and displaying real-time status.
<img width="1900" height="859" alt="image" src="https://github.com/user-attachments/assets/16a507f7-54c7-4143-b8cf-a3fd4cc05cc0" />

Easily generate comprehensive case reports in various formats (HTML, PDF, etc.) from the Reporting screen.
<img width="1881" height="830" alt="image" src="https://github.com/user-attachments/assets/dd4e3651-7e80-46c2-b869-267b4b677e7b" />

The powerful Manual Carving tool, featuring a built-in hex viewer for precise data extraction by offset or signature.
<img width="1881" height="835" alt="image" src="https://github.com/user-attachments/assets/b7c15d65-7095-491f-a443-9cd962293ca1" />

-----

## ✨ Key Features

  * **Performance Optimized**: Automatically applies runtime "monkey patches" via `fast_patch.py` to accelerate heavy operations like hashing, string extraction, and file carving without altering the core application logic.
  * **Persistent Evidence Database**: Uses PostgreSQL to store and manage evidence file metadata, allowing you to load past cases instantly.
  * **Automatic Storage Management**: Automatically manages a configurable storage limit (default 50GB), removing the oldest evidence files to make space for new ones.
  * **AJAX-Powered File Uploads**: Supports large disk images (`.dd`, `.e01`, `.img`, `.raw`, etc.) with a real-time progress bar showing speed, ETA, and percentage.
  * **High-Accuracy Automated File Carving**:
      * Signature-based carving for a wide variety of file types (images, documents, archives, media).
      * Strictly prevents carving empty and duplicate files using hash-based deduplication for more reliable results.
  * **Advanced Deleted File Recovery**: Scans file system metadata using `pytsk3` to recover deleted file entries, with improved validation and deduplication to reduce noise.
  * **File Encryption & Decryption**:
      * Built-in tool to encrypt files using a secure, password-based Fernet (AES) implementation.
      * Detects encrypted files and volumes (BitLocker, OpenSSL AES, etc.) and provides a module to attempt decryption via password or dictionary attack.
  * **Manual Carving & Hex Viewer**: Built-in hex viewer to manually inspect evidence files, search for text/hex values, and carve data blocks by offset and length.
  * **Log & Event Viewer**: Parse and view logs from Windows, Linux, or macOS directly in the interface.
  * **Comprehensive Reporting**: Generate detailed forensic reports in **HTML, PDF, DOCX, and CSV** formats summarizing all findings.
  * [cite\_start]**Streamlined Development Environment**: Includes a batch script (`start_dev_server.bat`) and a file watcher (`watcher.py`) for automatic server reloading when code changes are detected[cite: 25, 27].

-----

## 🛠️ Technology Stack

  * **Backend**: Python, Flask
  * **Database**: PostgreSQL
  * **Frontend**: HTML, Tailwind CSS
  * **Core Libraries**:
      * `pytsk3`: File system analysis and deleted file recovery.
      * `Flask-SQLAlchemy` & `psycopg2-binary`: Database ORM and PostgreSQL connection.
      * `python-magic-bin`: Accurate file type identification.
      * `cryptography`: Encryption and decryption utilities.
      * `Pillow`: Image processing for thumbnails and validation.
      * `watchdog`: For automatic server reloading in development.
  * **Deployment**: Apache HTTP Server with `mod_wsgi` (recommended for production).

-----

## 🚀 Getting Started

### Prerequisites

  * Python 3.9 or higher
  * `pip` (Python package installer)
  * PostgreSQL Server
  * Apache HTTP Server 2.4 (for production deployment on Windows)

### Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Kavinesh-C/Forensic-Auto-Carver-Pro.git
    cd Forensic-Carver-Pro
    ```

2.  **Create and activate a virtual environment:**

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

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure the Database:**

      * Create a new database in PostgreSQL (e.g., `Autoamted_File_carving_System`).
      * Open `app.py` and edit the `SQLALCHEMY_DATABASE_URI` line with your PostgreSQL username, password, and database name.
        *Example: `postgresql://<user>:<password>@<host>:<port>/<dbname>`*
        ```python
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:kavin@localhost:5432/Autoamted_File_carving_System'
        ```

5.  **Initialize the Database Tables:**

      * Run the `create_tables.py` script once to create the necessary tables in your database.
        ```bash
        python create_tables.py
        ```

-----

## ▶️ How to Run

### 1\. Recommended Development Environment (Windows)

This method provides the best development experience, including performance patches and automatic reloading on code changes.

1.  **Run the development server script:**
    ```bash
    start_dev_server.bat
    ```
    This script will:
      * [cite\_start]Start the Apache server in a new window[cite: 26].
      * [cite\_start]Start the `watcher.py` script in another window to monitor for `.py` file changes[cite: 27].
2.  Open your browser and navigate to **http://localhost:8080** (or the port you configured in Apache).

When you save changes to any `.py` file, the watcher will automatically "touch" the `run.wsgi` file, causing Apache to gracefully reload the application with your changes.

### 2\. Basic Flask Development Server (For Quick Testing)

This method is simpler but **does not** apply the performance patches from `fast_patch.py`.

1.  Run the Flask app directly:
    ```bash
    python app.py
    ```
2.  Open your browser at **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.

### 3\. Production Deployment (Apache on Windows)

This setup is for a production environment. The included `run.wsgi` file is designed to be robust and will automatically apply the performance patches from `fast_patch.py`.

#### Step 1: Configure Apache with `mod_wsgi`

1.  From your activated virtual environment, run:
    ```bash
    mod_wsgi-express module-config
    ```
2.  Copy the three output lines and paste them into your Apache configuration file (`C:\Apache24\conf\httpd.conf`). It will look similar to this:
    ```apache
    LoadFile "c:/path/to/venv/scripts/python39.dll"
    LoadModule wsgi_module "c:/path/to/venv/lib/site-packages/mod_wsgi/server/mod_wsgi.cp39-win_amd64.pyd"
    WSGIPythonHome "c:/path/to/venv"
    ```

#### Step 2: Configure Apache Virtual Host

1.  Add the following `VirtualHost` block to the end of your `httpd.conf` file. **Make sure to update the file paths to match your project's location.**
    ```apache
    Listen 8080
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

#### Step 3: Restart Apache

1.  Open a command prompt as an Administrator and restart the Apache service:
    ```bash
    httpd -k restart
    ```
2.  The application will now be available at **http://localhost:8080**.

-----

## � Migration: Prefix existing artifact files with session IDs

If you've been running the app before session-prefixing was added, you can migrate existing artifact files on disk so their filenames include the session prefix (recommended for consistency).

1. Dry-run to see what would change (no files moved):

```powershell
# from project root
curl "http://localhost:5000/migrate_prefix_artifacts?dry=1" | ConvertFrom-Json
```

2. If the dry-run output looks good, run the migration (this WILL move files and update DB/JSON records):

```powershell
curl "http://localhost:5000/migrate_prefix_artifacts" | ConvertFrom-Json
```

Notes:
* The endpoint performs a best-effort attempt to associate artifacts with their sessions. If an artifact cannot be associated with a session, it will be reported in the `errors` array.
* Backup your repository (or at least `carved_files/`, `decrypted_files/`, `encrypted_files/` and your database) before running the migration.

## 🧭 Session UI

* The sidebar shows the currently active session. Click the session name to open a session detail page that lists artifacts from that session.
* Use the "Quick End Session" button in the sidebar to end the current session immediately.


## 📂 Project structure (current)

The tree below reflects the repository contents as of 2025-10-15. It lists files and directories found in the workspace and can be used as a quick reference when navigating the project.

```
Forensic Auto Carver/
├── .github/
│   └── workflows/
│       └── python-package.yml
├── .gitignore
├── README.md
├── RUNNING.md
├── SECURITY.md
├── requirements.txt
├── start_dev_server.bat
├── run.wsgi
├── app.py
├── fast_patch.py
├── watcher.py
├── db_connections.json
├── common_passwords.txt
├── audit.log
├── app_loaded.log
├── run_imported_app_file.log
├── fac_data.db
├── test_target.db
├── logs/
│   ├── access.log
│   ├── app_loaded.log
│   ├── app_out.log
│   ├── app_startup_error.log
│   ├── error.log
│   ├── run_imported_app_file.log
│   ├── wsgi_loaded.log
+│   ├── log_viewer_SuspectData.dd_20251004_191157.log
│   └── event_log_viewer_SuspectData.dd_20251004_191203.log
├── scripts/
│   ├── backfill_status_changed_at.py
│   ├── create_pg_files_table.py
│   └── test_create_folders.py
├── static/
│   ├── css/
│   │   ├── explorer.css
│   │   └── local_tailwind_fallback.css
│   └── js/
│       ├── create_image_modal.js
│       └── explorer.js
├── templates/
│   └── explorer.html
├── tests/
│   ├── test_reporting_save.py
│   ├── test_load_to_upload.py
│   ├── test_image_backends.py
│   ├── test_fs_explorer.py
│   ├── test_file_status.py
│   └── test_explorer_ui.py
├── scripts/__pycache__/
├── tests/__pycache__/
├── static/css/__pycache__/
├── static/js/__pycache__/
├── templates/__pycache__/
├── Carved Files/
├── Decrypted Files/
├── Deleted Files/
├── Encrypted Files/
├── Session Files/
├── Upload Files/
├── uploads/
└── .github/
```

### Modifications

- Updated project structure to match the current workspace contents (2025-10-15).
- Included log files, database files, and script names discovered in the repository root and subfolders.

If you'd like, I can expand this into a more detailed manifest (file sizes, last modified timestamps, or a machine-readable JSON/YAML listing). 

-----

## 📦 requirements.txt

```text
Flask
Flask-SQLAlchemy
psycopg2-binary
pytsk3
Pillow
python-magic-bin
cryptography
weasyprint
python-docx
openpyxl
python-pptx
rarfile
py7zr
python-evtx
mod_wsgi
watchdog
```

-----

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

-----
