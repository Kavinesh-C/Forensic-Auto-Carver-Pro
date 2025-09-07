# Forensic Carver Pro

Forensic Carver Pro is a web-based digital evidence analysis and file carving tool built with Python and Flask. It provides a user-friendly interface for uploading disk images, performing forensic analysis, automatically carving files based on signatures, and recovering deleted file entries.

## How to Run

1.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

2.  **Install dependencies:**
    *(You should create a `requirements.txt` file for this)*
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the application:**
    ```bash
    python Setup.py
    ```
4. Open your web browser and go to `http://127.0.0.1:5000`.