# Digital Clutter Detector backend

The Flask app serves the frontend and JSON API from one local origin. It uses Python's standard-library SQLite, file, and hashing modules; Flask is the only external dependency.

## Install and run (Windows PowerShell)

```powershell
cd backend
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Flask creates `digital_clutter.db`, the default scan directory, and `quarantine/` on startup.

## Scan access and safety

By default, the only permitted scan directory is `backend/scan_roots/`. Put or copy files you want to scan there, or configure one or more trusted directories before starting the server:

```powershell
$env:DIGICLUTTER_SCAN_ROOTS = "C:\Users\you\Documents;D:\Shared"
python app.py
```

The list separator is the platform's path separator (`;` on Windows, `:` on macOS/Linux). Scans outside configured directories are rejected. Directory traversal skips symlinks, and quarantine is excluded from scans. Files are hashed in chunks only when another file of the same size is present; unique-size files have a null hash because they cannot be duplicates in that scan.

Cleanup only accepts database IDs for verified, active duplicate copies. One original per matching-hash group is protected, and its content is checked again before a move. Copies are moved—not deleted—to `backend/quarantine/` under collision-resistant names. Restore checks the hash, permitted original root, folder access, and that the destination does not already exist. SQLite stores file metadata and paths, never file contents.

## API

- `GET /api/health`
- `GET /api/dashboard`
- `POST /api/scan` — JSON: `{ "path": "C:\\path\\inside\\an\\allowed\\root" }`
- `GET /api/duplicates` — optionally `?scan_id=1`
- `GET /api/history`
- `GET /api/quarantine`
- `POST /api/cleanup` — JSON: `{ "file_ids": [2, 3] }`
- `POST /api/restore` — JSON: `{ "quarantine_ids": [1] }`

For scan, cleanup, and restore requests, errors are returned as JSON. Cleanup and restore may return a successful subset alongside a `failed` array when an operation could not safely complete.

## Run the tests

From the project root, after installing the backend dependencies:

```powershell
python -m unittest backend.test_backend -v
```

The tests use temporary databases and folders. Permission-denied cases are simulated so they can be tested consistently on Windows.
