"""Flask API and local frontend server for Digital Clutter Detector."""

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, current_app, g, jsonify, request, send_from_directory

if __package__:
    from .cleanup import quarantine_files, restore_files
    from .database import connect, initialize_database
    from .duplicate_detector import duplicate_groups, duplicate_totals, scan_file_records
    from .scanner import ScanPathError, scan_folder, validate_scan_folder
else:
    from cleanup import quarantine_files, restore_files
    from database import connect, initialize_database
    from duplicate_detector import duplicate_groups, duplicate_totals, scan_file_records
    from scanner import ScanPathError, scan_folder, validate_scan_folder


BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"


def _configured_scan_roots():
    configured = os.environ.get("DIGICLUTTER_SCAN_ROOTS", "").strip()
    if configured:
        roots = [Path(item).expanduser() for item in configured.split(os.pathsep) if item.strip()]
    else:
        roots = [BACKEND_DIR / "scan_roots"]
    for root in roots:
        root.mkdir(parents=True, exist_ok=True)
    return [str(root.resolve()) for root in roots]


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        DATABASE_PATH=str(BACKEND_DIR / "digital_clutter.db"),
        QUARANTINE_DIR=str(BACKEND_DIR / "quarantine"),
        SCAN_ROOTS=_configured_scan_roots(),
        JSON_SORT_KEYS=False,
    )
    if test_config:
        app.config.update(test_config)
    Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["QUARANTINE_DIR"]).mkdir(parents=True, exist_ok=True)
    for root in app.config["SCAN_ROOTS"]:
        Path(root).mkdir(parents=True, exist_ok=True)
    initialize_database(app.config["DATABASE_PATH"])

    @app.teardown_appcontext
    def close_database(_error=None):
        connection = g.pop("database", None)
        if connection is not None:
            connection.close()

    def database():
        if "database" not in g:
            g.database = connect(current_app.config["DATABASE_PATH"])
        return g.database

    def error_response(message, status):
        return jsonify({"error": message}), status

    def latest_scan(connection):
        return connection.execute(
            "SELECT * FROM scan_history WHERE status = 'completed' ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def serialize_file(file, duplicate=False):
        return {
            "id": file["id"],
            "scan_id": file["scan_id"],
            "name": file["name"],
            "path": file["original_path"],
            "size": file["size"],
            "extension": file["extension"],
            "category": _category(file["extension"]),
            "sha256": file["sha256"],
            "modifiedAt": file["modified_at"],
            "scannedAt": file["scanned_at"],
            "protected": bool(file["is_protected"]),
            "duplicate": bool(duplicate),
            "status": file["status"],
        }

    @app.get("/")
    def frontend_index():
        return send_from_directory(FRONTEND_DIR, "index.html")

    @app.get("/css/<path:filename>")
    def frontend_css(filename):
        return send_from_directory(FRONTEND_DIR / "css", filename)

    @app.get("/js/<path:filename>")
    def frontend_javascript(filename):
        return send_from_directory(FRONTEND_DIR / "js", filename)

    @app.get("/api/health")
    def health():
        try:
            database().execute("SELECT 1").fetchone()
        except sqlite3.Error:
            current_app.logger.exception("Database health check failed.")
            return jsonify({"status": "error", "database": "unavailable"}), 503
        return jsonify({"status": "ok", "database": "ok"})

    @app.get("/api/dashboard")
    def dashboard():
        connection = database()
        scan = latest_scan(connection)
        if scan is None:
            return jsonify(
                {
                    "total_files_scanned": 0,
                    "duplicate_files_found": 0,
                    "duplicate_groups": 0,
                    "recoverable_bytes": 0,
                    "total_size_bytes": 0,
                    "latest_scan": None,
                }
            )
        groups = duplicate_groups(connection, scan["id"])
        totals = duplicate_totals(groups)
        total_size = connection.execute(
            "SELECT COALESCE(SUM(size), 0) FROM scanned_files WHERE scan_id = ?",
            (scan["id"],),
        ).fetchone()[0]
        return jsonify(
            {
                "total_files_scanned": scan["files_scanned"],
                "duplicate_files_found": totals["duplicates_found"],
                "duplicate_groups": totals["duplicate_groups"],
                "recoverable_bytes": totals["recoverable_bytes"],
                "total_size_bytes": total_size,
                "latest_scan": {
                    "id": scan["id"],
                    "folder": scan["folder_path"],
                    "date": scan["completed_at"],
                },
            }
        )

    @app.post("/api/scan")
    def start_scan():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return error_response("A JSON request body is required.", 400)
        folder_path = body.get("path")
        if not isinstance(folder_path, str) or not folder_path.strip():
            return error_response("The 'path' field must be a non-empty string.", 400)

        started_at = datetime.now(timezone.utc).isoformat()
        connection = database()
        scan_id = None
        try:
            # Validate before creating history so invalid paths do not leave failed scans.
            folder = validate_scan_folder(folder_path, current_app.config["SCAN_ROOTS"])
            with connection:
                cursor = connection.execute(
                    """
                    INSERT INTO scan_history (folder_path, started_at, status)
                    VALUES (?, ?, 'scanning')
                    """,
                    (str(folder), started_at),
                )
                scan_id = cursor.lastrowid
            result = scan_folder(
                str(folder),
                current_app.config["SCAN_ROOTS"],
                excluded_directories=(current_app.config["QUARANTINE_DIR"],),
            )
        except ScanPathError as error:
            if scan_id is not None:
                _mark_scan_failed(connection, scan_id, str(error))
            status = 403 if "outside the configured scan directories" in str(error) else 400
            return error_response(str(error), status)
        except OSError as error:
            current_app.logger.exception("Could not scan folder %s.", folder_path)
            if scan_id is not None:
                _mark_scan_failed(connection, scan_id, str(error))
            return error_response("The folder could not be scanned.", 500)

        files = result["files"]
        hash_groups = {}
        for item in files:
            if item["sha256"]:
                hash_groups.setdefault(item["sha256"], []).append(item)
        for matches in hash_groups.values():
            if len(matches) > 1:
                protected = min(
                    matches,
                    key=lambda item: (item["modified_at"], item["original_path"]),
                )
                protected["is_protected"] = True
            else:
                matches[0]["is_protected"] = False

        with connection:
            for item in files:
                item.setdefault("is_protected", False)
                connection.execute(
                    """
                    INSERT INTO scanned_files
                        (scan_id, name, original_path, size, extension, sha256,
                         modified_at, scanned_at, is_protected, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active')
                    """,
                    (
                        scan_id,
                        item["name"],
                        item["original_path"],
                        item["size"],
                        item["extension"],
                        item["sha256"],
                        item["modified_at"],
                        item["scanned_at"],
                        int(item["is_protected"]),
                    ),
                )
            groups = duplicate_groups(connection, scan_id)
            totals = duplicate_totals(groups)
            connection.execute(
                """
                UPDATE scan_history
                SET completed_at = ?, status = 'completed', files_scanned = ?,
                    duplicates_found = ?, duplicate_groups = ?, recoverable_bytes = ?,
                    skipped_files = ?
                WHERE id = ?
                """,
                (
                    datetime.now(timezone.utc).isoformat(),
                    len(files),
                    totals["duplicates_found"],
                    totals["duplicate_groups"],
                    totals["recoverable_bytes"],
                    result["skipped_files"],
                    scan_id,
                ),
            )

        records = scan_file_records(connection, scan_id)
        duplicate_ids = {
            file["id"] for group in groups for file in group["files"] if file["duplicate"]
        }
        return (
            jsonify(
                {
                    "scan_id": scan_id,
                    "folder": result["folder"],
                    "files_scanned": len(records),
                    "skipped_files": result["skipped_files"],
                    "duplicate_files_found": totals["duplicates_found"],
                    "duplicate_groups": totals["duplicate_groups"],
                    "recoverable_bytes": totals["recoverable_bytes"],
                    "files": [
                        serialize_file(file, file["id"] in duplicate_ids)
                        for file in records
                    ],
                }
            ),
            201,
        )

    @app.get("/api/duplicates")
    def get_duplicates():
        connection = database()
        requested_scan = request.args.get("scan_id")
        if requested_scan is not None:
            if not requested_scan.isdecimal():
                return error_response("'scan_id' must be a positive integer.", 400)
            scan = connection.execute(
                "SELECT id, folder_path FROM scan_history WHERE id = ? AND status = 'completed'",
                (int(requested_scan),),
            ).fetchone()
        else:
            scan = latest_scan(connection)
        if scan is None:
            return jsonify({"scan_id": None, "groups": [], "files": []})
        groups = duplicate_groups(connection, scan["id"])
        records = scan_file_records(connection, scan["id"])
        return jsonify(
            {
                "scan_id": scan["id"],
                "folder": scan["folder_path"],
                "groups": [
                    {
                        **group,
                        "files": [
                            serialize_file(file, file["duplicate"])
                            for file in group["files"]
                        ],
                    }
                    for group in groups
                ],
                "files": [
                    serialize_file(
                        file,
                        any(
                            duplicate["id"] == file["id"]
                            for group in groups
                            for duplicate in group["files"]
                            if duplicate["duplicate"]
                        ),
                    )
                    for file in records
                ],
            }
        )

    @app.get("/api/history")
    def get_history():
        rows = database().execute(
            """
            SELECT id, folder_path, started_at, completed_at, status, files_scanned,
                   duplicates_found, duplicate_groups, recoverable_bytes, skipped_files
            FROM scan_history
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
        return jsonify(
            {
                "history": [
                    {
                        "id": row["id"],
                        "folder": row["folder_path"],
                        "date": row["completed_at"] or row["started_at"],
                        "fileCount": row["files_scanned"],
                        "duplicateCount": row["duplicates_found"],
                        "groupCount": row["duplicate_groups"],
                        "recoverable": row["recoverable_bytes"],
                        "skippedFiles": row["skipped_files"],
                        "status": row["status"],
                    }
                    for row in rows
                ]
            }
        )

    @app.get("/api/quarantine")
    def get_quarantine():
        rows = database().execute(
            """
            SELECT quarantine.id, quarantine.scanned_file_id, quarantine.original_path,
                   quarantine.quarantine_path, quarantine.quarantined_at,
                   quarantine.restored_at, quarantine.status, file.name, file.size,
                   file.extension, file.sha256, file.modified_at
            FROM quarantine_files AS quarantine
            JOIN scanned_files AS file ON file.id = quarantine.scanned_file_id
            WHERE quarantine.status = 'quarantined'
            ORDER BY quarantine.id DESC
            """
        ).fetchall()
        return jsonify(
            {
                "files": [
                    {
                        "id": row["id"],
                        "scanned_file_id": row["scanned_file_id"],
                        "name": row["name"],
                        "size": row["size"],
                        "extension": row["extension"],
                        "sha256": row["sha256"],
                        "modifiedAt": row["modified_at"],
                        "originalPath": row["original_path"],
                        "quarantinePath": row["quarantine_path"],
                        "quarantinedAt": row["quarantined_at"],
                        "restoredAt": row["restored_at"],
                        "status": row["status"],
                    }
                    for row in rows
                ]
            }
        )

    @app.post("/api/cleanup")
    def cleanup():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return error_response("A JSON request body is required.", 400)
        file_ids, error = _validated_ids(body.get("file_ids"), "file_ids")
        if error:
            return error_response(error, 400)
        result = quarantine_files(
            database(),
            file_ids,
            current_app.config["SCAN_ROOTS"],
            current_app.config["QUARANTINE_DIR"],
        )
        if not result["moved"]:
            return jsonify({"files": [], "failed": result["failed"]}), 409
        moved_by_id = {item["id"]: item for item in result["moved"]}
        files = []
        for file_id in file_ids:
            move = moved_by_id.get(file_id)
            if move:
                files.append(
                    {
                        "id": file_id,
                        "quarantineId": move["quarantine_id"],
                        "quarantinePath": move["quarantine_path"],
                    }
                )
        return jsonify({"files": files, "failed": result["failed"]})

    @app.post("/api/restore")
    def restore():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            return error_response("A JSON request body is required.", 400)
        quarantine_ids, error = _validated_ids(body.get("quarantine_ids"), "quarantine_ids")
        if error:
            return error_response(error, 400)
        result = restore_files(
            database(),
            quarantine_ids,
            current_app.config["SCAN_ROOTS"],
            current_app.config["QUARANTINE_DIR"],
        )
        if not result["restored"]:
            return jsonify({"restored": [], "failed": result["failed"]}), 409
        return jsonify(result)

    @app.errorhandler(404)
    def not_found(_error):
        if request.path.startswith("/api/"):
            return error_response("API endpoint not found.", 404)
        return _error

    @app.errorhandler(500)
    def internal_error(_error):
        current_app.logger.exception("Unhandled server error.")
        return error_response("An unexpected server error occurred.", 500)

    return app


def _validated_ids(value, field_name):
    if not isinstance(value, list) or not value:
        return None, f"'{field_name}' must be a non-empty array of file IDs."
    identifiers = []
    for item in value:
        if isinstance(item, bool):
            return None, f"Every entry in '{field_name}' must be a positive integer."
        if isinstance(item, int):
            identifier = item
        elif isinstance(item, str) and item.isdecimal():
            identifier = int(item)
        else:
            return None, f"Every entry in '{field_name}' must be a positive integer."
        if identifier <= 0:
            return None, f"Every entry in '{field_name}' must be a positive integer."
        identifiers.append(identifier)
    if len(set(identifiers)) != len(identifiers):
        return None, f"'{field_name}' must not contain duplicate IDs."
    return identifiers, None


def _mark_scan_failed(connection, scan_id, message):
    with connection:
        connection.execute(
            """
            UPDATE scan_history
            SET status = 'failed', completed_at = ?, error_message = ?
            WHERE id = ? AND status = 'scanning'
            """,
            (datetime.now(timezone.utc).isoformat(), message[:500], scan_id),
        )


def _category(extension):
    extension = extension.lower().lstrip(".")
    categories = {
        "images": {"jpg", "jpeg", "png", "gif", "webp", "bmp", "svg", "tif", "tiff", "heic", "raw"},
        "documents": {"pdf", "doc", "docx", "txt", "rtf", "odt", "xls", "xlsx", "ppt", "pptx", "csv", "md"},
        "videos": {"mp4", "mov", "mkv", "avi", "webm", "m4v", "wmv"},
        "audio": {"mp3", "wav", "aac", "flac", "m4a", "ogg", "wma"},
    }
    for category, extensions in categories.items():
        if extension in extensions:
            return category
    return "other"


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
