"""Quarantine and restore operations for verified duplicate files."""

import hashlib
import os
import shutil
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


class FileOperationError(ValueError):
    """Raised when a file cannot safely be moved or restored."""


def _is_within(path, root):
    try:
        common = os.path.commonpath((str(path), str(root)))
        return os.path.normcase(common) == os.path.normcase(str(root))
    except ValueError:
        return False


def _allowed_file_path(value, allowed_roots):
    requested_path = Path(value)
    if requested_path.is_symlink():
        raise FileOperationError("Symbolic links cannot be moved.")
    try:
        path = requested_path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise FileOperationError("The source file is missing or inaccessible.") from error
    if not path.is_file() or path.is_symlink():
        raise FileOperationError("The source is not a regular file.")
    roots = []
    for root in allowed_roots:
        try:
            resolved = Path(root).resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        roots.append(resolved)
    if not any(_is_within(path, root) for root in roots):
        raise FileOperationError("The file is outside the configured scan directories.")
    return path


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _move_without_overwrite(source, destination, expected_hash=None):
    if os.path.lexists(destination):
        raise FileOperationError("The destination already exists.")
    try:
        os.link(source, destination, follow_symlinks=False)
    except OSError:
        destination_created = False
        try:
            with source.open("rb") as source_file:
                with destination.open("xb") as destination_file:
                    destination_created = True
                    shutil.copyfileobj(source_file, destination_file, CHUNK_SIZE)
                    destination_file.flush()
                    os.fsync(destination_file.fileno())
            shutil.copystat(source, destination, follow_symlinks=False)
            if expected_hash and _file_hash(destination) != expected_hash:
                raise FileOperationError("File contents changed during the move.")
            source.unlink()
        except (OSError, FileOperationError):
            if destination_created and destination.exists():
                destination.unlink()
            raise
        return

    try:
        if expected_hash and _file_hash(destination) != expected_hash:
            raise FileOperationError("File contents changed during the move.")
        source.unlink()
    except (OSError, FileOperationError):
        destination.unlink()
        raise


def quarantine_files(connection, file_ids, allowed_roots, quarantine_directory):
    """Move eligible duplicate copies into quarantine and record each success."""
    moved = []
    failed = []
    quarantine_root = Path(quarantine_directory).resolve()
    quarantine_root.mkdir(parents=True, exist_ok=True)

    for file_id in file_ids:
        row = connection.execute(
            """
            SELECT file.*, scan.folder_path
            FROM scanned_files AS file
            JOIN scan_history AS scan ON scan.id = file.scan_id
            WHERE file.id = ?
            """,
            (file_id,),
        ).fetchone()
        if row is None:
            failed.append({"id": file_id, "error": "File ID was not found."})
            continue
        if row["status"] != "active":
            failed.append({"id": file_id, "error": "File is not active."})
            continue
        if row["is_protected"]:
            failed.append({"id": file_id, "error": "The protected original cannot be quarantined."})
            continue
        if not row["sha256"]:
            failed.append({"id": file_id, "error": "File is not part of a verified duplicate group."})
            continue
        protected = connection.execute(
            """
            SELECT id FROM scanned_files
            WHERE scan_id = ? AND sha256 = ? AND is_protected = 1 AND status = 'active'
            LIMIT 1
            """,
            (row["scan_id"], row["sha256"]),
        ).fetchone()
        if protected is None:
            failed.append({"id": file_id, "error": "The protected original is no longer available."})
            continue

        source = None
        destination = quarantine_root / f"{uuid.uuid4().hex}_{Path(row['name']).name}"
        try:
            source = _allowed_file_path(row["original_path"], allowed_roots)
            if source.stat().st_size != row["size"] or _file_hash(source) != row["sha256"]:
                raise FileOperationError("The file changed after scanning; run a new scan first.")
            protected_record = connection.execute(
                "SELECT original_path FROM scanned_files WHERE id = ?",
                (protected["id"],),
            ).fetchone()
            protected_path = _allowed_file_path(
                protected_record["original_path"], allowed_roots
            )
            if _file_hash(protected_path) != row["sha256"]:
                raise FileOperationError("The protected original no longer matches this duplicate.")

            _move_without_overwrite(source, destination, row["sha256"])
            try:
                quarantined_at = datetime.now(timezone.utc).isoformat()
                with connection:
                    connection.execute(
                        "UPDATE scanned_files SET status = 'quarantined' WHERE id = ? AND status = 'active'",
                        (file_id,),
                    )
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        raise FileOperationError("The file record changed before quarantine completed.")
                    cursor = connection.execute(
                        """
                        INSERT INTO quarantine_files
                            (scanned_file_id, original_path, quarantine_path, quarantined_at, status)
                        VALUES (?, ?, ?, ?, 'quarantined')
                        """,
                        (file_id, str(source), str(destination), quarantined_at),
                    )
                    quarantine_id = cursor.lastrowid
            except (sqlite3.Error, FileOperationError):
                if destination.exists() and not source.exists():
                    _move_without_overwrite(destination, source, row["sha256"])
                raise
            moved.append(
                {
                    "id": file_id,
                    "quarantine_id": quarantine_id,
                    "quarantine_path": str(destination),
                }
            )
        except (OSError, sqlite3.Error, FileOperationError, KeyError) as error:
            failed.append({"id": file_id, "error": str(error)})
    return {"moved": moved, "failed": failed}


def restore_files(connection, quarantine_ids, allowed_roots, quarantine_directory):
    """Restore selected quarantined files when their original destination is free."""
    restored = []
    failed = []
    for quarantine_id in quarantine_ids:
        record = connection.execute(
            """
            SELECT quarantine.*, file.name, file.size, file.sha256, file.scan_id
            FROM quarantine_files AS quarantine
            JOIN scanned_files AS file ON file.id = quarantine.scanned_file_id
            WHERE quarantine.id = ?
            """,
            (quarantine_id,),
        ).fetchone()
        if record is None:
            failed.append({"id": quarantine_id, "error": "Quarantine ID was not found."})
            continue
        if record["status"] != "quarantined":
            failed.append({"id": quarantine_id, "error": "File is not currently quarantined."})
            continue

        source = Path(record["quarantine_path"])
        try:
            quarantine_root = Path(quarantine_directory).resolve(strict=True)
            resolved_source = source.resolve(strict=True)
            if not _is_within(resolved_source, quarantine_root):
                raise FileOperationError("The quarantine source is invalid.")
            if not source.is_file() or source.is_symlink():
                raise FileOperationError("The quarantined file is missing or is not a regular file.")
            if _file_hash(source) != record["sha256"]:
                raise FileOperationError("The quarantined file changed; it was not restored.")

            original = Path(record["original_path"])
            parent = original.parent.resolve(strict=True)
            destination = parent / original.name
            if not any(_is_within(destination, Path(root).resolve(strict=True)) for root in allowed_roots):
                raise FileOperationError("The original destination is outside configured scan directories.")
            if os.path.lexists(destination):
                raise FileOperationError("The original destination is already occupied.")
            if not os.access(parent, os.W_OK):
                raise FileOperationError("The original folder is not writable.")

            _move_without_overwrite(source, destination, record["sha256"])
            try:
                restored_at = datetime.now(timezone.utc).isoformat()
                with connection:
                    connection.execute(
                        "UPDATE quarantine_files SET status = 'restored', restored_at = ? WHERE id = ? AND status = 'quarantined'",
                        (restored_at, quarantine_id),
                    )
                    if connection.execute("SELECT changes()").fetchone()[0] != 1:
                        raise FileOperationError("The quarantine record changed before restore completed.")
                    connection.execute(
                        "UPDATE scanned_files SET status = 'active' WHERE id = ?",
                        (record["scanned_file_id"],),
                    )
            except (sqlite3.Error, FileOperationError):
                if destination.exists() and not source.exists():
                    _move_without_overwrite(destination, source, record["sha256"])
                raise
            restored.append({"id": quarantine_id, "original_path": str(destination)})
        except (OSError, sqlite3.Error, FileOperationError, ValueError) as error:
            failed.append({"id": quarantine_id, "error": str(error)})
    return {"restored": restored, "failed": failed}
