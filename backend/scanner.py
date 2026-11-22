"""Safe recursive file discovery and chunked SHA-256 hashing."""

import hashlib
import os
import stat
from datetime import datetime, timezone
from pathlib import Path


CHUNK_SIZE = 1024 * 1024


class ScanPathError(ValueError):
    """Raised when a requested folder is unavailable or outside scan roots."""


def _is_within(path, root):
    try:
        common = os.path.commonpath((str(path), str(root)))
        return os.path.normcase(common) == os.path.normcase(str(root))
    except ValueError:
        return False


def validate_scan_folder(folder_path, allowed_roots):
    """Resolve and validate a directory against explicitly allowed roots."""
    if not isinstance(folder_path, str) or not folder_path.strip():
        raise ScanPathError("A non-empty folder path is required.")

    try:
        target = Path(folder_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ScanPathError("The folder does not exist or cannot be accessed.") from error

    if not target.is_dir():
        raise ScanPathError("The requested path is not a directory.")
    try:
        with os.scandir(target):
            pass
    except OSError as error:
        raise ScanPathError("The folder cannot be accessed.") from error

    roots = []
    for root in allowed_roots:
        try:
            resolved_root = Path(root).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if resolved_root.is_dir():
            roots.append(resolved_root)
    if not any(_is_within(target, root) for root in roots):
        raise ScanPathError("The folder is outside the configured scan directories.")
    return target


def _sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        while True:
            chunk = file_handle.read(CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def scan_folder(folder_path, allowed_roots, excluded_directories=()):
    """
    Scan a permitted folder without following symlinks.

    Files with a size that occurs only once are recorded without a hash because
    they cannot match another file in this scan. Same-size candidates are
    fingerprinted in chunks; unreadable or changing files are skipped.
    """
    root = validate_scan_folder(folder_path, allowed_roots)
    excluded = set()
    for directory in excluded_directories:
        try:
            excluded.add(Path(directory).resolve(strict=False))
        except (OSError, RuntimeError):
            continue

    discovered = []
    skipped = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        if any(_is_within(directory, excluded_directory) for excluded_directory in excluded):
            continue
        try:
            entries = list(os.scandir(directory))
        except OSError:
            skipped += 1
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    child = Path(entry.path)
                    if not any(
                        _is_within(child.resolve(strict=False), excluded_directory)
                        for excluded_directory in excluded
                    ):
                        pending.append(child)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                file_path = Path(entry.path)
                metadata = entry.stat(follow_symlinks=False)
                if not stat.S_ISREG(metadata.st_mode):
                    continue
                discovered.append((file_path, metadata))
            except OSError:
                skipped += 1

    by_size = {}
    for path, metadata in discovered:
        by_size.setdefault(metadata.st_size, []).append((path, metadata))

    scanned_at = datetime.now(timezone.utc).isoformat()
    records = []
    for candidates in by_size.values():
        for path, initial_metadata in candidates:
            try:
                file_hash = _sha256_file(path) if len(candidates) > 1 else None
                final_metadata = path.stat(follow_symlinks=False)
                if not stat.S_ISREG(final_metadata.st_mode):
                    skipped += 1
                    continue
                if (initial_metadata.st_size, initial_metadata.st_mtime_ns) != (
                    final_metadata.st_size,
                    final_metadata.st_mtime_ns,
                ):
                    skipped += 1
                    continue
                records.append(
                    {
                        "name": path.name,
                        "original_path": str(path),
                        "size": final_metadata.st_size,
                        "extension": path.suffix.lower(),
                        "sha256": file_hash,
                        "modified_at": datetime.fromtimestamp(
                            final_metadata.st_mtime, timezone.utc
                        ).isoformat(),
                        "scanned_at": scanned_at,
                    }
                )
            except (OSError, PermissionError):
                skipped += 1

    return {"folder": str(root), "files": records, "skipped_files": skipped}
