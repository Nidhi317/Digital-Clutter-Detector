"""Duplicate grouping and JSON serialization for scan records."""


def duplicate_groups(connection, scan_id):
    """Return groups with equal non-null SHA-256 and their additional-copy size."""
    rows = connection.execute(
        """
        SELECT id, scan_id, name, original_path, size, extension, sha256,
               modified_at, scanned_at, is_protected, status
        FROM scanned_files
        WHERE scan_id = ? AND sha256 IS NOT NULL AND status = 'active'
        ORDER BY sha256, modified_at, original_path, id
        """,
        (scan_id,),
    ).fetchall()
    by_hash = {}
    for row in rows:
        by_hash.setdefault(row["sha256"], []).append(dict(row))

    groups = []
    for file_hash, files in by_hash.items():
        if len(files) < 2:
            continue
        protected = [file for file in files if file["is_protected"]]
        if not protected:
            protected = [files[0]]
        protected_id = protected[0]["id"]
        for file in files:
            file["protected"] = file["id"] == protected_id
            file["duplicate"] = not file["protected"]
        groups.append(
            {
                "sha256": file_hash,
                "protected_file_id": protected_id,
                "file_count": len(files),
                "duplicate_count": len(files) - 1,
                "recoverable_bytes": sum(
                    file["size"] for file in files if file["id"] != protected_id
                ),
                "files": files,
            }
        )
    return groups


def scan_file_records(connection, scan_id):
    """Return all metadata for a scan, including files with no hash candidates."""
    rows = connection.execute(
        """
        SELECT id, scan_id, name, original_path, size, extension, sha256,
               modified_at, scanned_at, is_protected, status
        FROM scanned_files
        WHERE scan_id = ? AND status = 'active'
        ORDER BY original_path
        """,
        (scan_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def duplicate_totals(groups):
    """Summarize duplicate-file and recoverable-byte counts for groups."""
    return {
        "duplicates_found": sum(group["duplicate_count"] for group in groups),
        "duplicate_groups": len(groups),
        "recoverable_bytes": sum(group["recoverable_bytes"] for group in groups),
    }
