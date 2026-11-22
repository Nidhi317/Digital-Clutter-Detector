"""SQLite setup and small connection helpers for Digital Clutter Detector."""

import sqlite3
from pathlib import Path


def connect(database_path):
    """Open a SQLite connection with foreign-key enforcement enabled."""
    connection = sqlite3.connect(str(database_path), timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    return connection


def initialize_database(database_path):
    """Create the database tables and indexes if they do not exist."""
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    connection = connect(database_path)
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                folder_path TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                status TEXT NOT NULL CHECK (status IN ('scanning', 'completed', 'failed')),
                files_scanned INTEGER NOT NULL DEFAULT 0 CHECK (files_scanned >= 0),
                duplicates_found INTEGER NOT NULL DEFAULT 0 CHECK (duplicates_found >= 0),
                duplicate_groups INTEGER NOT NULL DEFAULT 0 CHECK (duplicate_groups >= 0),
                recoverable_bytes INTEGER NOT NULL DEFAULT 0 CHECK (recoverable_bytes >= 0),
                skipped_files INTEGER NOT NULL DEFAULT 0 CHECK (skipped_files >= 0),
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS scanned_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                original_path TEXT NOT NULL,
                size INTEGER NOT NULL CHECK (size >= 0),
                extension TEXT NOT NULL DEFAULT '',
                sha256 TEXT,
                modified_at TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                is_protected INTEGER NOT NULL DEFAULT 0 CHECK (is_protected IN (0, 1)),
                status TEXT NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'quarantined', 'missing')),
                FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS quarantine_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_file_id INTEGER NOT NULL,
                original_path TEXT NOT NULL,
                quarantine_path TEXT NOT NULL UNIQUE,
                quarantined_at TEXT NOT NULL,
                restored_at TEXT,
                status TEXT NOT NULL DEFAULT 'quarantined'
                    CHECK (status IN ('quarantined', 'restored')),
                FOREIGN KEY (scanned_file_id) REFERENCES scanned_files(id)
            );

            CREATE INDEX IF NOT EXISTS idx_scanned_files_scan_id
                ON scanned_files(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scanned_files_scan_hash_size
                ON scanned_files(scan_id, size, sha256);
            CREATE INDEX IF NOT EXISTS idx_scanned_files_status
                ON scanned_files(status);
            CREATE INDEX IF NOT EXISTS idx_scan_history_started
                ON scan_history(started_at DESC);
            CREATE INDEX IF NOT EXISTS idx_quarantine_status
                ON quarantine_files(status, quarantined_at DESC);
            """
        )
    finally:
        connection.close()


def row_to_dict(row):
    """Convert a SQLite row to a JSON-friendly dictionary."""
    return dict(row) if row is not None else None
