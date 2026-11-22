"""Focused API and filesystem safety tests."""

import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend import scanner
from backend.app import create_app


class BackendApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary_directory.name)
        self.root = self.base / "allowed"
        self.root.mkdir()
        self.quarantine = self.base / "quarantine"
        self.database = self.base / "test.db"
        self.app = create_app(
            {
                "TESTING": True,
                "DATABASE_PATH": str(self.database),
                "QUARANTINE_DIR": str(self.quarantine),
                "SCAN_ROOTS": [str(self.root)],
            }
        )
        self.client = self.app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    def scan(self):
        response = self.client.post("/api/scan", json={"path": str(self.root)})
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()

    def test_health_and_frontend_are_served(self):
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.get_json()["database"], "ok")
        with self.client.get("/") as page:
            self.assertEqual(page.status_code, 200)
            self.assertIn(b"Digital Clutter Detector", page.data)
        with self.client.get("/css/style.css") as stylesheet:
            self.assertEqual(stylesheet.status_code, 200)
        with self.client.get("/js/app.js") as javascript:
            self.assertEqual(javascript.status_code, 200)

    def test_database_schema_indexes_and_persisted_scan_results(self):
        self.assertTrue(self.database.is_file())
        (self.root / "stored.txt").write_bytes(b"persisted metadata")
        scan = self.scan()

        connection = sqlite3.connect(self.database)
        try:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(
                {"scan_history", "scanned_files", "quarantine_files"}.issubset(tables)
            )
            indexes = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'index'"
                )
            }
            self.assertTrue(
                {
                    "idx_scanned_files_scan_id",
                    "idx_scanned_files_scan_hash_size",
                    "idx_scanned_files_status",
                    "idx_scan_history_started",
                    "idx_quarantine_status",
                }.issubset(indexes)
            )
            self.assertEqual(
                connection.execute("PRAGMA foreign_key_check").fetchall(), []
            )
            file_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(scanned_files)")
            }
            self.assertNotIn("contents", file_columns)
            self.assertNotIn("content", file_columns)
            self.assertEqual(
                connection.execute(
                    "SELECT name, size FROM scanned_files WHERE scan_id = ?",
                    (scan["scan_id"],),
                ).fetchone(),
                ("stored.txt", len(b"persisted metadata")),
            )
        finally:
            connection.close()

        self.assertEqual(scan["duplicate_files_found"], 0)
        self.assertEqual(scan["duplicate_groups"], 0)
        history = self.client.get("/api/history").get_json()["history"]
        self.assertEqual(history[0]["id"], scan["scan_id"])
        self.assertEqual(history[0]["fileCount"], 1)

    def test_health_reports_database_connection_failure(self):
        self.app.config["DATABASE_PATH"] = str(self.base)
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.get_json()["database"], "unavailable")

    def test_read_endpoints_path_validation_and_empty_folder(self):
        self.assertEqual(self.client.get("/api/dashboard").status_code, 200)
        self.assertEqual(
            self.client.get("/api/dashboard").get_json()["total_files_scanned"], 0
        )
        self.assertEqual(self.client.get("/api/duplicates").get_json()["groups"], [])
        self.assertEqual(self.client.get("/api/history").get_json()["history"], [])
        self.assertEqual(self.client.get("/api/quarantine").get_json()["files"], [])

        malformed = self.client.post(
            "/api/scan", data="not json", content_type="application/json"
        )
        self.assertEqual(malformed.status_code, 400)
        for path in ("", str(self.root / "missing"), str(self.root / "file.txt")):
            response = self.client.post("/api/scan", json={"path": path})
            self.assertEqual(response.status_code, 400, response.get_json())
        (self.root / "file.txt").write_text("not a folder", encoding="utf-8")

        outside = self.base / "outside"
        outside.mkdir()
        forbidden = self.client.post("/api/scan", json={"path": str(outside)})
        self.assertEqual(forbidden.status_code, 403)

        (self.root / "file.txt").unlink()
        empty_scan = self.scan()
        self.assertEqual(empty_scan["files_scanned"], 0)
        self.assertEqual(empty_scan["duplicate_files_found"], 0)
        self.assertEqual(empty_scan["recoverable_bytes"], 0)
        self.assertEqual(self.client.get("/api/duplicates").get_json()["files"], [])
        self.assertEqual(
            self.client.get("/api/history").get_json()["history"][0]["status"],
            "completed",
        )
        missing_endpoint = self.client.get("/api/not-a-route")
        self.assertEqual(missing_endpoint.status_code, 404)
        self.assertIn("error", missing_endpoint.get_json())

    def test_duplicate_detection_edge_cases_and_recoverable_bytes(self):
        first_payload = b"identical payload with a different name"
        extension_payload = b"same bytes across extensions"
        large_payload = bytes(range(256)) * 8192
        (self.root / "named-one.txt").write_bytes(first_payload)
        (self.root / "named-two.bin").write_bytes(first_payload)
        (self.root / "cross-one.jpg").write_bytes(extension_payload)
        (self.root / "cross-two.data").write_bytes(extension_payload)
        (self.root / "empty-one").write_bytes(b"")
        (self.root / "empty-two").write_bytes(b"")
        (self.root / "large-one.bin").write_bytes(large_payload)
        (self.root / "large-two.bin").write_bytes(large_payload)
        left = self.root / "left"
        right = self.root / "right"
        left.mkdir()
        right.mkdir()
        (left / "same-name.txt").write_bytes(b"alpha!")
        (right / "same-name.txt").write_bytes(b"bravo!")
        (self.root / "different-small").write_bytes(b"tiny")
        (self.root / "different-large").write_bytes(b"not the same size")

        scan = self.scan()
        self.assertEqual(scan["files_scanned"], 12)
        self.assertEqual(scan["duplicate_groups"], 4)
        self.assertEqual(scan["duplicate_files_found"], 4)
        self.assertEqual(
            scan["recoverable_bytes"],
            len(first_payload) + len(extension_payload) + len(large_payload),
        )
        records = {record["path"]: record for record in scan["files"]}
        self.assertEqual(records[str(self.root / "large-one.bin")]["sha256"], hashlib.sha256(large_payload).hexdigest())
        self.assertEqual(
            records[str(left / "same-name.txt")]["sha256"],
            hashlib.sha256(b"alpha!").hexdigest(),
        )
        self.assertNotEqual(
            records[str(left / "same-name.txt")]["sha256"],
            records[str(right / "same-name.txt")]["sha256"],
        )
        groups = self.client.get("/api/duplicates").get_json()["groups"]
        grouped_names = {
            frozenset(file["name"] for file in group["files"]) for group in groups
        }
        self.assertIn(frozenset({"named-one.txt", "named-two.bin"}), grouped_names)
        self.assertIn(frozenset({"cross-one.jpg", "cross-two.data"}), grouped_names)
        self.assertIn(frozenset({"empty-one", "empty-two"}), grouped_names)
        self.assertIn(frozenset({"large-one.bin", "large-two.bin"}), grouped_names)
        self.assertNotIn(
            frozenset({"same-name.txt"}), grouped_names
        )
        self.assertEqual(
            self.client.get("/api/dashboard").get_json()["recoverable_bytes"],
            scan["recoverable_bytes"],
        )

    def test_permission_errors_are_skipped_without_failing_scan(self):
        blocked_directory = self.root / "blocked"
        blocked_directory.mkdir()
        (blocked_directory / "hidden.txt").write_bytes(b"not readable")
        (self.root / "readable.txt").write_bytes(b"readable")
        real_scandir = os.scandir

        def guarded_scandir(path):
            if Path(path) == blocked_directory:
                raise PermissionError("access denied")
            return real_scandir(path)

        with patch("backend.scanner.os.scandir", side_effect=guarded_scandir):
            scan = self.scan()
        self.assertEqual(scan["files_scanned"], 1)
        self.assertEqual(scan["skipped_files"], 1)

        (self.root / "candidate-a.bin").write_bytes(b"duplicate")
        (self.root / "candidate-b.bin").write_bytes(b"duplicate")
        with patch.object(
            scanner, "_sha256_file", side_effect=PermissionError("read denied")
        ):
            unreadable_scan = self.scan()
        self.assertEqual(unreadable_scan["files_scanned"], 2)
        self.assertEqual(unreadable_scan["skipped_files"], 2)

    def test_cleanup_moves_only_selected_copy_and_updates_database(self):
        copies = [self.root / name for name in ("a.txt", "b.txt", "c.txt")]
        for copy in copies:
            copy.write_bytes(b"three identical copies")
        scan = self.scan()
        group = self.client.get("/api/duplicates").get_json()["groups"][0]
        self.assertEqual(group["duplicate_count"], 2)
        protected_id = group["protected_file_id"]
        selected = next(file for file in group["files"] if file["id"] != protected_id)
        other_duplicate = next(
            file
            for file in group["files"]
            if file["id"] not in (protected_id, selected["id"])
        )

        result = self.client.post(
            "/api/cleanup", json={"file_ids": [selected["id"]]}
        )
        self.assertEqual(result.status_code, 200, result.get_json())
        self.assertEqual(len(result.get_json()["files"]), 1)
        self.assertEqual(len(result.get_json()["failed"]), 0)
        quarantine = self.client.get("/api/quarantine").get_json()["files"][0]
        quarantine_path = Path(quarantine["quarantinePath"])
        original_path = Path(selected["path"])
        self.assertFalse(original_path.exists())
        self.assertEqual(quarantine_path.read_bytes(), b"three identical copies")
        self.assertEqual(quarantine["originalPath"], str(original_path))
        self.assertTrue(Path(other_duplicate["path"]).is_file())
        self.assertTrue(
            any(Path(file["path"]).is_file() and file["protected"] for file in group["files"])
        )
        active_status = self.client.get(
            f"/api/duplicates?scan_id={scan['scan_id']}"
        ).get_json()
        active_ids = {file["id"] for file in active_status["files"]}
        self.assertNotIn(selected["id"], active_ids)

        connection = sqlite3.connect(self.database)
        try:
            file_status = connection.execute(
                "SELECT status FROM scanned_files WHERE id = ?", (selected["id"],)
            ).fetchone()[0]
            quarantine_record = connection.execute(
                "SELECT original_path, quarantine_path, status FROM quarantine_files WHERE id = ?",
                (quarantine["id"],),
            ).fetchone()
        finally:
            connection.close()
        self.assertEqual(file_status, "quarantined")
        self.assertEqual(
            quarantine_record,
            (str(original_path), str(quarantine_path), "quarantined"),
        )
        self.assertEqual(
            sum(path.is_file() for path in copies) + int(quarantine_path.is_file()), 3
        )

    def test_cleanup_rejects_missing_file_and_restore_missing_quarantine(self):
        (self.root / "a.txt").write_bytes(b"same")
        (self.root / "b.txt").write_bytes(b"same")
        self.scan()
        group = self.client.get("/api/duplicates").get_json()["groups"][0]
        duplicate = next(file for file in group["files"] if file["duplicate"])
        Path(duplicate["path"]).unlink()
        missing_source = self.client.post(
            "/api/cleanup", json={"file_ids": [duplicate["id"]]}
        )
        self.assertEqual(missing_source.status_code, 409)
        self.assertEqual(self.client.get("/api/quarantine").get_json()["files"], [])

        (self.root / "b.txt").write_bytes(b"same")
        self.scan()
        group = self.client.get("/api/duplicates").get_json()["groups"][0]
        duplicate = next(file for file in group["files"] if file["duplicate"])
        self.client.post("/api/cleanup", json={"file_ids": [duplicate["id"]]})
        quarantine = self.client.get("/api/quarantine").get_json()["files"][0]
        Path(quarantine["quarantinePath"]).unlink()
        missing_quarantine = self.client.post(
            "/api/restore", json={"quarantine_ids": [quarantine["id"]]}
        )
        self.assertEqual(missing_quarantine.status_code, 409)
        self.assertTrue(missing_quarantine.get_json()["failed"])

    def test_hash_duplicates_and_safe_quarantine_restore(self):
        original = self.root / "same-name.txt"
        duplicate = self.root / "different-name.bin"
        other_folder = self.root / "another-folder"
        other_folder.mkdir()
        same_name_different_content = other_folder / "same-name.txt"
        original.write_bytes(b"identical payload")
        duplicate.write_bytes(b"identical payload")
        same_name_different_content.write_bytes(b"different content")

        scan = self.scan()
        self.assertEqual(scan["files_scanned"], 3)
        self.assertEqual(scan["duplicate_files_found"], 1)
        self.assertEqual(scan["duplicate_groups"], 1)
        self.assertEqual(scan["recoverable_bytes"], len(b"identical payload"))
        self.assertEqual(
            self.client.get("/api/dashboard").get_json()["duplicate_files_found"], 1
        )

        group = self.client.get("/api/duplicates").get_json()["groups"][0]
        protected = next(file for file in group["files"] if file["protected"])
        duplicate_file = next(file for file in group["files"] if file["duplicate"])
        blocked = self.client.post(
            "/api/cleanup", json={"file_ids": [protected["id"]]}
        )
        self.assertEqual(blocked.status_code, 409)
        self.assertTrue(original.exists())
        self.assertTrue(duplicate.exists())

        cleaned = self.client.post(
            "/api/cleanup", json={"file_ids": [duplicate_file["id"]]}
        )
        self.assertEqual(cleaned.status_code, 200, cleaned.get_json())
        quarantine_entry = self.client.get("/api/quarantine").get_json()["files"][0]
        quarantined_path = Path(quarantine_entry["quarantinePath"])
        self.assertTrue(quarantined_path.is_file())
        self.assertFalse(Path(duplicate_file["path"]).exists())
        self.assertTrue(Path(protected["path"]).exists())

        restored = self.client.post(
            "/api/restore", json={"quarantine_ids": [quarantine_entry["id"]]}
        )
        self.assertEqual(restored.status_code, 200, restored.get_json())
        self.assertTrue(Path(duplicate_file["path"]).is_file())
        self.assertFalse(quarantined_path.exists())

    def test_rejects_paths_outside_the_configured_root(self):
        outside = self.base / "outside"
        outside.mkdir()
        response = self.client.post("/api/scan", json={"path": str(outside)})
        self.assertEqual(response.status_code, 403)
        self.assertIn("error", response.get_json())

    def test_scan_skips_symlinks_and_hashes_only_size_candidates(self):
        (self.root / "candidate-a.txt").write_bytes(b"repeated")
        (self.root / "candidate-b.txt").write_bytes(b"repeated")
        (self.root / "unique.txt").write_bytes(b"different length")
        symlink = self.root / "linked.txt"
        symlink_created = False
        try:
            symlink.symlink_to(self.root / "candidate-a.txt")
            symlink_created = True
        except (OSError, NotImplementedError):
            pass

        scan = self.scan()
        files = {file["name"]: file for file in scan["files"]}
        if symlink_created:
            self.assertNotIn("linked.txt", files)
        self.assertIsNotNone(files["candidate-a.txt"]["sha256"])
        self.assertIsNone(files["unique.txt"]["sha256"])

    def test_rejects_invalid_and_protected_ids(self):
        (self.root / "a.txt").write_bytes(b"same")
        (self.root / "b.txt").write_bytes(b"same")
        self.scan()
        invalid = self.client.post("/api/cleanup", json={"file_ids": ["../1"]})
        self.assertEqual(invalid.status_code, 400)
        missing = self.client.post("/api/cleanup", json={"file_ids": [999999]})
        self.assertEqual(missing.status_code, 409)

    def test_restore_refuses_to_overwrite_an_existing_destination(self):
        (self.root / "a.txt").write_bytes(b"same")
        (self.root / "b.txt").write_bytes(b"same")
        self.scan()
        group = self.client.get("/api/duplicates").get_json()["groups"][0]
        duplicate_file = next(file for file in group["files"] if file["duplicate"])
        self.client.post("/api/cleanup", json={"file_ids": [duplicate_file["id"]]})
        entry = self.client.get("/api/quarantine").get_json()["files"][0]
        Path(entry["originalPath"]).write_bytes(b"keep this file")
        response = self.client.post("/api/restore", json={"quarantine_ids": [entry["id"]]})
        self.assertEqual(response.status_code, 409)
        self.assertEqual(Path(entry["originalPath"]).read_bytes(), b"keep this file")
        self.assertTrue(Path(entry["quarantinePath"]).is_file())


if __name__ == "__main__":
    unittest.main()
