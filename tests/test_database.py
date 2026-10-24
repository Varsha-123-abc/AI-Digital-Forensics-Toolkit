import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from forensics.database import (
    add_evidence,
    create_case,
    get_case,
    init_db,
    list_audit_events,
    list_cases,
    list_evidence,
    record_audit_event,
    verify_audit_chain,
)

class TestForensicsDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.db_path = Path(self.temp_dir.name) / "test.db"
        init_db(self.db_path)

    def sample_metadata(self):
        content = b"harmless evidence"
        return {
            "file_name": "sample.txt",
            "file_path": "/training/sample.txt",
            "file_size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "mime_type_guess": "text/plain",
            "collected_at_utc": "2026-01-01T00:00:00+00:00",
            "collection_status": "completed",
        }

    def test_create_and_retrieve_case(self):
        case_id = create_case(
            "Training investigation",
            "Test case",
            self.db_path,
        )

        case = get_case(case_id, self.db_path)

        self.assertIsNotNone(case)
        self.assertEqual(case["title"], "Training investigation")
        self.assertEqual(case["status"], "open")
        self.assertEqual(len(list_cases(self.db_path)), 1)

    def test_register_evidence(self):
        case_id = create_case("Evidence test", db_path=self.db_path)
        evidence_id = add_evidence(
            case_id,
            self.sample_metadata(),
            self.db_path,
        )

        evidence = list_evidence(case_id, self.db_path)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["evidence_id"], evidence_id)
        self.assertEqual(
            evidence[0]["sha256"],
            self.sample_metadata()["sha256"],
        )

        stored_metadata = json.loads(evidence[0]["metadata_json"])
        self.assertEqual(stored_metadata["file_name"], "sample.txt")

    def test_audit_events_are_recorded(self):
        case_id = create_case("Audit test", db_path=self.db_path)
        add_evidence(case_id, self.sample_metadata(), self.db_path)

        events = list_audit_events(case_id, self.db_path)
        event_types = [event["event_type"] for event in events]

        self.assertIn("case_created", event_types)
        self.assertIn("evidence_registered", event_types)

    def test_evidence_requires_existing_case(self):
        with self.assertRaises(ValueError):
            add_evidence(
                "CASE-DOES-NOT-EXIST",
                self.sample_metadata(),
                self.db_path,
            )

    def test_invalid_sha256_is_rejected(self):
        case_id = create_case("Invalid hash test", db_path=self.db_path)
        metadata = self.sample_metadata()
        metadata["sha256"] = "not-a-valid-hash"

        with self.assertRaises(ValueError):
            add_evidence(case_id, metadata, self.db_path)

    def test_empty_collection_timestamp_is_rejected(self):
        case_id = create_case("Timestamp validation", db_path=self.db_path)
        metadata = self.sample_metadata()
        metadata["collected_at_utc"] = "   "

        with self.assertRaisesRegex(ValueError, "timestamp"):
            add_evidence(case_id, metadata, self.db_path)

    def test_invalid_mime_type_is_rejected(self):
        case_id = create_case("MIME validation", db_path=self.db_path)
        metadata = self.sample_metadata()
        metadata["mime_type_guess"] = None

        with self.assertRaisesRegex(ValueError, "MIME type"):
            add_evidence(case_id, metadata, self.db_path)

    def test_empty_case_id_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Case ID"):
            add_evidence("", self.sample_metadata(), self.db_path)

    def test_empty_case_title_is_rejected(self):
        with self.assertRaises(ValueError):
            create_case("  ", db_path=self.db_path)

    def test_audit_hash_chain_is_valid(self):
        case_id = create_case("Hash chain test", db_path=self.db_path)
        add_evidence(case_id, self.sample_metadata(), self.db_path)
        record_audit_event(
            case_id,
            "investigation_note",
            {"note": "Initial review"},
            db_path=self.db_path,
        )

        result = verify_audit_chain(self.db_path)

        self.assertTrue(result["valid"], result)
        self.assertEqual(result["checked_events"], 3)
        self.assertIsNone(result["error"])

    def test_audit_chain_detects_modified_details(self):
        case_id = create_case("Tamper test", db_path=self.db_path)

        import sqlite3

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE audit_events
                SET details_json = ?
                WHERE case_id = ?
                """,
                ('{"title":"Modified title"}', case_id),
            )

        result = verify_audit_chain(self.db_path)

        self.assertFalse(result["valid"])
        self.assertEqual(result["error"], "event_hash_mismatch")

    def test_audit_chain_detects_deleted_middle_event(self):
        case_id = create_case("Deletion test", db_path=self.db_path)
        record_audit_event(
            case_id, "event_two", {"sequence": 2}, db_path=self.db_path
        )
        record_audit_event(
            case_id, "event_three", {"sequence": 3}, db_path=self.db_path
        )

        import sqlite3

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                DELETE FROM audit_events
                WHERE event_type = ?
                """,
                ("event_two",),
            )

        result = verify_audit_chain(self.db_path)

        self.assertFalse(result["valid"])
        self.assertEqual(result["error"], "previous_hash_mismatch")

    def test_legacy_audit_events_are_migrated(self):
        import sqlite3

        legacy_db = Path(self.temp_dir.name) / "legacy.db"

        with sqlite3.connect(legacy_db) as connection:
            connection.executescript(
                """
                CREATE TABLE cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    file_size_bytes INTEGER NOT NULL,
                    mime_type_guess TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE audit_events (
                    event_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    evidence_id TEXT,
                    event_type TEXT NOT NULL,
                    event_time TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                INSERT INTO cases VALUES (
                    'CASE-LEGACY', 'Legacy case', '', 'open',
                    '2026-01-01', '2026-01-01'
                );

                INSERT INTO audit_events VALUES (
                    'legacy-event-1', 'CASE-LEGACY', NULL,
                    'case_created', '2026-01-01T00:00:00+00:00',
                    '{"title":"Legacy case"}'
                );

                INSERT INTO audit_events VALUES (
                    'legacy-event-2', 'CASE-LEGACY', NULL,
                    'legacy_note', '2026-01-01T00:01:00+00:00',
                    '{"note":"Existing event"}'
                );
                """
            )

        init_db(legacy_db)

        with sqlite3.connect(legacy_db) as connection:
            rows = connection.execute(
                """
                SELECT previous_hash, event_hash
                FROM audit_events
                ORDER BY rowid
                """
            ).fetchall()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], "")
        self.assertTrue(rows[0][1])
        self.assertEqual(rows[1][0], rows[0][1])
        self.assertTrue(rows[1][1])

        result = verify_audit_chain(legacy_db)
        self.assertTrue(result["valid"], result)
        self.assertEqual(result["checked_events"], 2)

if __name__ == "__main__":
    unittest.main()
