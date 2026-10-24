"""Tests for signed forensic audit checkpoints."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from forensics.audit_checkpoint import (
    create_checkpoint,
    verify_checkpoint,
)
from forensics.database import (
    create_case,
    init_db,
    record_audit_event,
)


class AuditCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.db_path = self.root / "test.db"
        self.checkpoint_path = self.root / "checkpoint.json"
        self.key_path = self.root / "checkpoint.key"

        init_db(self.db_path)
        self.case_id = create_case(
            "Checkpoint test case",
            "Temporary test data only",
            db_path=self.db_path,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def create_test_checkpoint(self):
        return create_checkpoint(
            db_path=self.db_path,
            checkpoint_path=self.checkpoint_path,
            key_path=self.key_path,
        )

    def verify_test_checkpoint(self):
        return verify_checkpoint(
            db_path=self.db_path,
            checkpoint_path=self.checkpoint_path,
            key_path=self.key_path,
        )

    def test_valid_checkpoint_verifies(self):
        self.create_test_checkpoint()

        result = self.verify_test_checkpoint()

        self.assertTrue(result["valid"])
        self.assertIsNone(result["error"])
        self.assertEqual(result["event_count"], 1)

    def test_modified_checkpoint_signature_is_rejected(self):
        self.create_test_checkpoint()

        document = json.loads(
            self.checkpoint_path.read_text(encoding="utf-8")
        )
        document["payload"]["event_count"] = 999
        self.checkpoint_path.write_text(
            json.dumps(document),
            encoding="utf-8",
        )

        result = self.verify_test_checkpoint()

        self.assertFalse(result["valid"])
        self.assertEqual(
            result["error"],
            "checkpoint_signature_mismatch",
        )

    def test_new_event_after_checkpoint_is_detected(self):
        self.create_test_checkpoint()

        record_audit_event(
            self.case_id,
            "test_event",
            {"message": "Added after checkpoint"},
            db_path=self.db_path,
        )

        result = self.verify_test_checkpoint()

        self.assertFalse(result["valid"])
        self.assertEqual(
            result["error"],
            "audit_chain_checkpoint_mismatch",
        )

    def test_deleted_last_event_after_checkpoint_is_detected(self):
        self.create_test_checkpoint()

        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                DELETE FROM audit_events
                WHERE rowid = (
                    SELECT MAX(rowid) FROM audit_events
                )
                """
            )

        result = self.verify_test_checkpoint()

        self.assertFalse(result["valid"])
        self.assertEqual(
            result["error"],
            "audit_chain_checkpoint_mismatch",
        )

    def test_invalid_chain_cannot_be_checkpointed(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                UPDATE audit_events
                SET details_json = ?
                WHERE rowid = (
                    SELECT MIN(rowid) FROM audit_events
                )
                """,
                ('{"tampered":true}',),
            )

        with self.assertRaisesRegex(
            ValueError,
            "invalid audit chain",
        ):
            self.create_test_checkpoint()

        self.assertFalse(self.checkpoint_path.exists())


if __name__ == "__main__":
    unittest.main()
