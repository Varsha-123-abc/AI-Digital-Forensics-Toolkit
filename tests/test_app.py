import json
import tempfile
import unittest
from pathlib import Path

import app as app_module
from forensics.database import (
    get_case,
    init_db,
    list_cases,
)

class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.db_path = Path(self.temp_dir.name) / "dashboard.db"
        self.original_db_path = app_module.app.config["DATABASE_PATH"]
        self.original_testing = app_module.app.config.get("TESTING", False)
        self.original_secret = app_module.app.config.get("SECRET_KEY")
        self.original_checkpoint_path = app_module.app.config["CHECKPOINT_PATH"]
        self.original_checkpoint_key_path = app_module.app.config["CHECKPOINT_KEY_PATH"]

        self.checkpoint_path = Path(self.temp_dir.name) / "audit-checkpoint.json"
        self.checkpoint_key_path = Path(self.temp_dir.name) / "checkpoint.key"

        app_module.app.config.update(
            DATABASE_PATH=str(self.db_path),
            CHECKPOINT_PATH=str(self.checkpoint_path),
            CHECKPOINT_KEY_PATH=str(self.checkpoint_key_path),
            TESTING=True,
            SECRET_KEY="test-only-secret",
        )

        init_db(str(self.db_path))
        self.client = app_module.app.test_client()

    def tearDown(self):
        app_module.app.config["DATABASE_PATH"] = self.original_db_path
        app_module.app.config["CHECKPOINT_PATH"] = self.original_checkpoint_path
        app_module.app.config["CHECKPOINT_KEY_PATH"] = self.original_checkpoint_key_path
        app_module.app.config["TESTING"] = self.original_testing
        app_module.app.config["SECRET_KEY"] = self.original_secret


    def test_checkpoint_create_and_verify_routes(self):
        case_id = app_module.create_case(
            "Checkpoint route test",
            "Test checkpoint dashboard actions",
            db_path=self.db_path,
        )

        create_response = self.client.post(
            f"/cases/{case_id}/audit-checkpoint/create"
        )
        self.assertEqual(create_response.status_code, 302)
        self.assertTrue(self.checkpoint_path.is_file())
        self.assertTrue(self.checkpoint_key_path.is_file())

        page_response = self.client.get(f"/cases/{case_id}")
        self.assertEqual(page_response.status_code, 200)
        self.assertIn(b"Signed audit checkpoint", page_response.data)
        self.assertIn(b"Verify checkpoint", page_response.data)

        verify_response = self.client.post(
            f"/cases/{case_id}/audit-checkpoint/verify"
        )
        self.assertEqual(verify_response.status_code, 302)

        verified_page = self.client.get(f"/cases/{case_id}")
        self.assertEqual(verified_page.status_code, 200)
        self.assertIn(b"Verified", verified_page.data)

    def test_checkpoint_creation_does_not_overwrite_existing_checkpoint(self):
        case_id = app_module.create_case(
            "Checkpoint overwrite test",
            "Ensure existing checkpoint is preserved",
            db_path=self.db_path,
        )

        first_response = self.client.post(
            f"/cases/{case_id}/audit-checkpoint/create"
        )
        self.assertEqual(first_response.status_code, 302)
        original_checkpoint = self.checkpoint_path.read_bytes()

        second_response = self.client.post(
            f"/cases/{case_id}/audit-checkpoint/create"
        )
        self.assertEqual(second_response.status_code, 302)
        self.assertEqual(
            self.checkpoint_path.read_bytes(),
            original_checkpoint,
        )

    def test_checkpoint_routes_return_404_for_unknown_case(self):
        create_response = self.client.post(
            "/cases/CASE-DOES-NOT-EXIST/audit-checkpoint/create"
        )
        verify_response = self.client.post(
            "/cases/CASE-DOES-NOT-EXIST/audit-checkpoint/verify"
        )

        self.assertEqual(create_response.status_code, 404)
        self.assertEqual(verify_response.status_code, 404)
        self.assertFalse(self.checkpoint_path.exists())


    def test_case_report_download_contains_evidence_and_audit_trail(self):
        case_id = app_module.create_case(
            "Report export test",
            "Verify downloadable report contents",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "report-evidence.txt"
        evidence_path.write_text(
            "Harmless report export test data\\n",
            encoding="utf-8",
        )

        analyze_response = self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        self.assertEqual(analyze_response.status_code, 302)

        response = self.client.get(f"/cases/{case_id}/report")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(
            response.headers["Content-Disposition"].startswith("attachment;")
        )
        self.assertIn("application/json", response.content_type)

        report = json.loads(response.get_data(as_text=True))
        self.assertEqual(report["case"]["case_id"], case_id)
        self.assertEqual(report["case"]["title"], "Report export test")
        self.assertEqual(len(report["evidence"]), 1)
        self.assertEqual(
            report["evidence"][0]["file_name"],
            "report-evidence.txt",
        )
        self.assertEqual(len(report["evidence"][0]["sha256"]), 64)
        self.assertIn("indicators", report["evidence"][0]["metadata"])
        self.assertTrue(any(
            event["event_type"] == "evidence_registered"
            for event in report["audit_events"]
        ))
        self.assertTrue(report["limitations"])

    def test_unknown_case_report_returns_404(self):
        response = self.client.get("/cases/CASE-DOES-NOT-EXIST/report")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(list_cases(db_path=self.db_path), [])

    def test_html_report_download_contains_evidence_and_escapes_html(self):
        case_id = app_module.create_case(
            "HTML <script>alert(1)</script> report",
            "Verify HTML report output",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "html-evidence.txt"
        evidence_path.write_text("Harmless HTML report test data", encoding="utf-8")

        analyze_response = self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        self.assertEqual(analyze_response.status_code, 302)

        response = self.client.get(f"/cases/{case_id}/report/html")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.content_type)
        self.assertTrue(
            response.headers["Content-Disposition"].startswith("attachment;")
        )
        self.assertIn(b"Evidence inventory", response.data)
        self.assertIn(b"html-evidence.txt", response.data)
        self.assertIn(b"SHA-256", response.data)
        self.assertIn(b"evidence_registered", response.data)
        self.assertIn(b"Forensic limitations", response.data)
        self.assertIn(b"&lt;script&gt;", response.data)
        self.assertNotIn(b"<script>alert(1)</script>", response.data)

    def test_unknown_case_html_report_returns_404(self):
        response = self.client.get(
            "/cases/CASE-DOES-NOT-EXIST/report/html"
        )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(list_cases(db_path=self.db_path), [])

    def test_health_endpoint(self):
        response = self.client.get("/health")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["status"], "ok")

    def test_dashboard_loads(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Digital Forensics Toolkit", response.data)

    def test_case_creation(self):
        response = self.client.post(
            "/cases",
            data={
                "title": "Dashboard test case",
                "description": "Testing case creation",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Dashboard test case", response.data)

        cases = list_cases(db_path=self.db_path)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["title"], "Dashboard test case")

    def test_empty_case_title_is_rejected(self):
        response = self.client.post(
            "/cases",
            data={"title": "   ", "description": ""},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Case title cannot be empty", response.data)
        self.assertEqual(list_cases(db_path=self.db_path), [])

    def test_unknown_case_does_not_create_a_case(self):
        response = self.client.get(
            "/cases/CASE-DOES-NOT-EXIST",
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(list_cases(db_path=self.db_path), [])

    def test_missing_evidence_file_is_handled(self):
        from forensics.database import list_evidence

        case_id = app_module.create_case(
            "Missing file test",
            db_path=self.db_path,
        )

        response = self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": "/path/that/does/not/exist.txt"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis failed:", response.data)
        self.assertEqual(
            list_evidence(case_id, db_path=self.db_path),
            [],
        )

    def test_case_creation_is_isolated_from_default_database(self):
        default_db_path = app_module.DEFAULT_DB_PATH
        cases_before = {
            case["case_id"]
            for case in list_cases(db_path=default_db_path)
        }

        response = self.client.post(
            "/cases",
            data={
                "title": "Isolation verification case",
                "description": "Temporary test only",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)

        cases_after = {
            case["case_id"]
            for case in list_cases(db_path=default_db_path)
        }

        self.assertEqual(cases_after, cases_before)
        self.assertEqual(
            list_cases(db_path=self.db_path)[0]["title"],
            "Isolation verification case",
        )


    def test_integrity_verification_reports_matching_hash(self):
        from forensics.database import list_audit_events

        case_id = app_module.create_case(
            "Integrity match test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "unchanged.txt"
        evidence_path.write_text("original evidence", encoding="utf-8")

        self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )

        evidence = app_module.list_evidence(
            case_id,
            db_path=self.db_path,
        )[0]

        response = self.client.post(
            f"/cases/{case_id}/evidence/{evidence['evidence_id']}/verify"
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            response.headers["Location"],
            f"/cases/{case_id}",
        )

        events = list_audit_events(case_id, db_path=self.db_path)
        verification_events = [
            event for event in events
            if event["event_type"] == "evidence_integrity_verification"
        ]
        self.assertEqual(len(verification_events), 1)
        details = json.loads(verification_events[0]["details_json"])
        self.assertEqual(details["status"], "Match")
        self.assertEqual(
            details["recorded_sha256"],
            details["calculated_sha256"],
        )

    def test_integrity_verification_detects_modified_file(self):
        from forensics.database import list_audit_events

        case_id = app_module.create_case(
            "Integrity mismatch test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "modified.txt"
        evidence_path.write_text("original evidence", encoding="utf-8")

        self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        evidence = app_module.list_evidence(
            case_id,
            db_path=self.db_path,
        )[0]

        evidence_path.write_text("changed evidence", encoding="utf-8")
        response = self.client.post(
            f"/cases/{case_id}/evidence/{evidence['evidence_id']}/verify"
        )

        self.assertEqual(response.status_code, 302)
        events = list_audit_events(case_id, db_path=self.db_path)
        verification_events = [
            event for event in events
            if event["event_type"] == "evidence_integrity_verification"
        ]
        self.assertEqual(len(verification_events), 1)
        details = json.loads(verification_events[0]["details_json"])
        self.assertEqual(details["status"], "Mismatch")
        self.assertNotEqual(
            details["recorded_sha256"],
            details["calculated_sha256"],
        )

    def test_integrity_verification_handles_missing_file(self):
        from forensics.database import list_audit_events

        case_id = app_module.create_case(
            "Integrity missing file test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "will-disappear.txt"
        evidence_path.write_text("temporary evidence", encoding="utf-8")

        self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        evidence = app_module.list_evidence(
            case_id,
            db_path=self.db_path,
        )[0]
        evidence_path.unlink()

        response = self.client.post(
            f"/cases/{case_id}/evidence/{evidence['evidence_id']}/verify"
        )

        self.assertEqual(response.status_code, 302)
        events = list_audit_events(case_id, db_path=self.db_path)
        verification_events = [
            event for event in events
            if event["event_type"] == "evidence_integrity_verification"
        ]
        self.assertEqual(len(verification_events), 1)
        details = json.loads(verification_events[0]["details_json"])
        self.assertEqual(details["status"], "File unavailable")
        self.assertIsNone(details["calculated_sha256"])

    def test_integrity_verification_rejects_evidence_from_another_case(self):
        from forensics.database import list_audit_events

        first_case = app_module.create_case(
            "First isolation case",
            db_path=self.db_path,
        )
        second_case = app_module.create_case(
            "Second isolation case",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "isolated.txt"
        evidence_path.write_text("temporary evidence", encoding="utf-8")

        self.client.post(
            f"/cases/{first_case}/analyze",
            data={"file_path": str(evidence_path)},
        )
        evidence = app_module.list_evidence(
            first_case,
            db_path=self.db_path,
        )[0]

        response = self.client.post(
            f"/cases/{second_case}/evidence/{evidence['evidence_id']}/verify"
        )

        self.assertEqual(response.status_code, 404)
        self.assertFalse(
            any(
                event["event_type"] == "evidence_integrity_verification"
                for event in list_audit_events(
                    second_case,
                    db_path=self.db_path,
                )
            )
        )


    def test_evidence_initially_shows_not_verified(self):
        case_id = app_module.create_case(
            "Initial integrity status test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "initial-status.txt"
        evidence_path.write_text("initial status test", encoding="utf-8")

        analyze_response = self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        self.assertEqual(analyze_response.status_code, 302)

        response = self.client.get(f"/cases/{case_id}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Integrity status:", response.data)
        self.assertIn(b"Not verified", response.data)
        self.assertIn(
            b"No integrity verification has been recorded.",
            response.data,
        )

    def test_case_page_displays_latest_integrity_verification(self):
        case_id = app_module.create_case(
            "Latest integrity status test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "latest-status.txt"
        evidence_path.write_text("original evidence", encoding="utf-8")

        analyze_response = self.client.post(
            f"/cases/{case_id}/analyze",
            data={"file_path": str(evidence_path)},
        )
        self.assertEqual(analyze_response.status_code, 302)

        evidence = app_module.list_evidence(
            case_id,
            db_path=self.db_path,
        )[0]
        verify_url = (
            f"/cases/{case_id}/evidence/"
            f"{evidence['evidence_id']}/verify"
        )

        first_response = self.client.post(verify_url)
        self.assertEqual(first_response.status_code, 302)

        match_page = self.client.get(f"/cases/{case_id}")
        self.assertEqual(match_page.status_code, 200)
        self.assertIn(b"Match", match_page.data)

        evidence_path.write_text("modified evidence", encoding="utf-8")

        second_response = self.client.post(verify_url)
        self.assertEqual(second_response.status_code, 302)

        latest_page = self.client.get(f"/cases/{case_id}")
        self.assertEqual(latest_page.status_code, 200)
        self.assertIn(b"Mismatch", latest_page.data)
        self.assertIn(
            b"The current file hash differs from the recorded SHA-256.",
            latest_page.data,
        )


    def test_file_changed_during_collection_is_handled(self):
        from unittest.mock import patch

        from forensics.database import list_evidence
        from forensics.file_analyzer import FileChangedDuringCollection

        case_id = app_module.create_case(
            "Collection safety test",
            db_path=self.db_path,
        )
        evidence_path = Path(self.temp_dir.name) / "changing-file.txt"
        evidence_path.write_text("temporary test data", encoding="utf-8")

        with patch.object(
            app_module,
            "analyze_file",
            side_effect=FileChangedDuringCollection(
                "File changed during collection."
            ),
        ):
            response = self.client.post(
                f"/cases/{case_id}/analyze",
                data={"file_path": str(evidence_path)},
                follow_redirects=True,
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Analysis failed:", response.data)
        self.assertIn(b"changed during collection", response.data)
        self.assertEqual(
            list_evidence(case_id, db_path=self.db_path),
            [],
        )


if __name__ == "__main__":
    unittest.main()
