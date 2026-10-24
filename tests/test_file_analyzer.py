import hashlib
import tempfile
import unittest
from pathlib import Path

from forensics.file_analyzer import analyze_file


class TestFileAnalyzer(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_hash_and_metadata(self):
        evidence = self.root / "sample.txt"
        content = b"Harmless forensic test evidence\n"
        evidence.write_bytes(content)

        result = analyze_file(evidence)

        self.assertEqual(result["file_name"], "sample.txt")
        self.assertEqual(result["file_size_bytes"], len(content))
        self.assertEqual(
            result["sha256"],
            hashlib.sha256(content).hexdigest(),
        )
        self.assertEqual(result["collection_status"], "completed")
        self.assertFalse(result["change_detected"])
        self.assertTrue(Path(result["file_path"]).is_absolute())
        self.assertTrue(result["collected_at_utc"].endswith("+00:00"))

    def test_empty_file(self):
        evidence = self.root / "empty.bin"
        evidence.write_bytes(b"")

        result = analyze_file(evidence)

        self.assertEqual(result["file_size_bytes"], 0)
        self.assertEqual(
            result["sha256"],
            hashlib.sha256(b"").hexdigest(),
        )

    def test_missing_file(self):
        evidence = self.root / "missing.txt"

        with self.assertRaises(FileNotFoundError):
            analyze_file(evidence)

    def test_directory_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_file(self.root)

    def test_hash_changes_when_content_changes(self):
        evidence = self.root / "sample.txt"
        evidence.write_bytes(b"first version")
        first = analyze_file(evidence)

        evidence.write_bytes(b"second version")
        second = analyze_file(evidence)

        self.assertNotEqual(first["sha256"], second["sha256"])


if __name__ == "__main__":
    unittest.main()
