import unittest

from forensics.indicator_analyzer import analyze_indicators


def metadata(filename, size=100):
    return {
        "file_name": filename,
        "file_size_bytes": size,
        "sha256": "a" * 64,
        "mime_type_guess": "unknown",
    }


class TestIndicatorAnalyzer(unittest.TestCase):

    def test_double_extension_is_flagged(self):
        result = analyze_indicators(metadata("invoice.pdf.exe"))

        identifiers = [
            finding["indicator"] for finding in result["findings"]
        ]

        self.assertIn("executable_or_script_extension", identifiers)
        self.assertIn("double_extension", identifiers)
        self.assertEqual(result["malware_verdict"], "not_determined")

    def test_normal_text_file_has_no_indicators(self):
        result = analyze_indicators(metadata("meeting_notes.txt"))

        self.assertEqual(result["indicator_count"], 0)
        self.assertEqual(result["triage_status"], "no_indicators")

    def test_hidden_filename_is_flagged(self):
        result = analyze_indicators(metadata(".hidden.txt"))

        identifiers = [
            finding["indicator"] for finding in result["findings"]
        ]

        self.assertIn("hidden_or_temporary_style_name", identifiers)

    def test_empty_file_is_flagged(self):
        result = analyze_indicators(metadata("empty.bin", size=0))

        identifiers = [
            finding["indicator"] for finding in result["findings"]
        ]

        self.assertIn("empty_file", identifiers)

    def test_invalid_filename_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_indicators(metadata(""))

    def test_invalid_size_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_indicators(metadata("sample.txt", size=-1))


if __name__ == "__main__":
    unittest.main()
