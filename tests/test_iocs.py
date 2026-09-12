import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from build_iocs import extract, refang, build, HEADER


def document(rows):
    return "## IOCs\n\n| " + " | ".join(HEADER) + " |\n|---|---|---|\n" + rows


class IOCExtractionTests(unittest.TestCase):
    def test_ipv6_and_defanged_urls(self):
        records = extract(document(
            "| `2401:c080:1c01:c6:5400:5ff:fec1[:]ccc9` | IPv6 | VPS IPv6 |\n"
            "| `hXXps://example[.]com/a` | URL | Payload path |\n"))
        self.assertEqual(records[0]["value"], "2401:c080:1c01:c6:5400:5ff:fec1:ccc9")
        self.assertEqual(records[1]["value"], "https://example.com/a")
        self.assertEqual(records[1]["display"], "hXXps://example[.]com/a")

    def test_does_not_extract_prose_code_or_other_sections(self):
        body = "## Analysis\n192.0.2.1\n```text\n## IOCs\n```\n## IOCs\nNo indicators listed.\n## References\nhttps://example.com\n"
        self.assertEqual(extract(body), [])

    def test_preserves_distinct_observation_context(self):
        records = extract(document(
            "| `10.0.0.1` | IPv4 | Victim pivot \\| internal only |\n"
            "| `10.0.0.1` | IPv4 | Different observation |\n"))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["context"], "Victim pivot | internal only")
        self.assertEqual(records[1]["context"], "Different observation")

    def test_rejects_invalid_hashes_instead_of_silent_truncation(self):
        with self.assertRaisesRegex(ValueError, "Invalid hash"):
            extract(document("| `abcdef` | SHA256 | Incomplete |\n"))
        records = extract(document("| `abcdef` | Hash fragment | Source truncated |\n"))
        self.assertEqual(records[0]["type"], "Hash fragment")

    def test_rejects_malformed_or_missing_schema(self):
        for body in ["## Overview\n", "## IOCs\n## IOCs\n", "## IOCs\n| Value | Type |\n|---|---|\n"]:
            with self.assertRaises(ValueError):
                extract(body)

    def test_repository_has_context_for_every_observation(self):
        result = build()
        for source, rows in result.items():
            for row in rows:
                self.assertTrue(row["context"], source)
                self.assertEqual(set(row), {"value", "display", "type", "context"}, source)


if __name__ == "__main__":
    unittest.main()
