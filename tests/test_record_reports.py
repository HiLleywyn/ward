import copy
import re
import unittest

from ward.data import load_malware_records, load_malware_reports, malware_report


class ReviewedReportTests(unittest.TestCase):
    def test_every_presentation_is_bound_to_existing_reviewed_evidence(self):
        reports = load_malware_reports()
        covered = set()
        for record in load_malware_records():
            report = malware_report(record, reports)
            if record["malware"] not in reports:
                continue  # Future records retain their original finding until reviewed.
            with self.subTest(repository=record["repository"]):
                self.assertIsNotNone(report)
                covered.add(record["malware"])
                basis = record["finding"] + " " + record["behavior"]
                for artifact in report["hashes"]:
                    self.assertRegex(artifact["sha256"], r"^[a-f0-9]{64}$")
                    self.assertIn(artifact["sha256"], basis)
                self.assertEqual(set(re.findall(r"\b[a-f0-9]{64}\b", basis)),
                                 {item["sha256"] for item in report["hashes"]})
        self.assertEqual(covered, set(reports))

    def test_changed_evidence_scope_or_family_cannot_reuse_a_report(self):
        reports = load_malware_reports()
        record = next(item for item in load_malware_records() if malware_report(item, reports))
        for key in ("finding", "behavior", "scope", "malware"):
            changed = dict(record, **{key: record[key] + " changed"})
            with self.subTest(key=key):
                self.assertIsNone(malware_report(changed, reports))
        self.assertIsNone(malware_report(record, {}))

    def test_actual_repository_revision_and_original_evidence_are_preserved(self):
        record = next(item for item in load_malware_records() if item["repository"] == "CarrierForge/Fishing-Planet-Cheat")
        before = copy.deepcopy(record)
        report = malware_report(record, load_malware_reports())
        self.assertIsNotNone(report)
        self.assertIn("a48fd3fc0f587bc272b1ad5dc0ea72675fed5ff9", record["release"])
        self.assertIn("encrypted/1.zip", report["chain"])
        self.assertIn("1/1.exe", report["chain"])
        self.assertEqual(before, record)


if __name__ == "__main__":
    unittest.main()
