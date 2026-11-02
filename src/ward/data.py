import hashlib
import json
from pathlib import Path


def advisory_directory() -> Path:
    """Use packaged data in both wheels and editable installs."""
    return Path(__file__).with_name("advisories")


def load_malware_records(directory: Path | None = None) -> list[dict]:
    """Expand compact campaign sets into repository-specific public records."""
    directory = directory or advisory_directory()
    payload = json.loads((directory / "malware-records.json").read_text(encoding="utf-8"))
    records = [dict(item) for item in payload.get("records", [])]
    sets_path = directory / "malware-record-sets.json"
    if not sets_path.exists():
        return records
    sets = json.loads(sets_path.read_text(encoding="utf-8"))
    for record_set in sets.get("sets", []):
        common = record_set.get("common", {})
        for repository in record_set.get("repositories", []):
            records.append(dict(common, **repository))
    return records


def load_malware_reports(directory: Path | None = None) -> dict:
    """Load reviewed presentation without changing the underlying scan evidence."""
    path = (directory or advisory_directory()) / "malware-reports.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("reports", {})


def malware_report(record: dict, reports: dict) -> dict | None:
    """Never reuse a narrative after its supporting finding or scope changes."""
    report = reports.get(record.get("malware"), {})
    basis = json.dumps([record.get(key, "") for key in ("finding", "behavior", "scope")], ensure_ascii=True)
    digest = hashlib.sha256(basis.encode()).hexdigest()
    return report if digest in report.get("evidence_digests", []) else None
