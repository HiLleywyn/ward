from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RegistryProblem:
    file: str
    location: str
    message: str


def _load(path: Path, problems: list[RegistryProblem]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        problems.append(RegistryProblem(path.name, "$", str(exc)))
        return {}
    if not isinstance(value, dict):
        problems.append(RegistryProblem(path.name, "$", "top-level value must be an object"))
        return {}
    if value.get("schema_version") != 1:
        problems.append(RegistryProblem(path.name, "$.schema_version", "must equal 1"))
    return value


def _https(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme == "https" and bool(parsed.netloc)


def validate_registry(directory: Path) -> list[RegistryProblem]:
    problems: list[RegistryProblem] = []
    indicators = _load(directory / "indicators.json", problems)
    known_assets = _load(directory / "known-project-assets.json", problems)
    projects = _load(directory / "project-locations.json", problems)
    campaigns = _load(directory / "campaigns.json", problems)

    seen_hashes: set[str] = set()
    for index, item in enumerate(indicators.get("indicators", [])):
        location = f"$.indicators[{index}]"
        digest = str(item.get("sha256", "")).lower()
        if not SHA256_RE.fullmatch(digest):
            problems.append(RegistryProblem("indicators.json", location + ".sha256", "invalid SHA-256"))
        if digest in seen_hashes:
            problems.append(RegistryProblem("indicators.json", location + ".sha256", "duplicate SHA-256"))
        seen_hashes.add(digest)
        for field in ("source_url", "first_seen", "status", "validation_notes"):
            if not item.get(field):
                problems.append(RegistryProblem("indicators.json", location + f".{field}", "required"))
        if item.get("source_url") and not _https(item["source_url"]):
            problems.append(RegistryProblem("indicators.json", location + ".source_url", "must be HTTPS"))

    seen_assets: set[tuple[str, str]] = set()
    for index, item in enumerate(known_assets.get("assets", [])):
        location = f"$.assets[{index}]"
        digest = str(item.get("sha256", "")).lower()
        if not SHA256_RE.fullmatch(digest):
            problems.append(RegistryProblem("known-project-assets.json", location + ".sha256", "invalid SHA-256"))
        key = (digest, str(item.get("name", "")))
        if key in seen_assets:
            problems.append(RegistryProblem("known-project-assets.json", location, "duplicate asset record"))
        seen_assets.add(key)
        for field in ("project", "repository", "release", "name", "size", "release_url", "note"):
            if item.get(field) in (None, ""):
                problems.append(RegistryProblem("known-project-assets.json", location + f".{field}", "required"))
        if item.get("release_url") and not _https(item["release_url"]):
            problems.append(RegistryProblem("known-project-assets.json", location + ".release_url", "must be HTTPS"))

    seen_repositories: set[str] = set()
    for index, item in enumerate(projects.get("projects", [])):
        location = f"$.projects[{index}]"
        repository = str(item.get("repository", "")).lower()
        if repository in seen_repositories:
            problems.append(RegistryProblem("project-locations.json", location + ".repository", "duplicate repository"))
        seen_repositories.add(repository)
        for field in ("name", "repository", "homepage", "note"):
            if not item.get(field):
                problems.append(RegistryProblem("project-locations.json", location + f".{field}", "required"))
        for field in ("repository", "homepage"):
            if item.get(field) and not _https(item[field]):
                problems.append(RegistryProblem("project-locations.json", location + f".{field}", "must be HTTPS"))

    seen_campaigns: set[str] = set()
    for index, item in enumerate(campaigns.get("campaigns", [])):
        location = f"$.campaigns[{index}]"
        campaign_id = str(item.get("id", ""))
        if campaign_id in seen_campaigns:
            problems.append(RegistryProblem("campaigns.json", location + ".id", "duplicate campaign id"))
        seen_campaigns.add(campaign_id)
        for field in (
            "id",
            "status",
            "first_public_report",
            "impersonated_projects",
            "reported_behavior",
            "evidence",
            "validation_notes",
        ):
            if item.get(field) in (None, "", []):
                problems.append(RegistryProblem("campaigns.json", location + f".{field}", "required"))
        for evidence_index, evidence in enumerate(item.get("evidence", [])):
            if not _https(evidence.get("url")):
                problems.append(
                    RegistryProblem(
                        "campaigns.json",
                        location + f".evidence[{evidence_index}].url",
                        "must be HTTPS",
                    )
                )
    return problems

