from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .github import RepositorySnapshot


CANONICAL_PROJECTS = {
    "anyps5": {
        "name": "AnyPS5",
        "repository": "boykopovar/AnyPS5",
        "homepage": "https://boykopovar.github.io/AnyPS5/",
        "aliases": ["anyps5"],
    },
    "kytyps5": {
        "name": "KytyPS5",
        "repository": "KytyPS5/KytyPS5",
        "homepage": "https://github.com/KytyPS5/KytyPS5",
        "aliases": ["kytyps5", "kyttyps5"],
    },
    "shadps4": {
        "name": "shadPS4",
        "repository": "shadps4-emu/shadPS4",
        "homepage": "https://shadps4.net/",
        "aliases": ["shadps4"],
    },
    "rpcs3": {
        "name": "RPCS3",
        "repository": "RPCS3/rpcs3",
        "homepage": "https://rpcs3.net/",
        "aliases": ["rpcs3"],
    },
    "pcsx2": {
        "name": "PCSX2",
        "repository": "PCSX2/pcsx2",
        "homepage": "https://pcsx2.net/",
        "aliases": ["pcsx2"],
    },
    "dolphin": {
        "name": "Dolphin",
        "repository": "dolphin-emu/dolphin",
        "homepage": "https://dolphin-emu.org/",
        "aliases": ["dolphin", "dolphinemu", "dolphinemulator"],
    },
    "ppsspp": {
        "name": "PPSSPP",
        "repository": "hrydgard/ppsspp",
        "homepage": "https://www.ppsspp.org/",
        "aliases": ["ppsspp"],
    },
    "xenia": {
        "name": "Xenia",
        "repository": "xenia-project/xenia",
        "homepage": "https://xenia.jp/",
        "aliases": ["xenia", "xeniaemulator"],
    },
    "cemu": {
        "name": "Cemu",
        "repository": "cemu-project/Cemu",
        "homepage": "https://cemu.info/",
        "aliases": ["cemu", "cemuemulator"],
    },
}

ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz"}
EXECUTABLE_SUFFIXES = {".exe", ".msi", ".scr", ".com", ".bat", ".cmd", ".ps1"}


@dataclass(frozen=True)
class Signal:
    key: str
    points: int
    message: str


@dataclass(frozen=True)
class Assessment:
    target: str
    verdict: str
    score: int
    exact_indicator_match: bool
    canonical_project: str | None
    signals: list[Signal]
    limitations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_repository_target(value: str) -> tuple[str, str]:
    value = value.strip()
    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)
        if parsed.netloc.lower() not in {"github.com", "www.github.com"} or parsed.scheme != "https":
            raise ValueError("Only github.com repository URLs are supported")
        parts = [part for part in parsed.path.split("/") if part]
    else:
        parts = [part for part in value.split("/") if part]
    if len(parts) < 2:
        raise ValueError("Use OWNER/REPOSITORY or a github.com repository URL")
    owner, repository = parts[0], parts[1].removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", owner):
        raise ValueError("Invalid GitHub owner")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", repository) or repository in {".", ".."}:
        raise ValueError("Invalid GitHub repository")
    return owner, repository


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _age_days(value: str | None, now: datetime) -> int | None:
    parsed = _parse_time(value)
    return (now - parsed).days if parsed else None


def _project_for_name(name: str) -> dict[str, Any] | None:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    for project in CANONICAL_PROJECTS.values():
        if any(alias in normalized for alias in project["aliases"]):
            return project
    return None


def _external_download_hosts(readme: str) -> list[str]:
    urls = re.findall(r"https?://[^\s)>\]]+", readme, flags=re.IGNORECASE)
    allowed = {
        "github.com",
        "www.github.com",
        "raw.githubusercontent.com",
        "objects.githubusercontent.com",
        "api.github.com",
    }
    hosts = set()
    for url in urls:
        parsed = urlparse(url.rstrip(".,;\"'"))
        host = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        if host and host not in allowed and any(
            marker in path for marker in ("download", ".zip", ".exe", ".msi", ".rar", ".7z")
        ):
            hosts.add(host)
    return sorted(hosts)


def assess_repository(
    snapshot: RepositorySnapshot, now: datetime | None = None,
    indicators: dict[str, Any] | None = None,
) -> Assessment:
    now = now or datetime.now(timezone.utc)
    repo = snapshot.repository
    full_name = repo["full_name"]
    project = _project_for_name(repo["name"] if repo["name"] != ".github" else full_name.split("/", 1)[0])
    canonical = project and full_name.lower() == project["repository"].lower()
    canonical_owner = project and repo.get("owner", {}).get("login", full_name.split("/", 1)[0]).lower() == project["repository"].split("/", 1)[0].lower()
    signals: list[Signal] = []

    if canonical:
        signals.append(
            Signal(
                "known_project_location",
                0,
                f"This matches the registry location for {project['name']}.",
            )
        )
    elif project and canonical_owner:
        signals.append(
            Signal(
                "known_project_owner",
                0,
                f"This repository belongs to the registry owner for {project['name']}.",
            )
        )
    elif project and repo.get("fork") and repo.get("source", {}).get("full_name", "").lower() == project["repository"].lower():
        signals.append(
            Signal(
                "connected_fork",
                0,
                f"GitHub identifies this as a fork of the registered {project['name']} repository.",
            )
        )
    elif project:
        exact_name = re.sub(r"[^a-z0-9]", "", repo["name"].lower()) in project["aliases"]
        signals.append(
            Signal(
                "project_name_lookalike",
                35 if exact_name else 5,
                f"This is a third-party repository using the {project['name']} name. Verify the publisher before using downloads.",
            )
        )
        signals.append(
            Signal(
                "lookalike_not_fork",
                15 if exact_name else 0,
                "GitHub does not identify this lookalike as a fork of another repository.",
            )
        )

    if not canonical and not canonical_owner:
        repo_age = _age_days(repo.get("created_at"), now)
        if repo_age is not None and repo_age < 30:
            signals.append(Signal("new_repository", 15, f"Repository age is {repo_age} days."))
        elif repo_age is not None and repo_age < 90:
            signals.append(Signal("young_repository", 8, f"Repository age is {repo_age} days."))

        owner_age = _age_days(snapshot.owner.get("created_at"), now)
        if owner_age is not None and owner_age < 30:
            signals.append(Signal("new_owner", 10, f"Owner account age is {owner_age} days."))

    readme_lower = snapshot.readme.lower()
    actionable_lines = [line for line in readme_lower.splitlines()
        if not re.search(r"\b(?:never|don't|do not|must not|should not)\b", line)]
    instructions = "\n".join(actionable_lines)
    if re.search(r"\b(?:add|set)-mppreference\b", instructions):
        signals.append(
            Signal(
                "defender_exclusion_command",
                45,
                "README contains a command that changes Microsoft Defender preferences.",
            )
        )
    elif re.search(
        r"(?:disable|turn off|exclude|whitelist).{0,40}(?:antivirus|anti-virus|defender)",
        instructions,
    ):
        signals.append(
            Signal(
                "antivirus_bypass_instruction",
                30,
                "README appears to tell users to disable or bypass antivirus protection.",
            )
        )

    hosts = _external_download_hosts(snapshot.readme)
    if hosts:
        signals.append(
            Signal(
                "external_binary_download",
                10,
                "README appears to direct binary downloads through: " + ", ".join(hosts),
            )
        )

    assets = [asset for release in snapshot.releases for asset in release.get("assets", [])]
    digests = {str(asset.get("digest", "")).lower() for asset in assets}
    if any(digest.startswith("sha256:") for digest in digests):
        if indicators is None:
            from .data import advisory_directory
            indicators = load_indicators(advisory_directory() / "indicators.json")
        matches = [item for item in indicators.get("indicators", [])
            if item.get("status") == "confirmed" and "sha256:" + item.get("sha256", "").lower() in digests]
        if matches:
            return Assessment(
                target=full_name, verdict="confirmed-malicious-asset", score=100,
                exact_indicator_match=True, canonical_project=project["name"] if project else None,
                signals=[Signal("confirmed_release_digest", 100,
                    "GitHub reports a release asset SHA-256 matching a confirmed malicious-file indicator.")],
                limitations=[f"Evidence: {item['source_url']}" for item in matches] + [
                    "The comparison uses GitHub's asset digest metadata. The asset was not downloaded or executed.",
                    "Only the matching asset is identified by this hash; other assets and repository contributors were not assessed."],
            )
    executable_assets = [
        asset for asset in assets if Path(asset.get("name", "")).suffix.lower() in EXECUTABLE_SUFFIXES
    ]
    packaged_assets = [
        asset for asset in assets if Path(asset.get("name", "")).suffix.lower() in ARCHIVE_SUFFIXES
    ]
    if project and not canonical and not canonical_owner and executable_assets:
        signals.append(
            Signal(
                "lookalike_ships_executable",
                10,
                f"Lookalike releases contain {len(executable_assets)} directly executable asset(s).",
            )
        )
    if project and not canonical and not canonical_owner and packaged_assets:
        signals.append(
            Signal(
                "lookalike_ships_archive",
                5,
                f"Lookalike releases contain {len(packaged_assets)} archive asset(s).",
            )
        )

    largest_asset = max((int(asset.get("size") or 0) for asset in assets), default=0)
    tree = snapshot.tree_summary
    if project and not canonical and not canonical_owner and tree and not tree.get("truncated") and tree.get("source_bytes",0) < 2_000 and largest_asset > 5_000_000:
        signals.append(Signal("little_source_large_release", 25,
            f"At the inspected commit, {tree['source_count']} source files total {tree['source_bytes']} bytes while a release exceeds 5 MB. Verify its provenance."))
    repo_kb = int(repo.get("size") or 0)
    if project and not canonical and not canonical_owner and repo_kb < 1_000 and largest_asset > 5_000_000:
        signals.append(
            Signal(
                "thin_source_large_release",
                20,
                "Repository source is small while a release asset is larger than 5 MB.",
            )
        )

    score = min(100, sum(signal.points for signal in signals))
    if score >= 75:
        verdict = "high-risk-metadata"
    elif score >= 45:
        verdict = "needs-review"
    elif score >= 20:
        verdict = "caution"
    else:
        verdict = "no-strong-signals"

    return Assessment(
        target=full_name,
        verdict=verdict,
        score=score,
        exact_indicator_match=False,
        canonical_project=project["name"] if project else None,
        signals=signals,
        limitations=[
            "Metadata signals are not proof that a repository or file is malicious.",
            "A known project location is not a guarantee that every commit or release is safe.",
            "No release asset was downloaded, opened, uploaded, or executed.",
            "Only the first 20 release records were inspected. Repository metadata can be incomplete.",
        ],
    )


def load_indicators(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def assess_file(
    path: Path,
    indicators: dict[str, Any],
    known_assets: dict[str, Any] | None = None,
) -> Assessment:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    sha256 = digest.hexdigest()
    matches = [
        item for item in indicators.get("indicators", [])
        if item.get("sha256", "").lower() == sha256 and item.get("status") == "confirmed"
    ]
    known_matches = [
        item
        for item in (known_assets or {}).get("assets", [])
        if item.get("sha256", "").lower() == sha256
    ]
    signals = []
    if matches:
        signals.append(
            Signal(
                "confirmed_sha256_match",
                100,
                "SHA-256 exactly matches an evidence-backed malicious-file indicator.",
            )
        )
    elif known_matches:
        match = known_matches[0]
        signals.append(
            Signal(
                "known_project_asset",
                0,
                f"SHA-256 matches {match['project']} {match['release']} asset {match['name']}.",
            )
        )
    return Assessment(
        target=str(path),
        verdict=(
            "confirmed-malicious-indicator"
            if matches
            else "known-project-artifact"
            if known_matches
            else "no-known-hash-match"
        ),
        score=100 if matches else 0,
        exact_indicator_match=bool(matches),
        canonical_project=None,
        signals=signals,
        limitations=[
            f"Calculated SHA-256: {sha256}",
            *(
                ["A project-release match establishes provenance, not a guarantee of safety."]
                if known_matches
                else []
            ),
            "No hash match does not mean a file is safe.",
            "The file was read as bytes for hashing only and was not executed or uploaded.",
        ],
    )

