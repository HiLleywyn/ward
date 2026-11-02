from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analyze import assess_file, assess_repository, load_indicators, parse_repository_target
from .github import GitHubClient, GitHubError
from .discovery import hunt_project
from .analyze import CANONICAL_PROJECTS
from .web import serve
from .registry import validate_registry
from .data import advisory_directory
from .evidence import default_store, repository_warning, snapshot_evidence


def _default_indicator_path() -> Path:
    return advisory_directory() / "indicators.json"


def _print_human(result: dict) -> None:
    print(f"Target:  {result['target']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Score:   {result['score']}/100")
    if result["signals"]:
        print("\nSignals:")
        for signal in result["signals"]:
            suffix = f" (+{signal['points']})" if signal["points"] else ""
            print(f"  - {signal['message']}{suffix}")
    print("\nLimits:")
    for limitation in result["limitations"]:
        print(f"  - {limitation}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ward",
        description="Inspect Git repositories and local file hashes without executing repository code.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    repo = subparsers.add_parser("repo", help="inspect GitHub metadata and README text")
    repo.add_argument("target", help="OWNER/REPOSITORY or a github.com repository URL")
    repo.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    file_parser = subparsers.add_parser("file", help="compare a local file hash to confirmed indicators")
    file_parser.add_argument("path", type=Path)
    file_parser.add_argument("--indicators", type=Path, default=_default_indicator_path())
    file_parser.add_argument(
        "--known-assets",
        type=Path,
        default=advisory_directory() / "known-project-assets.json",
    )
    file_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    remnux = subparsers.add_parser("remnux", help="run deeper static file analysis in an offline REMnux container")
    remnux.add_argument("path", type=Path)
    remnux.add_argument("--sha256", help="require this exact artifact hash before analysis")

    web = subparsers.add_parser("web", help="launch the local interactive checker")
    web.add_argument("--port", type=int, default=8787)
    web.add_argument("--no-open", action="store_true", help="do not open a browser automatically")

    hunt = subparsers.add_parser("hunt", help="find lookalikes for private human review")
    hunt.add_argument("project", choices=sorted(CANONICAL_PROJECTS))
    hunt.add_argument("--limit", type=int, default=20, help="maximum repositories to inspect")
    hunt.add_argument("--min-score", type=int, default=20, help="minimum metadata score to show")
    hunt.add_argument("--json", action="store_true", help="emit machine-readable JSON")

    validate = subparsers.add_parser("validate", help="validate advisory registry files")
    validate.add_argument(
        "directory",
        nargs="?",
        type=Path,
        default=advisory_directory(),
    )
    history = subparsers.add_parser("history", help="show persisted scan and community report history")
    history.add_argument("--limit", type=int, default=100)
    report = subparsers.add_parser("report", help="record a community lead pending review")
    report.add_argument("target")
    report.add_argument("--evidence", required=True)
    report.add_argument("--description", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "remnux":
            from .remnux import MAX_SAMPLE_BYTES, analyze_remnux
            with args.path.open("rb") as sample:
                data = sample.read(MAX_SAMPLE_BYTES + 1)
            print(json.dumps(analyze_remnux(data, expected_sha256=args.sha256), indent=2))
            return 0
        if args.command == "history":
            print(json.dumps(default_store().history(args.limit), indent=2))
            return 0
        if args.command == "report":
            record_id = default_store().report(args.target, args.evidence, args.description)
            print(f"Recorded {record_id}: UNKNOWN, pending review")
            return 0
        if args.command == "web":
            serve(port=args.port, open_browser=not args.no_open)
            return 0
        if args.command == "hunt":
            result = hunt_project(
                GitHubClient(os.environ.get("GITHUB_TOKEN")),
                args.project,
                limit=args.limit,
                minimum_score=args.min_score,
                on_progress=None if args.json else lambda name: print(f"Checking {name}...", file=sys.stderr),
            )
            value = {
                "project": result.project,
                "query": result.query,
                "assessments": [item.to_dict() for item in result.assessments],
                "errors": [item.__dict__ for item in result.errors],
            }
            if args.json:
                print(json.dumps(value, indent=2))
            else:
                print(f"\n{result.project}: {len(result.assessments)} candidate(s) need review")
                for item in result.assessments:
                    print(f"  {item.score:>3}/100  {item.verdict:<20} {item.target}")
                if result.errors:
                    print(f"\n{len(result.errors)} repository check(s) failed.", file=sys.stderr)
                print("\nThese are review candidates, not confirmed malware.")
            return 0
        if args.command == "validate":
            problems = validate_registry(args.directory)
            if problems:
                for problem in problems:
                    print(f"{problem.file}:{problem.location}: {problem.message}", file=sys.stderr)
                return 1
            print(f"Registry is valid: {args.directory}")
            return 0
        if args.command == "repo":
            owner, repository = parse_repository_target(args.target)
            assessment = repository_warning(f"{owner}/{repository}")
            evidence = None
            if assessment is None:
                snapshot = GitHubClient(os.environ.get("GITHUB_TOKEN")).snapshot(owner, repository)
                assessment = assess_repository(snapshot)
                evidence = snapshot_evidence(snapshot)
            default_store().record_assessment(assessment, evidence)
        else:
            if not args.path.is_file():
                raise ValueError(f"File does not exist: {args.path}")
            assessment = assess_file(
                args.path,
                load_indicators(args.indicators),
                load_indicators(args.known_assets),
            )
            default_store().record_assessment(assessment)
    except (GitHubError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = assessment.to_dict()
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_human(result)
    return 1 if assessment.exact_indicator_match else 0

