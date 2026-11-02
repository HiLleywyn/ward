"""Build a pinned, per-repository ledger for a GitHub README delivery wave.

The collector uses the authenticated GitHub CLI for public metadata and README
content.  It never downloads release assets or executes repository content.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s<>\]\[()\"']+", re.IGNORECASE)
MEDIAFIRE_FOLDER_RE = re.compile(
    r"https?://(?:www\.)?mediafire\.com/folder/([A-Za-z0-9]+)", re.IGNORECASE
)


def gh_json(endpoint: str, fields: dict[str, str] | None = None) -> object:
    command = ["gh", "api", "-X", "GET", endpoint]
    for key, value in (fields or {}).items():
        command.extend(("-f", f"{key}={value}"))
    completed = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def search(query: str) -> tuple[int, list[dict]]:
    repositories: list[dict] = []
    total = 0
    for page in range(1, 11):
        response = gh_json(
            "search/repositories",
            {"q": query, "per_page": "100", "page": str(page)},
        )
        if not isinstance(response, dict):
            raise RuntimeError("unexpected GitHub search response")
        total = int(response.get("total_count", 0))
        items = response.get("items", [])
        if not isinstance(items, list):
            raise RuntimeError("unexpected GitHub search items")
        repositories.extend(item for item in items if isinstance(item, dict))
        if len(items) < 100 or len(repositories) >= min(total, 1000):
            break
    return total, repositories


def inspect_repository(repository: dict, marker: str) -> dict:
    name = str(repository["full_name"])
    branch = str(repository.get("default_branch") or "main")
    commit = gh_json(f"repos/{name}/commits/{branch}")
    if not isinstance(commit, dict) or not commit.get("sha"):
        raise RuntimeError("missing commit SHA")
    sha = str(commit["sha"])
    readme = gh_json(f"repos/{name}/readme", {"ref": sha})
    if not isinstance(readme, dict):
        raise RuntimeError("unexpected README response")
    text = base64.b64decode(str(readme.get("content", ""))).decode("utf-8", errors="replace")
    urls = sorted(set(URL_RE.findall(text)))
    mediafire_folders = sorted(set(MEDIAFIRE_FOLDER_RE.findall(text)))
    external_hosts = sorted(
        {
            urlparse(url).hostname.lower()
            for url in urls
            if urlparse(url).hostname
            and urlparse(url).hostname.lower() not in {"github.com", "raw.githubusercontent.com"}
        }
    )
    return {
        "repository": name,
        "repository_url": str(repository["html_url"]),
        "created_at": repository.get("created_at"),
        "pushed_at": repository.get("pushed_at"),
        "archived": bool(repository.get("archived")),
        "disabled": bool(repository.get("disabled")),
        "default_branch": branch,
        "commit": sha,
        "readme_path": readme.get("path"),
        "readme_blob_sha": readme.get("sha"),
        "readme_url": f"https://github.com/{name}/blob/{sha}/{readme.get('path', 'README.md')}",
        "marker_present": marker in text,
        "mediafire_folder_keys": mediafire_folders,
        "external_hosts": external_hosts,
        "external_urls": urls,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--query", required=True)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=6)
    args = parser.parse_args()

    total, repositories = search(args.query)
    observations: list[dict] = []
    errors: list[dict] = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, 8))) as executor:
        futures = {
            executor.submit(inspect_repository, repository, args.marker): repository["full_name"]
            for repository in repositories
        }
        for index, future in enumerate(as_completed(futures), start=1):
            name = str(futures[future])
            try:
                observation = future.result()
                observations.append(observation)
                print(
                    f"{index}/{len(futures)} {name} "
                    f"folders={len(observation['mediafire_folder_keys'])}",
                    flush=True,
                )
            except (OSError, subprocess.CalledProcessError, ValueError, RuntimeError) as error:
                errors.append({"repository": name, "error": str(error)[:500]})
                print(f"{index}/{len(futures)} {name} error", flush=True)

    result = {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "query": args.query,
        "marker": args.marker,
        "github_total_count": total,
        "collected_count": len(observations),
        "error_count": len(errors),
        "repositories": sorted(observations, key=lambda item: item["repository"].lower()),
        "errors": sorted(errors, key=lambda item: item["repository"].lower()),
        "limits": [
            "GitHub repository search returns at most 1,000 matches.",
            "A shared marker or external host is a campaign lead, not a malicious verdict.",
            "Repository and README state are pinned to the recorded commit.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Saved {len(observations)} repositories and {len(errors)} errors to {args.output}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
