from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


class GitHubError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepositorySnapshot:
    repository: dict[str, Any]
    owner: dict[str, Any]
    releases: list[dict[str, Any]]
    readme: str
    tree_summary: dict[str, Any] | None = None


class GitHubClient:
    """Small GitHub REST client that never requests release asset bodies."""

    def __init__(self, token: str | None = None, api_url: str = "https://api.github.com"):
        self.token = token or os.environ.get("GITHUB_TOKEN")
        self.api_url = api_url.rstrip("/")

    def _get(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.api_url}/{path.lstrip('/')}",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "ward-github-scanner/0.3",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise GitHubError("GitHub JSON response exceeded the 8 MB limit")
                return json.loads(body)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise GitHubError(f"GitHub returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"Could not reach GitHub: {exc.reason}") from exc

    def snapshot(self, owner: str, repository: str) -> RepositorySnapshot:
        from .analyze import parse_repository_target
        owner, repository = parse_repository_target(f"{owner}/{repository}")
        quoted = f"{urllib.parse.quote(owner)}/{urllib.parse.quote(repository)}"
        repo = self._get(f"repos/{quoted}")
        if repo.get("private"):
            raise GitHubError("Only public repositories can be checked")
        try:
            head = self._get(f"repos/{quoted}/commits?per_page=1")
        except GitHubError as exc:
            if "HTTP 409" not in str(exc):
                raise
            head = []
        repo["head_sha"] = head[0]["sha"] if head else None
        account = self._get(f"users/{urllib.parse.quote(owner)}")
        releases = self._get(f"repos/{quoted}/releases?per_page=20")
        readme = ""
        try:
            readme_record = self._get(f"repos/{quoted}/readme")
            if readme_record.get("encoding") == "base64":
                readme = base64.b64decode(readme_record.get("content", "")).decode(
                    "utf-8", errors="replace"
                )
        except GitHubError as exc:
            if "HTTP 404" in str(exc) and repository == ".github":
                try:
                    record = self._get(f"repos/{quoted}/contents/profile/README.md")
                    if record.get("encoding") == "base64":
                        readme = base64.b64decode(record["content"]).decode("utf-8", errors="replace")
                except GitHubError as profile_error:
                    if "HTTP 404" not in str(profile_error):
                        raise
            elif "HTTP 404" not in str(exc):
                raise
        tree_summary = None
        if repo.get("head_sha"):
            tree = self._get(f"repos/{quoted}/git/trees/{repo['head_sha']}?recursive=1")
            extensions = (".cpp", ".h", ".c", ".py", ".js", ".ts", ".cs", ".rs", ".go", ".ps1", ".sh")
            sources = [item for item in tree.get("tree", []) if item["type"] == "blob" and item["path"].lower().endswith(extensions)]
            tree_summary = {"truncated": tree.get("truncated", False), "source_count":len(sources),
                "source_bytes":sum(item.get("size",0) for item in sources)}
        return RepositorySnapshot(repo, account, releases, readme, tree_summary)

    def search_repositories(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        encoded = urllib.parse.urlencode({"q": query, "per_page": limit})
        result = self._get(f"search/repositories?{encoded}")
        return list(result.get("items", []))

