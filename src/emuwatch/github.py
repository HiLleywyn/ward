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
                "User-Agent": "emulator-safety-watch/0.1",
                "X-GitHub-Api-Version": "2022-11-28",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise GitHubError(f"GitHub returned HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise GitHubError(f"Could not reach GitHub: {exc.reason}") from exc

    def snapshot(self, owner: str, repository: str) -> RepositorySnapshot:
        quoted = f"{urllib.parse.quote(owner)}/{urllib.parse.quote(repository)}"
        repo = self._get(f"repos/{quoted}")
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
            if "HTTP 404" not in str(exc):
                raise
        return RepositorySnapshot(repo, account, releases, readme)

    def search_repositories(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        encoded = urllib.parse.urlencode({"q": query, "per_page": limit})
        result = self._get(f"search/repositories?{encoded}")
        return list(result.get("items", []))

