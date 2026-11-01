from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .analyze import CANONICAL_PROJECTS, Assessment, assess_repository
from .github import GitHubClient, GitHubError


@dataclass(frozen=True)
class HuntError:
    repository: str
    error: str


@dataclass(frozen=True)
class HuntResult:
    project: str
    query: str
    assessments: list[Assessment]
    errors: list[HuntError]


def project_queries(project_key: str) -> list[str]:
    project = CANONICAL_PROJECTS[project_key]
    names = {project["name"], *project["aliases"]}
    return [f"{name} in:name" for name in sorted(names, key=str.lower)]


def hunt_project(
    client: GitHubClient,
    project_key: str,
    *,
    limit: int = 20,
    minimum_score: int = 20,
    on_progress: Callable[[str], None] | None = None,
) -> HuntResult:
    if project_key not in CANONICAL_PROJECTS:
        raise ValueError(f"unknown project: {project_key}")
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    if not 0 <= minimum_score <= 100:
        raise ValueError("minimum_score must be between 0 and 100")

    repos: dict[str, dict[str, Any]] = {}
    queries = project_queries(project_key)
    per_query = limit
    for query in queries:
        for repo in client.search_repositories(query, per_query):
            repos.setdefault(repo["full_name"].lower(), repo)
            if len(repos) >= limit:
                break
        if len(repos) >= limit:
            break

    assessments: list[Assessment] = []
    errors: list[HuntError] = []
    for repo in list(repos.values())[:limit]:
        full_name = repo["full_name"]
        if on_progress:
            on_progress(full_name)
        try:
            owner, name = full_name.split("/", 1)
            assessment = assess_repository(client.snapshot(owner, name))
            if assessment.score >= minimum_score:
                assessments.append(assessment)
        except GitHubError as exc:
            errors.append(HuntError(full_name, str(exc)))

    assessments.sort(key=lambda item: (-item.score, item.target.lower()))
    return HuntResult(
        project=CANONICAL_PROJECTS[project_key]["name"],
        query=" OR ".join(queries),
        assessments=assessments,
        errors=errors,
    )

