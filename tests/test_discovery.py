from __future__ import annotations

import unittest

from ward.discovery import hunt_project, project_queries
from ward.github import RepositorySnapshot


class FakeClient:
    def search_repositories(self, query: str, limit: int = 20):
        return [
            {"full_name": "boykopovar/AnyPS5"},
            {"full_name": "new-user/AnyPS5"},
        ]

    def snapshot(self, owner: str, repository: str):
        canonical = owner == "boykopovar"
        return RepositorySnapshot(
            repository={
                "full_name": f"{owner}/{repository}",
                "name": repository,
                "owner": {"login": owner},
                "created_at": "2026-08-03T21:30:25Z" if canonical else "2026-10-30T00:00:00Z",
                "fork": False,
                "size": 5000,
            },
            owner={"login": owner, "created_at": "2020-01-01T00:00:00Z"},
            releases=[],
            readme="",
        )


class DiscoveryTests(unittest.TestCase):
    def test_queries_include_alias(self):
        self.assertIn("AnyPS5 in:name", project_queries("anyps5"))

    def test_hunt_filters_below_threshold(self):
        result = hunt_project(FakeClient(), "anyps5", limit=10, minimum_score=20)
        self.assertEqual([item.target for item in result.assessments], ["new-user/AnyPS5"])
        self.assertEqual(result.errors, [])

    def test_unknown_project_rejected(self):
        with self.assertRaises(ValueError):
            hunt_project(FakeClient(), "nope")


if __name__ == "__main__":
    unittest.main()
