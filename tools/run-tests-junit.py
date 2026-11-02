#!/usr/bin/env python3
"""Run Ward's unittest suite and emit a dependency-free JUnit report."""

from __future__ import annotations

import argparse
import sys
import time
import unittest
from pathlib import Path
from xml.etree import ElementTree


class JUnitResult(unittest.TextTestResult):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.successes: list[unittest.case.TestCase] = []
        self.started_at: dict[unittest.case.TestCase, float] = {}
        self.durations: dict[unittest.case.TestCase, float] = {}

    def addSuccess(self, test: unittest.case.TestCase) -> None:
        self.successes.append(test)
        super().addSuccess(test)

    def startTest(self, test: unittest.case.TestCase) -> None:
        self.started_at[test] = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test: unittest.case.TestCase) -> None:
        started = self.started_at.pop(test, time.perf_counter())
        self.durations[test] = time.perf_counter() - started
        super().stopTest(test)


def split_test_id(test: unittest.case.TestCase) -> tuple[str, str]:
    identifier = test.id()
    class_name, _, method = identifier.rpartition(".")
    return class_name, method or identifier


def add_issue(
    case: ElementTree.Element,
    tag: str,
    test: unittest.case.TestCase,
    detail: str,
) -> None:
    issue = ElementTree.SubElement(case, tag, {"message": str(test)})
    issue.text = detail


def write_report(result: JUnitResult, elapsed: float, destination: Path) -> None:
    failures = dict(result.failures)
    errors = dict(result.errors)
    skipped = dict(result.skipped)
    suite = ElementTree.Element(
        "testsuite",
        {
            "name": "Ward Python tests",
            "tests": str(result.testsRun),
            "failures": str(len(failures)),
            "errors": str(len(errors)),
            "skipped": str(len(skipped)),
            "time": f"{elapsed:.6f}",
        },
    )

    for test in result.successes + [item[0] for item in result.failures + result.errors + result.skipped]:
        class_name, name = split_test_id(test)
        case = ElementTree.SubElement(
            suite,
            "testcase",
            {
                "classname": class_name,
                "name": name,
                "time": f"{result.durations.get(test, 0.0):.6f}",
            },
        )
        if test in failures:
            add_issue(case, "failure", test, failures[test])
        elif test in errors:
            add_issue(case, "error", test, errors[test])
        elif test in skipped:
            ElementTree.SubElement(case, "skipped", {"message": skipped[test]})

    destination.parent.mkdir(parents=True, exist_ok=True)
    tree = ElementTree.ElementTree(suite)
    ElementTree.indent(tree, space="  ")
    tree.write(destination, encoding="utf-8", xml_declaration=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-directory", default="tests")
    parser.add_argument("--output", default="reports/python.xml")
    args = parser.parse_args()

    suite = unittest.defaultTestLoader.discover(args.start_directory)
    runner = unittest.TextTestRunner(verbosity=2, resultclass=JUnitResult)
    started = time.perf_counter()
    result = runner.run(suite)
    elapsed = time.perf_counter() - started
    write_report(result, elapsed, Path(args.output))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
