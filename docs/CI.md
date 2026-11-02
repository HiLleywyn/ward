# Continuous integration

The git.lley.cat Tests page uses the repository's Actions configuration stored
by the Git gateway. It is separate from `.forgejo/workflows/tests.yml` and
`.github/workflows/tests.yml`.

The checked-in configuration is [integrations/lley-ci.json](../integrations/lley-ci.json).
Apply it with `PUT /api/repositories/:id/actions`, passing the current gateway
configuration version and the file contents as `config`. Changes to this file
do not update the hosted configuration automatically.

Every hosted run creates a fresh virtual environment, installs Ward and its
declared dependencies from `pyproject.toml`, and runs `pip check` before the
tests. The only external HTTPS destinations are `pypi.org` and
`files.pythonhosted.org`. No credentials are needed for dependency downloads.
The HTTP test clients connect directly to their own loopback servers, independent
of the runner's download proxy.

The Python test runner writes `reports/python.xml`; the web integrity checks
write `reports/ci.xml`. Both reports feed the Tests page. Dependency installation
errors fail the job before test execution.

For local tests, install Ward first:

```text
python -m pip install -e .
python -m pip check
python tools/run-tests-junit.py
node tools/ci-check.mjs
```
