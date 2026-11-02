# Ward GitHub Action and README badge

Ward can inspect the exact revision used by a GitHub Actions run, publish the result in the repository ledger, and provide a README badge linked to that ledger.

```yaml
name: Ward

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  ward:
    runs-on: ubuntu-latest
    steps:
      - uses: HiLleywyn/ward/.github/actions/ward@main
```

The action does not need a Ward key. It submits the public repository URL, branch, and exact Git commit. Ward rejects the scan if the branch moves before inspection, rather than recording evidence for the wrong revision.

The step summary contains the exact scan record and copyable badge Markdown. A badge links to the repository ledger:

```markdown
[![Ward](https://ward.lley.cat/api/v1/badges/OWNER/REPOSITORY.svg?branch=main)](https://ward.lley.cat/repositories/OWNER/REPOSITORY)
```

## Badge meanings

- `✓ inspected`: Ward cloned the exact revision and completed its configured bounded static checks without a configured indicator or rule match.
- `! suspicious`: source-backed repository evidence or a high-signal rule requires review.
- `✕ malware detected`: an exact confirmed malware indicator matched.
- `~ partial scan`: Ward reached a configured inspection limit.
- `~ incomplete`: the job failed, was cancelled, or was interrupted.
- `… scanning`: a new scan is in progress.
- `? not scanned`: Ward has no matching record for that repository and branch.

`Inspected` is not a promise that software is safe. The linked record identifies the exact commit, checks, limits, evidence digest, and findings. Ward reserves `verified` for a future isolated build and behavioral-analysis tier. That tier will not be issued until it runs outside the web-service host in a disposable sandbox boundary.

GitHub may cache badge images briefly. The exact workflow result and scan record remain authoritative.

## git.lley.cat and other Git hosts

The action script accepts any public HTTPS Git URL. Non-GitHub badges use the generic endpoint:

```markdown
[![Ward](https://ward.lley.cat/api/v1/badge.svg?repository=ENCODED_HTTPS_GIT_URL&branch=main)](https://ward.lley.cat/repository?target=ENCODED_HTTPS_GIT_URL)
```

This Markdown can be placed in a git.lley.cat README. A CI runner can invoke `.github/actions/ward/ward_scan.py` with the documented `WARD_*` environment variables even when it is not running on GitHub.

Ward can clone public git.lley.cat repositories immediately. Private repositories are not supported by anonymous scanning. Ward does not retain or use a git.lley.cat owner token; private scanning requires a future scoped upload capability and explicit retention policy.
