# Ward issue fixes and release verification

Released revision: `47fdbc084594f191ef1ede588cfb7787c1a83901`.

## Fixes

| Issue | Change | Fix commit |
| --- | --- | --- |
| #1 | Keep repository identity scoped to its Git host; shorthand means GitHub. | `d227d0b` |
| #2 | Preserve ClamAV matches alongside warnings, nonzero exits and partial output. | `36ca8db` |
| #3 | Include bound antivirus findings in history, comparisons and the ledger without rewriting static evidence. | `a9c2525` |
| #4 | Retain previous completed evidence while a refresh is pending or unsuccessful, explicitly labeled as previous. | `af6329e` |
| #5 | Renew REMnux worker availability during bounded analysis; stop renewal on exit or lifetime expiry. | `7697815` |
| #6 | Merge Python branch flows conservatively and clear overwritten sensitive paths/data. | `10d368d` |
| #7 | Share archive byte, entry and time budgets across the repository and report exhausted coverage as partial. | `e4e726f` |

Cross-surface regressions were committed in `3ac3a30`. Requested UI changes were preserved in `47fdbc0`: lighter parent accordions (`#25241f`), darker child rows (`#11110f`), structured evidence reports, inline code, shared family guidance and contained report overflow.

## Verification

- Hosted CI run `8904a5eb-7224-4307-b68e-c00f54c5bc3e` tested the released revision: **161 Python tests and 16 integrity checks passed**, with no failures, errors or skips.
- The exact built Linux image also passed all 161 Python tests. Tests used harmless fixtures, including synthetic antivirus output; no malware was executed for release verification.
- Both deployed services are healthy. All 40 installed package files in each service match the release snapshot byte-for-byte.
- Environment values, state volume, networks, read-only settings, dropped capabilities, security options, memory/PID limits, users and published ports were compared with the previous deployment. The analysis worker's previous Docker Desktop proxy socket mount was restored through a deployment override.
- Public health and engine endpoints respond successfully. REST and MCP return identical history for a repository with 10 recorded scans. The same path on another Git host returns zero scans.
- A harmless text fixture completed isolated REMnux analysis through the deployed worker's Docker connection. File identification and ClamAV completed; PE-specific tools correctly returned not-applicable. No indicators were detected; that is not a general safety guarantee.
- The live interface was inspected at desktop and mobile widths. Accordion expansion works, requested colors are present, and long report content stays within its scroll region without widening the page.

## Limits

- Warning/timeout handling, antivirus-positive ledger transitions, unsuccessful refreshes, branch-flow controls and archive exhaustion were verified with controlled regressions, not production fault injection.
- Archive elapsed-time checks are cooperative between members/read chunks. They cannot interrupt a single native parser or decompressor call.
- Python tracing remains bounded static analysis, not complete program understanding.
- Windows behavioral analysis was unavailable at verification time and was not exercised or changed by this release.
- Concurrent unfinished FLOSS/Ghidra work was preserved outside the released snapshot.
