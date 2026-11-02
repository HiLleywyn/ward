---
name: ward-scanner
description: Use Ward to scan a public Git repository or inspect a SHA-256 when the user wants evidence-based malware analysis without executing the target.
---

# Ward Scanner

Use Ward's MCP tools for public Git repository and SHA-256 analysis.

## Workflow

1. Submit the repository URL or SHA-256 with `ward_submit_scan`. Reuse an idempotency key when retrying the same submission.
2. Poll `ward_get_scan` at a restrained interval until the scan is completed, failed, cancelled, or incomplete.
3. On a terminal state, use `ward_get_report` and explain the verdict, exact findings, evidence sources, and limitations.
4. Use `ward_lookup_artifact` only for reviewed public SHA-256 evidence. An absent record is not evidence of safety.
5. Use `ward_repository_history` to recall prior scans and shared-commit relationships. Use `ward_compare_scans` when the user asks what changed between two scans.

## Evidence boundaries

- `malicious` requires an exact reviewed indicator match.
- `suspicious` reflects repository-specific corroboration without an exact artifact match.
- `unknown` means Ward did not establish a conclusion. Never translate it to clean or safe.
- `incomplete` means analysis did not finish reliably. Preserve any available failure details.
- Ward performs bounded static inspection and does not execute installers, scripts, or repository code.
- Do not claim coverage beyond the report's stated limits or treat heuristic findings as confirmed malware.
- A previous `unknown` or `Unverified` scan was not proven safe. Describe newly observed findings at the later scanned commit rather than claiming an unscanned commit introduced malware.

The MCP endpoint intentionally omits file uploads. Use Ward's REST API for a user-authorized transient file scan.
