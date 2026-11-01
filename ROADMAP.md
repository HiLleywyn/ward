# Roadmap

The long-term goal is to make malware impersonation expensive, short-lived,
and easy for ordinary players to recognize. A blacklist and a score are only
the beginning.

## Phase 1: Defensive core

Status: working locally

- Separate confirmed indicators, reported campaigns, project identity anchors,
  provenance controls, and unverified candidates.
- Inspect GitHub metadata without downloading release binaries.
- Calculate local file hashes without uploading or executing files.
- Provide a friendly local web interface and a scriptable CLI.
- Validate advisory data and run regression tests in CI.
- Preserve an explicit correction and false-positive process.

## Phase 2: Discovery and evidence preservation

- Expand project identity anchors through reciprocal verification with official
  project sites and maintainers.
- Run bounded searches for exact-name clones, typo variants, fake installers,
  recently created release repositories, and external download redirects.
- Capture immutable repository, commit, tag, release, asset, owner, certificate,
  and SHA-256 metadata before malicious repositories disappear.
- Add authenticated, rate-limited GitHub monitoring with checkpoints so scans
  do not repeatedly consume the same API budget.
- Keep discovery results private until they are validated.
- Request exact indicators from security vendors when public reporting omits
  the data users need to protect themselves.

## Phase 3: Safe static triage

- Add archive inventory with strict file-count, path, nesting, and expanded-size
  limits. Never unpack untrusted archives onto ordinary user paths.
- Parse PE metadata without loading executable code.
- Extract Authenticode signer information, certificate subjects, timestamps,
  imports, section layout, entropy, embedded URLs, and suspicious command text.
- Add YARA-compatible defensive rules for validated campaign traits.
- Compare GitHub-provided release digests against optional reputation services
  before downloading anything.
- Keep dynamic execution out of the end-user tool. Any future detonation system
  must be a separately reviewed, disposable, network-controlled environment.

## Phase 4: Campaign clustering

- Link rotating repositories through exact hashes, fuzzy hashes, certificate
  reuse, signer patterns, file structure, filenames, download infrastructure,
  build metadata, and behavioral rules.
- Distinguish copied malicious payloads from unrelated repositories that happen
  to share a project name.
- Record first seen, last seen, removal status, confidence, source provenance,
  and analyst decisions.
- Produce machine-readable feeds without publishing live malware download URLs.

## Phase 5: Player-facing protection

- Publish a fast static advisory site with clear project locations, current
  campaigns, exact indicators, corrections, and recovery instructions.
- Add a browser extension that warns on unverified GitHub release pages while
  preserving a click-through path and explaining every signal.
- Add a Windows shell integration that can hash a download and open the local
  explanation without launching the file.
- Provide QR-friendly incident instructions for users who need to change
  passwords from a different device.
- Localize the high-risk warnings and recovery guide.

## Phase 6: Coordinated disruption

- Generate a compact evidence bundle for GitHub containing immutable URLs,
  hashes, asset metadata, validated behavior, and the impersonated project.
- Notify project maintainers through their declared security channel.
- Report only validated active malware or impersonation. Never automate the
  final abuse submission.
- Track acknowledgements, takedowns, reappearances, corrections, and disputes.
- Share defensive indicators with antivirus and browser-protection vendors.

## Phase 7: Governance and durability

- Publish a transparent confidence rubric and changelog.
- Give maintainers a fast correction and appeal path.
- Require two-person review before a public malicious-repository label when an
  exact vendor or platform confirmation is unavailable.
- Sign releases and advisory snapshots.
- Maintain reproducible builds and provenance for the checker itself.
- Measure time to detection, time to validation, time to removal, recurrence,
  false positives, and user-facing warning usefulness.

## Success measures

- Confirmed indicators are published quickly and can be independently checked.
- Unverified leads do not leak into public accusations.
- Players can identify the intended project location in under one minute.
- A suspicious file can be hashed and explained without running or uploading it.
- Valid abuse reports contain enough evidence for a platform response without a
  long clarification cycle.
- Corrections are visible, fast, and auditable.

