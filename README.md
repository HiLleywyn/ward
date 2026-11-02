# Ward

[![Ward](https://ward.lley.cat/api/v1/badges/HiLleywyn/ward.svg?branch=main)](https://ward.lley.cat/repositories/HiLleywyn/ward)

Public site: [ward.lley.cat](https://ward.lley.cat)

Developer interfaces: [REST API and MCP](docs/API.md) · [OpenAPI 3.1](https://ward.lley.cat/api/v1/openapi.json)

Repository maintainers can add the [Ward GitHub Action and linked README badge](docs/GITHUB-ACTION.md). The action binds each inspection to the exact workflow commit and publishes the result in Ward's repository ledger. [Verification tiers](docs/VERIFICATION-TIERS.md) define what each badge actually proves.

[Reviewed results and status history](docs/RESULTS.md) records 25 historical
repository warnings named by primary security research and 12 confirmed
SHA-256 indicators. The public malware database is stricter: it currently has
three repository records where the source identifies the repository, release
archive, and malicious path. Campaign-only associations remain in Coverage.
Community reports use the repository issue form and begin as UNKNOWN.

The [November 1 investigation](docs/HUNT-2026-11-01.md) covers 125 indexed PS5
repositories, two unresolved provenance leads, and current availability of
historical campaign repositories.

Ward clones public HTTPS Git repositories into a constrained container, records
the exact commit, hashes bounded files, inspects scripts and small archives, and
compares content against an evidence-backed malware indicator registry. It does
not execute repository code, installers, build scripts, or package hooks.

Completed results include an evidence digest and verification tier. `Inspected`
means Ward completed its configured static checks for that exact revision. It is
not a promise that the software is safe. Ward will reserve `Verified` for a future
isolated build and behavioral-analysis tier running outside the web-service host.

The public interface keeps every completed repository scan in a recent-scan
directory. A scan without a match is `Unverified`, never a safety guarantee.

## Why this exists

In October 2026, several outlets reported a NordVPN Threat Intelligence finding
about fake GitHub repositories impersonating AnyPS5 and KytyPS5. The reported
packages changed Microsoft Defender exclusions, launched a suspected
information stealer, and removed traces afterward.

The public reports did not provide repository URLs or file hashes. That means a
responsible warning list cannot name random same-name repositories as malware.
This project keeps three claims separate:

1. **Exact indicator match:** a file hash or URL matches evidence in the public
   registry.
2. **High-risk metadata:** a repository combines impersonation signals with
   dangerous instructions or suspicious release structure.
3. **No strong signals:** the bounded static scan found nothing decisive. This
   is not a safety guarantee.

## Install

Python 3.10 or newer is required.

```powershell
python -m pip install -e .
```

An optional `GITHUB_TOKEN` raises GitHub API rate limits. The token only needs
read access to public repositories.

## Check a GitHub repository

```powershell
emuwatch repo https://github.com/OWNER/REPOSITORY
emuwatch repo OWNER/REPOSITORY --json
```

The checker reads repository metadata, public account metadata, release asset
names and sizes, and README text. It does not request release asset contents.

## Use the repository scanner

```powershell
emuwatch web
```

This opens a local interface at `http://127.0.0.1:8787`. Paste a GitHub shorthand,
a GitHub URL, or another public HTTPS Git URL. Ward clones the repository into a
temporary directory, inspects it without running its code, stores the scan
record, then removes the checkout. Public scans are serialized, size-bounded,
and rate-limited.

The public interface no longer accepts file uploads. Local file hashing remains
available through the CLI below, where the file stays on your machine.

## Hunt for rotating lookalikes

```powershell
emuwatch hunt anyps5 --limit 20
emuwatch hunt kytyps5 --limit 50 --min-score 45 --json
```

Hunt mode searches GitHub by known project names, then applies bounded
metadata checks to a limited number of repositories. Its output is a
private review queue, not a malware blacklist. A repository must still be
validated before an indicator is published or a platform report is sent.

## Validate the registry

```powershell
emuwatch validate
```

Validation checks required fields, HTTPS evidence links, SHA-256 formatting,
and duplicate records before advisory data is published.

## Check a downloaded file

```powershell
emuwatch file C:\Users\you\Downloads\suspicious.zip
```

The file stays on your machine. The tool calculates SHA-256 locally and checks
it against `src/emuwatch/advisories/indicators.json`. A negative result only means the hash
is not currently in this small registry.

The checker also recognizes a small set of project-release assets in
`src/emuwatch/advisories/known-project-assets.json`. That can confirm where an exact file
came from, but it still does not guarantee that the file is safe.

## Current advisory status

News and threat research are kept in `src/emuwatch/advisories/campaigns.json`.
The initial PS5 campaign has no confirmed PS5 repository or hash indicators.
Repository-specific malware records are stored separately in
`src/emuwatch/advisories/malware-records.json`; campaign coverage alone is not
enough to enter that database.

Known project locations are listed separately in
`src/emuwatch/advisories/project-locations.json`. They are identity anchors, not blanket
safety guarantees.

## If you already ran a suspicious download

1. Disconnect the affected computer from the network.
2. From a different, known-clean device, change your email password first, then
   passwords for gaming, banking, social, and developer accounts.
3. Revoke active sessions and rotate authentication tokens.
4. Check Microsoft Defender exclusions and remove entries you did not create.
5. Run Microsoft Defender Offline or another trusted offline scan.
6. Preserve the download URL and calculate its SHA-256 before deleting it, if
   you can do so safely. Do not upload private files or personal data.
7. If account or financial data may have been stolen, consider rebuilding the
   system from trusted media instead of assuming cleanup was complete.

## Evidence policy

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: no malware samples, no mass
accusations, no automatic reporting, no dynamic execution in this project, and
no confirmed label without exact evidence.

## Reporting a confirmed malicious repository

Do not mass-report hunt results. First preserve the repository URL, immutable
commit or release reference, release asset name, SHA-256, and the evidence that
establishes malicious behavior. GitHub's documented path is the repository's
**Report repository** link or its abuse contact form. GitHub prohibits using
the platform to deliver malicious executables, while preserving legitimate
dual-use security research.

- Policy: https://docs.github.com/en/site-policy/acceptable-use-policies/github-active-malware-or-exploits
- Reporting steps: https://docs.github.com/en/communities/maintaining-your-safety-on-github/reporting-abuse-or-spam

## Sources

- [Check Point Research, "Gaming Engines: An Undetected Playground for Malware Loaders"](https://research.checkpoint.com/2024/gaming-engines-an-undetected-playground-for-malware-loaders/), November 27, 2024
- [TechSpot, "Gamers hunting for PS5 emulators on GitHub are downloading malware instead"](https://www.techspot.com/news/114376-gamers-hunting-ps5-emulators-actually-downloading-malware-instead.html), October 29, 2026
- [Tom's Hardware, "Fake PS5 emulators are being used to steal gamers' passwords"](https://www.tomshardware.com/tech-industry/cyber-security/fake-ps5-emulators-are-being-used-to-infect-gamers-computers-with-password-scraping-malware-two-well-known-github-repos-including-anyps5-hit), October 29, 2026
- [GitHub REST API release metadata](https://docs.github.com/en/rest/releases) for project identity, asset size, and SHA-256 records

## License

MIT. The advisory data is offered for defensive use and may contain incomplete
information. Always verify current project guidance before running software.

## Result history and privacy

Each CLI check appends an observation to a local SQLite database. Community
reports can be recorded with `emuwatch report`, and `emuwatch history` displays
the audit trail. UNKNOWN means review is needed; FAIL means a confirmed exact
indicator or a repository named in primary research. PASS applies only to a
specific reviewed claim and never means a program is guaranteed safe.

Public mode hides legacy local history and local file paths. Repository scan
records are intentionally public and contain repository paths, commit IDs,
findings, hashes that matched known indicators, and scan limits. The scanner is
globally capped at six clone attempts per hour and one active clone at a time.
The legacy GitHub metadata endpoint is cached for 15 minutes and capped at eight
fresh checks per hour. Local file hashing remains CLI-only.

Maintained by Lleywyn. No analytics or advertising scripts are included.

