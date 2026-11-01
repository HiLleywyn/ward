# Methodology

## Claim levels

### Confirmed malicious indicator

An exact repository revision, release asset, URL, certificate, or SHA-256 is
connected to malicious behavior by a primary source, reproducible static
analysis, or direct vendor or platform confirmation.

### Reported campaign

A credible source describes a campaign, but the public evidence does not expose
enough immutable indicators to identify a specific hosted object. The warning
may describe behaviors and impersonated projects, but must not accuse a current
repository by inference.

### High-risk metadata

A repository combines several review-worthy signals, such as an exact project
name under an unrelated owner, no fork relationship, recent creation, release
executables, external downloads, or instructions to weaken antivirus.

This is a triage result, not a malware verdict.

### Known project location or artifact

The repository or hash matches a documented project identity or release record.
This establishes provenance only. Maintainer compromise, build compromise, and
vulnerable software remain possible.

## Validation flow

1. Preserve immutable metadata and calculate hashes without execution.
2. Confirm which project is being impersonated through reciprocal official
   links or maintainer confirmation.
3. Establish source-to-behavior evidence through a primary report, static
   analysis, or isolated reproduction.
4. Run negative controls against the real project and known project assets.
5. Check for duplicate reports and prior false positives.
6. Assign a claim level and record limitations.
7. Have a second person review public malicious labels when practical.
8. Report active abuse through the platform's documented channel.
9. Track removal, recurrence, disputes, and corrections.

## Safety boundaries

- End-user checks do not run executables or scripts.
- Browser file checks do not upload file contents.
- Hunt mode does not automatically report repositories.
- Public advisories do not contain working live-malware download links.
- Malware samples are not stored in this repository.
- Suspicious repositories are not called malicious based on scores alone.
- A missing hash match is never presented as proof of safety.

## False-positive handling

False positives damage developers and train users to ignore warnings. A dispute
freezes escalation while contrary evidence is reviewed. If a claim is wrong,
the record changes to `false-positive`, the visible warning is withdrawn, and a
tombstone remains so the same mistake is not reintroduced later.

