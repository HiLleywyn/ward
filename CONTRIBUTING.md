# Contributing indicators

The purpose of this registry is to protect users without falsely accusing
developers.

## Accepted evidence

At least one of the following is required for a confirmed malicious indicator:

- a primary report from a security vendor, project maintainer, hosting provider,
  or law-enforcement body that identifies the exact indicator;
- a reproducible static analysis showing the exact file or repository revision
  performs malicious behavior;
- direct written confirmation from the affected project or GitHub Security.

Two secondary reports can justify a campaign warning, but not a specific
repository or file accusation when neither publishes the underlying indicator.

## Required fields

File indicators require SHA-256, first-seen date, source URL, source type,
impersonated project, and a short validation note. Repository records require a
full URL and an immutable commit or release reference where possible.

## Labels

- `confirmed`: exact evidence supports the claim.
- `suspected`: evidence warrants private review but is not ready for publication.
- `removed`: the indicator was previously confirmed but the hosted object is gone.
- `disputed`: credible contrary evidence exists and the record is under review.
- `false-positive`: the claim was incorrect. Keep a tombstone so it is not
  accidentally re-added.

## Prohibited submissions

- malware binaries, live payload URLs, credentials, or personal data;
- reports based only on a new account, low star count, unsigned binary, or
  antivirus false positive;
- automated bulk reports to GitHub or other providers;
- claims copied from AI output without independently inspectable evidence.

## Corrections

Corrections should be handled with the same urgency as new indicators. Provide
the disputed record, contrary evidence, and a safe contact method. A record can
be withdrawn without deleting its audit history.

