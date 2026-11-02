# Ward verification tiers

Ward separates what was checked from what was concluded. A repository can never earn a stronger badge merely because no indicator matched.

## Observed

Ward received an identifier such as a SHA-256 value and compared it with reviewed evidence. The artifact itself was not inspected.

## Partial

Ward received or cloned content, but at least one configured file, byte, archive, or time bound prevented full static coverage. A partial result fails the GitHub Action even when no indicator matched.

## Inspected

Ward pinned the exact Git revision, inventoried and hashed files within its published limits, inspected supported text and bounded archives, and ran the configured static rules. The record includes the exact commit, checks, limits, findings, and a content digest.

`Inspected` does not mean safe. Code can hide behavior in unsupported formats, encrypted content, dependencies fetched later, build output, or runtime-only paths.

## Verified

Reserved. Ward does not currently issue this tier.

A future Verified result requires all Inspected checks plus:

1. A dedicated malware-analysis VM outside the Ward web-service host.
2. A known-clean snapshot restored before every job.
3. No host folders, credentials, clipboard, USB devices, or management sockets exposed to the guest.
4. No route to the home or service network.
5. Network disabled by default, or routed only through a controlled simulator and packet capture.
6. A reproducible build when the project defines one, with dependencies and generated artifacts inventoried and hashed.
7. Bounded behavioral execution with process, filesystem, persistence, and attempted-network telemetry.
8. Authenticated result delivery from the worker to Ward.
9. Snapshot destruction or rollback after evidence collection.
10. An attestation binding the scanner version, policy version, exact commit, inputs, outputs, and engine results.

The [official REMnux virtual appliance guidance](https://docs.remnux.org/install-distro/get-virtual-appliance) is a suitable starting point. It provides prebuilt virtual-appliance formats and explicitly recommends verifying the download hash, updating the distro, and taking a snapshot. Ward still needs a separate controller, isolation policy, deterministic reset, and authenticated evidence protocol before it can safely automate that appliance.

Containers alone do not satisfy the Verified boundary. Ward will not mount the Docker socket or execute untrusted repositories on its public web host.

The [REMnux operator command](REMNUX.md) is available for deeper static file
analysis in a disposable offline container. It reports tool outcomes and exact
artifact/image digests. It does not issue Verified results or run sample code.
