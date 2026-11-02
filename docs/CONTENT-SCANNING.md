# Content scanning

Ward 0.8 inspects bounded file contents independently of filename extensions.
An extensionless script or Lua text named `.exe` receives source inspection;
only content with an executable signature is eligible for binary analysis.

## Layers

- SHA-256 matches against Ward's reviewed indicators, including archive members.
- UTF-8 and BOM-marked UTF-16 text inspection across filenames.
- Python syntax-tree checks for Discord abuse, decoded execution, sensitive
  file data reaching network uploads, reverse shells, destructive tree removal,
  and encryption/write loops. Data-flow checks cover common local assignments
  and containers, not every possible runtime path.
- Lua checks for immediate remote-code loading and IP/geolocation data carried
  into webhook uploads. Comments and string examples are excluded.
- Existing PowerShell, shell, persistence, and protection-disabling signatures.
- ZIP and ZIP-based packages/documents, TAR, gzip, bzip2, XZ, and nested members
  read as streams without writing archive paths to the host.
- Extended mode sends a deterministic repository snapshot plus up to two
  genuine binaries to offline disposable REMnux containers. ClamAV scans the
  snapshot, including its supported nested containers; PE inspection, packer
  detection, and capa inspect applicable binary artifacts separately.

## Evidence and limits

Static behavior findings produce `Suspicious`; they do not establish a malware
family or prove malicious intent. Exact reviewed hashes and completed antivirus
signature detections can produce `Malicious`. Antivirus matches retain the engine,
signature names, database versions, artifact SHA-256, and analysis-image digest.
Antivirus limit alerts are incomplete coverage, not malware detections.

The original static result stays immutable. `assessment` projects subsequent
validated analysis results into the current API verdict, website, and badge.
README actions wait for analysis jobs and fail on partial analysis coverage.

Text analysis is limited to 2 MiB per file; Python/Lua structural checks have
smaller parser limits. In-process archive reading shares a 32 MiB expansion
budget, 500 member limit, and depth limit of three. Links, traversal entries,
encrypted members, malformed archives, unsupported formats, and reached limits
are reported explicitly. LFS pointers and submodule definitions report missing
external content. RAR/7z require the isolated engine for member scanning;
Ward does not claim in-process coverage for them.

The antivirus snapshot is limited to about 31 MiB including entry overhead and
5,000 files. Omitted files are counted. Antivirus has its own expansion/time
limits, so a completed static scan does not imply completed antivirus coverage.
Offline analysis cannot inspect later network payloads, determine every possible
runtime behavior, or prove that software is safe. Linux/macOS binaries do not
receive Windows behavioral execution.

## Signature maintenance

Build the analysis image before deploying the controller:

```text
docker build --no-cache --file Dockerfile.remnux --tag ward-remnux:0.8.0 .
```

The build pins its REMnux base and downloads vendor-validated ClamAV databases
using freshclam. Analysis children have no network and resolve the installed
image to an immutable ID for every report. Rebuild this image to refresh
signatures; a routine scan does not download signatures. Each report exposes
database versions and publication timestamps so stale data remains visible.
