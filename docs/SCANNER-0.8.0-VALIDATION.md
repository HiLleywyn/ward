# Ward 0.8.0 release verification

Verified on November 2, 2026. Implementation revision:
`acbc69b4b86e27b4ec22ca212e67a6f0728a0a9e`.

## Delivered

- Content-based inspection of decodable files, including extensionless scripts,
  Lua disguised as `.exe`, and BOM-marked UTF-16.
- Bounded Python syntax-tree checks for sensitive file uploads, Discord abuse,
  decoded execution, reverse shells, destructive tree removal, and bulk file
  encryption. Lua checks cover immediate downloaded-code execution and common
  IP/geolocation-to-webhook assignment chains.
- Nested ZIP, ZIP-based packages/documents, TAR, gzip, bzip2, and XZ inspection.
  Member hashes and source findings retain their archive paths. No member paths
  are extracted onto the host. Unsafe, encrypted, unsupported, and oversized
  content produces explicit incomplete-coverage evidence.
- Extended analysis submits a deterministic repository snapshot and up to two
  genuine executable artifacts to isolated REMnux analysis. ClamAV now has
  installed vendor-validated databases and scans the whole submitted snapshot.
- API, MCP, reports, recent scans, scan pages, badges, and README actions use
  validated follow-up evidence. The original static result remains immutable.
  Actions wait for follow-up jobs and fail on incomplete follow-up coverage.
- Timeouts preserve completed tool output. Antivirus detections completed before
  a timeout remain usable evidence with partial coverage. Parser limits are no
  longer mislabeled as archive failures.

See [Content scanning](CONTENT-SCANNING.md) for exact budgets and maintenance.

## Regression checks

Hosted CI for the implementation revision:
`7ef7eed8-edac-4e98-bf4c-fcd3f04f9cfe`.

109 Python tests and 10 integrity checks passed: 119 total, zero failures,
errors, or skips. This includes six Linux-only REMnux tests. Windows local
execution passed its applicable tests; the six Linux-only tests were skipped
there and executed in hosted Linux CI.

Coverage includes archive nesting, encrypted/unsupported/malformed entries,
byte/depth/count limits, traversal and links, exact member hashes, source
data-flow positives, inert examples and unrelated uploads as negative controls,
JavaScript/Python discrimination, filename spoofing, UTF-16, timeout evidence,
analysis binding, immutable evidence digests, badge propagation, and action
waiting/failure behavior. Registry validation, dependency checks, Python
compilation, JavaScript parsing, and package integrity also passed.

## Live checks

### Extensionless Lua repository

[Scan record](https://ward.lley.cat/scans/ad7f0fdc-f007-4c66-bdca-b99629ff9eab)

`01010101010x/010100101`, revision
`565d7996417a818297097200e299226c2a1826cf`:

- All 157 files were hashed; 157 text files received inspection, compared with
  two in the previous scan. No file was a genuine executable.
- Four IP/geolocation webhook flows: `Giveawaylog:17`, `extf:149`,
  `wwwwww:48`, and `zzz:159`. Destination credentials were not reproduced.
- 38 immediate Lua remote-code loaders were flagged separately.
- Four oversized Lua files retain explicit parser-limit findings. Overall
  structural inspection is partial; the antivirus snapshot included all 157
  files with zero omissions.
- ClamAV completed with no known signature match. The current verdict remains
  **Suspicious** because of source behavior, without inventing a malware family.
- The original 30-second antivirus deadline timed out on this workload. With
  the adjusted bounded deadline, the queued analysis completed in about 40
  seconds. The historical incomplete result was preserved.

Public REST and MCP returned the current assessment. Recent Scans, the persisted
scan page, report, and repository badge reflected it. Report evidence digest
matched the immutable scan digest.

### Benign control

[Scan record](https://ward.lley.cat/scans/5a6f3af5-34be-44bd-9da7-02956ff36167)

`HiLleywyn/ward`, revision
`405ff90f75b4e31cc69b64102a9112b8b44afe2b`: 91 files inspected, no static
findings, isolated antivirus completed without a signature match. Result:
**Unverified**, with inspected coverage. No safety guarantee was issued.
Submission and result rendering were exercised through the public website.

### Earlier Built.exe example

[Scan record](https://ward.lley.cat/scans/0c654f2f-f151-448a-88ae-dfab38b13d21)

`sjyjoghkkjj/Discord-Nitro-Generator`, revision
`451f057fa9c67739e37b8bcff2db7e2094e8c982`: the reviewed exact indicator
continues to produce **Malicious**, and its badge retains that verdict.
ClamAV did not independently match this file or its repository snapshot.
PE/packer inspection completed; packed payload capability analysis remains
partial and is not presented as completed behavioral execution.

### Antivirus positive control

The harmless standard EICAR antivirus test file was created only in memory,
wrapped in an in-memory ZIP, and sent to the same disposable REMnux path.
ClamAV returned `Eicar-Test-Signature` with completed coverage. No test payload
was executed or saved onto the host. EICAR is treated as a test/caution signal,
not an actual malware finding in the combined assessment.

## Installed runtime

- Ward image: `sha256:bf0289a70541bb860d38eea2b52eebd622df26dcd52801ee8bdab02f8806f87d`
- Controller image: `sha256:bd14f3f92687d9be132026157490f5e9cae25ebd45f16ea3ad0599d20f6a474e`
- REMnux image: `sha256:9a6756aedbc34b1c4a6190a6e8f03b2b37a3b7ac73ec25d30374ac3df618e968`
- ClamAV databases: daily 28171, main 63, bytecode 339; 3,642,948 signatures.
  Database publication timestamps are retained in each report.

The live health endpoint and MCP report 0.8.0. All 37 packaged Python, web,
configuration, and guest-script files matched the checkout after normalizing
line endings. Both services were healthy, non-root, read-only, with dropped
capabilities. Existing state volume, ingress network, loopback binding, and
controller network isolation were preserved. Analysis children had no network,
host mounts, or sample execution.

## Remaining limits

These are bounded static checks, not complete program semantics. Structural
source tracing currently targets Python and Lua; other decodable source still
receives configured text rules and the isolated antivirus layer. RAR/7z member
coverage depends on the isolated engine and is explicitly unsupported by the
in-process reader. Large, encrypted, obfuscated, external/LFS/submodule, or later
downloaded content can remain unresolved. ClamAV missing a known malicious
artifact is documented above, not concealed by its successful engine status.

Signature refresh currently requires rebuilding the analysis image; it is not
an automatic update service. Windows behavioral execution remains limited to
eligible PE artifacts and was not rerun for this static-scanner release. No
new result claims that the previously encrypted payload was resolved.
