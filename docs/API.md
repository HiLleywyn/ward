# Ward API

Ward exposes a versioned REST API at `https://ward.lley.cat/api/v1` and a stateless MCP Streamable HTTP endpoint at `https://ward.lley.cat/mcp`.

The complete OpenAPI 3.1 contract is available at:

```text
https://ward.lley.cat/api/v1/openapi.json
```

## Architecture

Ward keeps one evidence model across its website, REST API, MCP tools, and CLI:

- The existing static scanner clones public HTTPS Git repositories into a temporary directory and never executes their code.
- A single bounded background worker serializes asynchronous repository scans.
- Eligible executables from Extended scans are copied into a durable bounded
  analysis queue, then removed as soon as an isolated worker finishes or fails.
- The REMnux controller is separate from the public web container. Windows
  behavior runs only through a verified host worker and disposable Sandbox.
- SQLite stores lifecycle state, reports, exact commits, branches, and historical comparisons.
- Existing website scans and API or MCP repository scans populate the same Recent Scans history.
- Reviewed Malware Records remain curated source evidence. Automated scans cannot promote themselves into that database.
- File contents are inspected transiently, deleted after analysis, and never returned through public artifact lookup.

No GraphQL, gRPC, queue service, or additional database was introduced.

## Scan lifecycle

```text
queued -> running -> completed
                  -> failed
queued -> cancelled
queued/running -> incomplete after a worker restart
```

Running Git clones cannot currently be interrupted safely. Cancellation is therefore supported only while a job remains queued. A newly created scan returns an `X-Ward-Cancel-Token`; Ward stores only its SHA-256 digest.

Completed repository scans record the normalized repository URL, exact commit, checked branch or tag, findings, sources, verification tier, evidence digest, and stated limitations. Historical comparisons report findings that appear or disappear between two scanned revisions. They do not claim that an unscanned intermediate commit was safe or establish author intent.

## Submit a repository scan

```bash
curl -i https://ward.lley.cat/api/v1/scans \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: example-repository-main-1" \
  --data '{"kind":"repository","url":"https://github.com/owner/repository","ref":"main","expected_commit":"0123456789abcdef0123456789abcdef01234567","analysis":"extended"}'
```

The response is `202 Accepted` for a new job and `200 OK` when the same idempotency key and request are replayed. Reusing a key for a different request returns `409 Conflict`.

`expected_commit` closes the branch-movement race used by CI. Ward fails the job if the cloned ref does not resolve to that exact object ID.

Repository analysis modes are:

- `static`: clone, hash, source rules, bounded archive inspection, and reviewed indicators.
- `extended`: static plus automatic offline REMnux analysis for at most two discovered Windows executables.
- `behavioral`: extended plus disposable offline Windows Sandbox execution when the verified Windows worker is online.

`GET /api/v1/engines` reports current worker availability. A behavioral request
fails with `503` instead of silently downgrading when the Windows worker is not
available. Follow-up analyses are attached to the scan as `analyses`; they can
still be queued when the repository scan itself reaches `completed`.

## Submit a SHA-256 lookup

```bash
curl https://ward.lley.cat/api/v1/scans \
  -H "Content-Type: application/json" \
  --data '{"kind":"sha256","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}'
```

An unknown hash means only that Ward did not find it in the reviewed indicator registry.

## Submit a transient file

REST accepts one base64-encoded file up to 5 MiB:

```json
{
  "kind": "file",
  "filename": "sample.bin",
  "content_base64": "..."
}
```

The file is written only inside the scanner's temporary directory. Ward stores the SHA-256, bounded findings, and report, but not the bytes. File and raw-hash jobs are unlisted and require their unpredictable scan ID for later retrieval.

## Retrieve results

```text
GET /api/v1/scans/{scan_id}
GET /api/v1/scans/{scan_id}/events
GET /api/v1/reports/{scan_id}
GET /api/v1/scans?limit=20&cursor={scan_id}&status=completed
```

The events endpoint emits bounded server-sent events until the job reaches a terminal state or the connection window ends.

Report verdicts are:

- `malicious`: exact reviewed indicator evidence was detected.
- `suspicious`: repository-specific research or bounded source-behavior evidence warrants review without an exact artifact match.
- `unknown`: analysis completed without enough evidence for a conclusion.
- `incomplete`: the job failed, was cancelled, or did not finish reliably.

Ward does not define or issue a `clean` verdict. Reports separately describe verification coverage:

- `observed`: a registry lookup was completed without receiving the artifact.
- `partial`: Ward reached an inspection bound.
- `inspected`: Ward completed its configured bounded static inspection.
- `verified`: reserved for a stronger attested build and behavioral-analysis tier. Ward does not currently issue it.

The evidence digest content-addresses the exact persisted result. It detects accidental result changes, but it is not a third-party digital signature.

## Historical ledger

```text
GET /api/v1/repositories/history?target=owner/repository
GET /api/v1/comparisons?base_scan={id}&head_scan={id}
```

Repository history returns chronological scans, observed verdict transitions, and related scanned repositories that share an exact commit. A `shared_commit` relationship is evidence of shared history, not proof of current ownership or fork ancestry.

GitHub repositories can use `/api/v1/badges/{owner}/{repository}.svg`. Other public HTTPS Git hosts use `/api/v1/badge.svg?repository={encoded_url}` and link to `/repository?target={encoded_url}`. This includes public git.lley.cat repositories. Private repositories cannot be cloned by the anonymous public service.

## Malware records and artifacts

```text
GET /api/v1/malware-records
GET /api/v1/malware-records/{record_id}
GET /api/v1/artifacts/{sha256}
```

Artifact lookup exposes only reviewed public indicators and public repository-scan history. It never reveals a private file or hash submission.

## MCP

Ward's public MCP endpoint supports stateless Streamable HTTP and protocol version `2025-06-18`. It exposes tools for submitting repository or SHA-256 scans, retrieving scans and reports, recalling repository history, comparing scans, generating repository badge Markdown, listing reviewed Malware Records, and looking up public artifact evidence.

The MCP interface intentionally omits file uploads. Use REST only when a user explicitly authorizes sending a file to Ward for transient inspection.

A portable plugin package and Ward skill are under `integrations/ward-plugin`.

## Security and limits

- Public submissions have no hourly allowance. A bounded queue, one repository worker, and an eight-job follow-up queue control simultaneous work.
- Git hosts are restricted to public HTTPS on port 443. Credentials, fragments, query strings, local addresses, and private DNS results are rejected.
- The scanner pins the validated public IP in libcurl for the clone to reduce DNS-rebinding risk and disables Git HTTP redirects, file protocol, ext protocol, prompts, and LFS downloads.
- Repository, file count, byte, hash, text, archive expansion, process, memory, and request body limits remain enforced.
- API errors use `{error:{code,message,request_id}}`. Unexpected exceptions are not returned to clients.
- Ward has no account system or user-generated API keys in this release. Anonymous access is deliberately constrained. The cancellation capability is the only per-job write authority.
- Webhooks are not implemented because safe delivery requires a durable retry and SSRF policy that Ward does not yet need.
- STIX export is not implemented because Ward's present evidence does not benefit from a lossy mapping merely to claim format support.
- REST file-scan bytes live only in process memory. If Ward restarts before processing them, the job becomes `incomplete` and the bytes are gone.
- Automatic repository-artifact bytes are stored only in the dedicated analysis queue. They are hash-bound to the completed scan and cleared on completion, failure, expiration, or originating-scan recovery.
- The web scanner never executes repository code. REMnux treats samples as data. Optional Windows behavior executes only inside a disposable offline Sandbox and remains `partial`, not `verified`.
