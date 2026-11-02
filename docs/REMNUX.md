# REMnux static analysis

Ward's operator CLI can run a selected file through the official REMnux
container. It adds file identification, PE headers, imports, section entropy,
Detect It Easy signatures, and capa's static capability results for unpacked
PE files. Samples are never executed.

## Setup

Install Docker with Linux containers, then pull the official image:

```text
docker pull remnux/remnux-distro:noble
```

The image needs approximately 6 GB to download and 14 GB on disk, plus temporary
working space. See [REMnux's container documentation](https://docs.remnux.org/install-distro/remnux-as-a-container).

## Analyze a file

```text
ward remnux sample.exe --sha256 EXPECTED_SHA256
```

The command prints a JSON evidence report. The expected hash is optional, but
should be supplied when investigating a known repository artifact. Input files
are limited to 32 MiB. A mismatch stops before a container starts.

The runner resolves the installed image to its immutable local image ID and
records the registry digest. It sends sample bytes over standard input to a
fixed worker program. It creates no host mounts, published ports, or Docker
socket mounts. Each run uses an unprivileged user, a read-only root filesystem,
disabled networking, dropped capabilities, bounded memory/CPU/processes, and
an ephemeral noexec sample tmpfs. A separate scratch tmpfs allows execution
because capa's trusted bundled Python runtime needs to load shared libraries
there; the worker invokes only fixed installed tools and treats the sample as
data. The worker uses REMnux's dnfile Python environment, which includes pefile.
An outer 120-second deadline removes the container
even when the Docker client times out. Individual tools have shorter limits.

The report records each tool's outcome, including unavailable tools, errors,
output limits, and timeouts. capa's rules and version come from the pinned
REMnux image. Capability matches describe static evidence, not runtime actions
observed on a victim. No findings never establishes safety. Packed/encrypted
payloads can hide behavior from capa. Files with a PyInstaller archive marker
receive packer analysis but skip capa's native disassembly; the report records
that scope and remains partial because embedded Python and encrypted payload
behavior is unresolved. On the pinned sample, capa 9.3.1's full analysis exceeded
60 seconds, and its file-feature backend raised NotImplementedError. Neither
attempt established payload behavior.

## Boundary and current integration

The operator command requires local Docker access. Public Extended website,
REST, and MCP scans now queue at most two discovered Windows executables for the
same analysis automatically. A separate trusted controller owns the Docker
socket; the public web container does not. The controller passes bytes directly
to a disposable networkless child and writes the bounded result back to the
originating scan. It cannot rewrite the immutable base result or promote a
record into the curated malware database.

The analysis queue is capped at eight active jobs. Artifact bytes are
SHA-256-bound to a path in the completed scan and cleared after completion,
failure, expiration, or interrupted-scan recovery. `GET /api/v1/engines`
reports whether the controller has passed its smoke test and has a current
heartbeat.

This is deeper static analysis, not a behavioral sandbox or Ward's reserved
Verified tier. Optional Windows execution uses a separate disposable offline
Sandbox and is documented in [Windows behavior](WINDOWS-BEHAVIOR.md). That
partial telemetry still does not satisfy the stronger attestation requirements
for `Verified`.
