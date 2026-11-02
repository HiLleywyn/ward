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

This command requires an operator with local Docker access. The public web
service has no Docker socket and cannot launch analysis containers. Reports
are returned to the operator; they are not automatically added to public scan
history or used to rewrite previous evidence records. Public REST/MCP scans
continue to use Ward's bounded static engine.

This is deeper static analysis, not a behavioral sandbox or Ward's reserved
Verified tier. Executing Windows malware needs a separate disposable Windows
VM, isolated networking, controlled telemetry, and a verified reset mechanism.
REMnux can support that lab, but a container on the service host does not provide
that boundary.
