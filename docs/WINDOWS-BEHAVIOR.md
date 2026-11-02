# Windows behavior

Ward can execute a selected repository artifact inside a fresh Windows Sandbox
after the host worker proves that Sandbox can launch a benign Windows binary,
collect telemetry, and tear down cleanly. Until that smoke test passes, the API
reports the Windows worker unavailable and rejects behavioral requests rather
than silently downgrading them.

## Boundary

- Windows Sandbox is started for one artifact and stopped after the bounded run.
- Networking, clipboard, GPU, audio, video, and printer redirection are disabled.
- The input mapping is job-specific and read-only.
- The output mapping is job-specific, monitored, and limited to bounded JSON telemetry.
- No personal folder, credential, browser profile, USB device, or service secret is mapped.
- Ward refuses to attach to or stop a Sandbox instance it did not create.

The guest runs for at most 60 seconds inside a 180-second outer deadline. It
records process starts, profile file changes, selected startup registry keys,
and Defender detections. Offline execution can prevent later stages from
running. Guest telemetry can be incomplete or altered by the sample.

## Host setup

Run `tools/windows/Enable-WardSandbox.ps1` from an elevated PowerShell session,
restart Windows when the script records `restart_needed: true`, then register
the controller with `tools/windows/Register-WardWorker.ps1`. The registration
does not restart Windows.

At the next sign-in the controller waits for `wsb.exe`, runs the benign smoke
test, then sends a current heartbeat through Ward's private worker bridge. Only
then does `GET /api/v1/engines` show Windows behavior as available.

## Evidence status

Windows behavior is attached to the immutable originating scan as a separate
analysis record. It is SHA-256-bound to a scanned artifact and has its own
evidence digest. It remains `partial` and does not issue Ward's reserved
`Verified` tier.
