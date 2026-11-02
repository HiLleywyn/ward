$ErrorActionPreference = 'Stop'
$Error.Clear()
$request = Get-Content -LiteralPath 'C:\WardInput\request.json' -Raw | ConvertFrom-Json
$root = Join-Path $env:TEMP 'WardSample'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$sample = Join-Path $root 'sample.exe'
$bytes = [Convert]::FromBase64String($request.content_base64)
[IO.File]::WriteAllBytes($sample, $bytes)
$digest = (Get-FileHash -LiteralPath $sample -Algorithm SHA256).Hash.ToLowerInvariant()
if ($digest -ne $request.sha256) { throw 'Artifact digest mismatch inside Windows Sandbox' }

function Get-ProfileFiles {
    $values = @{}
    Get-ChildItem -LiteralPath $env:USERPROFILE -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 5000 | ForEach-Object {
            $values[$_.FullName] = "$($_.Length):$($_.LastWriteTimeUtc.Ticks)"
        }
    return $values
}
function Get-RunKeys {
    $values = @{}
    foreach ($path in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
                       'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
                       'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
        if (Test-Path $path) { $values[$path] = (Get-ItemProperty $path | Out-String).Trim() }
    }
    return $values
}

$beforeFiles = Get-ProfileFiles
$beforeRun = Get-RunKeys
$events = @()
$telemetryErrors = @()
$subscription = $null
$process = $null
$launchError = $null
try {
    $subscription = Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier WardProcessStart
} catch { $telemetryErrors += $_.Exception.Message }
try {
    $process = Start-Process -FilePath $sample -WorkingDirectory $root -PassThru -ErrorAction Stop
} catch { $launchError = $_.Exception.Message }
$deadline = (Get-Date).AddSeconds(60)
if ($process) {
    while ((Get-Date) -lt $deadline) {
        foreach ($event in @(Get-Event -SourceIdentifier WardProcessStart -ErrorAction SilentlyContinue)) {
            if ($events.Count -lt 500) {
                $entry = $event.SourceEventArgs.NewEvent
                $events += @{pid=[int]$entry.ProcessID; parent_pid=[int]$entry.ParentProcessID; name=[string]$entry.ProcessName}
            }
            Remove-Event -EventIdentifier $event.EventIdentifier -ErrorAction SilentlyContinue
        }
        Start-Sleep -Milliseconds 250
    }
}
if ($subscription) { Unregister-Event -SourceIdentifier WardProcessStart -ErrorAction SilentlyContinue }
$afterFiles = Get-ProfileFiles
$changed = @($afterFiles.Keys | Where-Object { -not $beforeFiles.ContainsKey($_) -or $beforeFiles[$_] -ne $afterFiles[$_] } | Select-Object -First 200)
$afterRun = Get-RunKeys
$descendantIds = @()
if ($process) {
    $descendantIds = @($process.Id)
    for ($round = 0; $round -lt 10; $round++) {
        foreach ($entry in $events) {
            if ($entry.parent_pid -in $descendantIds -and $entry.pid -notin $descendantIds) { $descendantIds += $entry.pid }
        }
    }
}
$defender = @()
try { $defender = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 20 ThreatID,InitialDetectionTime,ActionSuccess,Resources) }
catch { $telemetryErrors += 'Windows Defender telemetry unavailable' }
$result = @{
    sha256=$digest
    executed=[bool]$process
    root_pid=$(if ($process) {$process.Id} else {$null})
    launch_error=$launchError
    processes=@($events | Where-Object {$_.pid -in $descendantIds})
    profile_changes=$changed
    run_keys_before=$beforeRun
    run_keys_after=$afterRun
    defender=$defender
    telemetry_errors=$telemetryErrors
    duration_seconds=$(if ($process) {60} else {0})
    windows_build=[Environment]::OSVersion.Version.ToString()
    network='disabled'
}
$json = $result | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText('C:\WardOutput\result.json', $json, (New-Object Text.UTF8Encoding($false)))
