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
$rootPid = $null
$executed = $false
$launchError = $null
try {
    $subscription = Register-CimIndicationEvent -Query 'SELECT * FROM Win32_ProcessStartTrace' -SourceIdentifier WardProcessStart
} catch { $telemetryErrors += $_.Exception.Message }
$launchJob = Start-Job -ScriptBlock {
    param($SamplePath, $WorkingDirectory)
    try {
        $started = Start-Process -FilePath $SamplePath -WorkingDirectory $WorkingDirectory -PassThru -ErrorAction Stop
        [pscustomobject]@{ id = [int]$started.Id; error = $null }
    } catch {
        [pscustomobject]@{ id = $null; error = $_.Exception.Message }
    }
} -ArgumentList $sample, $root
if (Wait-Job -Job $launchJob -Timeout 20) {
    $launchResult = Receive-Job -Job $launchJob
    $launchError = $launchResult.error
    if ($launchResult.id) {
        $rootPid = [int]$launchResult.id
        $executed = $true
        $process = Get-Process -Id $rootPid -ErrorAction SilentlyContinue
    }
} else {
    $launchError = 'Sample launch exceeded the 20 second limit'
    Stop-Job -Job $launchJob -ErrorAction SilentlyContinue
}
Remove-Job -Job $launchJob -Force -ErrorAction SilentlyContinue
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
if ($rootPid) {
    $descendantIds = @($rootPid)
    for ($round = 0; $round -lt 10; $round++) {
        foreach ($entry in $events) {
            if ($entry.parent_pid -in $descendantIds -and $entry.pid -notin $descendantIds) { $descendantIds += $entry.pid }
        }
    }
}
$defender = @()
$defenderJob = Start-Job -ScriptBlock {
    Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 20 ThreatID,InitialDetectionTime,ActionSuccess,Resources
}
if (Wait-Job -Job $defenderJob -Timeout 10) {
    try { $defender = @(Receive-Job -Job $defenderJob -ErrorAction Stop) }
    catch { $telemetryErrors += 'Windows Defender telemetry unavailable' }
} else {
    $telemetryErrors += 'Windows Defender telemetry exceeded the 10 second limit'
    Stop-Job -Job $defenderJob -ErrorAction SilentlyContinue
}
Remove-Job -Job $defenderJob -Force -ErrorAction SilentlyContinue
$result = @{
    sha256=$digest
    executed=$executed
    root_pid=$rootPid
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
