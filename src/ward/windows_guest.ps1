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
    $roots = @($env:TEMP, $env:APPDATA, $env:LOCALAPPDATA, 'C:\ProgramData') | Select-Object -Unique
    foreach ($directory in $roots) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $directory -File -Force -ErrorAction SilentlyContinue |
                Select-Object -First 500)) {
            $values[$item.FullName] = "$($item.Length):$($item.LastWriteTimeUtc.Ticks)"
            if ($values.Count -ge 2000) { break }
        }
        if ($values.Count -ge 2000) { break }
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
try {
    $launchResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = '"' + $sample + '"'
        CurrentDirectory = $root
    } -OperationTimeoutSec 20 -ErrorAction Stop
    if ($launchResult.ReturnValue -eq 0 -and $launchResult.ProcessId) {
        $rootPid = [int]$launchResult.ProcessId
        $executed = $true
        $process = Get-Process -Id $rootPid -ErrorAction SilentlyContinue
    } else {
        $launchError = "Win32_Process.Create returned $($launchResult.ReturnValue)"
    }
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
if ($rootPid) {
    $descendantIds = @($rootPid)
    for ($round = 0; $round -lt 10; $round++) {
        foreach ($entry in $events) {
            if ($entry.parent_pid -in $descendantIds -and $entry.pid -notin $descendantIds) { $descendantIds += $entry.pid }
        }
    }
}
$defender = @()
try {
    $defender = @(Get-CimInstance -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpThreatDetection `
        -OperationTimeoutSec 10 -ErrorAction Stop |
        Select-Object -First 20 ThreatID,InitialDetectionTime,ActionSuccess,Resources)
} catch { $telemetryErrors += 'Windows Defender telemetry unavailable or timed out' }
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
