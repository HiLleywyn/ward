param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$KeyMaterial
)
$ErrorActionPreference = 'Stop'
$Error.Clear()
$request = Get-Content -LiteralPath 'C:\WardInput\request.json' -Raw | ConvertFrom-Json
$root = Join-Path $env:TEMP 'WardSample'
New-Item -ItemType Directory -Path $root -Force | Out-Null
$sample = Join-Path $root 'sample.exe'
$keyBytes = [Convert]::FromBase64String($KeyMaterial)
if ($keyBytes.Length -ne 64) { throw 'Invalid artifact key material' }
$encryptionKey = New-Object byte[] 32
$macKey = New-Object byte[] 32
[Array]::Copy($keyBytes, 0, $encryptionKey, 0, 32)
[Array]::Copy($keyBytes, 32, $macKey, 0, 32)
$iv = [Convert]::FromBase64String($request.iv_base64)
$expectedTag = [Convert]::FromBase64String($request.tag_base64)
$ciphertext = [IO.File]::ReadAllBytes('C:\WardInput\sample.enc')
$authenticated = New-Object byte[] ($iv.Length + $ciphertext.Length)
[Array]::Copy($iv, 0, $authenticated, 0, $iv.Length)
[Array]::Copy($ciphertext, 0, $authenticated, $iv.Length, $ciphertext.Length)
$hmac = New-Object System.Security.Cryptography.HMACSHA256
$hmac.Key = $macKey
$actualTag = $hmac.ComputeHash($authenticated)
$tagDifference = 0
if ($actualTag.Length -ne $expectedTag.Length) { throw 'Artifact authentication failed' }
for ($index = 0; $index -lt $actualTag.Length; $index++) {
    $tagDifference = $tagDifference -bor ($actualTag[$index] -bxor $expectedTag[$index])
}
if ($tagDifference -ne 0) { throw 'Artifact authentication failed' }
$aes = [Security.Cryptography.Aes]::Create()
$aes.Key = $encryptionKey
$aes.IV = $iv
$aes.Mode = [Security.Cryptography.CipherMode]::CBC
$aes.Padding = [Security.Cryptography.PaddingMode]::PKCS7
$decryptor = $aes.CreateDecryptor()
$bytes = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
$decryptor.Dispose()
$aes.Dispose()
$hmac.Dispose()
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
$rootPid = $null
$executed = $false
$launchError = $null
try {
    $launchResult = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = '"' + $sample + '"'
        CurrentDirectory = $root
    } -OperationTimeoutSec 20 -ErrorAction Stop
    if ($launchResult.ReturnValue -eq 0 -and $launchResult.ProcessId) {
        $rootPid = [int]$launchResult.ProcessId
        $executed = $true
    } else {
        $launchError = "Win32_Process.Create returned $($launchResult.ReturnValue)"
    }
} catch { $launchError = $_.Exception.Message }
$deadline = (Get-Date).AddSeconds(60)
$descendantIds = @()
$seenProcessIds = @{}
if ($executed) {
    $descendantIds = @($rootPid)
    while ((Get-Date) -lt $deadline) {
        try {
            $snapshot = @(Get-CimInstance -ClassName Win32_Process -Property ProcessId,ParentProcessId,Name `
                -OperationTimeoutSec 2 -ErrorAction Stop)
            foreach ($entry in $snapshot) {
                $pidValue = [int]$entry.ProcessId
                $parentValue = [int]$entry.ParentProcessId
                if ($pidValue -eq $rootPid -or $parentValue -in $descendantIds) {
                    if ($pidValue -notin $descendantIds) { $descendantIds += $pidValue }
                    if ($events.Count -lt 500 -and -not $seenProcessIds.ContainsKey($pidValue)) {
                        $events += @{pid=$pidValue; parent_pid=$parentValue; name=[string]$entry.Name}
                        $seenProcessIds[$pidValue] = $true
                    }
                }
            }
        } catch {
            if ('Process polling timed out or failed' -notin $telemetryErrors) {
                $telemetryErrors += 'Process polling timed out or failed'
            }
        }
        Start-Sleep -Milliseconds 250
    }
}
$afterFiles = Get-ProfileFiles
$changed = @($afterFiles.Keys | Where-Object { -not $beforeFiles.ContainsKey($_) -or $beforeFiles[$_] -ne $afterFiles[$_] } | Select-Object -First 200)
$afterRun = Get-RunKeys
$defender = @()
$telemetryErrors += 'Windows Defender telemetry is not collected by this bounded profile'
$result = @{
    sha256=$digest
    executed=$executed
    root_pid=$rootPid
    launch_error=$launchError
    processes=$events
    profile_changes=$changed
    run_keys_before=$beforeRun
    run_keys_after=$afterRun
    defender=$defender
    telemetry_errors=$telemetryErrors
    duration_seconds=$(if ($executed) {60} else {0})
    windows_build=[Environment]::OSVersion.Version.ToString()
    network='disabled'
}
$json = $result | ConvertTo-Json -Depth 10
[IO.File]::WriteAllText('C:\WardOutput\result.json', $json, (New-Object Text.UTF8Encoding($false)))
