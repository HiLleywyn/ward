#Requires -RunAsAdministrator
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$reportPath = Join-Path $PSScriptRoot '..\..\.local\windows-sandbox-setup.json'
$reportDirectory = Split-Path -Parent $reportPath
New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null
try {
    $feature = Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM
    $restartNeeded = $feature.State -eq 'EnablePending'
    if ($feature.State -eq 'Disabled') {
        $result = Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
        $restartNeeded = [bool]$result.RestartNeeded
    }
    $state = (Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).State.ToString()
    @{state=$state; restart_needed=$restartNeeded; automatic_restart=$false} |
        ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
} catch {
    @{state='failed'; error=$_.Exception.Message; automatic_restart=$false} |
        ConvertTo-Json | Set-Content -LiteralPath $reportPath -Encoding UTF8
    throw
}
