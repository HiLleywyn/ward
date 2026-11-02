[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$python = (& python -c 'import sys; print(sys.executable)').Trim()
$pythonw = Join-Path (Split-Path -Parent $python) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw)) { throw 'pythonw.exe is required for the background controller' }
$action = New-ScheduledTaskAction -Execute $pythonw -Argument '-m ward windows-worker --container ward' -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -AtLogOn -User ([Security.Principal.WindowsIdentity]::GetCurrent().Name)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -RestartCount 6 -RestartInterval (New-TimeSpan -Minutes 5)
$principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName 'Ward Windows Analysis' -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'Disposable offline Windows Sandbox analysis; enables API availability only after a benign smoke test.' -Force | Out-Null
Write-Output 'Ward Windows Analysis registered for the next sign-in. No restart was initiated.'
