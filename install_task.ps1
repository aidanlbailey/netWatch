# Registers netWatch as a Scheduled Task that starts at logon.
# Self-elevates (task registration needs admin); the task itself runs unelevated.
# Uses the Task Scheduler COM API: schtasks' simple form can't disable the 72h
# execution limit / battery restrictions that would kill a 24/7 service.
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}
$pyw = (Get-Command pythonw.exe).Source

$svc = New-Object -ComObject Schedule.Service
$svc.Connect()
$def = $svc.NewTask(0)

$trigger = $def.Triggers.Create(9)          # 9 = at logon
$action = $def.Actions.Create(0)            # 0 = exec
$action.Path = $pyw
$action.Arguments = "`"$PSScriptRoot\netwatch.py`""
$action.WorkingDirectory = $PSScriptRoot

$s = $def.Settings
$s.ExecutionTimeLimit = "PT0S"              # never kill (default is 72h!)
$s.DisallowStartIfOnBatteries = $false
$s.StopIfGoingOnBatteries = $false
$s.StartWhenAvailable = $true
$s.MultipleInstances = 2                    # ignore new if already running
$s.RestartCount = 3
$s.RestartInterval = "PT1M"

$folder = $svc.GetFolder("\")
# 6 = create-or-update, 3 = run only when this user is logged on (interactive token)
$folder.RegisterTaskDefinition("netWatch", $def, 6, $null, $null, 3) | Out-Null
$folder.GetTask("netWatch").Run($null) | Out-Null
Write-Host "Installed and started. Logs: $PSScriptRoot\netwatch.log"
Read-Host "Press Enter to close"
