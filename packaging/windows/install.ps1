# install.ps1
param (
    [string]$ConfigPath = "C:\ProgramData\wstunnel-go\client.yaml",
    [string]$BinaryPath = "C:\Program Files\wstunnel-go\wstunnel-go.exe"
)

$Action = New-ScheduledTaskAction -Execute $BinaryPath -Argument "client --config `"$ConfigPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "wstunnel-go-client" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
Write-Host "wstunnel-go-client task registered successfully."
