# control.ps1
param (
    [ValidateSet("start", "stop", "restart", "status")]
    [Parameter(Mandatory=$true)]
    [string]$Action
)

$TaskName = "wstunnel-go-client"

switch ($Action) {
    "start" {
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Task '$TaskName' started."
    }
    "stop" {
        Stop-ScheduledTask -TaskName $TaskName
        Write-Host "Task '$TaskName' stopped."
    }
    "restart" {
        Stop-ScheduledTask -TaskName $TaskName
        Start-ScheduledTask -TaskName $TaskName
        Write-Host "Task '$TaskName' restarted."
    }
    "status" {
        Get-ScheduledTask -TaskName $TaskName
    }
}
