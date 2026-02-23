# uninstall.ps1
Unregister-ScheduledTask -TaskName "wstunnel-go-client" -Confirm:$false
Write-Host "wstunnel-go-client task unregistered successfully."
