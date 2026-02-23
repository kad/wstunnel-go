# uninstall.ps1
$TaskName = "wstunnel-go-client"
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "$TaskName task unregistered successfully."
} else {
    Write-Host "$TaskName task not found, skipping."
}
