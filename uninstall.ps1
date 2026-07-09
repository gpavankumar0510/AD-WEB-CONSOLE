#Requires -RunAsAdministrator
param([string]$ServiceName="ADWebConsole",[string]$InstallPath="C:\ADWebConsole")
$nssm="$InstallPath\nssm.exe"
if(Test-Path $nssm){& $nssm stop $ServiceName 2>$null;& $nssm remove $ServiceName confirm 2>$null;Write-Host "[OK] Service removed" -ForegroundColor Green}
Remove-NetFirewallRule -DisplayName "AD Web Console" -ErrorAction SilentlyContinue
Write-Host "[OK] Firewall rule removed" -ForegroundColor Green
if((Read-Host "Remove install directory $InstallPath? (y/n)") -eq 'y'){Remove-Item -Path $InstallPath -Recurse -Force -ErrorAction SilentlyContinue;Write-Host "[OK] Files removed" -ForegroundColor Green}
Write-Host "Uninstall complete." -ForegroundColor Green
