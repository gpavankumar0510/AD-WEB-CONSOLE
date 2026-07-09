#Requires -RunAsAdministrator
param([string]$InstallPath="C:\ADWebConsole",[int]$Port=4000,[string]$ServiceName="ADWebConsole")
$ErrorActionPreference="Stop"
function W($m){Write-Host "[STEP] $m" -ForegroundColor Cyan}
function OK($m){Write-Host "  [OK] $m" -ForegroundColor Green}
function WARN($m){Write-Host "  [!!] $m" -ForegroundColor Yellow}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AD Web Console - Installer v5.0" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan

W "Detecting environment..."
$os=(Get-WmiObject Win32_OperatingSystem);OK "OS: $($os.Caption)"
$isDC=(Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4;OK "Role: $(if($isDC){'Domain Controller'}else{'Member Server'})"

W "Checking Node.js..."
$nodeCmd=$null
try{$nv=node --version 2>$null;if($nv -match "v(\d+)\."){if([int]$Matches[1] -ge 18){OK "Node.js $nv";$nodeCmd="node"}else{WARN "Node.js $nv too old. Need v18+"}}}catch{WARN "Node.js not found"}
if(-not $nodeCmd){
  W "Installing Node.js 20 LTS..."
  $url="https://nodejs.org/dist/v20.11.0/node-v20.11.0-x64.msi"
  $msi="$env:TEMP\nodejs.msi"
  Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
  Start-Process msiexec -ArgumentList "/i `"$msi`" /quiet /norestart" -Wait
  $env:PATH=[System.Environment]::GetEnvironmentVariable("PATH","Machine")+";"+[System.Environment]::GetEnvironmentVariable("PATH","User")
  OK "Node.js installed"
  $nodeCmd="node"
}

W "Installing application to $InstallPath..."
if(Test-Path $InstallPath){WARN "Directory exists — updating"}else{New-Item -ItemType Directory -Path $InstallPath -Force|Out-Null}
$src=Split-Path -Parent $MyInvocation.MyCommand.Path
Copy-Item -Path "$src\*" -Destination $InstallPath -Recurse -Force -Exclude @("install.ps1","node_modules","*.log")
@("logs","data","public") | ForEach-Object {$d="$InstallPath\$_";if(-not(Test-Path $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}}
OK "Files copied"

W "Installing npm dependencies..."
Set-Location $InstallPath
npm install --production 2>&1 | Out-Null
OK "Dependencies installed"

W "Configuring environment..."
$envFile="$InstallPath\.env"
if(-not(Test-Path $envFile)){
  $secret=-join((65..90)+(97..122)+(48..57)|Get-Random -Count 64|ForEach-Object{[char]$_})
  $localPw="ADConsole@"+(Get-Random -Min 1000 -Max 9999)+"!"
  @"
PORT=$Port
NODE_ENV=production
SESSION_SECRET=$secret
LOCAL_ADMIN_USER=admin
LOCAL_ADMIN_PASS=$localPw
AD_HOST=ldaps://127.0.0.1
AD_PORT=636
"@ | Set-Content $envFile -Encoding UTF8
  OK ".env created. Local admin password: $localPw"
  WARN "Save this password — it won't be shown again!"
}else{OK ".env exists — keeping"}

W "Validating AD tools..."
try{Import-Module ActiveDirectory -ErrorAction Stop;OK "AD module: $(( Get-ADDomain).DNSRoot)"}
catch{WARN "AD module unavailable";if($isDC){Add-WindowsFeature RSAT-AD-PowerShell -ErrorAction SilentlyContinue|Out-Null;OK "RSAT installed"}}

W "Setting up Windows Service..."
$nssm="$InstallPath\nssm.exe"
if(-not(Test-Path $nssm)){
  try{
    $zip="$env:TEMP\nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath "$env:TEMP\nssm_ext" -Force
    Copy-Item "$env:TEMP\nssm_ext\nssm-2.24\win64\nssm.exe" -Destination $nssm -Force
    OK "NSSM downloaded"
  }catch{WARN "NSSM download failed — service not configured. Start manually: node $InstallPath\server.js";$nssm=$null}
}
if($nssm -and (Test-Path $nssm)){
  $existing=Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if($existing){& $nssm stop $ServiceName 2>$null;& $nssm remove $ServiceName confirm 2>$null;Start-Sleep 2}
  $nodePath=(Get-Command node).Source
  & $nssm install $ServiceName $nodePath "$InstallPath\server.js"
  & $nssm set $ServiceName AppDirectory $InstallPath
  & $nssm set $ServiceName AppStdout "$InstallPath\logs\service.log"
  & $nssm set $ServiceName AppStderr "$InstallPath\logs\error.log"
  & $nssm set $ServiceName AppRotateFiles 1
  & $nssm set $ServiceName AppRotateBytes 10485760
  & $nssm set $ServiceName Start SERVICE_AUTO_START
  & $nssm set $ServiceName AppExit Default Restart
  & $nssm set $ServiceName AppRestartDelay 5000
  & $nssm start $ServiceName 2>$null
  Start-Sleep 3
  $st=& $nssm status $ServiceName 2>$null
  OK "Service status: $st"
}

W "Configuring firewall..."
try{Remove-NetFirewallRule -DisplayName "AD Web Console" -ErrorAction SilentlyContinue;New-NetFirewallRule -DisplayName "AD Web Console" -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow -Profile Any|Out-Null;OK "Firewall rule added for port $Port"}
catch{WARN "Firewall config failed. Run: New-NetFirewallRule -DisplayName 'AD Web Console' -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow"}

W "Health check..."
Start-Sleep 3
try{$h=Invoke-WebRequest -Uri "http://localhost:$Port/health" -UseBasicParsing -TimeoutSec 10;if($h.StatusCode -eq 200){OK "Console is responding"}}
catch{WARN "Health check failed — service may still be starting"}

$ip=(Get-NetIPAddress -AddressFamily IPv4|Where-Object{$_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown"}|Select-Object -First 1).IPAddress
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Installation Complete!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Local:   http://localhost:$Port" -ForegroundColor White
if($ip){Write-Host "  Network: http://${ip}:$Port" -ForegroundColor White}
Write-Host "  Service: $ServiceName" -ForegroundColor White
Write-Host "  Path:    $InstallPath" -ForegroundColor White
Write-Host ""
Write-Host "  IMPORTANT: After first login run fix-gopi.ps1 to" -ForegroundColor Yellow
Write-Host "  grant full AD permissions to the service account." -ForegroundColor Yellow
Write-Host ""
