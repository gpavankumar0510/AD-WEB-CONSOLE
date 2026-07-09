'use strict';
var fs=require('fs'),path=require('path'),os=require('os');
var execSync=require('child_process').execSync;
var logger=require('./logger');

function runPS(script, timeout) {
  var tmp=path.join(os.tmpdir(),'svc_'+Date.now()+'.ps1');
  try {
    fs.writeFileSync(tmp,script,'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+tmp+'"',
      {timeout:timeout||20000,encoding:'utf8',windowsHide:true}).trim();
  } catch(e){return '';} finally{try{fs.unlinkSync(tmp);}catch(e){}}
}
function safeJ(s){try{return JSON.parse(s);}catch(e){return null;}}

// Auto-detect ALL domain controllers dynamically
function getAllDomainControllers() {
  var out=runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $dcs = Get-ADDomainController -Filter * | Select-Object Name,HostName,IPv4Address,OperatingSystem,OperatingSystemVersion,IsGlobalCatalog,IsReadOnly,Site,Enabled,Responding',
    '  $dcs | ConvertTo-Json -Compress -Depth 3',
    '} catch { Write-Output "[]" }'
  ].join('\n'), 15000);
  var dcs=safeJ(out)||[];
  if(!Array.isArray(dcs)) dcs=[dcs];
  return dcs.map(function(dc){return {
    name: dc.Name||dc.HostName||'Unknown',
    hostname: dc.HostName||dc.Name||'',
    ip: dc.IPv4Address||'—',
    os: dc.OperatingSystem||'—',
    osVersion: dc.OperatingSystemVersion||'—',
    isGC: dc.IsGlobalCatalog===true||dc.IsGlobalCatalog==='True',
    isRODC: dc.IsReadOnly===true||dc.IsReadOnly==='True',
    site: dc.Site||'Default-First-Site-Name',
    enabled: dc.Enabled!==false,
    responding: dc.Responding!==false,
  };});
}

// Get GPO settings - list mode (all GPOs, names/status only, fast)
function getGPOList() {
  var out=runPS([
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $gpos = Get-GPO -All | Select-Object @{N="id";E={$_.Id.ToString()}},@{N="name";E={$_.DisplayName}},@{N="status";E={$_.GpoStatus.ToString()}},@{N="created";E={$_.CreationTime.ToString("o")}},@{N="modified";E={$_.ModificationTime.ToString("o")}}',
    '  $gpos | ConvertTo-Json -Compress -Depth 3',
    '} catch { Write-Output "ERROR: " + $_.Exception.Message }'
  ].join('\n'), 20000);
  if (out.indexOf('ERROR:') >= 0) return { error: out.replace('ERROR: ','') };
  var gpos=safeJ(out)||[];
  if(!Array.isArray(gpos)) gpos=[gpos];
  return { gpos: gpos };
}

// Get GPO settings for ONE GPO by name or GUID (slow - Get-GPOReport can take 10-30s)
function getGPOSettingsDetail(identifier) {
  var isGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
  var getCmd = isGuid ? 'Get-GPO -Guid "' + identifier + '"' : 'Get-GPO -Name "' + identifier.replace(/"/g,'') + '"';
  var out=runPS([
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $gpo = ' + getCmd + ' -ErrorAction Stop',
    '  $xml = Get-GPOReport -Guid $gpo.Id -ReportType Xml -ErrorAction Stop',
    '  $doc = [xml]$xml',
    '  $settings = @()',
    '  $nodes = $doc.SelectNodes("//*[local-name()=" + [char]39 + "Name" + [char]39 + " or local-name()=" + [char]39 + "name" + [char]39 + "]")',
    '  foreach ($n in $nodes) {',
    '    $val = $n.NextSibling',
    '    $name = $n.InnerText',
    '    if ($name -and $name.Trim() -and $name.Length -lt 100) {',
    '      $parent = $n.ParentNode',
    '      $state = $parent.SelectSingleNode("*[local-name()=" + [char]39 + "State" + [char]39 + "]")',
    '      $settingVal = $parent.SelectSingleNode("*[local-name()=" + [char]39 + "SettingNumber" + [char]39 + " or local-name()=" + [char]39 + "SettingBoolean" + [char]39 + " or local-name()=" + [char]39 + "SettingString" + [char]39 + " or local-name()=" + [char]39 + "Value" + [char]39 + " or local-name()=" + [char]39 + "DisplayValue" + [char]39 + "]")',
    '      $v = if ($state) { $state.InnerText } elseif ($settingVal) { $settingVal.InnerText } else { "" }',
    '      $settings += @{ name=$name.Trim(); value=$v }',
    '    }',
    '  }',
    '  $unique = $settings | Sort-Object name -Unique | Select-Object -First 100',
    '  @{ id=$gpo.Id.ToString(); name=$gpo.DisplayName; status=$gpo.GpoStatus.ToString(); settings=$unique; xml=$xml } | ConvertTo-Json -Compress -Depth 6',
    '} catch { Write-Output "ERROR: " + $_.Exception.Message }'
  ].join('\n'), 60000);
  if (out.indexOf('ERROR:') === 0) return { error: out.replace('ERROR: ','') };
  var parsed = safeJ(out);
  if (!parsed) return { error: 'Could not parse GPO report output' };
  return parsed;
}

// Get GPO report as raw HTML or XML for export
function getGPOReportRaw(identifier, format) {
  format = (format === 'html') ? 'Html' : 'Xml';
  var isGuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(identifier);
  var getCmd = isGuid ? 'Get-GPO -Guid "' + identifier + '"' : 'Get-GPO -Name "' + identifier.replace(/"/g,'') + '"';
  var marker = '___GPOREPORT_START___';
  var out=runPS([
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $gpo = ' + getCmd + ' -ErrorAction Stop',
    '  $report = Get-GPOReport -Guid $gpo.Id -ReportType ' + format + ' -ErrorAction Stop',
    '  Write-Output "' + marker + '"',
    '  Write-Output $report',
    '} catch { Write-Output "ERROR: " + $_.Exception.Message }'
  ].join('\n'), 60000);
  if (out.indexOf('ERROR:') === 0) return { error: out.replace('ERROR: ','') };
  var idx = out.indexOf(marker);
  if (idx < 0) return { error: 'No report generated' };
  return { content: out.slice(idx + marker.length).trim() };
}

// Backward-compat: returns list with empty settings (used by older callers)
function getGPOSettings() {
  var list = getGPOList();
  if (list.error) return [];
  return (list.gpos || []).map(function(g) { return Object.assign({}, g, { settings: [] }); });
}

// Get users with password expiry
function getUsersPasswordExpiry() {
  // Check for a disk cache first (3 min TTL) to avoid blocking the dashboard
  var PWD_CACHE = path.join(__dirname, '../data/pwd_expiry_cache.json');
  try {
    if (fs.existsSync(PWD_CACHE)) {
      var c = JSON.parse(fs.readFileSync(PWD_CACHE, 'utf8'));
      if (c.cachedAt && (Date.now() - new Date(c.cachedAt).getTime()) < 3*60*1000) return c.data;
    }
  } catch(e) {}

  var out=runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $policy = Get-ADDefaultDomainPasswordPolicy',
    '  $maxAge = $policy.MaxPasswordAge.TotalDays',
    '  # Also check per-user Fine-Grained Password Policy effective max age',
    '  $users = Get-ADUser -Filter * -Properties PasswordLastSet,PasswordNeverExpires,PasswordExpired,Enabled,DisplayName,SamAccountName,UserAccountControl',
    '  $results = @()',
    '  foreach ($u in $users) {',
    '    $expiry = $null; $daysLeft = $null',
    '    # UserAccountControl flag 0x10000 (65536) = DONT_EXPIRE_PASSWORD',
    '    $dontExpire = ($u.PasswordNeverExpires -eq $true) -or (($u.UserAccountControl -band 0x10000) -ne 0)',
    '    if (-not $dontExpire -and $u.PasswordLastSet -and $maxAge -gt 0) {',
    '      $expiry = $u.PasswordLastSet.AddDays($maxAge)',
    '      $daysLeft = [math]::Round(($expiry - (Get-Date)).TotalDays)',
    '    }',
    '    $results += @{',
    '      username=$u.SamAccountName',
    '      displayName=if($u.DisplayName){$u.DisplayName}else{$u.SamAccountName}',
    '      passwordLastSet=if($u.PasswordLastSet){$u.PasswordLastSet.ToString("o")}else{$null}',
    '      passwordExpiry=if($expiry){$expiry.ToString("o")}else{$null}',
    '      daysUntilExpiry=$daysLeft',
    '      neverExpires=$dontExpire',
    '      enabled=$u.Enabled',
    '    }',
    '  }',
    '  @{ maxPasswordAgeDays=$maxAge; users=$results } | ConvertTo-Json -Compress -Depth 4',
    '} catch { Write-Output "{}" }'
  ].join('\n'), 25000);

  var result = safeJ(out) || { maxPasswordAgeDays:0, users:[] };
  // Cache to disk
  try {
    var dir = path.dirname(PWD_CACHE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(PWD_CACHE, JSON.stringify({ cachedAt: new Date().toISOString(), data: result }));
  } catch(e) {}
  return result;
}

// Calculate SCAP/Security score for the domain
function getSCAPScore() {
  // Each check is fully isolated in its own try/catch INSIDE the PowerShell script.
  // PowerShell string literals below use double-quotes with backtick-escaped inner
  // double-quotes (PowerShell's native escape character) - NOT backslash escaping,
  // which is invalid PS syntax and was silently breaking the whole script before,
  // causing every score to fall through to the 0% fallback.
  var certCachePath = path.join(__dirname, '..', 'data', 'cert_cache.json').replace(/\\/g, '\\\\');
  var bkHistPath = path.join(__dirname, '..', 'data', 'backup_history.json').replace(/\\/g, '\\\\');

  var script = [
    '$ErrorActionPreference = "Continue"',
    '$score = 0; $total = 0; $checks = @()',
    'function AddCheck($name,$category,$pass,$detail,$weight,$remediation) {',
    '  $script:total += $weight',
    '  if ($pass) { $script:score += $weight }',
    '  $script:checks += [PSCustomObject]@{ name=$name; category=$category; pass=$pass; detail=$detail; weight=$weight; remediation=$remediation }',
    '}',
    "try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Output '{\"score\":0,\"total\":100,\"percent\":0,\"grade\":\"N/A\",\"checks\":[],\"error\":\"AD module unavailable\"}'; exit }",
    '',
    '# --- Password Policy ---',
    'try {',
    '  $pp = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop',
    '  AddCheck "Minimum Password Length" "Password Policy" ($pp.MinPasswordLength -ge 14) "$($pp.MinPasswordLength) characters (recommended: 14+)" 10 "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14"',
    '  AddCheck "Password History" "Password Policy" ($pp.PasswordHistoryCount -ge 24) "$($pp.PasswordHistoryCount) remembered (recommended: 24)" 10 "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24"',
    '  $maxAgeDays = [int]$pp.MaxPasswordAge.TotalDays',
    '  AddCheck "Maximum Password Age" "Password Policy" ($maxAgeDays -le 90 -and $maxAgeDays -gt 0) "$maxAgeDays days (recommended: 60-90)" 10 "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge 90.00:00:00"',
    '  $complexityText = if($pp.ComplexityEnabled){"Enabled"}else{"Disabled"}',
    '  AddCheck "Password Complexity" "Password Policy" ($pp.ComplexityEnabled) $complexityText 10 "Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled $true"',
    '  $revEncText = if($pp.ReversibleEncryptionEnabled){"Enabled (BAD)"}else{"Disabled (Good)"}',
    '  AddCheck "Reversible Encryption" "Password Policy" (-not $pp.ReversibleEncryptionEnabled) $revEncText 5 "Set-ADDefaultDomainPasswordPolicy -ReversibleEncryptionEnabled $false"',
    '} catch { AddCheck "Password Policy" "Password Policy" $false ("Could not read password policy: " + $_.Exception.Message) 10 "Verify AD module connectivity" }',
    '',
    '# --- Account Lockout Policy ---',
    'try {',
    '  $pp2 = Get-ADDefaultDomainPasswordPolicy -ErrorAction Stop',
    '  AddCheck "Account Lockout Threshold" "Account Lockout" ($pp2.LockoutThreshold -gt 0 -and $pp2.LockoutThreshold -le 10) "Locks after $($pp2.LockoutThreshold) attempts (recommended: 5-10)" 10 "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5"',
    '  $lockDurMin = [int]$pp2.LockoutDuration.TotalMinutes',
    '  AddCheck "Account Lockout Duration" "Account Lockout" ($lockDurMin -ge 15) "$lockDurMin minutes (recommended: 15+)" 5 "Set-ADDefaultDomainPasswordPolicy -LockoutDuration 00:30:00"',
    '} catch { AddCheck "Account Lockout Policy" "Account Lockout" $false "Could not read lockout policy" 10 "Verify AD module connectivity" }',
    '',
    '# --- Stale / Privileged Accounts ---',
    'try {',
    '  $stale90 = (Get-ADUser -Filter {LastLogonDate -lt (Get-Date).AddDays(-90) -and Enabled -eq $true} -ErrorAction Stop | Measure-Object).Count',
    '  AddCheck "No Stale Active Accounts (90d)" "Privileged Accounts" ($stale90 -eq 0) "$stale90 enabled account(s) inactive 90+ days" 10 "Review and disable inactive accounts in Users module"',
    '} catch { AddCheck "Stale Account Check" "Privileged Accounts" $false "Could not query stale accounts" 10 "Verify AD module connectivity" }',
    'try {',
    '  $admins = (Get-ADGroupMember "Domain Admins" -ErrorAction Stop | Measure-Object).Count',
    '  AddCheck "Domain Admin Count" "Privileged Accounts" ($admins -le 5) "$admins member(s) (recommended: 5 or fewer)" 10 "Review Domain Admins membership and apply least-privilege"',
    '} catch { AddCheck "Domain Admin Count" "Privileged Accounts" $false "Could not query Domain Admins group" 10 "Verify AD module connectivity" }',
    'try {',
    '  $eaCount = (Get-ADGroupMember "Enterprise Admins" -ErrorAction Stop | Measure-Object).Count',
    '  AddCheck "Enterprise Admin Count" "Privileged Accounts" ($eaCount -le 2) "$eaCount member(s) (recommended: 2 or fewer, empty except during forest changes)" 5 "Remove unnecessary Enterprise Admins members"',
    '} catch { AddCheck "Enterprise Admin Count" "Privileged Accounts" $true "Not applicable or not a forest root domain" 5 $null }',
    'try {',
    '  $krbtgtAge = ((Get-Date) - (Get-ADUser krbtgt -Properties PasswordLastSet -ErrorAction Stop).PasswordLastSet).Days',
    '  AddCheck "KRBTGT Password Age" "Privileged Accounts" ($krbtgtAge -le 180) "Last changed $krbtgtAge days ago (recommended: reset every 180 days)" 5 "Rotate krbtgt password twice with a 24h gap (see Microsoft KB on krbtgt reset)"',
    '} catch { AddCheck "KRBTGT Password Age" "Privileged Accounts" $false "Could not check krbtgt account" 5 $null }',
    '',
    '# --- AD Infrastructure Hardening ---',
    'try {',
    '  $rb = Get-ADOptionalFeature -Filter {Name -eq "Recycle Bin Feature"} -ErrorAction Stop',
    '  $rbEnabled = $rb -and $rb.EnabledScopes.Count -gt 0',
    '  $rbText = if($rbEnabled){"Enabled"}else{"Not enabled"}',
    '  AddCheck "AD Recycle Bin" "AD Hardening" $rbEnabled $rbText 10 "Enable-ADOptionalFeature -Identity \'Recycle Bin Feature\' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name"',
    '} catch { AddCheck "AD Recycle Bin" "AD Hardening" $false "Could not check Recycle Bin feature" 10 $null }',
    'try {',
    '  $fgpp = (Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | Measure-Object).Count',
    '  AddCheck "Fine-Grained Password Policy" "AD Hardening" ($fgpp -gt 0) "$fgpp policy(ies) defined" 5 "Create FGPP for privileged accounts via New-ADFineGrainedPasswordPolicy"',
    '} catch { AddCheck "Fine-Grained Password Policy" "AD Hardening" $false "Could not query FGPP" 5 $null }',
    'try {',
    '  $dfl = (Get-ADDomain -ErrorAction Stop).DomainMode.ToString()',
    '  $dflOk = $dfl -match "2016|2025|2019|2012R2"',
    '  AddCheck "Domain Functional Level" "AD Hardening" $dflOk "$dfl" 5 "Raise domain functional level via Set-ADDomainMode once all DCs support it"',
    '} catch { AddCheck "Domain Functional Level" "AD Hardening" $false "Could not check functional level" 5 $null }',
    '',
    '# --- Domain Controller Security ---',
    'try {',
    '  $dcs = Get-ADDomainController -Filter * -ErrorAction Stop',
    '  $oldOS = $dcs | Where-Object { $_.OperatingSystemVersion -match "6\\.[0-1]" }',
    '  AddCheck "DC Operating System Versions" "Domain Controller Security" ($oldOS.Count -eq 0) "$($dcs.Count) DC(s) checked, $($oldOS.Count) running outdated OS" 10 "Upgrade or decommission DCs running Server 2008/2008R2"',
    '} catch { AddCheck "DC Operating System Versions" "Domain Controller Security" $false "Could not enumerate DCs" 10 $null }',
    '',
    '# --- LDAP / LDAPS Security ---',
    'try {',
    '  $ldapsPort = Test-NetConnection -ComputerName localhost -Port 636 -WarningAction SilentlyContinue -ErrorAction Stop',
    '  $ldapsText = "Port 636 " + $(if($ldapsPort.TcpTestSucceeded){"reachable"}else{"not reachable"})',
    '  AddCheck "LDAPS Available" "LDAP Security" ($ldapsPort.TcpTestSucceeded) $ldapsText 10 "Install a valid server certificate and ensure LDAPS (port 636) is listening - see AD CS setup"',
    '} catch { AddCheck "LDAPS Available" "LDAP Security" $false "Could not test LDAPS port" 10 "Install AD Certificate Services for LDAPS support" }',
    '',
    '# --- Audit Policy ---',
    'try {',
    '  $auditOut = auditpol /get /category:"Account Logon","Account Management","DS Access" 2>&1 | Out-String',
    '  $auditOk = $auditOut -match "Success and Failure"',
    '  $auditText = if($auditOk){"Success and Failure auditing detected"}else{"May not be fully configured"}',
    '  AddCheck "Advanced Audit Policy" "Audit Policy" $auditOk $auditText 10 "Configure Advanced Audit Policy via GPO: Account Logon, Account Management, DS Access -> Success and Failure"',
    '} catch { AddCheck "Advanced Audit Policy" "Audit Policy" $false "Could not query auditpol" 10 "Configure auditing via Group Policy" }',
    '',
    '# --- Certificate Health (reuses certMonitor cache if present) ---',
    'try {',
    '  $certCache = "' + certCachePath + '"',
    '  if (Test-Path $certCache) {',
    '    $certData = Get-Content $certCache -Raw | ConvertFrom-Json',
    '    $certOk = $certData.summary.expired -eq 0',
    '    AddCheck "Certificate Expiry Status" "Certificate Security" $certOk "$($certData.summary.expired) expired, $($certData.summary.expiringSoon) expiring soon" 5 "Renew expired/expiring certificates - see Certificates module"',
    '  } else {',
    '    AddCheck "Certificate Expiry Status" "Certificate Security" $false "No certificate scan run yet" 5 "Run a scan from the Certificates module"',
    '  }',
    '} catch { AddCheck "Certificate Expiry Status" "Certificate Security" $false "Could not read certificate cache" 5 "Run a scan from the Certificates module" }',
    '',
    '# --- Windows Defender / Endpoint Security ---',
    'try {',
    '  $defenderStatus = Get-MpComputerStatus -ErrorAction Stop',
    '  $defenderText = if($defenderStatus.RealTimeProtectionEnabled){"Enabled"}else{"Disabled"}',
    '  AddCheck "Windows Defender Real-Time Protection" "Endpoint Security" ($defenderStatus.RealTimeProtectionEnabled) $defenderText 5 "Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring $false"',
    '  $sigAge = $defenderStatus.AntivirusSignatureAge',
    '  AddCheck "Antivirus Signatures Current" "Endpoint Security" ($sigAge -le 3) "Signatures are $sigAge day(s) old" 5 "Update-MpSignature"',
    '} catch { AddCheck "Windows Defender Status" "Endpoint Security" $false "Defender not available or not installed on this server" 5 "Verify endpoint protection is installed (Defender or 3rd-party)" }',
    '',
    '# --- Backup / Disaster Recovery ---',
    'try {',
    '  $bkHistFile = "' + bkHistPath + '"',
    '  $bkOk = $false; $bkDetail = "No backup history found"',
    '  if (Test-Path $bkHistFile) {',
    '    $bkHist = Get-Content $bkHistFile -Raw | ConvertFrom-Json',
    '    if ($bkHist.Count -gt 0) {',
    '      $lastBk = $bkHist[0]',
    '      $bkAge = ((Get-Date) - [datetime]$lastBk.timestamp).TotalHours',
    '      $bkOk = ($lastBk.status -eq "completed") -and ($bkAge -le 48)',
    '      $bkDetail = "Last backup: $($lastBk.status), $([math]::Round($bkAge,1))h ago"',
    '    }',
    '  }',
    '  AddCheck "Recent Successful Backup" "Backup & DR" $bkOk $bkDetail 10 "Run a backup from the Backup module and verify scheduled backups are configured in Settings"',
    '} catch { AddCheck "Recent Successful Backup" "Backup & DR" $false "Could not read backup history" 10 "Configure scheduled backups in Settings" }',
    '',
    '$pct = if ($total -gt 0) { [math]::Round($score/$total*100) } else { 0 }',
    '$grade = if($pct -ge 90){"A"}elseif($pct -ge 75){"B"}elseif($pct -ge 60){"C"}elseif($pct -ge 40){"D"}else{"F"}',
    '@{ score=$score; total=$total; percent=$pct; grade=$grade; checks=$checks } | ConvertTo-Json -Compress -Depth 6',
  ].join('\n');

  var out = runPS(script, 45000);

  var parsed = safeJ(out);
  if (!parsed) return { score: 0, total: 100, percent: 0, grade: 'N/A', checks: [], error: 'Could not parse SCAP scan output' };
  if (parsed.checks && !Array.isArray(parsed.checks)) parsed.checks = [parsed.checks];
  return parsed;
}

var SCAP_CACHE_FILE = path.join(__dirname, '../data/scap_cache.json');
var SCAP_CACHE_TTL_MS = 15 * 60 * 1000; // 15 minutes - the scan itself can take up to 45s, so don't run it on every page load

function getSCAPScoreCached(forceRescan) {
  try {
    if (!forceRescan && fs.existsSync(SCAP_CACHE_FILE)) {
      var cached = JSON.parse(fs.readFileSync(SCAP_CACHE_FILE, 'utf8'));
      if (cached.cachedAt && (Date.now() - new Date(cached.cachedAt).getTime()) < SCAP_CACHE_TTL_MS) {
        return cached.data;
      }
    }
  } catch(e) {}

  var fresh = getSCAPScore();
  try {
    var dir = path.dirname(SCAP_CACHE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(SCAP_CACHE_FILE, JSON.stringify({ cachedAt: new Date().toISOString(), data: fresh }, null, 2));
  } catch(e) { logger.warn('Could not write SCAP cache: ' + e.message); }
  return fresh;
}


// Disk cache for domain info - rarely changes, expensive to re-fetch
var DOMAIN_INFO_CACHE_FILE = path.join(__dirname, '../data/domain_info_cache.json');

function getDomainInfo() {
  // Disk cache: 30-minute TTL - domain topology barely changes
  try {
    if (fs.existsSync(DOMAIN_INFO_CACHE_FILE)) {
      var cached = JSON.parse(fs.readFileSync(DOMAIN_INFO_CACHE_FILE, 'utf8'));
      if (cached.cachedAt && (Date.now() - new Date(cached.cachedAt).getTime()) < 30*60*1000 && cached.data && cached.data.dnsRoot) {
        return cached.data;
      }
    }
  } catch(e) {}

  // Single combined PS script - AD info + system info in one call for speed
  var out = runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $d = Get-ADDomain -ErrorAction Stop',
    '  $f = Get-ADForest -ErrorAction Stop',
    '  $os = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue',
    '  $cpu = Get-WmiObject Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1',
    '  $disks = Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue',
    '  $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } | Select-Object -First 1).IPAddress',
    '  $uptime = if($os){ [math]::Round(($os.ConvertToDateTime($os.LastBootUpTime) | ForEach-Object { (Get-Date) - $_ }).TotalHours, 1) } else { 0 }',
    '  $memTotal = if($os){ [math]::Round($os.TotalVisibleMemorySize/1MB, 1) } else { 0 }',
    '  $memFree  = if($os){ [math]::Round($os.FreePhysicalMemory/1MB, 1) } else { 0 }',
    '  $memUsed  = [math]::Round($memTotal - $memFree, 1)',
    '  $diskInfo = @($disks | ForEach-Object { "$($_.DeviceID) $([math]::Round($_.FreeSpace/1GB,1))GB free of $([math]::Round($_.Size/1GB,1))GB" }) -join "; "',
    '  @{',
    '    computerName   = $env:COMPUTERNAME',
    '    dnsRoot        = $d.DNSRoot',
    '    netbios        = $d.NetBIOSName',
    '    distinguishedName = $d.DistinguishedName',
    '    domainMode     = $d.DomainMode.ToString()',
    '    forestMode     = $f.ForestMode.ToString()',
    '    pdcEmulator    = $d.PDCEmulator',
    '    ridMaster      = $d.RIDMaster',
    '    schemaMaster   = $f.SchemaMaster',
    '    domainNaming   = $f.DomainNamingMaster',
    '    infrastructureMaster = $d.InfrastructureMaster',
    '    created        = $d.Created.ToString("o")',
    '    currentDCTime  = (Get-Date).ToString("o")',
    '    sites          = @($f.Sites)',
    '    domainControllers = ($d.ReplicaDirectoryServers | Measure-Object).Count',
    '    childDomains   = @($d.ChildDomains)',
    '    ipAddress      = if($ip){$ip}else{"N/A"}',
    '    osName         = if($os){$os.Caption}else{"N/A"}',
    '    osBuild        = if($os){$os.BuildNumber}else{"N/A"}',
    '    osVersion      = if($os){$os.Version}else{"N/A"}',
    '    cpuName        = if($cpu){$cpu.Name.Trim()}else{"N/A"}',
    '    cpuCores       = if($cpu){$cpu.NumberOfCores}else{0}',
    '    totalMemoryGB  = $memTotal',
    '    usedMemoryGB   = $memUsed',
    '    freeMemoryGB   = $memFree',
    '    uptimeHours    = $uptime',
    '    diskInfo       = $diskInfo',
    '    adVersion      = $d.DomainMode.ToString()',
    '    isDC           = $true',
    '  } | ConvertTo-Json -Compress -Depth 3',
    '} catch { Write-Output "{}" }',
  ].join('\n'), 20000);

  var result = safeJ(out) || {};

  // Cache to disk
  try {
    var dir = path.dirname(DOMAIN_INFO_CACHE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DOMAIN_INFO_CACHE_FILE, JSON.stringify({ cachedAt: new Date().toISOString(), data: result }, null, 2));
  } catch(e) {}

  return result;
}


function getAllServices() {
  logger.info('AD Services: scanning...');
  var rolesOut=runPS('try{$r=Get-WindowsFeature|Where-Object{$_.Installed}|Select-Object Name,DisplayName;$r|ConvertTo-Json -Compress}catch{Write-Output "[]"}', 15000);
  var roles=safeJ(rolesOut)||[];
  function installed(name){return roles.some(function(r){return (r.Name||'').indexOf(name)>=0;});}

  var dns=installed('DNS')?safeJ(runPS('try{Import-Module DnsServer -EA Stop;$z=Get-DnsServerZone|Select-Object ZoneName,ZoneType,IsReverseLookupZone,IsDsIntegrated;@{installed=$true;zones=@($z);totalZones=($z|Measure-Object).Count}|ConvertTo-Json -Compress -Depth 5}catch{\'{"installed":false}\'}', 10000))||{installed:false}:{installed:false};
  var dhcp=installed('DHCP')?safeJ(runPS('try{Import-Module DhcpServer -EA Stop;$s=Get-DhcpServerv4Scope|Select-Object ScopeId,Name,StartRange,EndRange,State;@{installed=$true;scopes=@($s);totalScopes=($s|Measure-Object).Count}|ConvertTo-Json -Compress -Depth 5}catch{\'{"installed":false}\'}', 10000))||{installed:false}:{installed:false};
  var wsus=safeJ(runPS('try{$s=Get-Service "WsusService" -EA Stop;@{installed=$true;status=$s.Status.ToString();running=($s.Status -eq "Running")}|ConvertTo-Json -Compress}catch{\'{"installed":false}\'}', 8000))||{installed:false};
  var wds=safeJ(runPS('try{$s=Get-Service "WDSServer" -EA Stop;@{installed=$true;status=$s.Status.ToString();running=($s.Status -eq "Running")}|ConvertTo-Json -Compress}catch{\'{"installed":false}\'}', 8000))||{installed:false};
  var ca=safeJ(runPS('try{$s=Get-Service "CertSvc" -EA Stop;@{installed=$true;status=$s.Status.ToString();running=($s.Status -eq "Running")}|ConvertTo-Json -Compress}catch{\'{"installed":false}\'}', 8000))||{installed:false};
  var repOut=runPS('try{$r=repadmin /replsummary 2>&1|Out-String;$f=($r|Select-String "fail" -AllMatches).Matches.Count;$dcs=(Get-ADDomainController -Filter *).Count;@{checked=$true;dcCount=$dcs;failures=$f;healthy=($f-eq 0)}|ConvertTo-Json -Compress}catch{\'{"checked":false}\'}', 12000);
  var rep=safeJ(repOut)||{checked:false};
  var fsmoOut=runPS('try{Import-Module ActiveDirectory -EA Stop;$d=Get-ADDomain;$f=Get-ADForest;@{PDCEmulator=$d.PDCEmulator;RIDMaster=$d.RIDMaster;InfrastructureMaster=$d.InfrastructureMaster;SchemaMaster=$f.SchemaMaster;DomainNamingMaster=$f.DomainNamingMaster}|ConvertTo-Json -Compress}catch{\'{}\'  }', 10000);
  var fsmo=safeJ(fsmoOut)||{};
  var filteredRoles=roles.filter(function(r){var n=r.Name||'';return n.indexOf('AD-')>=0||n.indexOf('DNS')>=0||n.indexOf('DHCP')>=0||n.indexOf('UpdateServices')>=0||n.indexOf('WDS')>=0||n.indexOf('ADCS')>=0;});
  return { scannedAt:new Date().toISOString(), dns, dhcp, wsus, wds, ca, replication:rep, fsmo, installedRoles:filteredRoles };
}

module.exports = { getAllServices, getAllDomainControllers, getGPOSettings, getGPOList, getGPOSettingsDetail, getGPOReportRaw, getUsersPasswordExpiry, getSCAPScore, getSCAPScoreCached, getDomainInfo };
