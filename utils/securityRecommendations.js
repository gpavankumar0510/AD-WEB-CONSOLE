'use strict';
var fs = require('fs');
var path = require('path');
var os = require('os');
var execSync = require('child_process').execSync;
var logger = require('./logger');

function runPS(script, timeoutMs) {
  var tmp = path.join(os.tmpdir(), 'secrec_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: timeoutMs || 20000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; } finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function safeJ(s) { try { return JSON.parse(s); } catch(e) { return null; } }

// ── AD / DC / Replication / DNS / SYSVOL / FSMO health summary ──────────────
// Each sub-check is isolated so one failure cannot break the others.
function getHealthSummary() {
  var script = [
    '$ErrorActionPreference = "Continue"',
    'function Result($name,$status,$detail) { [PSCustomObject]@{ name=$name; status=$status; detail=$detail } }',
    '$results = @()',
    '',
    '# Domain Controller Health',
    'try {',
    '  $dcs = Get-ADDomainController -Filter * -ErrorAction Stop',
    '  $up = 0; foreach ($dc in $dcs) { if (Test-Connection -ComputerName $dc.HostName -Count 1 -Quiet -ErrorAction SilentlyContinue) { $up++ } }',
    '  $status = if ($up -eq $dcs.Count) { "healthy" } elseif ($up -gt 0) { "warning" } else { "critical" }',
    '  $results += Result "Domain Controller Health" $status "$up of $($dcs.Count) DC(s) responding"',
    '} catch { $results += Result "Domain Controller Health" "unknown" "Could not enumerate domain controllers" }',
    '',
    '# Replication Health',
    'try {',
    '  $replOut = repadmin /replsummary 2>&1 | Out-String',
    '  $replOk = $replOut -notmatch "Largest Delta.*[1-9][0-9]*\\s*[Ee]rror" -and $replOut -notmatch "fail"',
    '  $status2 = if ($replOk) { "healthy" } else { "warning" }',
    '  $results += Result "Replication Health" $status2 "repadmin /replsummary checked"',
    '} catch { $results += Result "Replication Health" "unknown" "Could not run repadmin" }',
    '',
    '# DNS Health',
    'try {',
    '  $dnsService = Get-Service -Name DNS -ErrorAction Stop',
    '  $status3 = if ($dnsService.Status -eq "Running") { "healthy" } else { "critical" }',
    '  $results += Result "DNS Health" $status3 "DNS service is $($dnsService.Status)"',
    '} catch { $results += Result "DNS Health" "unknown" "DNS service not found on this server" }',
    '',
    '# SYSVOL / NETLOGON Health',
    'try {',
    '  $sysvolShare = Get-SmbShare -Name SYSVOL -ErrorAction Stop',
    '  $netlogonShare = Get-SmbShare -Name NETLOGON -ErrorAction Stop',
    '  $status4 = if ($sysvolShare -and $netlogonShare) { "healthy" } else { "warning" }',
    '  $results += Result "SYSVOL/NETLOGON Health" $status4 "Both shares published"',
    '} catch { $results += Result "SYSVOL/NETLOGON Health" "warning" "Could not verify SYSVOL/NETLOGON shares" }',
    '',
    '# FSMO Role Status',
    'try {',
    '  $domain = Get-ADDomain -ErrorAction Stop',
    '  $forest = Get-ADForest -ErrorAction Stop',
    '  $fsmoOk = $true',
    '  $fsmoDetail = "PDC=$($domain.PDCEmulator); RID=$($domain.RIDMaster); Infra=$($domain.InfrastructureMaster); Schema=$($forest.SchemaMaster); DomainNaming=$($forest.DomainNamingMaster)"',
    '  $results += Result "FSMO Role Status" "healthy" $fsmoDetail',
    '} catch { $results += Result "FSMO Role Status" "unknown" "Could not query FSMO role holders" }',
    '',
    '# Certificate Health (reuses cert monitor cache)',
    'try {',
    '  $certCache = "' + path.join(__dirname, '..', 'data', 'cert_cache.json').replace(/\\/g, '\\\\') + '"',
    '  if (Test-Path $certCache) {',
    '    $certData = Get-Content $certCache -Raw | ConvertFrom-Json',
    '    $status5 = if ($certData.summary.expired -gt 0) { "critical" } elseif ($certData.summary.expiringSoon -gt 0) { "warning" } else { "healthy" }',
    '    $results += Result "Certificate Health" $status5 "$($certData.summary.expired) expired, $($certData.summary.expiringSoon) expiring soon, $($certData.summary.healthy) healthy"',
    '  } else {',
    '    $results += Result "Certificate Health" "unknown" "No certificate scan run yet"',
    '  }',
    '} catch { $results += Result "Certificate Health" "unknown" "Could not read certificate cache" }',
    '',
    '$results | ConvertTo-Json -Compress -Depth 4',
  ].join('\n');

  var out = runPS(script, 30000);
  var parsed = safeJ(out);
  if (!parsed) return [];
  if (!Array.isArray(parsed)) parsed = [parsed];
  return parsed;
}

// ── Remediation dispatcher for Security Recommendations "Fix" buttons ───────
// Mirrors the migration assessor's repairCheck pattern: each fix is a specific,
// validated, scoped command - never the free-text remediation string itself.
function applyFix(checkName) {
  var result = { ok: false, message: '', output: '' };

  if (checkName === 'AD Recycle Bin') {
    var out = runPS([
      'try {',
      '  $forest = (Get-ADForest).Name',
      '  Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target $forest -Confirm:$false -ErrorAction Stop',
      '  Write-Output "AD Recycle Bin enabled successfully."',
      '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
    ].join('\n'), 30000);
    result.ok = out.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'AD Recycle Bin has been enabled.' : 'Could not enable AD Recycle Bin.';
    result.output = out;

  } else if (checkName === 'Password Complexity') {
    var out2 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ComplexityEnabled $true -ErrorAction Stop; Write-Output "Password complexity enabled." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out2.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Password complexity requirement enabled.' : 'Could not enable password complexity.';
    result.output = out2;

  } else if (checkName === 'Minimum Password Length') {
    var out3 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MinPasswordLength 14 -ErrorAction Stop; Write-Output "Minimum password length set to 14." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out3.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Minimum password length set to 14 characters.' : 'Could not update password length policy.';
    result.output = out3;

  } else if (checkName === 'Password History') {
    var out4 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -PasswordHistoryCount 24 -ErrorAction Stop; Write-Output "Password history set to 24." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out4.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Password history set to remember 24 passwords.' : 'Could not update password history policy.';
    result.output = out4;

  } else if (checkName === 'Maximum Password Age') {
    var out5 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -MaxPasswordAge "90.00:00:00" -ErrorAction Stop; Write-Output "Maximum password age set to 90 days." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out5.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Maximum password age set to 90 days.' : 'Could not update max password age.';
    result.output = out5;

  } else if (checkName === 'Reversible Encryption') {
    var out6 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -ReversibleEncryptionEnabled $false -ErrorAction Stop; Write-Output "Reversible encryption disabled." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out6.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Reversible password encryption disabled.' : 'Could not disable reversible encryption.';
    result.output = out6;

  } else if (checkName === 'Account Lockout Threshold') {
    var out7 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -LockoutThreshold 5 -ErrorAction Stop; Write-Output "Lockout threshold set to 5." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out7.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Account lockout threshold set to 5 attempts.' : 'Could not update lockout threshold.';
    result.output = out7;

  } else if (checkName === 'Account Lockout Duration') {
    var out8 = runPS('try { Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName -LockoutDuration "00:30:00" -ErrorAction Stop; Write-Output "Lockout duration set to 30 minutes." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out8.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Account lockout duration set to 30 minutes.' : 'Could not update lockout duration.';
    result.output = out8;

  } else if (checkName === 'Windows Defender Real-Time Protection') {
    var out9 = runPS('try { Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop; Write-Output "Real-time protection enabled." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out9.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Windows Defender real-time protection enabled.' : 'Could not enable real-time protection (Defender may not be installed).';
    result.output = out9;

  } else if (checkName === 'Antivirus Signatures Current') {
    var out10 = runPS('try { Update-MpSignature -ErrorAction Stop; Write-Output "Antivirus signatures updated." } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 30000);
    result.ok = out10.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Antivirus signatures updated.' : 'Could not update signatures (Defender may not be installed).';
    result.output = out10;

  } else if (checkName === 'Advanced Audit Policy') {
    var out11 = runPS([
      'try {',
      '  auditpol /set /category:"Account Logon" /success:enable /failure:enable | Out-Null',
      '  auditpol /set /category:"Account Management" /success:enable /failure:enable | Out-Null',
      '  auditpol /set /category:"DS Access" /success:enable /failure:enable | Out-Null',
      '  Write-Output "Advanced audit policy configured for Account Logon, Account Management, DS Access."',
      '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
    ].join('\n'), 15000);
    result.ok = out11.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Advanced audit policy (Success and Failure) configured for key categories.' : 'Could not configure audit policy.';
    result.output = out11;

  } else if (checkName === 'Recent Successful Backup') {
    result.ok = false;
    result.message = 'No automatic fix available — please run a backup from the Backup module, or configure a schedule in Settings.';

  } else if (checkName === 'LDAPS Available') {
    result.ok = false;
    result.message = 'No automatic fix available — LDAPS requires a valid server certificate. Install AD Certificate Services, then this check will pass automatically.';

  } else if (checkName === 'KRBTGT Password Age') {
    result.ok = false;
    result.message = 'KRBTGT rotation is not automated here for safety (must be done twice with a 24h gap and can impact Kerberos tickets domain-wide). Follow Microsoft\'s documented krbtgt reset procedure manually.';

  } else {
    result.ok = false;
    result.message = 'No automatic fix is available for "' + checkName + '". Please apply the suggested remediation manually.';
  }

  logger.info('Security recommendation fix attempted: ' + checkName + ' -> ' + (result.ok ? 'success' : 'failed/unavailable'));
  return result;
}

module.exports = { getHealthSummary, applyFix };
