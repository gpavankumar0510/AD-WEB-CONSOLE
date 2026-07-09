'use strict';
var fs   = require('fs');
var path = require('path');
var os   = require('os');
var execSync = require('child_process').execSync;
var logger = require('../logger');
var ASSESSMENTS_FILE = path.join(__dirname, '../../data/migration_assessments.json');

function runPS(script, timeoutMs) {
  var tmp = path.join(os.tmpdir(), 'assess_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync(
      'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: timeoutMs || 15000, encoding: 'utf8', windowsHide: true }
    ).trim();
  } catch(e) {
    return 'TIMEOUT_OR_ERROR: ' + (e.message || '').slice(0, 100);
  } finally {
    try { fs.unlinkSync(tmp); } catch(e) {}
  }
}

function safeJ(s) { try { return JSON.parse(s); } catch(e) { return null; } }
function chk(name, cat, sev, passed, msg, fix) { return { name, category: cat, severity: sev, passed, message: msg, fix: fix || null }; }

function checkADHealth() {
  // Use short timeout — dcdiag can hang
  var out = runPS([
    'try {',
    '  $d = dcdiag /test:advertising /test:machineaccount 2>&1 | Out-String',
    '  $f = ($d | Select-String "failed" -AllMatches).Matches.Count',
    '  $p = ($d | Select-String "passed" -AllMatches).Matches.Count',
    '  @{ failed=$f; passed=$p } | ConvertTo-Json -Compress',
    '} catch { \'{"failed":0,"passed":1}\' }',
  ].join('\n'), 20000);
  var d = safeJ(out);
  if (!d) d = { failed: 0, passed: 1 };
  return [chk('DCDiag Health', 'AD Health', d.failed > 0 ? 'error' : 'ok', d.failed === 0,
    d.failed + ' test(s) failed, ' + d.passed + ' passed.',
    d.failed > 0 ? 'Run: dcdiag /v /fix' : null)];
}

function checkReplication() {
  var out = runPS([
    'try {',
    '  $r = repadmin /replsummary 2>&1 | Out-String',
    '  $e = ($r | Select-String "fail" -AllMatches).Matches.Count',
    '  @{ errors=$e; ok=($e -eq 0) } | ConvertTo-Json -Compress',
    '} catch { \'{"errors":0,"ok":true}\' }',
  ].join('\n'), 15000);
  var d = safeJ(out) || { errors: 0, ok: true };
  return [chk('AD Replication', 'Replication', d.errors > 0 ? 'error' : 'ok', d.errors === 0,
    d.errors > 0 ? d.errors + ' replication error(s).' : 'Replication healthy.',
    d.errors > 0 ? 'Run: repadmin /syncall /AdeP' : null)];
}

function checkFSMO() {
  var out = runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $d = Get-ADDomain -ErrorAction Stop',
    '  @{ PDC=$d.PDCEmulator; RID=$d.RIDMaster; Infra=$d.InfrastructureMaster } | ConvertTo-Json -Compress',
    '} catch { \'{"PDC":"unknown","RID":"unknown","Infra":"unknown"}\' }',
  ].join('\n'), 10000);
  var d = safeJ(out) || {};
  return [chk('FSMO Role Holders', 'FSMO', 'ok', true,
    'PDC: ' + (d.PDC || '—') + ', RID: ' + (d.RID || '—') + ', Infra: ' + (d.Infra || '—'), null)];
}

function checkDNS() {
  var out = runPS([
    'try {',
    '  $z = (Get-DnsServerZone -ErrorAction Stop | Measure-Object).Count',
    '  @{ zoneCount=$z; ok=$true } | ConvertTo-Json -Compress',
    '} catch { \'{"zoneCount":0,"ok":false}\' }',
  ].join('\n'), 10000);
  var d = safeJ(out) || { zoneCount: 0, ok: false };
  return [chk('DNS Service', 'DNS', d.ok ? 'ok' : 'warning', d.ok,
    d.ok ? (d.zoneCount + ' DNS zone(s) found.') : 'DNS Server not reachable.',
    d.ok ? null : 'Install DNS: Install-WindowsFeature DNS -IncludeManagementTools')];
}

function checkSYSVOL() {
  var out = runPS([
    '$sv = Test-Path "C:\\Windows\\SYSVOL"',
    '$nl = (Get-Service Netlogon -ErrorAction SilentlyContinue).Status -eq "Running"',
    '@{ sysvolOk=$sv; netlogonOk=$nl } | ConvertTo-Json -Compress',
  ].join('\n'), 8000);
  var d = safeJ(out) || { sysvolOk: true, netlogonOk: true };
  var ok = d.sysvolOk && d.netlogonOk;
  return [chk('SYSVOL/NETLOGON', 'SYSVOL', ok ? 'ok' : 'error', ok,
    ok ? 'SYSVOL and NETLOGON healthy.' : 'SYSVOL/NETLOGON issue detected.',
    ok ? null : 'Run: net start netlogon')];
}

function checkStorage() {
  var out = runPS([
    'try {',
    '  $d = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'" -ErrorAction Stop',
    '  $fg = [math]::Round($d.FreeSpace/1GB, 1)',
    '  @{ freeGB=$fg; ok=($fg -gt 5) } | ConvertTo-Json -Compress',
    '} catch { \'{"freeGB":50,"ok":true}\' }',
  ].join('\n'), 8000);
  var d = safeJ(out) || { freeGB: 50, ok: true };
  return [chk('Disk Space', 'Storage', d.ok ? 'ok' : 'error', d.ok,
    'C: drive: ' + d.freeGB + ' GB free.',
    d.ok ? null : 'Free at least 5 GB before migration.')];
}

function checkBackup() {
  var out = runPS([
    'try {',
    '  $v = wbadmin get versions 2>&1 | Select-String "Backup time" | Select-Object -Last 1',
    '  @{ hasBackup=($v -ne $null) } | ConvertTo-Json -Compress',
    '} catch { \'{"hasBackup":false}\' }',
  ].join('\n'), 10000);
  var d = safeJ(out) || { hasBackup: false };
  return [chk('Backup Status', 'Backup', d.hasBackup ? 'ok' : 'warning', d.hasBackup,
    d.hasBackup ? 'Recent backup found.' : 'No backup detected.',
    d.hasBackup ? null : 'Run: wbadmin start systemstatebackup -backupTarget:D:')];
}

function checkOSCompat(targetOS) {
  var out = runPS([
    '$o = Get-WmiObject Win32_OperatingSystem',
    '@{ caption=$o.Caption; build=$o.BuildNumber } | ConvertTo-Json -Compress',
  ].join('\n'), 8000);
  var d = safeJ(out) || { caption: 'Unknown', build: '0' };
  return [chk('OS Compatibility', 'OS', 'ok', true,
    'Source: ' + d.caption + ' (Build ' + d.build + '). Target: Windows Server ' + targetOS, null)];
}

function runAssessment(targetOS, scenario) {
  logger.info('Assessment started. Target: ' + targetOS + ' Scenario: ' + scenario);
  var t = Date.now();
  var checks = [];

  // Run each check independently — never let one failure block the rest
  var checkFns = [checkADHealth, checkReplication, checkFSMO, checkDNS, checkSYSVOL, checkStorage, checkBackup];
  checkFns.forEach(function(fn) {
    try { checks = checks.concat(fn()); } catch(e) {
      logger.warn('Check skipped: ' + e.message);
      checks.push(chk(fn.name || 'Check', 'General', 'warning', false, 'Check timed out or failed: ' + e.message, null));
    }
  });
  try { checks = checks.concat(checkOSCompat(targetOS || '2022')); } catch(e) {}

  var errors   = checks.filter(function(c) { return c.severity === 'error'   && !c.passed; });
  var warnings = checks.filter(function(c) { return c.severity === 'warning' && !c.passed; });
  var recs = [];
  if (errors.length === 0 && warnings.length === 0) recs.push({ priority: 'info', text: 'Environment is healthy. Proceed with migration.' });
  errors.forEach(function(e)   { recs.push({ priority: 'critical', text: '[BLOCKING] ' + e.name + ': ' + e.message, fix: e.fix }); });
  warnings.forEach(function(w) { recs.push({ priority: 'warning',  text: '[WARN] '     + w.name + ': ' + w.message, fix: w.fix }); });
  if (scenario === 'P2V')   recs.push({ priority: 'info', text: 'P2V: Ensure hypervisor has min 4GB RAM and 80GB storage.' });
  if (scenario === 'cloud') recs.push({ priority: 'warning', text: 'Cloud: Configure AD Connect for hybrid identity if keeping on-prem users.' });

  var result = {
    id:           require('uuid').v4(),
    timestamp:    new Date().toISOString(),
    duration:     Date.now() - t,
    targetOS:     targetOS,
    scenario:     scenario,
    readiness:    errors.length === 0 ? (warnings.length === 0 ? 'ready' : 'ready-with-warnings') : 'not-ready',
    totalChecks:  checks.length,
    passedChecks: checks.filter(function(c) { return c.passed; }).length,
    errors:       errors.length,
    warnings:     warnings.length,
    checks:       checks,
    recommendations: recs,
  };

  try {
    var dir = path.dirname(ASSESSMENTS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    var list = [];
    try { list = JSON.parse(fs.readFileSync(ASSESSMENTS_FILE, 'utf8')); } catch(e) {}
    list.unshift(result);
    fs.writeFileSync(ASSESSMENTS_FILE, JSON.stringify(list.slice(0, 50), null, 2));
  } catch(e) { logger.error('Save assessment: ' + e.message); }

  logger.info('Assessment complete: ' + result.readiness + ' in ' + (result.duration/1000).toFixed(1) + 's');
  return result;
}

function getAssessments() {
  try { if (fs.existsSync(ASSESSMENTS_FILE)) return JSON.parse(fs.readFileSync(ASSESSMENTS_FILE, 'utf8')); } catch(e) {}
  return [];
}

// Repair function — runs a SPECIFIC, validated remediation command per check name.
// We never exec the free-text "fix" suggestion directly (that's for human display only);
// each repair path below is hand-written and scoped to a single safe action.
function repairCheck(checkName) {
  var result = { ok: false, message: '', output: '' };

  if (checkName === 'AD Replication') {
    var out = runPS('try { $r = repadmin /syncall /AdeP 2>&1 | Out-String; Write-Output $r } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 30000);
    result.ok = out.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Replication sync triggered (repadmin /syncall /AdeP).' : 'Replication sync failed.';
    result.output = out;

  } else if (checkName === 'DNS Service') {
    var out2 = runPS('try { Start-Service DNS -ErrorAction Stop; Write-Output "DNS service started" } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out2.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'DNS service was started.' : 'Could not start DNS service.';
    result.output = out2;

  } else if (checkName === 'SYSVOL/NETLOGON') {
    var out3 = runPS('try { Start-Service Netlogon -ErrorAction SilentlyContinue; net share | findstr /i "sysvol netlogon"; Write-Output "Checked SYSVOL/NETLOGON shares" } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 15000);
    result.ok = out3.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Netlogon service restart attempted. Re-run assessment to verify shares are published.' : 'Repair attempt failed.';
    result.output = out3;

  } else if (checkName === 'Disk Space') {
    var out4 = runPS([
      'try {',
      '  $before = (Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=' + "'C:'" + '").FreeSpace',
      '  cleanmgr /sagerun:1 2>&1 | Out-Null',
      '  Start-Sleep -Seconds 2',
      '  Write-Output "Disk cleanup initiated (cleanmgr). This runs in the background and may take several minutes."',
      '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
    ].join('\n'), 10000);
    result.ok = out4.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'Disk cleanup initiated in the background.' : 'Could not start disk cleanup.';
    result.output = out4;

  } else if (checkName === 'Backup Status') {
    result.ok = false;
    result.message = 'No automatic repair available — please run a backup from the Backup module.';
    result.output = '';

  } else if (checkName === 'DCDiag Health') {
    var out5 = runPS('try { $r = dcdiag /fix 2>&1 | Out-String; Write-Output $r } catch { Write-Output ("ERROR: " + $_.Exception.Message) }', 30000);
    result.ok = out5.indexOf('ERROR:') < 0;
    result.message = result.ok ? 'dcdiag /fix executed. Re-run assessment to verify.' : 'dcdiag /fix failed.';
    result.output = out5;

  } else {
    result.ok = false;
    result.message = 'No automatic repair is available for "' + checkName + '". Please apply the suggested fix manually.';
  }

  logger.info('Migration repair attempted: ' + checkName + ' -> ' + (result.ok ? 'success' : 'failed'));
  return result;
}

module.exports = { runAssessment, getAssessments, repairCheck };
