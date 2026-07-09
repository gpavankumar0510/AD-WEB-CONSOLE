'use strict';
var fs   = require('fs');
var path = require('path');
var os   = require('os');
var execSync = require('child_process').execSync;
var logger = require('./logger');

var BACKUP_HISTORY_FILE = path.join(__dirname, '../data/gpo_backup_history.json');
var DEFAULT_BACKUP_PATH = 'C:\\GPOBackups';

function runPS(script, timeoutMs) {
  var tmp = path.join(os.tmpdir(), 'gpobak_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: timeoutMs || 30000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return 'ERROR: ' + e.message; }
  finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function safeJ(s) { try { return JSON.parse(s); } catch(e) { return null; } }

function getHistory() {
  try {
    var dir = path.dirname(BACKUP_HISTORY_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(BACKUP_HISTORY_FILE))
      return JSON.parse(fs.readFileSync(BACKUP_HISTORY_FILE, 'utf8'));
  } catch(e) {}
  return [];
}

function addHistory(entry) {
  var h = getHistory();
  h.unshift(Object.assign({ id: require('crypto').randomBytes(6).toString('hex'), timestamp: new Date().toISOString() }, entry));
  h = h.slice(0, 100); // keep last 100 entries
  try { fs.writeFileSync(BACKUP_HISTORY_FILE, JSON.stringify(h, null, 2)); } catch(e) {}
}

// Backup a single GPO or all GPOs to a folder
function backupGPO(gpoName, backupPath, actor) {
  backupPath = backupPath || DEFAULT_BACKUP_PATH;
  var isAll = !gpoName || gpoName === '*';

  var script = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $backupPath = "' + backupPath.replace(/\\/g, '\\\\') + '"',
    '  if (-not (Test-Path $backupPath)) { New-Item -ItemType Directory -Path $backupPath -Force | Out-Null }',
    isAll
      ? '  $results = Backup-GPO -All -Path $backupPath -ErrorAction Stop'
      : '  $results = Backup-GPO -Name "' + gpoName + '" -Path $backupPath -ErrorAction Stop',
    '  $out = @{ ok=$true; count=($results | Measure-Object).Count; path=$backupPath; ids=@($results | ForEach-Object { $_.Id.ToString() }) }',
    '  $out | ConvertTo-Json -Compress',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
  ].join('\n');

  var out = runPS(script, 60000);
  if (out.indexOf('ERROR:') === 0) {
    addHistory({ action: 'backup', gpo: gpoName||'all', path: backupPath, status: 'failed', error: out.replace('ERROR: ',''), actor });
    return { ok: false, error: out.replace('ERROR: ', '') };
  }
  var parsed = safeJ(out);
  if (!parsed || !parsed.ok) {
    addHistory({ action: 'backup', gpo: gpoName||'all', path: backupPath, status: 'failed', error: 'Unexpected output', actor });
    return { ok: false, error: 'Unexpected output from backup command' };
  }
  addHistory({ action: 'backup', gpo: gpoName||'all', path: backupPath, status: 'completed', count: parsed.count, actor });
  logger.info('GPO backup: ' + (gpoName||'ALL') + ' -> ' + backupPath + ' (' + parsed.count + ' GPO(s)) by ' + actor);
  return { ok: true, count: parsed.count, path: backupPath };
}

// List available backups in a folder
function listBackups(backupPath) {
  backupPath = backupPath || DEFAULT_BACKUP_PATH;
  var script = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $backupPath = "' + backupPath.replace(/\\/g, '\\\\') + '"',
    '  if (-not (Test-Path $backupPath)) { Write-Output "[]"; exit }',
    '  $backups = Get-GPOBackup -All -Path $backupPath -ErrorAction Stop',
    '  $results = @($backups | ForEach-Object {',
    '    @{ gpoName=$_.DisplayName; gpoId=$_.GpoId.ToString(); backupId=$_.Id.ToString(); timestamp=$_.Timestamp.ToString("o"); domain=$_.Domain }',
    '  })',
    '  $results | ConvertTo-Json -Compress -Depth 3',
    '} catch { Write-Output "ERROR: " + $_.Exception.Message }',
  ].join('\n');

  var out = runPS(script, 20000);
  if (!out || out.indexOf('ERROR:') === 0) return { ok: false, error: out ? out.replace('ERROR: ','') : 'No backup folder found', backups: [] };
  var parsed = safeJ(out);
  if (!parsed) return { ok: true, backups: [] };
  if (!Array.isArray(parsed)) parsed = [parsed];
  return { ok: true, backups: parsed };
}

// Restore one or more GPOs from backup
function restoreGPO(backupPath, backupIds, targetDomain, actor) {
  backupPath = backupPath || DEFAULT_BACKUP_PATH;
  var restoreAll = !backupIds || !backupIds.length;
  var idList = Array.isArray(backupIds) ? backupIds : [backupIds];

  var scriptLines = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $backupPath = "' + backupPath.replace(/\\/g, '\\\\') + '"',
    '  $restored = 0; $failed = 0; $errors = @()',
  ];

  if (restoreAll) {
    scriptLines.push('  $backups = Get-GPOBackup -All -Path $backupPath -ErrorAction Stop');
    scriptLines.push('  foreach ($b in $backups) {');
    scriptLines.push('    try { Restore-GPO -Name $b.DisplayName -Path $backupPath -ErrorAction Stop; $restored++ }');
    scriptLines.push('    catch { $failed++; $errors += $_.Exception.Message }');
    scriptLines.push('  }');
  } else {
    idList.forEach(function(bId) {
      var safeId = bId.replace(/[^a-zA-Z0-9\-]/g, '');
      scriptLines.push('  try { Restore-GPO -BackupId "' + safeId + '" -Path $backupPath -ErrorAction Stop; $restored++ }');
      scriptLines.push('  catch { $failed++; $errors += $_.Exception.Message }');
    });
  }

  scriptLines.push('  @{ ok=$true; restored=$restored; failed=$failed; errors=$errors } | ConvertTo-Json -Compress');
  scriptLines.push('} catch { Write-Output ("ERROR: " + $_.Exception.Message) }');

  var out = runPS(scriptLines.join('\n'), 120000);
  if (out.indexOf('ERROR:') === 0) {
    addHistory({ action: 'restore', path: backupPath, status: 'failed', error: out.replace('ERROR: ',''), actor });
    return { ok: false, error: out.replace('ERROR: ', '') };
  }
  var parsed = safeJ(out);
  if (!parsed) { return { ok: false, error: 'Unexpected output from restore command' }; }
  addHistory({ action: 'restore', path: backupPath, status: parsed.failed > 0 ? 'partial' : 'completed', restored: parsed.restored, failed: parsed.failed, actor });
  logger.info('GPO restore: ' + parsed.restored + ' restored, ' + parsed.failed + ' failed from ' + backupPath + ' by ' + actor);
  return { ok: true, restored: parsed.restored, failed: parsed.failed, errors: parsed.errors || [] };
}

// Export GPO as HTML report
function exportGPOReport(gpoName, format) {
  format = format || 'HTML';
  var ext = format === 'XML' ? 'xml' : 'html';
  var outFile = path.join(os.tmpdir(), 'gpo_export_' + Date.now() + '.' + ext);
  var script = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  Get-GPOReport -Name "' + gpoName + '" -ReportType ' + format + ' -Path "' + outFile.replace(/\\/g, '\\\\') + '" -ErrorAction Stop',
    '  Write-Output "OK:' + outFile.replace(/\\/g, '\\\\') + '"',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }',
  ].join('\n');

  var out = runPS(script, 30000);
  if (out.indexOf('OK:') === 0) {
    var filePath = out.replace('OK:', '').trim();
    try {
      var content = fs.readFileSync(filePath, 'utf8');
      try { fs.unlinkSync(filePath); } catch(e) {}
      return { ok: true, content: content, filename: gpoName.replace(/[^a-z0-9_\-]/gi, '_') + '_report.' + ext };
    } catch(e) { return { ok: false, error: 'Could not read export file: ' + e.message }; }
  }
  return { ok: false, error: out.replace('ERROR: ', '') };
}

module.exports = { backupGPO, listBackups, restoreGPO, exportGPOReport, getHistory, DEFAULT_BACKUP_PATH };
