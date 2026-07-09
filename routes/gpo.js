'use strict';
var gpoBackup = require('../utils/gpoBackup');
var express  = require('express');
var router   = express.Router();
var gpoStore = require('../utils/gpoStore');
var gpoSync  = require('../utils/gpoSync');
var rbac     = require('../utils/rbac');
var recycleBin = require('../utils/recycleBin');
var audit     = require('../utils/auditLogger');
var ad       = require('../utils/adService');
var logger   = require('../utils/logger');
var fs       = require('fs');
var path     = require('path');
var os       = require('os');
var execSync = require('child_process').execSync;
var GPO_TEMPLATES = require('../utils/gpoTemplates').GPO_TEMPLATES;

function runPS(script) {
  var tmp = path.join(os.tmpdir(), 'gpo_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync(
      'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: 30000, encoding: 'utf8', windowsHide: true }
    ).trim();
  } catch(e) { return 'ERROR: ' + e.message; }
  finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function applyLinkToAD(policyName, target) {
  var pname = policyName.replace(/"/g,'').replace(/`/g,'');
  var ttarget = target.replace(/"/g,'').replace(/`/g,'');
  var script = [
    '$ErrorActionPreference = "Stop"',
    '$log = @()',
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  $log += "ModuleLoaded"',
    '} catch { Write-Output "ERROR: Failed to load GroupPolicy module - " + $_.Exception.Message; exit }',
    '',
    '$gpo = $null',
    'try {',
    '  $gpo = Get-GPO -Name "' + pname + '" -ErrorAction Stop',
    '  $log += "FoundExisting:" + $gpo.Id.ToString()',
    '} catch {',
    '  try {',
    '    $gpo = New-GPO -Name "' + pname + '" -ErrorAction Stop',
    '    $log += "CreatedGPO:" + $gpo.Id.ToString()',
    '  } catch {',
    '    Write-Output ("ERROR: Failed to find or create GPO " + [char]39 + "' + pname + '" + [char]39 + " - " + $_.Exception.Message)',
    '    exit',
    '  }',
    '}',
    '',
    'try {',
    '  $existing = Get-GPInheritance -Target "' + ttarget + '" -ErrorAction Stop',
    '  $log += "GotInheritance"',
    '} catch {',
    '  Write-Output ("ERROR: Target OU/Domain not found or inaccessible: " + "' + ttarget + '" + " - " + $_.Exception.Message)',
    '  exit',
    '}',
    '',
    '$alreadyLinked = $existing.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }',
    'if ($alreadyLinked) {',
    '  Write-Output ("ALREADY_LINKED:" + ($log -join ";"))',
    '  exit',
    '}',
    '',
    'try {',
    '  New-GPLink -Name "' + pname + '" -Target "' + ttarget + '" -LinkEnabled Yes -ErrorAction Stop | Out-Null',
    '  Write-Output ("LINKED:" + $gpo.Id.ToString() + "|" + ($log -join ";"))',
    '} catch {',
    '  Write-Output ("ERROR: New-GPLink failed - " + $_.Exception.Message + " | log=" + ($log -join ";"))',
    '}',
  ].join('\n');
  return runPS(script);
}

function removeLinkFromAD(policyName, target) {
  var script = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  Remove-GPLink -Name "' + policyName + '" -Target "' + target + '" -ErrorAction SilentlyContinue',
    '  Write-Output "Removed"',
    '} catch { Write-Output "ERROR: " + $_.Exception.Message }',
  ].join('\n');
  return runPS(script);
}

function deleteGPOFromAD(policyName) {
  var script = [
    'try {',
    '  Import-Module GroupPolicy -ErrorAction Stop',
    '  Remove-GPO -Name "' + policyName + '" -Confirm:$false -ErrorAction Stop',
    '  Write-Output "Deleted"',
    '} catch { Write-Output "SKIP: " + $_.Exception.Message }',
  ].join('\n');
  return runPS(script);
}

// List all policies
// Map common setting keys to actual registry paths for Set-GPRegistryValue
var SETTING_REGISTRY_MAP = {
  'MinimumPasswordLength':  null, // handled via password policy, not registry
  'ScreensaverTimeout':     { key: 'HKCU\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Control Panel\\\\Desktop', value: 'ScreenSaveTimeOut', type: 'String' },
  'UAC':                    { key: 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\System', value: 'EnableLUA', type: 'DWord', map: { Enabled: 1, Disabled: 0 } },
  'WindowsFirewall':        { key: 'HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\WindowsFirewall\\\\StandardProfile', value: 'EnableFirewall', type: 'DWord', map: { Enabled: 1, Disabled: 0 } },
  'SMBSigning':             { key: 'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\LanmanWorkstation\\\\Parameters', value: 'RequireSecuritySignature', type: 'DWord', map: { Required: 1, Disabled: 0 } },
  'RDPEnabled':             { key: 'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server', value: 'fDenyTSConnections', type: 'DWord', map: { Enabled: 0, Disabled: 1 } },
  'NLARequired':            { key: 'HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Terminal Server\\\\WinStations\\\\RDP-Tcp', value: 'UserAuthentication', type: 'DWord', map: { Enabled: 1, Disabled: 0 } },
  'AutorunDisabled':        { key: 'HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer', value: 'NoDriveTypeAutoRun', type: 'DWord', map: { Enabled: 255, Disabled: 0 } },
  'SmartScreen':            { key: 'HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\System', value: 'EnableSmartScreen', type: 'DWord', map: { Enabled: 1, Disabled: 0 } },
  'EventLogSize':           { key: 'HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\EventLog\\\\Application', value: 'MaxSize', type: 'DWord' },
  'WSUSServer':             { key: 'HKLM\\\\SOFTWARE\\\\Policies\\\\Microsoft\\\\Windows\\\\WindowsUpdate', value: 'WUServer', type: 'String' },
};

function pushSettingsToAD(policyName, settings) {
  var lines = ['try {', '  Import-Module GroupPolicy -ErrorAction Stop', '  $applied = @()', '  $skipped = @()'];
  settings.forEach(function(s) {
    var mapping = SETTING_REGISTRY_MAP[s.key];
    if (!mapping) {
      lines.push('  $skipped += "' + s.key.replace(/"/g,'') + ' (no registry mapping)"');
      return;
    }
    var value = s.value;
    if (mapping.map && mapping.map[value] !== undefined) value = mapping.map[value];
    var valueArg = mapping.type === 'String' ? '"' + String(value).replace(/"/g,'') + '"' : value;
    lines.push('  try {');
    lines.push('    Set-GPRegistryValue -Name "' + policyName.replace(/"/g,'') + '" -Key "' + mapping.key + '" -ValueName "' + mapping.value + '" -Type ' + mapping.type + ' -Value ' + valueArg + ' -ErrorAction Stop | Out-Null');
    lines.push('    $applied += "' + s.key.replace(/"/g,'') + '"');
    lines.push('  } catch { $skipped += "' + s.key.replace(/"/g,'') + ' (' + '$($_.Exception.Message)' + ')" }');
  });
  lines.push('  Write-Output ("APPLIED:" + ($applied -join ",") + "|SKIPPED:" + ($skipped -join ";"))');
  lines.push('} catch { Write-Output "ERROR: " + $_.Exception.Message }');
  var out = runPS(lines.join('\n'));
  return out;
}


router.get('/', function(req, res) {
  var policies = gpoStore.getAllPolicies();
  var links    = gpoStore.getAllLinks();
  var lastSync = null;
  try {
    var sf = path.join(__dirname, '../data/gpo_last_sync.json');
    if (fs.existsSync(sf)) lastSync = JSON.parse(fs.readFileSync(sf)).time;
  } catch(e) {}
  res.render('gpo/list', {
    admin: req.session.admin, policies: policies,
    links: links, page: 'gpo', lastSync: lastSync,
  });
});

// Templates
router.get('/templates', function(req, res) {
  res.render('gpo/templates', {
    admin: req.session.admin, templates: GPO_TEMPLATES,
    page: 'gpo', subpage: 'templates',
  });
});

// Sync from AD
router.post('/sync-from-ad', function(req, res) {
  try {
    var result = gpoSync.fullSync();
    var sf = path.join(__dirname, '../data/gpo_last_sync.json');
    var dir = path.dirname(sf);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(sf, JSON.stringify({ time: new Date().toISOString(), result: result }));
    logger.info('GPO sync: imported=' + result.imported + ' total=' + result.total);
    res.json({ ok: true, message: 'Synced ' + result.total + ' GPO(s). Imported: ' + result.imported + '.' });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Create from template
router.post('/from-template/:id', function(req, res) {
  var template = GPO_TEMPLATES.find(function(t) { return t.id === req.params.id; });
  if (!template) return res.redirect('/gpo/templates');
  var policy = gpoStore.createPolicy({
    name: req.body.name || template.name,
    description: req.body.description || template.description,
    templateId: template.id, category: template.category,
    settings: template.settings, status: 'Active',
    createdBy: req.session.admin.username,
  });
  logger.info('GPO from template: ' + policy.name + ' by ' + req.session.admin.username);
  res.redirect('/gpo/' + policy.id + '?created=1');
});

// Create custom
router.get('/create', function(req, res) {
  res.render('gpo/create', { admin: req.session.admin, page: 'gpo', error: null });
});

router.post('/create', function(req, res) {
  var keys  = [].concat(req.body.settingKey   || []);
  var vals  = [].concat(req.body.settingValue || []);
  var descs = [].concat(req.body.settingDesc  || []);
  var settings = [];
  keys.forEach(function(k, i) {
    if (k && k.trim()) {
      settings.push({ key: k.trim(), value: (vals[i]||'').trim(), description: (descs[i]||'').trim() });
    }
  });
  var policy = gpoStore.createPolicy({
    name: req.body.name, description: req.body.description || '',
    category: req.body.category || 'Custom', settings: settings,
    status: 'Active', createdBy: req.session.admin.username,
  });
  logger.info('Custom GPO created: ' + policy.name + ' by ' + req.session.admin.username);
  res.redirect('/gpo/' + policy.id);
});

// View/edit policy
router.get('/:id', async function(req, res) {
  var policy = gpoStore.getPolicy(req.params.id);
  if (!policy) return res.redirect('/gpo');
  var links  = gpoStore.getLinksForPolicy(req.params.id);
  var ous    = await ad.getOUs().catch(function() { return []; });
  var groups = await ad.getGroups().catch(function() { return []; });
  var cfg    = require('../utils/autoDetect').getSettings();
  res.render('gpo/detail', {
    admin: req.session.admin, policy: policy, links: links,
    ous: ous, groups: groups, page: 'gpo', created: req.query.created || null,
    domainDN: cfg.baseDN, domainName: cfg.domain,
    success: req.query.success || null, error: req.query.error || null,
  });
});

// Update settings
router.post('/:id/update', function(req, res) {
  var keys  = [].concat(req.body.settingKey   || []);
  var vals  = [].concat(req.body.settingValue || []);
  var descs = [].concat(req.body.settingDesc  || []);
  var settings = [];
  keys.forEach(function(k, i) {
    if (k && k.trim()) {
      settings.push({ key: k.trim(), value: (vals[i]||'').trim(), description: (descs[i]||'').trim() });
    }
  });
  var policy = gpoStore.getPolicy(req.params.id);
  gpoStore.updatePolicy(req.params.id, {
    name: req.body.name,
    description: req.body.description || '',
    settings: settings,
  });
  logger.info('GPO updated: ' + req.params.id + ' by ' + req.session.admin.username);

  // Push settings to actual AD GPO registry.pol if this is an AD-synced or any named GPO
  var policyName = req.body.name || (policy && policy.name);
  if (policyName && settings.length) {
    var pushResult = pushSettingsToAD(policyName, settings);
    if (pushResult.indexOf('ERROR:') >= 0) {
      logger.warn('GPO push to AD failed: ' + pushResult);
    } else {
      logger.info('GPO settings pushed to AD: ' + pushResult.slice(0, 200));
    }
  }

  res.redirect('/gpo/' + req.params.id + '?success=' + encodeURIComponent('Settings saved and synced to AD'));
});

// Link policy — saves in console AND applies in Windows AD
router.post('/:id/link', function(req, res) {
  var policy = gpoStore.getPolicy(req.params.id);
  if (!req.body.target || !policy) return res.redirect('/gpo/' + req.params.id + '?error=' + encodeURIComponent('Missing target or policy not found'));

  // Apply link in actual Windows AD via PowerShell FIRST - only save console link if AD succeeds
  var adResult = applyLinkToAD(policy.name, req.body.target);
  logger.info('GPO link result for ' + policy.name + ' -> ' + req.body.target + ': ' + adResult);

  if (adResult.indexOf('ERROR:') >= 0 || adResult.indexOf('ERROR ') >= 0) {
    return res.redirect('/gpo/' + req.params.id + '?error=' + encodeURIComponent('AD link failed: ' + adResult.replace(/^ERROR:\s*/,'')));
  }

  // Success (LINKED or ALREADY_LINKED) - now save console-side record
  gpoStore.createLink(req.params.id, req.body.target, req.body.targetType);

  // Extract GUID if present and store it on the policy
  var guidMatch = adResult.match(/(?:LINKED|FoundExisting|CreatedGPO):([0-9a-f-]{36})/i);
  if (!guidMatch) {
    // Try the LINKED:<guid>| format
    guidMatch = adResult.match(/^LINKED:([0-9a-f-]{36})/i);
  }
  if (guidMatch && !policy.adGpoId) {
    gpoStore.updatePolicy(req.params.id, { adGpoId: guidMatch[1] });
  }

  var msg = adResult.indexOf('ALREADY_LINKED') >= 0
    ? 'GPO was already linked to ' + req.body.target + ' (link recorded in console)'
    : 'GPO linked successfully to ' + req.body.target;

  res.redirect('/gpo/' + req.params.id + '?success=' + encodeURIComponent(msg));
});

// Remove link — removes from console AND from Windows AD
router.post('/link/:linkId/delete', function(req, res) {
  var allLinks = gpoStore.getAllLinks();
  var link     = allLinks.find(function(l) { return l.id === req.params.linkId; });
  var policy   = link ? gpoStore.getPolicy(link.policyId) : null;

  gpoStore.deleteLink(req.params.linkId);

  if (policy && link) {
    var adResult = removeLinkFromAD(policy.name, link.target);
    logger.info('GPO unlinked from AD: ' + policy.name + ' -> ' + link.target + ' (' + adResult + ')');
  }

  res.json({ ok: true });
});

// Delete policy — removes from console AND from Windows AD, moves to recycle bin
router.post('/:id/delete', function(req, res) {
  var policy = gpoStore.getPolicy(req.params.id);
  if (policy) {
    var adResult = deleteGPOFromAD(policy.name);
    logger.info('GPO deleted from AD: ' + policy.name + ' (' + adResult + ')');

    // Move to recycle bin before deleting from store
    var links = gpoStore.getLinksForPolicy(req.params.id);
    recycleBin.add({
      type: 'gpo',
      name: policy.name,
      displayName: policy.name,
      policyData: policy,
      links: links,
      deletedBy: req.session.admin.username,
    });
    audit.log('GPO_DELETED', req.session.admin.username, policy.name, 'Moved to recycle bin', req.ip);
  }
  gpoStore.deletePolicy(req.params.id);
  logger.info('GPO deleted from console: ' + req.params.id + ' by ' + req.session.admin.username);
  res.redirect('/gpo');
});


// ── GPO Backup / Restore / Import / Export ────────────────────────────────

router.get('/backup', rbac.requirePermission('dashboard.view'), function(req, res) {
  var history = gpoBackup.getHistory();
  var policies = gpoStore.getAllPolicies ? gpoStore.getAllPolicies() : [];
  res.render('gpo/backup', {
    admin: req.session.admin, page: 'gpo',
    history: history, policies: policies,
    defaultPath: gpoBackup.DEFAULT_BACKUP_PATH,
    error: req.query.error || null, success: req.query.success || null,
  });
});

// Backup one or all GPOs - returns JSON so the JS can show progress feedback
router.post('/backup/run', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var gpoName = (req.body.gpoName || '*').trim();
    var backupPath = (req.body.backupPath || gpoBackup.DEFAULT_BACKUP_PATH).trim();
    var result = gpoBackup.backupGPO(gpoName === '*' ? null : gpoName, backupPath, req.session.admin.username);
    audit.log('GPO_BACKUP', req.session.admin.username, gpoName, backupPath, req.ip);
    res.json(result);
  } catch(e) {
    logger.error('GPO backup: ' + e.message);
    res.json({ ok: false, error: e.message });
  }
});

// List available backups in a folder (AJAX)
router.post('/backup/list', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var backupPath = (req.body.backupPath || gpoBackup.DEFAULT_BACKUP_PATH).trim();
    var result = gpoBackup.listBackups(backupPath);
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message, backups: [] });
  }
});

// Restore GPOs from backup
router.post('/backup/restore', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var backupPath = (req.body.backupPath || gpoBackup.DEFAULT_BACKUP_PATH).trim();
    var backupIds = req.body.backupIds;
    if (typeof backupIds === 'string') backupIds = backupIds ? [backupIds] : [];
    if (!Array.isArray(backupIds)) backupIds = [];
    var restoreAll = req.body.restoreAll === '1' || backupIds.length === 0;
    var result = gpoBackup.restoreGPO(backupPath, restoreAll ? [] : backupIds, null, req.session.admin.username);
    audit.log('GPO_RESTORE', req.session.admin.username, restoreAll ? 'ALL' : backupIds.join(','), backupPath, req.ip);
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

// Export a single GPO as HTML or XML report
router.get('/export/:id', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var policy = gpoStore.getPolicy(req.params.id);
    if (!policy) return res.status(404).send('GPO not found');
    var format = (req.query.format || 'HTML').toUpperCase();
    var gpoName = policy.adGpoName || policy.name;
    var result = gpoBackup.exportGPOReport(gpoName, format);
    if (!result.ok) return res.status(500).send('Export failed: ' + result.error);
    var contentType = format === 'XML' ? 'application/xml' : 'text/html';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'attachment; filename="' + result.filename + '"');
    res.send(result.content);
  } catch(e) {
    res.status(500).send('Export error: ' + e.message);
  }
});

// Export a GPO by AD name (used from backup page)
router.post('/backup/export', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var gpoName = (req.body.gpoName || '').trim();
    var format = (req.body.format || 'HTML').toUpperCase();
    if (!gpoName) return res.json({ ok: false, error: 'GPO name required' });
    var result = gpoBackup.exportGPOReport(gpoName, format);
    if (!result.ok) return res.json({ ok: false, error: result.error });
    // Return as base64 so the browser can download it via JS
    var b64 = Buffer.from(result.content, 'utf8').toString('base64');
    res.json({ ok: true, filename: result.filename, content: b64, format: format });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
