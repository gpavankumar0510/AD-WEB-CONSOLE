'use strict';
var express  = require('express');
var router   = express.Router();
var backup   = require('../utils/backupService');
var settings = require('../utils/settings');
var audit    = require('../utils/auditLogger');
var logger   = require('../utils/logger');
var fs       = require('fs');
var path     = require('path');
var os       = require('os');
var execSync = require('child_process').execSync;

function runPS(script) {
  var tmp = path.join(os.tmpdir(), 'bk_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: 15000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; } finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

router.get('/', function(req, res) {
  var history  = backup.getHistory();
  var sched    = backup.getSchedule();
  var s        = settings.get();
  res.render('backup/index', { admin: req.session.admin, history: history, schedule: sched, s: s, page: 'backup' });
});

router.post('/start', async function(req, res) {
  var type = req.body.type || 'AD-State';
  var dest = req.body.destination || settings.get().backupDestination || 'C:\\ADBackups';
  logger.info('Backup started: ' + type + ' -> ' + dest + ' by ' + req.session.admin.username);
  audit.log('BACKUP_STARTED', req.session.admin.username, dest, type, req.ip);
  backup.runBackup(type, dest).then(function(r) {
    audit.log('BACKUP_COMPLETED', req.session.admin.username, dest, type + ' status=' + r.status, req.ip);
  }).catch(function(e) {
    logger.error('Backup error: ' + e.message);
    audit.log('BACKUP_FAILED', req.session.admin.username, dest, e.message, req.ip);
  });
  res.json({ ok: true, message: 'Backup job (' + type + ') started to ' + dest });
});

// Restore from backup
router.post('/restore', async function(req, res) {
  var backupPath = req.body.backupPath || '';
  if (!backupPath) return res.json({ ok: false, error: 'Backup path required' });
  var script = [
    '$bp = "' + backupPath.replace(/"/g,'') + '"',
    'if (-not (Test-Path $bp)) { Write-Output "ERROR: Path not found: $bp"; exit 1 }',
    '$versions = wbadmin get versions -backupTarget:$bp 2>&1 | Out-String',
    'Write-Output $versions',
  ].join('\n');
  var out = runPS(script);
  if (out.indexOf('ERROR:') >= 0 || !out.trim()) return res.json({ ok: false, error: 'Cannot read backup versions from: ' + backupPath });
  res.json({ ok: true, message: 'Backup versions found:\n' + out.slice(0, 500) + '\n\nTo restore, run on the DC:\nwbadmin start systemstaterecovery -version:<version> -backupTarget:' + backupPath + ' -quiet' });
});

router.get('/history', function(req, res) { res.json(backup.getHistory()); });

// Server-side folder browser for backup destination picker
router.get('/browse', function(req, res) {
  var dirPath = req.query.path || 'C:\\';
  try {
    if (!fs.existsSync(dirPath)) return res.json({ ok:false, error:'Path not found: '+dirPath });
    var stat = fs.statSync(dirPath);
    if (!stat.isDirectory()) return res.json({ ok:false, error:'Not a directory' });

    var entries = fs.readdirSync(dirPath, { withFileTypes: true });
    var dirs = entries.filter(function(e){ return e.isDirectory(); })
      .map(function(e){ return e.name; })
      .sort(function(a,b){ return a.localeCompare(b); });

    var parent = path.dirname(dirPath);
    if (parent === dirPath) parent = null; // already at root

    res.json({ ok:true, path: dirPath, parent: parent, dirs: dirs });
  } catch(e) {
    res.json({ ok:false, error: e.message });
  }
});

// List available drives (Windows)
router.get('/drives', function(req, res) {
  try {
    var out = runPS('Get-PSDrive -PSProvider FileSystem | Select-Object Name,Root | ConvertTo-Json -Compress');
    var drives = JSON.parse(out || '[]');
    if (!Array.isArray(drives)) drives = [drives];
    res.json({ ok:true, drives: drives.map(function(d){ return d.Root; }) });
  } catch(e) {
    res.json({ ok:true, drives: ['C:\\\\'] });
  }
});

// Create a new folder
router.post('/create-folder', function(req, res) {
  try {
    var target = req.body.path || '';
    if (!target) return res.json({ ok:false, error:'Path required' });
    fs.mkdirSync(target, { recursive: true });
    res.json({ ok:true });
  } catch(e) {
    res.json({ ok:false, error: e.message });
  }
});

module.exports = router;
