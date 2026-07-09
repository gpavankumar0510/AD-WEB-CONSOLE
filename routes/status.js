'use strict';
var express = require('express');
var router  = express.Router();
var rbac    = require('../utils/rbac');
var os      = require('os');
var fs      = require('fs');
var path    = require('path');
var execSync = require('child_process').execSync;
var autoDetect = require('../utils/autoDetect');
var bruteForce = require('../utils/bruteForce');

function runPS(script, timeout) {
  var p = path.join(os.tmpdir(), 'status_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(p, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + p + '"',
      { timeout: timeout||8000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; } finally { try { fs.unlinkSync(p); } catch(e) {} }
}

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  var cfg = autoDetect.getSettings();

  // LDAP connectivity test
  var ldapOk = false, ldapMsg = '';
  try {
    var net = require('net');
    var sock = new net.Socket();
    sock.setTimeout(2000);
    sock.on('connect', function() { ldapOk = true; sock.destroy(); });
    sock.on('error', function() {});
    sock.connect(cfg.port, '127.0.0.1');
  } catch(e) { ldapMsg = e.message; }

  // AD module check
  var adModule = runPS('try { Import-Module ActiveDirectory -ErrorAction Stop; Write-Output "ok" } catch { Write-Output "missing" }', 8000);

  // PowerShell version
  var psVersion = runPS('$PSVersionTable.PSVersion.ToString()', 5000);

  // Disk space
  var diskOut = runPS('try { $d=Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'"; [math]::Round($d.FreeSpace/1GB,1) } catch { "0" }', 5000);

  var memUsage = process.memoryUsage();
  var uptimeSec = process.uptime();

  res.render('status/index', {
    admin: req.session.admin, page: 'status',
    cfg: cfg,
    ldapOk: ldapOk,
    adModuleOk: adModule.indexOf('ok') >= 0,
    psVersion: psVersion || 'Unknown',
    diskFreeGB: diskOut || '—',
    nodeVersion: process.version,
    uptimeSec: uptimeSec,
    memUsage: memUsage,
    platform: os.platform() + ' ' + os.release(),
  });
});

module.exports = router;
