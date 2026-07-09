'use strict';
var execSync = require('child_process').execSync;
var net      = require('net');
var logger   = require('./logger');
var fs = require('fs'), path = require('path'), os = require('os');
var _cache = null;

function runPSScript(script) {
  var tmp = path.join(os.tmpdir(), 'detect_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: 15000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; }
  finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

// Real TCP connect test — more reliable than Test-NetConnection
function tcpTest(host, port, timeout) {
  return new Promise(function(resolve) {
    var timer;
    var sock = new net.Socket();
    var done = false;
    function finish(ok) {
      if (done) return; done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch(e) {}
      resolve(ok);
    }
    timer = setTimeout(function() { finish(false); }, timeout || 3000);
    sock.on('connect', function() { finish(true); });
    sock.on('error', function() { finish(false); });
    sock.on('timeout', function() { finish(false); });
    try { sock.connect(port, host); } catch(e) { finish(false); }
  });
}

function getSettings() {
  if (_cache) return _cache;
  var domain  = process.env.AD_DOMAIN_DISPLAY || '';
  var baseDN  = process.env.AD_BASE_DN        || '';
  var netbios = process.env.AD_NETBIOS        || '';

  if (!domain || !baseDN) {
    var script = [
      'try {',
      '  Import-Module ActiveDirectory -ErrorAction Stop',
      '  $d = Get-ADDomain',
      '  Write-Output ($d.DNSRoot + "|" + $d.DistinguishedName + "|" + $d.NetBIOSName)',
      '} catch { Write-Output "||" }'
    ].join('\n');
    var out = runPSScript(script);
    if (out && out.indexOf('|') >= 0) {
      var parts = out.split('|');
      if (!domain  && parts[0].trim()) domain  = parts[0].trim();
      if (!baseDN  && parts[1].trim()) baseDN  = parts[1].trim();
      if (!netbios && parts[2].trim()) netbios = parts[2].trim();
    }
  }

  if (!domain)  domain  = 'domain.local';
  if (!baseDN)  baseDN  = 'DC=' + domain.replace(/\./g, ',DC=');
  if (!netbios) netbios = domain.split('.')[0].toUpperCase();

  // Use .env values if set — trust them completely
  var host = process.env.AD_HOST || '';
  var port = parseInt(process.env.AD_PORT || '0') || 0;

  if (host) {
    // Validate and fix empty hostname
    var stripped = host.replace('ldaps://','').replace('ldap://','').trim();
    if (!stripped) { host = 'ldap://127.0.0.1'; }
    if (!port) port = host.startsWith('ldaps://') ? 636 : 389;
  } else {
    // No .env setting — detect using PS (more reliable on Windows than raw TCP in sync context)
    var psTest = runPSScript([
      '$r389  = $false; $r636  = $false',
      'try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect("127.0.0.1",636); $r636=$true; $c.Close() } catch {}',
      'try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect("127.0.0.1",389); $r389=$true; $c.Close() } catch {}',
      'Write-Output ("636:"+$r636+"|389:"+$r389)',
    ].join('\n'));

    var has636 = psTest && psTest.indexOf('636:True') >= 0;
    var has389 = psTest && psTest.indexOf('389:True') >= 0;

    if (has636) {
      host = 'ldaps://127.0.0.1'; port = 636;
      logger.info('Auto-detected LDAPS port 636');
    } else if (has389) {
      host = 'ldap://127.0.0.1'; port = 389;
      logger.info('Auto-detected LDAP port 389');
    } else {
      // Cannot detect — use plain LDAP 389 as safest fallback
      // LDAPS ECONNRESET means cert issue; plain LDAP likely works
      host = 'ldap://127.0.0.1'; port = 389;
      logger.warn('Cannot detect LDAP ports - defaulting to ldap://127.0.0.1:389');
    }
  }

  var serviceAcct = process.env.AD_SERVICE_ACCOUNT || null;
  var servicePwd  = process.env.AD_SERVICE_PASSWORD || null;

  if (!serviceAcct) {
    var findScript = [
      'try {',
      '  Import-Module ActiveDirectory -ErrorAction Stop',
      '  $u = Get-ADUser -Identity "svc-adconsole" -Properties UserPrincipalName -ErrorAction Stop',
      '  Write-Output $u.UserPrincipalName',
      '} catch { Write-Output "" }'
    ].join('\n');
    var found = runPSScript(findScript);
    if (found && found.trim()) serviceAcct = found.trim();
  }

  var adminGroups = process.env.ADMIN_AD_GROUPS
    ? process.env.ADMIN_AD_GROUPS.split(',').map(function(g) { return g.trim(); })
    : ['Domain Admins','Administrators','Enterprise Admins','IT-Admins','IT-Helpdesk'];

  _cache = {
    domain, baseDN, netbios, host, port, serviceAcct, servicePwd,
    usersOU:     process.env.AD_USERS_OU     || ('CN=Users,'     + baseDN),
    computersOU: process.env.AD_COMPUTERS_OU || ('CN=Computers,' + baseDN),
    adminGroups, source: (process.env.AD_HOST || process.env.AD_BASE_DN) ? 'env' : 'auto',
  };
  logger.info('Settings: domain=' + domain + ' host=' + host + ' port=' + port + ' source=' + _cache.source);
  return _cache;
}

function clearCache() { _cache = null; }
module.exports = { getSettings, clearCache };
