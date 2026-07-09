'use strict';
var fs = require('fs');
var path = require('path');
var os = require('os');
var execSync = require('child_process').execSync;
var logger = require('./logger');

var CERT_CACHE_FILE = path.join(__dirname, '../data/cert_cache.json');

function runPS(script, timeoutMs) {
  var tmp = path.join(os.tmpdir(), 'certmon_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: timeoutMs || 20000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; } finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function safeJ(s) { try { return JSON.parse(s); } catch(e) { return null; } }

// Scan all certificate stores relevant to AD/IIS/LDAPS/services
function scanCertificates() {
  var out = runPS([
    'try {',
    '  $results = @()',
    '  $stores = @(',
    '    @{Path="Cert:\\\\LocalMachine\\\\My"; Label="Local Machine - Personal (LDAPS/DC/Service certs)"},',
    '    @{Path="Cert:\\\\LocalMachine\\\\CA"; Label="Local Machine - Intermediate CA"},',
    '    @{Path="Cert:\\\\LocalMachine\\\\Root"; Label="Local Machine - Trusted Root"}',
    '  )',
    '  foreach ($store in $stores) {',
    '    $certs = Get-ChildItem -Path $store.Path -ErrorAction SilentlyContinue',
    '    foreach ($c in $certs) {',
    '      $daysLeft = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)',
    '      $isLdapCert = $c.Subject -match $env:COMPUTERNAME -or $c.EnhancedKeyUsageList -match "Server Authentication"',
    '      $results += @{',
    '        thumbprint = $c.Thumbprint',
    '        subject = $c.Subject',
    '        issuer = $c.Issuer',
    '        notBefore = $c.NotBefore.ToString("o")',
    '        notAfter = $c.NotAfter.ToString("o")',
    '        daysLeft = $daysLeft',
    '        store = $store.Label',
    '        hasPrivateKey = $c.HasPrivateKey',
    '        isCA = $c.Subject -eq $c.Issuer',
    '        keyUsage = ($c.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName }) -join ", "',
    '      }',
    '    }',
    '  }',
    '  # Check for IIS bindings with certs (if IIS installed)',
    '  $iisCerts = @()',
    '  try {',
    '    Import-Module WebAdministration -ErrorAction Stop',
    '    $bindings = Get-WebBinding | Where-Object { $_.protocol -eq "https" }',
    '    foreach ($b in $bindings) {',
    '      if ($b.certificateHash) {',
    '        $iisCerts += @{ site = $b.ItemXPath; thumbprint = $b.certificateHash; bindingInfo = $b.bindingInformation }',
    '      }',
    '    }',
    '  } catch {}',
    '  @{ certs = $results; iisCerts = $iisCerts } | ConvertTo-Json -Compress -Depth 5',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }'
  ].join('\n'), 30000);

  if (out.indexOf('ERROR:') === 0) return { error: out.replace('ERROR: ', '') };
  var parsed = safeJ(out);
  if (!parsed) return { error: 'Could not parse certificate scan output' };

  var certs = parsed.certs || [];
  if (!Array.isArray(certs)) certs = [certs];
  var iisCerts = parsed.iisCerts || [];
  if (!Array.isArray(iisCerts)) iisCerts = iisCerts ? [iisCerts] : [];

  // Mark IIS-bound certs
  var iisThumbprints = iisCerts.map(function(c) { return c.thumbprint; });
  certs.forEach(function(c) {
    c.usedByIIS = iisThumbprints.indexOf(c.thumbprint) >= 0;
    c.category = classifyCert(c);
  });

  // De-duplicate by thumbprint (same cert can appear in multiple stores)
  var seen = {};
  var unique = [];
  certs.forEach(function(c) {
    if (!seen[c.thumbprint]) { seen[c.thumbprint] = true; unique.push(c); }
    else {
      // merge store info
      var existing = unique.find(function(u) { return u.thumbprint === c.thumbprint; });
      if (existing && existing.store.indexOf(c.store) < 0) existing.store += ', ' + c.store;
    }
  });

  unique.sort(function(a, b) { return a.daysLeft - b.daysLeft; });

  var result = {
    scannedAt: new Date().toISOString(),
    certs: unique,
    summary: {
      total: unique.length,
      expired: unique.filter(function(c) { return c.daysLeft < 0; }).length,
      expiringSoon: unique.filter(function(c) { return c.daysLeft >= 0 && c.daysLeft <= 30; }).length,
      healthy: unique.filter(function(c) { return c.daysLeft > 30; }).length,
    },
  };

  try {
    var dir = path.dirname(CERT_CACHE_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(CERT_CACHE_FILE, JSON.stringify(result, null, 2));
  } catch(e) { logger.warn('Could not cache cert scan: ' + e.message); }

  return result;
}

function classifyCert(c) {
  var subj = (c.subject || '').toLowerCase();
  var ku = (c.keyUsage || '').toLowerCase();
  if (c.isCA) return 'AD CS / Internal PKI Root';
  if (c.usedByIIS) return 'IIS / Web Server';
  if (subj.indexOf(os.hostname().toLowerCase()) >= 0 && ku.indexOf('server authentication') >= 0) return 'LDAPS / Domain Controller';
  if (ku.indexOf('server authentication') >= 0) return 'Service Certificate';
  return 'Other / Client Certificate';
}

function getCached() {
  try {
    if (fs.existsSync(CERT_CACHE_FILE)) {
      var c = JSON.parse(fs.readFileSync(CERT_CACHE_FILE, 'utf8'));
      return c;
    }
  } catch(e) {}
  return null;
}

function getExpiringCerts(thresholdDays) {
  var cached = getCached();
  if (!cached) return [];
  thresholdDays = thresholdDays === undefined ? 30 : thresholdDays;
  return cached.certs.filter(function(c) { return c.daysLeft <= thresholdDays; });
}

module.exports = { scanCertificates, getCached, getExpiringCerts, classifyCert };
