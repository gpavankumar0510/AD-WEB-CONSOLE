'use strict';
var fs = require('fs');
var path = require('path');
var os = require('os');
var execSync = require('child_process').execSync;
var logger = require('./logger');

var DOMAINS_FILE = path.join(__dirname, '../data/domains.json');

function runPS(script, timeoutMs) {
  var tmp = path.join(os.tmpdir(), 'domain_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: timeoutMs || 20000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; } finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function safeJ(s) { try { return JSON.parse(s); } catch(e) { return null; } }

function ensureDir() {
  var dir = path.dirname(DOMAINS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

// Registered additional domains (the primary domain from .env/autoDetect is always implicit and not stored here)
function getRegisteredDomains() {
  ensureDir();
  try {
    if (fs.existsSync(DOMAINS_FILE)) return JSON.parse(fs.readFileSync(DOMAINS_FILE, 'utf8'));
  } catch(e) {}
  return [];
}

function saveRegisteredDomains(list) {
  ensureDir();
  fs.writeFileSync(DOMAINS_FILE, JSON.stringify(list, null, 2));
}

function addDomain(config) {
  var list = getRegisteredDomains();
  var entry = {
    id: require('crypto').randomBytes(6).toString('hex'),
    name: config.name,
    dnsRoot: config.dnsRoot || config.name,
    netbios: config.netbios || '',
    type: config.type || 'child', // 'child' | 'tree' | 'external-trust'
    dc: config.dc || '',
    readOnly: true, // multi-domain entries are inventory/monitoring only - no write ops cross-domain
    addedAt: new Date().toISOString(),
    addedBy: config.addedBy || 'admin',
    lastSync: null,
    status: 'pending',
  };
  list.push(entry);
  saveRegisteredDomains(list);
  logger.info('Domain registered: ' + entry.dnsRoot);
  return entry;
}

function removeDomain(id) {
  var list = getRegisteredDomains().filter(function(d) { return d.id !== id; });
  saveRegisteredDomains(list);
}

// Auto-discover all domains in the current forest (uses the primary domain's AD module - read-only)
function discoverForestDomains() {
  var out = runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $forest = Get-ADForest -ErrorAction Stop',
    '  $domains = @()',
    '  foreach ($d in $forest.Domains) {',
    '    try {',
    '      $dom = Get-ADDomain -Identity $d -ErrorAction Stop',
    '      $domains += @{ name=$dom.Name; dnsRoot=$dom.DNSRoot; netbios=$dom.NetBIOSName; pdc=$dom.PDCEmulator; mode=$dom.DomainMode.ToString() }',
    '    } catch { $domains += @{ name=$d; dnsRoot=$d; netbios=""; pdc=""; mode="Unreachable" } }',
    '  }',
    '  @{ forestName=$forest.Name; forestMode=$forest.ForestMode.ToString(); domains=$domains } | ConvertTo-Json -Compress -Depth 5',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }'
  ].join('\n'), 25000);

  if (out.indexOf('ERROR:') === 0) return { error: out.replace('ERROR: ', '') };
  var parsed = safeJ(out);
  if (!parsed) return { error: 'Could not parse forest discovery output' };
  if (parsed.domains && !Array.isArray(parsed.domains)) parsed.domains = [parsed.domains];
  return parsed;
}

// Forest/Domain trust monitoring - Get-ADTrust
function getTrustRelationships() {
  var out = runPS([
    'try {',
    '  Import-Module ActiveDirectory -ErrorAction Stop',
    '  $trusts = Get-ADTrust -Filter * -ErrorAction Stop',
    '  $results = @()',
    '  foreach ($t in $trusts) {',
    '    $results += @{',
    '      name = $t.Name',
    '      source = $t.Source',
    '      target = $t.Target',
    '      direction = $t.Direction.ToString()',
    '      trustType = $t.TrustType.ToString()',
    '      isForest = $t.ForestTransitive',
    '      sidFilteringQuarantined = $t.SIDFilteringQuarantined',
    '      selectiveAuthentication = $t.SelectiveAuthentication',
    '      created = $t.Created.ToString("o")',
    '      modified = $t.Modified.ToString("o")',
    '    }',
    '  }',
    '  $results | ConvertTo-Json -Compress -Depth 5',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }'
  ].join('\n'), 20000);

  if (out.indexOf('ERROR:') === 0) return { error: out.replace('ERROR: ', '') };
  var parsed = safeJ(out);
  if (!parsed) return { trusts: [] };
  if (!Array.isArray(parsed)) parsed = parsed ? [parsed] : [];
  return { trusts: parsed };
}

// Test connectivity/health of a trust relationship (nltest-based)
function testTrust(trustName) {
  var out = runPS([
    'try {',
    '  $r = nltest /sc_query:' + trustName.replace(/[^a-zA-Z0-9.\-]/g, '') + ' 2>&1 | Out-String',
    '  Write-Output $r',
    '} catch { Write-Output ("ERROR: " + $_.Exception.Message) }'
  ].join('\n'), 15000);
  return { output: out, healthy: out.indexOf('successfully') >= 0 || out.indexOf('STATUS_SUCCESS') >= 0 };
}

module.exports = {
  getRegisteredDomains, addDomain, removeDomain,
  discoverForestDomains, getTrustRelationships, testTrust,
};
