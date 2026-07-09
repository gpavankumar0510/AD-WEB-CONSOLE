'use strict';
var fs = require('fs');
var path = require('path');
var crypto = require('crypto');
var logger = require('./logger');

var INTEGRATIONS_FILE = path.join(__dirname, '../data/integrations.json');

var ALGO = 'aes-256-gcm';
function getKey() {
  return crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'ad-console-default-key').digest();
}
function encrypt(plain) {
  if (!plain) return '';
  var key = getKey();
  var iv = crypto.randomBytes(16);
  var cipher = crypto.createCipheriv(ALGO, key, iv);
  var enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  var authTag = cipher.getAuthTag();
  return Buffer.concat([iv, authTag, enc]).toString('base64');
}
function decrypt(encB64) {
  if (!encB64) return '';
  try {
    var data = Buffer.from(encB64, 'base64');
    var iv = data.slice(0, 16);
    var authTag = data.slice(16, 32);
    var ciphertext = data.slice(32);
    var key = getKey();
    var decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
  } catch(e) { return ''; }
}

function ensureDir() {
  var dir = path.dirname(INTEGRATIONS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

var DEFAULTS = {
  azureAD:      { enabled: false, tenantId: '', clientId: '', clientSecretEnc: '', domain: '', lastSync: null, status: 'not_configured' },
  meshCentral:  { enabled: false, serverUrl: '', apiKeyEnc: '', lastSync: null, status: 'not_configured' },
  vmware:       { enabled: false, vcenterUrl: '', username: '', passwordEnc: '', lastSync: null, status: 'not_configured' },
  sccm:         { enabled: false, siteServer: '', siteCode: '', lastSync: null, status: 'not_configured' },
};

function get() {
  ensureDir();
  try {
    if (fs.existsSync(INTEGRATIONS_FILE)) {
      var saved = JSON.parse(fs.readFileSync(INTEGRATIONS_FILE, 'utf8'));
      return {
        azureAD:     Object.assign({}, DEFAULTS.azureAD,     saved.azureAD     || {}),
        meshCentral: Object.assign({}, DEFAULTS.meshCentral, saved.meshCentral || {}),
        vmware:      Object.assign({}, DEFAULTS.vmware,      saved.vmware      || {}),
        sccm:        Object.assign({}, DEFAULTS.sccm,        saved.sccm        || {}),
      };
    }
  } catch(e) {}
  return JSON.parse(JSON.stringify(DEFAULTS));
}

function save(section, updates) {
  var current = get();
  if (!current[section]) throw new Error('Unknown integration section: ' + section);
  current[section] = Object.assign({}, current[section], updates);
  ensureDir();
  fs.writeFileSync(INTEGRATIONS_FILE, JSON.stringify(current, null, 2));
  logger.info('Integration settings saved: ' + section);
  return current[section];
}

// Redacted view safe to send to the browser (never includes decrypted secrets)
function getRedacted() {
  var cfg = get();
  return {
    azureAD: Object.assign({}, cfg.azureAD, { clientSecretEnc: undefined, hasSecret: !!cfg.azureAD.clientSecretEnc }),
    meshCentral: Object.assign({}, cfg.meshCentral, { apiKeyEnc: undefined, hasApiKey: !!cfg.meshCentral.apiKeyEnc }),
    vmware: Object.assign({}, cfg.vmware, { passwordEnc: undefined, hasPassword: !!cfg.vmware.passwordEnc }),
    sccm: cfg.sccm,
  };
}

// ── Connectivity tests (best-effort; these call out to real APIs/endpoints when configured) ──

async function testAzureAD() {
  var cfg = get().azureAD;
  if (!cfg.tenantId || !cfg.clientId || !cfg.clientSecretEnc) {
    return { ok: false, error: 'Tenant ID, Client ID, and Client Secret are all required.' };
  }
  var secret = decrypt(cfg.clientSecretEnc);
  try {
    var https = require('https');
    var qs = 'client_id=' + encodeURIComponent(cfg.clientId) +
      '&scope=https%3A%2F%2Fgraph.microsoft.com%2F.default' +
      '&client_secret=' + encodeURIComponent(secret) +
      '&grant_type=client_credentials';
    var result = await new Promise(function(resolve, reject) {
      var req = https.request({
        hostname: 'login.microsoftonline.com',
        path: '/' + cfg.tenantId + '/oauth2/v2.0/token',
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(qs) },
        timeout: 15000,
      }, function(res) {
        var body = '';
        res.on('data', function(chunk) { body += chunk; });
        res.on('end', function() { resolve({ status: res.statusCode, body: body }); });
      });
      req.on('error', reject);
      req.on('timeout', function() { req.destroy(); reject(new Error('Request timed out')); });
      req.write(qs);
      req.end();
    });
    var parsed = JSON.parse(result.body);
    if (result.status === 200 && parsed.access_token) {
      save('azureAD', { status: 'connected', lastSync: new Date().toISOString() });
      return { ok: true, message: 'Successfully authenticated with Microsoft Graph API.' };
    }
    save('azureAD', { status: 'error' });
    return { ok: false, error: (parsed.error_description || parsed.error || 'Authentication failed (HTTP ' + result.status + ')') };
  } catch(e) {
    save('azureAD', { status: 'error' });
    return { ok: false, error: e.message };
  }
}

async function testMeshCentral() {
  var cfg = get().meshCentral;
  if (!cfg.serverUrl) return { ok: false, error: 'Server URL is required.' };
  try {
    var url = new URL(cfg.serverUrl);
    var https = require(url.protocol === 'https:' ? 'https' : 'http');
    var result = await new Promise(function(resolve, reject) {
      var req = https.request({ hostname: url.hostname, port: url.port || (url.protocol === 'https:' ? 443 : 80), path: '/', method: 'GET', timeout: 10000, rejectUnauthorized: false }, function(res) {
        resolve({ status: res.statusCode });
        res.resume();
      });
      req.on('error', reject);
      req.on('timeout', function() { req.destroy(); reject(new Error('Connection timed out')); });
      req.end();
    });
    var ok = result.status >= 200 && result.status < 500;
    save('meshCentral', { status: ok ? 'connected' : 'error', lastSync: new Date().toISOString() });
    return ok ? { ok: true, message: 'MeshCentral server reachable (HTTP ' + result.status + ').' } : { ok: false, error: 'Unexpected HTTP status ' + result.status };
  } catch(e) {
    save('meshCentral', { status: 'error' });
    return { ok: false, error: e.message };
  }
}

async function testVMware() {
  var cfg = get().vmware;
  if (!cfg.vcenterUrl) return { ok: false, error: 'vCenter URL is required.' };
  try {
    var url = new URL(cfg.vcenterUrl);
    var https = require('https');
    var result = await new Promise(function(resolve, reject) {
      var req = https.request({ hostname: url.hostname, port: url.port || 443, path: '/', method: 'GET', timeout: 10000, rejectUnauthorized: false }, function(res) {
        resolve({ status: res.statusCode });
        res.resume();
      });
      req.on('error', reject);
      req.on('timeout', function() { req.destroy(); reject(new Error('Connection timed out')); });
      req.end();
    });
    var ok = result.status >= 200 && result.status < 500;
    save('vmware', { status: ok ? 'connected' : 'error', lastSync: new Date().toISOString() });
    return ok ? { ok: true, message: 'vCenter server reachable (HTTP ' + result.status + '). Full inventory sync requires vSphere API credentials to be validated separately.' } : { ok: false, error: 'Unexpected HTTP status ' + result.status };
  } catch(e) {
    save('vmware', { status: 'error' });
    return { ok: false, error: e.message };
  }
}

async function testSCCM() {
  var cfg = get().sccm;
  if (!cfg.siteServer) return { ok: false, error: 'Site Server hostname is required.' };
  try {
    var net = require('net');
    var ok = await new Promise(function(resolve) {
      var sock = new net.Socket();
      var timer = setTimeout(function() { sock.destroy(); resolve(false); }, 8000);
      sock.on('connect', function() { clearTimeout(timer); sock.destroy(); resolve(true); });
      sock.on('error', function() { clearTimeout(timer); resolve(false); });
      sock.connect(135, cfg.siteServer); // SCCM WMI/DCOM endpoint mapper port
    });
    save('sccm', { status: ok ? 'connected' : 'error', lastSync: new Date().toISOString() });
    return ok ? { ok: true, message: 'SCCM site server is reachable on port 135 (WMI). Full SMS Provider integration requires the ConfigMgr WMI namespace to be queried separately via PowerShell on a console with the ConfigMgr console installed.' } : { ok: false, error: 'Could not reach ' + cfg.siteServer + ' on port 135. Check the hostname and firewall rules.' };
  } catch(e) {
    save('sccm', { status: 'error' });
    return { ok: false, error: e.message };
  }
}

module.exports = {
  get, save, getRedacted, encrypt, decrypt,
  testAzureAD, testMeshCentral, testVMware, testSCCM,
};
