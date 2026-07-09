'use strict';
// Minimal TOTP (RFC 6238) implementation using Node's built-in crypto - no external deps
var crypto = require('crypto');
var fs = require('fs');
var path = require('path');

var MFA_FILE = path.join(__dirname, '../data/mfa.json');

function ensureDir() {
  var dir = path.dirname(MFA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function load() {
  ensureDir();
  try { if (fs.existsSync(MFA_FILE)) return JSON.parse(fs.readFileSync(MFA_FILE, 'utf8')); } catch(e) {}
  return {};
}

function save(data) {
  ensureDir();
  fs.writeFileSync(MFA_FILE, JSON.stringify(data, null, 2));
}

// Base32 encode/decode (RFC 4648)
var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  var bits = '', output = '';
  for (var i = 0; i < buf.length; i++) bits += buf[i].toString(2).padStart(8, '0');
  for (var j = 0; j + 5 <= bits.length; j += 5) output += B32_ALPHABET[parseInt(bits.substr(j, 5), 2)];
  var rem = bits.length % 5;
  if (rem > 0) output += B32_ALPHABET[parseInt(bits.substr(bits.length - rem).padEnd(5, '0'), 2)];
  return output;
}

function base32Decode(str) {
  str = str.replace(/=+$/, '').toUpperCase();
  var bits = '';
  for (var i = 0; i < str.length; i++) {
    var idx = B32_ALPHABET.indexOf(str[i]);
    if (idx < 0) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  var bytes = [];
  for (var j = 0; j + 8 <= bits.length; j += 8) bytes.push(parseInt(bits.substr(j, 8), 2));
  return Buffer.from(bytes);
}

function generateSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit secret
}

// Generate TOTP code for a given secret + time step (default 30s)
function generateTOTP(secret, timeStep, digits, timestamp) {
  timeStep = timeStep || 30;
  digits = digits || 6;
  var time = Math.floor((timestamp || Date.now()) / 1000 / timeStep);
  var timeBuf = Buffer.alloc(8);
  timeBuf.writeBigUInt64BE(BigInt(time));

  var key = base32Decode(secret);
  var hmac = crypto.createHmac('sha1', key).update(timeBuf).digest();
  var offset = hmac[hmac.length - 1] & 0xf;
  var binCode = (hmac[offset] & 0x7f) << 24 |
                 (hmac[offset+1] & 0xff) << 16 |
                 (hmac[offset+2] & 0xff) << 8 |
                 (hmac[offset+3] & 0xff);
  var otp = (binCode % Math.pow(10, digits)).toString().padStart(digits, '0');
  return otp;
}

// Verify TOTP with +/- 1 time step window for clock drift
function verifyTOTP(secret, token, window) {
  window = window === undefined ? 1 : window;
  token = String(token).trim();
  var now = Date.now();
  for (var i = -window; i <= window; i++) {
    var expected = generateTOTP(secret, 30, 6, now + i * 30000);
    if (expected === token) return true;
  }
  return false;
}

// Build otpauth:// URI for QR code apps (Google Authenticator, Authy, etc.)
function buildOtpAuthUri(username, secret, issuer) {
  issuer = issuer || 'AD-Console';
  var label = encodeURIComponent(issuer + ':' + username);
  return 'otpauth://totp/' + label + '?secret=' + secret + '&issuer=' + encodeURIComponent(issuer) + '&algorithm=SHA1&digits=6&period=30';
}

// Per-user MFA management
function getUserMFA(username) {
  var data = load();
  return data[username] || null;
}

function setupMFA(username) {
  var data = load();
  var secret = generateSecret();
  data[username] = { secret: secret, enabled: false, backupCodes: generateBackupCodes(), setupAt: new Date().toISOString() };
  save(data);
  return data[username];
}

function enableMFA(username) {
  var data = load();
  if (!data[username]) return false;
  data[username].enabled = true;
  data[username].enabledAt = new Date().toISOString();
  save(data);
  return true;
}

function disableMFA(username) {
  var data = load();
  if (data[username]) {
    delete data[username];
    save(data);
  }
  return true;
}

function isMFAEnabled(username) {
  var data = load();
  return !!(data[username] && data[username].enabled);
}

function generateBackupCodes() {
  var codes = [];
  for (var i = 0; i < 8; i++) {
    codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
  }
  return codes;
}

function useBackupCode(username, code) {
  var data = load();
  if (!data[username] || !data[username].backupCodes) return false;
  var idx = data[username].backupCodes.indexOf(code.toUpperCase());
  if (idx < 0) return false;
  data[username].backupCodes.splice(idx, 1);
  save(data);
  return true;
}

module.exports = {
  generateSecret, generateTOTP, verifyTOTP, buildOtpAuthUri,
  getUserMFA, setupMFA, enableMFA, disableMFA, isMFAEnabled,
  useBackupCode, generateBackupCodes,
};
