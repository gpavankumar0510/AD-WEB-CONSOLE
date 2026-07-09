'use strict';
var fs = require('fs');
var path = require('path');

var BF_FILE = path.join(__dirname, '../data/brute_force.json');
var MAX_ATTEMPTS = 10;       // max failed attempts per IP
var WINDOW_MS = 15*60*1000;  // 15 minute window
var BAN_MS    = 30*60*1000;  // 30 minute ban

function ensureDir() {
  var dir = path.dirname(BF_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}
function load() {
  ensureDir();
  try { if (fs.existsSync(BF_FILE)) return JSON.parse(fs.readFileSync(BF_FILE, 'utf8')); } catch(e) {}
  return {};
}
function save(data) { ensureDir(); fs.writeFileSync(BF_FILE, JSON.stringify(data, null, 2)); }

function recordFailure(ip) {
  var data = load();
  var now = Date.now();
  if (!data[ip]) data[ip] = { attempts: [], bannedUntil: 0 };
  data[ip].attempts = data[ip].attempts.filter(function(t) { return now - t < WINDOW_MS; });
  data[ip].attempts.push(now);
  if (data[ip].attempts.length >= MAX_ATTEMPTS) {
    data[ip].bannedUntil = now + BAN_MS;
  }
  save(data);
  return data[ip];
}

function recordSuccess(ip) {
  var data = load();
  if (data[ip]) { data[ip].attempts = []; data[ip].bannedUntil = 0; save(data); }
}

function isBanned(ip) {
  var data = load();
  if (!data[ip]) return false;
  if (data[ip].bannedUntil && Date.now() < data[ip].bannedUntil) return true;
  return false;
}

function getBanInfo(ip) {
  var data = load();
  if (!data[ip]) return null;
  var remaining = data[ip].bannedUntil - Date.now();
  return remaining > 0 ? { remainingMs: remaining, attempts: data[ip].attempts.length } : null;
}

function cleanup() {
  var data = load();
  var now = Date.now();
  Object.keys(data).forEach(function(ip) {
    data[ip].attempts = (data[ip].attempts||[]).filter(function(t) { return now - t < WINDOW_MS; });
    if (data[ip].bannedUntil && data[ip].bannedUntil < now) data[ip].bannedUntil = 0;
    if (!data[ip].attempts.length && !data[ip].bannedUntil) delete data[ip];
  });
  save(data);
}

module.exports = { recordFailure, recordSuccess, isBanned, getBanInfo, cleanup, MAX_ATTEMPTS, BAN_MS };
