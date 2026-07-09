'use strict';
var fs   = require('fs');
var path = require('path');

var AUDIT_FILE = path.join(__dirname, '../data/audit.log');
var MAX_SIZE   = 10 * 1024 * 1024; // 10MB

function ensureDir() {
  var dir = path.dirname(AUDIT_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function log(action, actor, target, details, ip) {
  ensureDir();
  var entry = {
    ts:      new Date().toISOString(),
    action:  action,
    actor:   actor || 'system',
    target:  target || '',
    details: details || '',
    ip:      ip || '',
  };
  var line = JSON.stringify(entry) + '\n';
  try {
    // Rotate if too large
    if (fs.existsSync(AUDIT_FILE)) {
      var stat = fs.statSync(AUDIT_FILE);
      if (stat.size > MAX_SIZE) {
        fs.renameSync(AUDIT_FILE, AUDIT_FILE + '.bak');
      }
    }
    fs.appendFileSync(AUDIT_FILE, line, 'utf8');
  } catch(e) {}
}

function getAll(limit) {
  ensureDir();
  try {
    if (!fs.existsSync(AUDIT_FILE)) return [];
    var lines = fs.readFileSync(AUDIT_FILE, 'utf8').trim().split('\n').filter(Boolean);
    var parsed = lines.map(function(l) { try { return JSON.parse(l); } catch(e) { return null; } }).filter(Boolean);
    parsed.reverse(); // newest first
    return limit ? parsed.slice(0, limit) : parsed;
  } catch(e) { return []; }
}

function clear() {
  try { fs.writeFileSync(AUDIT_FILE, '', 'utf8'); } catch(e) {}
}

function exportCSV() {
  var rows = getAll();
  var header = 'Timestamp,Action,Actor,Target,Details,IP\n';
  var body = rows.map(function(r) {
    return [r.ts, r.action, r.actor, r.target, (r.details||'').replace(/,/g,';'), r.ip].map(function(v){ return '"'+(v||'')+'"'; }).join(',');
  }).join('\n');
  return header + body;
}

module.exports = { log, getAll, clear, exportCSV };
