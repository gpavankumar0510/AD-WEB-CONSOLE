'use strict';
var fs   = require('fs');
var path = require('path');
var SETTINGS_FILE = path.join(__dirname, '../data/settings.json');

var DEFAULTS = {
  sessionTimeoutMinutes: 480,
  auditLogRetentionDays: 90,
  smtpHost:     '',
  smtpPort:     25,
  smtpUser:     '',
  smtpPass:     '',
  smtpFrom:     '',
  alertEmails:  [],
  mfaEnabled:   false,
  mfaEnforced:  false,
  backupSchedule:    '0 2 * * *',
  backupDestination: 'C:\\ADBackups',
  backupRetentionDays: 30,
  backupType:        'daily',
  backupEncryption:  false,
  backupEncryptionPassphrase: '',
  orgName:      '',
  orgAnnouncement: '',
  orgHolidays: [], // [{date:'2026-12-25', name:'Christmas'}]
};

function get() {
  try {
    var dir = path.dirname(SETTINGS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (fs.existsSync(SETTINGS_FILE)) {
      var saved = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
      return Object.assign({}, DEFAULTS, saved);
    }
  } catch(e) {}
  return Object.assign({}, DEFAULTS);
}

function save(updates) {
  var current = get();
  var merged  = Object.assign({}, current, updates);
  var dir = path.dirname(SETTINGS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(merged, null, 2));
  return merged;
}

module.exports = { get, save, DEFAULTS };
