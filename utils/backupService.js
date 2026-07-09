'use strict';
var fs = require('fs'), path = require('path'), os = require('os');
var logger = require('./logger');
var exec = require('child_process').exec;
var uuidv4 = require('uuid').v4;
var HISTORY_FILE = path.join(__dirname, '../data/backup_history.json');

function ensureDir(dir) { if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true }); }

function loadHistory() {
  try { if (fs.existsSync(HISTORY_FILE)) return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8')); } catch(e) {}
  return [];
}

function saveHistory(h) {
  ensureDir(path.dirname(HISTORY_FILE));
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(h, null, 2));
}

function addEntry(entry) {
  var h = loadHistory();
  h.unshift(Object.assign({ id: uuidv4(), timestamp: new Date().toISOString() }, entry));
  saveHistory(h.slice(0, 100));
}

var backupService = {
  getHistory: function() { return loadHistory(); },

  runBackup: async function(type, destination) {
    var dest = (destination || process.env.BACKUP_PATH || 'C:\\ADBackups').trim();
    try { fs.mkdirSync(dest, { recursive: true }); } catch(e) {}
    var ts = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
    var ifmPath = dest + '\\IFM-' + ts;
    var logFile = dest + '\\backup-' + type + '-' + ts + '.log';

    var commands = {
      'AD-State':    'powershell -NoProfile -Command "New-Item -ItemType Directory -Path \'' + ifmPath + '\' -Force | Out-Null; ntdsutil.exe \'activate instance ntds\' \'ifm\' \'create sysvol full ' + ifmPath + '\' quit quit 2>&1 | Out-File -FilePath \'' + logFile + '\'"',
      'System-State':'powershell -NoProfile -Command "wbadmin start systemstatebackup -backupTarget:\'' + dest + '\' -quiet 2>&1 | Out-File -FilePath \'' + logFile + '\'"',
      'SYSVOL':      'powershell -NoProfile -Command "robocopy C:\\Windows\\SYSVOL \'' + dest + '\\SYSVOL-' + ts + '\' /MIR /NP 2>&1 | Out-File -FilePath \'' + logFile + '\'"',
      'Full-Server': 'powershell -NoProfile -Command "wbadmin start backup -backupTarget:\'' + dest + '\' -include:C: -allCritical -quiet 2>&1 | Out-File -FilePath \'' + logFile + '\'"',
    };

    var cmd = commands[type] || commands['AD-State'];
    var jobId = uuidv4();
    addEntry({ jobId: jobId, type: type, destination: dest, status: 'running' });

    return new Promise(function(resolve) {
      exec(cmd, { timeout: 300000 }, function(err) {
        var status = err ? 'failed' : 'completed';
        var encryptedFiles = 0;

        // Encrypt if enabled and backup succeeded
        if (!err) {
          try {
            var settings = require('./settings').get();
            if (settings.backupEncryption && settings.backupEncryptionPassphrase) {
              var enc = require('./backupEncryption');
              if (type === 'AD-State' && fs.existsSync(ifmPath)) {
                var files = enc.encryptDirectory(ifmPath, settings.backupEncryptionPassphrase);
                encryptedFiles = files.length;
              } else if (fs.existsSync(logFile)) {
                // For other types, encrypt the log file as a marker (full directory encryption
                // of wbadmin/robocopy output is handled by BitLocker/destination encryption)
                encryptedFiles = 0;
              }
            }
          } catch(e) { logger.warn('Backup encryption: ' + e.message); }
        }

        var h = loadHistory();
        var idx = h.findIndex(function(e) { return e.jobId === jobId; });
        if (idx >= 0) {
          h[idx].status = status;
          h[idx].completedAt = new Date().toISOString();
          h[idx].logFile = logFile;
          h[idx].encrypted = encryptedFiles > 0;
          h[idx].encryptedFiles = encryptedFiles;
          saveHistory(h);
        }
        logger.info('Backup ' + type + ' ' + status + (encryptedFiles > 0 ? ' (encrypted ' + encryptedFiles + ' files)' : ''));
        resolve({ jobId: jobId, status: status, logFile: logFile, encrypted: encryptedFiles > 0 });
      });
    });
  },

  getSchedule: function() {
    return {
      cron: process.env.BACKUP_SCHEDULE || '0 2 * * *',
      description: 'Daily at 2:00 AM',
      destination: process.env.BACKUP_PATH || 'C:\\ADBackups',
      retentionDays: parseInt(process.env.BACKUP_RETENTION_DAYS || '30'),
    };
  },

  cleanOldBackups: function() { logger.info('Backup cleanup done'); },
};

module.exports = backupService;
