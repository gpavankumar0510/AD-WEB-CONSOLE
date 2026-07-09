'use strict';
var express = require('express');
var router  = express.Router();
var ad      = require('../utils/adService');
var adSvc   = require('../utils/adServices');
var audit   = require('../utils/auditLogger');
var backup  = require('../utils/backupService');
var logger  = require('../utils/logger');

router.get('/', function(req, res) {
  res.render('reports/index', { admin: req.session.admin, page: 'reports', error: null });
});

// User Activity Report
router.get('/user-activity', async function(req, res) {
  var logs = audit.getAll(500);
  var userLogs = logs.filter(function(l) { return l.action && l.action.toLowerCase().indexOf('user') >= 0; });
  res.render('reports/user-activity', { admin: req.session.admin, page: 'reports', logs: userLogs });
});

// Group Membership Report
router.get('/group-membership', async function(req, res) {
  try {
    var groups = await ad.getGroups();
    res.render('reports/group-membership', { admin: req.session.admin, page: 'reports', groups: groups, error: null });
  } catch(e) {
    res.render('reports/group-membership', { admin: req.session.admin, page: 'reports', groups: [], error: e.message });
  }
});

// Password Expiry Report
router.get('/password-expiry', async function(req, res) {
  try {
    var data = adSvc.getUsersPasswordExpiry();
    res.render('reports/password-expiry', { admin: req.session.admin, page: 'reports', data: data, error: null });
  } catch(e) {
    res.render('reports/password-expiry', { admin: req.session.admin, page: 'reports', data: { users: [] }, error: e.message });
  }
});

// Security Compliance / SCAP
router.get('/security-compliance', function(req, res) {
  try {
    var scap = adSvc.getSCAPScore();
    res.render('reports/security-compliance', { admin: req.session.admin, page: 'reports', scap: scap, error: null });
  } catch(e) {
    res.render('reports/security-compliance', { admin: req.session.admin, page: 'reports', scap: null, error: e.message });
  }
});

// Audit Report
router.get('/audit', function(req, res) {
  var logs = audit.getAll(1000);
  res.render('reports/audit', { admin: req.session.admin, page: 'reports', logs: logs });
});

// Backup Report
router.get('/backup', function(req, res) {
  var history = backup.getHistory();
  res.render('reports/backup', { admin: req.session.admin, page: 'reports', history: history });
});

// GDPR Report (user data summary)
router.get('/gdpr', async function(req, res) {
  try {
    var users = await ad.getUsers();
    res.render('reports/gdpr', { admin: req.session.admin, page: 'reports', users: users, error: null });
  } catch(e) {
    res.render('reports/gdpr', { admin: req.session.admin, page: 'reports', users: [], error: e.message });
  }
});

// Login Failure Report
router.get('/login-failures', function(req, res) {
  var logs = audit.getAll(1000);
  var failures = logs.filter(function(l) { return l.action === 'LOGIN_FAILED' || l.action === 'LOGIN_BLOCKED'; });
  res.render('reports/login-failures', { admin: req.session.admin, page: 'reports', logs: failures });
});

// Account Lockout Report
router.get('/lockouts', async function(req, res) {
  try {
    var lockedUsers = await ad.getLockedUsers();
    var logs = audit.getAll(1000).filter(function(l) { return l.action === 'USER_UNLOCKED' || l.action === 'IP_BANNED'; });
    res.render('reports/lockouts', { admin: req.session.admin, page: 'reports', lockedUsers: lockedUsers, logs: logs, error: null });
  } catch(e) {
    res.render('reports/lockouts', { admin: req.session.admin, page: 'reports', lockedUsers: [], logs: [], error: e.message });
  }
});

// Certificate Expiry Report
router.get('/certificates', function(req, res) {
  try {
    var certMonitor = require('../utils/certMonitor');
    var data = certMonitor.getCached();
    res.render('reports/certificates', { admin: req.session.admin, page: 'reports', data: data, error: null });
  } catch(e) {
    res.render('reports/certificates', { admin: req.session.admin, page: 'reports', data: null, error: e.message });
  }
});

// AD Health Report (DCDiag-style, reuses migration assessor checks read-only)
router.get('/ad-health', function(req, res) {
  try {
    var assessor = require('../utils/migration/assessor');
    var assessments = assessor.getAssessments();
    var latest = assessments && assessments.length ? assessments[0] : null;
    res.render('reports/ad-health', { admin: req.session.admin, page: 'reports', latest: latest, error: null });
  } catch(e) {
    res.render('reports/ad-health', { admin: req.session.admin, page: 'reports', latest: null, error: e.message });
  }
});

// Domain Controller Health Report
router.get('/dc-health', function(req, res) {
  try {
    var dcs = adSvc.getAllDomainControllers();
    res.render('reports/dc-health', { admin: req.session.admin, page: 'reports', dcs: dcs, error: null });
  } catch(e) {
    res.render('reports/dc-health', { admin: req.session.admin, page: 'reports', dcs: [], error: e.message });
  }
});

// Replication Report
router.get('/replication', function(req, res) {
  try {
    var fs = require('fs'), path = require('path');
    var cacheFile = path.join(__dirname, '../data/services_cache.json');
    var services = null;
    if (fs.existsSync(cacheFile)) services = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    res.render('reports/replication', { admin: req.session.admin, page: 'reports', services: services, error: null });
  } catch(e) {
    res.render('reports/replication', { admin: req.session.admin, page: 'reports', services: null, error: e.message });
  }
});

// DNS Health Report
router.get('/dns-health', function(req, res) {
  try {
    var fs = require('fs'), path = require('path');
    var cacheFile = path.join(__dirname, '../data/services_cache.json');
    var services = null;
    if (fs.existsSync(cacheFile)) services = JSON.parse(fs.readFileSync(cacheFile, 'utf8'));
    res.render('reports/dns-health', { admin: req.session.admin, page: 'reports', services: services, error: null });
  } catch(e) {
    res.render('reports/dns-health', { admin: req.session.admin, page: 'reports', services: null, error: e.message });
  }
});

// Group Policy Report
router.get('/gpo', function(req, res) {
  try {
    var gpoStore = require('../utils/gpoStore');
    var policies = gpoStore.getAllPolicies ? gpoStore.getAllPolicies() : [];
    res.render('reports/gpo', { admin: req.session.admin, page: 'reports', policies: policies, error: null });
  } catch(e) {
    res.render('reports/gpo', { admin: req.session.admin, page: 'reports', policies: [], error: e.message });
  }
});

// Security Report (combines SCAP + lockouts + cert issues + login failures into one exec summary)
router.get('/security', function(req, res) {
  try {
    var scap = null; try { scap = adSvc.getSCAPScore(); } catch(e) {}
    var logs = audit.getAll(1000);
    var failedLogins = logs.filter(function(l) { return l.action === 'LOGIN_FAILED'; }).length;
    var bannedIPs = logs.filter(function(l) { return l.action === 'IP_BANNED'; }).length;
    var certMonitor = require('../utils/certMonitor');
    var certData = certMonitor.getCached();
    var certIssues = certData ? (certData.summary.expired + certData.summary.expiringSoon) : 0;
    res.render('reports/security', {
      admin: req.session.admin, page: 'reports',
      scap: scap, failedLogins: failedLogins, bannedIPs: bannedIPs, certIssues: certIssues,
      error: null,
    });
  } catch(e) {
    res.render('reports/security', { admin: req.session.admin, page: 'reports', scap: null, failedLogins: 0, bannedIPs: 0, certIssues: 0, error: e.message });
  }
});

// Event Error Report (errors pulled from audit log + Windows Application/System event log via PowerShell)
router.get('/event-errors', function(req, res) {
  try {
    var logs = audit.getAll(500).filter(function(l) {
      return l.action && (l.action.indexOf('FAILED') >= 0 || l.action.indexOf('ERROR') >= 0);
    });
    res.render('reports/event-errors', { admin: req.session.admin, page: 'reports', logs: logs, error: null });
  } catch(e) {
    res.render('reports/event-errors', { admin: req.session.admin, page: 'reports', logs: [], error: e.message });
  }
});

// Custom Report Builder
router.get('/custom', function(req, res) {
  res.render('reports/custom', { admin: req.session.admin, page: 'reports', result: null, error: null });
});

router.post('/custom', function(req, res) {
  try {
    var source = req.body.source;
    var filterField = req.body.filterField || '';
    var filterValue = (req.body.filterValue || '').toLowerCase();
    var result = [];

    if (source === 'audit') {
      result = audit.getAll(2000).filter(function(row) {
        if (!filterField || !filterValue) return true;
        return String(row[filterField] || '').toLowerCase().indexOf(filterValue) >= 0;
      });
    }

    res.render('reports/custom', { admin: req.session.admin, page: 'reports', result: result, source: source, filterField: filterField, filterValue: req.body.filterValue, error: null });
  } catch(e) {
    res.render('reports/custom', { admin: req.session.admin, page: 'reports', result: null, error: e.message });
  }
});

// CSV helper - escapes commas/quotes/newlines per RFC 4180
function csvEscape(v) {
  if (v === null || v === undefined) return '';
  var s = String(v);
  if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}
function csvRow(values) { return values.map(csvEscape).join(',') + '\n'; }

// Export any report as CSV - covers every report type in the Reports index
router.get('/export/:type', async function(req, res) {
  var type = req.params.type;
  try {
    var csv = '';
    var filename = type + '-report-' + new Date().toISOString().slice(0,10) + '.csv';

    if (type === 'audit') {
      csv = audit.exportCSV();

    } else if (type === 'user-activity') {
      var uLogs = audit.getAll(2000).filter(function(l) { return l.action && l.action.toLowerCase().indexOf('user') >= 0; });
      csv = csvRow(['Timestamp','Action','Actor','Target','Detail','IP']);
      uLogs.forEach(function(l) { csv += csvRow([l.ts, l.action, l.actor, l.target, l.details, l.ip]); });

    } else if (type === 'login-failures') {
      var failLogs = audit.getAll(2000).filter(function(l) { return l.action === 'LOGIN_FAILED' || l.action === 'LOGIN_BLOCKED'; });
      csv = csvRow(['Timestamp','Type','Username Attempted','Detail','IP']);
      failLogs.forEach(function(l) { csv += csvRow([l.ts, l.action, l.target, l.details, l.ip]); });

    } else if (type === 'lockouts') {
      var lockedUsers = await ad.getLockedUsers();
      csv = csvRow(['Display Name','Username']);
      lockedUsers.forEach(function(u) { csv += csvRow([u.displayName||u.sAMAccountName, u.sAMAccountName]); });
      csv += '\n';
      csv += csvRow(['--- Lockout/Unlock/Ban Events ---']);
      csv += csvRow(['Timestamp','Event','Target','Actor','IP']);
      var lockLogs = audit.getAll(2000).filter(function(l) { return l.action === 'USER_UNLOCKED' || l.action === 'IP_BANNED'; });
      lockLogs.forEach(function(l) { csv += csvRow([l.ts, l.action, l.target, l.actor, l.ip]); });

    } else if (type === 'certificates') {
      var certMonitor = require('../utils/certMonitor');
      var certData = certMonitor.getCached();
      csv = csvRow(['Category','Subject','Issuer','Not After','Days Left','Store','Thumbprint']);
      (certData ? certData.certs : []).forEach(function(c) {
        csv += csvRow([c.category, c.subject, c.issuer, c.notAfter, c.daysLeft, c.store, c.thumbprint]);
      });

    } else if (type === 'event-errors') {
      var errLogs = audit.getAll(2000).filter(function(l) { return l.action && (l.action.indexOf('FAILED') >= 0 || l.action.indexOf('ERROR') >= 0); });
      csv = csvRow(['Timestamp','Event','Actor','Target','Detail']);
      errLogs.forEach(function(l) { csv += csvRow([l.ts, l.action, l.actor, l.target, l.details]); });

    } else if (type === 'ad-health') {
      var assessor = require('../utils/migration/assessor');
      var assessments = assessor.getAssessments();
      var latest = assessments && assessments.length ? assessments[0] : null;
      csv = csvRow(['Check','Category','Severity','Passed','Message','Suggested Fix']);
      (latest ? (latest.checks||[]) : []).forEach(function(c) {
        csv += csvRow([c.name, c.category, c.severity, c.passed, c.message, c.fix||'']);
      });

    } else if (type === 'dc-health') {
      var dcs = adSvc.getAllDomainControllers();
      csv = csvRow(['Name','IP','OS','Responding','Global Catalog','RODC']);
      dcs.forEach(function(dc) { csv += csvRow([dc.name, dc.ip, dc.os, dc.responding, dc.isGC, dc.isRODC]); });

    } else if (type === 'replication') {
      var fs1 = require('fs'), path1 = require('path');
      var cacheFile1 = path1.join(__dirname, '../data/services_cache.json');
      var svc1 = fs1.existsSync(cacheFile1) ? JSON.parse(fs1.readFileSync(cacheFile1, 'utf8')) : null;
      csv = csvRow(['Metric','Value']);
      if (svc1 && svc1.replication) {
        csv += csvRow(['DC Count', svc1.replication.dcCount]);
        csv += csvRow(['Replication Healthy', svc1.replication.healthy]);
        csv += csvRow(['Failures', svc1.replication.failures]);
      }
      if (svc1 && svc1.fsmo) {
        csv += '\n' + csvRow(['--- FSMO Role Holders ---']);
        Object.keys(svc1.fsmo).forEach(function(k) { csv += csvRow([k, svc1.fsmo[k]]); });
      }

    } else if (type === 'dns-health') {
      var fs2 = require('fs'), path2 = require('path');
      var cacheFile2 = path2.join(__dirname, '../data/services_cache.json');
      var svc2 = fs2.existsSync(cacheFile2) ? JSON.parse(fs2.readFileSync(cacheFile2, 'utf8')) : null;
      csv = csvRow(['Zone Name','Type','Reverse Lookup','AD Integrated']);
      if (svc2 && svc2.dns && svc2.dns.zones) {
        svc2.dns.zones.forEach(function(z) { csv += csvRow([z.ZoneName||z.name, z.ZoneType||z.type, z.IsReverseLookupZone, z.IsDsIntegrated]); });
      }

    } else if (type === 'gpo') {
      var gpoStore1 = require('../utils/gpoStore');
      var policies1 = gpoStore1.getAllPolicies ? gpoStore1.getAllPolicies() : [];
      csv = csvRow(['Name','Category','Status','Settings Count','Source','Created']);
      policies1.forEach(function(p) { csv += csvRow([p.name, p.category, p.status, (p.settings||[]).length, p.adGpoId?'AD Synced':'Custom', p.createdAt]); });

    } else if (type === 'security') {
      var scap1 = null; try { scap1 = adSvc.getSCAPScore(); } catch(e) {}
      csv = csvRow(['Metric','Value']);
      if (scap1) {
        csv += csvRow(['SCAP Score %', scap1.percent]);
        csv += csvRow(['SCAP Grade', scap1.grade]);
      }
      csv += '\n' + csvRow(['--- SCAP Checks ---']);
      csv += csvRow(['Check','Pass','Detail']);
      (scap1 && scap1.checks ? scap1.checks : []).forEach(function(c) { csv += csvRow([c.name, c.pass, c.detail]); });

    } else if (type === 'security-compliance') {
      var scap2 = null; try { scap2 = adSvc.getSCAPScore(); } catch(e) {}
      csv = csvRow(['Check','Pass','Detail']);
      (scap2 && scap2.checks ? scap2.checks : []).forEach(function(c) { csv += csvRow([c.name, c.pass, c.detail]); });

    } else if (type === 'password-expiry') {
      var d = adSvc.getUsersPasswordExpiry();
      csv = csvRow(['Username','DisplayName','PasswordLastSet','PasswordExpiry','DaysLeft','NeverExpires','Enabled']);
      (d.users || []).forEach(function(u) {
        csv += csvRow([u.username, u.displayName, u.passwordLastSet, u.passwordExpiry, u.daysUntilExpiry, u.neverExpires, u.enabled]);
      });

    } else if (type === 'group-membership') {
      var groups = await ad.getGroups();
      csv = csvRow(['Group','SAMAccountName','Type','Members']);
      groups.forEach(function(g) {
        var members = Array.isArray(g.member) ? g.member : (g.member ? [g.member] : []);
        csv += csvRow([g.sAMAccountName, g.sAMAccountName, parseInt(g.groupType||0)<0?'Security':'Distribution', members.length]);
      });

    } else if (type === 'gdpr') {
      var users1 = await ad.getUsers();
      csv = csvRow(['Username','DisplayName','Email','Department','Title','Created','LastLogon']);
      users1.forEach(function(u) {
        var ll = parseInt(u.lastLogon||0);
        var lastLogonStr = ll > 0 ? new Date(ll/1e4 - 11644473600000).toISOString() : 'Never';
        csv += csvRow([u.sAMAccountName, u.displayName, u.mail, u.department, u.title, u.whenCreated, lastLogonStr]);
      });

    } else if (type === 'backup') {
      var history = backup.getHistory();
      csv = csvRow(['Type','Status','Encrypted','Destination','Started','Completed']);
      history.forEach(function(b) { csv += csvRow([b.type, b.status, b.encrypted, b.destination, b.timestamp, b.completedAt]); });

    } else {
      csv = 'Report type "' + type + '" not recognized for export.\n';
    }

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send(csv);
  } catch(e) {
    logger.error('Report export failed for ' + type + ': ' + e.message);
    res.status(500).send('Export failed: ' + e.message);
  }
});

module.exports = router;
