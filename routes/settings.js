'use strict';
var express  = require('express');
var router   = express.Router();
var settings = require('../utils/settings');
var audit    = require('../utils/auditLogger');
var rbac     = require('../utils/rbac');
var logger   = require('../utils/logger');

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  var s = settings.get();
  res.render('settings/index', { admin: req.session.admin, page: 'settings', s: s, success: req.query.success || null, error: req.query.error || null });
});

router.post('/save', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var updates = {
      sessionTimeoutMinutes: parseInt(req.body.sessionTimeoutMinutes) || 480,
      auditLogRetentionDays: parseInt(req.body.auditLogRetentionDays) || 90,
      smtpHost:   (req.body.smtpHost || '').trim(),
      smtpPort:   parseInt(req.body.smtpPort) || 25,
      smtpUser:   (req.body.smtpUser || '').trim(),
      smtpFrom:   (req.body.smtpFrom || '').trim(),
      alertEmails: (req.body.alertEmails || '').split(/[\n,;]+/).map(function(e){ return e.trim(); }).filter(Boolean),
      backupSchedule:      req.body.backupSchedule      || '0 2 * * *',
      backupDestination:   req.body.backupDestination   || 'C:\\ADBackups',
      backupRetentionDays: parseInt(req.body.backupRetentionDays) || 30,
      backupType:          req.body.backupType          || 'daily',
      orgName:         req.body.orgName         || '',
      orgAnnouncement: req.body.orgAnnouncement || '',
      orgHolidays: (function() {
        var dates = [].concat(req.body.holidayDate || []);
        var names = [].concat(req.body.holidayName || []);
        var result = [];
        for (var i = 0; i < dates.length; i++) {
          if (dates[i] && names[i] && names[i].trim()) result.push({ date: dates[i], name: names[i].trim() });
        }
        return result;
      })(),
      mfaEnabled:  req.body.mfaEnabled  === 'on',
      mfaEnforced: req.body.mfaEnforced === 'on',
      backupEncryption: req.body.backupEncryption === 'on',
    };
    if (req.body.smtpPass && req.body.smtpPass.trim()) {
      // Strip ALL whitespace, not just edges - Google App Passwords are often copy-pasted
      // with internal spaces in the "abcd efgh ijkl mnop" display format, which Gmail's SMTP
      // server will reject. Same defensive cleanup applies harmlessly to other providers.
      updates.smtpPass = req.body.smtpPass.replace(/\s+/g, '');
    }
    if (req.body.backupEncryptionPassphrase && req.body.backupEncryptionPassphrase.trim()) updates.backupEncryptionPassphrase = req.body.backupEncryptionPassphrase.trim();
    settings.save(updates);
    audit.log('SETTINGS_CHANGED', req.session.admin.username, 'system', 'Settings updated', req.ip);
    logger.info('Settings saved by ' + req.session.admin.username);
    res.redirect('/settings?success=Settings saved successfully');
  } catch(e) {
    res.redirect('/settings?error=' + encodeURIComponent(e.message));
  }
});

router.get('/audit-export', rbac.requirePermission('dashboard.view'), function(req, res) {
  var csv = audit.exportCSV();
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-log-' + new Date().toISOString().slice(0,10) + '.csv"');
  res.send(csv);
});

router.post('/audit-clear', rbac.requirePermission('dashboard.view'), function(req, res) {
  audit.log('AUDIT_CLEARED', req.session.admin.username, 'audit.log', 'Audit log cleared by admin', req.ip);
  audit.clear();
  logger.info('Audit log cleared by ' + req.session.admin.username);
  res.json({ ok: true });
});

router.post('/test-email', rbac.requirePermission('dashboard.view'), async function(req, res) {
  try {
    var notifier = require('../utils/emailNotifier');
    var result = await notifier.sendAlert('Test Alert from AD Console', 'This is a test email from AD Web Console.\n\nIf you received this, your email notification settings are configured correctly.\n\nTime: ' + new Date().toISOString());
    if (result.ok) {
      logger.info('Test email sent successfully to: ' + (require('../utils/settings').get().alertEmails||[]).join(', '));
      res.json({ ok: true, message: 'Email accepted by SMTP server (messageId: ' + result.messageId + '). Check your inbox and spam folder.' });
    } else {
      logger.warn('Test email failed: ' + result.error);
      res.json({ ok: false, error: result.error });
    }
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/verify-email', rbac.requirePermission('dashboard.view'), async function(req, res) {
  try {
    var notifier = require('../utils/emailNotifier');
    var result = await notifier.verifyConnection();
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/test-email-to', rbac.requirePermission('dashboard.view'), async function(req, res) {
  try {
    var to = (req.body.to || '').trim();
    if (!to) return res.json({ ok: false, error: 'No address provided.' });
    var notifier = require('../utils/emailNotifier');
    var result = await notifier.sendTestTo(to, 'Test Alert from AD Console',
      'This is a test email from AD Web Console, sent to a specific address.\n\nIf you received this, your email notification settings are configured correctly.\n\nTime: ' + new Date().toISOString());
    if (result.ok) {
      logger.info('Test email sent to specific address: ' + to);
      res.json({ ok: true, message: 'Email accepted by SMTP server (messageId: ' + result.messageId + '). Check the inbox and spam folder for ' + to + '.' });
    } else {
      res.json({ ok: false, error: result.error });
    }
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
