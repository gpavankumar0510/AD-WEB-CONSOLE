'use strict';
var fs   = require('fs');
var path = require('path');
var logger = require('./logger');

var SETTINGS_FILE = path.join(__dirname, '../data/settings.json');

function getSettings() {
  try {
    if (fs.existsSync(SETTINGS_FILE)) return JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
  } catch(e) {}
  return {};
}

function buildTransportOptions(settings) {
  var port = parseInt(settings.smtpPort || '587');
  // Port 465 = implicit TLS (secure:true). Port 587/25 = STARTTLS (secure:false, requireTLS:true for providers that mandate it).
  var opts = {
    host: settings.smtpHost,
    port: port,
    secure: port === 465,
    requireTLS: port !== 465, // force STARTTLS upgrade on 587/25 - required by Gmail, Outlook, M365
    auth: (settings.smtpUser && settings.smtpPass) ? { user: settings.smtpUser, pass: settings.smtpPass } : undefined,
    tls: { rejectUnauthorized: false, minVersion: 'TLSv1.2' },
    connectionTimeout: 15000,
    greetingTimeout: 10000,
    socketTimeout: 20000,
  };
  return opts;
}

// Sends an alert email. Returns { ok: true } on confirmed delivery to the SMTP server,
// or { ok: false, error: '...' } on any failure. NEVER silently swallows errors -
// callers (e.g. the Settings "Test Email" button) depend on this to report the real outcome.
async function sendAlert(subject, body) {
  var settings = getSettings();

  if (!settings.smtpHost || !settings.smtpHost.trim()) {
    var msg = 'SMTP host is not configured. Go to Settings > Email Notifications and enter your SMTP server details.';
    logger.warn('Email alert skipped: ' + msg);
    return { ok: false, error: msg };
  }
  if (!settings.alertEmails || !settings.alertEmails.length) {
    var msg2 = 'No alert recipient email addresses configured. Add at least one under Settings > Alert Recipients.';
    logger.warn('Email alert skipped: ' + msg2);
    return { ok: false, error: msg2 };
  }
  if (!settings.smtpUser || !settings.smtpPass) {
    logger.warn('Email alert attempted without SMTP credentials - this will likely fail for Gmail/Outlook/M365.');
  }

  try {
    var nodemailer = require('nodemailer');
    var transporter = nodemailer.createTransport(buildTransportOptions(settings));

    var emails = Array.isArray(settings.alertEmails) ? settings.alertEmails : [settings.alertEmails];
    var info = await transporter.sendMail({
      from: settings.smtpFrom && settings.smtpFrom.trim() ? settings.smtpFrom.trim() : (settings.smtpUser || ('ad-console@' + (process.env.AD_DOMAIN_DISPLAY || 'domain.local'))),
      to: emails.join(','),
      subject: '[AD Console] ' + subject,
      text: body,
      html: '<pre style="font-family:monospace;white-space:pre-wrap;">' + String(body).replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre>',
    });

    logger.info('Alert email sent: ' + subject + ' (messageId=' + (info && info.messageId) + ', accepted=' + JSON.stringify(info && info.accepted) + ')');

    if (info && info.rejected && info.rejected.length) {
      return { ok: false, error: 'Server rejected recipient(s): ' + info.rejected.join(', ') };
    }
    return { ok: true, messageId: info && info.messageId, accepted: info && info.accepted };

  } catch(e) {
    // Translate the most common provider-specific failures into actionable messages
    var friendly = e.message || String(e);
    if (/Invalid login|EAUTH|Username and Password not accepted/i.test(friendly)) {
      friendly = 'Authentication rejected by the mail server. For Gmail/Outlook/M365 with 2FA enabled, you must use an App Password, not your normal account password. (' + friendly + ')';
    } else if (/self.signed certificate|unable to verify/i.test(friendly)) {
      friendly = 'TLS certificate validation failed connecting to the SMTP server. (' + friendly + ')';
    } else if (/ETIMEDOUT|ECONNREFUSED|ENOTFOUND/i.test(friendly)) {
      friendly = 'Could not reach the SMTP server (' + (getSettings().smtpHost||'') + ':' + (getSettings().smtpPort||'') + '). Check the host/port and that this server has outbound network access to it. (' + friendly + ')';
    }
    logger.warn('Email alert failed: ' + friendly);
    return { ok: false, error: friendly };
  }
}

async function alertLockout(username, ip) {
  return sendAlert('Account Locked Out: ' + username,
    'Account lockout detected\n\nUsername: ' + username + '\nTime: ' + new Date().toISOString() + '\nSource IP: ' + (ip||'unknown'));
}

async function alertDeletion(type, name, actor) {
  return sendAlert(type + ' Deleted: ' + name,
    type + ' deleted\n\nObject: ' + name + '\nDeleted by: ' + actor + '\nTime: ' + new Date().toISOString());
}

async function alertFailedOp(operation, actor, error) {
  return sendAlert('Failed Operation: ' + operation,
    'Operation failed\n\nOperation: ' + operation + '\nActor: ' + actor + '\nError: ' + error + '\nTime: ' + new Date().toISOString());
}

async function alertSecurityEvent(event, details) {
  return sendAlert('Security Event: ' + event,
    'Security event detected\n\nEvent: ' + event + '\nDetails: ' + details + '\nTime: ' + new Date().toISOString());
}

// Verify SMTP connectivity/auth without sending an actual email - faster feedback loop
async function verifyConnection() {
  var settings = getSettings();
  if (!settings.smtpHost || !settings.smtpHost.trim()) {
    return { ok: false, error: 'SMTP host is not configured.' };
  }

  // Build a non-secret diagnostic string of exactly what will be sent to the SMTP server,
  // so auth failures can be debugged without ever exposing the password itself.
  var diag = 'host=' + settings.smtpHost +
    ' port=' + settings.smtpPort +
    ' user="' + (settings.smtpUser || '') + '" (length ' + (settings.smtpUser || '').length + ')' +
    ' passwordSet=' + !!settings.smtpPass +
    ' passwordLength=' + (settings.smtpPass ? settings.smtpPass.length : 0) +
    ' passwordHasSpaces=' + (settings.smtpPass ? /\s/.test(settings.smtpPass) : false);

  try {
    var nodemailer = require('nodemailer');
    var transporter = nodemailer.createTransport(buildTransportOptions(settings));
    await transporter.verify();
    return { ok: true, diagnostic: diag };
  } catch(e) {
    var friendly = e.message || String(e);
    if (/Invalid login|EAUTH/i.test(friendly)) {
      friendly = 'Authentication rejected by the mail server. (' + friendly + ')';
    }
    return { ok: false, error: friendly, diagnostic: diag };
  }
}

// Send a one-off test email to a specific address, bypassing the saved alertEmails list
async function sendTestTo(toAddress, subject, body) {
  var settings = getSettings();
  if (!settings.smtpHost || !settings.smtpHost.trim()) {
    return { ok: false, error: 'SMTP host is not configured.' };
  }
  try {
    var nodemailer = require('nodemailer');
    var transporter = nodemailer.createTransport(buildTransportOptions(settings));
    var info = await transporter.sendMail({
      from: settings.smtpFrom && settings.smtpFrom.trim() ? settings.smtpFrom.trim() : (settings.smtpUser || 'ad-console@domain.local'),
      to: toAddress,
      subject: '[AD Console] ' + subject,
      text: body,
      html: '<pre style="font-family:monospace;white-space:pre-wrap;">' + String(body).replace(/&/g,'&amp;').replace(/</g,'&lt;') + '</pre>',
    });
    if (info && info.rejected && info.rejected.length) {
      return { ok: false, error: 'Server rejected recipient: ' + info.rejected.join(', ') };
    }
    return { ok: true, messageId: info && info.messageId };
  } catch(e) {
    var friendly = e.message || String(e);
    if (/Invalid login|EAUTH/i.test(friendly)) {
      friendly = 'Authentication rejected. Use an App Password for Gmail/Outlook/M365 if 2FA is enabled. (' + friendly + ')';
    }
    return { ok: false, error: friendly };
  }
}

module.exports = { sendAlert, alertLockout, alertDeletion, alertFailedOp, alertSecurityEvent, verifyConnection, sendTestTo };
