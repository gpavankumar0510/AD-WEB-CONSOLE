'use strict';
var express  = require('express');
var router   = express.Router();
var ad       = require('../utils/adService');
var adSvc    = require('../utils/adServices');
var backup   = require('../utils/backupService');
var settings = require('../utils/settings');
var holidays = require('../utils/holidays');
var calendarEvents = require('../utils/calendarEvents');
var audit    = require('../utils/auditLogger');
var logger   = require('../utils/logger');
var rbac     = require('../utils/rbac');
var fs = require('fs'), path = require('path');

// ── Unified dashboard cache (single file for all widgets) ────────────────
var DASH_CACHE = path.join(__dirname, '../data/dashboard_cache.json');
var DASH_TTL   = 5 * 60 * 1000; // 5 minutes

function readCache() {
  try {
    if (fs.existsSync(DASH_CACHE)) {
      var c = JSON.parse(fs.readFileSync(DASH_CACHE, 'utf8'));
      return c;
    }
  } catch(e) {}
  return {};
}

function writeCache(key, value) {
  try {
    var dir = path.dirname(DASH_CACHE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    var c = readCache();
    c[key] = { ts: Date.now(), data: value };
    fs.writeFileSync(DASH_CACHE, JSON.stringify(c));
  } catch(e) {}
}

function getCached(key) {
  var c = readCache();
  if (c[key] && (Date.now() - c[key].ts) < DASH_TTL) return c[key].data;
  return null;
}

// Refresh all heavy widgets in the background (called after serving the page)
var refreshing = false;
function backgroundRefresh(force) {
  if (refreshing && !force) return;
  refreshing = true;
  setTimeout(function() {
    try {
      var domInfo  = null;
      var dcs      = null;
      var pwdExp   = null;
      var services = null;
      var certSum  = null;

      try { domInfo = adSvc.getDomainInfo(); if (domInfo && Object.keys(domInfo).length > 2) writeCache('domainInfo', domInfo); } catch(e) { logger.warn('BG domainInfo: '+e.message); }
      try { dcs = adSvc.getAllDomainControllers(); if (dcs && dcs.length) writeCache('allDCs', dcs); } catch(e) { logger.warn('BG allDCs: '+e.message); }
      try { pwdExp = adSvc.getUsersPasswordExpiry(); if (pwdExp) writeCache('pwdExpiry', pwdExp); } catch(e) { logger.warn('BG pwdExpiry: '+e.message); }

      try {
        var sc = path.join(__dirname, '../data/services_cache.json');
        if (fs.existsSync(sc)) {
          var srv = JSON.parse(fs.readFileSync(sc, 'utf8'));
          if ((Date.now() - new Date(srv.scannedAt).getTime()) < 10*60*1000) { services = srv; writeCache('services', services); }
        }
      } catch(e) {}

      try {
        var cm = require('../utils/certMonitor').getCached();
        if (cm) { certSum = cm.summary; writeCache('certSummary', certSum); }
      } catch(e) {}

      ad.getDomainStats().then(function(s) {
        writeCache('stats', s);
        refreshing = false;
      }).catch(function(e) {
        refreshing = false;
        logger.warn('Dashboard background refresh stats: ' + e.message);
      });
    } catch(e) {
      refreshing = false;
      logger.warn('Dashboard background refresh outer: ' + e.message);
    }
  }, 100);
}

// Pre-warm cache on startup so the first dashboard load has real data
setTimeout(function() {
  logger.info('Dashboard: pre-warming cache...');
  backgroundRefresh(true);
}, 8000); // after autoSetup and LDAP init have had a chance to complete

// ── Admin dashboard: serves from cache instantly, triggers background refresh ──
router.get('/', async function(req, res) {
  var isAdmin = req.session.admin && req.session.admin.role === 'admin';

  if (!isAdmin) {
    // Domain user dashboard - lightweight, LDAP only
    try {
      var user = await ad.getUser(req.session.admin.username);
      var pwdDaysLeft = null, pwdExpiryDate = null;
      if (user) {
        var pls = parseInt(user.pwdLastSet || 0);
        if (pls > 0 && !(parseInt(user.userAccountControl||0) & 0x10000)) {
          var policyOut = null;
          try { policyOut = adSvc.getUsersPasswordExpiry(); } catch(e) {}
          var maxAge = (policyOut && policyOut.maxPasswordAgeDays) || 90;
          var lastSetDate = new Date(pls/1e4 - 11644473600000);
          pwdExpiryDate = new Date(lastSetDate.getTime() + maxAge*24*60*60*1000);
          pwdDaysLeft = Math.round((pwdExpiryDate - Date.now()) / (1000*60*60*24));
        }
      }
      var appSettings = settings.get();
      return res.render('dashboard/user', {
        admin: req.session.admin, page: 'dashboard',
        user: user, pwdDaysLeft: pwdDaysLeft, pwdExpiryDate: pwdExpiryDate,
        appSettings: appSettings,
        upcomingHolidays: holidays.getUpcomingHolidays(appSettings.orgHolidays, 5),
        mfaStatus: require('../utils/mfa').isMFAEnabled(req.session.admin.username),
      });
    } catch(e) {
      logger.error('User dashboard: ' + e.message);
      return res.render('dashboard/user', {
        admin: req.session.admin, page: 'dashboard',
        user: null, pwdDaysLeft: null, pwdExpiryDate: null,
        appSettings: settings.get(), mfaStatus: false,
        upcomingHolidays: holidays.getUpcomingHolidays(settings.get().orgHolidays, 5),
      });
    }
  }

  // Admin: serve from cache immediately, trigger background refresh
  var appSettings = settings.get();
  var now = new Date();
  var monthEvents = [];
  try { monthEvents = calendarEvents.getForMonth(now.getFullYear(), now.getMonth()); } catch(e) {}

  // Get LDAP stats - fast (direct LDAP, not PowerShell)
  var stats = getCached('stats');
  var lockedUsers = [];
  var backupHistory = backup.getHistory().slice(0, 5);
  try {
    if (!stats) {
      stats = await ad.getDomainStats();
      writeCache('stats', stats);
    }
    lockedUsers = await ad.getLockedUsers();
  } catch(e) { logger.warn('Dashboard LDAP: ' + e.message); }

  // Everything else from cache (stale is fine - background will refresh)
  // For domainInfo: if cache is empty (very first load), fetch synchronously so the
  // Domain & Server card shows real data immediately instead of all dashes.
  var domainInfo = getCached('domainInfo');
  if (!domainInfo || Object.keys(domainInfo).length === 0) {
    try { domainInfo = adSvc.getDomainInfo(); writeCache('domainInfo', domainInfo); } catch(e) {}
    if (!domainInfo) domainInfo = {};
  }

  var allDCs      = getCached('allDCs') || [];
  var pwdExpiry   = getCached('pwdExpiry') || null;

  // Load services from its own cache file (written by AD Services scan)
  var services = getCached('services') || null;
  if (!services) {
    try {
      var svcCacheFile = path.join(__dirname, '../data/services_cache.json');
      if (fs.existsSync(svcCacheFile)) {
        var svcCached = JSON.parse(fs.readFileSync(svcCacheFile, 'utf8'));
        if ((Date.now() - new Date(svcCached.scannedAt).getTime()) < 15*60*1000) {
          services = svcCached;
          writeCache('services', services);
        }
      }
    } catch(e) {}
  }

  var certSummary = getCached('certSummary') || null;
  if (!certSummary) {
    try { var cm = require('../utils/certMonitor').getCached(); if (cm) certSummary = cm.summary; } catch(e) {}
  }

  // System status data for inline dashboard widget
  var systemStatus = null;
  try {
    var statusCache = getCached('systemStatus');
    if (!statusCache) {
      var memUsage = process.memoryUsage();
      statusCache = {
        nodeVersion: process.version,
        uptimeSec: process.uptime(),
        memUsedMB: Math.round(memUsage.heapUsed / 1024 / 1024),
        memTotalMB: Math.round(memUsage.heapTotal / 1024 / 1024),
        platform: require('os').platform() + ' ' + require('os').release(),
        port: process.env.PORT || 4000,
        ldapHost: require('../utils/autoDetect').getSettings().host || '—',
        fetchedAt: new Date().toISOString(),
      };
      // Disk info from domainInfo if available (pulled in the getDomainInfo() call above)
      writeCache('systemStatus', statusCache);
    }
    systemStatus = statusCache;
  } catch(e) {}

  var scapScore   = null;
  try { scapScore = adSvc.getSCAPScoreCached(); } catch(e) {}
  if (pwdExpiry) appSettings.maxPasswordAgeDays = pwdExpiry.maxPasswordAgeDays;

  // Trigger background refresh so next load is fast
  backgroundRefresh();

  res.render('dashboard/index', {
    admin: req.session.admin, stats: stats||{}, lockedUsers, backupHistory,
    domainInfo, scapScore, allDCs, pwdExpiry, services, systemStatus,
    page: 'dashboard', isAdmin, appSettings,
    upcomingHolidays: holidays.getUpcomingHolidays(appSettings.orgHolidays, 5),
    certSummary, monthEvents,
  });
});

// ── Live widget API (polled by dashboard JS every 60s) ───────────────────
router.get('/api/stats', async function(req, res) {
  if (!req.session.admin) return res.json({ ok: false });
  try {
    var stats = await ad.getDomainStats();
    var locked = await ad.getLockedUsers();
    writeCache('stats', stats);
    res.json({ ok: true, stats: stats, lockedCount: locked.length });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

router.get('/api/domain', function(req, res) {
  if (!req.session.admin) return res.json({ ok: false });
  try {
    var domainInfo = adSvc.getDomainInfo();
    writeCache('domainInfo', domainInfo);
    res.json({ ok: true, domainInfo: domainInfo });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ── Editable Calendar Events API ─────────────────────────────────────────
router.get('/events', function(req, res) {
  var year  = parseInt(req.query.year)  || new Date().getFullYear();
  var month = req.query.month !== undefined ? parseInt(req.query.month) : new Date().getMonth();
  res.json({ ok: true, events: calendarEvents.getForMonth(year, month) });
});

router.post('/events', function(req, res) {
  if (!req.session.admin || req.session.admin.role !== 'admin') return res.json({ ok: false, error: 'Admin only' });
  try {
    var date  = (req.body.date  || '').trim();
    var title = (req.body.title || '').trim();
    if (!date || !title) return res.json({ ok: false, error: 'Date and title required' });
    var entry = calendarEvents.addEvent({ date, title, type: req.body.type||'event', description:(req.body.description||'').trim(), createdBy: req.session.admin.username });
    audit.log('CALENDAR_EVENT_ADDED', req.session.admin.username, entry.title, entry.date, req.ip);
    res.json({ ok: true, event: entry });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

router.put('/events/:id', function(req, res) {
  if (!req.session.admin || req.session.admin.role !== 'admin') return res.json({ ok: false, error: 'Admin only' });
  try {
    var updates = {};
    if (req.body.date)  updates.date  = req.body.date.trim();
    if (req.body.title) updates.title = req.body.title.trim();
    if (req.body.type)  updates.type  = req.body.type;
    if (req.body.description !== undefined) updates.description = req.body.description.trim();
    var updated = calendarEvents.updateEvent(req.params.id, updates);
    if (!updated) return res.json({ ok: false, error: 'Event not found' });
    audit.log('CALENDAR_EVENT_UPDATED', req.session.admin.username, updated.title, updated.date, req.ip);
    res.json({ ok: true, event: updated });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

router.delete('/events/:id', function(req, res) {
  if (!req.session.admin || req.session.admin.role !== 'admin') return res.json({ ok: false, error: 'Admin only' });
  try {
    calendarEvents.removeEvent(req.params.id);
    audit.log('CALENDAR_EVENT_DELETED', req.session.admin.username, req.params.id, '', req.ip);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ── Notifications API ────────────────────────────────────────────────────
router.get('/api/notifications', function(req, res) {
  if (!req.session.admin) return res.json({ ok: false });
  try {
    var audit = require('../utils/auditLogger');
    var allLogs = audit.getAll(100);
    var notifs = allLogs.map(function(log) {
      var type = 'info';
      var action = log.action || '';
      if (action.indexOf('FAILED') >= 0 || action.indexOf('ERROR') >= 0 || action.indexOf('LOCKED') >= 0 || action.indexOf('BANNED') >= 0) type = 'warning';
      if (action.indexOf('DELETED') >= 0) type = 'danger';
      if (action.indexOf('CREATED') >= 0 || action.indexOf('BACKUP') >= 0 || action.indexOf('RESTORE') >= 0) type = 'success';
      if (action.indexOf('LOGIN') >= 0) type = 'info';
      return {
        id: log.ts,
        type: type,
        action: action,
        actor: log.actor || '—',
        target: log.target || '',
        details: log.details || '',
        ts: log.ts,
        timeAgo: timeAgo(new Date(log.ts)),
      };
    });

    // Add system alerts
    var alerts = [];
    try {
      var certMon = require('../utils/certMonitor').getCached();
      if (certMon && certMon.summary) {
        if (certMon.summary.expired > 0) alerts.push({ type: 'danger', action: 'CERT_EXPIRED', actor: 'system', target: certMon.summary.expired + ' certificate(s)', details: 'Certificates have expired — visit Certificates module', ts: new Date().toISOString(), timeAgo: 'now' });
        else if (certMon.summary.expiringSoon > 0) alerts.push({ type: 'warning', action: 'CERT_EXPIRING', actor: 'system', target: certMon.summary.expiringSoon + ' certificate(s)', details: 'Certificates expiring within 30 days', ts: new Date().toISOString(), timeAgo: 'now' });
      }
    } catch(e) {}

    res.json({ ok: true, notifications: alerts.concat(notifs).slice(0, 50) });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

function timeAgo(date) {
  var diff = Math.floor((Date.now() - date.getTime()) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff/60) + 'm ago';
  if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
  return Math.floor(diff/86400) + 'd ago';
}

module.exports = router;
