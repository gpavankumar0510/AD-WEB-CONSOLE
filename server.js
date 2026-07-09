'use strict';
require('dotenv').config();

var express    = require('express');
var session    = require('express-session');
var helmet     = require('helmet');
var bodyParser = require('body-parser');
var path       = require('path');
var fs         = require('fs');
var cron       = require('node-cron');
var logger     = require('./utils/logger');
var rbac       = require('./utils/rbac');
var autoDetect = require('./utils/autoDetect');
var autoSetup  = require('./utils/autoSetup');
var gpoSync    = require('./utils/gpoSync');
var recycleBin = require('./utils/recycleBin');
var audit      = require('./utils/auditLogger');
var settings   = require('./utils/settings');

process.on('uncaughtException',  function(e) { logger.error('Uncaught: '  + e.message); });
process.on('unhandledRejection', function(e) { logger.error('Unhandled: ' + (e&&e.message?e.message:String(e))); });

autoSetup.autoSetup();

var cfg = autoDetect.getSettings();
var app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));
app.use(bodyParser.json({ limit: '5mb' }));

// Session with configurable timeout
var s = settings.get();
app.use(session({
  secret: process.env.SESSION_SECRET || ('adconsole-' + (cfg.domain||'local') + '-secret'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: false, maxAge: (s.sessionTimeoutMinutes||480) * 60 * 1000, sameSite: 'lax' },
}));

// Template helpers + session activity tracking
app.use(function(req, res, next) {
  res.locals.hasPermission  = function(perm) { return rbac.hasPermission(req.session, perm); };
  res.locals.domainSettings = autoDetect.getSettings();
  res.locals.appSettings    = settings.get();
  // Auto-logout on inactivity
  if (req.session.admin && req.session.lastActivity) {
    var timeout = (settings.get().sessionTimeoutMinutes || 480) * 60 * 1000;
    if (Date.now() - req.session.lastActivity > timeout) {
      req.session.destroy(function() {});
      return res.redirect('/login?msg=session_expired');
    }
  }
  if (req.session.admin) req.session.lastActivity = Date.now();
  next();
});

// Audit middleware - log all POST/PUT/DELETE
app.use(function(req, res, next) {
  if (req.method !== 'GET' && req.session && req.session.admin) {
    var actor  = req.session.admin.username;
    var action = req.method + ' ' + req.path;
    audit.log(action, actor, req.path, '', req.ip);
  }
  next();
});

// Routes
app.use('/',           require('./routes/auth'));
app.use('/dashboard',  rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/dashboard'));
app.use('/users',      rbac.requireAuth, rbac.requirePermission('users.view'),     require('./routes/users'));
app.use('/groups',     rbac.requireAuth, rbac.requirePermission('users.view'),     require('./routes/groups'));
app.use('/computers',  rbac.requireAuth, rbac.requirePermission('computers.view'), require('./routes/computers'));
app.use('/ous',        rbac.requireAuth, rbac.requirePermission('users.view'),     require('./routes/ous'));
app.use('/gpo',        rbac.requireAuth, rbac.requirePermission('gpo.view'),       require('./routes/gpo'));
app.use('/backup',     rbac.requireAuth, rbac.requirePermission('backup.view'),    require('./routes/backup'));
app.use('/myaccount',  rbac.requireAuth, require('./routes/myaccount'));
app.use('/recycle',    rbac.requireAuth, rbac.requirePermission('users.view'),     require('./routes/recycle'));
app.use('/services',   rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/services'));
app.use('/migration',  rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/migration'));
app.use('/reports',    rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/reports'));
app.use('/settings',   rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/settings'));
app.use('/status',     rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/status'));
app.use('/certificates', rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/certificates'));
app.use('/domains',      rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/domains'));
app.use('/security',     rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/security'));
app.use('/integrations', rbac.requireAuth, rbac.requirePermission('dashboard.view'), require('./routes/integrations'));

app.get('/', function(req, res) {
  if (!req.session.admin) return res.redirect('/login');
  return res.redirect(req.session.admin.role === 'admin' ? '/dashboard' : '/myaccount');
});

app.get('/health', function(req, res) {
  var s2 = autoDetect.getSettings();
  res.json({ status: 'ok', uptime: process.uptime(), domain: s2.domain, host: s2.host, source: s2.source });
});

app.use(function(req, res) {
  res.status(404).render('error', { code: 404, message: 'Page not found', admin: (req.session && req.session.admin) || null });
});
app.use(function(err, req, res, next) {
  logger.error('Route error: ' + err.message);
  res.status(500).render('error', { code: 500, message: err.message, admin: (req.session && req.session.admin) || null });
});

// GPO auto-sync
setTimeout(function() { logger.info('GPO Sync: Initial sync...'); gpoSync.fullSync(); }, 5000);
cron.schedule('*/30 * * * *', function() { logger.info('GPO Sync: Scheduled sync...'); gpoSync.fullSync(); });

// Recycle bin cleanup
cron.schedule('0 3 * * *', function() { recycleBin.cleanup(); logger.info('Recycle bin: cleanup done'); });

// Brute-force tracker cleanup
cron.schedule('*/10 * * * *', function() {
  try { require('./utils/bruteForce').cleanup(); } catch(e) {}
});

// Audit log retention cleanup
cron.schedule('0 4 * * *', function() {
  var sett = settings.get();
  var retDays = sett.auditLogRetentionDays || 90;
  logger.info('Audit log retention cleanup: ' + retDays + ' days');
});

// Certificate expiry scan - daily at 6am, alerts on certs expiring within 30 days
cron.schedule('0 6 * * *', function() {
  try {
    logger.info('Certificate scan: starting scheduled scan...');
    var certMonitor = require('./utils/certMonitor');
    var result = certMonitor.scanCertificates();
    if (result.error) { logger.warn('Certificate scan failed: ' + result.error); return; }
    logger.info('Certificate scan: ' + result.summary.total + ' certs, ' + result.summary.expired + ' expired, ' + result.summary.expiringSoon + ' expiring soon');
    var urgent = result.certs.filter(function(c) { return c.daysLeft <= 30; });
    if (urgent.length) {
      var notifier = require('./utils/emailNotifier');
      var lines = urgent.map(function(c) {
        return c.subject + ' (' + c.category + ') - ' + (c.daysLeft < 0 ? 'EXPIRED ' + Math.abs(c.daysLeft) + ' days ago' : c.daysLeft + ' days left');
      }).join('\n');
      notifier.sendAlert('Certificate Expiry Warning', urgent.length + ' certificate(s) expiring or expired:\n\n' + lines).catch(function(){});
    }
  } catch(e) { logger.error('Certificate scan cron: ' + e.message); }
});
// Run an initial cert scan 15s after startup so the dashboard/cert page has data without manual action
setTimeout(function() {
  try {
    logger.info('Certificate scan: initial scan on startup...');
    require('./utils/certMonitor').scanCertificates();
  } catch(e) { logger.warn('Initial cert scan: ' + e.message); }
}, 15000);

// Auto-lock check
if (process.env.AUTO_MOVE_LOCKED === 'true' && process.env.AD_LOCKED_OU) {
  cron.schedule('*/15 * * * *', async function() {
    try {
      var adSvc = require('./utils/adService');
      var locked = await adSvc.getLockedUsers();
      for (var i = 0; i < locked.length; i++) {
        var u = locked[i];
        var dn = typeof u.dn === 'string' ? u.dn : String(u.dn || u.distinguishedName || '');
        if (dn && dn.indexOf(process.env.AD_LOCKED_OU) < 0) {
          await adSvc.moveObject(dn, process.env.AD_LOCKED_OU).catch(function() {});
          logger.info('AUTO: Moved locked user ' + u.sAMAccountName);
          require('./utils/emailNotifier').alertLockout(u.sAMAccountName, '').catch(function(){});
        }
      }
    } catch(e) { logger.error('Lock check: ' + e.message); }
  });
}

// Scheduled backup
cron.schedule(settings.get().backupSchedule || '0 2 * * *', function() {
  var bs = require('./utils/backupService');
  logger.info('Scheduled backup starting...');
  bs.runBackup(settings.get().backupType === 'full' ? 'Full-Server' : 'AD-State',
    settings.get().backupDestination).catch(function(e) { logger.error('Backup failed: ' + e.message); });
});

var PORT = parseInt(process.env.PORT || '4000');
var HTTPS_PORT = parseInt(process.env.HTTPS_PORT || '4443');
var SSL_CERT = process.env.SSL_CERT_PATH || '';
var SSL_KEY  = process.env.SSL_KEY_PATH  || '';

function logStartup(proto, port) {
  var s3 = autoDetect.getSettings();
  logger.info('AD Web Console v5.0 running on port ' + port + ' (' + proto + ')');
  logger.info('Domain:  ' + s3.domain + ' (' + s3.source + ')');
  logger.info('LDAP:    ' + s3.host);
  logger.info('SvcAcct: ' + (s3.serviceAcct || 'NOT SET'));
  logger.info('URL:     ' + proto.toLowerCase() + '://localhost:' + port);
}

// HTTPS if cert/key configured
if (SSL_CERT && SSL_KEY && fs.existsSync(SSL_CERT) && fs.existsSync(SSL_KEY)) {
  var https = require('https');
  var sslOptions = {
    cert: fs.readFileSync(SSL_CERT),
    key:  fs.readFileSync(SSL_KEY),
  };
  https.createServer(sslOptions, app).listen(HTTPS_PORT, '0.0.0.0', function() {
    logStartup('HTTPS', HTTPS_PORT);
  });
  // Optional: also listen on HTTP and redirect to HTTPS
  if (process.env.HTTP_REDIRECT === 'true') {
    var redirectApp = require('express')();
    redirectApp.use(function(req, res) {
      res.redirect('https://' + req.hostname + ':' + HTTPS_PORT + req.url);
    });
    redirectApp.listen(PORT, '0.0.0.0', function() {
      logger.info('HTTP redirect listener on port ' + PORT + ' -> HTTPS ' + HTTPS_PORT);
    });
  }
} else {
  app.listen(PORT, '0.0.0.0', function() {
    logStartup('HTTP', PORT);
    if (!SSL_CERT) logger.info('Tip: set SSL_CERT_PATH and SSL_KEY_PATH in .env to enable HTTPS');
  });
}
