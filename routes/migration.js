'use strict';
var express  = require('express');
var router   = express.Router();
var rbac     = require('../utils/rbac');
var logger   = require('../utils/logger');
var assessor = require('../utils/migration/assessor');
var engine   = require('../utils/migration/migrationEngine');
var adSvc    = require('../utils/adServices');

router.get('/', function(req, res) {
  var jobs = engine.loadJobs();
  var assessments = assessor.getAssessments();
  res.render('migration/index', { admin: req.session.admin, jobs: jobs, assessments: assessments, page: 'migration', error: null });
});

router.get('/assess', function(req, res) {
  res.render('migration/assess', { admin: req.session.admin, page: 'migration', result: null, error: null, running: false });
});

router.post('/assess', function(req, res) {
  var targetOS = req.body.targetOS || '2022';
  var scenario = req.body.scenario || 'DC-to-DC';
  req.socket.setTimeout(120000);
  res.setTimeout(120000);
  try {
    var result = assessor.runAssessment(targetOS, scenario);
    res.render('migration/assess', { admin: req.session.admin, page: 'migration', result: result, error: null, running: false });
  } catch(e) {
    logger.error('Assessment error: ' + e.message);
    res.render('migration/assess', { admin: req.session.admin, page: 'migration', result: null, error: e.message, running: false });
  }
});

router.get('/new', function(req, res) {
  var assessments = assessor.getAssessments();
  var scenarios   = Object.keys(engine.STEPS);
  var dcs = [];
  try { dcs = adSvc.getAllDomainControllers(); } catch(e) { logger.warn('getDCs for migration: ' + e.message); }
  res.render('migration/new', { admin: req.session.admin, page: 'migration', assessments: assessments, scenarios: scenarios, dcs: dcs, error: null });
});

router.post('/new', rbac.requirePermission('backup.run'), async function(req, res) {
  try {
    var jobData = {
      name:         req.body.name || 'Migration Job',
      scenario:     req.body.scenario,
      sourceServer: req.body.sourceServer || '',
      targetServer: req.body.targetServer || '',
      targetOS:     req.body.targetOS || '2022',
      backupPath:   req.body.backupPath || 'C:\\MigrationBackup',
      createdBy:    req.session.admin.username,
    };

    if (req.body.scenario === 'cloud') {
      jobData.cloudConfig = {
        provider: req.body.cloudProvider || 'azure-ad',
        tenantId: req.body.cloudTenantId || '',
        clientId: req.body.cloudClientId || '',
        domain:   req.body.cloudDomain || '',
        syncPasswords: req.body.cloudSyncPasswords === '1',
      };
      // Encrypt the client secret at rest if provided
      if (req.body.cloudClientSecret && req.body.cloudClientSecret.trim()) {
        try {
          var crypto = require('crypto');
          var key = crypto.createHash('sha256').update(process.env.SESSION_SECRET || 'ad-console-default-key').digest();
          var iv = crypto.randomBytes(16);
          var cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
          var enc = Buffer.concat([cipher.update(req.body.cloudClientSecret.trim(), 'utf8'), cipher.final()]);
          var authTag = cipher.getAuthTag();
          jobData.cloudConfig.clientSecretEnc = Buffer.concat([iv, authTag, enc]).toString('base64');
        } catch(e) { logger.warn('Could not encrypt cloud client secret: ' + e.message); }
      }
    }

    var job = engine.createJob(jobData);
    logger.info('Migration job created: ' + job.id + ' by ' + req.session.admin.username);
    res.redirect('/migration/job/' + job.id);
  } catch(e) {
    var dcs = [];
    try { dcs = adSvc.getAllDomainControllers(); } catch(e2) {}
    res.render('migration/new', {
      admin: req.session.admin, page: 'migration',
      assessments: assessor.getAssessments(),
      scenarios: Object.keys(engine.STEPS), dcs: dcs,
      error: e.message,
    });
  }
});

// Repair a specific failed/warning check from the last assessment
router.post('/repair', rbac.requirePermission('backup.run'), function(req, res) {
  var checkName = req.body.checkName || '';
  if (!checkName) return res.json({ ok: false, error: 'No check specified' });
  try {
    var result = assessor.repairCheck(checkName);
    require('../utils/auditLogger').log('MIGRATION_REPAIR', req.session.admin.username, checkName, result.message, req.ip);
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

// API endpoint to get current DC list (for AJAX refresh)
router.get('/dcs', function(req, res) {
  try {
    var dcs = adSvc.getAllDomainControllers();
    res.json({ ok: true, dcs: dcs });
  } catch(e) { res.json({ ok: false, error: e.message, dcs: [] }); }
});

router.get('/job/:id', function(req, res) {
  var job = engine.getJob(req.params.id);
  if (!job) return res.redirect('/migration');
  res.render('migration/job', { admin: req.session.admin, job: job, page: 'migration', error: null });
});

router.post('/job/:id/start', rbac.requirePermission('backup.run'), function(req, res) {
  var job = engine.getJob(req.params.id);
  if (!job) return res.json({ ok: false, error: 'Not found' });
  engine.runJob(req.params.id).catch(function(e) { logger.error('Job run: ' + e.message); });
  logger.info('Migration started: ' + req.params.id + ' by ' + req.session.admin.username);
  res.json({ ok: true });
});

router.post('/job/:id/cancel', rbac.requirePermission('backup.run'), function(req, res) {
  engine.cancelJob(req.params.id);
  logger.info('Migration cancelled: ' + req.params.id);
  res.json({ ok: true });
});

router.post('/job/:id/rollback', rbac.requirePermission('backup.run'), async function(req, res) {
  try {
    var result = await engine.rollbackJob(req.params.id);
    logger.info('Rollback: ' + req.params.id);
    res.json({ ok: true, message: result.output || 'Rollback initiated.' });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.get('/job/:id/status', function(req, res) {
  var job = engine.getJob(req.params.id);
  if (!job) return res.json({ ok: false });
  res.json({ ok: true, status: job.status, progress: job.progress, currentStep: job.currentStep || '', steps: job.steps, logs: (job.logs || []).slice(-20) });
});

module.exports = router;
