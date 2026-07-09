'use strict';
var express = require('express');
var router  = express.Router();
var rbac    = require('../utils/rbac');
var logger  = require('../utils/logger');
var certMonitor = require('../utils/certMonitor');
var audit   = require('../utils/auditLogger');

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  var cached = certMonitor.getCached();
  res.render('certificates/index', {
    admin: req.session.admin, page: 'certificates',
    data: cached, error: null,
  });
});

router.post('/scan', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    logger.info('Certificate scan triggered by ' + req.session.admin.username);
    var result = certMonitor.scanCertificates();
    if (result.error) return res.json({ ok: false, error: result.error });
    audit.log('CERT_SCAN', req.session.admin.username, 'certificates', 'Scanned ' + result.summary.total + ' certificates', req.ip);
    res.json({ ok: true, data: result });
  } catch(e) {
    logger.error('Cert scan error: ' + e.message);
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
