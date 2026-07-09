'use strict';
var express = require('express');
var router  = express.Router();
var rbac    = require('../utils/rbac');
var logger  = require('../utils/logger');
var integrations = require('../utils/integrations');
var audit   = require('../utils/auditLogger');

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  var cfg = integrations.getRedacted();
  res.render('integrations/index', {
    admin: req.session.admin, page: 'integrations',
    cfg: cfg, success: req.query.success || null, error: req.query.error || null,
  });
});

router.post('/azure-ad/save', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var updates = {
      enabled: req.body.enabled === 'on',
      tenantId: (req.body.tenantId || '').trim(),
      clientId: (req.body.clientId || '').trim(),
      domain: (req.body.domain || '').trim(),
    };
    if (req.body.clientSecret && req.body.clientSecret.trim()) {
      updates.clientSecretEnc = integrations.encrypt(req.body.clientSecret.trim());
    }
    integrations.save('azureAD', updates);
    audit.log('INTEGRATION_SAVED', req.session.admin.username, 'azureAD', '', req.ip);
    res.redirect('/integrations?success=' + encodeURIComponent('Azure AD / Entra ID settings saved'));
  } catch(e) {
    res.redirect('/integrations?error=' + encodeURIComponent(e.message));
  }
});

router.post('/meshcentral/save', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var updates = { enabled: req.body.enabled === 'on', serverUrl: (req.body.serverUrl || '').trim() };
    if (req.body.apiKey && req.body.apiKey.trim()) updates.apiKeyEnc = integrations.encrypt(req.body.apiKey.trim());
    integrations.save('meshCentral', updates);
    audit.log('INTEGRATION_SAVED', req.session.admin.username, 'meshCentral', '', req.ip);
    res.redirect('/integrations?success=' + encodeURIComponent('MeshCentral settings saved'));
  } catch(e) {
    res.redirect('/integrations?error=' + encodeURIComponent(e.message));
  }
});

router.post('/vmware/save', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var updates = { enabled: req.body.enabled === 'on', vcenterUrl: (req.body.vcenterUrl || '').trim(), username: (req.body.username || '').trim() };
    if (req.body.password && req.body.password.trim()) updates.passwordEnc = integrations.encrypt(req.body.password.trim());
    integrations.save('vmware', updates);
    audit.log('INTEGRATION_SAVED', req.session.admin.username, 'vmware', '', req.ip);
    res.redirect('/integrations?success=' + encodeURIComponent('VMware settings saved'));
  } catch(e) {
    res.redirect('/integrations?error=' + encodeURIComponent(e.message));
  }
});

router.post('/sccm/save', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var updates = { enabled: req.body.enabled === 'on', siteServer: (req.body.siteServer || '').trim(), siteCode: (req.body.siteCode || '').trim() };
    integrations.save('sccm', updates);
    audit.log('INTEGRATION_SAVED', req.session.admin.username, 'sccm', '', req.ip);
    res.redirect('/integrations?success=' + encodeURIComponent('SCCM settings saved'));
  } catch(e) {
    res.redirect('/integrations?error=' + encodeURIComponent(e.message));
  }
});

router.post('/test/:type', rbac.requirePermission('dashboard.view'), async function(req, res) {
  try {
    var type = req.params.type;
    var result;
    if (type === 'azure-ad') result = await integrations.testAzureAD();
    else if (type === 'meshcentral') result = await integrations.testMeshCentral();
    else if (type === 'vmware') result = await integrations.testVMware();
    else if (type === 'sccm') result = await integrations.testSCCM();
    else return res.json({ ok: false, error: 'Unknown integration type: ' + type });

    audit.log('INTEGRATION_TEST', req.session.admin.username, type, result.ok ? 'success' : ('failed: ' + result.error), req.ip);
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
