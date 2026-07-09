'use strict';
var express = require('express');
var router  = express.Router();
var rbac    = require('../utils/rbac');
var logger  = require('../utils/logger');
var multiDomain = require('../utils/multiDomain');
var audit   = require('../utils/auditLogger');

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  var registered = multiDomain.getRegisteredDomains();
  var trustData = null;
  try { trustData = multiDomain.getTrustRelationships(); } catch(e) {}
  res.render('domains/index', {
    admin: req.session.admin, page: 'domains',
    registered: registered, trustData: trustData, error: null,
  });
});

router.post('/discover', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var result = multiDomain.discoverForestDomains();
    if (result.error) return res.json({ ok: false, error: result.error });
    audit.log('FOREST_DISCOVERY', req.session.admin.username, 'forest', 'Discovered ' + (result.domains||[]).length + ' domain(s)', req.ip);
    res.json({ ok: true, data: result });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/add', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var entry = multiDomain.addDomain({
      name: req.body.name, dnsRoot: req.body.dnsRoot, netbios: req.body.netbios,
      type: req.body.type || 'child', dc: req.body.dc, addedBy: req.session.admin.username,
    });
    audit.log('DOMAIN_REGISTERED', req.session.admin.username, entry.dnsRoot, '', req.ip);
    res.redirect('/domains');
  } catch(e) {
    res.redirect('/domains?error=' + encodeURIComponent(e.message));
  }
});

router.post('/:id/remove', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    multiDomain.removeDomain(req.params.id);
    audit.log('DOMAIN_REMOVED', req.session.admin.username, req.params.id, '', req.ip);
    res.json({ ok: true });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.get('/trusts', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var result = multiDomain.getTrustRelationships();
    res.json(result.error ? { ok: false, error: result.error } : { ok: true, trusts: result.trusts });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/trusts/:name/test', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var result = multiDomain.testTrust(req.params.name);
    audit.log('TRUST_TEST', req.session.admin.username, req.params.name, result.healthy ? 'healthy' : 'unhealthy', req.ip);
    res.json({ ok: true, healthy: result.healthy, output: result.output });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
