'use strict';
var express = require('express');
var router  = express.Router();
var rbac    = require('../utils/rbac');
var logger  = require('../utils/logger');
var adSvc   = require('../utils/adServices');
var secRec  = require('../utils/securityRecommendations');
var audit   = require('../utils/auditLogger');

router.get('/', rbac.requirePermission('dashboard.view'), function(req, res) {
  // Always serve from cache instantly - rescan button triggers fresh data
  var scap = null, health = [];
  try {
    var fs2 = require('fs'), path2 = require('path');
    var cacheFile = path2.join(__dirname, '../data/scap_cache.json');
    if (fs2.existsSync(cacheFile)) {
      var cached = JSON.parse(fs2.readFileSync(cacheFile, 'utf8'));
      if (cached && cached.data) scap = cached.data;
    }
  } catch(e) {}
  // If no cache at all, return page with empty state (user clicks Rescan to populate)
  try {
    var hCacheFile = require('path').join(__dirname, '../data/health_cache.json');
    var fs3 = require('fs');
    if (fs3.existsSync(hCacheFile)) {
      var hCached = JSON.parse(fs3.readFileSync(hCacheFile, 'utf8'));
      if (hCached && hCached.data && (Date.now() - new Date(hCached.ts||0).getTime()) < 15*60*1000) health = hCached.data;
    }
  } catch(e) {}

  res.render('security/index', {
    admin: req.session.admin, page: 'security',
    scap: scap, health: health, error: null,
  });
});

router.post('/rescan', rbac.requirePermission('dashboard.view'), function(req, res) {
  try {
    var scap = adSvc.getSCAPScoreCached(true);
    var health = secRec.getHealthSummary();
    // Cache health summary
    try {
      var fs4 = require('fs'), path4 = require('path');
      var hf = path4.join(__dirname, '../data/health_cache.json');
      fs4.writeFileSync(hf, JSON.stringify({ ts: new Date().toISOString(), data: health }));
    } catch(e) {}
    audit.log('SECURITY_RESCAN', req.session.admin.username, 'security', 'SCAP=' + (scap.percent||0) + '%', req.ip);
    res.json({ ok: true, scap: scap, health: health });
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

router.post('/fix', rbac.requirePermission('backup.run'), function(req, res) {
  var checkName = req.body.checkName || '';
  if (!checkName) return res.json({ ok: false, error: 'No check specified' });
  try {
    var result = secRec.applyFix(checkName);
    audit.log('SECURITY_FIX', req.session.admin.username, checkName, result.message, req.ip);
    res.json(result);
  } catch(e) {
    res.json({ ok: false, error: e.message });
  }
});

module.exports = router;
