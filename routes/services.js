'use strict';
var express = require('express');
var router  = express.Router();
var logger  = require('../utils/logger');
var adSvc   = require('../utils/adServices');
var fs = require('fs'), path = require('path');
var CACHE_FILE = path.join(__dirname,'../data/services_cache.json');
var DC_CACHE   = path.join(__dirname,'../data/dc_cache.json');

function getCache(file, ttlMs) {
  try {
    if (fs.existsSync(file)) {
      var c = JSON.parse(fs.readFileSync(file,'utf8'));
      if (Date.now()-new Date(c.scannedAt||c.cachedAt).getTime() < (ttlMs||300000)) return c;
    }
  } catch(e) {}
  return null;
}
function saveCache(file, data) {
  try {
    var dir=path.dirname(file);
    if(!fs.existsSync(dir))fs.mkdirSync(dir,{recursive:true});
    fs.writeFileSync(file,JSON.stringify(data,null,2));
  } catch(e) {}
}

router.get('/', function(req,res) {
  var cached = getCache(CACHE_FILE, 5*60*1000);
  var dcCached = getCache(DC_CACHE, 2*60*1000);
  // If no cache, trigger a scan synchronously on first load (admin convenience)
  if (!cached) {
    try {
      logger.info('AD Services: auto-scanning on first page load');
      var data = adSvc.getAllServices();
      data.scannedAt = new Date().toISOString();
      saveCache(CACHE_FILE, data);
      cached = data;
    } catch(e) { logger.warn('Auto-scan failed: ' + e.message); }
  }
  if (!dcCached) {
    try {
      var dcs = adSvc.getAllDomainControllers();
      dcCached = { cachedAt: new Date().toISOString(), dcs: dcs };
      saveCache(DC_CACHE, dcCached);
    } catch(e) {}
  }
  res.render('services/index', { admin:req.session.admin, services:cached, allDCs:dcCached, page:'services', error:null });
});

router.post('/scan', function(req,res) {
  try {
    logger.info('Services scan by '+req.session.admin.username);
    var data = adSvc.getAllServices();
    data.scannedAt = new Date().toISOString();
    saveCache(CACHE_FILE, data);
    res.json({ ok:true, data });
  } catch(e) { logger.error('Services scan: '+e.message); res.json({ ok:false, error:e.message }); }
});

router.get('/dcs', function(req,res) {
  try {
    var cached = getCache(DC_CACHE, 2*60*1000);
    if (cached) return res.json({ ok:true, dcs:cached.dcs||[], fromCache:true });
    var dcs = adSvc.getAllDomainControllers();
    var data = { cachedAt:new Date().toISOString(), dcs };
    saveCache(DC_CACHE, data);
    res.json({ ok:true, dcs, fromCache:false });
  } catch(e) { res.json({ ok:false, error:e.message, dcs:[] }); }
});

router.post('/scan-dcs', function(req,res) {
  try {
    logger.info('DC scan by '+req.session.admin.username);
    var dcs = adSvc.getAllDomainControllers();
    var data = { cachedAt:new Date().toISOString(), dcs };
    saveCache(DC_CACHE, data);
    res.json({ ok:true, dcs, count:dcs.length });
  } catch(e) { res.json({ ok:false, error:e.message, dcs:[] }); }
});

// List all GPOs (fast - no Get-GPOReport)
router.get('/gpo-list', function(req,res) {
  try {
    var result = adSvc.getGPOList();
    if (result.error) return res.json({ ok:false, error: result.error, gpos: [] });
    res.json({ ok:true, gpos: result.gpos || [] });
  } catch(e) { res.json({ ok:false, error:e.message, gpos:[] }); }
});

// Detailed settings for ONE GPO (slow - Get-GPOReport)
router.get('/gpo-settings/:identifier', function(req,res) {
  try {
    var result = adSvc.getGPOSettingsDetail(decodeURIComponent(req.params.identifier));
    if (result.error) return res.json({ ok:false, error: result.error });
    res.json({ ok:true, gpo: result });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

// Export GPO report as HTML or XML
router.get('/gpo-export/:identifier/:format', function(req,res) {
  try {
    var format = req.params.format === 'html' ? 'html' : 'xml';
    var result = adSvc.getGPOReportRaw(decodeURIComponent(req.params.identifier), format);
    if (result.error) return res.status(500).send('Error: ' + result.error);
    var ext = format === 'html' ? 'html' : 'xml';
    var mime = format === 'html' ? 'text/html' : 'application/xml';
    var filename = 'gpo-report-' + decodeURIComponent(req.params.identifier).replace(/[^a-z0-9-]/gi,'_') + '.' + ext;
    res.setHeader('Content-Type', mime);
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send(result.content);
  } catch(e) { res.status(500).send('Error: ' + e.message); }
});

// Backward compat
router.get('/gpo-settings', function(req,res) {
  try {
    var settings = adSvc.getGPOSettings();
    res.json({ ok:true, gpos:settings });
  } catch(e) { res.json({ ok:false, error:e.message, gpos:[] }); }
});

router.get('/data', function(req,res) {
  var cached = getCache(CACHE_FILE, 5*60*1000);
  if (cached) return res.json({ ok:true, data:cached, fromCache:true });
  res.json({ ok:false, error:'No scan data yet.' });
});

module.exports = router;
