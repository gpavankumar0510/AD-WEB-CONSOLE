'use strict';
var fs = require('fs'), path = require('path');
var logger = require('./logger');
var DATA_FILE  = path.join(__dirname, '../data/gpo_policies.json');
var LINKS_FILE = path.join(__dirname, '../data/gpo_links.json');
function ensureDir() { var d = path.join(__dirname, '../data'); if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }
function loadP() { ensureDir(); try { if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch(e) {} return []; }
function saveP(p) { ensureDir(); fs.writeFileSync(DATA_FILE, JSON.stringify(p,null,2)); }
function loadL() { ensureDir(); try { if (fs.existsSync(LINKS_FILE)) return JSON.parse(fs.readFileSync(LINKS_FILE,'utf8')); } catch(e) {} return []; }
function saveL(l) { ensureDir(); fs.writeFileSync(LINKS_FILE, JSON.stringify(l,null,2)); }
var gpoStore = {
  getAllPolicies: function() { return loadP(); },
  getPolicy: function(id) { return loadP().find(function(p){return p.id===id;})||null; },
  createPolicy: function(data) { var p=loadP(); var pol={id:require('uuid').v4(),...data,createdAt:new Date().toISOString()}; p.push(pol); saveP(p); logger.info('GPO created: '+pol.name); return pol; },
  updatePolicy: function(id,data) { var p=loadP(); var i=p.findIndex(function(x){return x.id===id;}); if(i<0)return null; p[i]=Object.assign({},p[i],data,{updatedAt:new Date().toISOString()}); saveP(p); return p[i]; },
  deletePolicy: function(id) { var p=loadP().filter(function(x){return x.id!==id;}); saveP(p); var l=loadL().filter(function(x){return x.policyId!==id;}); saveL(l); logger.info('GPO deleted: '+id); },
  getAllLinks: function() { return loadL(); },
  createLink: function(policyId,target,targetType,enabled) { var l=loadL(); var lnk={id:require('uuid').v4(),policyId,target,targetType,enabled:enabled!==false,createdAt:new Date().toISOString()}; l.push(lnk); saveL(l); logger.info('GPO link created: '+policyId+' -> '+target); return lnk; },
  deleteLink: function(linkId) { saveL(loadL().filter(function(x){return x.id!==linkId;})); },
  getLinksForPolicy: function(policyId) { return loadL().filter(function(l){return l.policyId===policyId;}); },
  restorePolicy: function(policyData, links) {
    var p = loadP();
    // Avoid duplicate id collision
    var existing = p.find(function(x){return x.id===policyData.id;});
    if (existing) { policyData = Object.assign({}, policyData, { id: require('uuid').v4() }); }
    p.push(policyData);
    saveP(p);
    if (Array.isArray(links) && links.length) {
      var l = loadL();
      links.forEach(function(lnk) {
        l.push(Object.assign({}, lnk, { id: require('uuid').v4(), policyId: policyData.id }));
      });
      saveL(l);
    }
    logger.info('GPO restored: ' + policyData.name);
    return policyData;
  },
};
module.exports = gpoStore;
