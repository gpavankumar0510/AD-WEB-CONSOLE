'use strict';
var fs = require('fs'), path = require('path');
var logger = require('./logger');
var BIN_FILE = path.join(__dirname, '../data/recycle_bin.json');
function ensureDir() { var d = path.dirname(BIN_FILE); if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); }
function load() { ensureDir(); try { if (fs.existsSync(BIN_FILE)) return JSON.parse(fs.readFileSync(BIN_FILE, 'utf8')); } catch(e) {} return []; }
function save(items) { ensureDir(); fs.writeFileSync(BIN_FILE, JSON.stringify(items, null, 2)); }
var recycleBin = {
  getAll: function() { return load(); },
  add: function(item) {
    var items = load();
    var entry = Object.assign({}, item, { id: require('uuid').v4(), deletedAt: new Date().toISOString(), expiresAt: new Date(Date.now()+30*24*60*60*1000).toISOString() });
    items.unshift(entry); save(items); logger.info('Recycle bin: added '+item.type+' "'+item.name+'"'); return entry;
  },
  remove: function(id) { save(load().filter(function(i) { return i.id !== id; })); },
  getById: function(id) { return load().find(function(i) { return i.id === id; }) || null; },
  cleanup: function() { var now = Date.now(); save(load().filter(function(i) { return new Date(i.expiresAt).getTime() > now; })); },
};
module.exports = recycleBin;
