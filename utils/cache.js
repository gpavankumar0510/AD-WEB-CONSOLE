'use strict';
// Simple in-memory + disk cache for AD data that doesn't change second-by-second.
// The goal is to serve stale data instantly while refreshing in the background,
// rather than making the user wait for PowerShell/LDAP on every page load.
var fs   = require('fs');
var path = require('path');
var logger = require('./logger');

var MEM = {}; // in-memory: key -> { ts, data }
var CACHE_DIR = path.join(__dirname, '../data/cache');

function ensureDir() {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function memGet(key, ttlMs) {
  var e = MEM[key];
  if (e && (Date.now() - e.ts) < ttlMs) return e.data;
  return null;
}

function memSet(key, data) {
  MEM[key] = { ts: Date.now(), data: data };
}

function diskGet(key, ttlMs) {
  try {
    var f = path.join(CACHE_DIR, key.replace(/[^a-z0-9_]/gi, '_') + '.json');
    if (!fs.existsSync(f)) return null;
    var c = JSON.parse(fs.readFileSync(f, 'utf8'));
    if (c.ts && (Date.now() - c.ts) < ttlMs) return c.data;
  } catch(e) {}
  return null;
}

function diskSet(key, data) {
  try {
    ensureDir();
    var f = path.join(CACHE_DIR, key.replace(/[^a-z0-9_]/gi, '_') + '.json');
    fs.writeFileSync(f, JSON.stringify({ ts: Date.now(), data: data }));
  } catch(e) {}
}

// Get from memory first (fastest), then disk (survives restarts), then null
function get(key, ttlMs) {
  var m = memGet(key, ttlMs);
  if (m !== null) return m;
  var d = diskGet(key, ttlMs);
  if (d !== null) { memSet(key, d); return d; } // warm memory cache from disk
  return null;
}

// Set in both memory and disk
function set(key, data) {
  memSet(key, data);
  diskSet(key, data);
}

// Invalidate a key
function invalidate(key) {
  delete MEM[key];
  try {
    var f = path.join(CACHE_DIR, key.replace(/[^a-z0-9_]/gi, '_') + '.json');
    if (fs.existsSync(f)) fs.unlinkSync(f);
  } catch(e) {}
}

// Wrap an async fetcher with cache - returns stale data immediately if available,
// then refreshes in background. If no cached data exists, waits for fresh data.
function wrap(key, ttlMs, fetcher) {
  var cached = get(key, ttlMs);
  if (cached !== null) {
    // Serve from cache, refresh in background if older than half TTL
    var age = Date.now() - (MEM[key] ? MEM[key].ts : 0);
    if (age > ttlMs / 2) {
      setImmediate(function() {
        Promise.resolve(fetcher()).then(function(fresh) {
          set(key, fresh);
        }).catch(function(e) {
          logger.warn('Cache background refresh [' + key + ']: ' + e.message);
        });
      });
    }
    return Promise.resolve(cached);
  }
  // No cache - fetch and store
  return Promise.resolve(fetcher()).then(function(fresh) {
    set(key, fresh);
    return fresh;
  });
}

module.exports = { get, set, invalidate, wrap, memGet, memSet };
