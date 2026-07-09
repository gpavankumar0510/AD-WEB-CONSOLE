'use strict';
var fs = require('fs');
var path = require('path');
var logger = require('./logger');

var EVENTS_FILE = path.join(__dirname, '../data/calendar_events.json');

function ensureDir() {
  var dir = path.dirname(EVENTS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function getAll() {
  ensureDir();
  try {
    if (fs.existsSync(EVENTS_FILE)) return JSON.parse(fs.readFileSync(EVENTS_FILE, 'utf8'));
  } catch(e) {}
  return [];
}

function save(list) {
  ensureDir();
  fs.writeFileSync(EVENTS_FILE, JSON.stringify(list, null, 2));
}

function addEvent(data) {
  var list = getAll();
  var entry = {
    id: require('crypto').randomBytes(6).toString('hex'),
    date: data.date,           // YYYY-MM-DD
    title: data.title,
    type: data.type || 'event', // 'event' | 'maintenance' | 'holiday'
    description: data.description || '',
    createdBy: data.createdBy || 'admin',
    createdAt: new Date().toISOString(),
  };
  list.push(entry);
  save(list);
  logger.info('Calendar event added: ' + entry.title + ' on ' + entry.date);
  return entry;
}

function updateEvent(id, updates) {
  var list = getAll();
  var idx = list.findIndex(function(e) { return e.id === id; });
  if (idx < 0) return null;
  list[idx] = Object.assign({}, list[idx], updates, { id: list[idx].id });
  save(list);
  return list[idx];
}

function removeEvent(id) {
  var list = getAll().filter(function(e) { return e.id !== id; });
  save(list);
}

function getForMonth(year, month) {
  // month is 0-indexed (JS Date convention)
  var prefix = year + '-' + String(month + 1).padStart(2, '0');
  return getAll().filter(function(e) { return e.date && e.date.indexOf(prefix) === 0; });
}

function getUpcoming(limit) {
  var now = new Date();
  var all = getAll().filter(function(e) {
    return new Date(e.date + 'T23:59:59') >= now;
  }).sort(function(a, b) { return new Date(a.date) - new Date(b.date); });
  return all.slice(0, limit || 5);
}

module.exports = { getAll, addEvent, updateEvent, removeEvent, getForMonth, getUpcoming };
