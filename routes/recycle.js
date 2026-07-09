'use strict';
var express    = require('express');
var router     = express.Router();
var recycleBin = require('../utils/recycleBin');
var ad         = require('../utils/adService');
var rbac       = require('../utils/rbac');
var logger     = require('../utils/logger');

router.get('/', function(req, res) {
  var items = recycleBin.getAll();
  res.render('recycle/index', { admin: req.session.admin, items: items, page: 'recycle', error: req.query.error || null, success: req.query.success || null });
});

router.post('/:id/restore', rbac.requirePermission('users.create'), async function(req, res) {
  var item = recycleBin.getById(req.params.id);
  if (!item) return res.json({ ok: false, error: 'Item not found in recycle bin' });

  try {
    var cfg = require('../utils/autoDetect').getSettings();

    if (item.type === 'user') {
      var dnParts = (item.dn || '').split(',');
      var ouDn = cfg.usersOU || ('CN=Users,' + cfg.baseDN);
      for (var di = 1; di < dnParts.length; di++) {
        if (dnParts[di].indexOf('OU=') === 0 || (dnParts[di].indexOf('CN=') === 0 && di > 1)) {
          ouDn = dnParts.slice(di).join(','); break;
        }
      }
      var displayName = item.displayName || item.name || 'Restored User';
      var nameParts   = displayName.split(' ');
      var firstName   = nameParts[0] || item.name;
      var lastName    = nameParts.slice(1).join(' ') || 'User';
      var rand        = Math.random().toString(36).slice(2, 6).toUpperCase();
      var tempPw      = 'TmpRst' + rand + '@9!';

      await ad.createUser({
        username: item.name, firstName: firstName, lastName: lastName,
        displayName: displayName, email: item.mail || '',
        department: item.department || '', title: item.title || '',
        password: tempPw, ou: ouDn,
      });

      var groupsRestored = 0;
      if (item.memberOf && item.memberOf.length) {
        var restoredUser = await ad.getUser(item.name).catch(function() { return null; });
        if (restoredUser) {
          var udn = typeof restoredUser.dn === 'string' ? restoredUser.dn : restoredUser.dn.toString();
          for (var i = 0; i < item.memberOf.length; i++) {
            try { await ad.addToGroup(udn, item.memberOf[i]); groupsRestored++; } catch(e) {}
          }
        }
      }

      recycleBin.remove(req.params.id);
      logger.info('User RESTORED: ' + item.name + ' by ' + req.session.admin.username);
      res.json({ ok: true, message: 'User "' + item.name + '" restored.\n\nTemporary password: ' + tempPw + '\n\nGroups restored: ' + groupsRestored + '/' + (item.memberOf || []).length });

    } else if (item.type === 'group') {
      var grpParts = (item.dn || '').split(',');
      var grpOU    = grpParts.slice(1).join(',') || ('CN=Users,' + cfg.baseDN);
      await ad.createGroup({ name: item.name, samName: item.name, displayName: item.displayName || item.name, description: item.description || '', ou: grpOU, groupType: '-2147483646' });
      var membersRestored = 0;
      if (item.members && item.members.length) {
        var rg = await ad.getGroup(item.name).catch(function() { return null; });
        if (rg) {
          var gdn = typeof rg.dn === 'string' ? rg.dn : rg.dn.toString();
          for (var mi = 0; mi < item.members.length; mi++) {
            try { await ad.addToGroup(item.members[mi], gdn); membersRestored++; } catch(e) {}
          }
        }
      }
      recycleBin.remove(req.params.id);
      logger.info('Group RESTORED: ' + item.name + ' by ' + req.session.admin.username);
      res.json({ ok: true, message: 'Group "' + item.name + '" restored with ' + membersRestored + ' member(s).' });

    } else if (item.type === 'ou') {
      var ouParts  = (item.dn || '').split(',');
      var ouParent = ouParts.slice(1).join(',') || cfg.baseDN;
      // Pass empty description as undefined to avoid Invalid Attribute Syntax
      await ad.createOU({ name: item.name, parent: ouParent, description: item.description || undefined });
      recycleBin.remove(req.params.id);
      logger.info('OU RESTORED: ' + item.name + ' by ' + req.session.admin.username);
      res.json({ ok: true, message: 'OU "' + item.name + '" restored.' });

    } else if (item.type === 'computer') {
      res.json({ ok: false, error: 'Computer accounts cannot be auto-restored. The computer must rejoin the domain.' });

    } else if (item.type === 'gpo') {
      var gpoStore = require('../utils/gpoStore');
      var restored = gpoStore.restorePolicy(item.policyData, item.links || []);
      recycleBin.remove(req.params.id);
      logger.info('GPO RESTORED: ' + item.name + ' by ' + req.session.admin.username);
      res.json({ ok: true, message: 'GPO policy "' + item.name + '" restored to console.' + ((item.links||[]).length ? ' ' + item.links.length + ' link(s) restored. Re-link to AD if needed via the GPO page.' : '') });

    } else {
      res.json({ ok: false, error: 'Restore not supported for type: ' + item.type });
    }

  } catch(e) {
    logger.error('Restore error: ' + e.message);
    var msg = e.message;
    if (msg.indexOf('Unwilling') >= 0 || msg.indexOf('unwilling') >= 0)
      msg = 'Cannot set password on plain LDAP. Add AD_HOST=ldaps://127.0.0.1 to .env, or install AD CS for LDAPS support.';
    if (msg.indexOf('Already Exists') >= 0 || msg.indexOf('code 68') >= 0)
      msg = 'Object "' + item.name + '" already exists in AD.';
    if (msg.indexOf('Invalid Attribute') >= 0)
      msg = 'Invalid attribute — the object name may contain special characters.';
    res.json({ ok: false, error: msg });
  }
});

router.post('/:id/purge', rbac.requirePermission('users.delete'), function(req, res) {
  var item = recycleBin.getById(req.params.id);
  if (!item) return res.json({ ok: false, error: 'Not found' });
  recycleBin.remove(req.params.id);
  logger.info('Purged from bin: ' + item.name + ' by ' + req.session.admin.username);
  res.json({ ok: true });
});

router.post('/empty', rbac.requirePermission('users.delete'), function(req, res) {
  var items = recycleBin.getAll();
  items.forEach(function(i) { recycleBin.remove(i.id); });
  logger.info('Recycle bin emptied by ' + req.session.admin.username);
  res.json({ ok: true, count: items.length });
});

module.exports = router;
