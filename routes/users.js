'use strict';
var express = require('express');
var cache   = require('../utils/cache');
var router  = express.Router();
var ad      = require('../utils/adService');
var rbac    = require('../utils/rbac');
var recycleBin = require('../utils/recycleBin');
var logger  = require('../utils/logger');
var audit   = require('../utils/auditLogger');
var notifier = require('../utils/emailNotifier');
var pwdPolicy = require('../utils/passwordPolicy');

function safeDN(u){if(!u)return '';if(typeof u.dn==='string'&&u.dn)return u.dn;if(u.dn&&u.dn.toString)return u.dn.toString();if(u.distinguishedName)return String(u.distinguishedName);return '';}

router.get('/',async function(req,res){
  try{
    var users = await cache.wrap('ad_users', 2*60*1000, function(){ return ad.getUsers(); });
    res.render('users/list',{admin:req.session.admin,users,page:'users',search:req.query.q||'',created:req.query.created||null,error:null});
  } catch(e){res.render('users/list',{admin:req.session.admin,users:[],page:'users',search:'',created:null,error:e.message});}
});
router.get('/locked',async function(req,res){
  try{var users=await ad.getLockedUsers();res.render('users/locked',{admin:req.session.admin,users,page:'users',error:null});}
  catch(e){res.render('users/locked',{admin:req.session.admin,users:[],page:'users',error:e.message});}
});
router.get('/create',rbac.requirePermission('users.create'),async function(req,res){
  var ous=await ad.getOUs().catch(function(){return[];});
  res.render('users/create',{admin:req.session.admin,ous,page:'users',error:null,success:null});
});
router.post('/create',rbac.requirePermission('users.create'),async function(req,res){
  try{
    var check = pwdPolicy.checkComplexity(req.body.password, req.body.username, (req.body.firstName||'')+' '+(req.body.lastName||''));
    if (!check.valid) {
      var ous0 = await ad.getOUs().catch(function(){return[];});
      return res.render('users/create',{admin:req.session.admin,ous:ous0,page:'users',error:'Password policy: '+check.errors.join('; '),success:null});
    }
    await ad.createUser(req.body);
    logger.info('User created: '+req.body.username+' by '+req.session.admin.username);
    cache.invalidate('ad_users'); audit.log('USER_CREATED',req.session.admin.username,req.body.username,'New user account created',req.ip);
    res.redirect('/users?created=1');
  }
  catch(e){
    logger.error('Create user: '+e.message);
    audit.log('USER_CREATE_FAILED',req.session.admin.username,req.body.username,e.message,req.ip);
    notifier.alertFailedOp('Create User: '+req.body.username,req.session.admin.username,e.message).catch(function(){});
    var ous=await ad.getOUs().catch(function(){return[];});
    res.render('users/create',{admin:req.session.admin,ous,page:'users',error:e.message,success:null});
  }
});
router.get('/:username',async function(req,res){
  try{
    var user=await ad.getUser(req.params.username);if(!user)return res.redirect('/users');
    var dn=safeDN(user),userOU=dn.indexOf(',')>=0?dn.split(',').slice(1).join(','):'';
    var groups=await ad.getGroups().catch(function(){return[];});
    var ous=await ad.getOUs().catch(function(){return[];});
    res.render('users/detail',{admin:req.session.admin,user,groups,ous,userOU,page:'users',error:req.query.error||null,success:req.query.success||null});
  }catch(e){logger.error('User detail: '+e.message);res.redirect('/users?error='+encodeURIComponent(e.message));}
});
router.post('/:username/edit',rbac.requirePermission('users.edit'),async function(req,res){
  try{
    var user=await ad.getUser(req.params.username);if(!user)return res.redirect('/users');
    var changes={};['displayName','mail','telephoneNumber','department','title','description'].forEach(function(f){if(req.body[f]!==undefined&&String(req.body[f]).trim()!=='')changes[f]=String(req.body[f]).trim();});
    if(Object.keys(changes).length===0)return res.redirect('/users/'+req.params.username+'?success=No changes');
    await ad.modifyUser(safeDN(user),changes);
    logger.info('User modified: '+req.params.username+' by '+req.session.admin.username);
    cache.invalidate('ad_users'); audit.log('USER_MODIFIED',req.session.admin.username,req.params.username,JSON.stringify(changes),req.ip);
    res.redirect('/users/'+req.params.username+'?success=User updated successfully');
  }catch(e){res.redirect('/users/'+req.params.username+'?error='+encodeURIComponent(e.message));}
});
router.post('/:username/reset-password',rbac.requirePermission('users.resetPassword'),async function(req,res){
  try{
    var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'User not found'});
    var pw=req.body.password||'';
    var check=pwdPolicy.checkComplexity(pw, req.params.username, user.displayName||'');
    if(!check.valid) return res.json({ok:false,error:'Password policy: '+check.errors.join('; ')});
    await ad.resetPassword(safeDN(user),pw);logger.info('Password reset: '+req.params.username+' by '+req.session.admin.username);audit.log('PASSWORD_RESET',req.session.admin.username,req.params.username,'Password reset by admin',req.ip);res.json({ok:true,message:'Password reset successfully.'});}
  catch(e){audit.log('PASSWORD_RESET_FAILED',req.session.admin.username,req.params.username,e.message,req.ip);res.json({ok:false,error:e.message});}
});
router.post('/:username/unlock',rbac.requirePermission('users.unlock'),async function(req,res){
  try{var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'User not found'});await ad.unlockUser(safeDN(user));logger.info('User unlocked: '+req.params.username+' by '+req.session.admin.username);audit.log('USER_UNLOCKED',req.session.admin.username,req.params.username,'Account unlocked',req.ip);res.json({ok:true,message:'Account unlocked.'});}
  catch(e){res.json({ok:false,error:e.message});}
});
router.post('/:username/toggle-status',rbac.requirePermission('users.disable'),async function(req,res){
  try{var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'Not found'});var disabled=parseInt(user.userAccountControl||'0')&2;if(disabled)await ad.enableUser(safeDN(user));else await ad.disableUser(safeDN(user));logger.info('User '+(disabled?'enabled':'disabled')+': '+req.params.username+' by '+req.session.admin.username);audit.log(disabled?'USER_ENABLED':'USER_DISABLED',req.session.admin.username,req.params.username,'',req.ip);res.json({ok:true,newStatus:disabled?'enabled':'disabled'});}
  catch(e){res.json({ok:false,error:e.message});}
});
router.post('/:username/add-group',rbac.requirePermission('users.manageGroups'),async function(req,res){
  try{var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'Not found'});await ad.addToGroup(safeDN(user),req.body.groupDn);audit.log('USER_GROUP_ADD',req.session.admin.username,req.params.username,'Added to '+req.body.groupDn,req.ip);res.json({ok:true});}
  catch(e){res.json({ok:false,error:e.message});}
});
router.post('/:username/move',rbac.requirePermission('users.edit'),async function(req,res){
  try{var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'Not found'});await ad.moveObject(safeDN(user),req.body.targetOU);logger.info('User moved: '+req.params.username);audit.log('USER_MOVED',req.session.admin.username,req.params.username,'Moved to '+req.body.targetOU,req.ip);res.json({ok:true});}
  catch(e){res.json({ok:false,error:e.message});}
});
router.post('/:username/delete',rbac.requirePermission('users.delete'),async function(req,res){
  try{
    var user=await ad.getUser(req.params.username);if(!user)return res.json({ok:false,error:'Not found'});
    recycleBin.add({type:'user',name:user.sAMAccountName,displayName:user.displayName||user.sAMAccountName,dn:safeDN(user),mail:user.mail||'',department:user.department||'',title:user.title||'',memberOf:user.memberOf||[],deletedBy:req.session.admin.username});
    await ad.deleteObject(safeDN(user));
    logger.info('User DELETED: '+req.params.username+' by '+req.session.admin.username);
    cache.invalidate('ad_users'); audit.log('USER_DELETED',req.session.admin.username,req.params.username,'Moved to recycle bin',req.ip);
    notifier.alertDeletion('User',req.params.username,req.session.admin.username).catch(function(){});
    res.json({ok:true});
  }catch(e){logger.error('Delete user: '+e.message);res.json({ok:false,error:e.message});}
});

// ── Bulk User Import ──────────────────────────────────────────────────────
router.get('/bulk-import', rbac.requirePermission('users.create'), async function(req, res) {
  var ous = await ad.getOUs().catch(function() { return []; });
  res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: null, results: null });
});

router.post('/bulk-import', rbac.requirePermission('users.create'), async function(req, res) {
  var ous = await ad.getOUs().catch(function() { return []; });
  try {
    var csvRaw = (req.body.csvData || '').trim();
    if (!csvRaw) return res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: 'No CSV data provided.', results: null });

    var lines = csvRaw.split(/\r?\n/).filter(function(l) { return l.trim(); });
    if (lines.length < 2) return res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: 'CSV must have a header row and at least one data row.', results: null });

    var delim = lines[0].indexOf(';') > lines[0].indexOf(',') ? ';' : ',';
    var headers = lines[0].split(delim).map(function(h) { return h.trim().toLowerCase().replace(/['"]/g, ''); });

    var missing = ['username','password'].filter(function(r2) { return headers.indexOf(r2) < 0; });
    if (missing.length) return res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: 'Missing required columns: ' + missing.join(', '), results: null });

    var results = [];
    var defaultOU = req.body.targetOU || (ous.length ? ous[0].dn : null);

    for (var i = 1; i < lines.length; i++) {
      var cols = lines[i].split(delim).map(function(c) { return c.trim().replace(/^["']|["']$/g, ''); });
      var row = {};
      headers.forEach(function(h, idx) { row[h] = cols[idx] || ''; });

      var username = row['username'] || row['sam'] || '';
      var password = row['password'] || row['pass'] || '';
      var firstName = row['firstname'] || row['first'] || row['givenname'] || '';
      var lastName  = row['lastname']  || row['last']  || row['sn'] || '';
      var email     = row['email'] || row['mail'] || '';
      var department = row['department'] || row['dept'] || '';
      var title     = row['title'] || '';
      var rowOU     = row['ou'] || row['path'] || defaultOU || '';

      if (!username || !password) { results.push({ username: username||'(blank)', status: 'skipped', error: 'Username and password required' }); continue; }

      try {
        await ad.createUser({ username, password, firstName: firstName||username, lastName, displayName: (firstName+' '+lastName).trim()||username, email, department, title, ou: rowOU, enabled: true });
        cache.invalidate('ad_users');
        require('../utils/auditLogger').log('USER_CREATED', req.session.admin.username, username, 'bulk-import', req.ip);
        results.push({ username, status: 'created', error: null });
      } catch(e) {
        results.push({ username, status: 'failed', error: e.message });
      }
    }
    res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: null, results: results });
  } catch(e) {
    res.render('users/bulk-import', { admin: req.session.admin, page: 'users', ous: ous, error: 'Import error: ' + e.message, results: null });
  }
});


// ── Bulk User Export ──────────────────────────────────────────────────────
router.get('/bulk-export', rbac.requirePermission('users.view'), async function(req, res) {
  try {
    var users = await ad.getUsers();
    var format = req.query.format || 'csv';

    // Build CSV
    var headers = ['Username','DisplayName','Email','Department','Title','Enabled','PasswordNeverExpires','LastLogon','WhenCreated','DistinguishedName'];
    var rows = users.map(function(u) {
      var ll = parseInt(u.lastLogon || 0);
      var lastLogon = ll > 0 ? new Date(ll/1e4 - 11644473600000).toISOString().slice(0,10) : 'Never';
      var uac = parseInt(u.userAccountControl || 0);
      return [
        u.sAMAccountName || '',
        u.displayName || '',
        u.mail || '',
        u.department || '',
        u.title || '',
        (uac & 2) ? 'false' : 'true',
        (uac & 0x10000) ? 'true' : 'false',
        lastLogon,
        u.whenCreated ? u.whenCreated.toString().slice(0,10) : '',
        u.dn || '',
      ].map(function(v) {
        var s = String(v || '');
        if (/[",\n]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
        return s;
      }).join(',');
    });

    var csv = headers.join(',') + '\n' + rows.join('\n');
    var filename = 'users-export-' + new Date().toISOString().slice(0,10) + '.csv';
    require('../utils/auditLogger').log('USER_EXPORT', req.session.admin.username, users.length + ' users', '', req.ip);
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="' + filename + '"');
    res.send(csv);
  } catch(e) {
    logger.error('User export: ' + e.message);
    res.status(500).send('Export failed: ' + e.message);
  }
});

module.exports=router;
