'use strict';
var express=require('express'),router=express.Router();
var ad=require('../utils/adService'),rbac=require('../utils/rbac'),recycleBin=require('../utils/recycleBin'),logger=require('../utils/logger');
var cache=require('../utils/cache');
var audit=require('../utils/auditLogger'),notifier=require('../utils/emailNotifier');
function safeDN(o){if(!o)return '';if(typeof o.dn==='string'&&o.dn)return o.dn;if(o.dn&&o.dn.toString)return o.dn.toString();if(o.distinguishedName)return String(o.distinguishedName);return '';}

router.get('/',async function(req,res){try{var groups=await cache.wrap('ad_groups',2*60*1000,function(){return ad.getGroups();});res.render('groups/list',{admin:req.session.admin,groups,page:'groups',error:null,created:req.query.created||null});}catch(e){res.render('groups/list',{admin:req.session.admin,groups:[],page:'groups',error:e.message,created:null});}});
router.get('/create',rbac.requirePermission('users.create'),async function(req,res){var ous=await ad.getOUs().catch(function(){return[];});res.render('groups/create',{admin:req.session.admin,ous,page:'groups',error:null});});
router.post('/create',rbac.requirePermission('users.create'),async function(req,res){
  try{
    await ad.createGroup(req.body);
    logger.info('Group created: '+req.body.name+' by '+req.session.admin.username);
    cache.invalidate('ad_groups'); audit.log('GROUP_CREATED',req.session.admin.username,req.body.name,'New group created',req.ip);
    res.redirect('/groups?created=1');
  }catch(e){
    logger.error('Create group: '+e.message);
    audit.log('GROUP_CREATE_FAILED',req.session.admin.username,req.body.name,e.message,req.ip);
    notifier.alertFailedOp('Create Group: '+req.body.name,req.session.admin.username,e.message).catch(function(){});
    var ous=await ad.getOUs().catch(function(){return[];});
    res.render('groups/create',{admin:req.session.admin,ous,page:'groups',error:e.message});
  }
});
router.get('/:groupName',async function(req,res){try{var group=await ad.getGroup(req.params.groupName);if(!group)return res.redirect('/groups');var members=Array.isArray(group.member)?group.member:(group.member?[group.member]:[]);var allUsers=await ad.getUsers().catch(function(){return[];});var ous=await ad.getOUs().catch(function(){return[];});res.render('groups/detail',{admin:req.session.admin,group,members,allUsers,ous,page:'groups',error:req.query.error||null,success:req.query.success||null});}catch(e){res.redirect('/groups?error='+encodeURIComponent(e.message));}});
router.post('/:groupName/edit',rbac.requirePermission('users.edit'),async function(req,res){try{var group=await ad.getGroup(req.params.groupName);if(!group)return res.redirect('/groups');var changes={};if(req.body.description!==undefined&&req.body.description.trim())changes.description=req.body.description.trim();if(req.body.displayName&&req.body.displayName.trim())changes.displayName=req.body.displayName.trim();if(Object.keys(changes).length>0)await ad.modifyUser(safeDN(group),changes);audit.log('GROUP_MODIFIED',req.session.admin.username,req.params.groupName,JSON.stringify(changes),req.ip);res.redirect('/groups/'+req.params.groupName+'?success=Group updated');}catch(e){res.redirect('/groups/'+req.params.groupName+'?error='+encodeURIComponent(e.message));}});
router.post('/:groupName/add-member',rbac.requirePermission('users.manageGroups'),async function(req,res){try{var group=await ad.getGroup(req.params.groupName);if(!group)return res.json({ok:false,error:'Not found'});await ad.addToGroup(req.body.memberDn,safeDN(group));logger.info('Member added to '+req.params.groupName);audit.log('GROUP_MEMBER_ADDED',req.session.admin.username,req.params.groupName,req.body.memberDn,req.ip);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
router.post('/:groupName/remove-member',rbac.requirePermission('users.manageGroups'),async function(req,res){try{var group=await ad.getGroup(req.params.groupName);if(!group)return res.json({ok:false,error:'Not found'});await ad.removeFromGroup(req.body.memberDn,safeDN(group));logger.info('Member removed from '+req.params.groupName);audit.log('GROUP_MEMBER_REMOVED',req.session.admin.username,req.params.groupName,req.body.memberDn,req.ip);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
router.post('/:groupName/delete',rbac.requirePermission('users.delete'),async function(req,res){
  try{
    var group=await ad.getGroup(req.params.groupName);if(!group)return res.json({ok:false,error:'Not found'});
    var members=Array.isArray(group.member)?group.member:(group.member?[group.member]:[]);
    recycleBin.add({type:'group',name:group.sAMAccountName||group.cn,displayName:group.displayName||group.sAMAccountName,dn:safeDN(group),description:group.description||'',members,deletedBy:req.session.admin.username});
    await ad.deleteObject(safeDN(group));
    logger.info('Group DELETED: '+req.params.groupName+' by '+req.session.admin.username);
    cache.invalidate('ad_groups'); audit.log('GROUP_DELETED',req.session.admin.username,req.params.groupName,'Moved to recycle bin',req.ip);
    notifier.alertDeletion('Group',req.params.groupName,req.session.admin.username).catch(function(){});
    res.json({ok:true});
  }catch(e){res.json({ok:false,error:e.message});}
});
module.exports=router;
