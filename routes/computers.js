'use strict';
var express=require('express'),router=express.Router();
var ad=require('../utils/adService'),rbac=require('../utils/rbac'),recycleBin=require('../utils/recycleBin'),logger=require('../utils/logger');
var cache=require('../utils/cache');
function safeDN(o){if(!o)return '';if(typeof o.dn==='string'&&o.dn)return o.dn;if(o.dn&&o.dn.toString)return o.dn.toString();if(o.distinguishedName)return String(o.distinguishedName);return '';}
router.get('/',async function(req,res){
  try{
    var computers=await cache.wrap('ad_computers',3*60*1000,function(){return ad.getComputers();});
    var now=Date.now(),st=now-90*24*60*60*1000;
    computers.forEach(function(c){var ll=parseInt(c.lastLogon||0);c.isStale=ll===0||(new Date(ll/1e4-11644473600000).getTime()<st);c.lastLogonDate=ll>0?new Date(ll/1e4-11644473600000).toLocaleDateString('en-GB'):'Never';c.isDisabled=!!(parseInt(c.userAccountControl||0)&2);});
    res.render('computers/list',{admin:req.session.admin,computers,page:'computers',error:null});}catch(e){res.render('computers/list',{admin:req.session.admin,computers:[],page:'computers',error:e.message});}
});
async function findComp(cn){var cs=await ad.getComputers();return cs.find(function(c){return c.cn===cn;})||null;}
router.post('/:cn/disable',rbac.requirePermission('computers.disable'),async function(req,res){try{var c=await findComp(req.params.cn);if(!c)return res.json({ok:false,error:'Not found'});await ad.disableUser(safeDN(c));logger.info('Computer disabled: '+req.params.cn);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
router.post('/:cn/enable',rbac.requirePermission('computers.disable'),async function(req,res){try{var c=await findComp(req.params.cn);if(!c)return res.json({ok:false,error:'Not found'});await ad.enableUser(safeDN(c));logger.info('Computer enabled: '+req.params.cn);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
router.post('/:cn/move',rbac.requirePermission('computers.disable'),async function(req,res){try{var c=await findComp(req.params.cn);if(!c)return res.json({ok:false,error:'Not found'});await ad.moveObject(safeDN(c),req.body.targetOU);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
router.post('/:cn/delete',rbac.requirePermission('computers.delete'),async function(req,res){
  try{var c=await findComp(req.params.cn);if(!c)return res.json({ok:false,error:'Not found'});
  recycleBin.add({type:'computer',name:c.cn,displayName:c.dNSHostName||c.cn,dn:safeDN(c),os:c.operatingSystem||'',description:c.description||'',deletedBy:req.session.admin.username});
  await ad.deleteObject(safeDN(c));logger.info('Computer DELETED: '+req.params.cn);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}
});
module.exports=router;
