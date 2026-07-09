'use strict';
var express=require('express'),router=express.Router();
var ad=require('../utils/adService'),rbac=require('../utils/rbac'),recycleBin=require('../utils/recycleBin'),logger=require('../utils/logger');
router.get('/',async function(req,res){try{var ous=await ad.getOUs();var users=await ad.getUsers().catch(function(){return[];});res.render('ous/list',{admin:req.session.admin,ous,users,page:'ous',error:null,success:req.query.success||null});}catch(e){res.render('ous/list',{admin:req.session.admin,ous:[],users:[],page:'ous',error:e.message,success:null});}});
router.post('/create',rbac.requirePermission('users.create'),async function(req,res){
  try{var cfg=require('../utils/autoDetect').getSettings();var parent=req.body.parent&&req.body.parent.trim()?req.body.parent.trim():cfg.baseDN;var dn=await ad.createOU({name:req.body.name,parent,description:req.body.description||''});logger.info('OU created: '+dn);res.json({ok:true,dn});}
  catch(e){logger.error('Create OU: '+e.message);res.json({ok:false,error:e.message});}
});
router.post('/delete',rbac.requirePermission('users.delete'),async function(req,res){
  try{var dn=req.body.dn;if(!dn)return res.json({ok:false,error:'DN required'});var ouName=dn.split(',')[0].replace('OU=','').replace('ou=','');recycleBin.add({type:'ou',name:ouName,displayName:ouName,dn,description:req.body.description||'',deletedBy:req.session.admin.username});await ad.deleteObject(dn);logger.info('OU DELETED: '+dn);res.json({ok:true});}
  catch(e){logger.error('Delete OU: '+e.message);res.json({ok:false,error:e.message});}
});
router.post('/move',rbac.requirePermission('users.edit'),async function(req,res){try{await ad.moveObject(req.body.objectDn,req.body.targetOU);logger.info('Object moved: '+req.body.objectDn);res.json({ok:true});}catch(e){res.json({ok:false,error:e.message});}});
module.exports=router;
