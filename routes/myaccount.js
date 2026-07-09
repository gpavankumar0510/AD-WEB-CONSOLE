'use strict';
var express=require('express'),router=express.Router();
var ad=require('../utils/adService'),gpoStore=require('../utils/gpoStore'),backupService=require('../utils/backupService'),logger=require('../utils/logger'),rbac=require('../utils/rbac');
var pwdPolicy=require('../utils/passwordPolicy');
var audit=require('../utils/auditLogger');
function safeDN(u){if(!u)return '';if(typeof u.dn==='string'&&u.dn)return u.dn;if(u.dn&&u.dn.toString)return u.dn.toString();if(u.distinguishedName)return String(u.distinguishedName);return '';}
router.get('/',rbac.requireAuth,async function(req,res){
  try{
    var user=await ad.getUser(req.session.admin.username);if(!user)return res.redirect('/login');
    var memberOf=Array.isArray(user.memberOf)?user.memberOf:(user.memberOf?[user.memberOf]:[]);
    var allLinks=gpoStore.getAllLinks(),allPolicies=gpoStore.getAllPolicies(),appliedGPOs=[];
    memberOf.forEach(function(g){var gn=g.split(',')[0].replace('CN=','').replace('cn=','');allLinks.forEach(function(l){if(l.target===gn||g.indexOf(l.target)>=0){var p=allPolicies.find(function(x){return x.id===l.policyId;});if(p&&!appliedGPOs.find(function(x){return x.id===p.id;}))appliedGPOs.push(Object.assign({},p,{linkType:l.targetType}));}});});
    var userOU=safeDN(user);userOU=userOU.indexOf(',')>=0?userOU.split(',').slice(1).join(','):'';
    allLinks.forEach(function(l){if(l.targetType==='OU'&&userOU.indexOf(l.target)>=0){var p=allPolicies.find(function(x){return x.id===l.policyId;});if(p&&!appliedGPOs.find(function(x){return x.id===p.id;}))appliedGPOs.push(Object.assign({},p,{linkType:'OU'}));}});
    var bh=backupService.getHistory(),lastBackup=bh.find(function(b){return b.status==='completed';})||bh[0]||null;
    res.render('myaccount/index',{admin:req.session.admin,user,memberOf,appliedGPOs,lastBackup,mfaStatus:require('../utils/mfa').isMFAEnabled(req.session.admin.username),page:'myaccount',error:req.query.error||null,success:req.query.success||null});
  }catch(e){logger.error('MyAccount: '+e.message);res.render('myaccount/index',{admin:req.session.admin,user:null,memberOf:[],appliedGPOs:[],lastBackup:null,mfaStatus:false,page:'myaccount',error:e.message,success:null});}
});
router.post('/update',rbac.requireAuth,async function(req,res){
  try{var user=await ad.getUser(req.session.admin.username);if(!user)return res.redirect('/myaccount');var changes={};['telephoneNumber','title','department'].forEach(function(f){if(req.body[f]!==undefined&&String(req.body[f]).trim()!=='')changes[f]=String(req.body[f]).trim();});if(Object.keys(changes).length>0)await ad.modifyUser(safeDN(user),changes);res.redirect('/myaccount?success=Profile updated successfully');}
  catch(e){res.redirect('/myaccount?error='+encodeURIComponent(e.message));}
});
router.post('/change-password',rbac.requireAuth,async function(req,res){
  try{
    var np=req.body.newPassword||'',cp=req.body.confirmPassword||'';
    if(np!==cp)return res.redirect('/myaccount?error='+encodeURIComponent('Passwords do not match'));
    var user=await ad.getUser(req.session.admin.username);if(!user)return res.redirect('/login');
    var check=pwdPolicy.checkComplexity(np, req.session.admin.username, user.displayName||'');
    if(!check.valid)return res.redirect('/myaccount?error='+encodeURIComponent('Password policy: '+check.errors.join('; ')));
    await ad.resetPassword(safeDN(user),np);
    logger.info('Self password change: '+req.session.admin.username);
    audit.log('PASSWORD_SELF_CHANGE',req.session.admin.username,req.session.admin.username,'',req.ip);
    req.session.destroy(function(){res.redirect('/login?msg=password_changed');});
  }
  catch(e){var msg=e.message;if(msg.indexOf('constraint')>=0||msg.indexOf('Constraint')>=0)msg='Password does not meet domain complexity requirements';res.redirect('/myaccount?error='+encodeURIComponent(msg));}
});
module.exports=router;
