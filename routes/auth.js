'use strict';
var express=require('express'),router=express.Router();
var rateLimit=require('express-rate-limit');
var adService=require('../utils/adService'),logger=require('../utils/logger');
var audit=require('../utils/auditLogger');
var notifier=require('../utils/emailNotifier');
var mfa=require('../utils/mfa');
var settings=require('../utils/settings');
var bruteForce=require('../utils/bruteForce');
var loginLimiter=rateLimit({windowMs:15*60*1000,max:20});

router.get('/login',function(req,res){
  if(req.session.admin)return res.redirect('/dashboard');
  var cfg=require('../utils/autoDetect').getSettings();
  var msg=req.query.msg||null,info=null;
  if(msg==='password_changed')info='Password changed. Please log in with your new password.';
  if(msg==='session_expired')info='Your session expired due to inactivity. Please log in again.';
  if(msg==='mfa_disabled')info='MFA has been disabled for your account.';
  res.render('login',{error:null,info,domain:cfg.domain||'domain.local'});
});

router.post('/login',loginLimiter,async function(req,res){
  var username=(req.body.username||'').trim(),password=req.body.password||'';
  var cfg=require('../utils/autoDetect').getSettings();

  // Check IP ban from repeated failures
  if(bruteForce.isBanned(req.ip)){
    var ban=bruteForce.getBanInfo(req.ip);
    var mins=ban?Math.ceil(ban.remainingMs/60000):30;
    logger.warn('Blocked login attempt from banned IP: '+req.ip);
    audit.log('LOGIN_BLOCKED','(unauthenticated)',username,'IP banned for '+mins+' more minute(s)',req.ip);
    return res.render('login',{error:'Too many failed attempts. Try again in '+mins+' minute(s).',info:null,domain:cfg.domain});
  }

  if(!username||!password)return res.render('login',{error:'Enter your username and password.',info:null,domain:cfg.domain});
  try{
    var admin=await adService.authenticateAdmin(username,password);
    if(!admin){
      logger.warn('Failed login: '+username+' from '+req.ip);
      audit.log('LOGIN_FAILED','(unauthenticated)',username,'Invalid credentials',req.ip);
      var bf=bruteForce.recordFailure(req.ip);
      if(bf.bannedUntil>Date.now()){
        notifier.alertSecurityEvent('IP banned after repeated failures', 'IP: '+req.ip+' banned for 30 minutes after '+bf.attempts.length+' failed attempts.').catch(function(){});
        audit.log('IP_BANNED','(unauthenticated)',req.ip,'Too many failed login attempts',req.ip);
      } else {
        notifier.alertSecurityEvent('Failed login attempt', 'Username: '+username+' from IP: '+req.ip).catch(function(){});
      }
      return res.render('login',{error:'Invalid username or password.',info:null,domain:cfg.domain});
    }
    bruteForce.recordSuccess(req.ip);

    var samName = admin.username || admin.sAMAccountName;

    // Check if MFA is required
    var s = settings.get();
    var mfaRequired = s.mfaEnabled && (s.mfaEnforced ? admin.role === 'admin' : true);
    var userHasMFA = mfa.isMFAEnabled(samName);

    if (mfaRequired && userHasMFA) {
      // Stash pending login, require MFA code
      req.session.pendingAuth = {
        username: samName, displayName: admin.displayName||username,
        dn: String(admin.dn||''), mail: admin.mail||'', memberOf: admin.memberOf||[],
        department: admin.department||'', title: admin.title||'',
        role: admin.role, isLocal: admin.isLocal||false,
      };
      return res.redirect('/mfa-verify');
    }

    // No MFA required or not yet set up - proceed
    req.session.admin={username:samName,displayName:admin.displayName||username,dn:String(admin.dn||''),mail:admin.mail||'',memberOf:admin.memberOf||[],department:admin.department||'',title:admin.title||'',role:admin.role,isLocal:admin.isLocal||false,loginAt:Date.now()};
    req.session.lastActivity=Date.now();
    logger.info('Login ['+admin.role+']: '+req.session.admin.username+' from '+req.ip);
    audit.log('LOGIN_SUCCESS',req.session.admin.username,req.session.admin.username,'role='+admin.role,req.ip);

    // If MFA enforced but user hasn't set it up yet, redirect to setup
    if (mfaRequired && !userHasMFA) {
      return res.redirect('/mfa-setup?required=1');
    }

    return res.redirect(admin.role==='admin'?'/dashboard':'/myaccount');
  }catch(e){logger.error('Login error: '+e.message);return res.render('login',{error:'Auth error: '+e.message,info:null,domain:cfg.domain});}
});

// MFA verification step
router.get('/mfa-verify',function(req,res){
  if(!req.session.pendingAuth)return res.redirect('/login');
  res.render('mfa-verify',{error:null,username:req.session.pendingAuth.username});
});

router.post('/mfa-verify',loginLimiter,function(req,res){
  if(!req.session.pendingAuth)return res.redirect('/login');
  var pending=req.session.pendingAuth;
  var token=(req.body.token||'').trim();
  var userMfa=mfa.getUserMFA(pending.username);

  var valid=false;
  if(userMfa && userMfa.enabled){
    valid = mfa.verifyTOTP(userMfa.secret, token);
    if(!valid && /^[A-F0-9]{8}$/i.test(token)){
      valid = mfa.useBackupCode(pending.username, token);
    }
  }

  if(!valid){
    logger.warn('MFA failed for '+pending.username+' from '+req.ip);
    audit.log('MFA_FAILED',pending.username,pending.username,'Invalid MFA code',req.ip);
    return res.render('mfa-verify',{error:'Invalid authentication code. Please try again.',username:pending.username});
  }

  // MFA passed - complete login
  req.session.admin=Object.assign({},pending,{loginAt:Date.now()});
  req.session.lastActivity=Date.now();
  delete req.session.pendingAuth;
  logger.info('Login [MFA OK] ['+pending.role+']: '+pending.username+' from '+req.ip);
  audit.log('LOGIN_SUCCESS_MFA',pending.username,pending.username,'role='+pending.role,req.ip);
  res.redirect(pending.role==='admin'?'/dashboard':'/myaccount');
});

// MFA setup (for users enabling MFA themselves, or forced setup)
router.get('/mfa-setup',function(req,res){
  if(!req.session.admin)return res.redirect('/login');
  var username=req.session.admin.username;
  var existing=mfa.getUserMFA(username);
  var record = existing && !existing.enabled ? existing : mfa.setupMFA(username);
  var cfg=require('../utils/autoDetect').getSettings();
  var uri=mfa.buildOtpAuthUri(username, record.secret, cfg.domain||'AD-Console');
  res.render('mfa-setup',{
    admin:req.session.admin, page:'myaccount',
    secret:record.secret, otpUri:uri, backupCodes:record.backupCodes,
    required: req.query.required==='1', error:null,
  });
});

router.post('/mfa-setup',function(req,res){
  if(!req.session.admin)return res.redirect('/login');
  var username=req.session.admin.username;
  var token=(req.body.token||'').trim();
  var record=mfa.getUserMFA(username);
  if(!record)return res.redirect('/mfa-setup');

  if(!mfa.verifyTOTP(record.secret, token)){
    var cfg=require('../utils/autoDetect').getSettings();
    var uri=mfa.buildOtpAuthUri(username, record.secret, cfg.domain||'AD-Console');
    return res.render('mfa-setup',{
      admin:req.session.admin, page:'myaccount',
      secret:record.secret, otpUri:uri, backupCodes:record.backupCodes,
      required: req.query.required==='1', error:'Invalid code. Please scan the QR code again and enter the current 6-digit code.',
    });
  }

  mfa.enableMFA(username);
  logger.info('MFA enabled for '+username);
  require('../utils/auditLogger').log('MFA_ENABLED',username,username,'',req.ip);
  res.redirect(req.session.admin.role==='admin'?'/dashboard?mfa=enabled':'/myaccount?success=MFA enabled successfully');
});

router.post('/mfa-disable',function(req,res){
  if(!req.session.admin)return res.redirect('/login');
  var username=req.session.admin.username;
  mfa.disableMFA(username);
  logger.info('MFA disabled for '+username);
  require('../utils/auditLogger').log('MFA_DISABLED',username,username,'',req.ip);
  res.redirect('/myaccount?success=MFA disabled');
});

router.get('/logout',function(req,res){
  if(req.session.admin) audit.log('LOGOUT',req.session.admin.username,req.session.admin.username,'',req.ip);
  logger.info('Logout: '+(req.session.admin&&req.session.admin.username));
  req.session.destroy(function(){res.redirect('/login');});
});
module.exports=router;
