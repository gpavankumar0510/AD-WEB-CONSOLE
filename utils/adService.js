'use strict';
var ldap   = require('ldapjs');
var logger = require('./logger');

function escapeFilter(str) {
  if (!str) return '';
  return String(str).replace(/\\/g,'\\5c').replace(/\*/g,'\\2a').replace(/\(/g,'\\28').replace(/\)/g,'\\29').replace(/\0/g,'\\00');
}

function cfg() { return require('./autoDetect').getSettings(); }

function createClient() {
  var s = cfg(), url = s.host || 'ldap://127.0.0.1', isLdaps = url.startsWith('ldaps://');
  var opts = {
    url: url,
    timeout: 15000,
    connectTimeout: 15000,
    reconnect: false,
  };
  if (isLdaps) {
    opts.tlsOptions = {
      rejectUnauthorized: false,
      checkServerIdentity: function() { return undefined; },
    };
  }
  var client = ldap.createClient(opts);
  client.on('error', function(err) {
    if (err.message && (err.message.indexOf('ECONNRESET') >= 0 || err.message.indexOf('ECONNREFUSED') >= 0)) {
      logger.warn('LDAP connection reset on ' + url + ' - if using LDAPS, the DC may not have a valid certificate. Consider setting AD_HOST=ldap://127.0.0.1 in .env');
    } else {
      logger.error('LDAP: ' + err.message);
    }
  });
  return client;
}

async function bindService(client) {
  var s = cfg();
  if (!s.serviceAcct || !s.servicePwd) throw new Error('Service account not configured. Set AD_SERVICE_ACCOUNT and AD_SERVICE_PASSWORD in .env');
  return new Promise(function(resolve, reject) {
    client.bind(s.serviceAcct, s.servicePwd, function(err) { if(err) return reject(new Error('Bind failed: '+err.message)); resolve(); });
  });
}

async function withClient(fn) {
  var client = createClient();
  try { await bindService(client); return await fn(client); }
  finally { try { client.destroy(); } catch(e) {} }
}

function parseEntry(entry) {
  var dn = '';
  if (typeof entry.objectName === 'string') dn = entry.objectName;
  else if (entry.dn && typeof entry.dn === 'string') dn = entry.dn;
  else if (entry.dn && entry.dn.toString) dn = entry.dn.toString();
  else if (entry.pojo && entry.pojo.objectName) dn = entry.pojo.objectName;
  var obj = { dn };
  var attrs = (entry.pojo && entry.pojo.attributes) || entry.attributes || [];
  attrs.forEach(function(a) {
    var vals = a.values || (a.value !== undefined ? [a.value] : []);
    obj[a.type] = vals.length === 1 ? vals[0] : vals;
  });
  return obj;
}

async function search(baseDn, filter, attributes) {
  attributes = attributes || [];
  return withClient(async function(client) {
    return new Promise(function(resolve, reject) {
      var entries = [];
      client.search(baseDn, { filter, scope:'sub', attributes, timeLimit:30, sizeLimit:2000 }, function(err, res) {
        if (err) return reject(err);
        res.on('searchEntry', function(e) { entries.push(parseEntry(e)); });
        res.on('error', function(e) { if (e.message && e.message.indexOf('Size Limit')>=0) return resolve(entries); reject(e); });
        res.on('end', function() { resolve(entries); });
      });
    });
  });
}

function baseDN() { return cfg().baseDN; }

async function getUsers() {
  return search(baseDN(), '(&(objectClass=user)(objectCategory=person)(!(objectClass=computer)))',
    ['sAMAccountName','displayName','mail','userAccountControl','whenCreated','lastLogon',
     'memberOf','department','title','description','telephoneNumber','distinguishedName',
     'lockoutTime','pwdLastSet','givenName','sn','userPrincipalName']);
}

async function getUser(username) {
  var safe = escapeFilter(username);
  var results = await search(baseDN(), '(&(objectClass=user)(objectCategory=person)(sAMAccountName='+safe+'))',
    ['sAMAccountName','displayName','mail','userAccountControl','whenCreated','lastLogon',
     'memberOf','department','title','description','telephoneNumber','distinguishedName',
     'lockoutTime','pwdLastSet','givenName','sn','userPrincipalName','whenChanged']);
  return results[0] || null;
}

async function createUser(attrs) {
  var s = cfg();
  var isLdaps = (s.host || '').startsWith('ldaps://');

  // Strategy: if plain LDAP, create account disabled without password,
  // then set password via PowerShell (works on DC without LDAPS)
  if (!isLdaps) {
    return createUserViaPS(attrs, s);
  }

  return withClient(async function(client) {
    var cn   = ((attrs.cn || attrs.displayName || (attrs.firstName + ' ' + attrs.lastName))).trim();
    var ouDn = (attrs.ou && attrs.ou.trim()) ? attrs.ou.trim() : s.usersOU;
    var dn   = 'CN=' + cn + ',' + ouDn;
    var password = Buffer.from('"' + attrs.password + '"', 'utf16le');

    // Build UAC flags based on checkboxes
    // 512 = NORMAL_ACCOUNT (enabled)
    // 514 = NORMAL_ACCOUNT + ACCOUNTDISABLE
    // 65536 = DONT_EXPIRE_PASSWORD
    // 262144 = SMARTCARD_REQUIRED
    var uac = 512;
    if (attrs.accountDisabled) uac |= 2;
    if (attrs.passwordNeverExpires) uac |= 65536;
    if (attrs.smartcardRequired) uac |= 262144;
    if (attrs.cannotChangePassword) uac |= 64;

    var entry = {
      objectClass: ['top','person','organizationalPerson','user'],
      sAMAccountName: attrs.username.trim(),
      userPrincipalName: attrs.username.trim() + '@' + s.domain,
      givenName: attrs.firstName.trim(),
      sn: attrs.lastName.trim(),
      displayName: (attrs.displayName || (attrs.firstName + ' ' + attrs.lastName)).trim(),
      unicodePwd: password,
      userAccountControl: String(uac),
    };
    if (attrs.email && attrs.email.trim())           entry.mail            = attrs.email.trim();
    if (attrs.department && attrs.department.trim()) entry.department      = attrs.department.trim();
    if (attrs.title && attrs.title.trim())           entry.title           = attrs.title.trim();
    if (attrs.phone && attrs.phone.trim())           entry.telephoneNumber = attrs.phone.trim();
    if (attrs.description && attrs.description.trim()) entry.description   = attrs.description.trim();
    if (attrs.mustChangePassword) entry.pwdLastSet = '0';
    if (attrs.accountExpires && attrs.accountExpires.trim()) {
      var expDate = new Date(attrs.accountExpires);
      // AD FILETIME = (Unix epoch ms + 11644473600000) * 10000
      entry.accountExpires = String((expDate.getTime() + 11644473600000) * 10000);
    }

    return new Promise(function(resolve, reject) {
      client.add(dn, entry, function(err) {
        if (err) {
          if (err.message.indexOf('Already Exists') >= 0 || err.code === 68)
            return reject(new Error('User "' + cn + '" already exists.'));
          if (err.message.indexOf('Constraint') >= 0)
            return reject(new Error('Password does not meet complexity requirements.'));
          if (err.message.indexOf('Insufficient') >= 0)
            return reject(new Error('Service account lacks permission to create users.'));
          if (err.message.indexOf('Unwilling') >= 0 || err.message.indexOf('unwilling') >= 0)
            return reject(new Error('LDAPS required to set password. Using PowerShell fallback...'));
          return reject(new Error('Create failed: ' + err.message));
        }
        resolve(dn);
      });
    });
  });
}

// Fallback: create user via PowerShell (works on plain LDAP DCs)
async function createUserViaPS(attrs, s) {
  var path = require('path');
  var os2  = require('os');
  var exec = require('child_process').exec;

  var ouDn = (attrs.ou && attrs.ou.trim()) ? attrs.ou.trim() : s.usersOU;
  var displayName = (attrs.displayName || ((attrs.firstName||'') + ' ' + (attrs.lastName||''))).trim() || attrs.username;

  // Safe PS string: use double-quoted strings, escape backtick and dollar
  function psStr(v) {
    return '"' + (v||'').replace(/`/g, '``').replace(/"/g, '`"').replace(/\$/g, '`$') + '"';
  }

  var enabled       = attrs.accountDisabled     ? '$false' : '$true';
  var pwNeverExp    = attrs.passwordNeverExpires ? '$true'  : '$false';
  var changeAtLogon = attrs.mustChangePassword   ? '$true'  : '$false';
  var cannotChange  = attrs.cannotChangePassword ? '$true'  : '$false';
  var smartcard     = attrs.smartcardRequired    ? '$true'  : '$false';

  // Build a single splatted hashtable - safest way to pass many params
  var lines = [
    'Import-Module ActiveDirectory -ErrorAction Stop',
    '$pw = ConvertTo-SecureString ' + psStr(attrs.password || 'TempPass123!') + ' -AsPlainText -Force',
    '$params = @{',
    '  Name              = ' + psStr(displayName),
    '  SamAccountName    = ' + psStr(attrs.username.trim()),
    '  UserPrincipalName = ' + psStr(attrs.username.trim() + '@' + s.domain),
    '  GivenName         = ' + psStr((attrs.firstName||'').trim()),
    '  Surname           = ' + psStr((attrs.lastName||'').trim()),
    '  DisplayName       = ' + psStr(displayName),
    '  AccountPassword   = $pw',
    '  Enabled           = ' + enabled,
    '  PasswordNeverExpires = ' + pwNeverExp,
    '  CannotChangePassword = ' + cannotChange,
    '  ChangePasswordAtLogon = ' + changeAtLogon,
    '  SmartcardLogonRequired = ' + smartcard,
    '  Path              = ' + psStr(ouDn),
  ];
  if (attrs.email && attrs.email.trim())       lines.push('  EmailAddress = ' + psStr(attrs.email.trim()));
  if (attrs.department && attrs.department.trim()) lines.push('  Department   = ' + psStr(attrs.department.trim()));
  if (attrs.title && attrs.title.trim())       lines.push('  Title        = ' + psStr(attrs.title.trim()));
  if (attrs.description && attrs.description.trim()) lines.push('  Description  = ' + psStr(attrs.description.trim()));
  lines.push('}');
  lines.push('New-ADUser @params -ErrorAction Stop');
  if (attrs.accountExpires && attrs.accountExpires.trim()) {
    lines.push('Set-ADAccountExpiration -Identity ' + psStr(attrs.username.trim()) + ' -DateTime (Get-Date ' + psStr(attrs.accountExpires.trim()) + ')');
  }
  lines.push('Write-Output "CREATED"');

  var script = lines.join('\n');
  var tmp = path.join(os2.tmpdir(), 'createuser_' + Date.now() + '.ps1');
  try { require('fs').writeFileSync(tmp, script, 'utf8'); } catch(e) {}

  return new Promise(function(resolve, reject) {
    exec('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: 30000 },
      function(err, stdout, stderr) {
        try { require('fs').unlinkSync(tmp); } catch(e) {}
        if (err || (stderr && stderr.toLowerCase().indexOf('error') >= 0 && stdout.indexOf('CREATED') < 0)) {
          var msg = (stderr || (err && err.message) || '').replace(/[\r\n]+/g,' ').slice(0, 300);
          return reject(new Error('Create user failed: ' + msg));
        }
        if (stdout.indexOf('CREATED') >= 0) return resolve('CN=' + displayName + ',' + ouDn);
        return reject(new Error('PowerShell user creation failed — check AD permissions for svc-adconsole'));
      });
  });
}

async function modifyUser(dn, changes) {
  return withClient(async function(client) {
    var filtered = Object.entries(changes).filter(function(p) { return p[1]!==undefined&&p[1]!==null&&String(p[1]).trim()!==''; });
    if (!filtered.length) return true;
    var ldapChanges = filtered.map(function(p) {
      return new ldap.Change({ operation:'replace', modification: new ldap.Attribute({ type:p[0], values:[String(p[1]).trim()] }) });
    });
    return new Promise(function(resolve, reject) {
      client.modify(dn, ldapChanges, function(err) {
        if (err) { if (err.message.indexOf('Insufficient')>=0) return reject(new Error('Insufficient Access Rights - run fix-gopi.ps1 on DC.')); return reject(new Error('Modify failed: '+err.message)); }
        resolve(true);
      });
    });
  });
}

async function resetPassword(dn, newPassword) {
  return withClient(async function(client) {
    var encoded = Buffer.from('"'+newPassword+'"','utf16le');
    var changes = [new ldap.Change({ operation:'replace', modification:new ldap.Attribute({type:'unicodePwd',values:[encoded]}) })];
    return new Promise(function(resolve, reject) {
      client.modify(dn, changes, function(err) {
        if (err) {
          if (err.message.indexOf('unwilling')>=0||err.message.indexOf('UNWILLING')>=0) return reject(new Error('LDAPS required for password reset.'));
          if (err.message.indexOf('constraint')>=0||err.message.indexOf('Constraint')>=0) return reject(new Error('Password does not meet complexity requirements.'));
          if (err.message.indexOf('Insufficient')>=0) return reject(new Error('Insufficient Access Rights - run fix-gopi.ps1 on DC to grant Reset Password on this user.'));
          return reject(new Error('Reset failed: '+err.message));
        }
        resolve(true);
      });
    });
  });
}

async function unlockUser(dn) {
  return withClient(async function(client) {
    var changes = [new ldap.Change({ operation:'replace', modification:new ldap.Attribute({type:'lockoutTime',values:['0']}) })];
    return new Promise(function(resolve, reject) { client.modify(dn, changes, function(err) { if(err) return reject(new Error('Unlock failed: '+err.message)); resolve(true); }); });
  });
}

async function disableUser(dn) { return modifyUser(dn, { userAccountControl:'514' }); }
async function enableUser(dn)  { return modifyUser(dn, { userAccountControl:'512' }); }

async function deleteObject(dn) {
  return withClient(async function(client) {
    return new Promise(function(resolve, reject) {
      client.del(dn, function(err) {
        if (err) {
          if (err.message.indexOf('Insufficient')>=0) return reject(new Error('Insufficient Access - run fix-gopi.ps1 on DC.'));
          if (err.message.indexOf('Not Allowed On')>=0) return reject(new Error('Protected object - uncheck "Protect from accidental deletion" in ADUC.'));
          return reject(new Error('Delete failed: '+err.message));
        }
        resolve(true);
      });
    });
  });
}

async function moveObject(dn, newParentDn) {
  return withClient(async function(client) {
    var cn = dn.split(',')[0];
    return new Promise(function(resolve, reject) { client.modifyDN(dn, cn, true, newParentDn, function(err) { if(err) return reject(new Error('Move failed: '+err.message)); resolve(true); }); });
  });
}

async function renameObject(dn, newCN) {
  return withClient(async function(client) {
    var parent = dn.split(',').slice(1).join(',');
    return new Promise(function(resolve, reject) { client.modifyDN(dn, 'CN='+newCN, true, parent, function(err) { if(err) return reject(new Error('Rename failed: '+err.message)); resolve(true); }); });
  });
}

async function getGroups() {
  return search(baseDN(), '(objectClass=group)', ['sAMAccountName','displayName','description','distinguishedName','member','groupType','whenCreated','managedBy']);
}

async function getGroup(name) {
  var safe = escapeFilter(name);
  var results = await search(baseDN(), '(&(objectClass=group)(sAMAccountName='+safe+'))',
    ['sAMAccountName','displayName','description','distinguishedName','member','groupType','managedBy','whenCreated']);
  return results[0] || null;
}

async function createGroup(attrs) {
  var s = cfg();
  return withClient(async function(client) {
    var cn   = (attrs.cn || attrs.name).trim();
    var ouDn = (attrs.ou && attrs.ou.trim()) ? attrs.ou.trim() : ('CN=Users,' + baseDN());
    var dn   = 'CN=' + cn + ',' + ouDn;
    var entry = {
      objectClass:   ['top', 'group'],
      sAMAccountName: (attrs.samName || cn).trim(),
      groupType:      attrs.groupType || '-2147483646',
    };
    // Only add description if non-empty (empty string causes Invalid Attribute Syntax)
    if (attrs.description && attrs.description.trim()) {
      entry.description = attrs.description.trim();
    }
    if (attrs.displayName && attrs.displayName.trim()) {
      entry.displayName = attrs.displayName.trim();
    }
    return new Promise(function(resolve, reject) {
      client.add(dn, entry, function(err) {
        if (err) {
          if (err.message.indexOf('Already Exists') >= 0 || err.code === 68)
            return reject(new Error('Group "' + cn + '" already exists.'));
          if (err.message.indexOf('Invalid Attribute') >= 0)
            return reject(new Error('Invalid attribute value. Check group name has no special characters.'));
          return reject(new Error('Create group failed: ' + err.message));
        }
        resolve(dn);
      });
    });
  });
}

async function addToGroup(userDn, groupDn) {
  return withClient(async function(client) {
    var change = new ldap.Change({ operation:'add', modification:new ldap.Attribute({type:'member',values:[userDn]}) });
    return new Promise(function(resolve, reject) { client.modify(groupDn, change, function(err) { if(err&&err.message.indexOf('Already Exists')<0) return reject(err); resolve(true); }); });
  });
}

async function removeFromGroup(memberDn, groupDn) {
  return withClient(async function(client) {
    var change = new ldap.Change({ operation:'delete', modification:new ldap.Attribute({type:'member',values:[memberDn]}) });
    return new Promise(function(resolve, reject) { client.modify(groupDn, change, function(err) { if(err) return reject(err); resolve(true); }); });
  });
}

async function getComputers() {
  return search(baseDN(), '(objectClass=computer)',
    ['cn','dNSHostName','operatingSystem','operatingSystemVersion','whenCreated','lastLogon','distinguishedName','userAccountControl','description','managedBy','whenChanged']);
}

async function getOUs() {
  return search(baseDN(), '(|(objectClass=organizationalUnit)(objectClass=container))', ['ou','name','distinguishedName','description']);
}

async function createOU(attrs) {
  return withClient(async function(client) {
    var name   = attrs.name.trim();
    var parent = attrs.parent || baseDN();
    var dn     = 'OU=' + name + ',' + parent;
    var entry  = {
      objectClass: ['top', 'organizationalUnit'],
      ou: name,
    };
    // Only add description if non-empty - empty string causes Invalid Attribute Syntax
    if (attrs.description && attrs.description.trim()) {
      entry.description = attrs.description.trim();
    }
    return new Promise(function(resolve, reject) {
      client.add(dn, entry, function(err) {
        if (err) {
          if (err.message.indexOf('Already Exists') >= 0 || err.code === 68)
            return reject(new Error('OU "' + name + '" already exists.'));
          return reject(new Error('Create OU failed: ' + err.message));
        }
        resolve(dn);
      });
    });
  });
}

async function getLockedUsers() {
  return search(baseDN(), '(&(objectClass=user)(objectCategory=person)(lockoutTime>=1))', ['sAMAccountName','displayName','mail','lockoutTime','distinguishedName','userAccountControl']);
}

async function getDomainStats() {
  try {
    var [users, computers, groups, locked] = await Promise.all([
      search(baseDN(),'(&(objectClass=user)(objectCategory=person)(!(objectClass=computer)))',['userAccountControl','pwdLastSet']),
      search(baseDN(),'(objectClass=computer)',['cn','lastLogon']),
      search(baseDN(),'(objectClass=group)',['cn']),
      getLockedUsers(),
    ]);
    var disabled = users.filter(function(u) { return parseInt(u.userAccountControl||'0')&2; });
    var staleThreshold = Date.now() - 90*24*60*60*1000;
    var stale = computers.filter(function(c) { var ll=parseInt(c.lastLogon||0); return ll===0||(new Date(ll/1e4-11644473600000).getTime()<staleThreshold); });
    return { totalUsers:users.length, activeUsers:users.length-disabled.length, disabledUsers:disabled.length, lockedUsers:locked.length, totalComputers:computers.length, totalGroups:groups.length, staleComputers:stale.length };
  } catch(e) { logger.error('getDomainStats: '+e.message); return {totalUsers:0,activeUsers:0,disabledUsers:0,lockedUsers:0,totalComputers:0,totalGroups:0,staleComputers:0}; }
}

async function authenticateAdmin(username, password) {
  var s = cfg();
  if (process.env.LOCAL_ADMIN_USER && username===process.env.LOCAL_ADMIN_USER && password===process.env.LOCAL_ADMIN_PASS)
    return { username, displayName:'Local Admin', isLocal:true, role:'admin' };

  var samName = username;
  if (username.indexOf('@')>=0) samName=username.split('@')[0];
  else if (username.indexOf('\\')>=0) samName=username.split('\\')[1];

  var userInfo = null;
  var svcClient = createClient();
  try {
    await bindService(svcClient);
    userInfo = await new Promise(function(resolve) {
      var found = [];
      svcClient.search(s.baseDN, { filter:'(sAMAccountName='+escapeFilter(samName)+')', scope:'sub',
        attributes:['dn','displayName','mail','memberOf','sAMAccountName','userAccountControl','department','title','userPrincipalName'] },
        function(err, res) {
          if (err) return resolve(null);
          res.on('searchEntry', function(e) { found.push(parseEntry(e)); });
          res.on('error', function() { resolve(found[0]||null); });
          res.on('end', function() { resolve(found[0]||null); });
        });
    });
  } catch(e) { logger.error('Service bind during auth: '+e.message); return null; }
  finally { try { svcClient.destroy(); } catch(e) {} }

  if (!userInfo) { logger.warn('User not found: '+samName); return null; }
  if (parseInt(userInfo.userAccountControl||'0')&2) { logger.warn('Account disabled: '+samName); return null; }

  var bindFormats = [userInfo.dn, samName+'@'+s.domain, s.netbios+'\\'+samName].filter(Boolean);
  for (var i=0;i<bindFormats.length;i++) {
    var authClient = createClient();
    var success = await new Promise(function(resolve) {
      authClient.bind(bindFormats[i], password, function(err) { try{authClient.destroy();}catch(e){} resolve(!err); });
    });
    if (success) {
      var rbac = require('./rbac');
      return { username:userInfo.sAMAccountName||samName, displayName:userInfo.displayName||samName,
        dn:String(userInfo.dn||''), mail:userInfo.mail||'', memberOf:userInfo.memberOf||[],
        department:userInfo.department||'', title:userInfo.title||'', role:rbac.determineRole(userInfo), isLocal:false };
    }
  }
  return null;
}

module.exports = { getUsers, getUser, createUser, modifyUser, resetPassword, unlockUser, disableUser, enableUser, deleteObject, moveObject, renameObject, getGroups, getGroup, createGroup, addToGroup, removeFromGroup, getComputers, getOUs, createOU, getLockedUsers, getDomainStats, authenticateAdmin, escapeFilter };
