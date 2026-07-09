'use strict';
var execSync = require('child_process').execSync;
var logger = require('./logger');
var path = require('path'), fs = require('fs'), os = require('os');
var SETUP_FLAG = path.join(__dirname, '../data/.setup-complete');

function runPSScript(script) {
  var tmp = path.join(os.tmpdir(), 'setup_' + Date.now() + '.ps1');
  try {
    fs.writeFileSync(tmp, script, 'utf8');
    return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + tmp + '"',
      { timeout: 30000, encoding: 'utf8', windowsHide: true }).trim();
  } catch(e) { return ''; }
  finally { try { fs.unlinkSync(tmp); } catch(e) {} }
}

function isSetupDone() { return fs.existsSync(SETUP_FLAG); }
function markSetupDone() {
  try { var d=path.dirname(SETUP_FLAG); if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true}); fs.writeFileSync(SETUP_FLAG,new Date().toISOString()); } catch(e) {}
}

function autoSetup() {
  if (isSetupDone()) return;
  logger.info('=== AUTO-SETUP: First run ===');
  var adCheck = runPSScript(['try {','  Import-Module ActiveDirectory -ErrorAction Stop','  Write-Output "ok"','} catch { Write-Output "no" }'].join('\n'));
  if (!adCheck || adCheck.indexOf('ok') < 0) { logger.warn('AD module not available - skipping auto-setup'); markSetupDone(); return; }

  var domainOut = runPSScript(['Import-Module ActiveDirectory -ErrorAction Stop','$d=Get-ADDomain','Write-Output ($d.DNSRoot+"|"+$d.DistinguishedName+"|"+$d.NetBIOSName)'].join('\n'));
  if (!domainOut || domainOut.indexOf('|') < 0) { logger.warn('Cannot get domain info'); markSetupDone(); return; }

  var parts   = domainOut.split('|');
  var domain  = parts[0].trim(), baseDN = parts[1].trim(), netbios = parts[2].trim();
  var rand    = Math.random().toString(36).slice(2,8).toUpperCase();
  var svcPwd  = 'Svc' + rand + 'Adm9!';
  var upn     = 'svc-adconsole@' + domain;
  var svcFull = netbios + '\\svc-adconsole';

  var existsOut = runPSScript(['Import-Module ActiveDirectory -ErrorAction Stop','try { Get-ADUser -Identity "svc-adconsole" -ErrorAction Stop | Out-Null; Write-Output "exists" } catch { Write-Output "notfound" }'].join('\n'));
  if (existsOut && existsOut.indexOf('exists') >= 0) {
    logger.info('AUTO-SETUP: Resetting svc-adconsole password...');
    runPSScript(['Import-Module ActiveDirectory -ErrorAction Stop','$sp=ConvertTo-SecureString "'+svcPwd+'" -AsPlainText -Force','Set-ADAccountPassword -Identity "svc-adconsole" -Reset -NewPassword $sp','Set-ADUser -Identity "svc-adconsole" -PasswordNeverExpires $true -ChangePasswordAtLogon $false','Enable-ADAccount -Identity "svc-adconsole"','Unlock-ADAccount -Identity "svc-adconsole"','Write-Output "done"'].join('\n'));
  } else {
    logger.info('AUTO-SETUP: Creating svc-adconsole...');
    runPSScript(['Import-Module ActiveDirectory -ErrorAction Stop','$sp=ConvertTo-SecureString "'+svcPwd+'" -AsPlainText -Force','$ouPath="CN=Users,'+baseDN+'"','try { $ou=Get-ADOrganizationalUnit -Filter {Name -eq "ServiceAccounts"} | Select-Object -First 1; if($ou){$ouPath=$ou.DistinguishedName} } catch {}','New-ADUser -Name "svc-adconsole" -SamAccountName "svc-adconsole" -UserPrincipalName "'+upn+'" -AccountPassword $sp -Enabled $true -PasswordNeverExpires $true -ChangePasswordAtLogon $false -Path $ouPath -Description "AD Web Console service account"','Write-Output "created"'].join('\n'));
  }

  logger.info('AUTO-SETUP: Delegating permissions...');
  runPSScript(['$svc="'+svcFull+'"','$d="'+baseDN+'"','$containers=@("CN=Users,'+baseDN+'","CN=Computers,'+baseDN+'")',
    'foreach($c in $containers){','  dsacls $c /G "${svc}:CCDC;user" /I:T 2>$null|Out-Null','  dsacls $c /G "${svc}:RPWP;;user" /I:S 2>$null|Out-Null',
    '  dsacls $c /G "${svc}:CA;Reset Password;user" /I:S 2>$null|Out-Null','  dsacls $c /G "${svc}:WP;lockoutTime;user" /I:S 2>$null|Out-Null',
    '  dsacls $c /G "${svc}:WP;unicodePwd;user" /I:S 2>$null|Out-Null','  dsacls $c /G "${svc}:CCDC;computer" /I:T 2>$null|Out-Null',
    '  dsacls $c /G "${svc}:RPWP;;computer" /I:S 2>$null|Out-Null','  dsacls $c /G "${svc}:SD;;computer" /I:S 2>$null|Out-Null',
    '  dsacls $c /G "${svc}:CCDC;organizationalUnit" /I:T 2>$null|Out-Null',
    '}',
    'dsacls $d /G "${svc}:CA;Reset Password;user" /I:S 2>$null|Out-Null',
    'dsacls $d /G "${svc}:WP;unicodePwd;user" /I:S 2>$null|Out-Null',
    'dsacls $d /G "${svc}:RPWP;;user" /I:S 2>$null|Out-Null',
    'dsacls $d /G "${svc}:RPLCLORC" /I:T 2>$null|Out-Null',
    'try { Set-ADObject "CN=Computers,'+baseDN+'" -ProtectedFromAccidentalDeletion $false -ErrorAction Stop } catch {}',
    'Write-Output "delegated"'].join('\n'));

  var envPath = path.join(__dirname, '../.env');
  var envContent = '';
  try { envContent = fs.readFileSync(envPath, 'utf8'); } catch(e) {}
  var lines = envContent.split('\n'), newLines = [], setAcct = false, setPwd = false;
  lines.forEach(function(line) {
    if (line.startsWith('AD_SERVICE_ACCOUNT=')) { newLines.push('AD_SERVICE_ACCOUNT=' + upn); setAcct = true; }
    else if (line.startsWith('AD_SERVICE_PASSWORD=')) { newLines.push('AD_SERVICE_PASSWORD=' + svcPwd); setPwd = true; }
    else newLines.push(line);
  });
  if (!setAcct) newLines.push('AD_SERVICE_ACCOUNT=' + upn);
  if (!setPwd)  newLines.push('AD_SERVICE_PASSWORD=' + svcPwd);
  fs.writeFileSync(envPath, newLines.join('\n'), 'utf8');
  require('dotenv').config();
  require('./autoDetect').clearCache();
  logger.info('AUTO-SETUP: Complete. Account: ' + upn);
  markSetupDone();
}

module.exports = { autoSetup };
