'use strict';
var fs=require('fs'),path=require('path'),os=require('os');
var execSync=require('child_process').execSync;
var logger=require('./logger');
var gpoStore=require('./gpoStore');

function runPS(script) {
  var tmp=path.join(os.tmpdir(),'gposync_'+Date.now()+'.ps1');
  try { fs.writeFileSync(tmp,script,'utf8'); return execSync('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+tmp+'"',{timeout:30000,encoding:'utf8',windowsHide:true}).trim(); }
  catch(e){return '';} finally{try{fs.unlinkSync(tmp);}catch(e){}}
}

function syncGPOsFromAD() {
  logger.info('GPO Sync: Starting...');
  var script=['try {','  Import-Module GroupPolicy -ErrorAction Stop','  $gpos=Get-GPO -All|Select-Object DisplayName,Id,GpoStatus,Description','  $gpos|ConvertTo-Json -Compress',
    '} catch {','  $s=New-Object System.DirectoryServices.DirectorySearcher','  $s.Filter="(objectClass=groupPolicyContainer)"','  $s.PropertiesToLoad.AddRange(@("displayName","name","description"))',
    '  $r=$s.FindAll()','  $list=@()','  foreach($i in $r){$p=$i.Properties;$list+=@{DisplayName=if($p["displayname"]){$p["displayname"][0]}else{$p["name"][0]};Id=$p["name"][0];GpoStatus="AllSettingsEnabled";Description=""}}',
    '  $list|ConvertTo-Json -Compress','}'].join('\n');
  var out=runPS(script);
  if (!out||!out.trim()) return {imported:0,updated:0,total:0};
  try {
    var gpos=JSON.parse(out);
    if (!Array.isArray(gpos)) gpos=[gpos];
    var existing=gpoStore.getAllPolicies();
    var imported=0,updated=0;
    gpos.forEach(function(g) {
      if (!g.DisplayName) return;
      var adId=String(g.Id||g.DisplayName);
      var found=existing.find(function(p){return p.adGpoId===adId||p.name===g.DisplayName;});
      if (!found) { gpoStore.createPolicy({name:g.DisplayName,description:g.Description||'',category:'Synced from AD',adGpoId:adId,settings:[],status:(g.GpoStatus==='AllSettingsDisabled')?'Disabled':'Active',createdBy:'auto-sync'}); imported++; }
      else { var ns=(g.GpoStatus==='AllSettingsDisabled')?'Disabled':'Active'; if(found.status!==ns){gpoStore.updatePolicy(found.id,{status:ns});updated++;} }
    });
    logger.info('GPO Sync: imported='+imported+' updated='+updated+' total='+gpos.length);
    return {imported,updated,total:gpos.length};
  } catch(e) { logger.error('GPO Sync parse error: '+e.message); return {imported:0,updated:0,total:0}; }
}

function syncGPOLinks() {
  var script=['try {','  Import-Module GroupPolicy,ActiveDirectory -ErrorAction Stop','  $ous=@()+(Get-ADOrganizationalUnit -Filter *|Select-Object -ExpandProperty DistinguishedName)','  $ous+=(Get-ADDomain).DistinguishedName','  $all=@()',
    '  foreach($ou in $ous){try{$inh=Get-GPInheritance -Target $ou -ErrorAction Stop;foreach($l in $inh.GpoLinks){$all+=@{PolicyName=$l.DisplayName;Target=$ou;TargetType=if($ou -match "^DC="){"Domain"}else{"OU"};Enabled=$l.Enabled}}}catch{}}',
    '  $all|ConvertTo-Json -Compress','} catch { Write-Output "" }'].join('\n');
  var out=runPS(script);
  if (!out||!out.trim()) return;
  try {
    var links=JSON.parse(out); if(!Array.isArray(links))links=[links];
    var policies=gpoStore.getAllPolicies(), existingLinks=gpoStore.getAllLinks();
    links.forEach(function(link) {
      var policy=policies.find(function(p){return p.name===link.PolicyName;});
      if (!policy) return;
      var already=existingLinks.find(function(l){return l.policyId===policy.id&&l.target===link.Target;});
      if (!already) gpoStore.createLink(policy.id,link.Target,link.TargetType,link.Enabled!==false);
    });
    logger.info('GPO Link Sync: '+links.length+' links processed');
  } catch(e) { logger.error('GPO Link Sync: '+e.message); }
}

function fullSync() { var r=syncGPOsFromAD(); if(r.total>0)syncGPOLinks(); return r; }
module.exports = { syncGPOsFromAD, syncGPOLinks, fullSync };
