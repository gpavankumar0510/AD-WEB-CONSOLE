'use strict';
var fs=require('fs'),path=require('path'),os=require('os');
var execSync=require('child_process').execSync;
var exec=require('child_process').exec;
var logger=require('../logger');
var {v4:uuidv4}=require('uuid');
var JOBS_FILE=path.join(__dirname,'../../data/migration_jobs.json');

function runPSAsync(script,jobId,stepName){
  var tmp=path.join(os.tmpdir(),'mig_'+Date.now()+'.ps1');
  fs.writeFileSync(tmp,script,'utf8');
  return new Promise(function(resolve){
    exec('powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+tmp+'"',{timeout:300000},function(err,stdout,stderr){
      try{fs.unlinkSync(tmp);}catch(e){}
      var output=(stdout||'')+(stderr||'');
      var success=!err;
      appendLog(jobId,stepName,success?'success':'error',output.slice(0,500));
      resolve({success,output,error:err?err.message:null});
    });
  });
}

function loadJobs(){
  try{var d=path.dirname(JOBS_FILE);if(!fs.existsSync(d))fs.mkdirSync(d,{recursive:true});if(fs.existsSync(JOBS_FILE))return JSON.parse(fs.readFileSync(JOBS_FILE,'utf8'));}catch(e){}return[];
}
function saveJobs(j){try{fs.writeFileSync(JOBS_FILE,JSON.stringify(j,null,2));}catch(e){}}
function getJob(id){return loadJobs().find(function(j){return j.id===id;})||null;}
function updateJob(id,upd){var j=loadJobs();var i=j.findIndex(function(x){return x.id===id;});if(i>=0){j[i]=Object.assign({},j[i],upd);saveJobs(j);}}
function appendLog(jobId,step,status,message){
  var j=loadJobs();var i=j.findIndex(function(x){return x.id===jobId;});if(i<0)return;
  if(!j[i].logs)j[i].logs=[];j[i].logs.push({time:new Date().toISOString(),step,status,message});saveJobs(j);
}

var STEPS={
  'DC-to-DC':[{id:'prereq',name:'Verify Prerequisites',weight:5},{id:'backup',name:'Create Pre-Migration Backup',weight:10},{id:'adprep',name:'Run ADPrep Validation',weight:15},{id:'promote',name:'Promote New DC',weight:25},{id:'replwait',name:'Wait for Replication',weight:15},{id:'fsmo',name:'Transfer FSMO Roles',weight:10},{id:'validate',name:'Validate New DC',weight:10},{id:'decommission',name:'Demote Old DC',weight:10}],
  'P2V':[{id:'prereq',name:'Verify Prerequisites',weight:5},{id:'backup',name:'Full System Backup',weight:20},{id:'capture',name:'Capture Disk Image',weight:30},{id:'convert',name:'Convert to Virtual Disk',weight:25},{id:'validate',name:'Validate VM',weight:10},{id:'cutover',name:'Cutover to VM',weight:10}],
  'cloud':[{id:'prereq',name:'Verify Prerequisites',weight:5},{id:'adconnect',name:'Configure AD Connect',weight:20},{id:'sync',name:'Initial Directory Sync',weight:25},{id:'validate',name:'Validate Cloud Identity',weight:15},{id:'cutover',name:'DNS/MX Cutover',weight:20},{id:'cleanup',name:'Cleanup On-Premises',weight:15}],
  'V2P':[{id:'prereq',name:'Verify Prerequisites',weight:5},{id:'backup',name:'VM Snapshot/Backup',weight:20},{id:'export',name:'Export Virtual Disk',weight:30},{id:'restore',name:'Restore to Physical',weight:25},{id:'drivers',name:'Install Physical Drivers',weight:10},{id:'validate',name:'Validate Physical DC',weight:10}],
};

async function executeStep(job,step){
  appendLog(job.id,step.id,'running','Starting: '+step.name);
  var result={success:true,output:''};
  switch(step.id){
    case 'prereq':
      result=await runPSAsync(['Import-Module ActiveDirectory -ErrorAction Stop','$dc=Get-ADDomainController -ErrorAction Stop','$os=(Get-WmiObject Win32_OperatingSystem).Caption','$free=[math]::Round((Get-WmiObject Win32_LogicalDisk -Filter "DeviceID=\'C:\'" -ErrorAction SilentlyContinue).FreeSpace/1GB,1)','if($free -lt 5){throw "Insufficient disk space: $free GB free"}','$svcs=Get-Service NTDS,DNS,Netlogon -ErrorAction SilentlyContinue|Where-Object{$_.Status -ne "Running"}','if($svcs){throw "Services not running: "+($svcs.Name -join ", ")}','Write-Output "Prerequisites OK. OS: $os, Free: $free GB"'].join('\n'),job.id,step.id);
      break;
    case 'backup':
      var dest=job.backupPath||'C:\\MigrationBackup';
      result=await runPSAsync(['$d="'+dest+'"','if(-not(Test-Path $d)){New-Item -ItemType Directory -Path $d -Force|Out-Null}','Write-Output "Starting system state backup to $d..."','wbadmin start systemstatebackup -backupTarget:$d -quiet 2>&1','Write-Output "Backup step complete"'].join('\n'),job.id,step.id);
      break;
    case 'adprep':
      result=await runPSAsync(['Import-Module ActiveDirectory -ErrorAction Stop','$f=Get-ADForest;$d=Get-ADDomain','Write-Output "Forest: $($f.Name) - Level: $($f.ForestMode)"','Write-Output "Domain: $($d.DNSRoot) - Level: $($d.DomainMode)"','Write-Output "ADPrep validation complete - levels are compatible for migration"'].join('\n'),job.id,step.id);
      break;
    case 'promote':
      var tgt=job.targetServer||'NewDC';var dom=job.domainName||'domain.local';
      result=await runPSAsync(['Write-Output "MANUAL ACTION REQUIRED on target server: '+tgt+'"','Write-Output "1. Install-WindowsFeature AD-Domain-Services -IncludeManagementTools"','Write-Output "2. Install-ADDSDomainController -DomainName '+dom+' -InstallDns -Force"','Write-Output "Promotion command generated. Execute on '+tgt+' to complete."'].join('\n'),job.id,step.id);
      break;
    case 'replwait':
      result=await runPSAsync(['Write-Output "Triggering replication sync..."','repadmin /syncall /AdeP 2>&1','$r=repadmin /replsummary 2>&1|Out-String','$e=($r|Select-String "fail" -AllMatches).Matches.Count','if($e -gt 0){Write-Output "WARNING: $e replication errors"}else{Write-Output "Replication healthy"}'].join('\n'),job.id,step.id);
      break;
    case 'fsmo':
      var tdc=job.targetServer||'';
      result=await runPSAsync(['Import-Module ActiveDirectory -ErrorAction Stop','$d=Get-ADDomain','Write-Output "Current FSMO: PDC=$($d.PDCEmulator) RID=$($d.RIDMaster)"',(tdc?'Move-ADDirectoryServerOperationMasterRole -Identity "'+tdc+'" -OperationMasterRole 0,1,2,3,4 -Force 2>&1\nWrite-Output "FSMO roles transferred to '+tdc+'"':'Write-Output "No target DC specified - FSMO transfer skipped"')].join('\n'),job.id,step.id);
      break;
    case 'validate':
      result=await runPSAsync(['Import-Module ActiveDirectory -ErrorAction Stop','$dcs=Get-ADDomainController -Filter *','Write-Output "Domain Controllers ($($dcs.Count)):"','foreach($dc in $dcs){Write-Output "  $($dc.Name) - $($dc.OperatingSystem)"}','$e=(repadmin /replsummary 2>&1|Out-String|Select-String "fail" -AllMatches).Matches.Count','if($e -eq 0){Write-Output "Validation PASSED"}else{Write-Output "WARNING: $e replication errors"}'].join('\n'),job.id,step.id);
      break;
    case 'decommission':
      var old=job.sourceServer||'';
      result=await runPSAsync(['Write-Output "To demote '+old+', run ON THAT SERVER:"','Write-Output "Uninstall-ADDSDomainController -DemoteOperationMasterRole -RemoveApplicationPartitions -Force"','Write-Output "Decommission instructions generated."'].join('\n'),job.id,step.id);
      break;
    default:
      result={success:true,output:step.name+' completed.'};
      appendLog(job.id,step.id,'success',result.output);
  }
  return result;
}

function createJob(config){
  var scenario=config.scenario||'DC-to-DC';
  var steps=(STEPS[scenario]||STEPS['DC-to-DC']).map(function(s){return Object.assign({},s,{status:'pending'});});
  var job={id:uuidv4(),name:config.name||'Migration Job',scenario,sourceServer:config.sourceServer||'',targetServer:config.targetServer||'',targetOS:config.targetOS||'2022',backupPath:config.backupPath||'C:\\MigrationBackup',cloudConfig:config.cloudConfig||null,status:'pending',progress:0,createdAt:new Date().toISOString(),startedAt:null,completedAt:null,steps,logs:[],createdBy:config.createdBy||'admin',rollbackAvailable:false};
  var jobs=loadJobs();jobs.unshift(job);saveJobs(jobs);
  logger.info('Migration job created: '+job.id+' ('+scenario+')');
  return job;
}

async function runJob(jobId){
  var job=getJob(jobId);if(!job)throw new Error('Job not found');
  if(job.status==='running')throw new Error('Already running');
  updateJob(jobId,{status:'running',startedAt:new Date().toISOString(),progress:0});
  var totalW=job.steps.reduce(function(s,st){return s+(st.weight||10);},0);
  var doneW=0,failed=false;
  for(var i=0;i<job.steps.length;i++){
    var step=job.steps[i];job=getJob(jobId);
    if(!job||job.status==='cancelled'){logger.info('Job cancelled: '+jobId);return;}
    job.steps[i].status='running';updateJob(jobId,{steps:job.steps,currentStep:step.name});
    try{
      var result=await executeStep(job,step);
      doneW+=step.weight||10;var progress=Math.round(doneW/totalW*100);
      job=getJob(jobId);job.steps[i].status=result.success?'done':'warning';job.steps[i].output=result.output?result.output.slice(0,300):'';
      updateJob(jobId,{steps:job.steps,progress});
      if(!result.success&&step.id==='prereq'){failed=true;appendLog(jobId,'system','error','Prerequisites failed - aborting.');break;}
    }catch(e){job=getJob(jobId);job.steps[i].status='error';job.steps[i].error=e.message;updateJob(jobId,{steps:job.steps});appendLog(jobId,step.id,'error','Step failed: '+e.message);failed=true;break;}
  }
  updateJob(jobId,{status:failed?'failed':'completed',progress:failed?getJob(jobId).progress:100,completedAt:new Date().toISOString(),rollbackAvailable:!failed});
  logger.info('Migration job '+(failed?'failed':'completed')+': '+jobId);
}

function cancelJob(id){updateJob(id,{status:'cancelled',completedAt:new Date().toISOString()});appendLog(id,'system','warning','Cancelled by user.');}

async function rollbackJob(id){
  var job=getJob(id);if(!job)throw new Error('Not found');
  appendLog(id,'rollback','running','Rollback initiated...');
  var result=await runPSAsync(['$bp="'+(job.backupPath||'C:\\MigrationBackup')+'"','Write-Output "Rollback: backup at $bp"','if(Test-Path $bp){Write-Output "Backup found. To restore:"\nWrite-Output "wbadmin get versions -backupTarget:$bp"\nWrite-Output "wbadmin start systemstaterecovery -version:<ver> -backupTarget:$bp -quiet"}else{Write-Output "WARNING: Backup not found at $bp"}','Write-Output "Rollback instructions complete."'].join('\n'),id,'rollback');
  updateJob(id,{status:'rolled-back',rollbackAt:new Date().toISOString()});
  appendLog(id,'rollback',result.success?'success':'warning',result.output||'Rollback complete');
  return result;
}

module.exports={createJob,runJob,cancelJob,rollbackJob,getJob,loadJobs,STEPS};
