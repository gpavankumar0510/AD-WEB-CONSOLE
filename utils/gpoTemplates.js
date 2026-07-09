'use strict';
const GPO_TEMPLATES = [
  { id:'cis-password',category:'Security',name:'CIS Password Policy',description:'CIS Level 1 password requirements',icon:'lock',color:'danger',
    settings:[{key:'MinimumPasswordLength',value:'14'},{key:'MaximumPasswordAge',value:'60'},{key:'PasswordComplexity',value:'Enabled'},{key:'PasswordHistorySize',value:'24'}] },
  { id:'account-lockout',category:'Security',name:'Account Lockout Policy',description:'Lock after 5 failed attempts',icon:'shield',color:'warning',
    settings:[{key:'LockoutThreshold',value:'5'},{key:'LockoutDuration',value:'30'},{key:'ObservationWindow',value:'30'}] },
  { id:'workstation',category:'Workstation',name:'Workstation Security Baseline',description:'CIS workstation hardening',icon:'desktop',color:'info',
    settings:[{key:'ScreensaverTimeout',value:'900'},{key:'UAC',value:'Enabled'},{key:'AutorunDisabled',value:'Enabled'},{key:'WindowsFirewall',value:'Enabled'}] },
  { id:'server',category:'Server',name:'Server Security Baseline',description:'SMB signing, audit logging',icon:'server',color:'info',
    settings:[{key:'SMBSigning',value:'Required'},{key:'NTLMv2Only',value:'Enabled'},{key:'AuditLogon',value:'Success,Failure'},{key:'EventLogSize',value:'196608'}] },
  { id:'rdp',category:'Remote Access',name:'Remote Desktop Policy',description:'Secure RDP with NLA',icon:'remote',color:'success',
    settings:[{key:'RDPEnabled',value:'Enabled'},{key:'NLARequired',value:'Enabled'},{key:'EncryptionLevel',value:'High'},{key:'IdleTimeout',value:'60'}] },
  { id:'wsus',category:'Maintenance',name:'Windows Update (WSUS)',description:'Direct clients to WSUS',icon:'update',color:'info',
    settings:[{key:'WSUSServer',value:'http://wsus.domain.local'},{key:'AutoUpdate',value:'4'},{key:'InstallTime',value:'3'}] },
  { id:'software-restriction',category:'AppControl',name:'Software Restriction Policy',description:'Block execution from temp folders',icon:'app',color:'warning',
    settings:[{key:'BlockTempFolders',value:'Enabled'},{key:'BlockDownloads',value:'Enabled'},{key:'BlockAppData',value:'Enabled'}] },
  { id:'browser',category:'Browser',name:'Browser Security',description:'SmartScreen and zone hardening',icon:'browser',color:'success',
    settings:[{key:'SmartScreen',value:'Enabled'},{key:'ProtectedMode',value:'Enabled'},{key:'ActiveXDisabled',value:'Enabled'}] },
];
module.exports = { GPO_TEMPLATES };
