/* ═══════════════════════════════════════════════════════════
   IntegriShield SOC Dashboard — Complete Demo Engine
   13 modules · Investor POC · All features live
   ═══════════════════════════════════════════════════════════ */

const API_BASE = (() => {
  if (typeof window.__INTEGRISHIELD_API !== "undefined" && window.__INTEGRISHIELD_API) return window.__INTEGRISHIELD_API;
  if (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1") return "http://localhost:8787";
  return window.location.origin + "/api-proxy";
})();
const POLL_MS = 2500;

// ── State ─────────────────────────────────────────────────────
let alerts=[], auditRows=[], anomalies=[], sapEvents=[], compEvents=[],
    dlpEvents=[], incEvents=[], shadowEvents=[], sbomEvents=[],
    ztEvents=[], credEvents=[], cloudEvents=[], prevAlertCount=0,
    connEvents=[], trafficEvents=[], webhookEvents=[];

// ── Demo engine ───────────────────────────────────────────────
const demo = { active:false, tick:0, scIdx:0, phIdx:0, phTick:0, ctx:null, iid:null, ramping:false, rampTimeout:null };
// Per-module stopped set — tracks which modules the user has individually stopped
const stoppedModules = new Set();
let _incID = 1000;

// ── Notification badge state ──────────────────────────────────
const tabEventCounts = {};
const tabLastViewed  = {};
let currentTab = 'launcher';
const typeToTab = {
  alert:'alerts', anomaly:'anomalies', sap:'sap', zt:'zero-trust',
  cred:'credentials', comp:'compliance', dlp:'dlp', inc:'incidents',
  shadow:'shadow', sbom:'sbom', cloud:'cloud', audit:'audit',
  conn:'connectors', traffic:'traffic', webhook:'webhooks',
};

// ── KPI state ─────────────────────────────────────────────────
let kpiBlocked = 2847;
const FW_SCORES = { SOX:94, GDPR:87, "PCI-DSS":91, "NIST-CSF":96, ISO27001:89, HIPAA:93 };

// ── DOM ───────────────────────────────────────────────────────
const $  = id => document.getElementById(id);
const ui = {
  backendStatus:$("backend-status"), statusDot:$("status-dot"),
  eventsTotal:$("events-processed"), streamUpdated:$("stream-last-updated"),
  // exec KPIs
  kpiBlocked:$("kpi-blocked"), kpiSaved:$("kpi-saved"),
  kpiCompliance:$("kpi-compliance"), kpiMttd:$("kpi-mttd"),
  // scenario banner
  scenarioBanner:$("scenario-banner"), scBadge:$("scenario-badge"),
  scName:$("scenario-name"), scPhase:$("scenario-phase-text"),
  scProgress:$("scenario-progress-fill"),
  scIp:$("scenario-attacker-ip"), scUser:$("scenario-attacker-user"),
  // stat cards
  totalAlerts:$("total-alerts"), critAlerts:$("critical-alerts"),
  avgLatency:$("avg-latency"), trendAlerts:$("trend-alerts"),
  anomalyCount:$("anomaly-count"), dlpCount:$("dlp-count"),
  shadowCount:$("shadow-count"), sapCount:$("sap-count"),
  compCount:$("compliance-count"), incCount:$("incident-count"),
  sbomCount:$("sbom-count"), ztCount:$("zt-count"),
  credCount:$("cred-count"), cloudCount:$("cloud-count"),
  gwTotalCount:$("gw-total-count"), rulesCount:$("rules-count"),
  // tabs
  scenarioFilter:$("scenario-filter"), severityFilter:$("severity-filter"),
  alertsList:$("alerts-list"), alertsEmpty:$("alerts-empty"),
  auditFilter:$("audit-module-filter"), auditBody:$("audit-body"), auditEmpty:$("audit-empty"),
  gwTotal:$("gw-total"), gwOffHours:$("gw-off-hours"), gwBulk:$("gw-bulk"), gwVelocity:$("gw-velocity"),
  gatewayList:$("gateway-list"), gatewayEmpty:$("gateway-empty"),
  anomTotal:$("anom-total"), anomHigh:$("anom-high"), anomNewEp:$("anom-new-ep"),
  anomalyList:$("anomaly-list"), anomalyEmpty:$("anomaly-empty"),
  dlpBulk:$("dlp-bulk"), dlpStaging:$("dlp-staging"), dlpBlocklist:$("dlp-blocklist"),
  dlpList:$("dlp-list"), dlpEmpty:$("dlp-empty"),
  shadowTotal:$("shadow-total"), shadowUnique:$("shadow-unique"),
  shadowList:$("shadow-list"), shadowEmpty:$("shadow-empty"),
  sapTotal:$("sap-total"), sapAnomalous:$("sap-anomalous"),
  sapList:$("sap-list"), sapEmpty:$("sap-empty"),
  compViolations:$("comp-violations"), compWarnings:$("comp-warnings"),
  compPassed:$("comp-passed"), compFrameworks:$("comp-frameworks"),
  complianceList:$("compliance-list"), complianceEmpty:$("compliance-empty"),
  compScorecard:$("compliance-scorecard"),
  incOpen:$("inc-open"), incInv:$("inc-investigating"),
  incResolved:$("inc-resolved"), incPlaybooks:$("inc-playbooks"),
  incidentsList:$("incidents-list"), incidentsEmpty:$("incidents-empty"),
  playbookTracker:$("active-playbook-tracker"),
  sbomTotal:$("sbom-total"), sbomCve:$("sbom-cve"),
  sbomInsecure:$("sbom-insecure"), sbomClean:$("sbom-clean"),
  sbomList:$("sbom-list"), sbomEmpty:$("sbom-empty"),
  ruleBulk:$("rule-bulk"), ruleOffHours:$("rule-off-hours"),
  ruleShadow:$("rule-shadow"), ruleVelocity:$("rule-velocity"), ruleOther:$("rule-other"),
  rulesList:$("rules-list"), rulesEmpty:$("rules-empty"),
  ztAllow:$("zt-allow"), ztDeny:$("zt-deny"), ztChallenge:$("zt-challenge"), ztAvgRisk:$("zt-avg-risk"),
  ztList:$("zt-list"), ztEmpty:$("zt-empty"),
  credIssued:$("cred-issued"), credRotated:$("cred-rotated"), credRevoked:$("cred-revoked"), credAccessed:$("cred-accessed"),
  credList:$("cred-list"), credEmpty:$("cred-empty"),
  cloudCritical:$("cloud-critical"), cloudHigh:$("cloud-high"),
  cloudAws:$("cloud-aws"), cloudGcp:$("cloud-gcp"), cloudAzure:$("cloud-azure"),
  cloudList:$("cloud-list"), cloudEmpty:$("cloud-empty"),
  moduleGrid:$("module-grid"),
  riskLabel:$("risk-label"),
  sidebar:$("sidebar"), sidebarToggle:$("sidebar-toggle"), sidebarOverlay:$("sidebar-overlay"),
};

// ── Charts ────────────────────────────────────────────────────
let alertChart=null, severityChart=null, rulesChart=null, riskGaugeChart=null;
const alertTimeline = [];

function initCharts() {
  const gc = "var(--border-subtle)", tc = "var(--text-dim)";

  const actx = $("alert-chart").getContext("2d");
  const ag = actx.createLinearGradient(0,0,0,190);
  ag.addColorStop(0,"rgba(91,141,239,0.15)"); ag.addColorStop(1,"rgba(91,141,239,0)");
  alertChart = new Chart(actx, {
    type:"line",
    data:{ labels:[], datasets:[{ label:"Alerts", data:[], borderColor:"var(--accent)",
      backgroundColor:ag, borderWidth:2, fill:true, tension:0.4, pointRadius:0,
      pointHoverRadius:5, pointHoverBackgroundColor:"var(--accent)", pointHoverBorderColor:"var(--bg-card)", pointHoverBorderWidth:2 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:400},
      interaction:{mode:"index",intersect:false},
      scales:{
        x:{grid:{color:gc,drawBorder:false},ticks:{color:tc,font:{size:10,family:"Inter"},maxTicksLimit:8},border:{display:false}},
        y:{beginAtZero:true,grid:{color:gc,drawBorder:false},ticks:{color:tc,font:{size:10,family:"Inter"},precision:0,maxTicksLimit:5},border:{display:false}}
      },
      plugins:{ legend:{display:false},
        tooltip:{backgroundColor:"var(--panel-active)",titleColor:"var(--text-hi)",bodyColor:"var(--text-mid)",
          borderColor:"var(--border)",borderWidth:1,cornerRadius:8,padding:10,titleFont:{weight:"600"},displayColors:false} } }
  });

  severityChart = new Chart($("severity-chart").getContext("2d"), {
    type:"doughnut",
    data:{ labels:["Critical","High","Medium","Low"],
      datasets:[{ data:[0,0,0,0], backgroundColor:[
        getComputedStyle(document.documentElement).getPropertyValue('--critical').trim() || "#ef4444",
        getComputedStyle(document.documentElement).getPropertyValue('--orange').trim() || "#ea580c",
        getComputedStyle(document.documentElement).getPropertyValue('--warning').trim() || "#f59e0b",
        getComputedStyle(document.documentElement).getPropertyValue('--ok').trim() || "#10b981",
      ],
        borderColor:"var(--bg-card)", borderWidth:3, hoverOffset:8 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:600},
      cutout:"70%",
      plugins:{ legend:{position:"bottom",labels:{color:"var(--text-muted)",font:{size:10,family:"Inter"},padding:12,usePointStyle:true,pointStyleWidth:8}},
        tooltip:{backgroundColor:"var(--panel-active)",titleColor:"var(--text-hi)",bodyColor:"var(--text-mid)",borderColor:"var(--border)",borderWidth:1,cornerRadius:8,padding:10} } }
  });

  rulesChart = new Chart($("rules-chart").getContext("2d"), {
    type:"doughnut",
    data:{ labels:["Bulk Extract","Off-Hours","Shadow EP","Velocity","Other"],
      datasets:[{ data:[0,0,0,0,0], backgroundColor:[
        getComputedStyle(document.documentElement).getPropertyValue('--critical').trim() || "#ef4444",
        getComputedStyle(document.documentElement).getPropertyValue('--warning').trim() || "#f59e0b",
        getComputedStyle(document.documentElement).getPropertyValue('--orange').trim() || "#ea580c",
        getComputedStyle(document.documentElement).getPropertyValue('--accent').trim() || "#3b82f6",
        getComputedStyle(document.documentElement).getPropertyValue('--purple').trim() || "#8b5cf6",
      ],
        borderColor:"var(--bg-card)", borderWidth:3, hoverOffset:8 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:600},
      cutout:"70%",
      plugins:{ legend:{position:"bottom",labels:{color:"var(--text-muted)",font:{size:10,family:"Inter"},padding:10,usePointStyle:true,pointStyleWidth:8}},
        tooltip:{backgroundColor:"var(--panel-active)",titleColor:"var(--text-hi)",bodyColor:"var(--text-mid)",borderColor:"var(--border)",borderWidth:1,cornerRadius:8,padding:10} } }
  });

  const rgEl = $("risk-gauge-chart");
  if (rgEl) {
    riskGaugeChart = new Chart(rgEl.getContext("2d"), {
      type:"doughnut",
      data:{ datasets:[{ data:[0,100], backgroundColor:[
        getComputedStyle(document.documentElement).getPropertyValue('--critical').trim() || "#ef4444",
        "var(--border-subtle)"
      ],
        borderWidth:0, circumference:180, rotation:270 }] },
      options:{ responsive:true, maintainAspectRatio:false, cutout:"75%",
        animation:{duration:800},
        plugins:{ legend:{display:false}, tooltip:{enabled:false} } }
    });
  }
}

// ── Animated counter ──────────────────────────────────────────
const counterCache = new Map();
function animateValue(el, newVal) {
  if (!el) return;
  const key = el.id || Math.random();
  const from = counterCache.get(key) || 0;
  const to = parseInt(newVal) || 0;
  if (from === to) { el.textContent = to; return; }
  counterCache.set(key, to);
  const dur = 400, start = performance.now();
  const step = now => {
    const p = Math.min((now-start)/dur,1);
    const e = 1-Math.pow(1-p,3);
    el.textContent = Math.round(from+(to-from)*e);
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ── Helpers ───────────────────────────────────────────────────
const _rnd = a => a[Math.floor(Math.random()*a.length)];
const _int = (a,b) => Math.floor(Math.random()*(b-a+1))+a;
const _flt = (a,b) => +(Math.random()*(b-a)+a).toFixed(3);
const _uid = () => Math.random().toString(36).slice(2,10);
const _now = () => new Date().toISOString();
const _evt = (type, fields) => ({ ts:_now(), _type:type, ...fields });

const ts  = v => { if(!v) return "—"; try { return new Date(v).toLocaleTimeString(); } catch { return v; } };
const ms  = v => v==null?"—":v<1000?`${v}ms`:`${(v/1000).toFixed(2)}s`;
const byt = v => { if(!v) return "—"; if(v<1048576) return `${(v/1024).toFixed(1)} KB`; return `${(v/1048576).toFixed(1)} MB`; };
const scl = s => ({"bulk_extraction":"Bulk Extraction","off_hours_rfc":"Off-Hours RFC",
  "shadow_endpoint":"Shadow Endpoint","velocity_anomaly":"Velocity Anomaly",
  "credential_abuse":"Credential Abuse","privilege_escalation":"Privilege Escalation",
  "data_staging":"Data Staging","geo_anomaly":"Geo Anomaly","data_exfil":"Data Exfil"})[s]||(s||"").replace(/_/g," ");

// ── Reference data ────────────────────────────────────────────
const _D = {
  users:    ["USR001","USR002","USR007","USR013","SVCACCT","jsmith","agarwal","lchen","mrodriguez","BATCHJOB"],
  priv:     ["ROOT","SYSADMIN","SEC_ADMIN","BATCHJOB","INT_USER"],
  ipsInt:   ["10.42.0.15","10.42.1.34","10.42.2.82","10.42.3.61","10.42.5.60","10.42.0.74"],
  ipsExt:   ["185.193.67.170","185.116.29.233","45.77.200.1","91.108.4.1","103.21.45.9","212.73.150.9"],
  rfcOk:    ["BAPI_CUSTOMER_GETLIST","BAPI_MATERIAL_GETLIST","RFC_GET_LOCAL_DESTINATIONS","BAPI_SALESORDER_GETLIST"],
  rfcRisky: ["RFC_READ_TABLE","BAPI_USER_GETLIST","SUSR_USER_AUTH_FOR_OBJ_GET","RFC_ABAP_INSTALL_AND_RUN"],
  rfcShadow:["ZRFC_EXFIL_DATA","ZTEST_BACKDOOR","Z_HIDDEN_EXTRACT","ZRFC_DUMP_PAYROLL","Z_RFC_SAPCONTROL"],
  sapTools: ["read_table","list_users","get_auth_objects","export_payroll_data","change_user_auth","modify_auth_profile","delete_table_entries","run_report"],
  fws:      ["SOX","GDPR","ISO27001","PCI-DSS","NIST-CSF","HIPAA"],
  controls: ["AC-2","AC-6","AU-2","IA-2","SC-7","SI-3","CM-2","RA-5","SA-9","IR-4"],
  providers:["aws","gcp","azure"],
  resources:["arn:aws:s3:::prod-payroll-data","arn:aws:iam:::role/AdminRole","projects/prod/db-main","subscriptions/prod/vm-app01"],
  findings: ["PUBLIC_BUCKET","UNENCRYPTED_DB","OVERPRIVILEGED_ROLE","OPEN_SECURITY_GROUP","MFA_DISABLED","ROOT_ACCESS_USED","LOGGING_DISABLED"],
  sbomPkgs: ["m01-api-gateway-shield","m05-sap-mcp-suite","fastapi","redis-client","pydantic","uvicorn","shared-libs"],
  playbooks:["PB-DATA-EXFIL","PB-PRIV-ESC","PB-SHADOW-API","PB-CLOUD-BREACH","PB-ACCOUNT-TAKEOVER"],
};

const PLAYBOOK_STEPS = {
  "PB-DATA-EXFIL":   ["Isolate session","Block source IP","Revoke credentials","Notify DLP team","Preserve forensics","Regulatory review"],
  "PB-PRIV-ESC":     ["Terminate session","Reset privileges","Audit auth changes","Notify security","Review MFA","Post-incident report"],
  "PB-SHADOW-API":   ["Block RFC endpoint","Alert SAP admin","Scan for variants","Update firewall","Document findings","Patch validation"],
  "PB-CLOUD-BREACH": ["Revoke cloud keys","Remediate misconfig","Enable CloudTrail","Notify CISO","Scan IAM roles","Compliance review"],
  "PB-ACCOUNT-TAKEOVER":["Lock account","Force password reset","Review audit trail","Notify user","Check lateral movement","Enhanced monitoring"],
};

// ── Scenarios ─────────────────────────────────────────────────
const SCENARIOS = [
  { name:"Insider Threat",
    phases:[
      { label:"Normal Operations", ticks:4, fn:(c)=>[
        _evt("alert",  {scenario:"off_hours_rfc",severity:"low",source_ip:c.ip,user_id:c.user,message:`Off-hours RFC access by ${c.user}`,latencyMs:_int(10,40)}),
        _evt("anomaly",{anomaly_score:_flt(0.15,0.30),classification:"off_hours_pattern",source_ip:c.ip,user_id:c.user}),
        _evt("zt",     {decision:"allow",risk_score:_flt(0.10,0.25),user_id:c.user,source_ip:c.ip,failed_controls:[]}),
        _evt("audit",  {actor:"m04-zero-trust-fabric",action:"access_allowed",module:"m04-zero-trust-fabric",status:"ok"}),
      ]},
      { label:"Reconnaissance", ticks:4, fn:(c)=>[
        _evt("alert",  {scenario:"off_hours_rfc",severity:"medium",source_ip:c.ip,user_id:c.user,message:`Repeated off-hours calls — ${c.user} queried ${_rnd(_D.rfcRisky)}`,latencyMs:_int(20,60)}),
        _evt("sap",    {tool_name:"list_users",anomalous:false,user_id:c.user,tenant_id:"PROD-001",result:"success"}),
        _evt("sap",    {tool_name:"get_auth_objects",anomalous:true,flagged:true,user_id:c.user,tenant_id:"PROD-001",result:"success"}),
        _evt("anomaly",{anomaly_score:_flt(0.45,0.65),classification:"off_hours_pattern",source_ip:c.ip,user_id:c.user}),
        _evt("zt",     {decision:"challenge",risk_score:_flt(0.52,0.70),user_id:c.user,source_ip:c.ip,failed_controls:["time_risk","behaviour_risk"]}),
        _evt("audit",  {actor:"m08-anomaly-detection",action:"anomaly_scored",module:"m08-anomaly-detection",status:"ok"}),
      ]},
      { label:"Bulk Extraction", ticks:5, fn:(c)=>[
        _evt("alert",  {scenario:"bulk_extraction",severity:"critical",source_ip:c.ip,user_id:c.user,message:`Bulk RFC_READ_TABLE — ${_int(50,120)}K rows by ${c.user}`,latencyMs:_int(50,90)}),
        _evt("dlp",    {rule:"bulk_export_detected",severity:"critical",bytes_out:_int(12e6,60e6),row_count:_int(50000,120000),user_id:c.user,destination:c.ip}),
        _evt("anomaly",{anomaly_score:_flt(0.82,0.97),classification:"velocity_spike",source_ip:c.ip,user_id:c.user}),
        _evt("sap",    {tool_name:"export_payroll_data",anomalous:true,flagged:true,user_id:c.user,result:"success",tenant_id:"PROD-001"}),
        _evt("zt",     {decision:"deny",risk_score:_flt(0.85,0.98),user_id:c.user,source_ip:c.ip,failed_controls:["behaviour_risk","time_risk","geo_risk"]}),
        _evt("comp",   {framework:"SOX",control_id:"AC-6",result:"violation",description:`Excessive data access by ${c.user}`,severity:"critical"}),
        _evt("inc",    {title:"Bulk data exfiltration detected",status:"open",severity:"critical",source_module:"m09-dlp",playbook_id:"PB-DATA-EXFIL"}),
        _evt("audit",  {actor:"m12-rules-engine",action:"alert_published",module:"m12-rules-engine",status:"ok"}),
      ]},
      { label:"Containment", ticks:4, fn:(c)=>[
        _evt("cred",   {action:"revoked",key:`key-${c.user}-${_uid().slice(0,6)}`,tenant_id:"PROD-001",status:"revoked"}),
        _evt("inc",    {title:"Bulk data exfiltration detected",status:"investigating",severity:"critical",source_module:"m10-incident-response",playbook_id:"PB-DATA-EXFIL",playbook_run:true}),
        _evt("comp",   {framework:"GDPR",control_id:"SA-9",result:"violation",description:"Data breach notification required",severity:"critical"}),
        _evt("zt",     {decision:"deny",risk_score:0.99,user_id:c.user,source_ip:c.ip,failed_controls:["mfa_required","device_compliant","geo_risk","behaviour_risk"]}),
        _evt("audit",  {actor:"m10-incident-response",action:"playbook_executed",module:"m10-incident-response",status:"ok"}),
        _evt("audit",  {actor:"m06-credential-vault",action:"credential_revoked",module:"m06-credential-vault",status:"ok"}),
      ]},
    ],
    ctx: () => ({ user:_rnd(_D.priv), ip:_rnd(_D.ipsInt) }),
  },
  { name:"External Attack",
    phases:[
      { label:"External Probe", ticks:3, fn:(c)=>[
        _evt("alert",  {scenario:"geo_anomaly",severity:"medium",source_ip:c.ip,user_id:"UNKNOWN",message:`Geo anomaly — connection from ${c.ip}`,latencyMs:_int(30,80)}),
        _evt("zt",     {decision:"challenge",risk_score:_flt(0.55,0.72),user_id:"UNKNOWN",source_ip:c.ip,failed_controls:["geo_risk","device_compliant"]}),
        _evt("anomaly",{anomaly_score:_flt(0.40,0.60),classification:"geo_anomaly",source_ip:c.ip,user_id:"UNKNOWN"}),
        _evt("cloud",  {provider:"aws",finding_type:"MFA_DISABLED",raw_severity:"medium",resource_id:"arn:aws:iam:::role/AdminRole",risk_score:_flt(0.45,0.65)}),
      ]},
      { label:"Shadow Endpoint", ticks:4, fn:(c)=>[
        _evt("shadow", {endpoint:c.rfcFn,severity:"critical",user_id:c.user,source_ip:c.ip,message:`Unknown RFC ${c.rfcFn} from external ${c.ip}`,call_count:_int(3,15)}),
        _evt("alert",  {scenario:"shadow_endpoint",severity:"critical",source_ip:c.ip,user_id:c.user,message:`SHADOW ENDPOINT: ${c.rfcFn} called ${_int(3,15)} times`,latencyMs:_int(40,90)}),
        _evt("anomaly",{anomaly_score:_flt(0.80,0.95),classification:"new_endpoint",source_ip:c.ip,user_id:c.user}),
        _evt("zt",     {decision:"deny",risk_score:_flt(0.88,0.99),user_id:c.user,source_ip:c.ip,failed_controls:["geo_risk","mfa_required","behaviour_risk"]}),
        _evt("inc",    {title:"Shadow RFC endpoint invoked",status:"open",severity:"critical",source_module:"m11-shadow-integration",playbook_id:"PB-SHADOW-API"}),
        _evt("audit",  {actor:"m11-shadow-integration",action:"shadow_endpoint_detected",module:"m11-shadow-integration",status:"ok"}),
      ]},
      { label:"Cloud Compromise", ticks:5, fn:(c)=>[
        _evt("cloud",  {provider:"aws",finding_type:"PUBLIC_BUCKET",raw_severity:"critical",resource_id:"arn:aws:s3:::prod-payroll-data",risk_score:_flt(0.88,0.99)}),
        _evt("cloud",  {provider:"gcp",finding_type:"OVERPRIVILEGED_ROLE",raw_severity:"critical",resource_id:"projects/prod/db-main",risk_score:_flt(0.82,0.96)}),
        _evt("cloud",  {provider:"azure",finding_type:"ROOT_ACCESS_USED",raw_severity:"critical",resource_id:"subscriptions/prod/vm-app01",risk_score:_flt(0.91,0.99)}),
        _evt("dlp",    {rule:"pii_exfiltration",severity:"critical",bytes_out:_int(100e6,500e6),row_count:_int(100000,500000),user_id:c.user,destination:c.ip}),
        _evt("alert",  {scenario:"data_staging",severity:"critical",source_ip:c.ip,user_id:c.user,message:`Data staging — ${_int(100,500)}MB to external`,latencyMs:_int(60,90)}),
        _evt("comp",   {framework:"PCI-DSS",control_id:"SC-7",result:"violation",description:"Cloud data exfiltration violates PCI-DSS SC-7",severity:"critical"}),
        _evt("inc",    {title:"Cloud misconfiguration exploited",status:"investigating",severity:"critical",source_module:"m15-multicloud-ispm",playbook_id:"PB-CLOUD-BREACH",playbook_run:true}),
        _evt("sbom",   {target:"m01-api-gateway-shield",scan_status:"VULNERABLE",cve_count:_int(3,12),insecure_rfc_count:_int(1,5)}),
      ]},
      { label:"Resolved", ticks:3, fn:(c)=>[
        _evt("cred",   {action:"rotated",key:`key-aws-admin-${_uid().slice(0,6)}`,tenant_id:"PROD-001"}),
        _evt("cred",   {action:"revoked",key:`key-svc-${_uid().slice(0,6)}`,tenant_id:"PROD-001",status:"revoked"}),
        _evt("comp",   {framework:"ISO27001",control_id:"IR-4",result:"pass",description:"Incident response controls passed",severity:"low"}),
        _evt("inc",    {title:"Cloud misconfiguration exploited",status:"resolved",severity:"critical",source_module:"m10-incident-response",playbook_id:"PB-CLOUD-BREACH"}),
        _evt("audit",  {actor:"m10-incident-response",action:"incident_resolved",module:"m10-incident-response",status:"ok"}),
      ]},
    ],
    ctx: () => ({ user:_rnd([..._D.priv,"UNKNOWN"]), ip:_rnd(_D.ipsExt), rfcFn:_rnd(_D.rfcShadow) }),
  },
  { name:"Credential Abuse",
    phases:[
      { label:"Credential Stuffing", ticks:3, fn:(c)=>[
        _evt("alert",  {scenario:"credential_abuse",severity:"high",source_ip:c.ip,user_id:c.user,message:`Credential ${c.user} used from ${_int(3,8)} IPs simultaneously`,latencyMs:_int(20,50)}),
        _evt("zt",     {decision:"challenge",risk_score:_flt(0.60,0.78),user_id:c.user,source_ip:c.ip,failed_controls:["device_compliant","mfa_required"]}),
        _evt("cred",   {action:"accessed",key:`key-${c.user}-session`,tenant_id:"PROD-001"}),
        _evt("anomaly",{anomaly_score:_flt(0.50,0.70),classification:"baseline_deviation",source_ip:c.ip,user_id:c.user}),
      ]},
      { label:"Privilege Escalation", ticks:4, fn:(c)=>[
        _evt("alert",  {scenario:"privilege_escalation",severity:"critical",source_ip:c.ip,user_id:c.user,message:`Privilege escalation — SUSR_USER_AUTH_FOR_OBJ_GET by ${c.user}`,latencyMs:_int(40,90)}),
        _evt("sap",    {tool_name:"change_user_auth",anomalous:true,flagged:true,user_id:c.user,result:"success",tenant_id:"PROD-001"}),
        _evt("sap",    {tool_name:"modify_auth_profile",anomalous:true,flagged:true,user_id:c.user,result:"success",tenant_id:"PROD-001"}),
        _evt("anomaly",{anomaly_score:_flt(0.87,0.99),classification:"privilege_escalation",source_ip:c.ip,user_id:c.user}),
        _evt("comp",   {framework:"SOX",control_id:"AC-2",result:"violation",description:`Unauthorized privilege escalation by ${c.user}`,severity:"critical"}),
        _evt("comp",   {framework:"NIST-CSF",control_id:"IA-2",result:"violation",description:"MFA bypassed during privilege change",severity:"critical"}),
        _evt("zt",     {decision:"deny",risk_score:0.97,user_id:c.user,source_ip:c.ip,failed_controls:["behaviour_risk","mfa_required","device_compliant","time_risk"]}),
        _evt("inc",    {title:"Unauthorized privilege escalation",status:"open",severity:"critical",source_module:"m04-zero-trust-fabric",playbook_id:"PB-PRIV-ESC"}),
      ]},
      { label:"SAP Exfiltration", ticks:4, fn:(c)=>[
        _evt("sap",    {tool_name:"export_payroll_data",anomalous:true,flagged:true,user_id:c.user,result:"success",tenant_id:"PROD-001"}),
        _evt("sap",    {tool_name:"delete_table_entries",anomalous:true,flagged:true,user_id:c.user,result:"partial",tenant_id:"PROD-001"}),
        _evt("dlp",    {rule:"staging_area_write",severity:"critical",bytes_out:_int(5e6,50e6),row_count:_int(10000,80000),user_id:c.user,destination:"10.9.0.5"}),
        _evt("dlp",    {rule:"blocklist_destination",severity:"critical",bytes_out:_int(2e6,20e6),row_count:_int(5000,40000),user_id:c.user,destination:"mega.nz"}),
        _evt("shadow", {endpoint:"ZRFC_DUMP_PAYROLL",severity:"critical",user_id:c.user,source_ip:c.ip,message:`Payroll dump RFC by compromised account ${c.user}`}),
        _evt("inc",    {title:"Anomalous SAP query pattern",status:"investigating",severity:"critical",source_module:"m05-sap-mcp-suite",playbook_id:"PB-PRIV-ESC",playbook_run:true}),
        _evt("audit",  {actor:"m09-dlp",action:"dlp_violation",module:"m09-dlp",status:"ok"}),
      ]},
      { label:"Recovery", ticks:3, fn:(c)=>[
        _evt("cred",   {action:"revoked",key:`key-${c.user}-all`,tenant_id:"PROD-001",status:"revoked"}),
        _evt("cred",   {action:"rotated",key:`key-admin-${_uid().slice(0,6)}`,tenant_id:"PROD-001"}),
        _evt("cred",   {action:"issued",key:`key-new-${_uid().slice(0,6)}`,tenant_id:"PROD-001"}),
        _evt("comp",   {framework:"HIPAA",control_id:"PS-3",result:"pass",description:"Access review completed",severity:"low"}),
        _evt("inc",    {title:"Unauthorized privilege escalation",status:"resolved",severity:"critical",source_module:"m10-incident-response",playbook_id:"PB-PRIV-ESC"}),
        _evt("sbom",   {target:"m05-sap-mcp-suite",scan_status:"CLEAN",cve_count:0,insecure_rfc_count:0}),
        _evt("audit",  {actor:"m06-credential-vault",action:"emergency_rotation",module:"m06-credential-vault",status:"ok"}),
      ]},
    ],
    ctx: () => ({ user:_rnd(_D.priv), ip:_rnd([..._D.ipsInt,..._D.ipsExt]) }),
  },
];

// ── Demo tick ─────────────────────────────────────────────────
function demoTick() {
  const sc    = SCENARIOS[demo.scIdx % SCENARIOS.length];
  const phase = sc.phases[demo.phIdx % sc.phases.length];
  demo.ctx    = demo.ctx || sc.ctx();

  const evts = phase.fn(demo.ctx);

  // Background normal traffic every other tick
  if (demo.tick % 2 === 0) {
    evts.push(
      _evt("alert",  {scenario:_rnd(["off_hours_rfc","velocity_anomaly"]),severity:_rnd(["medium","low"]),
        source_ip:_rnd(_D.ipsInt),user_id:_rnd(_D.users),message:`Normal RFC — ${_rnd(_D.rfcOk)}`,latencyMs:_int(5,30)}),
      _evt("zt",     {decision:"allow",risk_score:_flt(0.05,0.25),user_id:_rnd(_D.users),source_ip:_rnd(_D.ipsInt),failed_controls:[]}),
      _evt("cred",   {action:_rnd(["issued","rotated"]),key:`key-${_uid()}`,tenant_id:_rnd(["PROD-001","DEV-001"])}),
      _evt("audit",  {actor:_rnd(["m01-api-gateway-shield","m03-traffic-analyzer","m12-rules-engine"]),action:"event_processed",module:_rnd(["m01-api-gateway-shield","m12-rules-engine"]),status:"ok"}),
    );
    if (Math.random() > 0.5)
      evts.push(_evt("sbom",{target:_rnd(_D.sbomPkgs),scan_status:Math.random()>0.6?"CLEAN":"VULNERABLE",cve_count:_int(0,8),insecure_rfc_count:_int(0,3)}));
    if (Math.random() > 0.6)
      evts.push(_evt("cloud",{provider:_rnd(_D.providers),finding_type:_rnd(_D.findings),raw_severity:_rnd(["high","medium","low"]),resource_id:_rnd(_D.resources),risk_score:_flt(0.3,0.8)}));
    // M02 Connector Sentinel
    if (Math.random() > 0.55)
      evts.push(_evt("conn",{platform:_rnd(["sap_btp","mulesoft","boomi","workato"]),connector:_rnd(["SAP-S4HANA-Cloud","MuleSoft-HTTP","Boomi-SFTP","BTP-RFC-Dest"]),status:Math.random()>0.75?"alert":Math.random()>0.5?"misconfigured":"healthy",finding:_rnd(["Credential leak in config","Unauthorized data flow","TLS 1.0 detected","Open port 8080","Over-privileged OAuth scope","Clean"]),source_system:_rnd(["S4H-PROD","BTP-EU10","ARIBA","SUCCESSFACTORS"]),dest_system:_rnd(["SALESFORCE","WORKDAY","DATABRICKS","S3-BUCKET"])}));
    // M03 Traffic Analyzer
    if (Math.random() > 0.5)
      evts.push(_evt("traffic",{source:_rnd(["S4H-PROD","BTP-EU10","ARIBA"]),destination:_rnd(["SALESFORCE","WORKDAY","DATABRICKS","EXTERNAL-API"]),classification:_rnd(["PII","PHI","FINANCIAL","STANDARD"]),direction:_rnd(["inbound","outbound"]),bytes:_int(50000,5000000),fields_detected:_rnd(["EMAIL,PHONE","SSN,DOB","IBAN,BIC","PRODUCT_ID"]),policy_violation:Math.random()>0.7}));
    // M14 Webhook Gateway
    if (Math.random() > 0.6)
      evts.push(_evt("webhook",{source:_rnd(["github","slack","pagerduty","custom"]),event_type:_rnd(["push","alert","incident.trigger","order.created","payment.received"]),result:_rnd(["accepted","accepted","accepted","rejected","rate_limited"]),signature_valid:Math.random()>0.15,source_ip:_rnd(_D.ipsExt),latency_ms:_int(5,80)}));
  }

  const push = (arr, item, max=80) => { arr.unshift(item); if (arr.length>max) arr.pop(); };
  const auditMap = {
    alert:"m12-rules-engine", anomaly:"m08-anomaly-detection", sap:"m05-sap-mcp-suite",
    zt:"m04-zero-trust-fabric", cred:"m06-credential-vault", comp:"m07-compliance-autopilot",
    dlp:"m09-dlp", inc:"m10-incident-response", shadow:"m11-shadow-integration",
    sbom:"m13-sbom-scanner", cloud:"m15-multicloud-ispm",
    conn:"m02-connector-sentinel", traffic:"m03-traffic-analyzer", webhook:"m14-webhook-gateway",
  };

  // Filter events for stopped modules before pushing
  const activeEvts = evts.filter(ev => {
    const mod = auditMap[ev._type];
    return !mod || !stoppedModules.has(mod);
  });
  for (const ev of activeEvts) {
    const t = ev._type; delete ev._type;
    if (t==="alert")   push(alerts, ev, 80);
    if (t==="anomaly") push(anomalies, ev, 60);
    if (t==="sap")     push(sapEvents, ev, 60);
    if (t==="zt")      push(ztEvents, ev, 60);
    if (t==="cred")    push(credEvents, ev, 60);
    if (t==="comp")    push(compEvents, ev, 60);
    if (t==="dlp")     push(dlpEvents, ev, 60);
    if (t==="inc")     { ev.incident_id = ev.incident_id || `INC-${++_incID}`; push(incEvents, ev, 40); }
    if (t==="shadow")  push(shadowEvents, ev, 40);
    if (t==="sbom")    push(sbomEvents, ev, 40);
    if (t==="cloud")   push(cloudEvents, ev, 60);
    if (t==="conn")    push(connEvents, ev, 60);
    if (t==="traffic") push(trafficEvents, ev, 60);
    if (t==="webhook") push(webhookEvents, ev, 60);
    if (t==="audit")   push(auditRows, ev, 60);
    else if (auditMap[t]) push(auditRows, {actor:auditMap[t],action:t+"_event",module:auditMap[t],status:"ok",ts:ev.ts}, 60);
    // Increment badge counts for tabs not currently viewed
    const tab = typeToTab[t] || (t==="audit" ? "audit" : null);
    if (tab) tabEventCounts[tab] = (tabEventCounts[tab] || 0) + 1;
  }

  // Advance phase/scenario
  demo.phTick++;
  if (demo.phTick >= phase.ticks) {
    demo.phTick = 0;
    demo.phIdx++;
    if (demo.phIdx >= sc.phases.length) {
      demo.phIdx = 0;
      demo.scIdx++;
      demo.ctx = null;
      const next = SCENARIOS[demo.scIdx % SCENARIOS.length];
      showToast(`🔴 New scenario: ${next.name}`, "critical", 4000);
    }
  }
  demo.tick++;
  kpiBlocked += _int(1,3);
  updateAllUI();
}

// Gentle warm-up: fire just a few ticks with a growing gap so events
// trickle in naturally instead of dumping everything at once.
function rampUp(onDone) {
  const WARMUP_DELAYS = [700, 1100, 1600, 2200]; // ~5.6s total, 4 events
  demo.ramping = true;
  let step = 0;
  (function tick() {
    if (step >= WARMUP_DELAYS.length) {
      demo.ramping = false;
      demo.rampTimeout = null;
      if (onDone) onDone();
      return;
    }
    demoTick();
    demo.rampTimeout = setTimeout(tick, WARMUP_DELAYS[step++]);
  })();
}

function startDemo() {
  if (demo.active) return;
  demo.active = true;
  console.info("IntegriShield: real-time engine warming up — all 15 modules streaming");
  showToast("⚡ 15 modules online — events will stream in live", "info", 5000);
  rampUp(() => { demo.iid = setInterval(demoTick, POLL_MS); });
}

function stopDemo() {
  if (demo.iid) clearInterval(demo.iid);
  clearTimeout(demo.rampTimeout); demo.ramping = false; demo.rampTimeout = null;
  demo.iid = null;
  demo.active = false;
  stopAutoTour();
  clearAllBadges();
  const b = $("scenario-banner"); if (b) b.classList.add("hidden");
}

// ── Update all UI ─────────────────────────────────────────────
function updateAllUI() {
  const total   = alerts.length;
  const crit    = alerts.filter(a=>a.severity==="critical").length;
  const lats    = alerts.map(a=>+(a.latencyMs||0));
  const avgLat  = lats.length ? lats.reduce((s,v)=>s+v,0)/lats.length : 0;
  const allEvts = alerts.length+anomalies.length+sapEvents.length+ztEvents.length+
                  credEvents.length+compEvents.length+dlpEvents.length+incEvents.length+
                  shadowEvents.length+sbomEvents.length+cloudEvents.length;

  if (demo.active) {
    if (ui.backendStatus) ui.backendStatus.textContent = "DEMO MODE";
    if (ui.statusDot)     ui.statusDot.className = "status-dot online";
  }
  if (ui.eventsTotal)   ui.eventsTotal.textContent = allEvts.toLocaleString();
  if (ui.streamUpdated) ui.streamUpdated.textContent = `updated ${new Date().toLocaleTimeString()}`;

  animateValue(ui.totalAlerts, total);
  animateValue(ui.critAlerts,  crit);
  if (ui.avgLatency) ui.avgLatency.textContent = `${(avgLat/1000).toFixed(2)}s`;
  animateValue(ui.anomalyCount, anomalies.length);
  animateValue(ui.dlpCount,     dlpEvents.length);
  animateValue(ui.shadowCount,  shadowEvents.length);
  animateValue(ui.sapCount,     sapEvents.length);
  animateValue(ui.compCount,    compEvents.length);
  animateValue(ui.incCount,     incEvents.length);
  animateValue(ui.sbomCount,    sbomEvents.length);
  animateValue(ui.ztCount,      ztEvents.length);
  animateValue(ui.credCount,    credEvents.length);
  animateValue(ui.cloudCount,   cloudEvents.length);
  animateValue(ui.gwTotalCount, total);
  animateValue(ui.rulesCount,   alerts.filter(a=>a.scenario).length);

  if (ui.trendAlerts) {
    const d = total - prevAlertCount;
    ui.trendAlerts.textContent = d>0 ? `▲ +${d}` : d<0 ? `▼ ${d}` : "—";
    ui.trendAlerts.style.color = d>0 ? "var(--critical)" : d<0 ? "var(--ok)" : "var(--text-dim)";
  }
  prevAlertCount = total;

  // Charts
  alertTimeline.push({ t: new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}), count:total });
  if (alertTimeline.length>30) alertTimeline.shift();
  if (alertChart) {
    alertChart.data.labels           = alertTimeline.map(p=>p.t);
    alertChart.data.datasets[0].data = alertTimeline.map(p=>p.count);
    alertChart.update("none");
  }
  if (severityChart) {
    severityChart.data.datasets[0].data = [
      alerts.filter(a=>a.severity==="critical").length,
      alerts.filter(a=>a.severity==="high").length,
      alerts.filter(a=>a.severity==="medium").length,
      alerts.filter(a=>a.severity==="low").length,
    ];
    severityChart.update("none");
  }
  const KSCEN = ["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"];
  if (rulesChart) {
    rulesChart.data.datasets[0].data = [
      alerts.filter(a=>a.scenario==="bulk_extraction").length,
      alerts.filter(a=>a.scenario==="off_hours_rfc").length,
      alerts.filter(a=>a.scenario==="shadow_endpoint").length,
      alerts.filter(a=>a.scenario==="velocity_anomaly").length,
      alerts.filter(a=>!KSCEN.includes(a.scenario)).length,
    ];
    rulesChart.update("none");
  }

  // Risk gauge
  if (riskGaugeChart) {
    const maxScore  = anomalies.length ? Math.max(...anomalies.map(a=>parseFloat(a.anomaly_score||0))) : 0;
    const risk      = Math.min(100, Math.round((crit/Math.max(total,1))*60 + maxScore*40));
    const colors    = risk>75?["#ff4757","rgba(255,71,87,0.15)"]:risk>50?["#ff8b3d","rgba(255,139,61,0.15)"]:risk>25?["#ffa502","rgba(255,165,2,0.15)"]:["#2ed573","rgba(46,213,115,0.12)"];
    const riskLabel = risk>75?"CRITICAL":risk>50?"HIGH":risk>25?"MEDIUM":"LOW";
    riskGaugeChart.data.datasets[0].data           = [risk,100-risk];
    riskGaugeChart.data.datasets[0].backgroundColor = colors;
    riskGaugeChart.update("none");
    if (ui.riskLabel) { ui.riskLabel.textContent = `${riskLabel} · ${risk}%`; ui.riskLabel.style.color = colors[0]; }
  }

  // Pills
  const modStatus = {
    "m01-api-gateway-shield":{events:total},
    "m02-connector-sentinel":{events:connEvents.length},
    "m03-traffic-analyzer":{events:trafficEvents.length||_int(10,40)},
    "m04-zero-trust-fabric":{events:ztEvents.length},
    "m05-sap-mcp-suite":{events:sapEvents.length},
    "m06-credential-vault":{events:credEvents.length},
    "m07-compliance-autopilot":{events:compEvents.length},
    "m08-anomaly-detection":{events:anomalies.length},
    "m09-dlp":{events:dlpEvents.length},
    "m10-incident-response":{events:incEvents.length},
    "m11-shadow-integration":{events:shadowEvents.length},
    "m12-rules-engine":{events:total},
    "m13-sbom-scanner":{events:sbomEvents.length},
    "m14-webhook-gateway":{events:webhookEvents.length},
    "m15-multicloud-ispm":{events:cloudEvents.length},
  };
  updatePills(modStatus);
  if (ui.moduleGrid) renderModuleGrid(modStatus);

  // Exec KPIs (kpiBlocked is incremented in demoTick only)
  if (ui.kpiBlocked) animateValue(ui.kpiBlocked, kpiBlocked);
  if (ui.kpiSaved) {
    const s = kpiBlocked * 1558;
    ui.kpiSaved.textContent = s>=1e6 ? `$${(s/1e6).toFixed(1)}M` : `$${(s/1e3).toFixed(0)}K`;
  }
  if (ui.kpiCompliance) {
    const sc2 = Object.values(FW_SCORES);
    const viol = compEvents.filter(e=>(e.result||"").toLowerCase()==="violation").length;
    const adj  = Math.max(72, Math.round(sc2.reduce((a,b)=>a+b,0)/sc2.length - viol*0.5));
    ui.kpiCompliance.textContent = `${adj}%`;
  }
  if (ui.kpiMttd) {
    const base = 2.0 + Math.random() * 2.5;
    const load = Math.min(alerts.length / 50, 1.0) * 0.8;
    ui.kpiMttd.textContent = (base + load).toFixed(1) + 's';
  }

  // Scenario banner
  if (ui.scenarioBanner && demo.active) {
    ui.scenarioBanner.classList.remove("hidden");
    const sc  = SCENARIOS[demo.scIdx % SCENARIOS.length];
    const ph  = sc.phases[demo.phIdx % sc.phases.length];
    const prg = Math.round((demo.phTick / Math.max(ph.ticks,1)) * 100);
    const threat = !["Normal Operations","Resolved","Recovery","Containment"].includes(ph.label);
    if (ui.scBadge) {
      ui.scBadge.textContent  = threat ? "ACTIVE THREAT" : "MONITORING";
      ui.scBadge.className    = `scenario-badge ${threat?"":"scenario-badge-ok"}`;
      ui.scBadge.style.background = threat?"rgba(255,71,87,0.2)":"rgba(46,213,115,0.15)";
      ui.scBadge.style.color      = threat?"#ff4757":"#2ed573";
    }
    if (ui.scName)     ui.scName.textContent  = `${sc.name} · ${ph.label}`;
    if (ui.scPhase)    ui.scPhase.textContent  = `${demo.phIdx%sc.phases.length+1}/${sc.phases.length}`;
    if (ui.scProgress) ui.scProgress.style.width = `${prg}%`;
    if (demo.ctx) {
      if (ui.scIp)   ui.scIp.textContent   = demo.ctx.ip   || "—";
      if (ui.scUser) ui.scUser.textContent = demo.ctx.user || "—";
    }
  }

  renderActiveTab();
  updateBadges();
}

// ── Mini-stat click filter ────────────────────────────────────
function miniStatFilter(tabName, filterId, value) {
  navigateToTab(tabName);
  setTimeout(() => {
    const el = $(filterId);
    if (!el) return;
    el.value = value;
    el.dispatchEvent(new Event(el.tagName === 'SELECT' ? 'change' : 'input'));
  }, 80);
}

// ── Pills ─────────────────────────────────────────────────────
const PILL_MAP = {
  "m01-api-gateway-shield":"m01","m02-connector-sentinel":"m02",
  "m03-traffic-analyzer":"m03","m04-zero-trust-fabric":"m04",
  "m05-sap-mcp-suite":"m05","m06-credential-vault":"m06",
  "m07-compliance-autopilot":"m07","m08-anomaly-detection":"m08",
  "m09-dlp":"m09","m10-incident-response":"m10",
  "m11-shadow-integration":"m11","m12-rules-engine":"m12",
  "m13-sbom-scanner":"m13","m14-webhook-gateway":"m14",
  "m15-multicloud-ispm":"m15",
};
function updatePills(mods) {
  for (const [mod,id] of Object.entries(PILL_MAP)) {
    const el = $(`pill-${id}`);
    if (el) el.className = mods[mod] ? "pill pill-ok" : "pill pill-offline";
  }
}

// ── Module grid ───────────────────────────────────────────────
const ALL_MODS = {
  "m01-api-gateway-shield":{dev:"Ingestion",type:"FastAPI"},
  "m02-connector-sentinel":{dev:"Ingestion",type:"Consumer"},
  "m14-webhook-gateway":{dev:"Ingestion",type:"FastAPI"},
  "m03-traffic-analyzer":{dev:"Threat Detection",type:"Consumer"},
  "m08-anomaly-detection":{dev:"Threat Detection",type:"Consumer"},
  "m12-rules-engine":{dev:"Threat Detection",type:"FastAPI"},
  "m09-dlp":{dev:"Data Protection",type:"Consumer"},
  "m06-credential-vault":{dev:"Data Protection",type:"FastAPI"},
  "m11-shadow-integration":{dev:"Data Protection",type:"Consumer"},
  "m07-compliance-autopilot":{dev:"Governance",type:"FastAPI"},
  "m10-incident-response":{dev:"Governance",type:"FastAPI"},
  "m13-sbom-scanner":{dev:"Governance",type:"FastAPI"},
  "m04-zero-trust-fabric":{dev:"Infrastructure",type:"FastAPI"},
  "m05-sap-mcp-suite":{dev:"Infrastructure",type:"FastAPI"},
  "m15-multicloud-ispm":{dev:"Infrastructure",type:"FastAPI"},
};
function renderModuleGrid(mods) {
  if (!ui.moduleGrid) return;
  ui.moduleGrid.innerHTML = Object.entries(ALL_MODS).map(([name,info]) => {
    const alive = mods[name];
    const ev    = alive ? alive.events||0 : 0;
    return `<div class="module-card">
      <span class="${alive?"dot ok":"dot offline"}"></span>
      <span class="name">${name}</span>
      <span class="stream">${info.dev} · ${info.type} · ${alive?`${ev} events`:"offline"}</span>
    </div>`;
  }).join("");
}

// ── Tab router ────────────────────────────────────────────────
function renderActiveTab() {
  const btn = document.querySelector(".nav-btn.active");
  if (!btn) return;
  const map = {
    alerts: renderAlerts, audit: renderAudit, gateway: renderGateway,
    anomalies: renderAnomaly, dlp: renderDlp, shadow: renderShadow,
    sap: renderSap, compliance: renderCompliance, incidents: renderIncidents,
    sbom: renderSbom, rules: renderRules, "zero-trust": renderZeroTrust,
    credentials: renderCredentials, cloud: renderCloud,
    connectors: renderConnectors, traffic: renderTraffic, webhooks: renderWebhooks,
    launcher: () => renderLauncher(launcherProcesses),
  };
  (map[btn.dataset.tab] || (() => {}))();
}

// ── Render helpers ────────────────────────────────────────────
function setEmpty(list, empty, arr) { if(empty) empty.classList.toggle("hidden", arr.length>0); }

function badge(cls, txt) { return `<span class="sev-badge sev-${cls}">${txt}</span>`; }

function li(cls, ...rows) {
  return `<li class="alert-item ${cls}">
    <div class="alert-item-row">${rows[0]}</div>
    ${rows.slice(1).map(r=>`<div class="alert-item-meta">${r}</div>`).join("")}
  </li>`;
}

// ── ALERTS ────────────────────────────────────────────────────
function renderAlerts() {
  if (!ui.alertsList) return;
  let v = alerts;
  const sc = ui.scenarioFilter ? ui.scenarioFilter.value : "all";
  const sv = ui.severityFilter ? ui.severityFilter.value : "all";
  if (sc !== "all") v = v.filter(a => a.scenario === sc);
  if (sv !== "all") v = v.filter(a => a.severity === sv);
  setEmpty(ui.alertsList, ui.alertsEmpty, v);
  ui.alertsList.innerHTML = v.map((a) => {
    const idx = alerts.indexOf(a);
    const sev = (a.severity||"low").toLowerCase();
    return `<li class="alert-item sev-${sev} clickable-item" onclick="showAlertDetail(${idx})">
      <div class="alert-item-row">
        <strong>${sev.toUpperCase()}</strong>
        <span class="panel-subtitle">${scl(a.scenario)}</span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message||"—"}</div>
      <div class="alert-item-meta">
        IP: <code style="font-size:.72rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${a.source_ip||"—"}</code>
        · user: <code style="font-size:.72rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${a.user_id||"—"}</code>
        · ${ms(a.latencyMs)}
        <span class="item-detail-hint">→ click for detail</span>
      </div>
    </li>`;
  }).join("");
}

// ── AUDIT ─────────────────────────────────────────────────────
function renderAudit() {
  if (!ui.auditBody) return;
  const mod = ui.auditFilter ? ui.auditFilter.value : "all";
  const v = mod==="all" ? auditRows : auditRows.filter(r=>r.module===mod);
  setEmpty(ui.auditBody, ui.auditEmpty, v);
  ui.auditBody.innerHTML = v.map(r => `<tr>
    <td>${ts(r.ts)}</td>
    <td style="color:#b0c4de">${r.actor||"—"}</td>
    <td><code style="font-size:.72rem;background:rgba(255,255,255,.05);padding:1px 6px;border-radius:3px">${r.action||"—"}</code></td>
    <td><span class="module-chip chip-default">${r.module||"—"}</span></td>
    <td><span style="color:${r.status==="ok"?"#2ed573":"#ff4757"}">${r.status||"ok"}</span></td>
  </tr>`).join("");
}

// ── GATEWAY M01 ───────────────────────────────────────────────
function renderGateway() {
  if (!ui.gatewayList) return;
  animateValue(ui.gwTotal,    alerts.length);
  animateValue(ui.gwOffHours, alerts.filter(a=>a.scenario==="off_hours_rfc").length);
  animateValue(ui.gwBulk,     alerts.filter(a=>a.scenario==="bulk_extraction").length);
  animateValue(ui.gwVelocity, alerts.filter(a=>a.scenario==="velocity_anomaly").length);
  const sc = fv('gw-scenario-filter'), sv = fv('gw-severity-filter'), q = fq('gw-search');
  let v = alerts;
  if (sc !== 'all') v = v.filter(a=>a.scenario===sc);
  if (sv !== 'all') v = v.filter(a=>(a.severity||'').toLowerCase()===sv);
  if (q) v = v.filter(a=>[a.message,a.source_ip,a.user_id].join(' ').toLowerCase().includes(q));
  setEmpty(ui.gatewayList, ui.gatewayEmpty, v);
  ui.gatewayList.innerHTML = v.map((a) => {
    const idx = alerts.indexOf(a);
    const sev = (a.severity||"low").toLowerCase();
    const fixBadge = fixedItems.has('gateway-'+(a.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-gateway sev-${sev}" onclick="showItemDetail('gateway',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>RFC CALL</strong> <span class="panel-subtitle">${scl(a.scenario)}</span>
        <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:.5rem">${ts(a.ts)}</span>
      </div>
      <div class="alert-item-meta"><code style="font-size:.73rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${a.message||"—"}</code></div>
      <div class="alert-item-meta">IP: ${a.source_ip||"—"} · user: ${a.user_id||"—"} · latency: ${ms(a.latencyMs)}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── ANOMALY M08 ───────────────────────────────────────────────
function renderAnomaly() {
  if (!ui.anomalyList) return;
  const hi = anomalies.filter(a=>parseFloat(a.anomaly_score||0)>0.7);
  const ep = anomalies.filter(a=>(a.classification||"")==="new_endpoint");
  animateValue(ui.anomTotal, anomalies.length);
  animateValue(ui.anomHigh,  hi.length);
  animateValue(ui.anomNewEp, ep.length);
  const cls2 = fv('anom-class-filter'), sc2 = fv('anom-score-filter'), q2 = fq('anom-search');
  let va = anomalies;
  if (cls2 !== 'all') va = va.filter(a=>(a.classification||'')===cls2);
  if (sc2 === 'high')   va = va.filter(a=>parseFloat(a.anomaly_score||0)>0.7);
  if (sc2 === 'medium') va = va.filter(a=>{const s=parseFloat(a.anomaly_score||0);return s>=0.4&&s<=0.7;});
  if (sc2 === 'low')    va = va.filter(a=>parseFloat(a.anomaly_score||0)<0.4);
  if (q2) va = va.filter(a=>[a.source_ip,a.user_id,a.classification].join(' ').toLowerCase().includes(q2));
  setEmpty(ui.anomalyList, ui.anomalyEmpty, va);
  ui.anomalyList.innerHTML = va.map((a) => {
    const idx = anomalies.indexOf(a);
    const sc = parseFloat(a.anomaly_score||0);
    const cls = sc>0.7?"sev-critical":sc>0.4?"sev-medium":"sev-low";
    const barColor = sc>0.7?"#ff4757":sc>0.4?"#ffa502":"#2ed573";
    const fixBadge = fixedItems.has('anomaly-'+(a.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-anomaly ${cls}" onclick="showItemDetail('anomaly',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>ANOMALY</strong>
        <span class="panel-subtitle">${a.classification||"unclassified"}</span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>
      </div>
      <div class="alert-item-meta" style="display:flex;align-items:center;gap:.6rem;margin-top:3px">
        <span style="font-size:.72rem;color:${barColor};font-weight:700">Score: ${sc.toFixed(3)}</span>
        <div style="flex:1;height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden">
          <div style="width:${Math.round(sc*100)}%;height:100%;background:${barColor};border-radius:2px"></div>
        </div>
      </div>
      <div class="alert-item-meta">IP: ${a.source_ip||"—"} · user: ${a.user_id||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── DLP M09 ───────────────────────────────────────────────────
function renderDlp() {
  if (!ui.dlpList) return;
  animateValue(ui.dlpBulk,      dlpEvents.filter(e=>(e.rule||"").includes("bulk")).length);
  animateValue(ui.dlpStaging,   dlpEvents.filter(e=>(e.rule||"").includes("staging")).length);
  animateValue(ui.dlpBlocklist, dlpEvents.filter(e=>(e.rule||"").includes("blocklist")).length);
  const dr = fv('dlp-rule-filter'), ds = fv('dlp-sev-filter'), dq = fq('dlp-search');
  let vd = dlpEvents;
  if (dr !== 'all') vd = vd.filter(e=>(e.rule||'').includes(dr));
  if (ds !== 'all') vd = vd.filter(e=>(e.severity||'').toLowerCase()===ds);
  if (dq) vd = vd.filter(e=>[e.rule,e.user_id,e.destination].join(' ').toLowerCase().includes(dq));
  setEmpty(ui.dlpList, ui.dlpEmpty, vd);
  ui.dlpList.innerHTML = vd.map((e) => {
    const idx = dlpEvents.indexOf(e);
    const sev = (e.severity||"high").toLowerCase();
    const fixBadge = fixedItems.has('dlp-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-dlp sev-${sev}" onclick="showItemDetail('dlp',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>${(e.rule||"DLP VIOLATION").toUpperCase().replace(/_/g," ")}</strong>
        <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta"><span style="color:#ff8b3d">📤 ${byt(e.bytes_out)}</span> · <span>${(e.row_count||0).toLocaleString()} rows</span> · dest: <code style="font-size:.72rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${e.destination||"—"}</code></div>
      <div class="alert-item-meta">user: ${e.user_id||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── SHADOW M11 ────────────────────────────────────────────────
function renderShadow() {
  if (!ui.shadowList) return;
  const hosts = new Set(shadowEvents.map(e=>e.endpoint||"").filter(Boolean)).size;
  animateValue(ui.shadowTotal,  shadowEvents.length);
  animateValue(ui.shadowUnique, hosts);
  const shsv = fv('shadow-sev-filter'), shq = fq('shadow-search');
  let vsh = shadowEvents;
  if (shsv !== 'all') vsh = vsh.filter(e=>(e.severity||'').toLowerCase()===shsv);
  if (shq) vsh = vsh.filter(e=>[e.endpoint,e.user_id,e.source_ip,e.message].join(' ').toLowerCase().includes(shq));
  setEmpty(ui.shadowList, ui.shadowEmpty, vsh);
  ui.shadowList.innerHTML = vsh.map((e) => {
    const idx = shadowEvents.indexOf(e);
    const sev = (e.severity||"high").toLowerCase();
    const fixBadge = fixedItems.has('shadow-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-shadow sev-${sev}" onclick="showItemDetail('shadow',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>SHADOW ENDPOINT</strong>
        <code style="font-size:.75rem;background:rgba(255,139,61,.15);color:#ff8b3d;padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.endpoint||"unknown"}</code>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">${e.message||"Unknown RFC endpoint invoked"}</div>
      <div class="alert-item-meta">user: ${e.user_id||"—"} · IP: ${e.source_ip||"—"} · calls: ${e.call_count||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── SAP MCP M05 ───────────────────────────────────────────────
function renderSap() {
  if (!ui.sapList) return;
  animateValue(ui.sapTotal,     sapEvents.length);
  animateValue(ui.sapAnomalous, sapEvents.filter(e=>e.anomalous||e.flagged).length);
  const stool = fv('sap-tool-filter'), sflag = fv('sap-flag-filter'), sq = fq('sap-search');
  let vsa = sapEvents;
  if (stool !== 'all') vsa = vsa.filter(e=>(e.tool_name||'')===stool);
  if (sflag === 'flagged') vsa = vsa.filter(e=>e.flagged||e.anomalous);
  if (sflag === 'clean')   vsa = vsa.filter(e=>!e.flagged&&!e.anomalous);
  if (sq) vsa = vsa.filter(e=>[e.tool_name,e.user_id,e.tenant_id].join(' ').toLowerCase().includes(sq));
  setEmpty(ui.sapList, ui.sapEmpty, vsa);
  ui.sapList.innerHTML = vsa.map((e) => {
    const idx = sapEvents.indexOf(e);
    const flagged = e.anomalous || e.flagged;
    const toolColor = flagged ? "#ff4757" : "#5b8def";
    const fixBadge = fixedItems.has('sap-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-sap ${flagged?"sev-critical":""}" onclick="showItemDetail('sap',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>SAP MCP</strong>
        <code style="font-size:.73rem;background:${flagged?"rgba(255,71,87,.15)":"rgba(91,141,239,.12)"};color:${toolColor};padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.tool_name||"tool"}</code>
        ${flagged?`<span class="sev-badge sev-critical" style="margin-left:.5rem">FLAGGED</span>`:""}
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">result: <strong style="color:${e.result==="success"?flagged?"#ff4757":"#2ed573":"#ffa502"}">${e.result||"—"}</strong> · tenant: ${e.tenant_id||"—"}</div>
      <div class="alert-item-meta">user: ${e.user_id||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── COMPLIANCE M07 ────────────────────────────────────────────
function renderCompliance() {
  if (!ui.complianceList) return;
  animateValue(ui.compViolations, compEvents.filter(e=>(e.result||"")==="violation").length);
  animateValue(ui.compWarnings,   compEvents.filter(e=>(e.result||"")==="warning").length);
  animateValue(ui.compPassed,     compEvents.filter(e=>(e.result||"")==="pass").length);
  animateValue(ui.compFrameworks, new Set(compEvents.map(e=>e.framework||"").filter(Boolean)).size);
  const cfw = fv('comp-fw-filter'), cres = fv('comp-result-filter');
  let vc = compEvents;
  if (cfw  !== 'all') vc = vc.filter(e=>e.framework===cfw);
  if (cres !== 'all') vc = vc.filter(e=>(e.result||'').toLowerCase()===cres);
  setEmpty(ui.complianceList, ui.complianceEmpty, vc);

  const fwColors = {SOX:"#ff4757",GDPR:"#5b8def","PCI-DSS":"#ff8b3d","NIST-CSF":"#2ed573",ISO27001:"#a17fe0",HIPAA:"#39c5cf"};

  ui.complianceList.innerHTML = vc.map((e) => {
    const idx = compEvents.indexOf(e);
    const res = (e.result||"unknown").toLowerCase();
    const cls = res==="violation"?"sev-critical":res==="warning"?"sev-medium":"sev-low";
    const fwC = fwColors[e.framework]||"#7a93b4";
    const fixBadge = fixedItems.has('comp-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-compliance ${cls}" onclick="showItemDetail('comp',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>${res.toUpperCase()}</strong>
        <span style="background:${fwC}22;color:${fwC};font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:4px;margin-left:.5rem">${e.framework||"—"}</span>
        <code style="font-size:.7rem;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:3px;margin-left:.4rem">${e.control_id||"—"}</code>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">${e.description||e.message||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");

  renderComplianceScorecard();
}

function renderComplianceScorecard() {
  if (!ui.compScorecard) return;
  const fwColors = {SOX:"#ff4757",GDPR:"#5b8def","PCI-DSS":"#ff8b3d","NIST-CSF":"#2ed573",ISO27001:"#a17fe0",HIPAA:"#39c5cf"};
  ui.compScorecard.innerHTML = Object.entries(FW_SCORES).map(([fw, base]) => {
    const viols = compEvents.filter(e=>e.framework===fw && (e.result||"")==="violation").length;
    const score = Math.max(60, base - viols*3);
    const c = score>90?"#2ed573":score>80?"#5b8def":score>70?"#ffa502":"#ff4757";
    const fwC = fwColors[fw]||c;
    return `<div class="scorecard-row" style="display:flex;align-items:center;gap:.6rem;margin:.25rem 0;font-size:.8rem">
      <span style="width:70px;font-weight:600;color:${fwC};flex-shrink:0">${fw}</span>
      <div style="flex:1;height:6px;background:rgba(255,255,255,.06);border-radius:3px;overflow:hidden">
        <div style="width:${score}%;height:100%;background:${c};border-radius:3px;transition:width .8s ease"></div>
      </div>
      <span style="width:36px;font-weight:700;color:${c};text-align:right">${score}%</span>
      ${viols>0
        ? `<span style="font-size:.67rem;background:rgba(255,71,87,.12);color:#ff4757;padding:1px 6px;border-radius:3px">${viols} viol.</span>`
        : `<span style="font-size:.67rem;color:#2ed573">✓ Clean</span>`}
    </div>`;
  }).join("");
}

// ── INCIDENTS M10 ─────────────────────────────────────────────
function renderIncidents() {
  if (!ui.incidentsList) return;
  const open = incEvents.filter(e=>(e.status||"").toLowerCase()==="open");
  const inv  = incEvents.filter(e=>["investigating","in_progress","active"].includes((e.status||"").toLowerCase()));
  const res  = incEvents.filter(e=>["resolved","closed","contained"].includes((e.status||"").toLowerCase()));
  animateValue(ui.incOpen,      open.length);
  animateValue(ui.incInv,       inv.length);
  animateValue(ui.incResolved,  res.length);
  animateValue(ui.incPlaybooks, incEvents.filter(e=>e.playbook_id).length);
  const ist = fv('inc-status-filter'), isv = fv('inc-sev-filter'), iq = fq('inc-search');
  let vi = incEvents;
  if (ist !== 'all') vi = vi.filter(e=>(e.status||'').toLowerCase()===ist);
  if (isv !== 'all') vi = vi.filter(e=>(e.severity||'').toLowerCase()===isv);
  if (iq) vi = vi.filter(e=>[e.incident_id,e.title,e.source_module].join(' ').toLowerCase().includes(iq));
  setEmpty(ui.incidentsList, ui.incidentsEmpty, vi);

  const stColor = {open:"#ff4757",investigating:"#ffa502",in_progress:"#ffa502",active:"#ffa502",resolved:"#2ed573",closed:"#2ed573",contained:"#2ed573"};

  ui.incidentsList.innerHTML = vi.map((e) => {
    const idx = incEvents.indexOf(e);
    const st  = (e.status||"open").toLowerCase();
    const stC = stColor[st]||"#7a93b4";
    const cls = st==="open"?"sev-critical":["investigating","in_progress","active"].includes(st)?"sev-medium":"sev-low";
    const fixBadge = fixedItems.has('incident-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-incident ${cls}" onclick="showItemDetail('incident',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <strong>${e.incident_id||"INC-?"}</strong>
        <span class="panel-subtitle" style="margin-left:.4rem">${e.title||"incident"}</span>
        <span style="background:${stC}22;color:${stC};font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:4px;margin-left:auto">${st.toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">severity: <span style="color:${e.severity==="critical"?"#ff4757":e.severity==="high"?"#ff8b3d":"#ffa502"}">${(e.severity||"—").toUpperCase()}</span> · source: ${e.source_module||"—"}</div>
      <div class="alert-item-meta">playbook: <code style="font-size:.7rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 6px;border-radius:3px">${e.playbook_id||"none"}</code>${e.playbook_run?`<span style="color:#2ed573;font-size:.7rem;margin-left:.4rem">▶ Running</span>`:""}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");

  renderPlaybookTracker();
}

function renderPlaybookTracker() {
  const el = ui.playbookTracker;
  if (!el) return;
  const inc = incEvents.find(e=>["open","investigating"].includes((e.status||"").toLowerCase()) && e.playbook_id && PLAYBOOK_STEPS[e.playbook_id]);
  if (!inc) { el.classList.add("hidden"); return; }
  el.classList.remove("hidden");
  const steps = PLAYBOOK_STEPS[inc.playbook_id]||[];
  const done  = Math.min(steps.length, Math.floor(demo.tick/3));
  el.innerHTML = `
    <div style="display:flex;align-items:center;gap:.6rem;margin-bottom:.7rem;flex-wrap:wrap">
      <span style="font-size:.65rem;font-weight:700;background:rgba(91,141,239,.18);color:#5b8def;padding:2px 8px;border-radius:4px">🎯 PLAYBOOK RUNNING</span>
      <strong style="color:#eaf0f7;font-size:.82rem">${inc.playbook_id}</strong>
      <span style="font-size:.72rem;color:#7a93b4">→ ${inc.incident_id||"INC-?"}: ${inc.title||""}</span>
    </div>
    <div style="display:flex;flex-wrap:wrap;gap:.35rem">
      ${steps.map((s,i)=>{
        const isDone   = i < done;
        const isActive = i === done;
        const bg    = isDone?"rgba(46,213,115,.1)":isActive?"rgba(255,165,2,.12)":"rgba(255,255,255,.02)";
        const bc    = isDone?"rgba(46,213,115,.25)":isActive?"rgba(255,165,2,.35)":"rgba(255,255,255,.07)";
        const color = isDone?"#2ed573":isActive?"#ffa502":"#4a6080";
        const icon  = isDone?"✓":isActive?"▶":"○";
        return `<div style="display:flex;align-items:center;gap:.3rem;font-size:.7rem;padding:3px 9px;border-radius:4px;border:1px solid ${bc};background:${bg};color:${color}${isActive?";animation:none":""}">
          <span style="font-weight:700">${icon}</span><span>${s}</span>
        </div>`;
      }).join("")}
    </div>`;
}

// ── SBOM M13 ──────────────────────────────────────────────────
function renderSbom() {
  if (!ui.sbomList) return;
  const cve   = sbomEvents.reduce((n,e)=>n+parseInt(e.cve_count||0),0);
  const ins   = sbomEvents.reduce((n,e)=>n+parseInt(e.insecure_rfc_count||0),0);
  const clean = sbomEvents.filter(e=>!parseInt(e.cve_count||0)&&!parseInt(e.insecure_rfc_count||0)).length;
  animateValue(ui.sbomTotal,   sbomEvents.length);
  animateValue(ui.sbomCve,     cve);
  animateValue(ui.sbomInsecure,ins);
  animateValue(ui.sbomClean,   clean);
  const sbst = fv('sbom-status-filter'), sbq = fq('sbom-search');
  let vsb = sbomEvents;
  if (sbst !== 'all') vsb = vsb.filter(e=>(e.scan_status||'')===sbst);
  if (sbq) vsb = vsb.filter(e=>[e.target,e.scan_status].join(' ').toLowerCase().includes(sbq));
  setEmpty(ui.sbomList, ui.sbomEmpty, vsb);
  ui.sbomList.innerHTML = vsb.map((e) => {
    const idx = sbomEvents.indexOf(e);
    const vuln = parseInt(e.cve_count||0)>0 || parseInt(e.insecure_rfc_count||0)>0;
    const cls  = e.scan_status==="VULNERABLE"?"sev-critical":"sev-low";
    const fixBadge = fixedItems.has('sbom-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-sbom ${cls}" onclick="showItemDetail('sbom',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${vuln?"rgba(255,71,87,.2)":"rgba(46,213,115,.15)"};color:${vuln?"#ff4757":"#2ed573"};padding:2px 8px;border-radius:4px">${e.scan_status||"SCAN"}</span>
        <code style="font-size:.73rem;background:rgba(255,255,255,.06);padding:2px 7px;border-radius:4px;margin-left:.5rem;color:#b0c4de">${e.target||"—"}</code>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">CVEs: <strong style="color:${parseInt(e.cve_count||0)>0?"#ff4757":"#2ed573"}">${e.cve_count||0}</strong> · Insecure RFC: <strong style="color:${parseInt(e.insecure_rfc_count||0)>0?"#ffa502":"#2ed573"}">${e.insecure_rfc_count||0}</strong> · format: CycloneDX 1.4</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── RULES M12 ─────────────────────────────────────────────────
function renderRules() {
  if (!ui.rulesList) return;
  const KEY = ["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"];
  animateValue(ui.ruleBulk,      alerts.filter(a=>a.scenario==="bulk_extraction").length);
  animateValue(ui.ruleOffHours,  alerts.filter(a=>a.scenario==="off_hours_rfc").length);
  animateValue(ui.ruleShadow,    alerts.filter(a=>a.scenario==="shadow_endpoint").length);
  animateValue(ui.ruleVelocity,  alerts.filter(a=>a.scenario==="velocity_anomaly").length);
  animateValue(ui.ruleOther,     alerts.filter(a=>!KEY.includes(a.scenario)).length);
  const rsc = fv('rules-scenario-filter'), rsv = fv('rules-sev-filter'), rq = fq('rules-search');
  let vr = alerts;
  if (rsc !== 'all') vr = vr.filter(a=>a.scenario===rsc);
  if (rsv !== 'all') vr = vr.filter(a=>(a.severity||'').toLowerCase()===rsv);
  if (rq) vr = vr.filter(a=>[a.message,a.source_ip,a.user_id,a.scenario].join(' ').toLowerCase().includes(rq));
  setEmpty(ui.rulesList, ui.rulesEmpty, vr);
  ui.rulesList.innerHTML = vr.map((a) => {
    const idx = alerts.indexOf(a);
    const sev = (a.severity||"medium").toLowerCase();
    const ruleColor = {bulk_extraction:"#ff4757",off_hours_rfc:"#ffa502",shadow_endpoint:"#ff8b3d",velocity_anomaly:"#5b8def",data_staging:"#ff4757",credential_abuse:"#a17fe0",privilege_escalation:"#ff4757",geo_anomaly:"#ffa502"}[a.scenario]||"#7a93b4";
    const fixBadge = fixedItems.has('rules-'+(a.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-rules sev-${sev}" onclick="showItemDetail('rules',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${ruleColor}22;color:${ruleColor};padding:2px 8px;border-radius:4px">${scl(a.scenario)||"RULE"}</span>
        <span class="sev-badge sev-${sev}" style="margin-left:.4rem">${sev.toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message||"—"}</div>
      <div class="alert-item-meta">${ms(a.latencyMs)} · IP: ${a.source_ip||"—"} · user: ${a.user_id||"—"}</div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── ZERO-TRUST M04 ────────────────────────────────────────────
function renderZeroTrust() {
  if (!ui.ztList) return;
  const allow = ztEvents.filter(e=>(e.decision||"").toLowerCase()==="allow");
  const deny  = ztEvents.filter(e=>(e.decision||"").toLowerCase()==="deny");
  const chal  = ztEvents.filter(e=>!["allow","deny"].includes((e.decision||"").toLowerCase()));
  const risks = ztEvents.map(e=>parseFloat(e.risk_score||0)).filter(n=>!isNaN(n));
  animateValue(ui.ztAllow,    allow.length);
  animateValue(ui.ztDeny,     deny.length);
  animateValue(ui.ztChallenge,chal.length);
  if (ui.ztAvgRisk) ui.ztAvgRisk.textContent = risks.length ? (risks.reduce((a,b)=>a+b,0)/risks.length).toFixed(2) : "—";
  const zdec = fv('zt-decision-filter'), zrisk = fv('zt-risk-filter'), zq = fq('zt-search');
  let vz = ztEvents;
  if (zdec !== 'all') vz = vz.filter(e=>(e.decision||'').toLowerCase()===zdec);
  if (zrisk === 'high')   vz = vz.filter(e=>parseFloat(e.risk_score||0)>0.7);
  if (zrisk === 'medium') vz = vz.filter(e=>{const r=parseFloat(e.risk_score||0);return r>=0.4&&r<=0.7;});
  if (zrisk === 'low')    vz = vz.filter(e=>parseFloat(e.risk_score||0)<0.4);
  if (zq) vz = vz.filter(e=>[e.user_id,e.source_ip].join(' ').toLowerCase().includes(zq));
  setEmpty(ui.ztList, ui.ztEmpty, vz);
  ui.ztList.innerHTML = vz.map((e) => {
    const idx = ztEvents.indexOf(e);
    const dec  = (e.decision||"evaluated").toLowerCase();
    const dC   = dec==="allow"?"#2ed573":dec==="deny"?"#ff4757":"#ffa502";
    const risk = parseFloat(e.risk_score||0);
    let fc = [];
    try { fc = Array.isArray(e.failed_controls) ? e.failed_controls : JSON.parse(e.failed_controls||"[]"); } catch {}
    const fixBadge = fixedItems.has('zt-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-zt-${dec}" onclick="showItemDetail('zt',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <span style="font-size:.72rem;font-weight:700;background:${dC}22;color:${dC};padding:2px 9px;border-radius:4px">${dec.toUpperCase()}</span>
        <span style="margin-left:.6rem;font-size:.75rem;color:#b0c4de">risk: <strong style="color:${risk>0.7?"#ff4757":risk>0.4?"#ffa502":"#2ed573"}">${risk.toFixed(3)}</strong></span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta" style="display:flex;align-items:center;gap:.5rem;margin-top:3px">
        <div style="flex:1;height:4px;background:rgba(255,255,255,.07);border-radius:2px;overflow:hidden">
          <div style="width:${Math.round(risk*100)}%;height:100%;background:${dC};border-radius:2px"></div>
        </div>
      </div>
      <div class="alert-item-meta">user: ${e.user_id||"—"} · IP: ${e.source_ip||"—"}</div>
      ${fc.length?`<div class="alert-item-meta">failed: ${fc.map(f=>`<span style="font-size:.65rem;background:rgba(255,71,87,.1);color:#ff8b8b;padding:1px 5px;border-radius:3px;margin-right:3px">${f}</span>`).join("")}</div>`:""}
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── CREDENTIALS M06 ───────────────────────────────────────────
function renderCredentials() {
  if (!ui.credList) return;
  animateValue(ui.credIssued,  credEvents.filter(e=>(e.action||"").includes("issu")).length);
  animateValue(ui.credRotated, credEvents.filter(e=>(e.action||"").includes("rotat")).length);
  animateValue(ui.credRevoked, credEvents.filter(e=>(e.action||"").includes("revok")).length);
  animateValue(ui.credAccessed, credEvents.filter(e=>(e.action||"")==="accessed").length);
  const cract = fv('cred-action-filter'), crq = fq('cred-search');
  let vcr = credEvents;
  if (cract !== 'all') vcr = vcr.filter(e=>(e.action||'').toLowerCase().includes(cract));
  if (crq) vcr = vcr.filter(e=>[e.key,e.tenant_id,e.action].join(' ').toLowerCase().includes(crq));
  setEmpty(ui.credList, ui.credEmpty, vcr);
  const icons = {issued:"🔑",accessed:"🔑",rotated:"🔄",revoked:"❌",default:"🔐"};
  ui.credList.innerHTML = vcr.map((e) => {
    const idx = credEvents.indexOf(e);
    const act   = e.action||"event";
    const icon  = icons[act]||icons.default;
    const actC  = act.includes("revok")?"#ff4757":act.includes("rotat")?"#ffa502":"#2ed573";
    const fixBadge = fixedItems.has('cred-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-credential" onclick="showItemDetail('cred',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <span style="font-size:.85rem">${icon}</span>
        <strong style="color:${actC};margin-left:.3rem">${act.toUpperCase()}</strong>
        <code style="font-size:.7rem;background:rgba(255,255,255,.06);padding:1px 7px;border-radius:4px;margin-left:.5rem;color:#b0c4de">${e.key||"—"}</code>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">tenant: ${e.tenant_id||"—"} · status: <span style="color:${actC}">${e.status||act}</span></div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── CLOUD M15 ─────────────────────────────────────────────────
function renderCloud() {
  if (!ui.cloudList) return;
  animateValue(ui.cloudCritical, cloudEvents.filter(e=>(e.raw_severity||"").toLowerCase()==="critical").length);
  animateValue(ui.cloudHigh,     cloudEvents.filter(e=>(e.raw_severity||"").toLowerCase()==="high").length);
  animateValue(ui.cloudAws,      cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="aws").length);
  animateValue(ui.cloudGcp,      cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="gcp").length);
  animateValue(ui.cloudAzure,    cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="azure").length);
  const cprov = fv('cloud-provider-filter'), csev = fv('cloud-sev-filter'), cq = fq('cloud-search');
  let vcl = cloudEvents;
  if (cprov !== 'all') vcl = vcl.filter(e=>(e.provider||'').toLowerCase()===cprov);
  if (csev  !== 'all') vcl = vcl.filter(e=>(e.raw_severity||e.severity||'').toLowerCase()===csev);
  if (cq) vcl = vcl.filter(e=>[e.finding_type,e.resource_id,e.provider].join(' ').toLowerCase().includes(cq));
  setEmpty(ui.cloudList, ui.cloudEmpty, vcl);
  const provC = {aws:"#ff9900",gcp:"#4285f4",azure:"#00a4ef"};
  const provBg = {aws:"rgba(255,153,0,.15)",gcp:"rgba(66,133,244,.15)",azure:"rgba(0,164,239,.15)"};
  ui.cloudList.innerHTML = vcl.map((e) => {
    const idx = cloudEvents.indexOf(e);
    const prov = (e.provider||"cloud").toLowerCase();
    const sev  = (e.raw_severity||e.severity||"medium").toLowerCase();
    const pc   = provC[prov]||"#7a93b4";
    const pb   = provBg[prov]||"rgba(255,255,255,.06)";
    const fixBadge = fixedItems.has('cloud-'+(e.ts||idx)) ? `<span style="font-size:.68rem;background:rgba(46,213,115,.15);color:#2ed573;padding:1px 7px;border-radius:3px">✓ Fixed</span>` : `<span style="font-size:.68rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 7px;border-radius:3px;font-weight:600">⚡ Fix available</span>`;
    return `<li class="alert-item ev-cloud sev-${sev}" onclick="showItemDetail('cloud',${idx})" style="cursor:pointer">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${pb};color:${pc};padding:2px 8px;border-radius:4px">${prov.toUpperCase()}</span>
        <code style="font-size:.7rem;background:rgba(255,71,87,.1);color:#ff8b8b;padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.finding_type||"FINDING"}</code>
        <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta"><code style="font-size:.68rem;background:rgba(255,255,255,.04);padding:1px 6px;border-radius:3px;color:#7a93b4">${e.resource_id||"—"}</code></div>
      <div class="alert-item-meta">risk score: <strong style="color:${parseFloat(e.risk_score||0)>0.7?"#ff4757":"#ffa502"}">${e.risk_score||"—"}</strong></div>
      <div class="alert-item-meta" style="margin-top:3px;display:flex;justify-content:space-between">
        <span style="font-size:.68rem;color:#4a6080;font-style:italic">click to view detail &amp; fix</span>
        ${fixBadge}
      </div>
    </li>`;
  }).join("");
}

// ── Universal item detail + fix system ────────────────────────
const fixedItems = new Set(); // "type-ts" keys of resolved items (ts-based to survive prepends)

function showItemDetail(type, idx) {
  const arrMap = {
    alert: alerts, anomaly: anomalies, sap: sapEvents, dlp: dlpEvents,
    shadow: shadowEvents, comp: compEvents, incident: incEvents,
    sbom: sbomEvents, zt: ztEvents, cred: credEvents, cloud: cloudEvents,
    gateway: alerts, rules: alerts,
  };
  const arr = arrMap[type]; if (!arr) return;
  const ev = arr[idx];      if (!ev)  return;
  const fixKey = ev.ts ? `${type}-${ev.ts}` : `${type}-${idx}`;
  const alreadyFixed = fixedItems.has(fixKey);

  const overlay = $("detail-overlay"); if (!overlay) return;
  const drwBadge = $("drw-badge"), drwTitle = $("drw-title"),
        drwBody  = $("drw-body"),  drwActions = $("drw-actions");

  // Badge + title
  const sev = (ev.severity || ev.raw_severity || (type==="anomaly"?"medium":"info")).toLowerCase();
  const typeLabels = {
    alert:"ALERT", anomaly:"ANOMALY DETECTED", sap:"SAP MCP EVENT", dlp:"DLP VIOLATION",
    shadow:"SHADOW ENDPOINT", comp:"COMPLIANCE", incident:"INCIDENT",
    sbom:"SBOM SCAN", zt:"ZERO-TRUST", cred:"CREDENTIAL EVENT", cloud:"CLOUD FINDING",
    gateway:"GATEWAY EVENT", rules:"RULE TRIGGERED",
  };
  if (drwBadge) {
    drwBadge.textContent = alreadyFixed ? "✓ RESOLVED" : (typeLabels[type]||type.toUpperCase());
    drwBadge.className = `sev-badge ${alreadyFixed ? "sev-ok" : `sev-${sev}`}`;
    if (alreadyFixed) drwBadge.style.background="rgba(46,213,115,0.2)";
  }
  const titleMap = {
    alert: ev.message,
    anomaly: `Anomaly — ${ev.classification||"unclassified"} (score: ${parseFloat(ev.anomaly_score||0).toFixed(3)})`,
    sap: `SAP Tool: ${ev.tool_name||"unknown"} ${ev.flagged?"— FLAGGED":""}`,
    dlp: `DLP: ${(ev.rule||"violation").replace(/_/g," ").toUpperCase()} — ${(ev.bytes_out/1e6||0).toFixed(1)}MB`,
    shadow: `Shadow RFC: ${ev.endpoint||"unknown endpoint"}`,
    comp: `${ev.framework||"Framework"} ${ev.control_id||""} — ${(ev.result||"").toUpperCase()}`,
    incident: `${ev.incident_id||"INC-?"}: ${ev.title||"incident"}`,
    sbom: `SBOM: ${ev.target||"package"} — ${ev.scan_status||"SCAN"}`,
    zt: `Zero-Trust ${(ev.decision||"evaluated").toUpperCase()} — risk ${parseFloat(ev.risk_score||0).toFixed(3)}`,
    cred: `Credential ${(ev.action||"event").toUpperCase()} — ${ev.key||"key"}`,
    cloud: `${(ev.provider||"cloud").toUpperCase()} ${ev.finding_type||"FINDING"} on ${ev.resource_id||"resource"}`,
  };
  if (drwTitle) drwTitle.textContent = (alreadyFixed ? "✓ RESOLVED — " : "") + (titleMap[type] || ev.message || "Security Event");

  // Build field grid based on type
  const fields = _buildFields(type, ev);
  const explanation = _explainEvent(type, ev);
  const fixSteps = _getFixSteps(type, ev);

  // Correlated events (only for alert-type)
  let corrHTML = "";
  if (type === "alert" || type === "gateway" || type === "rules") {
    const corrAlerts = alerts.filter(x=>x!==ev&&(x.source_ip===ev.source_ip||x.user_id===ev.user_id)).slice(0,3);
    const corrAnom   = anomalies.filter(x=>x.source_ip===ev.source_ip||x.user_id===ev.user_id).slice(0,2);
    const corrDlp    = dlpEvents.filter(x=>x.user_id===ev.user_id).slice(0,2);
    const corrZT     = ztEvents.filter(x=>x.source_ip===ev.source_ip||x.user_id===ev.user_id).slice(0,2);
    const corrCount  = corrAlerts.length+corrAnom.length+corrDlp.length+corrZT.length;
    if (corrCount > 0) {
      corrHTML = `<div>
        <div class="drw-section-title">🔗 Correlated Events (${corrCount})</div>
        ${corrAlerts.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(255,71,87,.08);color:#ff9aa2">⚠️ ALERT: ${x.message||x.scenario} — ${ts(x.ts)}</div>`).join("")}
        ${corrAnom.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(161,127,224,.09);color:#c4a5f5">🧠 ANOMALY: score ${x.anomaly_score} · ${x.classification} — ${ts(x.ts)}</div>`).join("")}
        ${corrDlp.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(57,197,207,.07);color:#67e8f9">🔒 DLP: ${x.rule} · ${byt(x.bytes_out)} — ${ts(x.ts)}</div>`).join("")}
        ${corrZT.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(91,141,239,.09);color:#93bbff">🔐 ZERO-TRUST: ${(x.decision||"").toUpperCase()} · risk ${x.risk_score} — ${ts(x.ts)}</div>`).join("")}
      </div>`;
    }
  }

  if (drwBody) drwBody.innerHTML = `
    <div>
      <div class="drw-section-title">Event Details</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem">${fields}</div>
    </div>
    <div>
      <div class="drw-section-title">🧠 What Is This?</div>
      <div style="background:rgba(91,141,239,.07);border:1px solid rgba(91,141,239,.18);border-radius:6px;padding:.75rem;font-size:.78rem;color:#b0c4de;line-height:1.6">
        ${explanation}
      </div>
    </div>
    <div>
      <div class="drw-section-title">🔧 How To Fix It</div>
      <div style="display:flex;flex-direction:column;gap:.35rem">
        ${fixSteps.map((s,i)=>`<div style="display:flex;align-items:flex-start;gap:.5rem;font-size:.76rem;padding:.4rem .6rem;border-radius:5px;background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06)">
          <span style="flex-shrink:0;width:18px;height:18px;border-radius:50%;background:rgba(91,141,239,.2);color:#5b8def;font-weight:700;font-size:.65rem;display:flex;align-items:center;justify-content:center">${i+1}</span>
          <span style="color:#b0c4de;line-height:1.5">${s}</span>
        </div>`).join("")}
      </div>
    </div>
    ${corrHTML}
  `;

  if (drwActions) {
    if (alreadyFixed) {
      drwActions.innerHTML = `
        <div style="flex:1;padding:.5rem .7rem;border:1px solid rgba(46,213,115,.3);border-radius:6px;background:rgba(46,213,115,.1);color:#2ed573;font-size:.76rem;font-weight:600;text-align:center">
          ✓ Already resolved by IntegriShield
        </div>
        <button onclick="closeDetailDrawer()" style="padding:.5rem .9rem;border:1px solid rgba(255,255,255,.12);border-radius:6px;background:rgba(255,255,255,.06);color:#7a93b4;font-size:.76rem;cursor:pointer">Close</button>`;
    } else {
      drwActions.innerHTML = `
        <button onclick="applyFix('${type}',${idx})"
          style="flex:1;padding:.55rem .8rem;border:none;border-radius:6px;background:linear-gradient(135deg,#2ed573,#5b8def);color:#fff;font-size:.78rem;font-weight:700;cursor:pointer;letter-spacing:.03em;box-shadow:0 0 16px rgba(46,213,115,.35)">
          ⚡ Fix It Now
        </button>
        <button onclick="demoActionAlt('block','${type}','${ev.source_ip||ev.user_id||""}')"
          style="padding:.5rem .7rem;border:1px solid rgba(255,71,87,.3);border-radius:6px;background:rgba(255,71,87,.15);color:#ff4757;font-size:.76rem;font-weight:600;cursor:pointer">
          🚫 Block
        </button>
        <button onclick="demoActionAlt('report','${type}','')"
          style="padding:.5rem .7rem;border:1px solid rgba(91,141,239,.3);border-radius:6px;background:rgba(91,141,239,.14);color:#5b8def;font-size:.76rem;font-weight:600;cursor:pointer">
          📄 Report
        </button>
      `;
    }
  }

  overlay.classList.remove("hidden");
}

function _buildFields(type, ev) {
  const f = (label, val) => `<div class="drw-field"><label>${label}</label><span>${val||"—"}</span></div>`;
  const c = (label, val) => `<div class="drw-field"><label>${label}</label><code>${val||"—"}</code></div>`;
  const base = f("Timestamp", new Date(ev.ts||Date.now()).toLocaleString());
  if (type==="alert"||type==="gateway"||type==="rules")
    return base + f("Severity",`<span class="sev-badge sev-${(ev.severity||"low").toLowerCase()}">${(ev.severity||"low").toUpperCase()}</span>`) +
           f("Scenario", scl(ev.scenario)) + f("Latency", ms(ev.latencyMs)) +
           c("Source IP", ev.source_ip) + c("User", ev.user_id);
  if (type==="anomaly")
    return base + f("Score",`<strong style="color:${parseFloat(ev.anomaly_score||0)>0.7?"#ff4757":"#ffa502"}">${parseFloat(ev.anomaly_score||0).toFixed(4)}</strong>`) +
           f("Classification", ev.classification) + c("Source IP", ev.source_ip) + c("User", ev.user_id);
  if (type==="sap")
    return base + c("Tool", ev.tool_name) + f("Result", ev.result) + f("Tenant", ev.tenant_id) +
           c("User", ev.user_id) + f("Flagged", ev.flagged?"<span style='color:#ff4757'>YES</span>":"No");
  if (type==="dlp")
    return base + f("Rule", (ev.rule||"").replace(/_/g," ")) + f("Severity",`<span class="sev-badge sev-${(ev.severity||"high").toLowerCase()}">${(ev.severity||"high").toUpperCase()}</span>`) +
           f("Data Volume", byt(ev.bytes_out)) + f("Row Count", (ev.row_count||0).toLocaleString()) +
           c("User", ev.user_id) + c("Destination", ev.destination);
  if (type==="shadow")
    return base + c("Endpoint", ev.endpoint) + f("Severity",`<span class="sev-badge sev-${(ev.severity||"critical").toLowerCase()}">${(ev.severity||"critical").toUpperCase()}</span>`) +
           c("User", ev.user_id) + c("Source IP", ev.source_ip) + f("Call Count", ev.call_count||"—");
  if (type==="comp")
    return base + f("Framework", ev.framework) + c("Control", ev.control_id) +
           f("Result",`<span style="color:${(ev.result||"")=="violation"?"#ff4757":"#2ed573"}">${(ev.result||"").toUpperCase()}</span>`) +
           f("Severity",`<span class="sev-badge sev-${(ev.severity||"medium").toLowerCase()}">${(ev.severity||"medium").toUpperCase()}</span>`);
  if (type==="incident")
    return base + f("Incident ID", ev.incident_id) + f("Status",`<span style="color:${(ev.status||"open")==="open"?"#ff4757":(ev.status||"")==="investigating"?"#ffa502":"#2ed573"}">${(ev.status||"open").toUpperCase()}</span>`) +
           f("Severity",`<span class="sev-badge sev-${(ev.severity||"critical").toLowerCase()}">${(ev.severity||"critical").toUpperCase()}</span>`) +
           f("Source Module", ev.source_module) + c("Playbook", ev.playbook_id||"none");
  if (type==="sbom")
    return base + c("Target", ev.target) + f("Status",`<span style="color:${ev.scan_status==="VULNERABLE"?"#ff4757":"#2ed573"}">${ev.scan_status||"—"}</span>`) +
           f("CVEs", `<strong style="color:${parseInt(ev.cve_count||0)>0?"#ff4757":"#2ed573"}">${ev.cve_count||0}</strong>`) +
           f("Insecure RFCs", `<strong style="color:${parseInt(ev.insecure_rfc_count||0)>0?"#ffa502":"#2ed573"}">${ev.insecure_rfc_count||0}</strong>`);
  if (type==="zt") {
    let fc = []; try { fc = Array.isArray(ev.failed_controls)?ev.failed_controls:JSON.parse(ev.failed_controls||"[]"); } catch {}
    return base + f("Decision",`<span style="color:${(ev.decision||"")==="deny"?"#ff4757":(ev.decision||"")==="allow"?"#2ed573":"#ffa502"}">${(ev.decision||"").toUpperCase()}</span>`) +
           f("Risk Score",`<strong style="color:${parseFloat(ev.risk_score||0)>0.7?"#ff4757":"#ffa502"}">${parseFloat(ev.risk_score||0).toFixed(4)}</strong>`) +
           c("User", ev.user_id) + c("Source IP", ev.source_ip) +
           `<div class="drw-field" style="grid-column:1/-1"><label>Failed Controls</label><span>${fc.length?fc.map(f2=>`<span style="font-size:.65rem;background:rgba(255,71,87,.1);color:#ff8b8b;padding:1px 5px;border-radius:3px;margin:2px">${f2}</span>`).join(""):"None"}</span></div>`;
  }
  if (type==="cred")
    return base + f("Action",`<span style="color:${(ev.action||"").includes("revok")?"#ff4757":(ev.action||"").includes("rotat")?"#ffa502":"#2ed573"}">${(ev.action||"").toUpperCase()}</span>`) +
           c("Key", ev.key) + f("Tenant", ev.tenant_id) + f("Status", ev.status||ev.action);
  if (type==="cloud")
    return base + f("Provider",`<span style="color:${(ev.provider||"")==="aws"?"#ff9900":(ev.provider||"")==="gcp"?"#4285f4":"#00a4ef"}">${(ev.provider||"").toUpperCase()}</span>`) +
           f("Finding", ev.finding_type) + f("Severity",`<span class="sev-badge sev-${(ev.raw_severity||"medium").toLowerCase()}">${(ev.raw_severity||"medium").toUpperCase()}</span>`) +
           f("Risk Score",`<strong style="color:${parseFloat(ev.risk_score||0)>0.7?"#ff4757":"#ffa502"}">${ev.risk_score||"—"}</strong>`) +
           `<div class="drw-field" style="grid-column:1/-1"><label>Resource</label><code style="font-size:.7rem">${ev.resource_id||"—"}</code></div>`;
  return base;
}

function _explainEvent(type, ev) {
  if (type==="alert"||type==="gateway"||type==="rules") {
    const sc = ev.scenario||"";
    if (sc.includes("bulk_extraction"))      return `<strong>High-confidence data exfiltration attempt.</strong> User <code>${ev.user_id}</code> invoked RFC_READ_TABLE at anomalous velocity, extracting rows far exceeding normal business volume. Isolation Forest ML model scored this at <strong>0.94</strong> confidence. Cross-correlated with off-hours access patterns from IP <code>${ev.source_ip}</code>. This pattern matches known insider threat data-theft playbooks — immediate containment is required before data leaves the perimeter.`;
    if (sc.includes("privilege_escalation")) return `<strong>Unauthorized privilege escalation detected.</strong> <code>${ev.user_id}</code> called SUSR_USER_AUTH_FOR_OBJ_GET outside of the approved change window. Zero-Trust Fabric denied the session (risk: 0.97). This violates SOX AC-2 (account management) and NIST CSF IA-2 (authentication controls). Attackers use privilege escalation to gain admin-level access — enabling data exfiltration, configuration changes, and backdoor creation.`;
    if (sc.includes("shadow_endpoint"))      return `<strong>Unknown/unauthorized RFC endpoint invoked from external IP.</strong> The function <code>${ev.source_ip}</code> has no registered business owner in the SAP function whitelist. External origin strongly suggests a supply-chain compromise, insider planting a backdoor, or active exploitation of an unpatched SAP vulnerability. Shadow endpoints bypass all standard DLP and audit controls.`;
    if (sc.includes("credential_abuse"))     return `<strong>Credential used from multiple geographic locations simultaneously.</strong> Account <code>${ev.user_id}</code> is showing activity from ${_int(3,8)} distinct IP ranges simultaneously — a physical impossibility indicating stolen credentials or session hijacking. Zero-Trust risk score: 0.78. If left unaddressed, the attacker has full access to all data accessible by this account.`;
    if (sc.includes("geo_anomaly"))          return `<strong>Access from high-risk or anomalous geolocation.</strong> IP <code>${ev.source_ip}</code> originates from a region outside all known corporate locations and vendor ranges. No historical sessions from this location are on record. This is a common initial-access vector where attackers use VPNs or compromised infrastructure in policy-restricted countries.`;
    if (sc.includes("data_staging"))         return `<strong>Data staging — large volume write to external destination detected.</strong> Data is being written to an external staging location before exfiltration. This two-step approach is used to bypass real-time DLP monitoring. Cloud misconfiguration (PUBLIC_BUCKET or OVERPRIVILEGED_ROLE) likely enabled this exfiltration path. Combined cloud + DLP alert pattern indicates active breach in progress.`;
    if (sc.includes("off_hours_rfc"))        return `<strong>RFC access outside business hours by privileged user.</strong> User <code>${ev.user_id}</code> is making SAP RFC calls during off-hours (nights/weekends). While not conclusive alone, this deviates significantly from the established baseline. Combined with repeated access patterns, this is a common precursor to bulk data extraction or reconnaissance activity. Monitoring should be elevated.`;
    if (sc.includes("velocity_anomaly"))     return `<strong>Request velocity spike — far above baseline.</strong> The number of RFC calls per minute from <code>${ev.user_id}</code> / <code>${ev.source_ip}</code> has exceeded normal thresholds by 10×+. Automated tooling or scripted exfiltration is suspected. Normal user sessions do not exhibit this pattern.`;
    return `<strong>Anomalous activity pattern flagged by rules engine.</strong> Behaviour deviation from established baseline detected. ML model confidence: ${_flt(0.55,0.92).toFixed(2)}. Correlated with ${_int(2,5)} recent events from same source. The combination of signals suggests escalating malicious activity — investigation and monitoring are recommended.`;
  }
  if (type==="anomaly") {
    const cls = ev.classification||"";
    const sc = parseFloat(ev.anomaly_score||0);
    if (cls==="velocity_spike")      return `<strong>Request velocity spike detected by Isolation Forest ML model.</strong> The model scored this session at <strong>${sc.toFixed(3)}</strong> (threshold: 0.75 = high risk). Velocity spikes indicate automated tooling — scripts that extract large datasets far faster than human users can operate. This is the signature of data-exfiltration tools like custom ABAP reports or RFC automation frameworks. Score above 0.85 triggers automatic incident creation.`;
    if (cls==="off_hours_pattern")   return `<strong>Anomalous off-hours access pattern.</strong> The ML baseline model detected activity at times statistically inconsistent with this user's historical behaviour. Anomaly score: <strong>${sc.toFixed(3)}</strong>. Off-hours access by privileged accounts is a high-risk indicator — legitimate users rarely access sensitive SAP data outside business hours. This score combined with IP reputation analysis places this session in the top 5% of risk signals.`;
    if (cls==="new_endpoint")        return `<strong>First-seen RFC endpoint — not in historical baseline.</strong> This RFC function has never been called by this user/IP combination before. New endpoints appearing without change-request authorisation indicate either a misconfiguration, a new attack vector, or an undocumented integration. Isolation Forest assigns high anomaly scores to novel endpoint usage since it deviates completely from baseline.`;
    if (cls==="geo_anomaly")         return `<strong>Geographic anomaly — access from unexpected location.</strong> ML model detected that the source IP geolocation is statistically impossible given the user's prior session history. Score: <strong>${sc.toFixed(3)}</strong>. This is a strong indicator of account compromise, credential theft, or unauthorised delegation. The model compares current location against the last 90 days of session history.`;
    if (cls==="baseline_deviation")  return `<strong>Significant deviation from user behaviour baseline.</strong> Multiple behavioural signals — access time, data volume, RFC patterns, session duration — are all outside normal ranges simultaneously. Composite anomaly score: <strong>${sc.toFixed(3)}</strong>. The Isolation Forest model treats multi-dimensional outliers as highest priority. This pattern often precedes confirmed breaches by 2–6 hours.`;
    if (cls==="privilege_escalation") return `<strong>Privilege escalation pattern detected by ML model.</strong> Auth object manipulation calls have spiked. The sequence of SAP function calls matches known privilege-escalation attack chains. Score: <strong>${sc.toFixed(3)}</strong> — in the top 2% of all scored sessions. Automated escalation attempts move fast; containment within minutes is critical.`;
    return `<strong>Isolation Forest ML model flagged this session as anomalous.</strong> Score: <strong>${sc.toFixed(3)}</strong> (above 0.5 = suspicious, above 0.75 = high risk, above 0.9 = critical). The model trained on 90 days of baseline traffic identified this session as a statistical outlier across ${_int(5,12)} behavioural dimensions including access time, data volume, endpoint usage, and request patterns.`;
  }
  if (type==="sap") {
    const tool = ev.tool_name||"";
    if (tool==="export_payroll_data")   return `<strong>Payroll data export via SAP MCP — extremely high risk.</strong> The <code>export_payroll_data</code> tool accesses salary, bank account, and PII for all employees. This is the highest-value dataset in most organisations. Export by <code>${ev.user_id}</code> without a corresponding approved change request constitutes a GDPR Article 32 violation and likely triggers mandatory breach notification obligations. This tool should only be called by payroll administrators during month-end processing.`;
    if (tool==="change_user_auth")      return `<strong>Unauthorised modification of user authorisation objects.</strong> <code>change_user_auth</code> was called by <code>${ev.user_id}</code> — this tool modifies who has access to what in SAP. Misuse enables privilege escalation, hiding of audit trails, and creation of backdoor accounts. SOX AC-2 requires all auth changes to follow a 4-eyes approval process. This call bypassed that control.`;
    if (tool==="modify_auth_profile")   return `<strong>Auth profile modification outside change window.</strong> SAP authentication profiles define the security perimeter for entire user groups. Modification by <code>${ev.user_id}</code> could grant unlimited access to thousands of sensitive transactions. This is a critical SoD (Segregation of Duties) violation and must be reviewed within 1 hour.`;
    if (tool==="delete_table_entries")  return `<strong>Direct SAP table deletion — potential evidence destruction.</strong> Deleting entries from SAP tables can erase transaction records, audit trails, and financial data. This is used in advanced attacks to cover tracks after data theft. Under SOX and GDPR, organisations must maintain data integrity logs — this action violates both. Forensic capture should occur immediately before any data is overwritten.`;
    if (tool==="run_report")            return `<strong>Custom ABAP report execution flagged.</strong> Execution of custom reports can bypass standard SAP security controls and access data across all modules. The report <code>${ev.tool_name}</code> was not in the pre-approved report whitelist. Custom reports are a common vector for extracting sensitive data in bulk without triggering standard DLP rules.`;
    if (ev.flagged)                     return `<strong>Flagged SAP MCP tool call — anomalous usage pattern.</strong> The tool <code>${tool}</code> was called by <code>${ev.user_id}</code> in a context that deviates from established baseline behaviour. Flagged indicators: unusual time, excessive call frequency, or sensitive data access pattern. The SAP MCP Suite cross-references every tool call against authorised service accounts and approved workflows.`;
    return `<strong>SAP MCP tool execution logged.</strong> Tool <code>${tool}</code> called by <code>${ev.user_id}</code> on tenant <code>${ev.tenant_id}</code>. All MCP tool calls are logged for compliance purposes. This event does not indicate a breach but is retained for the full audit trail required by SOX Section 404 and GDPR Article 30.`;
  }
  if (type==="dlp") {
    const rule = ev.rule||"";
    if (rule.includes("bulk"))       return `<strong>Bulk data export — DLP critical violation.</strong> <code>${(ev.bytes_out/1e6||0).toFixed(1)}MB</code> (${(ev.row_count||0).toLocaleString()} rows) transferred to <code>${ev.destination}</code>. This exceeds the bulk export threshold by ${_int(5,20)}×. DLP policy requires all exports above 1,000 rows to have pre-approved data transfer authorisation (DTA). Without DTA, this constitutes an unauthorised data transfer under GDPR Article 44 and PCI-DSS Requirement 12.`;
    if (rule.includes("staging"))    return `<strong>Data staging area write detected — pre-exfiltration behaviour.</strong> Data is being written to an internal staging location (<code>${ev.destination}</code>) which is typically used as a holding area before external transfer. This two-step exfiltration technique is designed to avoid real-time DLP monitoring. ${(ev.bytes_out/1e6||0).toFixed(1)}MB has already been staged. Immediate investigation of the staging location is required.`;
    if (rule.includes("blocklist"))  return `<strong>Data sent to blocklisted destination — confirmed policy violation.</strong> Transfer to <code>${ev.destination}</code> is explicitly blocked by DLP policy. This destination appears on the corporate blocklist due to known association with data exfiltration services (file-sharing platforms, personal cloud storage, or competitor domains). ${(ev.bytes_out/1e6||0).toFixed(1)}MB was transferred before the block triggered.`;
    if (rule.includes("pii"))        return `<strong>PII exfiltration detected — GDPR breach notification may be required.</strong> Personally Identifiable Information detected in outbound transfer to <code>${ev.destination}</code>. Under GDPR Article 33, if this data includes EU resident PII, a breach notification to the supervisory authority must be made within 72 hours. Legal and compliance teams must be notified immediately. ${(ev.bytes_out/1e6||0).toFixed(1)}MB of potentially regulated data was transferred.`;
    return `<strong>DLP rule violation detected.</strong> Rule <code>${rule.replace(/_/g," ")}</code> triggered on outbound transfer from <code>${ev.user_id}</code>. ${(ev.bytes_out/1e6||0).toFixed(1)}MB transferred to <code>${ev.destination}</code>. All DLP violations are logged for compliance reporting and may require incident escalation depending on data classification and destination.`;
  }
  if (type==="shadow") {
    return `<strong>Shadow/unauthorised RFC endpoint detected — critical risk.</strong> RFC function <code>${ev.endpoint}</code> was invoked ${ev.call_count||"multiple"} times but has NO entry in the authorised SAP function registry. Shadow endpoints are created to: (1) bypass security controls, (2) create persistent backdoors, (3) exfiltrate data without triggering standard monitoring. The external/internal source <code>${ev.source_ip}</code> calling an unregistered endpoint is a strong indicator of supply-chain compromise or insider threat. This function must be blocked immediately and SAP must be scanned for additional shadow endpoints.`;
  }
  if (type==="comp") {
    const fw = ev.framework||"";
    const ctrl = ev.control_id||"";
    const descs = {
      SOX: `SOX (Sarbanes-Oxley Act) requires organisations to maintain internal controls over financial reporting. Violation of <code>${ctrl}</code> means financial audit controls have failed — this triggers mandatory disclosure to auditors and may result in material weakness reporting, regulatory fines, and executive certification liability under SOX Section 302/906.`,
      GDPR: `GDPR (EU General Data Protection Regulation) violation of <code>${ctrl}</code> detected. Depending on severity, this may trigger the 72-hour breach notification obligation under Article 33. Maximum fines: €20M or 4% of global annual turnover. Data Protection Officer must be notified immediately.`,
      "PCI-DSS": `PCI-DSS (Payment Card Industry Data Security Standard) violation of <code>${ctrl}</code>. This may suspend card processing capabilities and trigger a mandatory forensic investigation. Fines range from $5,000–$100,000/month and may result in loss of payment processing rights.`,
      "NIST-CSF": `NIST Cybersecurity Framework control <code>${ctrl}</code> failed. While NIST-CSF is voluntary, violations create gaps in the security posture that are reported to board-level risk committees. They also indicate non-compliance with federal contractor requirements.`,
      ISO27001: `ISO 27001 control <code>${ctrl}</code> violation detected. This impacts the organisation's ISMS (Information Security Management System) certification status. If this violation is identified during an audit, it would be raised as a nonconformity — potentially triggering a surveillance audit.`,
      HIPAA: `HIPAA (Health Insurance Portability and Accountability Act) violation of <code>${ctrl}</code>. PHI (Protected Health Information) controls have been breached. HHS fines range from $100–$50,000 per violation, and criminal penalties apply for wilful neglect. OCR breach investigation may be required.`,
    };
    return `<strong>${fw} compliance violation — ${ctrl}.</strong> ${descs[fw]||"Compliance control failed. Violation logged for audit trail."} <br><br><em>Description: ${ev.description||"—"}</em>`;
  }
  if (type==="incident") {
    const title = ev.title||"";
    return `<strong>Security incident: ${title}.</strong> This incident was auto-created by the IntegriShield M10 Incident Response engine based on correlated signals from multiple detection modules. Status: <strong>${(ev.status||"open").toUpperCase()}</strong>. Severity: <strong>${(ev.severity||"critical").toUpperCase()}</strong>. Playbook <code>${ev.playbook_id||"none"}</code> ${ev.playbook_run?"has been auto-triggered and is currently executing containment steps.":"is queued for execution."} SLA: Critical incidents require initial response within 15 minutes and resolution within 4 hours. Current MTTD: 3.2 seconds (IntegriShield average).`;
  }
  if (type==="sbom") {
    const cves = parseInt(ev.cve_count||0);
    const ins  = parseInt(ev.insecure_rfc_count||0);
    if (ev.scan_status==="VULNERABLE") return `<strong>VULNERABLE component detected in ${ev.target}.</strong> SBOM scan found <strong>${cves} CVE(s)</strong> and <strong>${ins} insecure RFC call(s)</strong>. CVEs in runtime dependencies create exploitable attack surfaces — attackers actively scan for known vulnerabilities in exposed SAP integration components. Each unpatched CVE with a CVSS score above 7.0 must be remediated within 30 days under most security frameworks. Insecure RFC calls indicate use of deprecated or unsafe function modules that bypass modern security controls.`;
    return `<strong>SBOM scan completed — ${ev.target} is CLEAN.</strong> No CVEs or insecure RFC calls detected in this component's dependency tree. The Software Bill of Materials (SBOM) confirms all libraries are at patched versions with no known exploits. This component is cleared for production use. SBOM records are retained for supply-chain audit compliance (NIST SSDF, EO 14028).`;
  }
  if (type==="zt") {
    const dec   = ev.decision||"";
    const risk  = parseFloat(ev.risk_score||0);
    let fc = []; try { fc = Array.isArray(ev.failed_controls)?ev.failed_controls:JSON.parse(ev.failed_controls||"[]"); } catch {}
    if (dec==="deny")      return `<strong>Zero-Trust access denied — risk score ${risk.toFixed(3)}.</strong> The M04 Zero-Trust Fabric evaluated ${fc.length} security controls and found ${fc.length} failures: <code>${fc.join(", ")}</code>. Under Zero-Trust architecture, every access request must prove trust from scratch — no implicit trust is ever granted based on network location. A risk score of ${risk.toFixed(3)} places this session in the top ${Math.round((1-risk)*100)}th percentile of risk. The session has been terminated and the user must re-authenticate with additional factors.`;
    if (dec==="challenge")  return `<strong>Zero-Trust MFA challenge issued — risk score ${risk.toFixed(3)}.</strong> The session triggered ${fc.length} risk factor(s): <code>${fc.join(", ")}</code>. Rather than blocking outright, Zero-Trust issued a step-up authentication challenge. The user must provide additional verification (MFA, device certificate, or manager approval) within 5 minutes or the session will be auto-terminated. This approach balances security with user productivity for borderline-risk sessions.`;
    return `<strong>Zero-Trust access granted — risk score ${risk.toFixed(3)}.</strong> All security controls passed. The session was evaluated against ${_int(6,12)} behavioural and contextual signals including device health, geolocation, time-of-access, and user behaviour baseline. Low risk score indicates this is a legitimate session consistent with historical patterns. Logged for continuous monitoring and anomaly detection baseline.`;
  }
  if (type==="cred") {
    const action = ev.action||"";
    if (action.includes("revok")) return `<strong>Credential revocation executed — access terminated.</strong> Key <code>${ev.key}</code> on tenant <code>${ev.tenant_id}</code> has been revoked by M06 Credential Vault. Revocation is the nuclear option — all active sessions using this credential are immediately terminated. This action was triggered by: correlated threat signals (anomaly score, Zero-Trust deny, or admin override). Forensic copies of session logs have been preserved. The credential cannot be reinstated without a new issuance workflow and manager approval.`;
    if (action.includes("rotat")) return `<strong>Credential rotation completed — key refreshed automatically.</strong> Key <code>${ev.key}</code> was rotated as part of M06's automated key lifecycle management. Rotation replaces credentials before they expire or are compromised, maintaining continuity while eliminating static credential risk. Rotated keys are logged immutably. Previous key version is now invalidated. This is compliant with CIS Control 5, NIST SP 800-53 IA-5, and PCI-DSS Requirement 8.`;
    if (action==="issued") return `<strong>New credential issued — access granted.</strong> Key <code>${ev.key}</code> has been issued to an authorised service or user on tenant <code>${ev.tenant_id}</code>. All issued credentials have a maximum TTL configured per policy. The issuance was logged with full audit trail including approver, purpose, and expiry. Monitor for first-use patterns to detect credential theft immediately after issuance.`;
    return `<strong>Credential event logged by M06 Credential Vault.</strong> Action <code>${action}</code> on key <code>${ev.key}</code>. All credential lifecycle events are captured for SOX Section 404 compliance, PCI-DSS Requirement 8 audit trails, and NIST CSF Identity management reporting.`;
  }
  if (type==="cloud") {
    const finding = ev.finding_type||"";
    if (finding==="PUBLIC_BUCKET")        return `<strong>Public cloud storage bucket detected — CRITICAL data exposure risk.</strong> Resource <code>${ev.resource_id}</code> on ${(ev.provider||"").toUpperCase()} is publicly accessible from the internet with NO authentication required. Any data in this bucket can be downloaded by anyone with the URL. This is one of the most common causes of large-scale data breaches (Capital One, Twitch, GoDaddy). If this bucket contains PII, financial data, or credentials, a breach notification may be legally required. Remediate immediately.`;
    if (finding==="UNENCRYPTED_DB")       return `<strong>Unencrypted database detected — data at rest not protected.</strong> Resource <code>${ev.resource_id}</code> stores data without encryption. If this server is compromised, all stored data is immediately readable. Encryption at rest is required by GDPR Article 32, PCI-DSS Requirement 3.5, and HIPAA § 164.312. Enabling encryption is a non-disruptive operation that should be completed within 24 hours.`;
    if (finding==="OVERPRIVILEGED_ROLE")  return `<strong>Overprivileged IAM role — principle of least privilege violated.</strong> Role <code>${ev.resource_id}</code> has excessive permissions beyond what its function requires. Overprivileged roles are exploited in lateral movement attacks — once an attacker compromises one service, they can pivot to the entire cloud environment. The blast radius of a compromise using this role is: ${_int(3,12)} additional services exposed. Permissions must be scoped to minimum required.`;
    if (finding==="OPEN_SECURITY_GROUP")  return `<strong>Open security group / firewall rule detected.</strong> Network access controls on <code>${ev.resource_id}</code> allow inbound traffic from 0.0.0.0/0 (any IP). This exposes the resource to the entire internet. Even if the service has application-level auth, exposed ports are actively scanned by automated bots within minutes of deployment. Immediate restriction to specific CIDR ranges required.`;
    if (finding==="MFA_DISABLED")         return `<strong>MFA disabled on privileged account or console access.</strong> Resource <code>${ev.resource_id}</code> does not require multi-factor authentication. Accounts without MFA are ${_int(40,100)}× more likely to be compromised. Stolen passwords alone are sufficient for full account takeover. This is a critical gap — MFA must be enforced for all console access, especially for roles with admin-level permissions.`;
    if (finding==="ROOT_ACCESS_USED")     return `<strong>Root/owner account used directly — critical policy violation.</strong> Cloud root account <code>${ev.resource_id}</code> was accessed directly. Root access should NEVER be used for day-to-day operations — it bypasses all IAM permission boundaries and cannot be restricted. Best practice (CIS Benchmark, AWS Well-Architected) requires root access only for initial account setup and billing. Every root access event is treated as a potential compromise indicator.`;
    if (finding==="LOGGING_DISABLED")     return `<strong>Cloud audit logging disabled — blind spot created.</strong> Resource <code>${ev.resource_id}</code> has logging turned off. Without logs, you cannot detect breaches, investigate incidents, or meet compliance requirements. SOC 2, PCI-DSS Requirement 10, and GDPR Article 30 all require comprehensive audit logs. A logging gap means any attacker activity in this resource is completely invisible.`;
    return `<strong>Cloud security posture finding on ${(ev.provider||"").toUpperCase()}.</strong> M15 Multi-Cloud ISPM detected misconfiguration or security risk on resource <code>${ev.resource_id}</code>. Risk score: ${ev.risk_score||"—"}. All cloud findings are continuously monitored and scored for exploitability, data sensitivity, and blast radius. This finding requires remediation within the SLA window for its severity level.`;
  }
  return `<strong>Security event detected.</strong> Logged by IntegriShield monitoring engine. All events are retained for compliance audit trails and cross-module correlation analysis.`;
}

function _getFixSteps(type, ev) {
  const fixMap = {
    alert: {
      bulk_extraction:       ["Block source IP via M01 Gateway firewall rule","Immediately revoke all active credentials for " + (ev.user_id||"user") + " via M06 Credential Vault","Trigger forensic capture of all RFC call logs for the past 24 hours","Create incident ticket and assign PB-DATA-EXFIL playbook","Notify DLP team and legal counsel of potential data breach","File SIEM correlation report and preserve evidence chain"],
      privilege_escalation:  ["Terminate all active sessions for " + (ev.user_id||"user") + " immediately","Reset SAP authorisation profile to last known-good state","Audit all auth object changes made in the last 4 hours","Enforce step-up MFA re-authentication before access restoration","Review and revoke any new roles/profiles created by this user","Submit SOX incident report to internal audit"],
      shadow_endpoint:       ["Block RFC endpoint " + (ev.source_ip||"source") + " at the gateway layer (M01)","Alert SAP Basis team to investigate the function module origin","Perform full scan of SAP function module registry for similar shadow entries","Trace the deployment source of the endpoint — check transport logs","Update SAP RFC whitelist and rebuild the approved endpoint registry","File security advisory if supply-chain compromise is suspected"],
      credential_abuse:      ["Force immediate re-authentication for account " + (ev.user_id||"user") + " across all sessions","Trigger M06 emergency credential rotation for all keys associated with this account","Enable enhanced logging for this user for 30 days","Review all access in the past 24h for unauthorised data access","Alert the user via out-of-band channel (phone) to confirm compromise","Implement device certificate requirement for future sessions"],
      geo_anomaly:           ["Challenge session from " + (ev.source_ip||"IP") + " with MFA step-up immediately","If MFA fails, block the IP at the perimeter firewall","Add IP to M04 Zero-Trust geo-risk blocklist","Notify user via registered phone number to confirm travel","If travel not confirmed, assume compromise and revoke session","Review access logs for the past 72 hours from this IP"],
      data_staging:          ["Immediately quarantine the staging destination " + (ev.source_ip||"") + "","Revoke write access to staging locations for account " + (ev.user_id||""),"Block all egress to external file transfer services (mega.nz, etc.)","Trigger cloud key rotation if AWS/GCP/Azure resources were involved","Initiate PB-CLOUD-BREACH playbook for full containment","Notify legal team of potential breach — assess GDPR Article 33 obligations"],
      off_hours_rfc:         ["Elevate monitoring level to HIGH for account " + (ev.user_id||"user"),"Trigger MFA step-up challenge for next RFC call from this session","Review all RFC calls made in the last 2 hours for anomalies","Set automated alert if off-hours activity continues beyond 30 minutes","Cross-reference with badge access records to confirm physical presence","No immediate block required — escalate to Tier 2 analyst"],
      velocity_anomaly:      ["Rate-limit RFC calls from " + (ev.source_ip||"IP") + " to 10 req/min immediately","Challenge the session with CAPTCHA or MFA step-up","Alert SAP admin to check if automated scripts are running","If velocity continues, block source IP via M01 gateway","Audit the tool or script that is generating high-velocity calls","Review SAP workload monitor for resource impact"],
    },
    anomaly: {
      default: ["Investigate the session flagged by the Isolation Forest model","Cross-reference with SAP audit log for the same user/IP pair","If anomaly score > 0.85, auto-escalate to Tier 1 analyst","Apply Zero-Trust step-up challenge to the current session","If pattern continues for 2+ ticks, create incident and trigger playbook","Retain session logs for forensic analysis — do not overwrite"]
    },
    sap: {
      default: ["Terminate the flagged SAP MCP session for user " + (ev.user_id||""),"Review what data was accessed or exported in this session","Revoke SAP authorisation for the tool " + (ev.tool_name||"") + " temporarily","Compare against SAP change request log — validate authorisation","If no change request exists, escalate to SAP Basis security team","Preserve RFC call logs and session data for forensic audit"]
    },
    dlp: {
      default: ["Block further egress from account " + (ev.user_id||"") + " immediately","Quarantine the data that was transferred to " + (ev.destination||"destination") + " if recoverable","Assess the data transferred for PII/financial data classification","Notify data protection officer if GDPR Article 33 threshold is met","Submit DLP incident report with transfer details and data classification","Apply stricter DLP policy to this user account for 30 days"]
    },
    shadow: {
      default: ["Block RFC function " + (ev.endpoint||"") + " at M01 API Gateway immediately","Notify SAP Basis administrator to investigate function module origin","Scan entire SAP system for additional unknown/shadow RFC modules","Check transport management system for unauthorised deployments","If external source: initiate PB-SHADOW-API playbook","Update function module whitelist — trigger differential rescan"]
    },
    comp: {
      default: ["Log violation " + (ev.control_id||"") + " in GRC system immediately","Notify compliance officer and relevant framework owner","Initiate remediation workflow with assigned control owner","Assess if violation triggers breach notification obligations","Apply compensating controls while primary control is remediated","Schedule follow-up audit to confirm control restoration within SLA"]
    },
    incident: {
      default: ["Assign incident to on-call Tier 2 analyst immediately","Execute playbook " + (ev.playbook_id||"assigned") + " — all steps must be completed in order","Update incident status to INVESTIGATING in ticketing system","Preserve all evidence — do not modify affected systems","Notify CISO and legal if severity is CRITICAL","Post-incident: complete root cause analysis within 5 business days"]
    },
    sbom: {
      default: ["Patch all CVEs with CVSS score >= 7.0 within 30 days (critical: 7 days)","Replace insecure RFC function calls with approved secure alternatives","Update dependency versions in requirements.txt/package.json","Rebuild and redeploy container with patched base image","Re-run SBOM scan to confirm clean bill of materials","Update SBOM report in compliance artifact store (SOC2, ISO27001)"]
    },
    zt: {
      deny: ["Session has been auto-terminated by Zero-Trust — no additional blocking needed","Notify user via out-of-band channel if legitimate access was expected","Review failed controls: " + (() => { let fc=[]; try{fc=Array.isArray(ev.failed_controls)?ev.failed_controls:JSON.parse(ev.failed_controls||"[]")}catch{} return fc.join(", ")||"none"; })(),"If MFA failure: force re-enrolment of authenticator device","If geo-risk: challenge with manager approval for location exception","Monitor for further access attempts from same source in next 1 hour"],
      challenge: ["User must complete MFA step-up within 5 minutes","If MFA not completed, session auto-terminates — no action needed","Review why risk score exceeded challenge threshold","If pattern repeats 3+ times, consider blocking the source","Log challenge outcome in Zero-Trust audit trail","No data access occurs during challenge state — safe to monitor"],
      allow: ["No action required — session is within normal risk parameters","Session will continue to be monitored in real-time by Zero-Trust","Anomaly detection (M08) will flag any behavioural changes","All RFC calls during this session are logged for compliance","This event is retained for baseline model updates","Review if risk score trended up over recent sessions"],
    },
    cred: {
      revoked: ["Credential has been revoked — no further action needed","Verify that all active sessions using this credential have been terminated","Issue replacement credential through proper approval workflow if legitimate","Audit all actions taken using the revoked credential in past 48h","Notify the application or user that was using this credential","Update any hardcoded credential references in configuration files"],
      rotated: ["New rotated credential is now active — update all consuming services","Verify that legacy credential version is fully invalidated (confirm in Vault)","Check for any hardcoded uses of the old credential in codebases","Update CI/CD pipeline secrets if applicable","Log rotation event in credential lifecycle audit trail","Next rotation scheduled per policy (30/60/90 day cycle)"],
      default: ["Audit the context in which credential " + (ev.key||"") + " was issued/accessed","Verify the requesting service/user is authorised for this credential","Monitor first-use of newly issued credentials for anomalous behaviour","Ensure credential TTL is set per least-privilege access policy","Review Vault audit log for this credential path","Alert if credential is used outside expected service boundary"]
    },
    cloud: {
      PUBLIC_BUCKET:        ["Apply bucket policy: Block Public Access = true immediately","Enable server-side encryption (SSE-S3 or SSE-KMS) if not already enabled","Review bucket contents for sensitive data — classify and inventory","Enable CloudTrail/GCS audit logging for this bucket","Notify data owner and confirm intended access policy","Add bucket to automated CSPM scanning policy for continuous monitoring"],
      UNENCRYPTED_DB:       ["Enable encryption at rest on the database (AWS RDS/GCP Cloud SQL/Azure SQL)","Apply KMS customer-managed key for encrypted data","Rotate database credentials immediately (encryption prevents static key reuse)","Enable database audit logging and query logging","Notify DBA and application team of encryption requirement","Verify application can connect to encrypted instance before retiring unencrypted"],
      OVERPRIVILEGED_ROLE:  ["Apply principle of least privilege — remove all permissions not required","Use IAM Access Analyzer to generate minimal-permission policy","Detach all managed policies — apply inline policy with only required actions","Set permission boundary to cap maximum permissions","Enable CloudTrail for all API calls using this role","Review all resources accessible by this role and assess blast radius"],
      OPEN_SECURITY_GROUP:  ["Restrict inbound rule 0.0.0.0/0 to specific CIDR ranges (corporate IP + VPN)","Apply separate security groups for each tier (web, app, DB)","Enable VPC Flow Logs to audit all network traffic","Use a WAF in front of any public-facing endpoints","Set up automated alert for any future 0.0.0.0/0 security group rule creation","Run network exposure assessment to identify all public-facing resources"],
      MFA_DISABLED:         ["Enable MFA immediately for all console/API access","For AWS: use virtual MFA device or hardware security key","For GCP: enforce 2FA in Admin Console > Security","For Azure: enable Conditional Access with MFA for all admin roles","Disable all access keys for root/admin accounts — use MFA-protected roles instead","Audit all recent access to confirm no unauthorised activity during MFA gap"],
      ROOT_ACCESS_USED:     ["Investigate the justification for root access — confirm it was authorised","Enable MFA on root account if not already configured","Create least-privilege admin IAM roles for all day-to-day operations","Lock root account credentials in secure password manager (1 person max)","Set CloudTrail alert for any future root access events","Review all actions taken under root session — verify no unauthorised changes"],
      LOGGING_DISABLED:     ["Enable CloudTrail (AWS) / Cloud Audit Logs (GCP) / Activity Log (Azure) immediately","Apply log retention policy: minimum 1 year for compliance","Send logs to immutable S3 / GCS bucket with Object Lock","Set up real-time alerting on log delivery failures","Ensure all API calls, management events, and data events are logged","Verify log integrity with CloudTrail Log File Validation or equivalent"],
      default: ["Remediate the finding per cloud provider security best practices","Apply CIS Cloud Benchmark controls for the affected resource","Enable continuous compliance scanning via M15 ISPM policy","Assign remediation ownership to cloud infrastructure team","Set SLA: Critical findings < 24h, High < 7 days, Medium < 30 days","Re-scan after remediation to confirm finding is resolved"]
    }
  };

  if (type==="alert"||type==="gateway"||type==="rules") {
    const sc = ev.scenario||"";
    for (const [k,v] of Object.entries(fixMap.alert)) {
      if (sc.includes(k)) return v;
    }
    return fixMap.alert.off_hours_rfc;
  }
  if (type==="anomaly") return fixMap.anomaly.default;
  if (type==="sap")     return fixMap.sap.default;
  if (type==="dlp")     return fixMap.dlp.default;
  if (type==="shadow")  return fixMap.shadow.default;
  if (type==="comp")    return fixMap.comp.default;
  if (type==="incident")return fixMap.incident.default;
  if (type==="sbom")    return fixMap.sbom.default;
  if (type==="zt") {
    const dec = (ev.decision||"allow").toLowerCase();
    return fixMap.zt[dec] || fixMap.zt.allow;
  }
  if (type==="cred") {
    const act = (ev.action||"").toLowerCase();
    if (act.includes("revok")) return fixMap.cred.revoked;
    if (act.includes("rotat")) return fixMap.cred.rotated;
    return fixMap.cred.default;
  }
  if (type==="cloud") {
    return fixMap.cloud[ev.finding_type] || fixMap.cloud.default;
  }
  return ["Investigate the flagged event","Escalate to Tier 2 analyst if pattern continues","Log remediation steps in incident tracker","Apply compensating controls while root cause is identified","Verify fix effectiveness with follow-up scan","Close incident with post-mortem report"];
}

function applyFix(type, idx) {
  const arrMap = {
    alert:alerts, anomaly:anomalies, sap:sapEvents, dlp:dlpEvents,
    shadow:shadowEvents, comp:compEvents, incident:incEvents,
    sbom:sbomEvents, zt:ztEvents, cred:credEvents, cloud:cloudEvents,
    gateway:alerts, rules:alerts,
  };
  const arr = arrMap[type]; if (!arr || !arr[idx]) return;
  const ev  = arr[idx];
  const fixKey = ev.ts ? `${type}-${ev.ts}` : `${type}-${idx}`;
  fixedItems.add(fixKey);

  // Visual feedback in drawer
  const drwBadge = $("drw-badge"), drwTitle = $("drw-title");
  if (drwBadge) { drwBadge.textContent="✓ RESOLVED"; drwBadge.className="sev-badge sev-ok"; drwBadge.style.background="rgba(46,213,115,0.2)"; }
  if (drwTitle) drwTitle.textContent = "✓ RESOLVED — " + (drwTitle.textContent||"");

  const actionsEl = $("drw-actions");
  if (actionsEl) {
    actionsEl.innerHTML = `<div style="flex:1;padding:.55rem .8rem;border:1px solid rgba(46,213,115,.35);border-radius:6px;background:rgba(46,213,115,.12);color:#2ed573;font-size:.78rem;font-weight:700;text-align:center;animation:none">
      ✅ IntegriShield applied all ${_getFixSteps(type,ev).length} fix steps automatically
    </div>
    <button onclick="closeDetailDrawer()" style="padding:.5rem .9rem;border:1px solid rgba(255,255,255,.12);border-radius:6px;background:rgba(255,255,255,.06);color:#7a93b4;font-size:.76rem;cursor:pointer">Close</button>`;
  }

  // Type-specific success messages
  const msgs = {
    alert:    `⚡ Alert remediated — IP blocked, credentials revoked, incident created`,
    anomaly:  `🧠 Anomaly suppressed — session terminated, analyst notified`,
    sap:      `⚙️ SAP MCP session terminated — tool access revoked for ${ev.user_id||"user"}`,
    dlp:      `🔒 DLP violation remediated — egress blocked, data owner notified`,
    shadow:   `👁️ Shadow RFC ${ev.endpoint||"endpoint"} blocked — gateway rule applied`,
    comp:     `✅ Compliance violation logged — remediation workflow triggered`,
    incident: `🚨 Incident ${ev.incident_id||""} resolved — playbook completed`,
    sbom:     `📦 SBOM patch applied — CVEs remediated on ${ev.target||"package"}`,
    zt:       `🔐 Zero-Trust action applied — session policy updated`,
    cred:     `🔑 Credential action confirmed — vault updated for ${ev.key||"key"}`,
    cloud:    `☁️ Cloud misconfiguration fixed on ${ev.resource_id||"resource"}`,
    gateway:  `🛡️ Gateway rule applied — RFC call blocked`,
    rules:    `📏 Rule triggered and enforced — alert suppressed`,
  };
  showToast(msgs[type]||"✅ Fix applied by IntegriShield", "success", 5000);

  // Increment fix-applied KPI
  kpiBlocked += _int(3,8);

  setTimeout(()=>{ closeDetailDrawer(); updateAllUI(); }, 1500);
}

function closeDetailDrawer(e) {
  const overlay = $("detail-overlay");
  if (!overlay) return;
  if (e && e.target !== overlay && e.type !== "click") return;
  overlay.classList.add("hidden");
}

function demoActionAlt(action, type, param) {
  const msgs = {
    block: `🚫 ${param||type} blocked at perimeter — firewall rule propagated across all zones`,
    report: `📄 ${type.charAt(0).toUpperCase()+type.slice(1)} report exported — PDF sent to SOC team & CISO`,
  };
  showToast(msgs[action]||"Action executed", action==="block"?"warning":"info", 4000);
}

// Keep legacy alias
function showAlertDetail(idx) { showItemDetail("alert", idx); }
function demoAction(action, param) {
  const msgs = {
    block_ip: `🚫 IP ${param} blocked — firewall rule applied`, revoke_user: `🔑 ${param} sessions terminated`,
    create_incident: `🚨 Incident INC-${_incID+1} created`, export: `📄 Report exported`,
  };
  showToast(msgs[action]||"Action executed","success",4000);
  closeDetailDrawer();
}

// ── Auto-Tour ─────────────────────────────────────────────────
let autoTourInterval = null, autoTourIdx = 0, autoTourActive = false;
const TOUR_TABS = ['alerts','gateway','anomalies','rules','dlp','credentials',
  'shadow','compliance','incidents','sbom','zero-trust','sap','cloud'];

function toggleAutoTour() {
  if (autoTourActive) {
    autoTourActive = false;
    clearInterval(autoTourInterval); autoTourInterval = null;
    const b = $("auto-tour-btn"); if (b) { b.textContent = "▶ Auto Tour"; b.classList.remove("tour-active"); }
    showToast("Auto Tour stopped", "info", 2000);
    return;
  }
  if (!demo.active) { showToast("Start the demo first", "warning", 2000); return; }
  autoTourActive = true;
  autoTourIdx = 0;
  // navigate immediately to first tab
  _tourNav(TOUR_TABS[autoTourIdx++ % TOUR_TABS.length]);
  autoTourInterval = setInterval(() => {
    _tourNav(TOUR_TABS[autoTourIdx++ % TOUR_TABS.length]);
  }, 6000);
  const b = $("auto-tour-btn"); if (b) { b.textContent = "■ Stop Tour"; b.classList.add("tour-active"); }
  showToast("Auto Tour — cycling tabs every 6s. Click any tab to stop.", "info", 4000);
}

function _tourNav(tab) {
  // Internal navigation used by auto-tour (doesn't stop the tour)
  const btn = document.querySelector(`.nav-btn[data-tab="${tab}"]`);
  if (!btn) return;
  currentTab = tab;
  tabLastViewed[tab] = tabEventCounts[tab] || 0;
  document.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".tab-content").forEach(c=>c.classList.add("hidden"));
  const target = $(`tab-${tab}`);
  if (target) target.classList.remove("hidden");
  document.querySelector(".main-content")?.scrollTo({top:0,behavior:"smooth"});
  const onAlerts = tab === "alerts";
  ["stat-cards","exec-kpis"].forEach(id => { const el=$(id); if(el) el.classList.toggle("hidden",!onAlerts); });
  document.querySelectorAll(".chart-row, .module-health-section").forEach(el=>el.classList.toggle("hidden",!onAlerts));
  const bannerEl = $("scenario-banner"); if (bannerEl) bannerEl.classList.toggle("hidden", !demo.active);
  if (tab==="launcher") startLauncherPolling(); else stopLauncherPolling();
  renderActiveTab();
  updateBadges();
}

function stopAutoTour() {
  if (!autoTourActive) return;
  autoTourActive = false;
  clearInterval(autoTourInterval); autoTourInterval = null;
  const b = $("auto-tour-btn"); if (b) { b.textContent = "▶ Auto Tour"; b.classList.remove("tour-active"); }
}

// ── Badge helpers ─────────────────────────────────────────────
function updateBadges() {
  for (const [tab, total] of Object.entries(tabEventCounts)) {
    const unseen = total - (tabLastViewed[tab] || 0);
    const btn = document.getElementById(`nav-${tab}`);
    if (!btn) continue;
    let badge = btn.querySelector('.nav-badge');
    if (unseen > 0 && tab !== currentTab) {
      if (!badge) {
        badge = document.createElement('span');
        badge.className = 'nav-badge';
        btn.appendChild(badge);
      }
      badge.textContent = unseen > 99 ? '99+' : String(unseen);
      badge.classList.remove('hidden');
    } else if (badge) {
      badge.classList.add('hidden');
    }
  }
}

function clearAllBadges() {
  Object.keys(tabEventCounts).forEach(k => { tabEventCounts[k] = 0; });
  Object.keys(tabLastViewed).forEach(k => { tabLastViewed[k] = 0; });
  document.querySelectorAll('.nav-badge').forEach(b => b.classList.add('hidden'));
}

// ── Navigate ──────────────────────────────────────────────────
function navigateToTab(tabName) {
  // Stop auto-tour when user manually navigates
  stopAutoTour();
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (!btn) return;
  // Snapshot badge counts for this tab (clears its badge)
  currentTab = tabName;
  tabLastViewed[tabName] = tabEventCounts[tabName] || 0;
  document.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".tab-content").forEach(c=>c.classList.add("hidden"));
  const target = $(`tab-${tabName}`);
  if (target) target.classList.remove("hidden");
  document.querySelector(".main-content")?.scrollTo({top:0,behavior:"smooth"});

  // Show stat cards & charts only on alerts tab; scenario banner on all tabs when demo active
  const onAlerts = tabName === "alerts";
  ["stat-cards","exec-kpis"].forEach(id => {
    const el = $(id); if(el) el.classList.toggle("hidden", !onAlerts);
  });
  document.querySelectorAll(".chart-row, .module-health-section")
    .forEach(el=>el.classList.toggle("hidden", !onAlerts));
  const bannerEl = $("scenario-banner");
  if (bannerEl) bannerEl.classList.toggle("hidden", !demo.active);

  if (tabName==="launcher") startLauncherPolling(); else stopLauncherPolling();
  renderActiveTab();
  updateBadges();
  closeSidebar();
  closeCommandPalette();
}

// ── Sidebar ───────────────────────────────────────────────────
function openSidebar()  { ui.sidebar?.classList.add("open"); ui.sidebarOverlay?.classList.add("active","visible"); }
function closeSidebar() {
  ui.sidebar?.classList.remove("open");
  ui.sidebarOverlay?.classList.remove("visible");
  setTimeout(()=>ui.sidebarOverlay?.classList.remove("active"), 400);
}

// ── Command palette ───────────────────────────────────────────
const palette       = $("command-palette");
const paletteInput  = $("palette-input");
const paletteResults= $("palette-results");
const CMDS = [
  {label:"Alerts Feed",     tab:"alerts",      icon:"🔔",kw:"alerts feed overview"},
  {label:"Audit Log",       tab:"audit",        icon:"📋",kw:"audit log trail"},
  {label:"M01 Gateway",     tab:"gateway",      icon:"🛡️",kw:"m01 gateway api rfc"},
  {label:"M08 Anomaly",     tab:"anomalies",    icon:"🧠",kw:"m08 anomaly ml"},
  {label:"M09 DLP",         tab:"dlp",          icon:"🔒",kw:"m09 dlp data loss"},
  {label:"M11 Shadow",      tab:"shadow",       icon:"👁️",kw:"m11 shadow integration"},
  {label:"M05 SAP MCP",     tab:"sap",          icon:"⚙️",kw:"m05 sap mcp tool"},
  {label:"M07 Compliance",  tab:"compliance",   icon:"✅",kw:"m07 compliance sox gdpr"},
  {label:"M10 Incidents",   tab:"incidents",    icon:"🚨",kw:"m10 incident response playbook"},
  {label:"M13 SBOM",        tab:"sbom",         icon:"📦",kw:"m13 sbom cve scanner"},
  {label:"M12 Rules",       tab:"rules",        icon:"📏",kw:"m12 rules engine"},
  {label:"M04 Zero-Trust",  tab:"zero-trust",   icon:"🔐",kw:"m04 zero trust fabric"},
  {label:"M06 Credentials", tab:"credentials",  icon:"🔑",kw:"m06 credential vault"},
  {label:"M15 Cloud",       tab:"cloud",        icon:"☁️",kw:"m15 cloud aws gcp azure"},
  {label:"⚡ Launcher",     tab:"launcher",     icon:"⚡",kw:"launcher start stop module"},
];
let palIdx=0, palFiltered=[...CMDS];

function openCommandPalette() {
  if (!palette) return;
  palette.classList.remove("hidden");
  if (paletteInput) { paletteInput.value=""; paletteInput.focus(); }
  palFiltered=[...CMDS]; palIdx=0; renderPalette();
}
function closeCommandPalette() { palette?.classList.add("hidden"); }
function renderPalette() {
  if (!paletteResults) return;
  paletteResults.innerHTML = palFiltered.map((c,i)=>
    `<div class="palette-item ${i===palIdx?"active":""}" data-tab="${c.tab}" onclick="navigateToTab('${c.tab}')">
      <span class="palette-icon">${c.icon}</span>
      <span class="palette-label">${c.label}</span>
      <span class="palette-shortcut">${i<9?i+1:""}</span>
    </div>`).join("");
}

if (paletteInput) {
  paletteInput.addEventListener("input", ()=>{
    const q = paletteInput.value.toLowerCase().trim();
    palFiltered = q ? CMDS.filter(c=>c.label.toLowerCase().includes(q)||c.kw.includes(q)) : [...CMDS];
    palIdx=0; renderPalette();
  });
  paletteInput.addEventListener("keydown", e=>{
    if (e.key==="ArrowDown"){ e.preventDefault(); palIdx=(palIdx+1)%palFiltered.length; renderPalette(); }
    else if (e.key==="ArrowUp"){ e.preventDefault(); palIdx=(palIdx-1+palFiltered.length)%palFiltered.length; renderPalette(); }
    else if (e.key==="Enter"){ e.preventDefault(); if(palFiltered[palIdx]) navigateToTab(palFiltered[palIdx].tab); }
    else if (e.key==="Escape") closeCommandPalette();
  });
}
if (palette) palette.addEventListener("click", e=>{ if(e.target===palette) closeCommandPalette(); });

// ── Keyboard shortcuts ────────────────────────────────────────
document.addEventListener("keydown", e=>{
  if ((e.metaKey||e.ctrlKey) && e.key==="k") {
    e.preventDefault();
    palette?.classList.contains("hidden") ? openCommandPalette() : closeCommandPalette();
    return;
  }
  if (e.key==="Escape" && palette && !palette.classList.contains("hidden")) { closeCommandPalette(); return; }
  if (e.target.tagName==="INPUT"||e.target.tagName==="SELECT"||e.target.tagName==="TEXTAREA") return;
  if (palette?.classList.contains("hidden") && e.key>="1" && e.key<="9") {
    const tabs=["alerts","audit","gateway","anomalies","dlp","shadow","sap","compliance","incidents"];
    if (tabs[+e.key-1]) navigateToTab(tabs[+e.key-1]);
  }
});

// ── Toast ─────────────────────────────────────────────────────
const toastContainer = $("toast-container");
function showToast(message, type="info", duration=4000) {
  if (!toastContainer) return;
  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.innerHTML = `<span class="toast-icon">${type==="critical"?"🔴":type==="warning"?"🟡":type==="success"?"🟢":"🔵"}</span>
    <span class="toast-message">${message}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>`;
  toastContainer.prepend(t);
  requestAnimationFrame(()=>requestAnimationFrame(()=>t.classList.add("toast-visible")));
  setTimeout(()=>{ t.classList.remove("toast-visible"); setTimeout(()=>t.remove(),300); }, duration);
}

// ── Live clock ────────────────────────────────────────────────
function updateClock() {
  const el = $("live-clock"); if(!el) return;
  el.textContent = new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});
}
updateClock();
setInterval(updateClock, 1000);

// ── Card stagger ──────────────────────────────────────────────
function staggerCards() {
  document.querySelectorAll(".card, .ekpi, .chart-panel").forEach((c,i)=>{
    c.style.opacity="0"; c.style.transform="translateY(12px)";
    c.style.transition=`opacity 400ms ${i*40}ms cubic-bezier(.4,0,.2,1),transform 400ms ${i*40}ms cubic-bezier(.4,0,.2,1)`;
    requestAnimationFrame(()=>requestAnimationFrame(()=>{ c.style.opacity="1"; c.style.transform="none"; }));
  });
}

// ── Launcher ──────────────────────────────────────────────────
let launcherProcesses=[], launcherPolling=null;

function renderLauncher(processes) {
  const grid = $("launcher-grid");
  if (!grid) return;
  const notice = $("launcher-notice");

  // Update status bar
  const statusBar = $("launcher-status-bar");
  if (statusBar) {
    const totalMods = Object.keys(ALL_MODS).length;
    const activeMods = totalMods - stoppedModules.size;
    const running = demo.active;
    statusBar.innerHTML = `
      <span class="launcher-dot ${running?"running":"stopped"}"></span>
      <span style="font-weight:600;color:${running?"var(--ok)":"var(--text-dim)"}">Demo Engine: <strong>${running?"RUNNING":"STOPPED"}</strong></span>
      <span style="margin-left:auto;font-size:.72rem;color:var(--text-dim)">${running?activeMods:0} / ${totalMods} modules active</span>`;
  }

  if (demo.active || stoppedModules.size > 0 || !processes || processes.length === 0) {
    if (notice) notice.style.display = demo.active ? "none" : "block";
    const engineRunning = demo.active;
    grid.innerHTML = Object.entries(ALL_MODS).map(([name, info]) => {
      const stopped = stoppedModules.has(name) || !engineRunning;
      const dot   = stopped ? "stopped" : "running";
      const meta  = stopped
        ? `<span style="color:#ff4757">⏹ Stopped</span>`
        : `${info.type} · <span style="color:#00e5a0">● LIVE</span>`;
      return `<div class="launcher-card">
        <div class="launcher-card-header">
          <div class="launcher-dot ${dot}"></div>
          <span class="launcher-name">${name}</span>
          <span class="launcher-tag">${info.dev}</span>
        </div>
        <div class="launcher-meta">${meta}</div>
        <div class="launcher-actions">
          <button class="launch-btn launch-btn-stop" onclick="stopModule('${name}')" ${stopped?"disabled style='opacity:.4'":""}>■ Stop</button>
          <button class="launch-btn launch-btn-start" onclick="startModule('${name}')" ${!stopped?"disabled style='opacity:.4'":""}>▶ Start</button>
        </div>
      </div>`;
    }).join("");
    return;
  }

  if (!processes||processes.length===0) {
    if (notice) notice.style.display="block";
    grid.innerHTML=`<div style="grid-column:1/-1;text-align:center;color:#4a6080;padding:2rem">No modules found. Start the backend first.</div>`;
    return;
  }
  if (notice) notice.style.display="none";
  grid.innerHTML = processes.map(p=>{
    const running = p.status==="running";
    return `<div class="launcher-card">
      <div class="launcher-card-header">
        <div class="launcher-dot ${running?"running":"stopped"}"></div>
        <span class="launcher-name">${p.name||p.module}</span>
        <span class="launcher-tag">${p.dev||""}</span>
      </div>
      <div class="launcher-meta">${running?`🟢 Running · ${p.uptime_s||0}s uptime`:"⚫ Stopped"}</div>
      <div class="launcher-actions">
        <button class="launch-btn launch-btn-stop" onclick="stopModule('${p.name||p.module}')">■ Stop</button>
        <button class="launch-btn launch-btn-start" onclick="startModule('${p.name||p.module}')">▶ Start</button>
      </div>
    </div>`;
  }).join("");
}

function logLauncher(msg) {
  const log=$("launcher-log"); if(!log) return;
  const t=new Date().toLocaleTimeString();
  log.textContent=`[${t}] ${msg}\n`+(log.textContent==="No logs yet."?"":log.textContent);
}
function clearLauncherLog() { const l=$("launcher-log"); if(l) l.textContent="No logs yet."; }

function startModule(name) {
  // Try real backend first; fall back to engine control
  fetch(`${API_BASE}/api/modules/start`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({module:name})})
    .then(r=>r.json()).then(d=>{ logLauncher(`Started ${name}: ${d.status||"ok"}`); })
    .catch(()=>{});
  // Always control the local engine
  stoppedModules.delete(name);
  const allStopped = Object.keys(ALL_MODS).every(m => stoppedModules.has(m));
  if (!demo.active && !allStopped) {
    // Re-start engine if it was fully stopped
    demo.active = true;
    if (alerts.length === 0) {
      rampUp(() => { if (!demo.iid) demo.iid = setInterval(demoTick, POLL_MS); });
    } else {
      demo.iid = setInterval(demoTick, POLL_MS);
      demoTick();
    }
  }
  if (ui.backendStatus) ui.backendStatus.textContent = "DEMO MODE";
  if (ui.statusDot) ui.statusDot.className = "status-dot online";
  logLauncher(`[${new Date().toLocaleTimeString()}] ▶ ${name} started`);
  showToast(`▶ ${name} is now live`, "success", 3000);
  renderLauncher(launcherProcesses);
  updateAllUI();
}

function stopModule(name) {
  // Try real backend first; fall back to engine control
  fetch(`${API_BASE}/api/modules/stop`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({module:name})})
    .then(r=>r.json()).then(d=>{ logLauncher(`Stopped ${name}: ${d.status||"ok"}`); })
    .catch(()=>{});
  // Always control the local engine
  stoppedModules.add(name);
  // If every module is stopped, pause the whole engine
  const allStopped = Object.keys(ALL_MODS).every(m => stoppedModules.has(m));
  if (allStopped && demo.iid) {
    clearInterval(demo.iid);
    demo.iid = null;
    demo.active = false;
    if (ui.backendStatus) ui.backendStatus.textContent = "STOPPED";
    if (ui.statusDot) ui.statusDot.className = "status-dot offline";
    const b = $("scenario-banner"); if (b) b.classList.add("hidden");
  }
  logLauncher(`[${new Date().toLocaleTimeString()}] ■ ${name} stopped`);
  showToast(`■ ${name} stopped`, "warning", 3000);
  renderLauncher(launcherProcesses);
  updateAllUI();
}

function startAll() {
  stoppedModules.clear();
  if (!demo.active) {
    demo.active = true;
    rampUp(() => { if (!demo.iid) demo.iid = setInterval(demoTick, POLL_MS); });
  }
  if (ui.backendStatus) ui.backendStatus.textContent = "DEMO MODE";
  if (ui.statusDot) ui.statusDot.className = "status-dot online";
  logLauncher(`[${new Date().toLocaleTimeString()}] ▶ All modules started`);
  showToast("▶ All 15 modules started — real-time threat detection active", "success", 4000);
  renderLauncher(launcherProcesses);
  updateAllUI();
}

function stopAll() {
  Object.keys(ALL_MODS).forEach(m => stoppedModules.add(m));
  if (demo.iid) { clearInterval(demo.iid); demo.iid = null; }
  clearTimeout(demo.rampTimeout); demo.ramping = false; demo.rampTimeout = null;
  demo.active = false;
  stopAutoTour();
  clearAllBadges();
  if (ui.backendStatus) ui.backendStatus.textContent = "STOPPED";
  if (ui.statusDot) ui.statusDot.className = "status-dot offline";
  const b = $("scenario-banner"); if (b) b.classList.add("hidden");
  logLauncher(`[${new Date().toLocaleTimeString()}] ■ All modules stopped`);
  showToast("■ All modules stopped — data stream paused", "warning", 4000);
  renderLauncher(launcherProcesses);
}

async function fetchLauncherData() {
  try {
    const r = await fetch(`${API_BASE}/api/modules/processes`);
    const d = await r.json();
    launcherProcesses = d.processes||d.modules||[];
    renderLauncher(launcherProcesses);
  } catch { renderLauncher(launcherProcesses); }
}
function startLauncherPolling() {
  fetchLauncherData();
  if (!launcherPolling) launcherPolling = setInterval(fetchLauncherData, 3000);
}
function stopLauncherPolling() {
  if (launcherPolling) { clearInterval(launcherPolling); launcherPolling=null; }
}

// ── CONNECTORS M02 ───────────────────────────────────────────
function renderConnectors() {
  const list  = $("conn-list"), empty = $("conn-empty");
  const total = $("conn-total"), alerts_ = $("conn-alerts");
  const misc  = $("conn-misconfig"), healthy = $("conn-healthy");
  if (!list) return;
  if (total)   animateValue(total,   connEvents.length);
  if (alerts_) animateValue(alerts_, connEvents.filter(e=>e.status==="alert").length);
  if (misc)    animateValue(misc,    connEvents.filter(e=>e.status==="misconfigured").length);
  if (healthy) animateValue(healthy, connEvents.filter(e=>e.status==="healthy").length);
  const plat = fv('conn-platform-filter'), stat = fv('conn-status-filter'), q = fq('conn-search');
  let v = connEvents;
  if (plat !== 'all') v = v.filter(e=>e.platform===plat);
  if (stat !== 'all') v = v.filter(e=>e.status===stat);
  if (q) v = v.filter(e=>[e.connector,e.source_system,e.dest_system,e.finding].join(' ').toLowerCase().includes(q));
  setEmpty(list, empty, v);
  const statC = {alert:"#ff4757",misconfigured:"#ffa502",healthy:"#2ed573"};
  list.innerHTML = v.map(e => {
    const sc = statC[e.status]||"#7a93b4";
    const platLabel = {sap_btp:"SAP BTP",mulesoft:"MuleSoft",boomi:"Boomi",workato:"Workato"}[e.platform]||e.platform;
    return `<li class="alert-item">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${sc}22;color:${sc};padding:2px 8px;border-radius:4px">${(e.status||"unknown").toUpperCase()}</span>
        <span style="margin-left:.5rem;font-size:.78rem;color:#b0c4de;font-weight:600">${e.connector||"—"}</span>
        <span style="margin-left:.4rem;font-size:.68rem;background:rgba(76,130,247,.12);color:#7a9fd4;padding:1px 6px;border-radius:3px">${platLabel}</span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">${e.source_system||"—"} → ${e.dest_system||"—"}</div>
      <div class="alert-item-meta" style="color:${e.status==='healthy'?'#4a6280':'#e0904a'}">${e.finding||"—"}</div>
    </li>`;
  }).join("");
}

// ── TRAFFIC ANALYZER M03 ─────────────────────────────────────
function renderTraffic() {
  const list  = $("traffic-list"), empty = $("traffic-empty");
  const total = $("traffic-total"), pii = $("traffic-pii");
  const phi   = $("traffic-phi"), vol = $("traffic-volume");
  if (!list) return;
  if (total) animateValue(total, trafficEvents.length);
  if (pii)   animateValue(pii,   trafficEvents.filter(e=>e.classification==="PII").length);
  if (phi)   animateValue(phi,   trafficEvents.filter(e=>e.classification==="PHI").length);
  const totalBytes = trafficEvents.reduce((s,e)=>s+(+e.bytes||0),0);
  if (vol) vol.textContent = totalBytes>1e6?`${(totalBytes/1e6).toFixed(1)} MB`:`${(totalBytes/1e3).toFixed(0)} KB`;
  const cls = fv('traffic-class-filter'), dir = fv('traffic-dir-filter'), q = fq('traffic-search');
  let v = trafficEvents;
  if (cls !== 'all') v = v.filter(e=>e.classification===cls);
  if (dir !== 'all') v = v.filter(e=>e.direction===dir);
  if (q) v = v.filter(e=>[e.source,e.destination,e.classification,e.fields_detected].join(' ').toLowerCase().includes(q));
  setEmpty(list, empty, v);
  const clsC = {PII:"#ff4757",PHI:"#ff8b3d",FINANCIAL:"#ffa502",STANDARD:"#2ed573"};
  list.innerHTML = v.map(e => {
    const cc = clsC[e.classification]||"#7a93b4";
    const bytes = +e.bytes||0;
    const byteStr = bytes>1e6?`${(bytes/1e6).toFixed(1)} MB`:`${(bytes/1e3).toFixed(0)} KB`;
    return `<li class="alert-item ${e.policy_violation?'sev-high':''}">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${cc}22;color:${cc};padding:2px 8px;border-radius:4px">${e.classification||"STANDARD"}</span>
        <span style="margin-left:.5rem;font-size:.75rem;color:#b0c4de">${e.source||"—"} → ${e.destination||"—"}</span>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">Direction: ${e.direction||"—"} · Volume: <strong style="color:#b0c4de">${byteStr}</strong> · Fields: <code style="font-size:.68rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${e.fields_detected||"—"}</code></div>
      ${e.policy_violation?`<div class="alert-item-meta" style="color:#ff8b3d">⚠ Policy violation — sensitive data transmitted without DLP approval</div>`:""}
    </li>`;
  }).join("");
}

// ── WEBHOOK GATEWAY M14 ──────────────────────────────────────
function renderWebhooks() {
  const list  = $("wh-list"), empty = $("wh-empty");
  const total = $("wh-total"), acc = $("wh-accepted");
  const rej   = $("wh-rejected"), rl = $("wh-rate-limited");
  if (!list) return;
  if (total) animateValue(total, webhookEvents.length);
  if (acc)   animateValue(acc,   webhookEvents.filter(e=>e.result==="accepted").length);
  if (rej)   animateValue(rej,   webhookEvents.filter(e=>e.result==="rejected").length);
  if (rl)    animateValue(rl,    webhookEvents.filter(e=>e.result==="rate_limited").length);
  const res = fv('wh-result-filter'), src = fv('wh-source-filter'), q = fq('wh-search');
  let v = webhookEvents;
  if (res !== 'all') v = v.filter(e=>e.result===res);
  if (src !== 'all') v = v.filter(e=>e.source===src);
  if (q) v = v.filter(e=>[e.source,e.event_type,e.source_ip].join(' ').toLowerCase().includes(q));
  setEmpty(list, empty, v);
  const resC = {accepted:"#2ed573",rejected:"#ff4757",rate_limited:"#ffa502"};
  list.innerHTML = v.map(e => {
    const rc = resC[e.result]||"#7a93b4";
    const sigC = e.signature_valid?"#2ed573":"#ff4757";
    return `<li class="alert-item ${e.result==='rejected'?'sev-high':''}">
      <div class="alert-item-row">
        <span style="font-size:.7rem;font-weight:700;background:${rc}22;color:${rc};padding:2px 8px;border-radius:4px">${(e.result||"unknown").toUpperCase().replace('_',' ')}</span>
        <span style="margin-left:.5rem;font-size:.75rem;color:#b0c4de;font-weight:600">${e.source||"—"}</span>
        <code style="margin-left:.4rem;font-size:.68rem;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:3px;color:#b0c4de">${e.event_type||"—"}</code>
        <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>
      </div>
      <div class="alert-item-meta">IP: ${e.source_ip||"—"} · Signature: <span style="color:${sigC}">${e.signature_valid?"✓ Valid":"✗ Invalid"}</span> · Latency: ${e.latency_ms||0}ms</div>
    </li>`;
  }).join("");
}

// ── CLAUDE CHAT ───────────────────────────────────────────────
let chatOpen = false;
const chatHistory = [];

function toggleChat() {
  chatOpen = !chatOpen;
  const panel = $("chat-panel");
  if (panel) panel.classList.toggle("hidden", !chatOpen);
  if (chatOpen) {
    const inp = $("chat-input");
    if (inp) setTimeout(() => inp.focus(), 100);
    const badge = $("chat-fab-badge");
    if (badge) badge.style.display = "none";
  }
}

function chatKeyDown(e) {
  if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
}

function sendSuggestion(el) {
  const inp = $("chat-input");
  if (inp) { inp.value = el.textContent; sendChatMessage(); }
}

// ── Local hard-trained response engine (no API key required) ──
// Uses live dashboard data + pattern matching to generate SAP-security answers
function _chatLocalAnswer(text) {
  const q = text.toLowerCase();
  const pick = (arr, n=3) => arr.slice(0, n);
  const list = (items) => items.length ? items.map(s => "• " + s).join("\n") : "None detected.";

  // Helper: live stats
  const stats = {
    totalAlerts: alerts.length,
    critical: alerts.filter(a => a.severity === "critical").length,
    high: alerts.filter(a => a.severity === "high").length,
    offHours: alerts.filter(a => a.scenario === "off_hours_rfc").length,
    bulk: alerts.filter(a => a.scenario === "bulk_extraction").length,
    velocity: alerts.filter(a => a.scenario === "velocity_anomaly").length,
    shadow: shadowEvents.length,
    dlpViol: dlpEvents.length,
    anomHigh: anomalies.filter(a => parseFloat(a.anomaly_score || 0) > 0.7).length,
    incOpen: incEvents.filter(i => (i.status || "").toLowerCase() === "open").length,
    incResolved: incEvents.filter(i => (i.status || "").toLowerCase() === "resolved").length,
    compViol: compEvents.filter(e => (e.result || "").toLowerCase() === "violation").length,
    cveVuln: sbomEvents.filter(s => (s.scan_status || "") === "VULNERABLE").length,
    ztDenied: ztEvents.filter(z => (z.decision || "") === "deny").length,
    cloudCrit: cloudEvents.filter(c => (c.raw_severity || c.severity || "").toLowerCase() === "critical").length,
  };

  // SAP_ALL / super-user questions
  if (/sap[_ ]?all|super[_ ]?user|excessive privilege|god role/.test(q)) {
    return {
      tools: ["list_users", "get_user_roles", "check_critical_auth"],
      text:
`Found 4 users with SAP_ALL or equivalent super-user authority:

• BASIS_ADMIN (SAP_ALL + SAP_NEW) — last login 2h ago, MFA: ✓
• FIREFIGHTER_01 (S_A.ADMIN) — emergency access, expires in 3d
• BATCH_USER_07 (SAP_ALL) — dormant 47 days ⚠ RECOMMEND REVOKE
• DEVELOPER_CI (S_DEVELOP + S_TCODE all) — CI/CD service account

Risk assessment: BATCH_USER_07 should be removed — dormant accounts with SAP_ALL are the #1 audit finding. I've queued a compliance evidence entry in M07.`
    };
  }

  // SoD violations
  if (/sod|segregation|separation of duties|conflict/.test(q)) {
    return {
      tools: ["get_sod_violations", "get_user_roles"],
      text:
`Detected 7 active SoD violations across the SAP landscape:

• MM_USER_04: Create Vendor (MK01) + Approve Payment (F-53) — CRITICAL
• FI_USER_12: Post Invoice (FB60) + Pay Vendor (F-58) — CRITICAL
• HR_USER_09: Maintain Master Data (PA30) + Run Payroll (PC00_M10_CALC) — HIGH
• PR_USER_03: Create PO (ME21N) + Receive Goods (MIGO) — HIGH
• +3 additional medium-risk combinations

These map to SOX ITGC-04 and are feeding directly into M07 Compliance Autopilot. Recommend running mitigation workflow for the 2 CRITICAL findings today.`
    };
  }

  // Dormant / inactive users
  if (/dormant|inactive|unused account|stale user/.test(q)) {
    return {
      tools: ["get_dormant_users", "list_users"],
      text:
`Found 23 dormant SAP accounts (no login >30 days):

• 8 with privileged roles — ⚠ HIGH RISK
• 12 standard dialog users
• 3 RFC/batch service accounts

Top concerns:
• BATCH_USER_07 — SAP_ALL, 47d dormant
• CONSULTANT_EY — S_A.DEVELOP, 62d dormant (contractor departed?)
• AUDITOR_Q3 — S_A.SYSTEM, 89d dormant

Recommend bulk-lock all 8 privileged dormant accounts. M06 Credential Vault can auto-rotate their credentials as part of offboarding.`
    };
  }

  // Alerts overview
  if (/critical alert|show alert|active alert|current alert|high severity/.test(q)) {
    const top = pick(alerts.filter(a => a.severity === "critical" || a.severity === "high"), 5);
    return {
      tools: ["list_alerts", "query_events"],
      text:
`Live alerts in the last window: ${stats.totalAlerts} total, ${stats.critical} CRITICAL, ${stats.high} HIGH.

Top findings right now:
${top.length ? top.map(a => `• [${(a.severity||"").toUpperCase()}] ${a.message || a.scenario || "alert"} — user=${a.user_id || "?"} ip=${a.source_ip || "?"}`).join("\n") : "• No high-severity alerts currently"}

Breakdown by scenario:
• Off-hours RFC: ${stats.offHours}
• Bulk extraction: ${stats.bulk}
• Velocity anomaly: ${stats.velocity}
• Shadow endpoints: ${stats.shadow}`
    };
  }

  // Anomaly questions
  if (/anomal|isolation forest|ml (score|model)|rfc anomaly/.test(q)) {
    const top = pick([...anomalies].sort((a,b) => parseFloat(b.anomaly_score||0) - parseFloat(a.anomaly_score||0)), 5);
    return {
      tools: ["get_anomaly_scores", "monitor_rfc_calls"],
      text:
`M08 Isolation Forest has scored ${anomalies.length} events in this window — ${stats.anomHigh} above the 0.7 high-risk threshold.

Top anomalies:
${top.length ? top.map(a => `• score=${(parseFloat(a.anomaly_score||0)).toFixed(2)} · ${a.classification || a.reason || "baseline deviation"} · user=${a.user_id || "?"}`).join("\n") : "• No anomalies scored yet — waiting for baseline."}

The model detects deviations in call volume, time-of-day, data volume extracted, and new endpoint patterns. All high-risk scores are auto-escalated to M10 Incident Response.`
    };
  }

  // DLP
  if (/dlp|data loss|pii|phi|exfil|leak|sensitive data/.test(q)) {
    return {
      tools: ["query_events", "list_alerts"],
      text:
`M09 DLP is actively scanning data in transit. ${stats.dlpViol} violations in the current window.

Categories detected:
• Bulk export (>500 rows from sensitive tables): ${dlpEvents.filter(d => (d.rule_type||d.rule||"").toLowerCase().includes("bulk")).length}
• PII in outbound payload: ${dlpEvents.filter(d => (d.classification||"").includes("PII")).length}
• Blocklist hits (known exfil destinations): ${dlpEvents.filter(d => (d.rule_type||d.rule||"").toLowerCase().includes("block")).length}
• Data staging to untrusted endpoints: ${dlpEvents.filter(d => (d.rule_type||d.rule||"").toLowerCase().includes("staging")).length}

Most sensitive table accessed: PA0008 (payroll). DLP is masking or blocking all non-compliant flows before they exit the middleware layer.`
    };
  }

  // Compliance
  if (/compliance|sox|gdpr|pci|hipaa|soc ?2|iso ?27001|audit report/.test(q)) {
    return {
      tools: ["analyze_report_access", "query_events"],
      text:
`M07 Compliance Autopilot is continuously collecting evidence across 6 frameworks:

• SOX — 94% pass rate
• GDPR — 87% pass rate
• PCI-DSS — 91% pass rate
• NIST-CSF — 96% pass rate
• ISO 27001 — 89% pass rate
• HIPAA — 93% pass rate

${stats.compViol} active violations, auto-mapped to specific controls. One-click report export is available from the Compliance tab. All evidence is backed by immutable audit vault entries.`
    };
  }

  // Security policy gaps / posture
  if (/policy|posture|gap|weakness|hardening/.test(q)) {
    return {
      tools: ["get_security_policy", "check_critical_auth"],
      text:
`SAP security policy review — current gaps vs CIS / SAP RSECPOL baseline:

• MIN_PASSWORD_LENGTH = 8 (recommend ≥12) — GAP
• PASSWORD_CHANGE_INTERVAL = 180d (recommend 90d) — GAP
• FAILED_LOGON_LOCKOUT = not set (recommend 5) — GAP
• RFC_TRUSTED_SYSTEMS: 4 trusted (review 2 legacy entries)
• S_RFC auth checks: ENABLED ✓
• Audit log retention: 730d ✓

3 hardening recommendations queued for M07 Compliance workflow.`
    };
  }

  // Failed logins / brute force
  if (/failed login|brute|lockout|password spray/.test(q)) {
    return {
      tools: ["get_failed_logins", "get_locked_users"],
      text:
`Failed login activity (last 24h):

• 142 failed logons across 18 users
• 3 accounts locked: HR_USER_02, FI_TEMP_06, SAP_DEV_11
• 1 suspected spray pattern: 37 distinct users attempted from IP 203.0.113.44 ⚠

M04 Zero-Trust denied ${stats.ztDenied} requests in the same window. The 203.0.113.44 pattern has been auto-fed to M10 Incident Response and M12 Rules Engine has generated a geo-block rule.`
    };
  }

  // Incidents
  if (/incident|response|playbook|containment/.test(q)) {
    return {
      tools: ["list_alerts", "query_events"],
      text:
`M10 Incident Response status:

• Open: ${stats.incOpen}
• Investigating: ${incEvents.filter(i => (i.status||"").toLowerCase() === "investigating").length}
• Resolved: ${stats.incResolved}

Active playbooks auto-trigger on critical detections: quarantine integration → capture forensics → notify SOC → generate AI remediation steps. Mean time to contain is running at ~2.3s.`
    };
  }

  // Shadow IT
  if (/shadow|unknown endpoint|rogue|undocumented|unregistered/.test(q)) {
    return {
      tools: ["query_events", "list_alerts"],
      text:
`M11 Shadow Integration Discovery — ${stats.shadow} detections in the current window.

These are undocumented integrations that IT does not know about: new REST endpoints, scheduled jobs, file transfers, or webhooks. Each is auto-classified and surfaced for review. 48% of surveyed orgs cite API sprawl as their biggest security challenge — this module closes that gap.`
    };
  }

  // SBOM / CVE
  if (/sbom|cve|vulnerab|dependency|package|library/.test(q)) {
    return {
      tools: ["query_events"],
      text:
`M13 SBOM Scanner (CycloneDX 1.4):

• Total scans: ${sbomEvents.length}
• Components vulnerable: ${stats.cveVuln}
• Clean: ${sbomEvents.length - stats.cveVuln}

Top CVEs detected in middleware dependencies are prioritised by CVSS + exploit availability. SAP ABAP static analysis checks for insecure RFC patterns and hard-coded credentials.`
    };
  }

  // Zero-trust
  if (/zero.?trust|mfa|device trust|risk score|access decision/.test(q)) {
    return {
      tools: ["query_events"],
      text:
`M04 Zero-Trust Fabric — every integration call is authenticated, authorised, and encrypted (even internal service-to-service).

• Allowed: ${ztEvents.filter(z => z.decision === "allow").length}
• Denied: ${stats.ztDenied}
• Challenged (step-up MFA): ${ztEvents.filter(z => z.decision === "challenge").length}

Risk score inputs: device trust, geo-velocity, prior auth failures, resource sensitivity, time-of-day baseline.`
    };
  }

  // Cloud posture
  if (/cloud|aws|azure|gcp|ispm|misconfig/.test(q)) {
    return {
      tools: ["query_events"],
      text:
`M15 Multi-Cloud ISPM — posture findings across AWS, GCP, Azure, SAP BTP:

• CRITICAL: ${stats.cloudCrit}
• HIGH: ${cloudEvents.filter(c => (c.raw_severity||c.severity||"").toLowerCase() === "high").length}
• AWS: ${cloudEvents.filter(c => (c.provider||"").toLowerCase() === "aws").length}
• GCP: ${cloudEvents.filter(c => (c.provider||"").toLowerCase() === "gcp").length}
• Azure: ${cloudEvents.filter(c => (c.provider||"").toLowerCase() === "azure").length}

Most common findings: over-privileged IAM roles, public S3 buckets, unencrypted secrets in env vars.`
    };
  }

  // Credentials
  if (/credential|secret|key rotation|vault|token/.test(q)) {
    return {
      tools: ["query_events"],
      text:
`M06 Credential Vault status:

• Issued: ${credEvents.filter(e => e.action === "issued").length}
• Rotated: ${credEvents.filter(e => e.action === "rotated").length}
• Revoked: ${credEvents.filter(e => e.action === "revoked").length}
• Accessed: ${credEvents.filter(e => e.action === "accessed").length}

Stale or over-privileged credentials are flagged by AI analysis. All rotations are event-sourced into the audit vault for compliance evidence.`
    };
  }

  // RFC monitoring
  if (/rfc|remote function|abap/.test(q)) {
    return {
      tools: ["monitor_rfc_calls", "query_events"],
      text:
`RFC monitoring — M01 Gateway + M08 Anomaly combined view:

• Total RFC calls: ${alerts.length}
• Off-hours: ${stats.offHours}
• Bulk extractions: ${stats.bulk}
• Velocity spikes: ${stats.velocity}

Most-invoked destinations: RFC_READ_TABLE, BAPI_USER_GET_DETAIL, SXPG_COMMAND_EXECUTE. Any RFC call classified as anomalous is scored by Isolation Forest in <50ms.`
    };
  }

  // Generic / help
  if (/help|what can you|who are you|capability|feature/.test(q) || text.length < 6) {
    return {
      tools: [],
      text:
`I'm your IntegriShield SAP security analyst — I have 17 SAP security tools plus live access to all 15 modules:

Try asking about:
• "Who has SAP_ALL?"
• "Any SoD violations?"
• "Show critical alerts"
• "Dormant users?"
• "Recent RFC anomalies"
• "Compliance posture for SOX"
• "DLP violations today"
• "Failed logins in last 24h"
• "Shadow endpoints detected"

All answers use live dashboard data from the platform.`
    };
  }

  // Default fallback with live data summary
  return {
    tools: ["query_events", "list_alerts"],
    text:
`Live security posture right now:

• Active alerts: ${stats.totalAlerts} (${stats.critical} critical, ${stats.high} high)
• ML anomalies above 0.7: ${stats.anomHigh}
• DLP violations: ${stats.dlpViol}
• Shadow endpoints: ${stats.shadow}
• Open incidents: ${stats.incOpen}
• Compliance violations: ${stats.compViol}

I can go deeper on SAP_ALL holders, SoD conflicts, dormant users, RFC anomalies, DLP, compliance frameworks, or zero-trust decisions. What would you like to investigate?`
  };
}

async function sendChatMessage() {
  const inp  = $("chat-input");
  const send = $("chat-send");
  const msgs = $("chat-messages");
  if (!inp || !msgs) return;
  const text = inp.value.trim();
  if (!text) return;

  // Append user message
  inp.value = "";
  inp.style.height = "auto";
  msgs.innerHTML += `<div class="chat-msg user">${escHtml(text)}</div>`;

  // Typing indicator
  const typingId = "chat-typing-" + Date.now();
  msgs.innerHTML += `<div class="chat-msg typing" id="${typingId}">Claude is thinking…</div>`;
  msgs.scrollTop = msgs.scrollHeight;

  if (send) send.disabled = true;
  chatHistory.push({ role: "user", content: text });

  // Simulate realistic "thinking" latency then respond from local engine
  const delay = 600 + Math.floor(Math.random() * 700);
  await new Promise(r => setTimeout(r, delay));

  const answer = _chatLocalAnswer(text);
  const typing = $(typingId);
  if (typing) typing.remove();

  let toolHtml = "";
  if (answer.tools && answer.tools.length) {
    toolHtml = `<div style="margin-bottom:.4rem;display:flex;flex-wrap:wrap;gap:.2rem">` +
      answer.tools.map(t => `<span class="chat-tool-pill">⚙ ${t}</span>`).join("") +
      `</div>`;
  }
  const body = escHtml(answer.text).replace(/\n/g, "<br>");
  msgs.innerHTML += `<div class="chat-msg assistant">${toolHtml}${body}</div>`;
  chatHistory.push({ role: "assistant", content: answer.text });

  msgs.scrollTop = msgs.scrollHeight;
  if (send) send.disabled = false;
  if (inp) inp.focus();
}

function escHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

// ── CSV Export ────────────────────────────────────────────────
function exportCSV(type) {
  const arrMap = {
    alerts: alerts, anomaly: anomalies, dlp: dlpEvents, shadow: shadowEvents,
    sap: sapEvents, compliance: compEvents, incidents: incEvents, sbom: sbomEvents,
    rules: alerts, zt: ztEvents, credentials: credEvents, cloud: cloudEvents,
    gateway: alerts, connectors: connEvents, traffic: trafficEvents, webhooks: webhookEvents,
  };
  const arr = arrMap[type] || [];
  if (!arr.length) { showToast("No data to export", "warning", 2000); return; }
  const keys = [...new Set(arr.flatMap(r => Object.keys(r)))].filter(k => k !== '_type');
  const rows = [keys.join(','), ...arr.map(r => keys.map(k => {
    const v = r[k] ?? '';
    const s = String(Array.isArray(v) ? v.join(';') : v).replace(/"/g, '""');
    return s.includes(',') || s.includes('"') || s.includes('\n') ? `"${s}"` : s;
  }).join(','))];
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `integrishield-${type}-${new Date().toISOString().slice(0,19).replace(/:/g,'-')}.csv`;
  a.click(); URL.revokeObjectURL(a.href);
  showToast(`⬇ ${arr.length} ${type} records exported to CSV`, "success", 3000);
}

// ── Filter helpers ────────────────────────────────────────────
const fv = id => { const el = $(id); return el ? el.value : 'all'; };
const fq = id => { const el = $(id); return el ? el.value.toLowerCase().trim() : ''; };

// ── Filter listeners ──────────────────────────────────────────
if (ui.scenarioFilter) ui.scenarioFilter.addEventListener("change", renderAlerts);
if (ui.severityFilter) ui.severityFilter.addEventListener("change", renderAlerts);
if (ui.auditFilter)    ui.auditFilter.addEventListener("change", renderAudit);

// Gateway filters
['gw-search','gw-scenario-filter','gw-severity-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderGateway);
});
// Anomaly filters
['anom-search','anom-class-filter','anom-score-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderAnomaly);
});
// DLP filters
['dlp-search','dlp-rule-filter','dlp-sev-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderDlp);
});
// Shadow filters
['shadow-search','shadow-sev-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderShadow);
});
// SAP filters
['sap-search','sap-tool-filter','sap-flag-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderSap);
});
// Compliance filters
['comp-fw-filter','comp-result-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener('change', renderCompliance);
});
// Incidents filters
['inc-search','inc-status-filter','inc-sev-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderIncidents);
});
// SBOM filters
['sbom-search','sbom-status-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderSbom);
});
// Rules filters
['rules-search','rules-scenario-filter','rules-sev-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderRules);
});
// Zero-Trust filters
['zt-search','zt-decision-filter','zt-risk-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderZeroTrust);
});
// Credentials filters
['cred-search','cred-action-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderCredentials);
});
// Cloud filters
['cloud-search','cloud-provider-filter','cloud-sev-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderCloud);
});
// Connector filters
['conn-search','conn-platform-filter','conn-status-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderConnectors);
});
// Traffic filters
['traffic-search','traffic-class-filter','traffic-dir-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderTraffic);
});
// Webhook filters
['wh-search','wh-result-filter','wh-source-filter'].forEach(id => {
  const el = $(id); if (el) el.addEventListener(el.tagName==='SELECT'?'change':'input', renderWebhooks);
});

// ── Theme toggle ──────────────────────────────────────────────
const themeToggleBtn = document.getElementById("theme-toggle");
if (themeToggleBtn) {
  const currentTheme = localStorage.getItem("theme") || "dark";
  document.documentElement.setAttribute("data-theme", currentTheme);
  themeToggleBtn.querySelector(".theme-icon").textContent = currentTheme === "dark" ? "☀" : "☾";

  themeToggleBtn.addEventListener("click", () => {
    let theme = document.documentElement.getAttribute("data-theme");
    let newTheme = theme === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
    themeToggleBtn.querySelector(".theme-icon").textContent = newTheme === "dark" ? "☀" : "☾";
  });
}

// ── Sidebar nav ───────────────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach(btn=>btn.addEventListener("click",()=>navigateToTab(btn.dataset.tab)));
if (ui.sidebarToggle)  ui.sidebarToggle.addEventListener("click",()=>ui.sidebar?.classList.contains("open")?closeSidebar():openSidebar());
if (ui.sidebarOverlay) ui.sidebarOverlay.addEventListener("click", closeSidebar);

// ── Detail overlay close on backdrop click ────────────────────
const detailOverlay = $("detail-overlay");
if (detailOverlay) detailOverlay.addEventListener("click", e=>{ if(e.target===detailOverlay) closeDetailDrawer(); });

// ── Main sync ─────────────────────────────────────────────────
async function syncData() {
  try {
    const [aR,auR,stR,anR,sR,cR,dR,iR,shR,sbR,zR,crR,clR,mR] = await Promise.all([
      fetch(`${API_BASE}/api/alerts?limit=80`).then(r=>r.json()),
      fetch(`${API_BASE}/api/audit?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/stats`).then(r=>r.json()),
      fetch(`${API_BASE}/api/anomalies?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/sap-activity?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/compliance?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/dlp?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/incidents?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/shadow?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/sbom?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/zero-trust?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/credentials?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/cloud-posture?limit=60`).then(r=>r.json()),
      fetch(`${API_BASE}/api/modules/health`).then(r=>r.json()),
    ]);

    if (demo.active) stopDemo();

    alerts=aR.alerts||[]; auditRows=auR.rows||[]; anomalies=anR.anomalies||[];
    sapEvents=sR.events||[]; compEvents=cR.findings||[]; dlpEvents=dR.violations||[];
    incEvents=iR.incidents||[]; shadowEvents=shR.detections||[]; sbomEvents=sbR.scans||[];
    ztEvents=zR.evaluations||[]; credEvents=crR.events||[]; cloudEvents=clR.findings||[];

    if (ui.backendStatus) ui.backendStatus.textContent="connected";
    if (ui.statusDot)     ui.statusDot.className="status-dot online";
    updateAllUI();

  } catch {
    // Backend not available — maintain current state, do NOT auto-start demo
    if (ui.backendStatus) ui.backendStatus.textContent = demo.active ? "DEMO MODE" : "DEMO READY";
    if (ui.statusDot) ui.statusDot.className = demo.active ? "status-dot online" : "status-dot offline";
    if (demo.active) updateAllUI();
  }
}

// ── Init ──────────────────────────────────────────────────────
function init() {
  initCharts();
  staggerCards();
  navigateToTab("alerts"); // Open on live Alerts Feed
  // Auto-start the demo engine so ALL 15 modules populate immediately
  startDemo();
  syncData();
  setInterval(syncData, POLL_MS);
  setTimeout(()=>showToast("IntegriShield SOC · All 15 modules live · Press ⌘K to navigate","info",6000), 800);
}

init();
