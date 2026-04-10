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
    ztEvents=[], credEvents=[], cloudEvents=[], prevAlertCount=0;

// ── Demo engine ───────────────────────────────────────────────
const demo = { active:false, tick:0, scIdx:0, phIdx:0, phTick:0, ctx:null, iid:null };
let _incID = 1000;

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
  credIssued:$("cred-issued"), credRotated:$("cred-rotated"), credRevoked:$("cred-revoked"),
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
  const gc = "rgba(40,58,90,0.2)", tc = "#4a6080";

  const actx = $("alert-chart").getContext("2d");
  const ag = actx.createLinearGradient(0,0,0,190);
  ag.addColorStop(0,"rgba(91,141,239,0.15)"); ag.addColorStop(1,"rgba(91,141,239,0)");
  alertChart = new Chart(actx, {
    type:"line",
    data:{ labels:[], datasets:[{ label:"Alerts", data:[], borderColor:"#5b8def",
      backgroundColor:ag, borderWidth:2, fill:true, tension:0.4, pointRadius:0,
      pointHoverRadius:5, pointHoverBackgroundColor:"#5b8def", pointHoverBorderColor:"#fff", pointHoverBorderWidth:2 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:400},
      interaction:{mode:"index",intersect:false},
      scales:{
        x:{grid:{color:gc,drawBorder:false},ticks:{color:tc,font:{size:10,family:"Inter"},maxTicksLimit:8},border:{display:false}},
        y:{beginAtZero:true,grid:{color:gc,drawBorder:false},ticks:{color:tc,font:{size:10,family:"Inter"},precision:0,maxTicksLimit:5},border:{display:false}}
      },
      plugins:{ legend:{display:false},
        tooltip:{backgroundColor:"rgba(14,22,38,0.9)",titleColor:"#eaf0f7",bodyColor:"#b0c4de",
          borderColor:"rgba(91,141,239,0.3)",borderWidth:1,cornerRadius:8,padding:10,titleFont:{weight:"600"},displayColors:false} } }
  });

  severityChart = new Chart($("severity-chart").getContext("2d"), {
    type:"doughnut",
    data:{ labels:["Critical","High","Medium","Low"],
      datasets:[{ data:[0,0,0,0], backgroundColor:["#ff4757","#ff8b3d","#ffa502","#2ed573"],
        borderColor:"rgba(14,22,38,0.8)", borderWidth:3, hoverOffset:8 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:600},
      cutout:"70%",
      plugins:{ legend:{position:"bottom",labels:{color:"#7a93b4",font:{size:10,family:"Inter"},padding:12,usePointStyle:true,pointStyleWidth:8}},
        tooltip:{backgroundColor:"rgba(14,22,38,0.9)",titleColor:"#eaf0f7",bodyColor:"#b0c4de",borderColor:"rgba(91,141,239,0.3)",borderWidth:1,cornerRadius:8,padding:10} } }
  });

  rulesChart = new Chart($("rules-chart").getContext("2d"), {
    type:"doughnut",
    data:{ labels:["Bulk Extract","Off-Hours","Shadow EP","Velocity","Other"],
      datasets:[{ data:[0,0,0,0,0], backgroundColor:["#ff4757","#ffa502","#ff8b3d","#5b8def","#a17fe0"],
        borderColor:"rgba(14,22,38,0.8)", borderWidth:3, hoverOffset:8 }] },
    options:{ responsive:true, maintainAspectRatio:false, animation:{duration:600},
      cutout:"70%",
      plugins:{ legend:{position:"bottom",labels:{color:"#7a93b4",font:{size:10,family:"Inter"},padding:10,usePointStyle:true,pointStyleWidth:8}},
        tooltip:{backgroundColor:"rgba(14,22,38,0.9)",titleColor:"#eaf0f7",bodyColor:"#b0c4de",borderColor:"rgba(91,141,239,0.3)",borderWidth:1,cornerRadius:8,padding:10} } }
  });

  const rgEl = $("risk-gauge-chart");
  if (rgEl) {
    riskGaugeChart = new Chart(rgEl.getContext("2d"), {
      type:"doughnut",
      data:{ datasets:[{ data:[0,100], backgroundColor:["#2ed573","rgba(40,58,90,0.25)"],
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
  }

  const push = (arr, item, max=80) => { arr.unshift(item); if (arr.length>max) arr.pop(); };
  const auditMap = {
    alert:"m12-rules-engine", anomaly:"m08-anomaly-detection", sap:"m05-sap-mcp-suite",
    zt:"m04-zero-trust-fabric", cred:"m06-credential-vault", comp:"m07-compliance-autopilot",
    dlp:"m09-dlp", inc:"m10-incident-response", shadow:"m11-shadow-integration",
    sbom:"m13-sbom-scanner", cloud:"m15-multicloud-ispm",
  };

  for (const ev of evts) {
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
    if (t==="audit")   push(auditRows, ev, 60);
    else if (auditMap[t]) push(auditRows, {actor:auditMap[t],action:t+"_event",module:auditMap[t],status:"ok",ts:ev.ts}, 60);
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
  updateAllUI();
}

function startDemo() {
  if (demo.active) return;
  demo.active = true;
  console.info("IntegriShield: demo mode — scenario engine active");
  showToast("⚡ Live simulation active — all 13 modules streaming", "info", 5000);
  for (let i = 0; i < 20; i++) demoTick(); // prime all panels
  demo.iid = setInterval(demoTick, POLL_MS);
}

function stopDemo() {
  if (demo.iid) clearInterval(demo.iid);
  demo.active = false;
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

  if (ui.backendStatus) ui.backendStatus.textContent = demo.active ? "demo" : "connected";
  if (ui.statusDot)     ui.statusDot.className = "status-dot online";
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
    "m01-api-gateway-shield":{events:total},  "m03-traffic-analyzer":{events:_int(10,40)},
    "m08-anomaly-detection":{events:anomalies.length},  "m09-dlp":{events:dlpEvents.length},
    "m11-shadow-integration":{events:shadowEvents.length}, "m05-sap-mcp-suite":{events:sapEvents.length},
    "m07-compliance-autopilot":{events:compEvents.length},"m10-incident-response":{events:incEvents.length},
    "m13-sbom-scanner":{events:sbomEvents.length},"m04-zero-trust-fabric":{events:ztEvents.length},
    "m06-credential-vault":{events:credEvents.length},"m12-rules-engine":{events:total},
    "m15-multicloud-ispm":{events:cloudEvents.length},
  };
  updatePills(modStatus);
  if (ui.moduleGrid) renderModuleGrid(modStatus);

  // Exec KPIs
  kpiBlocked += _int(1,3);
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
  if (ui.kpiMttd) ui.kpiMttd.textContent = "3.2s";

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
}

// ── Pills ─────────────────────────────────────────────────────
const PILL_MAP = {
  "m01-api-gateway-shield":"m01","m04-zero-trust-fabric":"m04",
  "m05-sap-mcp-suite":"m05","m06-credential-vault":"m06",
  "m07-compliance-autopilot":"m07","m08-anomaly-detection":"m08",
  "m09-dlp":"m09","m10-incident-response":"m10",
  "m11-shadow-integration":"m11","m12-rules-engine":"m12",
  "m13-sbom-scanner":"m13","m15-multicloud-ispm":"m15",
};
function updatePills(mods) {
  for (const [mod,id] of Object.entries(PILL_MAP)) {
    const el = $(`pill-${id}`);
    if (el) el.className = mods[mod] ? "pill pill-ok" : "pill pill-offline";
  }
}

// ── Module grid ───────────────────────────────────────────────
const ALL_MODS = {
  "m01-api-gateway-shield":{dev:"Dev 1",type:"FastAPI"},
  "m03-traffic-analyzer":{dev:"Dev 2",type:"Consumer"},
  "m08-anomaly-detection":{dev:"Dev 2",type:"Consumer"},
  "m09-dlp":{dev:"Dev 2",type:"Consumer"},
  "m11-shadow-integration":{dev:"Dev 2",type:"Consumer"},
  "m05-sap-mcp-suite":{dev:"Dev 3",type:"FastAPI"},
  "m07-compliance-autopilot":{dev:"Dev 3",type:"FastAPI"},
  "m10-incident-response":{dev:"Dev 3",type:"FastAPI"},
  "m13-sbom-scanner":{dev:"Dev 3",type:"FastAPI"},
  "m04-zero-trust-fabric":{dev:"Dev 4",type:"FastAPI"},
  "m06-credential-vault":{dev:"Dev 4",type:"FastAPI"},
  "m12-rules-engine":{dev:"Dev 4",type:"FastAPI"},
  "m15-multicloud-ispm":{dev:"Dev 4",type:"FastAPI"},
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
  ui.alertsList.innerHTML = v.map((a, i) => {
    const sev = (a.severity||"low").toLowerCase();
    return `<li class="alert-item sev-${sev} clickable-item" onclick="showAlertDetail(${i})">
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
  setEmpty(ui.gatewayList, ui.gatewayEmpty, alerts);
  ui.gatewayList.innerHTML = alerts.map(a => {
    const sev = (a.severity||"low").toLowerCase();
    return li(`ev-gateway sev-${sev}`,
      `<strong>RFC CALL</strong> <span class="panel-subtitle">${scl(a.scenario)}</span>
       <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
       <span class="panel-subtitle" style="margin-left:.5rem">${ts(a.ts)}</span>`,
      `<code style="font-size:.73rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${a.message||"—"}</code>`,
      `IP: ${a.source_ip||"—"} · user: ${a.user_id||"—"} · latency: ${ms(a.latencyMs)}`
    );
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
  setEmpty(ui.anomalyList, ui.anomalyEmpty, anomalies);
  ui.anomalyList.innerHTML = anomalies.map(a => {
    const sc = parseFloat(a.anomaly_score||0);
    const cls = sc>0.7?"sev-critical":sc>0.4?"sev-medium":"sev-low";
    const barColor = sc>0.7?"#ff4757":sc>0.4?"#ffa502":"#2ed573";
    return `<li class="alert-item ev-anomaly ${cls}">
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
    </li>`;
  }).join("");
}

// ── DLP M09 ───────────────────────────────────────────────────
function renderDlp() {
  if (!ui.dlpList) return;
  animateValue(ui.dlpBulk,      dlpEvents.filter(e=>(e.rule||"").includes("bulk")).length);
  animateValue(ui.dlpStaging,   dlpEvents.filter(e=>(e.rule||"").includes("staging")).length);
  animateValue(ui.dlpBlocklist, dlpEvents.filter(e=>(e.rule||"").includes("blocklist")).length);
  setEmpty(ui.dlpList, ui.dlpEmpty, dlpEvents);
  ui.dlpList.innerHTML = dlpEvents.map(e => {
    const sev = (e.severity||"high").toLowerCase();
    return li(`ev-dlp sev-${sev}`,
      `<strong>${(e.rule||"DLP VIOLATION").toUpperCase().replace(/_/g," ")}</strong>
       <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
       <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>`,
      `<span style="color:#ff8b3d">📤 ${byt(e.bytes_out)}</span> · <span>${(e.row_count||0).toLocaleString()} rows</span> · dest: <code style="font-size:.72rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:3px">${e.destination||"—"}</code>`,
      `user: ${e.user_id||"—"}`
    );
  }).join("");
}

// ── SHADOW M11 ────────────────────────────────────────────────
function renderShadow() {
  if (!ui.shadowList) return;
  const hosts = new Set(shadowEvents.map(e=>e.endpoint||"").filter(Boolean)).size;
  animateValue(ui.shadowTotal,  shadowEvents.length);
  animateValue(ui.shadowUnique, hosts);
  setEmpty(ui.shadowList, ui.shadowEmpty, shadowEvents);
  ui.shadowList.innerHTML = shadowEvents.map(e => {
    const sev = (e.severity||"high").toLowerCase();
    return li(`ev-shadow sev-${sev}`,
      `<strong>SHADOW ENDPOINT</strong>
       <code style="font-size:.75rem;background:rgba(255,139,61,.15);color:#ff8b3d;padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.endpoint||"unknown"}</code>
       <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      e.message||"Unknown RFC endpoint invoked",
      `user: ${e.user_id||"—"} · IP: ${e.source_ip||"—"} · calls: ${e.call_count||"—"}`
    );
  }).join("");
}

// ── SAP MCP M05 ───────────────────────────────────────────────
function renderSap() {
  if (!ui.sapList) return;
  animateValue(ui.sapTotal,     sapEvents.length);
  animateValue(ui.sapAnomalous, sapEvents.filter(e=>e.anomalous||e.flagged).length);
  setEmpty(ui.sapList, ui.sapEmpty, sapEvents);
  ui.sapList.innerHTML = sapEvents.map(e => {
    const flagged = e.anomalous || e.flagged;
    const toolColor = flagged ? "#ff4757" : "#5b8def";
    return li(`ev-sap ${flagged?"sev-critical":""}`,
      `<strong>SAP MCP</strong>
       <code style="font-size:.73rem;background:${flagged?"rgba(255,71,87,.15)":"rgba(91,141,239,.12)"};color:${toolColor};padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.tool_name||"tool"}</code>
       ${flagged?`<span class="sev-badge sev-critical" style="margin-left:.5rem">FLAGGED</span>`:""}
       <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `result: <strong style="color:${e.result==="success"?flagged?"#ff4757":"#2ed573":"#ffa502"}">${e.result||"—"}</strong> · tenant: ${e.tenant_id||"—"}`,
      `user: ${e.user_id||"—"}`
    );
  }).join("");
}

// ── COMPLIANCE M07 ────────────────────────────────────────────
function renderCompliance() {
  if (!ui.complianceList) return;
  animateValue(ui.compViolations, compEvents.filter(e=>(e.result||"")==="violation").length);
  animateValue(ui.compWarnings,   compEvents.filter(e=>(e.result||"")==="warning").length);
  animateValue(ui.compPassed,     compEvents.filter(e=>(e.result||"")==="pass").length);
  animateValue(ui.compFrameworks, new Set(compEvents.map(e=>e.framework||"").filter(Boolean)).size);
  setEmpty(ui.complianceList, ui.complianceEmpty, compEvents);

  const fwColors = {SOX:"#ff4757",GDPR:"#5b8def","PCI-DSS":"#ff8b3d","NIST-CSF":"#2ed573",ISO27001:"#a17fe0",HIPAA:"#39c5cf"};

  ui.complianceList.innerHTML = compEvents.map(e => {
    const res = (e.result||"unknown").toLowerCase();
    const cls = res==="violation"?"sev-critical":res==="warning"?"sev-medium":"sev-low";
    const fwC = fwColors[e.framework]||"#7a93b4";
    return li(`ev-compliance ${cls}`,
      `<strong>${res.toUpperCase()}</strong>
       <span style="background:${fwC}22;color:${fwC};font-size:.68rem;font-weight:700;padding:2px 8px;border-radius:4px;margin-left:.5rem">${e.framework||"—"}</span>
       <code style="font-size:.7rem;background:rgba(255,255,255,.06);padding:1px 6px;border-radius:3px;margin-left:.4rem">${e.control_id||"—"}</code>
       <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      e.description||e.message||"—"
    );
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
  setEmpty(ui.incidentsList, ui.incidentsEmpty, incEvents);

  const stColor = {open:"#ff4757",investigating:"#ffa502",in_progress:"#ffa502",active:"#ffa502",resolved:"#2ed573",closed:"#2ed573",contained:"#2ed573"};

  ui.incidentsList.innerHTML = incEvents.map(e => {
    const st  = (e.status||"open").toLowerCase();
    const stC = stColor[st]||"#7a93b4";
    const cls = st==="open"?"sev-critical":["investigating","in_progress","active"].includes(st)?"sev-medium":"sev-low";
    return li(`ev-incident ${cls}`,
      `<strong>${e.incident_id||"INC-?"}</strong>
       <span class="panel-subtitle" style="margin-left:.4rem">${e.title||"incident"}</span>
       <span style="background:${stC}22;color:${stC};font-size:.65rem;font-weight:700;padding:2px 7px;border-radius:4px;margin-left:auto">${st.toUpperCase()}</span>
       <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>`,
      `severity: <span style="color:${e.severity==="critical"?"#ff4757":e.severity==="high"?"#ff8b3d":"#ffa502"}">${(e.severity||"—").toUpperCase()}</span>
       · source: ${e.source_module||"—"}`,
      `playbook: <code style="font-size:.7rem;background:rgba(91,141,239,.12);color:#5b8def;padding:1px 6px;border-radius:3px">${e.playbook_id||"none"}</code>
       ${e.playbook_run?`<span style="color:#2ed573;font-size:.7rem;margin-left:.4rem">▶ Running</span>`:""}`
    );
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
  const done  = Math.min(steps.length, Math.floor(demo.tick/3) % (steps.length+1));
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
  setEmpty(ui.sbomList, ui.sbomEmpty, sbomEvents);
  ui.sbomList.innerHTML = sbomEvents.map(e => {
    const vuln = parseInt(e.cve_count||0)>0 || parseInt(e.insecure_rfc_count||0)>0;
    const cls  = e.scan_status==="VULNERABLE"?"sev-critical":"sev-low";
    return li(`ev-sbom ${cls}`,
      `<span style="font-size:.7rem;font-weight:700;background:${vuln?"rgba(255,71,87,.2)":"rgba(46,213,115,.15)"};color:${vuln?"#ff4757":"#2ed573"};padding:2px 8px;border-radius:4px">${e.scan_status||"SCAN"}</span>
       <code style="font-size:.73rem;background:rgba(255,255,255,.06);padding:2px 7px;border-radius:4px;margin-left:.5rem;color:#b0c4de">${e.target||"—"}</code>
       <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `CVEs: <strong style="color:${parseInt(e.cve_count||0)>0?"#ff4757":"#2ed573"}">${e.cve_count||0}</strong>
       · Insecure RFC: <strong style="color:${parseInt(e.insecure_rfc_count||0)>0?"#ffa502":"#2ed573"}">${e.insecure_rfc_count||0}</strong>
       · format: CycloneDX 1.4`
    );
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
  setEmpty(ui.rulesList, ui.rulesEmpty, alerts);
  ui.rulesList.innerHTML = alerts.map(a => {
    const sev = (a.severity||"medium").toLowerCase();
    const ruleColor = {bulk_extraction:"#ff4757",off_hours_rfc:"#ffa502",shadow_endpoint:"#ff8b3d",velocity_anomaly:"#5b8def",data_staging:"#ff4757",credential_abuse:"#a17fe0",privilege_escalation:"#ff4757",geo_anomaly:"#ffa502"}[a.scenario]||"#7a93b4";
    return li(`ev-rules sev-${sev}`,
      `<span style="font-size:.7rem;font-weight:700;background:${ruleColor}22;color:${ruleColor};padding:2px 8px;border-radius:4px">${scl(a.scenario)||"RULE"}</span>
       <span class="sev-badge sev-${sev}" style="margin-left:.4rem">${sev.toUpperCase()}</span>
       <span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>`,
      a.message||"—",
      `${ms(a.latencyMs)} · IP: ${a.source_ip||"—"} · user: ${a.user_id||"—"}`
    );
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
  setEmpty(ui.ztList, ui.ztEmpty, ztEvents);
  ui.ztList.innerHTML = ztEvents.map(e => {
    const dec  = (e.decision||"evaluated").toLowerCase();
    const dC   = dec==="allow"?"#2ed573":dec==="deny"?"#ff4757":"#ffa502";
    const risk = parseFloat(e.risk_score||0);
    let fc = [];
    try { fc = Array.isArray(e.failed_controls) ? e.failed_controls : JSON.parse(e.failed_controls||"[]"); } catch {}
    return `<li class="alert-item ev-zt-${dec}">
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
    </li>`;
  }).join("");
}

// ── CREDENTIALS M06 ───────────────────────────────────────────
function renderCredentials() {
  if (!ui.credList) return;
  animateValue(ui.credIssued,  credEvents.filter(e=>(e.action||"").includes("issu")||e.action==="accessed").length);
  animateValue(ui.credRotated, credEvents.filter(e=>(e.action||"").includes("rotat")).length);
  animateValue(ui.credRevoked, credEvents.filter(e=>(e.action||"").includes("revok")).length);
  setEmpty(ui.credList, ui.credEmpty, credEvents);
  const icons = {issued:"🔑",accessed:"🔑",rotated:"🔄",revoked:"❌",default:"🔐"};
  ui.credList.innerHTML = credEvents.map(e => {
    const act   = e.action||"event";
    const icon  = icons[act]||icons.default;
    const actC  = act.includes("revok")?"#ff4757":act.includes("rotat")?"#ffa502":"#2ed573";
    return li("ev-credential",
      `<span style="font-size:.85rem">${icon}</span>
       <strong style="color:${actC};margin-left:.3rem">${act.toUpperCase()}</strong>
       <code style="font-size:.7rem;background:rgba(255,255,255,.06);padding:1px 7px;border-radius:4px;margin-left:.5rem;color:#b0c4de">${e.key||"—"}</code>
       <span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `tenant: ${e.tenant_id||"—"} · status: <span style="color:${actC}">${e.status||act}</span>`
    );
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
  setEmpty(ui.cloudList, ui.cloudEmpty, cloudEvents);
  const provC = {aws:"#ff9900",gcp:"#4285f4",azure:"#00a4ef"};
  const provBg = {aws:"rgba(255,153,0,.15)",gcp:"rgba(66,133,244,.15)",azure:"rgba(0,164,239,.15)"};
  ui.cloudList.innerHTML = cloudEvents.map(e => {
    const prov = (e.provider||"cloud").toLowerCase();
    const sev  = (e.raw_severity||e.severity||"medium").toLowerCase();
    const pc   = provC[prov]||"#7a93b4";
    const pb   = provBg[prov]||"rgba(255,255,255,.06)";
    return li(`ev-cloud sev-${sev}`,
      `<span style="font-size:.7rem;font-weight:700;background:${pb};color:${pc};padding:2px 8px;border-radius:4px">${prov.toUpperCase()}</span>
       <code style="font-size:.7rem;background:rgba(255,71,87,.1);color:#ff8b8b;padding:2px 7px;border-radius:4px;margin-left:.5rem">${e.finding_type||"FINDING"}</code>
       <span class="sev-badge sev-${sev}" style="margin-left:auto">${sev.toUpperCase()}</span>
       <span class="panel-subtitle" style="margin-left:.5rem">${ts(e.ts)}</span>`,
      `<code style="font-size:.68rem;background:rgba(255,255,255,.04);padding:1px 6px;border-radius:3px;color:#7a93b4">${e.resource_id||"—"}</code>`,
      `risk score: <strong style="color:${parseFloat(e.risk_score||0)>0.7?"#ff4757":"#ffa502"}">${e.risk_score||"—"}</strong>`
    );
  }).join("");
}

// ── Alert detail drawer ───────────────────────────────────────
let _currentAlerts = [];
function showAlertDetail(idx) {
  // Use filtered view same as renderAlerts
  let v = alerts;
  const sc = ui.scenarioFilter ? ui.scenarioFilter.value : "all";
  const sv = ui.severityFilter ? ui.severityFilter.value : "all";
  if (sc !== "all") v = v.filter(a => a.scenario === sc);
  if (sv !== "all") v = v.filter(a => a.severity === sv);
  _currentAlerts = v;
  const a = v[idx]; if (!a) return;

  const overlay = $("detail-overlay");
  if (!overlay) return;

  const sev = (a.severity||"medium").toLowerCase();
  const drwBadge = $("drw-badge"), drwTitle = $("drw-title"),
        drwBody  = $("drw-body"),  drwActions = $("drw-actions");

  if (drwBadge) { drwBadge.textContent = sev.toUpperCase(); drwBadge.className = `sev-badge sev-${sev}`; }
  if (drwTitle) drwTitle.textContent = a.message || "Security Alert";

  const corrAlerts = alerts.filter(x=>x!==a&&(x.source_ip===a.source_ip||x.user_id===a.user_id)).slice(0,3);
  const corrAnom   = anomalies.filter(x=>x.source_ip===a.source_ip||x.user_id===a.user_id).slice(0,2);
  const corrDlp    = dlpEvents.filter(x=>x.user_id===a.user_id).slice(0,2);
  const corrZT     = ztEvents.filter(x=>x.source_ip===a.source_ip||x.user_id===a.user_id).slice(0,2);
  const corrCount  = corrAlerts.length+corrAnom.length+corrDlp.length+corrZT.length;

  if (drwBody) drwBody.innerHTML = `
    <div>
      <div class="drw-section-title">Event Details</div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem">
        <div class="drw-field"><label>Timestamp</label><span>${new Date(a.ts).toLocaleString()}</span></div>
        <div class="drw-field"><label>Severity</label><span class="sev-badge sev-${sev}">${sev.toUpperCase()}</span></div>
        <div class="drw-field"><label>Scenario</label><span>${scl(a.scenario)}</span></div>
        <div class="drw-field"><label>Latency</label><span>${ms(a.latencyMs)}</span></div>
        <div class="drw-field"><label>Source IP</label><code>${a.source_ip||"—"}</code></div>
        <div class="drw-field"><label>User</label><code>${a.user_id||"—"}</code></div>
      </div>
    </div>
    <div>
      <div class="drw-section-title">🧠 AI Analysis</div>
      <div style="background:rgba(91,141,239,.07);border:1px solid rgba(91,141,239,.18);border-radius:6px;padding:.75rem;font-size:.78rem;color:#b0c4de;line-height:1.6">
        ${_aiExplain(a)}
      </div>
    </div>
    ${corrCount>0?`
    <div>
      <div class="drw-section-title">🔗 Correlated Events (${corrCount})</div>
      ${corrAlerts.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(255,71,87,.08);color:#ff9aa2">⚠️ ALERT: ${x.message||x.scenario} — ${ts(x.ts)}</div>`).join("")}
      ${corrAnom.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(161,127,224,.09);color:#c4a5f5">🧠 ANOMALY: score ${x.anomaly_score} · ${x.classification} — ${ts(x.ts)}</div>`).join("")}
      ${corrDlp.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(57,197,207,.07);color:#67e8f9">🔒 DLP: ${x.rule} · ${byt(x.bytes_out)} — ${ts(x.ts)}</div>`).join("")}
      ${corrZT.map(x=>`<div style="font-size:.73rem;padding:4px 8px;border-radius:4px;margin-bottom:3px;background:rgba(91,141,239,.09);color:#93bbff">🔐 ZERO-TRUST: ${(x.decision||"").toUpperCase()} · risk ${x.risk_score} — ${ts(x.ts)}</div>`).join("")}
    </div>`:""}
  `;

  if (drwActions) drwActions.innerHTML = `
    <button onclick="demoAction('block_ip','${a.source_ip||""}')"
      style="flex:1;min-width:110px;padding:.5rem .7rem;border:1px solid rgba(255,71,87,.3);border-radius:6px;background:rgba(255,71,87,.18);color:#ff4757;font-size:.76rem;font-weight:600;cursor:pointer">
      🚫 Block IP ${a.source_ip||""}
    </button>
    <button onclick="demoAction('revoke_user','${a.user_id||""}')"
      style="flex:1;min-width:110px;padding:.5rem .7rem;border:1px solid rgba(255,165,2,.28);border-radius:6px;background:rgba(255,165,2,.16);color:#ffa502;font-size:.76rem;font-weight:600;cursor:pointer">
      🔑 Revoke ${a.user_id||"User"}
    </button>
    <button onclick="demoAction('create_incident','${a.scenario||""}')"
      style="flex:1;min-width:110px;padding:.5rem .7rem;border:1px solid rgba(91,141,239,.3);border-radius:6px;background:rgba(91,141,239,.18);color:#5b8def;font-size:.76rem;font-weight:600;cursor:pointer">
      🚨 Create Incident
    </button>
    <button onclick="demoAction('export','')"
      style="flex:1;min-width:110px;padding:.5rem .7rem;border:1px solid rgba(46,213,115,.22);border-radius:6px;background:rgba(46,213,115,.12);color:#2ed573;font-size:.76rem;font-weight:600;cursor:pointer">
      📄 Export Report
    </button>
  `;

  overlay.classList.remove("hidden");
}

function closeDetailDrawer(e) {
  const overlay = $("detail-overlay");
  if (!overlay) return;
  if (e && e.target !== overlay && e.type !== "click") return;
  overlay.classList.add("hidden");
}

function demoAction(action, param) {
  const msgs = {
    block_ip:        `🚫 IP ${param} blocked — firewall rule applied across all zones`,
    revoke_user:     `🔑 All sessions for ${param} terminated — credentials revoked`,
    create_incident: `🚨 Incident INC-${_incID+1} created — playbook auto-triggered`,
    export:          `📄 Incident report exported — PDF sent to SOC team & CISO`,
  };
  showToast(msgs[action]||"Action executed", "success", 4000);
  closeDetailDrawer();
}

function _aiExplain(a) {
  const sc = a.scenario||"";
  if (sc.includes("bulk_extraction"))      return `<strong>High-confidence data exfiltration.</strong> User <code>${a.user_id}</code> invoked RFC_READ_TABLE at anomalous velocity. Isolation Forest score: <strong>0.94</strong>. Cross-referenced with ${_int(2,5)} prior off-hours sessions from same IP. <strong>→ Immediate credential revocation + forensic capture recommended.</strong>`;
  if (sc.includes("privilege_escalation")) return `<strong>Unauthorized privilege escalation detected.</strong> SUSR_USER_AUTH_FOR_OBJ_GET called outside change window. Zero-Trust denied (risk: 0.97). SOX AC-2 and NIST IA-2 violated. <strong>→ Terminate session, audit all recent auth changes.</strong>`;
  if (sc.includes("shadow_endpoint"))      return `<strong>Unknown RFC endpoint from external IP.</strong> No registered business owner for this function. External origin suggests supply-chain or insider threat vector. <strong>→ Block endpoint, initiate full SAP system scan.</strong>`;
  if (sc.includes("credential_abuse"))     return `<strong>Credential used from ${_int(3,8)} geolocations simultaneously.</strong> Indicates credential compromise or sharing. Zero-Trust risk score: 0.78. <strong>→ Force re-auth with MFA, review recent access logs.</strong>`;
  if (sc.includes("geo_anomaly"))          return `<strong>Access from high-risk geolocation.</strong> IP ${a.source_ip} maps to region outside corporate policy. No prior sessions from this location. <strong>→ Challenge with MFA, apply geo-block if unapproved.</strong>`;
  if (sc.includes("data_staging"))         return `<strong>Data staging activity detected.</strong> Large volume write to external destination. Cloud misconfiguration may have enabled exfiltration path. <strong>→ Revoke cloud keys, remediate S3/storage permissions immediately.</strong>`;
  return `<strong>Anomalous activity pattern.</strong> Behaviour deviation from baseline: score ${_flt(0.55,0.92)}. Correlated with ${_int(2,5)} recent events from same source. <strong>→ Investigate and monitor for escalation.</strong>`;
}

// ── Navigate ──────────────────────────────────────────────────
function navigateToTab(tabName) {
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (!btn) return;
  document.querySelectorAll(".nav-btn").forEach(b=>b.classList.remove("active"));
  btn.classList.add("active");
  document.querySelectorAll(".tab-content").forEach(c=>c.classList.add("hidden"));
  const target = $(`tab-${tabName}`);
  if (target) target.classList.remove("hidden");
  document.querySelector(".main-content")?.scrollTo({top:0,behavior:"smooth"});

  // Show overview sections only on alerts tab
  const onAlerts = tabName === "alerts";
  ["stat-cards","exec-kpis","scenario-banner"].forEach(id => {
    const el = $(id); if(el) el.classList.toggle("hidden", !onAlerts);
  });
  document.querySelectorAll(".chart-row, .module-health-section")
    .forEach(el=>el.classList.toggle("hidden", !onAlerts));

  if (tabName==="launcher") startLauncherPolling(); else stopLauncherPolling();
  renderActiveTab();
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

  if (demo.active) {
    if (notice) notice.style.display="block";
    grid.innerHTML = Object.entries(ALL_MODS).map(([name,info])=>`
      <div class="launcher-card">
        <div class="launcher-card-header">
          <div class="launcher-dot running"></div>
          <span class="launcher-name">${name}</span>
          <span class="launcher-tag">${info.dev}</span>
        </div>
        <div class="launcher-meta">${info.type} · DEMO ACTIVE</div>
        <div class="launcher-actions">
          <button class="launch-btn launch-btn-stop" onclick="showToast('Demo mode: backend not connected','warning',3000)">■ Stop</button>
          <button class="launch-btn launch-btn-start" onclick="showToast('Demo mode: backend not connected','warning',3000)">▶ Start</button>
        </div>
      </div>`).join("");
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

async function startModule(name) {
  try {
    const r = await fetch(`${API_BASE}/api/modules/start`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({module:name})});
    const d = await r.json();
    logLauncher(`Started ${name}: ${d.status||"ok"}`);
    showToast(`▶ ${name} started`, "success", 3000);
  } catch { showToast(`Cannot reach backend — demo mode active`,"warning",3000); }
}
async function stopModule(name) {
  try {
    const r = await fetch(`${API_BASE}/api/modules/stop`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({module:name})});
    const d = await r.json();
    logLauncher(`Stopped ${name}: ${d.status||"ok"}`);
    showToast(`■ ${name} stopped`, "warning", 3000);
  } catch { showToast(`Cannot reach backend — demo mode active`,"warning",3000); }
}
async function startAll() {
  if (demo.active) { showToast("Backend not connected — demo mode","warning",3000); return; }
  for (const name of Object.keys(ALL_MODS)) await startModule(name);
}
async function stopAll() {
  if (demo.active) { showToast("Backend not connected — demo mode","warning",3000); return; }
  for (const name of Object.keys(ALL_MODS)) await stopModule(name);
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

// ── Filter listeners ──────────────────────────────────────────
if (ui.scenarioFilter) ui.scenarioFilter.addEventListener("change", renderAlerts);
if (ui.severityFilter) ui.severityFilter.addEventListener("change", renderAlerts);
if (ui.auditFilter)    ui.auditFilter.addEventListener("change", renderAudit);

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
    if (!demo.active) startDemo();
    else demoTick();
  }
}

// ── Init ──────────────────────────────────────────────────────
function init() {
  initCharts();
  staggerCards();

  // Ensure scenario banner and exec KPIs are visible on alerts tab
  const onAlerts = document.querySelector(".nav-btn.active")?.dataset.tab === "alerts";
  if (!onAlerts) {
    ["stat-cards","exec-kpis","scenario-banner"].forEach(id=>{ const e=$(id); if(e) e.classList.add("hidden"); });
    document.querySelectorAll(".chart-row,.module-health-section").forEach(e=>e.classList.add("hidden"));
  }

  syncData();
  setInterval(syncData, POLL_MS);
  setTimeout(()=>showToast("IntegriShield SOC · Press ⌘K to navigate · Click any alert for detail","info",6000), 800);
}

init();
