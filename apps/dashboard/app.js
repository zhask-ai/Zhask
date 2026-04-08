/* ═══════════════════════════════════════════════════════════
   IntegriShield SOC Dashboard — app.js
   13 modules · Dev 1–4 · All streams wired
   ═══════════════════════════════════════════════════════════ */

const API_BASE = "http://localhost:8787";
const POLL_MS  = 2500;

// ── DOM refs ─────────────────────────────────────────────────
const ui = {
  backendStatus:    document.getElementById("backend-status"),
  statusDot:        document.getElementById("status-dot"),
  eventsProcessed:  document.getElementById("events-processed"),
  streamUpdated:    document.getElementById("stream-last-updated"),
  totalAlerts:      document.getElementById("total-alerts"),
  criticalAlerts:   document.getElementById("critical-alerts"),
  avgLatency:       document.getElementById("avg-latency"),
  anomalyCount:     document.getElementById("anomaly-count"),
  dlpCount:         document.getElementById("dlp-count"),
  shadowCount:      document.getElementById("shadow-count"),
  sapCount:         document.getElementById("sap-count"),
  complianceCount:  document.getElementById("compliance-count"),
  incidentCount:    document.getElementById("incident-count"),
  sbomCount:        document.getElementById("sbom-count"),
  ztCount:          document.getElementById("zt-count"),
  credCount:        document.getElementById("cred-count"),
  cloudCount:       document.getElementById("cloud-count"),
  trendAlerts:      document.getElementById("trend-alerts"),
  alertsList:       document.getElementById("alerts-list"),
  alertsEmpty:      document.getElementById("alerts-empty"),
  gatewayList:      document.getElementById("gateway-list"),
  gatewayEmpty:     document.getElementById("gateway-empty"),
  anomalyList:      document.getElementById("anomaly-list"),
  anomalyEmpty:     document.getElementById("anomaly-empty"),
  dlpList:          document.getElementById("dlp-list"),
  dlpEmpty:         document.getElementById("dlp-empty"),
  shadowList:       document.getElementById("shadow-list"),
  shadowEmpty:      document.getElementById("shadow-empty"),
  sapList:          document.getElementById("sap-list"),
  sapEmpty:         document.getElementById("sap-empty"),
  complianceList:   document.getElementById("compliance-list"),
  complianceEmpty:  document.getElementById("compliance-empty"),
  incidentsList:    document.getElementById("incidents-list"),
  incidentsEmpty:   document.getElementById("incidents-empty"),
  sbomList:         document.getElementById("sbom-list"),
  sbomEmpty:        document.getElementById("sbom-empty"),
  ztList:           document.getElementById("zt-list"),
  ztEmpty:          document.getElementById("zt-empty"),
  credList:         document.getElementById("cred-list"),
  credEmpty:        document.getElementById("cred-empty"),
  cloudList:        document.getElementById("cloud-list"),
  cloudEmpty:       document.getElementById("cloud-empty"),
  rulesList:        document.getElementById("rules-list"),
  rulesEmpty:       document.getElementById("rules-empty"),
  auditBody:        document.getElementById("audit-body"),
  auditEmpty:       document.getElementById("audit-empty"),
  moduleGrid:       document.getElementById("module-grid"),
  scenarioFilter:   document.getElementById("scenario-filter"),
  severityFilter:   document.getElementById("severity-filter"),
  auditFilter:      document.getElementById("audit-module-filter"),
  gwTotal:          document.getElementById("gw-total"),
  gwOffHours:       document.getElementById("gw-off-hours"),
  gwBulk:           document.getElementById("gw-bulk"),
  gwVelocity:       document.getElementById("gw-velocity"),
  anomTotal:        document.getElementById("anom-total"),
  anomHigh:         document.getElementById("anom-high"),
  anomNewEp:        document.getElementById("anom-new-ep"),
  dlpBulk:          document.getElementById("dlp-bulk"),
  dlpStaging:       document.getElementById("dlp-staging"),
  dlpBlocklist:     document.getElementById("dlp-blocklist"),
  shadowTotal:      document.getElementById("shadow-total"),
  shadowUnique:     document.getElementById("shadow-unique"),
  sapTotal:         document.getElementById("sap-total"),
  sapAnomalous:     document.getElementById("sap-anomalous"),
  compViolations:   document.getElementById("comp-violations"),
  compWarnings:     document.getElementById("comp-warnings"),
  compPassed:       document.getElementById("comp-passed"),
  compFrameworks:   document.getElementById("comp-frameworks"),
  incOpen:          document.getElementById("inc-open"),
  incInvestigating: document.getElementById("inc-investigating"),
  incResolved:      document.getElementById("inc-resolved"),
  incPlaybooks:     document.getElementById("inc-playbooks"),
  sbomTotal:        document.getElementById("sbom-total"),
  sbomCve:          document.getElementById("sbom-cve"),
  sbomInsecure:     document.getElementById("sbom-insecure"),
  sbomClean:        document.getElementById("sbom-clean"),
  ztAllow:          document.getElementById("zt-allow"),
  ztDeny:           document.getElementById("zt-deny"),
  ztChallenge:      document.getElementById("zt-challenge"),
  ztAvgRisk:        document.getElementById("zt-avg-risk"),
  credIssued:       document.getElementById("cred-issued"),
  credRotated:      document.getElementById("cred-rotated"),
  credRevoked:      document.getElementById("cred-revoked"),
  cloudCritical:    document.getElementById("cloud-critical"),
  cloudHigh:        document.getElementById("cloud-high"),
  cloudAws:         document.getElementById("cloud-aws"),
  cloudGcp:         document.getElementById("cloud-gcp"),
  cloudAzure:       document.getElementById("cloud-azure"),
  ruleBulk:         document.getElementById("rule-bulk"),
  ruleOffHours:     document.getElementById("rule-off-hours"),
  ruleShadow:       document.getElementById("rule-shadow"),
  ruleVelocity:     document.getElementById("rule-velocity"),
  ruleOther:        document.getElementById("rule-other"),
};

// ── State ────────────────────────────────────────────────────
let alerts=[], auditRows=[], anomalies=[], sapEvents=[], compEvents=[],
    dlpEvents=[], incEvents=[], shadowEvents=[], sbomEvents=[],
    ztEvents=[], credEvents=[], cloudEvents=[], prevAlertCount=0;

// ── Charts ───────────────────────────────────────────────────
let alertChart=null, severityChart=null, rulesChart=null;
const alertTimeline=[];

function initCharts() {
  const grid="#1c2a4080", tick="#4d6480";
  alertChart = new Chart(document.getElementById("alert-chart").getContext("2d"), {
    type:"line", data:{labels:[],datasets:[{label:"Alerts",data:[],borderColor:"#3b82f6",
      backgroundColor:"rgba(59,130,246,0.08)",borderWidth:2,fill:true,tension:0.4,pointRadius:0}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},
      scales:{x:{display:true,grid:{color:grid},ticks:{color:tick,font:{size:10},maxTicksLimit:8}},
              y:{display:true,beginAtZero:true,grid:{color:grid},ticks:{color:tick,font:{size:10},precision:0}}},
      plugins:{legend:{display:false}}}});

  severityChart = new Chart(document.getElementById("severity-chart").getContext("2d"), {
    type:"doughnut", data:{labels:["Critical","High","Medium","Low"],
      datasets:[{data:[0,0,0,0],backgroundColor:["#ef4444","#f97316","#f59e0b","#22c55e"],
        borderColor:"#0f1829",borderWidth:3}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},cutout:"68%",
      plugins:{legend:{position:"bottom",labels:{color:"#8fa3bf",font:{size:10},padding:10,usePointStyle:true,boxWidth:8}}}}});

  rulesChart = new Chart(document.getElementById("rules-chart").getContext("2d"), {
    type:"doughnut", data:{labels:["Bulk Extract","Off-Hours","Shadow EP","Velocity","Other"],
      datasets:[{data:[0,0,0,0,0],backgroundColor:["#ef4444","#f59e0b","#f97316","#3b82f6","#a855f7"],
        borderColor:"#0f1829",borderWidth:3}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:400},cutout:"68%",
      plugins:{legend:{position:"bottom",labels:{color:"#8fa3bf",font:{size:10},padding:8,usePointStyle:true,boxWidth:8}}}}});
}

// ── Fetch ────────────────────────────────────────────────────
async function get(path) {
  const r = await fetch(`${API_BASE}${path}`);
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// ── Main sync ────────────────────────────────────────────────
async function syncData() {
  try {
    const [aR,auR,stR,anR,sR,cR,dR,iR,shR,sbR,zR,crR,clR,mR] = await Promise.all([
      get("/api/alerts?limit=80"),   get("/api/audit?limit=60"),
      get("/api/stats"),             get("/api/anomalies?limit=60"),
      get("/api/sap-activity?limit=60"), get("/api/compliance?limit=60"),
      get("/api/dlp?limit=60"),      get("/api/incidents?limit=60"),
      get("/api/shadow?limit=60"),   get("/api/sbom?limit=60"),
      get("/api/zero-trust?limit=60"),get("/api/credentials?limit=60"),
      get("/api/cloud-posture?limit=60"), get("/api/modules/health"),
    ]);

    alerts=aR.alerts||[]; auditRows=auR.rows||[]; anomalies=anR.anomalies||[];
    sapEvents=sR.events||[]; compEvents=cR.findings||[]; dlpEvents=dR.violations||[];
    incEvents=iR.incidents||[]; shadowEvents=shR.detections||[]; sbomEvents=sbR.scans||[];
    ztEvents=zR.evaluations||[]; credEvents=crR.events||[]; cloudEvents=clR.findings||[];

    ui.backendStatus.textContent  = "connected";
    ui.statusDot.className        = "status-dot online";
    ui.eventsProcessed.textContent= (mR.events_processed||0).toLocaleString();
    ui.streamUpdated.textContent  = `updated ${new Date().toLocaleTimeString()}`;

    const cur = stR.total_alerts||0;
    ui.totalAlerts.textContent    = cur;
    ui.criticalAlerts.textContent = stR.critical_alerts||0;
    ui.avgLatency.textContent     = `${((stR.avg_latency_ms||0)/1000).toFixed(1)}s`;
    ui.anomalyCount.textContent   = stR.anomalies_count||0;
    ui.dlpCount.textContent       = stR.dlp_violations||0;
    ui.shadowCount.textContent    = stR.shadow_detections||0;
    ui.sapCount.textContent       = stR.sap_events_count||0;
    ui.complianceCount.textContent= stR.compliance_findings||0;
    ui.incidentCount.textContent  = stR.incident_count||0;
    ui.sbomCount.textContent      = stR.sbom_scans||0;
    ui.ztCount.textContent        = stR.zero_trust_evals||0;
    ui.credCount.textContent      = stR.credential_events||0;
    ui.cloudCount.textContent     = stR.cloud_findings||0;

    if (prevAlertCount>0) {
      const d=cur-prevAlertCount;
      ui.trendAlerts.textContent=d>0?`▲ +${d}`:d<0?`▼ ${d}`:"—";
      ui.trendAlerts.style.color=d>0?"var(--critical)":d<0?"var(--ok)":"var(--text-dim)";
    }
    prevAlertCount=cur;

    alertTimeline.push({t:new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"}),count:alerts.length});
    if(alertTimeline.length>30) alertTimeline.shift();
    alertChart.data.labels=alertTimeline.map(p=>p.t);
    alertChart.data.datasets[0].data=alertTimeline.map(p=>p.count);
    alertChart.update("none");

    severityChart.data.datasets[0].data=[
      alerts.filter(a=>a.severity==="critical").length,
      alerts.filter(a=>a.severity==="high").length,
      alerts.filter(a=>a.severity==="medium").length,
      alerts.filter(a=>a.severity==="low").length,
    ];
    severityChart.update("none");

    const KEY_SCENARIOS=["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"];
    rulesChart.data.datasets[0].data=[
      alerts.filter(a=>a.scenario==="bulk_extraction").length,
      alerts.filter(a=>a.scenario==="off_hours_rfc").length,
      alerts.filter(a=>a.scenario==="shadow_endpoint").length,
      alerts.filter(a=>a.scenario==="velocity_anomaly").length,
      alerts.filter(a=>!KEY_SCENARIOS.includes(a.scenario)).length,
    ];
    rulesChart.update("none");

    updatePills(mR.modules||{});
    renderModuleGrid(mR.modules||{});
    renderActiveTab();

  } catch {
    ui.backendStatus.textContent="offline";
    ui.statusDot.className="status-dot offline";
    ["m01","m04","m05","m06","m07","m08","m09","m10","m11","m12","m13","m15"].forEach(id=>{
      const el=document.getElementById(`pill-${id}`);
      if(el) el.className="pill pill-offline";
    });
  }
}

// ── Pills ────────────────────────────────────────────────────
const PILL_MAP={
  "m01-api-gateway-shield":"m01","m04-zero-trust-fabric":"m04",
  "m05-sap-mcp-suite":"m05","m06-credential-vault":"m06",
  "m07-compliance-autopilot":"m07","m08-anomaly-detection":"m08",
  "m09-dlp":"m09","m10-incident-response":"m10",
  "m11-shadow-integration":"m11","m12-rules-engine":"m12",
  "m13-sbom-scanner":"m13","m15-multicloud-ispm":"m15",
};
function updatePills(modules) {
  for(const[mod,id] of Object.entries(PILL_MAP)){
    const el=document.getElementById(`pill-${id}`);
    if(el) el.className=modules[mod]?"pill pill-ok":"pill pill-offline";
  }
}

// ── Tab router ───────────────────────────────────────────────
function renderActiveTab(){
  const tab=document.querySelector(".tab.active");
  if(!tab) return;
  ({alerts:renderAlerts,audit:renderAudit,gateway:renderGateway,
    anomalies:renderAnomaly,dlp:renderDlp,shadow:renderShadow,
    sap:renderSap,compliance:renderCompliance,incidents:renderIncidents,
    sbom:renderSbom,rules:renderRules,"zero-trust":renderZeroTrust,
    credentials:renderCredentials,cloud:renderCloud}[tab.dataset.tab]||(_=>{}))();
}

// ── Render helpers ────────────────────────────────────────────
const ts  = v=>{if(!v)return"—";try{return new Date(v).toLocaleTimeString();}catch{return v;}};
const ms  = v=>v==null?"—":v<1000?`${v}ms`:`${(v/1000).toFixed(2)}s`;
const byt = v=>{if(!v)return"—";if(v<1048576)return`${(v/1024).toFixed(1)} KB`;return`${(v/1048576).toFixed(1)} MB`;};
const scl = s=>({bulk_extraction:"Bulk Extraction",off_hours_rfc:"Off-Hours RFC",
  shadow_endpoint:"Shadow Endpoint",velocity_anomaly:"Velocity Anomaly",
  credential_abuse:"Credential Abuse",privilege_escalation:"Privilege Escalation",
  data_staging:"Data Staging",geo_anomaly:"Geo Anomaly"})[s]||(s||"").replace(/_/g," ");

function item(cls,...rows){
  return`<li class="alert-item ${cls}"><div class="alert-item-row">${rows[0]}</div>${
    rows.slice(1).map(r=>`<div class="alert-item-meta">${r}</div>`).join("")}</li>`;
}
function setEmpty(list,empty,arr){empty.classList.toggle("hidden",arr.length>0);}

// ── Alerts ───────────────────────────────────────────────────
function renderAlerts(){
  let v=alerts;
  const sc=ui.scenarioFilter.value,sv=ui.severityFilter.value;
  if(sc!=="all") v=v.filter(a=>a.scenario===sc);
  if(sv!=="all") v=v.filter(a=>a.severity===sv);
  setEmpty(ui.alertsList,ui.alertsEmpty,v);
  ui.alertsList.innerHTML=v.map(a=>{
    const sev=(a.severity||"low").toLowerCase();
    return item(`sev-${sev}`,
      `<strong>${sev.toUpperCase()}</strong> <span class="panel-subtitle">${scl(a.scenario)}</span><span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>`,
      a.message||"—",`IP:${a.source_ip||"—"} · user:${a.user_id||"—"} · ${ms(a.latencyMs)}`);
  }).join("");
}

// ── Gateway M01 ──────────────────────────────────────────────
function renderGateway(){
  ui.gwTotal.textContent=alerts.length;
  ui.gwOffHours.textContent=alerts.filter(a=>a.scenario==="off_hours_rfc").length;
  ui.gwBulk.textContent=alerts.filter(a=>a.scenario==="bulk_extraction").length;
  ui.gwVelocity.textContent=alerts.filter(a=>a.scenario==="velocity_anomaly").length;
  setEmpty(ui.gatewayList,ui.gatewayEmpty,alerts);
  ui.gatewayList.innerHTML=alerts.map(a=>item("ev-gateway",
    `<strong>RFC CALL</strong> <span class="panel-subtitle">${scl(a.scenario)}</span><span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>`,
    a.message||a.endpoint||"—",`IP:${a.source_ip||"—"} · user:${a.user_id||"—"} · sev:${a.severity||"—"}`
  )).join("");
}

// ── Anomaly M08 ──────────────────────────────────────────────
function renderAnomaly(){
  const hi=anomalies.filter(a=>parseFloat(a.anomaly_score||a.score||0)>0.7);
  const ep=anomalies.filter(a=>(a.classification||a.type||"")==="new_endpoint");
  ui.anomTotal.textContent=anomalies.length; ui.anomHigh.textContent=hi.length; ui.anomNewEp.textContent=ep.length;
  setEmpty(ui.anomalyList,ui.anomalyEmpty,anomalies);
  ui.anomalyList.innerHTML=anomalies.map(a=>{
    const sc=parseFloat(a.anomaly_score||a.score||0);
    const cls=sc>0.7?"sev-critical":sc>0.4?"sev-medium":"sev-low";
    return item(`ev-anomaly ${cls}`,
      `<strong>ANOMALY</strong> <span class="panel-subtitle">score ${sc.toFixed(3)}</span><span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>`,
      `${a.classification||a.type||"unclassified"} · dev:${a.baseline_deviation||"—"}`,
      `IP:${a.source_ip||"—"} · endpoint:${a.endpoint||"—"}`);
  }).join("");
}

// ── DLP M09 ─────────────────────────────────────────────────
function renderDlp(){
  ui.dlpBulk.textContent=dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("bulk")).length;
  ui.dlpStaging.textContent=dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("staging")).length;
  ui.dlpBlocklist.textContent=dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("blocklist")).length;
  setEmpty(ui.dlpList,ui.dlpEmpty,dlpEvents);
  ui.dlpList.innerHTML=dlpEvents.map(e=>item(`ev-dlp sev-${(e.severity||"high").toLowerCase()}`,
    `<strong>${e.rule||"DLP VIOLATION"}</strong> <span class="panel-subtitle">${(e.severity||"").toUpperCase()}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    e.message||"—",`bytes:${byt(e.bytes_out)} · rows:${e.row_count||"—"} · user:${e.user_id||"—"}`
  )).join("");
}

// ── Shadow M11 ──────────────────────────────────────────────
function renderShadow(){
  const hosts=new Set(shadowEvents.map(e=>e.endpoint||"").filter(Boolean)).size;
  ui.shadowTotal.textContent=shadowEvents.length; ui.shadowUnique.textContent=hosts;
  setEmpty(ui.shadowList,ui.shadowEmpty,shadowEvents);
  ui.shadowList.innerHTML=shadowEvents.map(e=>item(`ev-shadow sev-${(e.severity||"high").toLowerCase()}`,
    `<strong>SHADOW ENDPOINT</strong> <span class="panel-subtitle">${(e.severity||"").toUpperCase()}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    e.endpoint||e.message||"unknown endpoint",`user:${e.user_id||"—"} · IP:${e.source_ip||"—"}`
  )).join("");
}

// ── SAP MCP M05 ─────────────────────────────────────────────
function renderSap(){
  ui.sapTotal.textContent=sapEvents.length;
  ui.sapAnomalous.textContent=sapEvents.filter(e=>e.anomalous||e.flagged).length;
  setEmpty(ui.sapList,ui.sapEmpty,sapEvents);
  ui.sapList.innerHTML=sapEvents.map(e=>item("ev-sap",
    `<strong>SAP MCP</strong> <span class="panel-subtitle">${e.tool_name||e.action||"tool invocation"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    `result:${e.result||e.status||"—"} · session:${e.session_id||"—"}`,
    `tenant:${e.tenant_id||"—"} · user:${e.user_id||"—"}`
  )).join("");
}

// ── Compliance M07 ──────────────────────────────────────────
function renderCompliance(){
  ui.compViolations.textContent=compEvents.filter(e=>(e.result||e.status||"")==="violation").length;
  ui.compWarnings.textContent=compEvents.filter(e=>(e.result||e.status||"")==="warning").length;
  ui.compPassed.textContent=compEvents.filter(e=>(e.result||e.status||"")==="pass").length;
  ui.compFrameworks.textContent=new Set(compEvents.map(e=>e.framework||"").filter(Boolean)).size;
  setEmpty(ui.complianceList,ui.complianceEmpty,compEvents);
  ui.complianceList.innerHTML=compEvents.map(e=>{
    const res=(e.result||e.status||"unknown").toLowerCase();
    const cls=res==="violation"?"sev-critical":res==="warning"?"sev-medium":"sev-low";
    return item(`ev-compliance ${cls}`,
      `<strong>${res.toUpperCase()}</strong> <span class="panel-subtitle">${e.control_id||"—"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `${e.framework||"—"} · ${e.description||e.message||"—"}`,
      `evidence:${e.evidence_ref||"—"} · actor:${e.actor||"—"}`);
  }).join("");
}

// ── Incidents M10 ───────────────────────────────────────────
function renderIncidents(){
  const open=incEvents.filter(e=>(e.status||e.state||"").toLowerCase()==="open");
  const inv=incEvents.filter(e=>["investigating","in_progress","active"].includes((e.status||e.state||"").toLowerCase()));
  const res=incEvents.filter(e=>["resolved","closed","contained"].includes((e.status||e.state||"").toLowerCase()));
  ui.incOpen.textContent=open.length; ui.incInvestigating.textContent=inv.length;
  ui.incResolved.textContent=res.length;
  ui.incPlaybooks.textContent=incEvents.filter(e=>e.playbook_run||e.playbook_id).length;
  setEmpty(ui.incidentsList,ui.incidentsEmpty,incEvents);
  ui.incidentsList.innerHTML=incEvents.map(e=>{
    const st=(e.status||e.state||"unknown").toLowerCase();
    const cls=st==="open"?"sev-critical":["investigating","in_progress","active"].includes(st)?"sev-medium":"sev-low";
    return item(`ev-incident ${cls}`,
      `<strong>INC-${e.incident_id||"?"}</strong> <span class="panel-subtitle">${e.title||e.action||"incident"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `status:${st} · severity:${e.severity||"—"}`,
      `playbook:${e.playbook_id||"none"} · source:${e.source_module||"—"}`);
  }).join("");
}

// ── SBOM M13 ────────────────────────────────────────────────
function renderSbom(){
  const cve=sbomEvents.reduce((n,e)=>n+parseInt(e.cve_count||e.vulnerabilities||0),0);
  const ins=sbomEvents.reduce((n,e)=>n+parseInt(e.insecure_rfc_count||0),0);
  const clean=sbomEvents.filter(e=>!parseInt(e.cve_count||0)&&!parseInt(e.insecure_rfc_count||0)).length;
  ui.sbomTotal.textContent=sbomEvents.length; ui.sbomCve.textContent=cve;
  ui.sbomInsecure.textContent=ins; ui.sbomClean.textContent=clean;
  setEmpty(ui.sbomList,ui.sbomEmpty,sbomEvents);
  ui.sbomList.innerHTML=sbomEvents.map(e=>{
    const hasCve=parseInt(e.cve_count||0)>0,hasIns=parseInt(e.insecure_rfc_count||0)>0;
    const cls=hasCve?"sev-critical":hasIns?"sev-medium":"sev-low";
    return item(`ev-sbom ${cls}`,
      `<strong>${e.scan_status||"SCAN"}</strong> <span class="panel-subtitle">${e.target||e.component||"scan"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `CVEs:${e.cve_count||0} · insecure RFC:${e.insecure_rfc_count||0} · components:${e.component_count||"—"}`,
      `format:${e.sbom_format||"CycloneDX"} · scan_id:${e.scan_id||"—"}`);
  }).join("");
}

// ── Rules M12 ───────────────────────────────────────────────
function renderRules(){
  ui.ruleBulk.textContent=alerts.filter(a=>a.scenario==="bulk_extraction").length;
  ui.ruleOffHours.textContent=alerts.filter(a=>a.scenario==="off_hours_rfc").length;
  ui.ruleShadow.textContent=alerts.filter(a=>a.scenario==="shadow_endpoint").length;
  ui.ruleVelocity.textContent=alerts.filter(a=>a.scenario==="velocity_anomaly").length;
  ui.ruleOther.textContent=alerts.filter(a=>!["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"].includes(a.scenario)).length;
  setEmpty(ui.rulesList,ui.rulesEmpty,alerts);
  ui.rulesList.innerHTML=alerts.map(a=>item(`ev-rules sev-${(a.severity||"medium").toLowerCase()}`,
    `<strong>${(a.scenario||"RULE").toUpperCase().replace(/_/g," ")}</strong> <span class="panel-subtitle">${(a.severity||"").toUpperCase()}</span><span class="panel-subtitle" style="margin-left:auto">${ts(a.ts)}</span>`,
    a.message||"—",`${ms(a.latencyMs)} · IP:${a.source_ip||"—"} · user:${a.user_id||"—"}`
  )).join("");
}

// ── Zero-Trust M04 ──────────────────────────────────────────
function renderZeroTrust(){
  const allow=ztEvents.filter(e=>(e.decision||"").toLowerCase()==="allow");
  const deny=ztEvents.filter(e=>(e.decision||"").toLowerCase()==="deny");
  const chal=ztEvents.filter(e=>!["allow","deny"].includes((e.decision||"").toLowerCase()));
  const risks=ztEvents.map(e=>parseFloat(e.risk_score||0)).filter(n=>!isNaN(n));
  ui.ztAllow.textContent=allow.length; ui.ztDeny.textContent=deny.length;
  ui.ztChallenge.textContent=chal.length;
  ui.ztAvgRisk.textContent=risks.length?(risks.reduce((a,b)=>a+b,0)/risks.length).toFixed(1):"—";
  setEmpty(ui.ztList,ui.ztEmpty,ztEvents);
  ui.ztList.innerHTML=ztEvents.map(e=>{
    const dec=(e.decision||"evaluated").toLowerCase();
    const cls=dec==="allow"?"ev-zt-allow":dec==="deny"?"ev-zt-deny":"ev-zt-challenge";
    return item(cls,
      `<strong>${dec.toUpperCase()}</strong> <span class="panel-subtitle">risk ${e.risk_score||0}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
      `user:${e.user_id||"—"} · IP:${e.source_ip||"—"}`,
      `failed:(${(e.failed_controls||[]).join(",")||"none"})`);
  }).join("");
}

// ── Credentials M06 ─────────────────────────────────────────
function renderCredentials(){
  ui.credIssued.textContent=credEvents.filter(e=>(e.action||"").includes("issu")).length;
  ui.credRotated.textContent=credEvents.filter(e=>(e.action||"").includes("rotat")).length;
  ui.credRevoked.textContent=credEvents.filter(e=>(e.action||"").includes("revok")).length;
  setEmpty(ui.credList,ui.credEmpty,credEvents);
  ui.credList.innerHTML=credEvents.map(e=>item("ev-credential",
    `<strong>${(e.action||"EVENT").toUpperCase()}</strong> <span class="panel-subtitle">${e.key||"—"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    `status:${e.status||"—"} · tenant:${e.tenant_id||"—"}`
  )).join("");
}

// ── Cloud M15 ───────────────────────────────────────────────
function renderCloud(){
  ui.cloudCritical.textContent=cloudEvents.filter(e=>(e.raw_severity||e.severity||"").toLowerCase()==="critical").length;
  ui.cloudHigh.textContent=cloudEvents.filter(e=>(e.raw_severity||e.severity||"").toLowerCase()==="high").length;
  ui.cloudAws.textContent=cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="aws").length;
  ui.cloudGcp.textContent=cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="gcp").length;
  ui.cloudAzure.textContent=cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="azure").length;
  setEmpty(ui.cloudList,ui.cloudEmpty,cloudEvents);
  ui.cloudList.innerHTML=cloudEvents.map(e=>item(`ev-cloud sev-${(e.raw_severity||e.severity||"medium").toLowerCase()}`,
    `<strong>${(e.provider||"CLOUD").toUpperCase()}</strong> <span class="panel-subtitle">${e.control_id||"—"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    `resource:${e.resource_id||"—"} · risk:${e.risk_score||"—"} · severity:${e.raw_severity||e.severity||"—"}`
  )).join("");
}

// ── Audit ────────────────────────────────────────────────────
function renderAudit(){
  const mod=ui.auditFilter.value;
  const v=mod==="all"?auditRows:auditRows.filter(r=>r.module===mod);
  setEmpty(ui.auditBody,ui.auditEmpty,v);
  ui.auditBody.innerHTML=v.map(r=>`<tr>
    <td>${ts(r.ts)}</td><td>${r.actor}</td><td>${r.action}</td>
    <td><span class="module-chip chip-default">${r.module}</span></td>
    <td style="color:var(--ok)">${r.status}</td></tr>`).join("");
}

// ── Module grid ───────────────────────────────────────────────
const ALL_MODS={
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
function renderModuleGrid(modules){
  ui.moduleGrid.innerHTML=Object.entries(ALL_MODS).map(([name,info])=>{
    const alive=modules[name];
    const ev=alive?alive.events||0:0;
    return`<div class="module-card">
      <span class="${alive?"dot ok":"dot offline"}"></span>
      <span class="name">${name}</span>
      <span class="stream">${info.dev} · ${info.type} · ${alive?`${ev} events`:"offline"}</span>
    </div>`;
  }).join("");
}

// ── Tab switching ─────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab=>{
  tab.addEventListener("click",()=>{
    document.querySelectorAll(".tab").forEach(t=>t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c=>c.classList.add("hidden"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`)?.classList.remove("hidden");
    renderActiveTab();
  });
});

ui.scenarioFilter.addEventListener("change",renderAlerts);
ui.severityFilter.addEventListener("change",renderAlerts);
ui.auditFilter.addEventListener("change",renderAudit);

// ── Boot ──────────────────────────────────────────────────────
initCharts();
syncData();
setInterval(syncData,POLL_MS);
