/* ═══════════════════════════════════════════════════════════
   IntegriShield SOC Dashboard — app.js
   13 modules · Dev 1–4 · All streams wired
   Premium UI with sidebar navigation
   ═══════════════════════════════════════════════════════════ */

// Auto-detect backend URL: use env config injected at build time,
// fall back to same-origin /api (nginx proxy in production),
// or localhost for local dev.
const API_BASE = (
  (typeof window.__INTEGRISHIELD_API !== "undefined" && window.__INTEGRISHIELD_API) ||
  (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1"
    ? "http://localhost:8787"
    : window.location.origin + "/api-proxy")
);
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
  gwTotalCount:     document.getElementById("gw-total-count"),
  rulesCount:       document.getElementById("rules-count"),
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
  sidebar:          document.getElementById("sidebar"),
  sidebarToggle:    document.getElementById("sidebar-toggle"),
  sidebarOverlay:   document.getElementById("sidebar-overlay"),
};

// ── State ────────────────────────────────────────────────────
let alerts=[], auditRows=[], anomalies=[], sapEvents=[], compEvents=[],
    dlpEvents=[], incEvents=[], shadowEvents=[], sbomEvents=[],
    ztEvents=[], credEvents=[], cloudEvents=[], prevAlertCount=0;

// ── Animated counter ─────────────────────────────────────────
const counterCache = new Map();
function animateValue(el, newVal) {
  if (!el) return;
  const key = el.id || el;
  const from = counterCache.get(key) || 0;
  const to = parseInt(newVal) || 0;
  if (from === to) { el.textContent = to; return; }
  counterCache.set(key, to);

  const duration = 400;
  const start = performance.now();
  const step = (now) => {
    const progress = Math.min((now - start) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // easeOutCubic
    el.textContent = Math.round(from + (to - from) * eased);
    if (progress < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// ── Charts ───────────────────────────────────────────────────
let alertChart=null, severityChart=null, rulesChart=null;
const alertTimeline=[];

function initCharts() {
  const gridColor = "rgba(40, 58, 90, 0.2)";
  const tickColor = "#4a6080";

  // Line chart with gradient fill
  const alertCtx = document.getElementById("alert-chart").getContext("2d");
  const alertGradient = alertCtx.createLinearGradient(0, 0, 0, 190);
  alertGradient.addColorStop(0, "rgba(91, 141, 239, 0.15)");
  alertGradient.addColorStop(1, "rgba(91, 141, 239, 0.0)");

  alertChart = new Chart(alertCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Alerts",
        data: [],
        borderColor: "#5b8def",
        backgroundColor: alertGradient,
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
        pointHoverRadius: 5,
        pointHoverBackgroundColor: "#5b8def",
        pointHoverBorderColor: "#fff",
        pointHoverBorderWidth: 2,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 500, easing: "easeOutQuart" },
      interaction: { mode: "index", intersect: false },
      scales: {
        x: {
          display: true,
          grid: { color: gridColor, drawBorder: false },
          ticks: { color: tickColor, font: { size: 10, family: "Inter" }, maxTicksLimit: 8 },
          border: { display: false },
        },
        y: {
          display: true,
          beginAtZero: true,
          grid: { color: gridColor, drawBorder: false },
          ticks: { color: tickColor, font: { size: 10, family: "Inter" }, precision: 0, maxTicksLimit: 5 },
          border: { display: false },
        },
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: "rgba(14, 22, 38, 0.9)",
          titleColor: "#eaf0f7",
          bodyColor: "#b0c4de",
          borderColor: "rgba(91, 141, 239, 0.3)",
          borderWidth: 1,
          cornerRadius: 8,
          padding: 10,
          titleFont: { weight: "600" },
          displayColors: false,
        },
      },
    },
  });

  // Severity donut
  severityChart = new Chart(document.getElementById("severity-chart").getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ["#ff4757", "#ff8b3d", "#ffa502", "#2ed573"],
        borderColor: "rgba(14, 22, 38, 0.8)",
        borderWidth: 3,
        hoverBorderColor: "rgba(14, 22, 38, 1)",
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 600, easing: "easeOutQuart" },
      cutout: "70%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#7a93b4",
            font: { size: 10, family: "Inter" },
            padding: 12,
            usePointStyle: true,
            pointStyleWidth: 8,
          },
        },
        tooltip: {
          backgroundColor: "rgba(14, 22, 38, 0.9)",
          titleColor: "#eaf0f7",
          bodyColor: "#b0c4de",
          borderColor: "rgba(91, 141, 239, 0.3)",
          borderWidth: 1,
          cornerRadius: 8,
          padding: 10,
        },
      },
    },
  });

  // Rules donut
  rulesChart = new Chart(document.getElementById("rules-chart").getContext("2d"), {
    type: "doughnut",
    data: {
      labels: ["Bulk Extract", "Off-Hours", "Shadow EP", "Velocity", "Other"],
      datasets: [{
        data: [0, 0, 0, 0, 0],
        backgroundColor: ["#ff4757", "#ffa502", "#ff8b3d", "#5b8def", "#a17fe0"],
        borderColor: "rgba(14, 22, 38, 0.8)",
        borderWidth: 3,
        hoverBorderColor: "rgba(14, 22, 38, 1)",
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 600, easing: "easeOutQuart" },
      cutout: "70%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: "#7a93b4",
            font: { size: 10, family: "Inter" },
            padding: 10,
            usePointStyle: true,
            pointStyleWidth: 8,
          },
        },
        tooltip: {
          backgroundColor: "rgba(14, 22, 38, 0.9)",
          titleColor: "#eaf0f7",
          bodyColor: "#b0c4de",
          borderColor: "rgba(91, 141, 239, 0.3)",
          borderWidth: 1,
          cornerRadius: 8,
          padding: 10,
        },
      },
    },
  });
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
    animateValue(ui.totalAlerts, cur);
    animateValue(ui.criticalAlerts, stR.critical_alerts||0);
    ui.avgLatency.textContent     = `${((stR.avg_latency_ms||0)/1000).toFixed(1)}s`;
    animateValue(ui.anomalyCount, stR.anomalies_count||0);
    animateValue(ui.dlpCount, stR.dlp_violations||0);
    animateValue(ui.shadowCount, stR.shadow_detections||0);
    animateValue(ui.sapCount, stR.sap_events_count||0);
    animateValue(ui.complianceCount, stR.compliance_findings||0);
    animateValue(ui.incidentCount, stR.incident_count||0);
    animateValue(ui.sbomCount, stR.sbom_scans||0);
    animateValue(ui.ztCount, stR.zero_trust_evals||0);
    animateValue(ui.credCount, stR.credential_events||0);
    animateValue(ui.cloudCount, stR.cloud_findings||0);
    if (ui.gwTotalCount) animateValue(ui.gwTotalCount, stR.api_calls_count||stR.total_alerts||0);
    if (ui.rulesCount)   animateValue(ui.rulesCount,   stR.rule_triggers||stR.alert_events||0);

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
  const btn=document.querySelector(".nav-btn.active");
  if(!btn) return;
  ({alerts:renderAlerts,audit:renderAudit,gateway:renderGateway,
    anomalies:renderAnomaly,dlp:renderDlp,shadow:renderShadow,
    sap:renderSap,compliance:renderCompliance,incidents:renderIncidents,
    sbom:renderSbom,rules:renderRules,"zero-trust":renderZeroTrust,
    credentials:renderCredentials,cloud:renderCloud,
    launcher:()=>renderLauncher(launcherProcesses)}[btn.dataset.tab]||(_=>{}))();
}

// ── Render helpers ────────────────────────────────────────────
const ts  = v=>{if(!v)return"—";try{return new Date(v).toLocaleTimeString();}catch{return v;}};
const ms  = v=>v==null?"—":v<1000?`${v}ms`:`${(v/1000).toFixed(2)}s`;
const byt = v=>{if(!v)return"—";if(v<1048576)return`${(v/1024).toFixed(1)} KB`;return`${(v/1048576).toFixed(1)} MB`;};
const scl = s=>({"bulk_extraction":"Bulk Extraction","off_hours_rfc":"Off-Hours RFC",
  "shadow_endpoint":"Shadow Endpoint","velocity_anomaly":"Velocity Anomaly",
  "credential_abuse":"Credential Abuse","privilege_escalation":"Privilege Escalation",
  "data_staging":"Data Staging","geo_anomaly":"Geo Anomaly"})[s]||(s||"").replace(/_/g," ");

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
  animateValue(ui.gwTotal, alerts.length);
  animateValue(ui.gwOffHours, alerts.filter(a=>a.scenario==="off_hours_rfc").length);
  animateValue(ui.gwBulk, alerts.filter(a=>a.scenario==="bulk_extraction").length);
  animateValue(ui.gwVelocity, alerts.filter(a=>a.scenario==="velocity_anomaly").length);
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
  animateValue(ui.anomTotal, anomalies.length);
  animateValue(ui.anomHigh, hi.length);
  animateValue(ui.anomNewEp, ep.length);
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
  animateValue(ui.dlpBulk, dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("bulk")).length);
  animateValue(ui.dlpStaging, dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("staging")).length);
  animateValue(ui.dlpBlocklist, dlpEvents.filter(e=>(e.rule||e.scenario||"").includes("blocklist")).length);
  setEmpty(ui.dlpList,ui.dlpEmpty,dlpEvents);
  ui.dlpList.innerHTML=dlpEvents.map(e=>item(`ev-dlp sev-${(e.severity||"high").toLowerCase()}`,
    `<strong>${e.rule||"DLP VIOLATION"}</strong> <span class="panel-subtitle">${(e.severity||"").toUpperCase()}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    e.message||"—",`bytes:${byt(e.bytes_out)} · rows:${e.row_count||"—"} · user:${e.user_id||"—"}`
  )).join("");
}

// ── Shadow M11 ──────────────────────────────────────────────
function renderShadow(){
  const hosts=new Set(shadowEvents.map(e=>e.endpoint||"").filter(Boolean)).size;
  animateValue(ui.shadowTotal, shadowEvents.length);
  animateValue(ui.shadowUnique, hosts);
  setEmpty(ui.shadowList,ui.shadowEmpty,shadowEvents);
  ui.shadowList.innerHTML=shadowEvents.map(e=>item(`ev-shadow sev-${(e.severity||"high").toLowerCase()}`,
    `<strong>SHADOW ENDPOINT</strong> <span class="panel-subtitle">${(e.severity||"").toUpperCase()}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    e.endpoint||e.message||"unknown endpoint",`user:${e.user_id||"—"} · IP:${e.source_ip||"—"}`
  )).join("");
}

// ── SAP MCP M05 ─────────────────────────────────────────────
function renderSap(){
  animateValue(ui.sapTotal, sapEvents.length);
  animateValue(ui.sapAnomalous, sapEvents.filter(e=>e.anomalous||e.flagged).length);
  setEmpty(ui.sapList,ui.sapEmpty,sapEvents);
  ui.sapList.innerHTML=sapEvents.map(e=>item("ev-sap",
    `<strong>SAP MCP</strong> <span class="panel-subtitle">${e.tool_name||e.action||"tool invocation"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    `result:${e.result||e.status||"—"} · session:${e.session_id||"—"}`,
    `tenant:${e.tenant_id||"—"} · user:${e.user_id||"—"}`
  )).join("");
}

// ── Compliance M07 ──────────────────────────────────────────
function renderCompliance(){
  animateValue(ui.compViolations, compEvents.filter(e=>(e.result||e.status||"")==="violation").length);
  animateValue(ui.compWarnings, compEvents.filter(e=>(e.result||e.status||"")==="warning").length);
  animateValue(ui.compPassed, compEvents.filter(e=>(e.result||e.status||"")==="pass").length);
  animateValue(ui.compFrameworks, new Set(compEvents.map(e=>e.framework||"").filter(Boolean)).size);
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
  animateValue(ui.incOpen, open.length);
  animateValue(ui.incInvestigating, inv.length);
  animateValue(ui.incResolved, res.length);
  animateValue(ui.incPlaybooks, incEvents.filter(e=>e.playbook_run||e.playbook_id).length);
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
  animateValue(ui.sbomTotal, sbomEvents.length);
  animateValue(ui.sbomCve, cve);
  animateValue(ui.sbomInsecure, ins);
  animateValue(ui.sbomClean, clean);
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
  animateValue(ui.ruleBulk, alerts.filter(a=>a.scenario==="bulk_extraction").length);
  animateValue(ui.ruleOffHours, alerts.filter(a=>a.scenario==="off_hours_rfc").length);
  animateValue(ui.ruleShadow, alerts.filter(a=>a.scenario==="shadow_endpoint").length);
  animateValue(ui.ruleVelocity, alerts.filter(a=>a.scenario==="velocity_anomaly").length);
  animateValue(ui.ruleOther, alerts.filter(a=>!["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"].includes(a.scenario)).length);
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
  animateValue(ui.ztAllow, allow.length);
  animateValue(ui.ztDeny, deny.length);
  animateValue(ui.ztChallenge, chal.length);
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
  animateValue(ui.credIssued, credEvents.filter(e=>(e.action||"").includes("issu")).length);
  animateValue(ui.credRotated, credEvents.filter(e=>(e.action||"").includes("rotat")).length);
  animateValue(ui.credRevoked, credEvents.filter(e=>(e.action||"").includes("revok")).length);
  setEmpty(ui.credList,ui.credEmpty,credEvents);
  ui.credList.innerHTML=credEvents.map(e=>item("ev-credential",
    `<strong>${(e.action||"EVENT").toUpperCase()}</strong> <span class="panel-subtitle">${e.key||"—"}</span><span class="panel-subtitle" style="margin-left:auto">${ts(e.ts)}</span>`,
    `status:${e.status||"—"} · tenant:${e.tenant_id||"—"}`
  )).join("");
}

// ── Cloud M15 ───────────────────────────────────────────────
function renderCloud(){
  animateValue(ui.cloudCritical, cloudEvents.filter(e=>(e.raw_severity||e.severity||"").toLowerCase()==="critical").length);
  animateValue(ui.cloudHigh, cloudEvents.filter(e=>(e.raw_severity||e.severity||"").toLowerCase()==="high").length);
  animateValue(ui.cloudAws, cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="aws").length);
  animateValue(ui.cloudGcp, cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="gcp").length);
  animateValue(ui.cloudAzure, cloudEvents.filter(e=>(e.provider||"").toLowerCase()==="azure").length);
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

// ── Navigate to tab ──────────────────────────────────────────
function navigateToTab(tabName) {
  const btn = document.querySelector(`.nav-btn[data-tab="${tabName}"]`);
  if (!btn) return;

  document.querySelectorAll(".nav-btn").forEach(b => b.classList.remove("active"));
  btn.classList.add("active");

  document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
  const target = document.getElementById(`tab-${tabName}`);
  if (target) target.classList.remove("hidden");

  // Scroll main content to top
  document.querySelector(".main-content")?.scrollTo({ top: 0, behavior: "smooth" });

  if (tabName === "launcher") {
    startLauncherPolling();
  } else {
    stopLauncherPolling();
  }

  renderActiveTab();
  closeSidebar();

  // Close command palette if open
  closeCommandPalette();
}

// ── Sidebar navigation ───────────────────────────────────────
document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => navigateToTab(btn.dataset.tab));
});

// ── Mobile sidebar toggle ────────────────────────────────────
function openSidebar() {
  ui.sidebar.classList.add("open");
  ui.sidebarOverlay.classList.add("active", "visible");
}
function closeSidebar() {
  ui.sidebar.classList.remove("open");
  ui.sidebarOverlay.classList.remove("visible");
  setTimeout(() => ui.sidebarOverlay.classList.remove("active"), 400);
}

if (ui.sidebarToggle) {
  ui.sidebarToggle.addEventListener("click", () => {
    if (ui.sidebar.classList.contains("open")) closeSidebar();
    else openSidebar();
  });
}
if (ui.sidebarOverlay) {
  ui.sidebarOverlay.addEventListener("click", closeSidebar);
}

// ── Filter listeners ─────────────────────────────────────────
ui.scenarioFilter.addEventListener("change", renderAlerts);
ui.severityFilter.addEventListener("change", renderAlerts);
ui.auditFilter.addEventListener("change", renderAudit);

// ── Live clock ───────────────────────────────────────────────
const clockEl = document.getElementById("live-clock");
function updateClock() {
  if (!clockEl) return;
  const now = new Date();
  clockEl.textContent = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
updateClock();
setInterval(updateClock, 1000);

// ── Command Palette (Ctrl+K / ⌘K) ──────────────────────────
const palette = document.getElementById("command-palette");
const paletteInput = document.getElementById("palette-input");
const paletteResults = document.getElementById("palette-results");

const COMMAND_ITEMS = [
  { label: "Alerts Feed",    tab: "alerts",      icon: "🔔", keywords: "alerts feed overview" },
  { label: "Audit Log",      tab: "audit",       icon: "📋", keywords: "audit log trail" },
  { label: "M01 Gateway",    tab: "gateway",     icon: "🛡️", keywords: "m01 gateway api rfc" },
  { label: "M08 Anomaly",    tab: "anomalies",   icon: "🧠", keywords: "m08 anomaly ml detection" },
  { label: "M09 DLP",        tab: "dlp",         icon: "🔒", keywords: "m09 dlp data loss prevention" },
  { label: "M11 Shadow",     tab: "shadow",      icon: "👁️", keywords: "m11 shadow integration" },
  { label: "M05 SAP MCP",    tab: "sap",         icon: "⚙️", keywords: "m05 sap mcp tool" },
  { label: "M07 Compliance", tab: "compliance",  icon: "✅", keywords: "m07 compliance sox gdpr" },
  { label: "M10 Incidents",  tab: "incidents",   icon: "🚨", keywords: "m10 incident response playbook" },
  { label: "M13 SBOM",       tab: "sbom",        icon: "📦", keywords: "m13 sbom scanner cve" },
  { label: "M12 Rules",      tab: "rules",       icon: "📏", keywords: "m12 rules engine" },
  { label: "M04 Zero-Trust", tab: "zero-trust",  icon: "🔐", keywords: "m04 zero trust fabric" },
  { label: "M06 Credentials",tab: "credentials", icon: "🔑", keywords: "m06 credential vault" },
  { label: "M15 Cloud",      tab: "cloud",       icon: "☁️", keywords: "m15 cloud ispm aws gcp azure" },
  { label: "⚡ Launcher",    tab: "launcher",    icon: "⚡", keywords: "launcher start stop module process run" },
];

let paletteIndex = 0;
let filteredItems = [...COMMAND_ITEMS];

function openCommandPalette() {
  if (!palette) return;
  palette.classList.remove("hidden");
  paletteInput.value = "";
  filteredItems = [...COMMAND_ITEMS];
  paletteIndex = 0;
  renderPaletteResults();
  requestAnimationFrame(() => paletteInput.focus());
}

function closeCommandPalette() {
  if (!palette) return;
  palette.classList.add("hidden");
}

function renderPaletteResults() {
  if (!paletteResults) return;
  paletteResults.innerHTML = filteredItems.map((item, i) =>
    `<div class="palette-item ${i === paletteIndex ? 'active' : ''}" data-tab="${item.tab}">
      <span class="palette-icon">${item.icon}</span>
      <span class="palette-label">${item.label}</span>
      <span class="palette-shortcut">${i < 9 ? i + 1 : ''}</span>
    </div>`
  ).join("");

  // Click handlers
  paletteResults.querySelectorAll(".palette-item").forEach(el => {
    el.addEventListener("click", () => {
      navigateToTab(el.dataset.tab);
    });
  });
}

if (paletteInput) {
  paletteInput.addEventListener("input", () => {
    const q = paletteInput.value.toLowerCase().trim();
    filteredItems = q
      ? COMMAND_ITEMS.filter(it => it.label.toLowerCase().includes(q) || it.keywords.includes(q))
      : [...COMMAND_ITEMS];
    paletteIndex = 0;
    renderPaletteResults();
  });

  paletteInput.addEventListener("keydown", (e) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      paletteIndex = (paletteIndex + 1) % filteredItems.length;
      renderPaletteResults();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      paletteIndex = (paletteIndex - 1 + filteredItems.length) % filteredItems.length;
      renderPaletteResults();
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (filteredItems[paletteIndex]) {
        navigateToTab(filteredItems[paletteIndex].tab);
      }
    } else if (e.key === "Escape") {
      closeCommandPalette();
    }
  });
}

// Palette overlay click
if (palette) {
  palette.addEventListener("click", (e) => {
    if (e.target === palette) closeCommandPalette();
  });
}

// ── Keyboard shortcuts ──────────────────────────────────────
document.addEventListener("keydown", (e) => {
  // Ctrl/Cmd + K → command palette
  if ((e.metaKey || e.ctrlKey) && e.key === "k") {
    e.preventDefault();
    if (palette?.classList.contains("hidden")) openCommandPalette();
    else closeCommandPalette();
    return;
  }

  // Escape → close palette
  if (e.key === "Escape" && palette && !palette.classList.contains("hidden")) {
    closeCommandPalette();
    return;
  }

  // Don't trigger shortcuts when typing in inputs
  if (e.target.tagName === "INPUT" || e.target.tagName === "SELECT" || e.target.tagName === "TEXTAREA") return;

  // Number keys 1-9 for quick nav (when palette is closed)
  if (palette?.classList.contains("hidden") && e.key >= "1" && e.key <= "9") {
    const idx = parseInt(e.key) - 1;
    const tabs = ["alerts","audit","gateway","anomalies","dlp","shadow","sap","compliance","incidents"];
    if (tabs[idx]) navigateToTab(tabs[idx]);
  }
});

// ── Toast notification system ────────────────────────────────
const toastContainer = document.getElementById("toast-container");
function showToast(message, type = "info", duration = 4000) {
  if (!toastContainer) return;
  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `
    <span class="toast-icon">${type === "critical" ? "🔴" : type === "warning" ? "🟡" : type === "success" ? "🟢" : "🔵"}</span>
    <span class="toast-message">${message}</span>
    <button class="toast-close" onclick="this.parentElement.remove()">×</button>
  `;
  toastContainer.prepend(toast);
  requestAnimationFrame(() => toast.classList.add("toast-visible"));
  setTimeout(() => {
    toast.classList.remove("toast-visible");
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// Show a welcome toast on load
setTimeout(() => showToast("IntegriShield SOC dashboard loaded · Press ⌘K to navigate", "info", 5000), 800);

// ── Card stagger animation on load ──────────────────────────
function staggerCards() {
  const cards = document.querySelectorAll(".card");
  cards.forEach((card, i) => {
    card.style.opacity = "0";
    card.style.transform = "translateY(12px)";
    card.style.transition = `opacity 400ms ${i * 50}ms cubic-bezier(0.4, 0, 0.2, 1), transform 400ms ${i * 50}ms cubic-bezier(0.4, 0, 0.2, 1)`;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        card.style.opacity = "1";
        card.style.transform = "translateY(0)";
      });
    });
  });
}

// ── Chart section stagger  ──────────────────────────────────
function staggerCharts() {
  const panels = document.querySelectorAll(".chart-panel");
  panels.forEach((panel, i) => {
    panel.style.opacity = "0";
    panel.style.transform = "translateY(10px) scale(0.98)";
    panel.style.transition = `opacity 500ms ${600 + i * 120}ms cubic-bezier(0.4, 0, 0.2, 1), transform 500ms ${600 + i * 120}ms cubic-bezier(0.4, 0, 0.2, 1)`;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        panel.style.opacity = "1";
        panel.style.transform = "translateY(0) scale(1)";
      });
    });
  });
}

// ── Module Launcher ──────────────────────────────────────────
let launcherProcesses = [];
let launcherPolling = null;

function logLauncher(msg) {
  const log = document.getElementById("launcher-log");
  if (!log) return;
  const time = new Date().toLocaleTimeString();
  log.textContent = `[${time}] ${msg}\n` + (log.textContent === "No logs yet." ? "" : log.textContent);
}

function clearLauncherLog() {
  const log = document.getElementById("launcher-log");
  if (log) log.textContent = "No logs yet.";
}

function renderLauncher(processes) {
  const grid = document.getElementById("launcher-grid");
  const notice = document.getElementById("launcher-notice");
  if (!grid) return;

  // Show/hide offline notice
  if (notice) {
    const isOnline = ui.backendStatus?.textContent === "online";
    notice.style.display = isOnline ? "none" : "block";
  }

  if (!processes || processes.length === 0) {
    grid.innerHTML = `<div style="grid-column:1/-1;text-align:center;color:var(--text-dim);padding:2rem;">
      No modules available. Backend may be offline or no launch configs found.</div>`;
    return;
  }

  grid.innerHTML = processes.map(p => {
    const running = p.status === "running";
    const statusLabel = running ? "Running" : (p.status === "starting" ? "Starting…" : "Stopped");
    const dotClass = running ? "launcher-dot dot-running" : (p.status === "starting" ? "launcher-dot dot-starting" : "launcher-dot dot-stopped");
    const pid = p.pid ? `PID ${p.pid}` : "";
    const uptime = p.uptime_s ? `${Math.round(p.uptime_s)}s` : "";

    return `<div class="launcher-card" id="lcard-${p.name.replace(/[^a-z0-9]/gi,'-')}">
      <div class="launcher-card-header">
        <span class="${dotClass}"></span>
        <span class="launcher-mod-name">${p.label || p.name}</span>
        <span class="launcher-status-text">${statusLabel}</span>
      </div>
      <div class="launcher-card-meta">${[pid, uptime].filter(Boolean).join(" · ") || "Not running"}</div>
      <div class="launcher-card-actions">
        <button class="launch-btn launch-btn-start" ${running ? "disabled" : ""}
          onclick="moduleAction('start','${p.name}')">▶ Start</button>
        <button class="launch-btn launch-btn-stop" ${!running ? "disabled" : ""}
          onclick="moduleAction('stop','${p.name}')">■ Stop</button>
        <button class="launch-btn launch-btn-logs"
          onclick="showModuleLogs('${p.name}')">📋 Logs</button>
      </div>
    </div>`;
  }).join("");
}

async function moduleAction(action, name) {
  logLauncher(`${action === "start" ? "Starting" : "Stopping"} ${name}…`);
  try {
    const res = await fetch(`${API_BASE}/api/modules/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const data = await res.json();
    logLauncher(`${name}: ${data.message || data.status || "done"}`);
    await fetchLauncherStatus();
  } catch (e) {
    logLauncher(`Error: ${e.message}`);
  }
}

async function startAll() {
  logLauncher("Starting all modules…");
  try {
    const res = await fetch(`${API_BASE}/api/modules/start-all`, { method: "POST" });
    const data = await res.json();
    logLauncher(`Start all: ${data.started || 0} started, ${data.failed || 0} failed`);
    await fetchLauncherStatus();
  } catch (e) {
    logLauncher(`Error: ${e.message}`);
  }
}

async function stopAll() {
  logLauncher("Stopping all modules…");
  try {
    const res = await fetch(`${API_BASE}/api/modules/stop-all`, { method: "POST" });
    const data = await res.json();
    logLauncher(`Stop all: ${data.stopped || 0} stopped`);
    await fetchLauncherStatus();
  } catch (e) {
    logLauncher(`Error: ${e.message}`);
  }
}

async function showModuleLogs(name) {
  try {
    const res = await fetch(`${API_BASE}/api/modules/processes`);
    const data = await res.json();
    const proc = (data.processes || []).find(p => p.name === name);
    const log = document.getElementById("launcher-log");
    if (!log) return;
    if (proc && proc.log_lines && proc.log_lines.length) {
      log.textContent = `=== ${name} logs ===\n` + proc.log_lines.join("\n");
    } else {
      log.textContent = `=== ${name} ===\nNo log output captured yet.`;
    }
  } catch (e) {
    logLauncher(`Could not fetch logs: ${e.message}`);
  }
}

async function fetchLauncherStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/modules/processes`);
    if (!res.ok) return;
    const data = await res.json();
    launcherProcesses = data.processes || [];
    renderLauncher(launcherProcesses);
  } catch {
    // backend offline — leave grid as-is
  }
}

function startLauncherPolling() {
  if (launcherPolling) return;
  fetchLauncherStatus();
  launcherPolling = setInterval(fetchLauncherStatus, POLL_MS);
}

function stopLauncherPolling() {
  if (launcherPolling) { clearInterval(launcherPolling); launcherPolling = null; }
}

// ── Boot ──────────────────────────────────────────────────────
staggerCards();
staggerCharts();
initCharts();
syncData();
setInterval(syncData, POLL_MS);
