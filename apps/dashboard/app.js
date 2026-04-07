/* ═══════════════════════════════════════════════════════════
   IntegriShield SOC Dashboard — Application Logic
   All 18 modules · Dev 1–4 · POC Sprint
   ═══════════════════════════════════════════════════════════ */

const API_BASE = "http://localhost:8787";
const POLL_MS  = 2500;

// ─── DOM refs ────────────────────────────────────────────────────────────────
const ui = {
  // topbar
  backendStatus:   document.getElementById("backend-status"),
  statusDot:       document.getElementById("status-dot"),
  eventsProcessed: document.getElementById("events-processed"),
  // stat cards
  totalAlerts:    document.getElementById("total-alerts"),
  criticalAlerts: document.getElementById("critical-alerts"),
  avgLatency:     document.getElementById("avg-latency"),
  anomalyCount:   document.getElementById("anomaly-count"),
  dlpCount:       document.getElementById("dlp-count"),
  shadowCount:    document.getElementById("shadow-count"),
  sapCount:       document.getElementById("sap-count"),
  ztCount:        document.getElementById("zt-count"),
  credCount:      document.getElementById("cred-count"),
  cloudCount:     document.getElementById("cloud-count"),
  trendAlerts:    document.getElementById("trend-alerts"),
  // panels / lists
  alertsList:     document.getElementById("alerts-list"),
  alertsEmpty:    document.getElementById("alerts-empty"),
  gatewayList:    document.getElementById("gateway-list"),
  gatewayEmpty:   document.getElementById("gateway-empty"),
  anomalyList:    document.getElementById("anomaly-list"),
  anomalyEmpty:   document.getElementById("anomaly-empty"),
  dlpList:        document.getElementById("dlp-list"),
  dlpEmpty:       document.getElementById("dlp-empty"),
  shadowList:     document.getElementById("shadow-list"),
  shadowEmpty:    document.getElementById("shadow-empty"),
  sapList:        document.getElementById("sap-list"),
  sapEmpty:       document.getElementById("sap-empty"),
  ztList:         document.getElementById("zt-list"),
  ztEmpty:        document.getElementById("zt-empty"),
  credList:       document.getElementById("cred-list"),
  credEmpty:      document.getElementById("cred-empty"),
  cloudList:      document.getElementById("cloud-list"),
  cloudEmpty:     document.getElementById("cloud-empty"),
  rulesList:      document.getElementById("rules-list"),
  rulesEmpty:     document.getElementById("rules-empty"),
  auditBody:      document.getElementById("audit-body"),
  auditEmpty:     document.getElementById("audit-empty"),
  moduleGrid:     document.getElementById("module-grid"),
  // filters
  scenarioFilter: document.getElementById("scenario-filter"),
  severityFilter: document.getElementById("severity-filter"),
  auditFilter:    document.getElementById("audit-module-filter"),
  // mini stats — gateway
  gwTotal:        document.getElementById("gw-total"),
  gwOffHours:     document.getElementById("gw-off-hours"),
  gwBulk:         document.getElementById("gw-bulk"),
  gwVelocity:     document.getElementById("gw-velocity"),
  // mini stats — anomaly
  anomTotal:      document.getElementById("anom-total"),
  anomHigh:       document.getElementById("anom-high"),
  anomNewEp:      document.getElementById("anom-new-ep"),
  // mini stats — dlp
  dlpBulk:        document.getElementById("dlp-bulk"),
  dlpStaging:     document.getElementById("dlp-staging"),
  // mini stats — shadow
  shadowTotal:    document.getElementById("shadow-total"),
  shadowUnique:   document.getElementById("shadow-unique"),
  // mini stats — SAP
  sapToolsCalled: document.getElementById("sap-tools-called"),
  sapAnomalous:   document.getElementById("sap-anomalous"),
  // mini stats — ZT
  ztAllow:        document.getElementById("zt-allow"),
  ztDeny:         document.getElementById("zt-deny"),
  ztChallenge:    document.getElementById("zt-challenge"),
  ztAvgRisk:      document.getElementById("zt-avg-risk"),
  // mini stats — credentials
  credIssued:     document.getElementById("cred-issued"),
  credRotated:    document.getElementById("cred-rotated"),
  credRevoked:    document.getElementById("cred-revoked"),
  // mini stats — cloud
  cloudCritical:  document.getElementById("cloud-critical"),
  cloudHigh:      document.getElementById("cloud-high"),
  cloudAws:       document.getElementById("cloud-aws"),
  cloudGcp:       document.getElementById("cloud-gcp"),
  cloudAzure:     document.getElementById("cloud-azure"),
  // rules mini stats
  ruleBulk:       document.getElementById("rule-bulk"),
  ruleOffHours:   document.getElementById("rule-off-hours"),
  ruleShadow:     document.getElementById("rule-shadow"),
  ruleVelocity:   document.getElementById("rule-velocity"),
  ruleOther:      document.getElementById("rule-other"),
  // SAP live indicator
  sapLiveIndicator: document.getElementById("sap-live-indicator"),
  // stream updated
  streamUpdated:  document.getElementById("stream-last-updated"),
};

// ─── State ───────────────────────────────────────────────────────────────────
let alerts     = [];
let auditRows  = [];
let anomalies  = [];
let sapEvents  = [];
let ztEvents   = [];
let credEvents = [];
let cloudEvents= [];
let prevAlertCount = 0;

// ─── Charts ──────────────────────────────────────────────────────────────────
let alertChart    = null;
let severityChart = null;
let rulesChart    = null;
const alertTimeline = [];

function initCharts() {
  const gridColor = "rgba(28,42,64,0.8)";
  const tickColor = "#4d6480";

  // Timeline chart
  alertChart = new Chart(
    document.getElementById("alert-chart").getContext("2d"), {
      type: "line",
      data: {
        labels: [],
        datasets: [{
          label: "Alerts",
          data: [],
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59,130,246,0.08)",
          borderWidth: 2, fill: true, tension: 0.4, pointRadius: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: { duration: 300 },
        scales: {
          x: { display: true, grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 }, maxTicksLimit: 8 } },
          y: { display: true, beginAtZero: true, grid: { color: gridColor }, ticks: { color: tickColor, font: { size: 10 }, precision: 0 } },
        },
        plugins: { legend: { display: false } },
      },
    }
  );

  // Severity donut
  severityChart = new Chart(
    document.getElementById("severity-chart").getContext("2d"), {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ["#ef4444", "#f97316", "#f59e0b", "#22c55e"],
          borderColor: "#0f1829", borderWidth: 3,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: { duration: 400 }, cutout: "68%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#8fa3bf", font: { size: 10 }, padding: 10, usePointStyle: true, boxWidth: 8 },
          },
        },
      },
    }
  );

  // Rules breakdown donut
  rulesChart = new Chart(
    document.getElementById("rules-chart").getContext("2d"), {
      type: "doughnut",
      data: {
        labels: ["Bulk Extraction", "Off-Hours RFC", "Shadow Endpoint", "Velocity", "Other"],
        datasets: [{
          data: [0, 0, 0, 0, 0],
          backgroundColor: ["#ef4444", "#f59e0b", "#f97316", "#3b82f6", "#a855f7"],
          borderColor: "#0f1829", borderWidth: 3,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        animation: { duration: 400 }, cutout: "68%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#8fa3bf", font: { size: 10 }, padding: 8, usePointStyle: true, boxWidth: 8 },
          },
        },
      },
    }
  );
}

// ─── Fetch helper ─────────────────────────────────────────────────────────────
async function fetchJson(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ─── Main sync ────────────────────────────────────────────────────────────────
async function syncData() {
  try {
    const [alertsR, auditR, statsR, anomR, sapR, ztR, credR, cloudR, modulesR] = await Promise.all([
      fetchJson("/api/alerts?limit=80"),
      fetchJson("/api/audit?limit=60"),
      fetchJson("/api/stats"),
      fetchJson("/api/anomalies?limit=60"),
      fetchJson("/api/sap-activity?limit=60"),
      fetchJson("/api/zero-trust?limit=60"),
      fetchJson("/api/credentials?limit=60"),
      fetchJson("/api/cloud-posture?limit=60"),
      fetchJson("/api/modules/health"),
    ]);

    alerts      = alertsR.alerts      || [];
    auditRows   = auditR.rows         || [];
    anomalies   = anomR.anomalies     || [];
    sapEvents   = sapR.events         || [];
    ztEvents    = ztR.evaluations     || [];
    credEvents  = credR.events        || [];
    cloudEvents = cloudR.findings     || [];

    // ── Topbar status ──
    ui.backendStatus.textContent  = "connected";
    ui.statusDot.className        = "status-dot online";
    ui.eventsProcessed.textContent= (modulesR.events_processed || 0).toLocaleString();
    ui.streamUpdated.textContent  = `updated ${new Date().toLocaleTimeString()}`;

    // ── Stat cards ──
    const dlpAlerts    = alerts.filter(a => ["bulk_extraction","data_staging"].includes(a.scenario));
    const shadowAlerts = alerts.filter(a => a.scenario === "shadow_endpoint");

    ui.totalAlerts.textContent   = statsR.total_alerts       || 0;
    ui.criticalAlerts.textContent= statsR.critical_alerts    || 0;
    ui.avgLatency.textContent    = `${((statsR.avg_latency_ms || 0) / 1000).toFixed(1)}s`;
    ui.anomalyCount.textContent  = statsR.anomalies_count    || 0;
    ui.dlpCount.textContent      = dlpAlerts.length;
    ui.shadowCount.textContent   = shadowAlerts.length;
    ui.sapCount.textContent      = statsR.sap_events_count   || 0;
    ui.ztCount.textContent       = statsR.zero_trust_evals   || 0;
    ui.credCount.textContent     = statsR.credential_events  || 0;
    ui.cloudCount.textContent    = statsR.cloud_findings     || 0;

    // Alert trend indicator
    const curCount = statsR.total_alerts || 0;
    if (prevAlertCount > 0) {
      const diff = curCount - prevAlertCount;
      ui.trendAlerts.textContent = diff > 0 ? `▲ +${diff}` : diff < 0 ? `▼ ${diff}` : "—";
      ui.trendAlerts.style.color = diff > 0 ? "var(--critical)" : diff < 0 ? "var(--ok)" : "var(--text-dim)";
    }
    prevAlertCount = curCount;

    // ── Timeline chart ──
    alertTimeline.push({ t: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }), count: alerts.length });
    if (alertTimeline.length > 30) alertTimeline.shift();
    alertChart.data.labels               = alertTimeline.map(p => p.t);
    alertChart.data.datasets[0].data     = alertTimeline.map(p => p.count);
    alertChart.update("none");

    // ── Severity donut ──
    severityChart.data.datasets[0].data = [
      alerts.filter(a => a.severity === "critical").length,
      alerts.filter(a => a.severity === "high").length,
      alerts.filter(a => a.severity === "medium").length,
      alerts.filter(a => a.severity === "low").length,
    ];
    severityChart.update("none");

    // ── Rules donut ──
    rulesChart.data.datasets[0].data = [
      dlpAlerts.filter(a => a.scenario === "bulk_extraction").length,
      alerts.filter(a => a.scenario === "off_hours_rfc").length,
      shadowAlerts.length,
      alerts.filter(a => a.scenario === "velocity_anomaly").length,
      alerts.filter(a => !["bulk_extraction","data_staging","shadow_endpoint","off_hours_rfc","velocity_anomaly"].includes(a.scenario)).length,
    ];
    rulesChart.update("none");

    // ── Module health pills ──
    updateHealthPills(modulesR.modules || {});
    renderModuleHealth(modulesR.modules || {}, modulesR.events_processed || 0);

    // ── SAP live indicator ──
    if (sapEvents.length > 0) {
      ui.sapLiveIndicator.textContent = "● live";
      ui.sapLiveIndicator.className   = "live-badge";
    } else {
      ui.sapLiveIndicator.textContent = "● waiting";
      ui.sapLiveIndicator.className   = "live-badge waiting";
    }

    // ── Render active tab ──
    renderActiveTab();

  } catch {
    ui.backendStatus.textContent = "offline";
    ui.statusDot.className       = "status-dot offline";
    // Flip all pills offline
    ["m01","m04","m05","m06","m08","m12","m15"].forEach(id => {
      const el = document.getElementById(`pill-${id}`);
      if (el) { el.className = "pill pill-offline"; }
    });
  }
}

// ─── Health pill update ───────────────────────────────────────────────────────
function updateHealthPills(modules) {
  const map = {
    "m01-api-gateway-shield": "m01",
    "m04-zero-trust-fabric":  "m04",
    "m05-sap-mcp-suite":      "m05",
    "m06-credential-vault":   "m06",
    "m08-anomaly-detection":  "m08",
    "m12-rules-engine":       "m12",
    "m15-multicloud-ispm":    "m15",
  };
  for (const [mod, id] of Object.entries(map)) {
    const el  = document.getElementById(`pill-${id}`);
    if (!el) continue;
    const info   = modules[mod];
    const isDev3 = id === "m05";
    el.className = info
      ? (isDev3 ? "pill pill-pending" : "pill pill-ok")
      : "pill pill-offline";
  }
}

// ─── Active tab router ────────────────────────────────────────────────────────
function renderActiveTab() {
  const active = document.querySelector(".tab.active");
  if (!active) return;
  switch (active.dataset.tab) {
    case "alerts":     renderAlerts();      break;
    case "gateway":    renderGateway();     break;
    case "anomalies":  renderAnomaly();     break;
    case "dlp":        renderDlp();         break;
    case "shadow":     renderShadow();      break;
    case "dev3":       renderDev3();        break;
    case "rules":      renderRules();       break;
    case "zero-trust": renderZeroTrust();   break;
    case "credentials":renderCredentials(); break;
    case "cloud":      renderCloud();       break;
    case "audit":      renderAudit();       break;
  }
}

// ─── Alerts ───────────────────────────────────────────────────────────────────
function renderAlerts() {
  const scenario = ui.scenarioFilter.value;
  const severity = ui.severityFilter.value;
  let visible = alerts;
  if (scenario !== "all") visible = visible.filter(a => a.scenario === scenario);
  if (severity !== "all") visible = visible.filter(a => a.severity === severity);

  ui.alertsEmpty.classList.toggle("hidden", visible.length > 0);
  ui.alertsList.innerHTML = visible.map(a => {
    const sev = (a.severity || "low").toLowerCase();
    return `<li class="alert-item sev-${sev}">
      <div class="alert-item-row">
        <strong>${sev.toUpperCase()}</strong>
        <span class="panel-subtitle">${scenarioLabel(a.scenario)}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message || a.scenario || "alert"}</div>
      <div class="alert-item-meta">IP: ${a.source_ip || "—"} · user: ${a.user_id || "—"} · latency ${fmtMs(a.latencyMs)}</div>
    </li>`;
  }).join("");
}

// ─── Gateway (M01) ────────────────────────────────────────────────────────────
function renderGateway() {
  // Gateway calls = all alerts (all came from M01 events via M12 rules engine)
  const visible = alerts;
  const offHours  = alerts.filter(a => a.scenario === "off_hours_rfc");
  const bulk      = alerts.filter(a => a.scenario === "bulk_extraction");
  const velocity  = alerts.filter(a => a.scenario === "velocity_anomaly");

  ui.gwTotal.textContent    = visible.length;
  ui.gwOffHours.textContent = offHours.length;
  ui.gwBulk.textContent     = bulk.length;
  ui.gwVelocity.textContent = velocity.length;

  ui.gatewayEmpty.classList.toggle("hidden", visible.length > 0);
  ui.gatewayList.innerHTML = visible.map(a => `
    <li class="alert-item ev-gateway">
      <div class="alert-item-row">
        <strong>RFC CALL</strong>
        <span class="panel-subtitle">${scenarioLabel(a.scenario)}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message || a.endpoint || "—"}</div>
      <div class="alert-item-meta">IP: ${a.source_ip || "—"} · user: ${a.user_id || "—"} · sev: ${a.severity || "—"}</div>
    </li>`).join("");
}

// ─── Anomaly (M08) ────────────────────────────────────────────────────────────
function renderAnomaly() {
  const highScore = anomalies.filter(a => parseFloat(a.anomaly_score || a.score || 0) > 0.7);
  const newEp     = anomalies.filter(a => a.classification === "new_endpoint" || a.type === "new_endpoint");

  ui.anomTotal.textContent  = anomalies.length;
  ui.anomHigh.textContent   = highScore.length;
  ui.anomNewEp.textContent  = newEp.length;

  ui.anomalyEmpty.classList.toggle("hidden", anomalies.length > 0);
  ui.anomalyList.innerHTML = anomalies.map(a => {
    const score = parseFloat(a.anomaly_score || a.score || 0);
    const cls   = score > 0.7 ? "sev-critical" : score > 0.4 ? "sev-medium" : "sev-low";
    return `<li class="alert-item ev-anomaly ${cls}">
      <div class="alert-item-row">
        <strong>ANOMALY</strong>
        <span class="panel-subtitle">score ${score.toFixed(3)}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.classification || a.type || "unclassified"} · dev: ${a.baseline_deviation || "—"}</div>
      <div class="alert-item-meta">IP: ${a.source_ip || "—"} · endpoint: ${a.endpoint || "—"}</div>
    </li>`;
  }).join("");
}

// ─── DLP (M09 via M12 rules) ──────────────────────────────────────────────────
function renderDlp() {
  const dlp     = alerts.filter(a => ["bulk_extraction","data_staging"].includes(a.scenario));
  const bulk    = dlp.filter(a => a.scenario === "bulk_extraction");
  const staging = dlp.filter(a => a.scenario === "data_staging");

  ui.dlpBulk.textContent    = bulk.length;
  ui.dlpStaging.textContent = staging.length;

  ui.dlpEmpty.classList.toggle("hidden", dlp.length > 0);
  ui.dlpList.innerHTML = dlp.map(a => `
    <li class="alert-item ev-dlp sev-${(a.severity||"medium").toLowerCase()}">
      <div class="alert-item-row">
        <strong>${a.scenario === "bulk_extraction" ? "BULK EXTRACT" : "DATA STAGING"}</strong>
        <span class="panel-subtitle">${(a.severity||"").toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message || "—"}</div>
      <div class="alert-item-meta">bytes_out: ${a.bytes_out ? fmtBytes(a.bytes_out) : "—"} · user: ${a.user_id || "—"} · IP: ${a.source_ip || "—"}</div>
    </li>`).join("");
}

// ─── Shadow (M11 via M12 rules) ───────────────────────────────────────────────
function renderShadow() {
  const sh       = alerts.filter(a => a.scenario === "shadow_endpoint");
  const uniqHosts= new Set(sh.map(a => a.endpoint || "").filter(Boolean)).size;

  ui.shadowTotal.textContent  = sh.length;
  ui.shadowUnique.textContent = uniqHosts;

  ui.shadowEmpty.classList.toggle("hidden", sh.length > 0);
  ui.shadowList.innerHTML = sh.map(a => `
    <li class="alert-item ev-shadow sev-${(a.severity||"high").toLowerCase()}">
      <div class="alert-item-row">
        <strong>SHADOW ENDPOINT</strong>
        <span class="panel-subtitle">${(a.severity||"").toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.endpoint || a.message || "unknown endpoint"}</div>
      <div class="alert-item-meta">user: ${a.user_id || "—"} · IP: ${a.source_ip || "—"}</div>
    </li>`).join("");
}

// ─── Dev 3 (SAP + coming-soon) ────────────────────────────────────────────────
function renderDev3() {
  // M05 live feed
  ui.sapToolsCalled.textContent = sapEvents.length;
  ui.sapAnomalous.textContent   = sapEvents.filter(e => e.anomalous || e.flagged).length;

  ui.sapEmpty.classList.toggle("hidden", sapEvents.length > 0);
  ui.sapList.innerHTML = sapEvents.map(e => `
    <li class="alert-item ev-sap">
      <div class="alert-item-row">
        <strong>SAP MCP</strong>
        <span class="panel-subtitle">${e.tool_name || e.action || "tool invocation"}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(e.ts)}</span>
      </div>
      <div class="alert-item-meta">result: ${e.result || e.status || "—"} · tenant: ${e.tenant_id || "—"}</div>
    </li>`).join("");
}

// ─── Rules Engine (M12) ───────────────────────────────────────────────────────
function renderRules() {
  const bulk     = alerts.filter(a => a.scenario === "bulk_extraction").length;
  const offHours = alerts.filter(a => a.scenario === "off_hours_rfc").length;
  const shadow   = alerts.filter(a => a.scenario === "shadow_endpoint").length;
  const velocity = alerts.filter(a => a.scenario === "velocity_anomaly").length;
  const other    = alerts.filter(a => !["bulk_extraction","off_hours_rfc","shadow_endpoint","velocity_anomaly"].includes(a.scenario)).length;

  ui.ruleBulk.textContent     = bulk;
  ui.ruleOffHours.textContent = offHours;
  ui.ruleShadow.textContent   = shadow;
  ui.ruleVelocity.textContent = velocity;
  ui.ruleOther.textContent    = other;

  ui.rulesEmpty.classList.toggle("hidden", alerts.length > 0);
  ui.rulesList.innerHTML = alerts.map(a => `
    <li class="alert-item ev-rules sev-${(a.severity||"medium").toLowerCase()}">
      <div class="alert-item-row">
        <strong>${(a.scenario || "RULE").toUpperCase().replace(/_/g," ")}</strong>
        <span class="panel-subtitle">${(a.severity||"").toUpperCase()}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(a.ts)}</span>
      </div>
      <div class="alert-item-meta">${a.message || "—"}</div>
      <div class="alert-item-meta">latency ${fmtMs(a.latencyMs)} · IP: ${a.source_ip || "—"} · user: ${a.user_id || "—"}</div>
    </li>`).join("");
}

// ─── Zero-Trust (M04) ─────────────────────────────────────────────────────────
function renderZeroTrust() {
  const allow     = ztEvents.filter(e => (e.decision||"").toLowerCase() === "allow");
  const deny      = ztEvents.filter(e => (e.decision||"").toLowerCase() === "deny");
  const challenge = ztEvents.filter(e => !["allow","deny"].includes((e.decision||"").toLowerCase()));
  const risks     = ztEvents.map(e => parseFloat(e.risk_score || 0)).filter(n => !isNaN(n));
  const avgRisk   = risks.length ? (risks.reduce((a,b) => a+b, 0) / risks.length).toFixed(1) : "—";

  ui.ztAllow.textContent    = allow.length;
  ui.ztDeny.textContent     = deny.length;
  ui.ztChallenge.textContent= challenge.length;
  ui.ztAvgRisk.textContent  = avgRisk;

  ui.ztEmpty.classList.toggle("hidden", ztEvents.length > 0);
  ui.ztList.innerHTML = ztEvents.map(e => {
    const dec = (e.decision || "evaluated").toLowerCase();
    const cls = dec === "allow" ? "ev-zt-allow" : dec === "deny" ? "ev-zt-deny" : "ev-zt-challenge";
    return `<li class="alert-item ${cls}">
      <div class="alert-item-row">
        <strong>${dec.toUpperCase()}</strong>
        <span class="panel-subtitle">risk ${e.risk_score || 0}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(e.ts)}</span>
      </div>
      <div class="alert-item-meta">user: ${e.user_id || "—"} · IP: ${e.source_ip || "—"}</div>
      <div class="alert-item-meta">failed controls: ${(e.failed_controls||[]).join(", ") || "none"}</div>
    </li>`;
  }).join("");
}

// ─── Credentials (M06) ───────────────────────────────────────────────────────
function renderCredentials() {
  const issued  = credEvents.filter(e => (e.action||"").includes("issu"));
  const rotated = credEvents.filter(e => (e.action||"").includes("rotat"));
  const revoked = credEvents.filter(e => (e.action||"").includes("revok"));

  ui.credIssued.textContent  = issued.length;
  ui.credRotated.textContent = rotated.length;
  ui.credRevoked.textContent = revoked.length;

  ui.credEmpty.classList.toggle("hidden", credEvents.length > 0);
  ui.credList.innerHTML = credEvents.map(e => `
    <li class="alert-item ev-credential">
      <div class="alert-item-row">
        <strong>${(e.action || "EVENT").toUpperCase()}</strong>
        <span class="panel-subtitle">${e.key || "—"}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(e.ts)}</span>
      </div>
      <div class="alert-item-meta">status: ${e.status || "—"} · tenant: ${e.tenant_id || "—"}</div>
    </li>`).join("");
}

// ─── Cloud Posture (M15) ──────────────────────────────────────────────────────
function renderCloud() {
  const critical = cloudEvents.filter(e => (e.raw_severity||e.severity||"").toLowerCase() === "critical");
  const high     = cloudEvents.filter(e => (e.raw_severity||e.severity||"").toLowerCase() === "high");
  const aws      = cloudEvents.filter(e => (e.provider||"").toLowerCase() === "aws");
  const gcp      = cloudEvents.filter(e => (e.provider||"").toLowerCase() === "gcp");
  const azure    = cloudEvents.filter(e => (e.provider||"").toLowerCase() === "azure");

  ui.cloudCritical.textContent = critical.length;
  ui.cloudHigh.textContent     = high.length;
  ui.cloudAws.textContent      = aws.length;
  ui.cloudGcp.textContent      = gcp.length;
  ui.cloudAzure.textContent    = azure.length;

  ui.cloudEmpty.classList.toggle("hidden", cloudEvents.length > 0);
  ui.cloudList.innerHTML = cloudEvents.map(e => `
    <li class="alert-item ev-cloud sev-${(e.raw_severity||e.severity||"medium").toLowerCase()}">
      <div class="alert-item-row">
        <strong>${(e.provider||"CLOUD").toUpperCase()}</strong>
        <span class="panel-subtitle">${e.control_id || "—"}</span>
        <span class="panel-subtitle" style="margin-left:auto">${fmtTime(e.ts)}</span>
      </div>
      <div class="alert-item-meta">resource: ${e.resource_id || "—"} · risk: ${e.risk_score || "—"} · severity: ${e.raw_severity || e.severity || "—"}</div>
    </li>`).join("");
}

// ─── Audit Log ────────────────────────────────────────────────────────────────
function renderAudit() {
  const modFilter = ui.auditFilter.value;
  const visible   = modFilter === "all" ? auditRows : auditRows.filter(r => r.module === modFilter);
  ui.auditEmpty.classList.toggle("hidden", visible.length > 0);
  ui.auditBody.innerHTML = visible.map(r => `
    <tr>
      <td>${fmtTime(r.ts)}</td>
      <td>${r.actor}</td>
      <td>${r.action}</td>
      <td><span class="module-chip chip-default">${r.module}</span></td>
      <td style="color:var(--ok)">${r.status}</td>
    </tr>`).join("");
}

// ─── Module health grid ───────────────────────────────────────────────────────
function renderModuleHealth(modules, eventsProcessed) {
  const DEV3_MODS = ["m05-sap-mcp-suite","m07-compliance-autopilot","m10-incident-response","m13-sbom-scanner"];
  const ALL_MODULES = {
    "m01-api-gateway-shield":   { stream: "api_call_events",      dev: "Dev 1" },
    "m03-traffic-analyzer":     { stream: "analyzed_events",      dev: "Dev 2" },
    "m08-anomaly-detection":    { stream: "anomaly_scores",        dev: "Dev 2" },
    "m09-dlp":                  { stream: "dlp_alerts",            dev: "Dev 2" },
    "m11-shadow-integration":   { stream: "shadow_alerts",         dev: "Dev 2" },
    "m05-sap-mcp-suite":        { stream: "sap_mcp_events",        dev: "Dev 3" },
    "m07-compliance-autopilot": { stream: "compliance_events",     dev: "Dev 3" },
    "m10-incident-response":    { stream: "incident_events",       dev: "Dev 3" },
    "m13-sbom-scanner":         { stream: "sbom_events",           dev: "Dev 3" },
    "m04-zero-trust-fabric":    { stream: "zero_trust_events",     dev: "Dev 4" },
    "m06-credential-vault":     { stream: "credential_events",     dev: "Dev 4" },
    "m12-rules-engine":         { stream: "alert_events",          dev: "Dev 4" },
    "m15-multicloud-ispm":      { stream: "cloud_posture_events",  dev: "Dev 4" },
  };

  ui.moduleGrid.innerHTML = Object.entries(ALL_MODULES).map(([name, info]) => {
    const backendKnows = modules[name];
    const isDev3 = DEV3_MODS.includes(name);
    const dotCls = isDev3 ? "dot dev3" : backendKnows ? "dot ok" : "dot offline";
    const statusLabel = isDev3 ? "building" : backendKnows ? "consuming" : "offline";
    return `<div class="module-card">
      <span class="${dotCls}"></span>
      <span class="name">${name}</span>
      <span class="stream">${info.dev} · ${statusLabel}</span>
    </div>`;
  }).join("");
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function fmtTime(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleTimeString(); } catch { return ts; }
}

function fmtMs(ms) {
  if (ms == null) return "—";
  return ms < 1000 ? `${ms}ms` : `${(ms/1000).toFixed(2)}s`;
}

function fmtBytes(bytes) {
  if (!bytes) return "—";
  if (bytes < 1024)       return `${bytes} B`;
  if (bytes < 1048576)    return `${(bytes/1024).toFixed(1)} KB`;
  return `${(bytes/1048576).toFixed(1)} MB`;
}

function scenarioLabel(s) {
  const map = {
    bulk_extraction:     "Bulk Extraction",
    off_hours_rfc:       "Off-Hours RFC",
    shadow_endpoint:     "Shadow Endpoint",
    velocity_anomaly:    "Velocity Anomaly",
    credential_abuse:    "Credential Abuse",
    privilege_escalation:"Privilege Escalation",
    data_staging:        "Data Staging",
    geo_anomaly:         "Geo Anomaly",
  };
  return map[s] || (s || "").replace(/_/g, " ");
}

// ─── Tab switching ────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
    tab.classList.add("active");
    const panel = document.getElementById(`tab-${tab.dataset.tab}`);
    if (panel) panel.classList.remove("hidden");
    renderActiveTab();
  });
});

// ─── Filter listeners ─────────────────────────────────────────────────────────
ui.scenarioFilter.addEventListener("change", renderAlerts);
ui.severityFilter.addEventListener("change", renderAlerts);
ui.auditFilter.addEventListener("change", renderAudit);

// ─── Boot ─────────────────────────────────────────────────────────────────────
initCharts();
syncData();
setInterval(syncData, POLL_MS);
