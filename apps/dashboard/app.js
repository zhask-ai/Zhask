/* ═══════════════════════════════════════════════════════════
   IntegriShield SOC Dashboard — Application Logic
   ═══════════════════════════════════════════════════════════ */

const API_BASE = "http://localhost:8787";

// ── DOM refs ──
const ui = {
  totalAlerts:    document.getElementById("total-alerts"),
  criticalAlerts: document.getElementById("critical-alerts"),
  avgLatency:     document.getElementById("avg-latency"),
  anomalyCount:   document.getElementById("anomaly-count"),
  sapCount:       document.getElementById("sap-count"),
  ztCount:        document.getElementById("zt-count"),
  credCount:      document.getElementById("cred-count"),
  cloudCount:     document.getElementById("cloud-count"),
  trendAlerts:    document.getElementById("trend-alerts"),
  alertsList:     document.getElementById("alerts-list"),
  auditBody:      document.getElementById("audit-body"),
  filter:         document.getElementById("scenario-filter"),
  backendStatus:  document.getElementById("backend-status"),
  statusDot:      document.getElementById("status-dot"),
  eventsProcessed:document.getElementById("events-processed"),
  anomalyList:    document.getElementById("anomaly-list"),
  anomalyEmpty:   document.getElementById("anomaly-empty"),
  sapList:        document.getElementById("sap-list"),
  sapEmpty:       document.getElementById("sap-empty"),
  ztList:         document.getElementById("zt-list"),
  ztEmpty:        document.getElementById("zt-empty"),
  credList:       document.getElementById("cred-list"),
  credEmpty:      document.getElementById("cred-empty"),
  cloudList:      document.getElementById("cloud-list"),
  cloudEmpty:     document.getElementById("cloud-empty"),
  moduleGrid:     document.getElementById("module-grid"),
};

// ── State ──
let alerts = [];
let auditRows = [];
let anomalies = [];
let sapEvents = [];
let ztEvents = [];
let credEvents = [];
let cloudEvents = [];
let prevAlertCount = 0;

// ── Charts ──
let alertChart = null;
let severityChart = null;
const alertTimeline = [];  // { t: Date, count: int }

function initCharts() {
  const timelineCtx = document.getElementById("alert-chart").getContext("2d");
  alertChart = new Chart(timelineCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Alerts / interval",
        data: [],
        borderColor: "#3b82f6",
        backgroundColor: "rgba(59, 130, 246, 0.1)",
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 300 },
      scales: {
        x: { display: true, grid: { color: "rgba(30,41,59,0.5)" }, ticks: { color: "#64748b", font: { size: 10 } } },
        y: { display: true, beginAtZero: true, grid: { color: "rgba(30,41,59,0.5)" }, ticks: { color: "#64748b", font: { size: 10 } } },
      },
      plugins: { legend: { display: false } },
    },
  });

  const sevCtx = document.getElementById("severity-chart").getContext("2d");
  severityChart = new Chart(sevCtx, {
    type: "doughnut",
    data: {
      labels: ["Critical", "Medium", "Low"],
      datasets: [{
        data: [0, 0, 0],
        backgroundColor: ["#ef4444", "#f59e0b", "#22c55e"],
        borderColor: "#111827",
        borderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 400 },
      cutout: "65%",
      plugins: {
        legend: { position: "bottom", labels: { color: "#94a3b8", font: { size: 11 }, padding: 12, usePointStyle: true } },
      },
    },
  });
}

// ── Fetch helpers ──
async function fetchJson(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Sync all data ──
async function syncData() {
  try {
    const [alertsR, auditR, statsR, anomR, sapR, ztR, credR, cloudR, modulesR] = await Promise.all([
      fetchJson("/api/alerts?limit=60"),
      fetchJson("/api/audit?limit=40"),
      fetchJson("/api/stats"),
      fetchJson("/api/anomalies?limit=40"),
      fetchJson("/api/sap-activity?limit=40"),
      fetchJson("/api/zero-trust?limit=40"),
      fetchJson("/api/credentials?limit=40"),
      fetchJson("/api/cloud-posture?limit=40"),
      fetchJson("/api/modules/health"),
    ]);

    alerts = alertsR.alerts || [];
    auditRows = auditR.rows || [];
    anomalies = anomR.anomalies || [];
    sapEvents = sapR.events || [];
    ztEvents = ztR.evaluations || [];
    credEvents = credR.events || [];
    cloudEvents = cloudR.findings || [];

    // Update backend status
    ui.backendStatus.textContent = "connected";
    ui.statusDot.className = "status-dot online";
    ui.eventsProcessed.textContent = (modulesR.events_processed || 0).toLocaleString();

    // Update stats cards
    ui.totalAlerts.textContent = statsR.total_alerts || 0;
    ui.criticalAlerts.textContent = statsR.critical_alerts || 0;
    ui.avgLatency.textContent = `${((statsR.avg_latency_ms || 0) / 1000).toFixed(1)}s`;
    ui.anomalyCount.textContent = statsR.anomalies_count || 0;
    ui.sapCount.textContent = statsR.sap_events_count || 0;
    ui.ztCount.textContent = statsR.zero_trust_evals || 0;
    ui.credCount.textContent = statsR.credential_events || 0;
    ui.cloudCount.textContent = statsR.cloud_findings || 0;

    // Alert trend
    const currentCount = statsR.total_alerts || 0;
    if (prevAlertCount > 0) {
      const diff = currentCount - prevAlertCount;
      ui.trendAlerts.textContent = diff > 0 ? `▲ +${diff}` : diff < 0 ? `▼ ${diff}` : "—";
      ui.trendAlerts.style.color = diff > 0 ? "#ef4444" : "#22c55e";
    }
    prevAlertCount = currentCount;

    // Update timeline chart
    const now = new Date();
    alertTimeline.push({ t: now.toLocaleTimeString(), count: alerts.length });
    if (alertTimeline.length > 30) alertTimeline.shift();
    alertChart.data.labels = alertTimeline.map(p => p.t);
    alertChart.data.datasets[0].data = alertTimeline.map(p => p.count);
    alertChart.update("none");

    // Update severity chart
    const critical = alerts.filter(a => a.severity === "critical").length;
    const medium = alerts.filter(a => a.severity === "medium").length;
    const low = alerts.filter(a => a.severity === "low").length;
    severityChart.data.datasets[0].data = [critical, medium, low];
    severityChart.update("none");

    // Render module health grid
    renderModuleHealth(modulesR.modules || {});

    // Render active tab
    renderActiveTab();

  } catch (err) {
    ui.backendStatus.textContent = "offline";
    ui.statusDot.className = "status-dot offline";
  }
}

// ── Render functions ──
function renderActiveTab() {
  const active = document.querySelector(".tab.active");
  if (!active) return;
  const tab = active.dataset.tab;

  if (tab === "alerts") renderAlerts();
  else if (tab === "anomalies") renderAnomaly();
  else if (tab === "sap") renderSap();
  else if (tab === "zero-trust") renderZeroTrust();
  else if (tab === "credentials") renderCredentials();
  else if (tab === "cloud") renderCloud();
  else if (tab === "audit") renderAudit();
}

function renderAlerts() {
  const selected = ui.filter.value;
  const visible = selected === "all" ? alerts : alerts.filter(a => a.scenario === selected);
  ui.alertsList.innerHTML = visible.map(a => `
    <li class="alert-item sev-${a.severity}">
      <strong>${(a.severity || "").toUpperCase()}</strong> — ${a.message || a.scenario || "alert"}
      <div>${fmtTime(a.ts)} | ${a.scenario || ""} | latency ${((a.latencyMs || 0) / 1000).toFixed(2)}s</div>
    </li>
  `).join("");
}

function renderAnomaly() {
  ui.anomalyEmpty.classList.toggle("hidden", anomalies.length > 0);
  ui.anomalyList.innerHTML = anomalies.map(a => `
    <li class="alert-item ev-anomaly">
      <strong>ANOMALY</strong> — score: ${a.anomaly_score || a.score || "—"} | ${a.classification || a.type || "unclassified"}
      <div>${fmtTime(a.ts)} | baseline dev: ${a.baseline_deviation || "—"}</div>
    </li>
  `).join("");
}

function renderSap() {
  ui.sapEmpty.classList.toggle("hidden", sapEvents.length > 0);
  ui.sapList.innerHTML = sapEvents.map(e => `
    <li class="alert-item ev-sap">
      <strong>SAP MCP</strong> — ${e.tool_name || e.action || "tool invocation"}
      <div>${fmtTime(e.ts)} | ${e.result || e.status || ""}</div>
    </li>
  `).join("");
}

function renderZeroTrust() {
  ui.ztEmpty.classList.toggle("hidden", ztEvents.length > 0);
  ui.ztList.innerHTML = ztEvents.map(e => {
    const decision = (e.decision || "evaluated").toLowerCase();
    const cls = decision === "allow" ? "ev-zt-allow" : decision === "deny" ? "ev-zt-deny" : "ev-zt-challenge";
    return `
      <li class="alert-item ${cls}">
        <strong>${decision.toUpperCase()}</strong> — user: ${e.user_id || "—"} | risk: ${e.risk_score || 0}
        <div>${fmtTime(e.ts)} | failed: ${(e.failed_controls || []).join(", ") || "none"} | IP: ${e.source_ip || "—"}</div>
      </li>
    `;
  }).join("");
}

function renderCredentials() {
  ui.credEmpty.classList.toggle("hidden", credEvents.length > 0);
  ui.credList.innerHTML = credEvents.map(e => `
    <li class="alert-item ev-credential">
      <strong>${(e.action || "event").toUpperCase()}</strong> — ${e.key || "—"}
      <div>${fmtTime(e.ts)} | status: ${e.status || "—"} | tenant: ${e.tenant_id || "—"}</div>
    </li>
  `).join("");
}

function renderCloud() {
  ui.cloudEmpty.classList.toggle("hidden", cloudEvents.length > 0);
  ui.cloudList.innerHTML = cloudEvents.map(e => `
    <li class="alert-item ev-cloud">
      <strong>${(e.provider || "cloud").toUpperCase()}</strong> — ${e.control_id || "—"} | risk: ${e.risk_score || 0}
      <div>${fmtTime(e.ts)} | resource: ${e.resource_id || "—"} | severity: ${e.raw_severity || "—"}</div>
    </li>
  `).join("");
}

function renderAudit() {
  ui.auditBody.innerHTML = auditRows.map(r => `
    <tr>
      <td>${fmtTime(r.ts)}</td>
      <td>${r.actor}</td>
      <td>${r.action}</td>
      <td><span class="badge badge-poc">${r.module}</span></td>
      <td>${r.status}</td>
    </tr>
  `).join("");
}

function renderModuleHealth(modules) {
  ui.moduleGrid.innerHTML = Object.entries(modules).map(([name, info]) => `
    <div class="module-card">
      <span class="dot"></span>
      <span class="name">${name}</span>
      <span class="stream">${info.stream || ""}</span>
    </div>
  `).join("");
}

function fmtTime(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleTimeString(); }
  catch { return ts; }
}

// ── Tab switching ──
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(c => c.classList.add("hidden"));
    tab.classList.add("active");
    document.getElementById(`tab-${tab.dataset.tab}`).classList.remove("hidden");
    renderActiveTab();
  });
});

// ── Filter change ──
ui.filter.addEventListener("change", renderAlerts);

// ── Init ──
initCharts();
syncData();
setInterval(syncData, 2000);
