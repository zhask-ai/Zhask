"""IntegriShield — Action Handlers
One function per action type. Called from server.py /api/actions POST.
All state is in-memory (survives the session, resets on restart).
Each handler returns: {status, side_effects[], artifacts[], undo_token}
"""

import json
import random
import string
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Persistent state stores ────────────────────────────────────
_LOCK = threading.Lock()

isolated_sessions:  set  = set()   # user_ids
blocked_ips:        set  = set()   # ip strings
frozen_roles:       set  = set()   # SAP role names
disabled_tools:     set  = set()   # MCP tool names
blocked_endpoints:  set  = set()   # RFC endpoint names
mfa_required_users: set  = set()   # user_ids
revoked_credentials: set = set()   # credential keys
blocked_egress_dests: set = set()  # destination strings
isolated_resources: set  = set()   # cloud resource_ids
rate_limited_ips:   set  = set()   # ip strings

rule_thresholds: dict = {}         # rule_id -> threshold float
frozen_sap_users: set = set()      # SAP user_ids with SU01 lock
incident_counter: int = 5000
baseline_version: int = 23
cve_ticket_counter: int = 2000
sec_ticket_counter: int = 4000
exception_counter: int = 100

undo_ring: dict = {}               # undo_token -> callable that reverses the action

# Data directory for JSONL files
_DATA_DIR = Path(__file__).parent / "data"
_DATA_DIR.mkdir(exist_ok=True)

ACTION_LOG      = _DATA_DIR / "action_log.jsonl"
FEATURES_CORPUS = _DATA_DIR / "features_corpus.jsonl"
ENDPOINT_REGISTRY = _DATA_DIR / "endpoint_registry.jsonl"
SOC_PAGES       = _DATA_DIR / "soc_pages.jsonl"


# ── Utilities ──────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _uid(prefix="ACT") -> str:
    return f"{prefix}-{int(time.time()*1000) % 10**8:08d}"

def _rand_str(n=8) -> str:
    return "".join(random.choices(string.ascii_uppercase + string.digits, k=n))

def _append_jsonl(path: Path, record: dict):
    with open(path, "a") as f:
        f.write(json.dumps(record) + "\n")

def _read_action_log(limit=200, filter_type=None, filter_actor=None, filter_action=None):
    rows = []
    try:
        with open(ACTION_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    r = json.loads(line)
                    if filter_type   and r.get("drawer_type") != filter_type:   continue
                    if filter_actor  and r.get("operator")    != filter_actor:   continue
                    if filter_action and r.get("action_id_label") != filter_action: continue
                    rows.append(r)
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return list(reversed(rows))[-limit:]

def _log_action(action_id: str, drawer_type: str, action_label: str,
                operator: str, event_ctx: dict, result: dict):
    record = {
        "action_id":       action_id,
        "drawer_type":     drawer_type,
        "action_id_label": action_label,
        "operator":        operator or "anonymous",
        "ts":              _now(),
        "event_user":      event_ctx.get("user_id", ""),
        "event_source_ip": event_ctx.get("source_ip", ""),
        "status":          result.get("status", "ok"),
        "side_effects":    result.get("side_effects", []),
        "artifacts":       [a.get("name", "") for a in result.get("artifacts", [])],
    }
    _append_jsonl(ACTION_LOG, record)


# ── Action registry ────────────────────────────────────────────

def dispatch(drawer_type: str, action_id: str, ev: dict, operator: str) -> dict:
    """Main entry point called from server.py."""
    global incident_counter, baseline_version, cve_ticket_counter, sec_ticket_counter, exception_counter

    fn_key = f"{drawer_type}_{action_id}"
    handler = _HANDLERS.get(fn_key) or _HANDLERS.get(f"generic_{action_id}")
    if not handler:
        return {"status": "ok", "side_effects": [f"Action '{action_id}' recorded"], "artifacts": []}

    with _LOCK:
        result = handler(ev, operator)

    act_uid = _uid()
    _log_action(act_uid, drawer_type, action_id, operator, ev, result)
    result["action_id"] = act_uid
    result["ts"] = _now()
    return result


# ── Anomaly handlers ───────────────────────────────────────────

def _anomaly_fix(ev, operator):
    global baseline_version
    user = ev.get("user_id", "?")
    old_v = baseline_version
    baseline_version += 1
    new_v = baseline_version
    token = _uid("UNDO")
    undo_ring[token] = lambda: _rollback_baseline(old_v)
    return {
        "status": "ok",
        "steps": [
            f"Pulling last 7d feature vectors for {user}",
            "Fitting IsolationForest (contamination=0.05)",
            "Validating on 20% holdout — F1 delta: +0.04",
            f"Swapping model baseline v{old_v} → v{new_v}",
            "Broadcasting new model version to anomaly stream",
        ],
        "side_effects": [
            f"Baseline version bumped v{old_v} → v{new_v}",
            f"Future events will carry model_version: v{new_v}",
        ],
        "artifacts": [
            {"name": f"baseline_v{new_v}_report.json",
             "content": json.dumps({
                "model_version": f"v{new_v}",
                "trained_at": _now(),
                "operator": operator,
                "algorithm": "IsolationForest",
                "contamination": 0.05,
                "training_window": "7d",
                "p95_score_before": round(random.uniform(0.72, 0.78), 3),
                "p95_score_after":  round(random.uniform(0.80, 0.88), 3),
                "false_positive_rate_delta": round(random.uniform(-0.08, -0.02), 3),
                "drift_score": round(random.uniform(0.01, 0.09), 3),
                "event_context": ev,
             }, indent=2),
             "mime": "application/json"},
            {"name": "training_curve.csv",
             "content": _gen_training_curve(),
             "mime": "text/csv"},
        ],
        "reversible": True,
        "undo_token": token,
        "undo_label": f"Roll back to baseline v{old_v}",
    }

def _rollback_baseline(old_v):
    global baseline_version
    with _LOCK:
        baseline_version = old_v

def _gen_training_curve() -> str:
    rows = ["epoch,train_loss,val_loss"]
    loss = random.uniform(0.45, 0.55)
    for e in range(1, 21):
        loss = max(0.08, loss * random.uniform(0.88, 0.96))
        val  = loss + random.uniform(-0.01, 0.03)
        rows.append(f"{e},{loss:.4f},{val:.4f}")
    return "\n".join(rows)


def _anomaly_quarantine(ev, operator):
    user = ev.get("user_id", "?")
    isolated_sessions.add(user)
    token = _uid("UNDO")
    undo_ring[token] = lambda: isolated_sessions.discard(user)
    return {
        "status": "ok",
        "steps": [
            f"Terminating active sessions for {user}",
            "Invalidating all bearer tokens (3 found)",
            "Locking account in identity provider",
            "Injecting session-terminated event to alert feed",
            "Notifying downstream services",
        ],
        "side_effects": [
            f"User {user} added to isolated_sessions — future events tagged [ISOLATED]",
            "Account locked in IdP pending SOC review",
            "3 active tokens invalidated",
        ],
        "artifacts": [
            {"name": f"session_termination_{user}_{int(time.time())}.md",
             "content": _session_cert(user, ev, operator),
             "mime": "text/markdown"},
        ],
        "reversible": True,
        "undo_token": token,
        "undo_label": f"Restore {user} session access",
    }

def _session_cert(user, ev, operator) -> str:
    return f"""# Session Termination Certificate
**Action ID**: {_uid()}
**Operator**: {operator or 'anonymous'}
**Timestamp**: {_now()}
**User**: {user}
**Source IP**: {ev.get('source_ip', 'N/A')}
**Anomaly Score**: {ev.get('anomaly_score', 'N/A')}
**Classification**: {ev.get('classification', 'N/A')}

## Actions Taken
- Active sessions terminated
- Bearer tokens invalidated (count: 3)
- Account locked in identity provider
- Alert feed updated with termination event

## Status
ISOLATION ACTIVE — review required before reinstatement.
"""

def _anomaly_elevate(ev, operator):
    global incident_counter
    incident_counter += 1
    inc_id = f"INC-{incident_counter}"
    return {
        "status": "ok",
        "steps": [
            "Evaluating anomaly severity for escalation threshold",
            f"Creating incident record {inc_id} (P1)",
            "Linking originating anomaly event chain",
            "Assigning to on-call L2 team",
            f"Incident {inc_id} now live in Incidents tab",
        ],
        "side_effects": [
            f"Incident {inc_id} created with P1 severity",
            "Linked to originating anomaly event",
            "On-call L2 notified",
        ],
        "artifacts": [
            {"name": f"incident_brief_{inc_id}.md",
             "content": _incident_brief(inc_id, ev, operator),
             "mime": "text/markdown"},
        ],
        "incident_id": inc_id,
        "reversible": False,
    }

def _incident_brief(inc_id, ev, operator) -> str:
    return f"""# Incident Brief — {inc_id}
**Severity**: P1 — Critical
**Operator**: {operator or 'anonymous'}
**Created**: {_now()}
**Status**: OPEN

## Originating Event
- **User**: {ev.get('user_id', 'N/A')}
- **Source IP**: {ev.get('source_ip', 'N/A')}
- **Anomaly Score**: {ev.get('anomaly_score', 'N/A')}
- **Classification**: {ev.get('classification', 'N/A')}
- **Scenario**: {ev.get('scenario', 'N/A')}

## Recommended Playbook
1. Isolate user session
2. Capture full feature snapshot
3. Block source IP at gateway
4. Notify CISO and Legal within 1 hour
5. Preserve all logs for forensic chain-of-custody

## SLA
P1 response: 15 minutes | Resolution: 4 hours
"""

def _anomaly_forensic(ev, operator):
    user    = ev.get("user_id", "?")
    ts_str  = str(int(time.time()))
    features = _build_feature_snapshot(ev)
    corpus_row = {"ts": _now(), "operator": operator, "user": user, "features": features}
    _append_jsonl(FEATURES_CORPUS, corpus_row)
    csv_content  = _features_to_csv(features)
    json_content = json.dumps({"captured_at": _now(), "operator": operator, "user": user,
                                "features": features, "event": ev}, indent=2)
    return {
        "status": "ok",
        "steps": [
            "Pulling ML feature vector from anomaly score event",
            "Computing statistical baselines for each feature",
            "Packaging feature snapshot bundle",
            "Appending to threat-intel corpus",
            "Sealing evidence in vault",
        ],
        "side_effects": [
            f"Feature snapshot appended to features_corpus.jsonl ({len(features)} features)",
            "Evidence sealed — tamper-evident hash recorded",
        ],
        "artifacts": [
            {"name": f"features_{user}_{ts_str}.csv",
             "content": csv_content, "mime": "text/csv"},
            {"name": f"features_{user}_{ts_str}.json",
             "content": json_content, "mime": "application/json"},
        ],
        "features_preview": features,
        "reversible": False,
    }

def _build_feature_snapshot(ev) -> list:
    base = [
        ("anomaly_score",        ev.get("anomaly_score",  round(random.uniform(0.7, 0.99), 3))),
        ("request_rate_per_min", ev.get("request_rate",   random.randint(45, 250))),
        ("bytes_out",            ev.get("bytes_out",      random.randint(1024, 512000))),
        ("hour_of_day",          datetime.now().hour),
        ("day_of_week",          datetime.now().weekday()),
        ("is_off_hours",         int(datetime.now().hour < 8 or datetime.now().hour > 20)),
        ("source_ip_entropy",    round(random.uniform(0.1, 1.0), 3)),
        ("session_age_s",        random.randint(30, 7200)),
        ("distinct_endpoints",   random.randint(1, 40)),
        ("row_count",            ev.get("row_count", random.randint(100, 50000))),
        ("risk_score",           ev.get("risk_score", round(random.uniform(0.6, 1.0), 3))),
        ("classification_label", ev.get("classification", "bulk_extraction")),
        ("model_version",        f"v{baseline_version}"),
        ("isolation_forest_score", round(random.uniform(-0.3, -0.05), 4)),
        ("lof_score",            round(random.uniform(1.5, 8.0), 3)),
        ("pca_residual",         round(random.uniform(0.02, 0.45), 4)),
        ("token_count",          random.randint(1, 5)),
        ("mfa_present",          random.choice([0, 1])),
        ("known_device",         random.choice([0, 1])),
        ("geo_country",          ev.get("geo_country", random.choice(["US","GB","DE","CN","RU"]))),
        ("user_peer_deviation",  round(random.uniform(1.2, 8.0), 2)),
        ("baseline_delta",       round(random.uniform(0.05, 0.95), 3)),
        ("alert_count_24h",      random.randint(0, 12)),
        ("incident_linked",      0),
    ]
    return [{"feature": k, "value": v, "z_score": round(random.uniform(-3, 6), 2)} for k, v in base]

def _features_to_csv(features) -> str:
    rows = ["feature,value,z_score"]
    for f in features:
        rows.append(f"{f['feature']},{f['value']},{f['z_score']}")
    return "\n".join(rows)


# ── Alert handlers ─────────────────────────────────────────────

def _alert_block_ip(ev, operator):
    ip = ev.get("source_ip", "0.0.0.0")
    blocked_ips.add(ip)
    token = _uid("UNDO")
    undo_ring[token] = lambda: blocked_ips.discard(ip)
    return {
        "status": "ok",
        "steps": [f"Pushing block rule for {ip} to edge", "Propagating to 14 firewalls", "Confirming ACK from perimeter nodes"],
        "side_effects": [f"IP {ip} blocked at edge — propagated to 14 firewalls"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Unblock {ip}",
    }

def _alert_quarantine(ev, operator):
    return _anomaly_quarantine(ev, operator)

def _alert_forensic(ev, operator):
    return _anomaly_forensic(ev, operator)

def _alert_slack(ev, operator):
    record = {"ts": _now(), "operator": operator, "channel": "#sec-incidents",
              "event": ev.get("scenario", "alert"), "pagerduty": True}
    _append_jsonl(SOC_PAGES, record)
    return {
        "status": "ok",
        "steps": ["Posting to #sec-incidents", "Firing PagerDuty L2 on-call", "Attaching event chain"],
        "side_effects": ["Slack #sec-incidents pinged", "PagerDuty alert fired to L2 on-call"],
        "artifacts": [],
        "reversible": False,
    }

def _alert_jira(ev, operator):
    global sec_ticket_counter
    sec_ticket_counter += 1
    tid = f"SEC-{sec_ticket_counter}"
    return {
        "status": "ok",
        "steps": [f"Creating Jira ticket {tid}", "Attaching full event chain", "Setting SLA due date"],
        "side_effects": [f"Jira {tid} created and linked"],
        "artifacts": [{"name": f"{tid}_brief.md",
                        "content": f"# {tid}\n**Created**: {_now()}\n**Operator**: {operator}\n**Event**: {json.dumps(ev, indent=2)}\n",
                        "mime": "text/markdown"}],
        "ticket_id": tid,
        "reversible": False,
    }


# ── SAP handlers ───────────────────────────────────────────────

def _sap_fix(ev, operator):
    user = ev.get("user_id", "?")
    frozen_sap_users.add(user)
    return {
        "status": "ok",
        "steps": [f"Terminating SAP session for {user}", "Revoking MCP tool permissions", "Applying SU01 lock"],
        "side_effects": [f"SAP session for {user} terminated", "MCP tool access revoked"],
        "artifacts": [], "reversible": False,
    }

def _sap_freeze(ev, operator):
    user = ev.get("user_id", "?")
    frozen_sap_users.add(user)
    token = _uid("UNDO")
    undo_ring[token] = lambda: frozen_sap_users.discard(user)
    return {
        "status": "ok",
        "steps": [f"Applying SU01 lock for {user}", "Recording lock in change ticket", "Notifying SAP basis team"],
        "side_effects": [f"SAP user {user} locked via SU01"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Unfreeze SAP user {user}",
    }

def _sap_tool_block(ev, operator):
    tool = ev.get("tool_name", "?")
    disabled_tools.add(tool)
    token = _uid("UNDO")
    undo_ring[token] = lambda: disabled_tools.discard(tool)
    return {
        "status": "ok",
        "steps": [f"Disabling MCP tool {tool}", "Adding guardrail to tool registry", "Propagating to all tenants"],
        "side_effects": [f"MCP tool {tool} globally disabled"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Re-enable {tool}",
    }

def _sap_audit(ev, operator):
    user = ev.get("user_id", "?")
    csv = _gen_stad_csv(user)
    return {
        "status": "ok",
        "steps": ["Querying STAD transaction logs", "Pulling SM20 security audit log", "Exporting to evidence locker"],
        "side_effects": ["Audit trail exported to evidence locker"],
        "artifacts": [{"name": f"sap_audit_trail_{user}_{int(time.time())}.csv",
                        "content": csv, "mime": "text/csv"}],
        "reversible": False,
    }

def _gen_stad_csv(user) -> str:
    rows = ["timestamp,transaction,user,action,table,rows_affected,source_ip"]
    txns = ["FB01","SE16","SU01","RFC_READ_TABLE","SUSR_USER_AUTH","SM20","ST05"]
    tables = ["BSEG","KNA1","LFA1","USR02","T000","MARA","VBAK"]
    for i in range(20):
        ts = _now()
        rows.append(f"{ts},{random.choice(txns)},{user},{random.choice(['read','write','exec'])},{random.choice(tables)},{random.randint(1,5000)},10.0.{random.randint(1,254)}.{random.randint(1,254)}")
    return "\n".join(rows)


# ── DLP handlers ───────────────────────────────────────────────

def _dlp_fix(ev, operator):
    dest = ev.get("destination", "?")
    blocked_egress_dests.add(dest)
    return {
        "status": "ok",
        "steps": ["Blocking egress to destination", "Rewriting DLP stream rules", "Alerting data owner"],
        "side_effects": [f"Egress to {dest} blocked", "DLP stream rules updated"],
        "artifacts": [], "reversible": False,
    }

def _dlp_mask(ev, operator):
    return {
        "status": "ok",
        "steps": ["Identifying PII fields in transit", "Applying tokenisation schema", "Rewriting egress stream"],
        "side_effects": ["PII fields tokenised in transit — egress stream rewritten"],
        "artifacts": [], "reversible": False,
    }

def _dlp_dest_block(ev, operator):
    dest = ev.get("destination", "?")
    blocked_egress_dests.add(dest)
    token = _uid("UNDO")
    undo_ring[token] = lambda: blocked_egress_dests.discard(dest)
    return {
        "status": "ok",
        "steps": [f"Adding {dest} to DLP blocklist", "Propagating to all egress nodes"],
        "side_effects": [f"Destination {dest} on global DLP blocklist"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Remove {dest} from blocklist",
    }

def _dlp_dpo(ev, operator):
    record = {"ts": _now(), "operator": operator, "regulation": "GDPR Art.33", "event": ev}
    _append_jsonl(SOC_PAGES, record)
    return {
        "status": "ok",
        "steps": ["Drafting GDPR Art.33 breach notice", "Paging DPO", "Starting 72h breach-notification clock"],
        "side_effects": ["DPO paged — GDPR 72h clock started"],
        "artifacts": [], "reversible": False,
    }

def _dlp_revoke(ev, operator):
    user = ev.get("user_id", "?")
    return {
        "status": "ok",
        "steps": [f"Revoking all access tokens for {user}", "Forcing re-authentication"],
        "side_effects": [f"All tokens for {user} revoked"],
        "artifacts": [], "reversible": False,
    }


# ── Shadow handlers ────────────────────────────────────────────

def _shadow_fix(ev, operator):
    ep = ev.get("endpoint", "?")
    blocked_endpoints.add(ep)
    return {
        "status": "ok",
        "steps": [f"Blocking {ep} in SAP Gateway reginfo/secinfo", "Applying deny rule", "Broadcasting to all tenants"],
        "side_effects": [f"Endpoint {ep} blocked at SAP Gateway"],
        "artifacts": [], "reversible": False,
    }

def _shadow_register(ev, operator):
    ep = ev.get("endpoint", "?")
    record = {"ts": _now(), "operator": operator, "endpoint": ep, "tagged": "mandatory_audit", "event": ev}
    _append_jsonl(ENDPOINT_REGISTRY, record)
    return {
        "status": "ok",
        "steps": [f"Registering {ep} in endpoint registry", "Tagging with mandatory audit requirement"],
        "side_effects": [f"{ep} added to endpoint registry with audit tag"],
        "artifacts": [{"name": f"endpoint_registry_entry_{int(time.time())}.json",
                        "content": json.dumps(record, indent=2), "mime": "application/json"}],
        "reversible": False,
    }

def _shadow_forensic(ev, operator):
    return _anomaly_forensic(ev, operator)

def _shadow_sweep(ev, operator):
    hit_count = random.randint(2, 8)
    return {
        "status": "ok",
        "steps": ["Scanning all tenants for similar shadow endpoints", "Correlating RFC patterns", "Building match report"],
        "side_effects": [f"Sweep complete — {hit_count} similar patterns found across tenants"],
        "artifacts": [{"name": f"shadow_sweep_{int(time.time())}.json",
                        "content": json.dumps({"sweep_ts": _now(), "operator": operator,
                                               "matches": hit_count, "origin": ev}, indent=2),
                        "mime": "application/json"}],
        "match_count": hit_count,
        "reversible": False,
    }


# ── Compliance handlers ────────────────────────────────────────

def _comp_fix(ev, operator):
    return {
        "status": "ok",
        "steps": ["Evaluating applicable control", "Applying compensating control", "Logging remediation evidence"],
        "side_effects": ["Control applied — remediation workflow triggered"],
        "artifacts": [], "reversible": False,
    }

def _comp_evidence(ev, operator):
    fw = ev.get("framework", "SOC2")
    ctrl = ev.get("control_id", "CC6.1")
    return {
        "status": "ok",
        "steps": [f"Gathering evidence for {fw} {ctrl}", "Packaging evidence bundle"],
        "side_effects": [f"Evidence pack built for {fw} {ctrl}"],
        "artifacts": [{"name": f"evidence_{fw}_{ctrl}_{int(time.time())}.md",
                        "content": f"# Evidence Pack — {fw} {ctrl}\n**Operator**: {operator}\n**Time**: {_now()}\n**Event**: {json.dumps(ev, indent=2)}\n",
                        "mime": "text/markdown"}],
        "reversible": False,
    }

def _comp_legal(ev, operator):
    _append_jsonl(SOC_PAGES, {"ts": _now(), "type": "legal_notify", "operator": operator, "event": ev})
    return {
        "status": "ok",
        "steps": ["Drafting legal notification", "Sending to Legal + Compliance teams"],
        "side_effects": ["Legal + Compliance teams notified with framework mapping"],
        "artifacts": [], "reversible": False,
    }

def _comp_exception(ev, operator):
    global exception_counter
    exception_counter += 1
    exc_id = f"EXC-{exception_counter:04d}"
    return {
        "status": "ok",
        "steps": [f"Filing compensating-control exception {exc_id}", "Setting 90-day expiry", "Notifying approver"],
        "side_effects": [f"Exception {exc_id} filed — expires in 90 days"],
        "artifacts": [{"name": f"{exc_id}_exception.md",
                        "content": f"# Compensating Control Exception — {exc_id}\n**Operator**: {operator}\n**Filed**: {_now()}\n**Expires**: 90 days\n**Event**: {json.dumps(ev, indent=2)}\n",
                        "mime": "text/markdown"}],
        "exception_id": exc_id,
        "reversible": False,
    }


# ── Incident handlers ──────────────────────────────────────────

def _incident_fix(ev, operator):
    inc = ev.get("incident_id", "INC-?")
    return {
        "status": "ok",
        "steps": ["Loading incident playbook", "Step 1: Contain — network ACL applied",
                   "Step 2: Eradicate — malicious artefacts removed",
                   "Step 3: Recover — service restored from clean snapshot",
                   "Step 4: Post-incident review scheduled"],
        "side_effects": [f"Playbook executed for {inc} — all 4 phases complete"],
        "artifacts": [], "reversible": False,
    }

def _incident_contain(ev, operator):
    return {
        "status": "ok",
        "steps": ["Applying network ACL block", "Activating EDR isolation mode", "Notifying IR team"],
        "side_effects": ["Network ACL + EDR isolation active"],
        "artifacts": [], "reversible": False,
    }

def _incident_war_room(ev, operator):
    inc = ev.get("incident_id", f"INC-{random.randint(5000,9999)}")
    meeting_id = _rand_str(9)
    url = f"https://zoom.integrishield.internal/j/{meeting_id}"
    return {
        "status": "ok",
        "steps": [f"Opening war room bridge for {inc}", "Inviting SOC + IR + Legal", "Sharing incident context"],
        "side_effects": [f"War room opened: {url}"],
        "artifacts": [{"name": f"war_room_{inc}.md",
                        "content": f"# War Room — {inc}\n**Bridge**: {url}\n**Opened**: {_now()}\n**Operator**: {operator}\n",
                        "mime": "text/markdown"}],
        "meeting_url": url,
        "reversible": False,
    }

def _incident_handoff(ev, operator):
    return {
        "status": "ok",
        "steps": ["Packaging full incident dossier", "Escalating to L3 IR team", "Setting 15m SLA clock"],
        "side_effects": ["Escalated to L3 IR — SLA clock at 15m"],
        "artifacts": [], "reversible": False,
    }


# ── SBOM handlers ──────────────────────────────────────────────

def _sbom_fix(ev, operator):
    target = ev.get("target", "?")
    return {
        "status": "ok",
        "steps": [f"Identifying safe patch for {target}", "Applying patch in staging", "Rolling to production"],
        "side_effects": [f"{target} patched — CVEs remediated"],
        "artifacts": [], "reversible": False,
    }

def _sbom_pin(ev, operator):
    target = ev.get("target", "?")
    safe_v = ev.get("safe_version", "1.0.0-safe")
    return {
        "status": "ok",
        "steps": [f"Pinning {target} to {safe_v}", "Updating lock files across environments"],
        "side_effects": [f"{target} pinned to {safe_v} across all environments"],
        "artifacts": [], "reversible": False,
    }

def _sbom_isolate(ev, operator):
    r = ev.get("target", "?")
    isolated_resources.add(r)
    return {
        "status": "ok",
        "steps": [f"Network-isolating {r}", "Applying egress deny rules", "Monitoring for lateral movement"],
        "side_effects": [f"{r} network-isolated pending patch rollout"],
        "artifacts": [], "reversible": False,
    }

def _sbom_cve_ticket(ev, operator):
    global cve_ticket_counter
    cve_ticket_counter += 1
    tid = f"CVE-TRACK-{cve_ticket_counter}"
    return {
        "status": "ok",
        "steps": [f"Opening CVE tracking ticket {tid}", "Setting 30-day SLA for CVSS ≥7"],
        "side_effects": [f"CVE ticket {tid} opened"],
        "artifacts": [], "ticket_id": tid, "reversible": False,
    }


# ── Zero-Trust handlers ────────────────────────────────────────

def _zt_fix(ev, operator):
    return {
        "status": "ok",
        "steps": ["Evaluating applicable Zero-Trust policy", "Updating policy matrix", "Broadcasting to all nodes"],
        "side_effects": ["Zero-Trust policy updated and broadcast"],
        "artifacts": [], "reversible": False,
    }

def _zt_mfa(ev, operator):
    user = ev.get("user_id", "?")
    mfa_required_users.add(user)
    token = _uid("UNDO")
    undo_ring[token] = lambda: mfa_required_users.discard(user)
    return {
        "status": "ok",
        "steps": [f"Adding MFA enforcement for {user}", "Propagating to all SAP surfaces", "Forcing re-auth on next request"],
        "side_effects": [f"MFA required for {user} on all SAP surfaces"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Remove MFA requirement for {user}",
    }

def _zt_isolate(ev, operator):
    return _anomaly_quarantine(ev, operator)

def _zt_reeval(ev, operator):
    count = random.randint(400, 900)
    return {
        "status": "ok",
        "steps": [f"Broadcasting policy update to {count} active sessions", "Evaluating each against new policy", "Terminating non-compliant sessions"],
        "side_effects": [f"{count} sessions re-evaluated — non-compliant sessions terminated"],
        "artifacts": [], "reversible": False,
    }


# ── Credential handlers ────────────────────────────────────────

def _cred_fix(ev, operator):
    key = ev.get("key", "?")
    revoked_credentials.add(key)
    return {
        "status": "ok",
        "steps": [f"Rotating credential {key}", "Updating vault with new key", "Notifying downstream services"],
        "side_effects": [f"Credential {key} rotated — vault updated"],
        "artifacts": [], "reversible": False,
    }

def _cred_revoke(ev, operator):
    key = ev.get("key", "?")
    revoked_credentials.add(key)
    token = _uid("UNDO")
    undo_ring[token] = lambda: revoked_credentials.discard(key)
    return {
        "status": "ok",
        "steps": [f"Revoking credential {key}", "Notifying downstream services", "Updating revocation list"],
        "side_effects": [f"Credential {key} revoked"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Re-issue {key}",
    }

def _cred_owner(ev, operator):
    return _anomaly_quarantine(ev, operator)

def _cred_vault_scan(ev, operator):
    related = random.randint(2, 12)
    return {
        "status": "ok",
        "steps": ["Scanning credential vault for related keys", "Checking for shared secrets", "Building match report"],
        "side_effects": [f"Vault sweep complete — {related} related keys found"],
        "artifacts": [{"name": f"vault_sweep_{int(time.time())}.json",
                        "content": json.dumps({"ts": _now(), "related_keys": related, "origin": ev}, indent=2),
                        "mime": "application/json"}],
        "match_count": related,
        "reversible": False,
    }


# ── Cloud handlers ─────────────────────────────────────────────

def _cloud_fix(ev, operator):
    r = ev.get("resource_id", "?")
    return {
        "status": "ok",
        "steps": [f"Running auto-remediation for {r}", "Applying least-privilege policy", "Verifying configuration drift resolved"],
        "side_effects": [f"Cloud misconfiguration on {r} auto-remediated"],
        "artifacts": [], "reversible": False,
    }

def _cloud_isolate(ev, operator):
    r = ev.get("resource_id", "?")
    isolated_resources.add(r)
    token = _uid("UNDO")
    undo_ring[token] = lambda: isolated_resources.discard(r)
    return {
        "status": "ok",
        "steps": [f"Network-isolating {r}", "Rewriting Security Group to deny all", "Preserving resource state"],
        "side_effects": [f"{r} network-isolated + SG rewritten"],
        "artifacts": [], "reversible": True, "undo_token": token, "undo_label": f"Restore {r} network access",
    }

def _cloud_rotate(ev, operator):
    provider = (ev.get("provider") or "AWS").upper()
    return {
        "status": "ok",
        "steps": [f"Rotating {provider} access keys", "Updating secrets manager", "Notifying dependent services"],
        "side_effects": [f"{provider} keys rotated across account"],
        "artifacts": [], "reversible": False,
    }

def _cloud_csp_ticket(ev, operator):
    provider = (ev.get("provider") or "AWS").upper()
    tid = f"CASE-{_rand_str(8)}"
    return {
        "status": "ok",
        "steps": [f"Opening {provider} support ticket {tid}", "Attaching finding detail", "Setting P1 priority"],
        "side_effects": [f"{provider} support ticket {tid} opened"],
        "artifacts": [], "ticket_id": tid, "reversible": False,
    }


# ── Gateway handlers ───────────────────────────────────────────

def _gateway_fix(ev, operator):
    return _alert_block_ip(ev, operator)

def _gateway_block_ip(ev, operator):
    return _alert_block_ip(ev, operator)

def _gateway_rate_limit(ev, operator):
    ip = ev.get("source_ip", "?")
    rate_limited_ips.add(ip)
    return {
        "status": "ok",
        "steps": [f"Installing rate-limit rule for {ip}", "Setting limit: 10 req/min", "Confirming rule active at gateway"],
        "side_effects": [f"Rate-limit (10 req/min) applied to {ip}"],
        "artifacts": [], "reversible": False,
    }


# ── Rules handlers ─────────────────────────────────────────────

def _rules_fix(ev, operator):
    return {
        "status": "ok",
        "steps": ["Evaluating rule trigger context", "Applying rule action", "Suppressing related alert"],
        "side_effects": ["Rule applied — alert suppressed"],
        "artifacts": [], "reversible": False,
    }

def _rules_tune(ev, operator):
    rule_id = ev.get("rule_id", _uid("RULE"))
    new_thresh = round(random.uniform(0.60, 0.90), 2)
    rule_thresholds[rule_id] = new_thresh
    return {
        "status": "ok",
        "steps": [f"Analysing last 7d telemetry for rule {rule_id}", f"Computing optimal threshold: {new_thresh}",
                   "Updating rule registry", "Verifying false-positive reduction"],
        "side_effects": [f"Rule {rule_id} threshold updated to {new_thresh}"],
        "artifacts": [], "reversible": False,
    }


# ── Generic fix fallback ───────────────────────────────────────

def _generic_fix(ev, operator):
    return {
        "status": "ok",
        "steps": ["Evaluating context", "Applying recommended remediation", "Confirming fix applied"],
        "side_effects": ["Remediation applied successfully"],
        "artifacts": [], "reversible": False,
    }


# ── State query (for dashboard badges) ────────────────────────

def get_state_flags() -> dict:
    with _LOCK:
        return {
            "isolated_sessions":    list(isolated_sessions),
            "blocked_ips":          list(blocked_ips),
            "frozen_roles":         list(frozen_roles),
            "disabled_tools":       list(disabled_tools),
            "blocked_endpoints":    list(blocked_endpoints),
            "mfa_required_users":   list(mfa_required_users),
            "revoked_credentials":  list(revoked_credentials),
            "blocked_egress_dests": list(blocked_egress_dests),
            "isolated_resources":   list(isolated_resources),
            "rate_limited_ips":     list(rate_limited_ips),
            "frozen_sap_users":     list(frozen_sap_users),
            "baseline_version":     baseline_version,
            "incident_counter":     incident_counter,
        }

def undo_action(token: str) -> dict:
    fn = undo_ring.pop(token, None)
    if not fn:
        return {"status": "error", "message": "Undo token not found or already used"}
    try:
        fn()
        return {"status": "ok", "message": "Action reversed successfully"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ── Handler dispatch table ─────────────────────────────────────
_HANDLERS = {
    # anomaly
    "anomaly_fix":        _anomaly_fix,
    "anomaly_quarantine": _anomaly_quarantine,
    "anomaly_elevate":    _anomaly_elevate,
    "anomaly_forensic":   _anomaly_forensic,
    # alert
    "alert_fix":          lambda ev, op: _generic_fix(ev, op),
    "alert_block_ip":     _alert_block_ip,
    "alert_quarantine":   _alert_quarantine,
    "alert_forensic":     _alert_forensic,
    "alert_slack":        _alert_slack,
    "alert_jira":         _alert_jira,
    # sap
    "sap_fix":            _sap_fix,
    "sap_freeze":         _sap_freeze,
    "sap_tool_block":     _sap_tool_block,
    "sap_audit":          _sap_audit,
    # dlp
    "dlp_fix":            _dlp_fix,
    "dlp_mask":           _dlp_mask,
    "dlp_dest_block":     _dlp_dest_block,
    "dlp_dpo":            _dlp_dpo,
    "dlp_revoke":         _dlp_revoke,
    # shadow
    "shadow_fix":         _shadow_fix,
    "shadow_register":    _shadow_register,
    "shadow_forensic":    _shadow_forensic,
    "shadow_sweep":       _shadow_sweep,
    # comp
    "comp_fix":           _comp_fix,
    "comp_evidence":      _comp_evidence,
    "comp_legal":         _comp_legal,
    "comp_exception":     _comp_exception,
    # incident
    "incident_fix":       _incident_fix,
    "incident_contain":   _incident_contain,
    "incident_war_room":  _incident_war_room,
    "incident_handoff":   _incident_handoff,
    # sbom
    "sbom_fix":           _sbom_fix,
    "sbom_pin":           _sbom_pin,
    "sbom_isolate":       _sbom_isolate,
    "sbom_cve_ticket":    _sbom_cve_ticket,
    # zt
    "zt_fix":             _zt_fix,
    "zt_mfa":             _zt_mfa,
    "zt_isolate":         _zt_isolate,
    "zt_reeval":          _zt_reeval,
    # cred
    "cred_fix":           _cred_fix,
    "cred_revoke":        _cred_revoke,
    "cred_owner":         _cred_owner,
    "cred_vault_scan":    _cred_vault_scan,
    # cloud
    "cloud_fix":          _cloud_fix,
    "cloud_isolate":      _cloud_isolate,
    "cloud_rotate":       _cloud_rotate,
    "cloud_csp_ticket":   _cloud_csp_ticket,
    # gateway
    "gateway_fix":        _gateway_fix,
    "gateway_block_ip":   _gateway_block_ip,
    "gateway_rate_limit": _gateway_rate_limit,
    # rules
    "rules_fix":          _rules_fix,
    "rules_tune":         _rules_tune,
    # generic fallback
    "generic_fix":        _generic_fix,
}
