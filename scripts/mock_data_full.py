"""
IntegriShield — Full Mock Data Injector
Populates ALL 12 Redis streams with rich, realistic data across 3 phases.

Phase 1 — Baseline (normal traffic, low severity)
Phase 2 — Escalation (anomalies emerge, DLP hits, shadow endpoints found)
Phase 3 — Full Attack (critical incidents, compliance violations, cloud breach)

Usage:
  python scripts/mock_data_full.py                     # all 3 phases
  python scripts/mock_data_full.py --phase 1           # single phase
  python scripts/mock_data_full.py --speed fast        # 50ms delay
  python scripts/mock_data_full.py --speed instant     # no delay
  REDIS_URL=redis://localhost:6379 python scripts/mock_data_full.py
"""

import argparse
import json
import random
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import redis

REDIS_URL = "redis://localhost:6379"

# Stream keys (must match server.py STREAM_KEYS)
STREAMS = {
    "api_calls":     "integrishield:api_call_events",
    "anomalies":     "integrishield:anomaly_scores",
    "sap_mcp":       "integrishield:mcp_query_events",
    "zero_trust":    "integrishield:zero_trust_events",
    "credentials":   "integrishield:credential_events",
    "compliance":    "integrishield:compliance_alerts",
    "dlp":           "integrishield:dlp_alerts",
    "incidents":     "integrishield:incident_events",
    "shadow":        "integrishield:shadow_alerts",
    "sbom":          "integrishield:sbom_scan_events",
    "cloud_posture": "integrishield:cloud_posture_events",
    "alerts":        "integrishield:alert_events",
}

# ── Helpers ──────────────────────────────────────────────────────────────────

def now_iso(offset_minutes=0):
    t = datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)
    return t.isoformat()

def offhours_iso():
    t = datetime.now(timezone.utc).replace(hour=2, minute=random.randint(0,59), second=random.randint(0,59))
    return t.isoformat()

def uid(): return str(uuid4())

def pick(lst): return random.choice(lst)

USERS       = ["USR001","USR002","USR003","USR007","USR013","SVCACCT","ADMIN","jsmith","agarwal","lchen","mrodriguez"]
PRIV_USERS  = ["ROOT","SYSADMIN","SEC_ADMIN","BATCHJOB","INT_USER"]
IPS_INTERNAL= [f"10.42.{random.randint(0,5)}.{random.randint(2,245)}" for _ in range(20)]
IPS_EXTERNAL= [f"185.{random.randint(100,200)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10)]
RFC_NORMAL  = ["BAPI_CUSTOMER_GETLIST","BAPI_MATERIAL_GETLIST","RFC_GET_LOCAL_DESTINATIONS",
               "BAPI_USER_GET_DETAIL","BAPI_SALESORDER_GETLIST","RFC_SYSTEM_INFO"]
RFC_RISKY   = ["RFC_READ_TABLE","BAPI_USER_GETLIST","SUSR_USER_AUTH_FOR_OBJ_GET"]
RFC_SHADOW  = ["ZRFC_EXFIL_DATA","ZTEST_BACKDOOR","Z_HIDDEN_EXTRACT","ZRFC_DUMP_PAYROLL"]
TENANTS     = ["PROD-001","PROD-002","DEV-001","STAGING-001"]
PROVIDERS   = ["aws","gcp","azure"]
FRAMEWORKS  = ["SOX","GDPR","ISO27001","PCI-DSS","NIST-CSF","HIPAA"]
SAP_TOOLS   = ["read_table","execute_bapi","get_system_info","list_users","get_auth_objects",
               "run_report","change_user_auth","delete_table_entries","export_payroll_data"]
RESOURCES   = ["arn:aws:s3:::prod-payroll-data","projects/prod/instances/db-main",
               "subscriptions/xxx/resourceGroups/prod/Microsoft.Compute/virtualMachines/app01",
               "arn:aws:iam:::role/AdminRole","arn:aws:rds:::db:prod-hr-db"]
CONTROLS    = ["AC-2","AC-6","AU-2","IA-2","SC-7","SI-3","CM-2","RA-5","SA-9","IR-4"]

# ── Stream event factories ────────────────────────────────────────────────────

def api_call_normal():
    return {
        "event_id":      uid(),
        "source_ip":     pick(IPS_INTERNAL),
        "user_id":       pick(USERS),
        "rfc_function":  pick(RFC_NORMAL),
        "bytes_out":     str(random.randint(200, 8000)),
        "row_count":     str(random.randint(1, 500)),
        "off_hours":     "false",
        "unknown_endpoint": "false",
        "response_time_ms": str(random.randint(80, 600)),
        "sap_system":    "PRD",
        "timestamp_utc": now_iso(),
    }

def api_call_bulk():
    return {
        "event_id":      uid(),
        "source_ip":     pick(IPS_INTERNAL),
        "user_id":       pick(USERS),
        "rfc_function":  "RFC_READ_TABLE",
        "bytes_out":     str(random.randint(12_000_000, 28_000_000)),
        "row_count":     str(random.randint(50_000, 120_000)),
        "off_hours":     "false",
        "unknown_endpoint": "false",
        "response_time_ms": str(random.randint(8000, 25000)),
        "sap_system":    "PRD",
        "timestamp_utc": now_iso(),
    }

def api_call_offhours():
    return {
        "event_id":      uid(),
        "source_ip":     pick(IPS_INTERNAL + IPS_EXTERNAL),
        "user_id":       pick(PRIV_USERS),
        "rfc_function":  pick(RFC_RISKY),
        "bytes_out":     str(random.randint(1000, 50000)),
        "row_count":     str(random.randint(100, 5000)),
        "off_hours":     "true",
        "unknown_endpoint": "false",
        "response_time_ms": str(random.randint(200, 3000)),
        "sap_system":    "PRD",
        "timestamp_utc": offhours_iso(),
    }

def api_call_shadow():
    return {
        "event_id":      uid(),
        "source_ip":     pick(IPS_EXTERNAL),
        "user_id":       pick(PRIV_USERS),
        "rfc_function":  pick(RFC_SHADOW),
        "bytes_out":     str(random.randint(500_000, 5_000_000)),
        "row_count":     str(random.randint(1000, 80000)),
        "off_hours":     "true",
        "unknown_endpoint": "true",
        "response_time_ms": str(random.randint(300, 2000)),
        "sap_system":    "PRD",
        "timestamp_utc": now_iso(),
    }

def anomaly_event(score=None, classification=None):
    s = score or round(random.uniform(0.3, 0.99), 3)
    c = classification or pick(["velocity_spike","new_endpoint","off_hours_pattern",
                                 "geo_anomaly","baseline_deviation","privilege_escalation"])
    return {
        "event_id":          uid(),
        "anomaly_score":     str(s),
        "classification":    c,
        "baseline_deviation":str(round(random.uniform(1.5, 8.0), 2)),
        "source_ip":         pick(IPS_INTERNAL + IPS_EXTERNAL),
        "user_id":           pick(USERS + PRIV_USERS),
        "endpoint":          pick(RFC_NORMAL + RFC_RISKY + RFC_SHADOW),
        "model_version":     "isolation_forest_v1",
        "timestamp_utc":     now_iso(),
        "ts":                now_iso(),
    }

def sap_mcp_event(tool=None, anomalous=False):
    t = tool or pick(SAP_TOOLS)
    return {
        "event_id":   uid(),
        "tool_name":  t,
        "session_id": f"sess-{uid()[:8]}",
        "tenant_id":  pick(TENANTS),
        "user_id":    pick(USERS + PRIV_USERS),
        "result":     "error" if anomalous else pick(["success","success","success","partial"]),
        "status":     "anomalous" if anomalous else "ok",
        "anomalous":  "true" if anomalous else "false",
        "flagged":    "true" if anomalous else "false",
        "latency_ms": str(random.randint(10, 800)),
        "timestamp_utc": now_iso(),
        "ts":         now_iso(),
    }

def zero_trust_event(decision=None):
    d = decision or pick(["allow","allow","allow","deny","challenge"])
    risk = round(random.uniform(0.1, 0.4) if d == "allow" else random.uniform(0.5, 0.95), 2)
    failed = [] if d == "allow" else random.sample(
        ["mfa_required","device_compliant","geo_risk","time_risk","behaviour_risk"], k=random.randint(1,3))
    return {
        "event_id":       uid(),
        "decision":       d,
        "risk_score":     str(risk),
        "user_id":        pick(USERS + PRIV_USERS),
        "source_ip":      pick(IPS_INTERNAL + IPS_EXTERNAL),
        "failed_controls": json.dumps(failed),
        "device_id":      f"dev-{uid()[:8]}",
        "timestamp_utc":  now_iso(),
        "ts":             now_iso(),
    }

def credential_event(action=None):
    a = action or pick(["issued","issued","rotated","rotated","revoked","accessed"])
    return {
        "event_id":   uid(),
        "action":     a,
        "key":        f"key-{uid()[:12]}",
        "tenant_id":  pick(TENANTS),
        "status":     "ok" if a != "revoked" else "revoked",
        "algorithm":  pick(["RSA-4096","EC-P256","AES-256-GCM"]),
        "ttl_days":   str(random.randint(1, 90)),
        "timestamp_utc": now_iso(),
        "ts":         now_iso(),
    }

def compliance_event(result=None):
    r = result or pick(["pass","pass","pass","warning","violation"])
    fw = pick(FRAMEWORKS)
    ctrl = pick(CONTROLS)
    return {
        "event_id":    uid(),
        "framework":   fw,
        "control_id":  ctrl,
        "result":      r,
        "status":      r,
        "description": f"{fw} control {ctrl} — {'passed' if r=='pass' else r}",
        "evidence_ref":f"EVD-{uid()[:8]}",
        "actor":       pick(USERS),
        "severity":    "critical" if r=="violation" else ("medium" if r=="warning" else "low"),
        "timestamp_utc": now_iso(),
        "ts":          now_iso(),
    }

def dlp_event(rule=None, severity=None):
    r = rule or pick(["bulk_export_detected","staging_area_write","blocklist_destination",
                       "large_file_transfer","pii_exfiltration","mass_download"])
    s = severity or pick(["critical","critical","high","high","medium"])
    return {
        "event_id":    uid(),
        "rule":        r,
        "scenario":    r,
        "severity":    s,
        "bytes_out":   str(random.randint(1_000_000, 500_000_000)),
        "row_count":   str(random.randint(1000, 200_000)),
        "user_id":     pick(USERS + PRIV_USERS),
        "destination": pick(["10.9.0.5","192.168.50.100","45.77.200.1","dropbox.com","mega.nz"]),
        "message":     f"DLP policy triggered: {r.replace('_',' ').upper()}",
        "timestamp_utc": now_iso(),
        "ts":          now_iso(),
    }

_inc_counter = [0]
def incident_event(status=None, severity=None):
    _inc_counter[0] += 1
    s = status or pick(["open","open","investigating","investigating","resolved"])
    sev = severity or pick(["critical","high","high","medium"])
    pid = pick(["PB-RANSOMWARE","PB-DATA-EXFIL","PB-PRIV-ESC","PB-ACCOUNT-TAKEOVER","PB-SHADOW-API"])
    return {
        "event_id":     uid(),
        "incident_id":  f"INC-{1000 + _inc_counter[0]:04d}",
        "title":        pick(["Bulk data exfiltration detected","Off-hours privileged access",
                               "Shadow RFC endpoint invoked","Anomalous SAP query pattern",
                               "Credential rotation overdue","Cloud misconfiguration exploited",
                               "Zero-trust policy violated","Compliance control failed"]),
        "status":       s,
        "state":        s,
        "severity":     sev,
        "source_module":pick(["m01-api-gateway-shield","m08-anomaly-detection","m09-dlp",
                               "m11-shadow-integration","m04-zero-trust-fabric"]),
        "playbook_id":  pid,
        "playbook_run": "true" if s == "investigating" else "false",
        "action":       pick(["created","escalated","contained","assigned","resolved"]),
        "timestamp_utc":now_iso(),
        "ts":           now_iso(),
    }

def shadow_event():
    fn = pick(RFC_SHADOW)
    return {
        "event_id":   uid(),
        "endpoint":   fn,
        "rfc_function": fn,
        "severity":   pick(["critical","critical","high"]),
        "user_id":    pick(PRIV_USERS),
        "source_ip":  pick(IPS_EXTERNAL),
        "message":    f"Unknown RFC function {fn} called from external IP",
        "first_seen": now_iso(offset_minutes=-random.randint(5, 1440)),
        "call_count": str(random.randint(1, 50)),
        "timestamp_utc": now_iso(),
        "ts":         now_iso(),
    }

_sbom_targets = ["m01-api-gateway-shield","m05-sap-mcp-suite","m07-compliance-autopilot",
                  "shared-libs","redis-client","fastapi","uvicorn","pydantic"]
def sbom_event(clean=False):
    cve = 0 if clean else random.randint(0, 15)
    ins = 0 if clean else random.randint(0, 5)
    return {
        "event_id":           uid(),
        "target":             pick(_sbom_targets),
        "component":          pick(_sbom_targets),
        "scan_status":        "CLEAN" if (cve == 0 and ins == 0) else "VULNERABLE",
        "cve_count":          str(cve),
        "insecure_rfc_count": str(ins),
        "component_count":    str(random.randint(10, 200)),
        "sbom_format":        pick(["CycloneDX","SPDX"]),
        "scan_id":            f"SCAN-{uid()[:8]}",
        "scanner_version":    "grype-0.74.0",
        "timestamp_utc":      now_iso(),
        "ts":                 now_iso(),
    }

def cloud_event(severity=None):
    s = severity or pick(["critical","high","high","medium","medium","low"])
    return {
        "event_id":     uid(),
        "provider":     pick(PROVIDERS),
        "resource_id":  pick(RESOURCES),
        "control_id":   f"CIS-{random.randint(1,9)}.{random.randint(1,20)}",
        "raw_severity": s,
        "severity":     s,
        "risk_score":   str(round(random.uniform(0.3, 0.99), 2)),
        "region":       pick(["us-east-1","us-west-2","eu-west-1","ap-southeast-1","eastus","us-central1"]),
        "finding_type": pick(["PUBLIC_BUCKET","UNENCRYPTED_DB","OVERPRIVILEGED_ROLE",
                               "OPEN_SECURITY_GROUP","MFA_DISABLED","LOGGING_DISABLED",
                               "ROOT_ACCESS_USED","INSECURE_TLS"]),
        "remediation":  pick(["Enable encryption","Restrict IAM policy","Enable MFA",
                               "Close port 0.0.0.0/0","Enable CloudTrail","Rotate credentials"]),
        "timestamp_utc": now_iso(),
        "ts":           now_iso(),
    }

def alert_event(scenario=None, severity=None):
    sc = scenario or pick(["bulk_extraction","off_hours_rfc","shadow_endpoint",
                            "velocity_anomaly","credential_abuse","privilege_escalation",
                            "data_staging","geo_anomaly"])
    sv = severity or pick(["critical","high","high","medium","medium","low"])
    return {
        "event_id":   uid(),
        "scenario":   sc,
        "severity":   sv,
        "source_ip":  pick(IPS_INTERNAL + IPS_EXTERNAL),
        "user_id":    pick(USERS + PRIV_USERS),
        "message":    f"{sc.replace('_',' ').upper()} detected from {pick(IPS_EXTERNAL)}",
        "latencyMs":  str(random.randint(5, 80)),
        "endpoint":   pick(RFC_NORMAL + RFC_RISKY + RFC_SHADOW),
        "timestamp_utc": now_iso(),
        "ts":         now_iso(),
    }


# ── Phase definitions ─────────────────────────────────────────────────────────

PHASES = {
    1: {
        "name": "Phase 1 — Baseline (Normal Operations)",
        "color": "\033[92m",  # green
        "events": [
            # Healthy traffic across all streams
            *[(STREAMS["api_calls"],    api_call_normal)       for _ in range(18)],
            *[(STREAMS["anomalies"],    lambda: anomaly_event(score=round(random.uniform(0.05,0.25),3))) for _ in range(6)],
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event(anomalous=False)) for _ in range(8)],
            *[(STREAMS["zero_trust"],   lambda: zero_trust_event("allow"))  for _ in range(10)],
            *[(STREAMS["credentials"],  lambda: credential_event("issued"))  for _ in range(5)],
            *[(STREAMS["credentials"],  lambda: credential_event("rotated")) for _ in range(4)],
            *[(STREAMS["compliance"],   lambda: compliance_event("pass"))    for _ in range(8)],
            *[(STREAMS["sbom"],         lambda: sbom_event(clean=True))      for _ in range(4)],
            *[(STREAMS["sbom"],         lambda: sbom_event(clean=False))     for _ in range(2)],
            *[(STREAMS["cloud_posture"],lambda: cloud_event("low"))          for _ in range(5)],
            *[(STREAMS["cloud_posture"],lambda: cloud_event("medium"))       for _ in range(3)],
            *[(STREAMS["alerts"],       lambda: alert_event("off_hours_rfc","low")) for _ in range(2)],
        ],
    },
    2: {
        "name": "Phase 2 — Escalation (Anomalies & Threats Emerging)",
        "color": "\033[93m",  # yellow
        "events": [
            # API calls escalate
            *[(STREAMS["api_calls"],    api_call_normal)        for _ in range(8)],
            *[(STREAMS["api_calls"],    api_call_offhours)      for _ in range(6)],
            *[(STREAMS["api_calls"],    api_call_bulk)          for _ in range(4)],
            # Anomaly scores spike
            *[(STREAMS["anomalies"],    lambda: anomaly_event(score=round(random.uniform(0.5,0.75),3), classification="velocity_spike")) for _ in range(5)],
            *[(STREAMS["anomalies"],    lambda: anomaly_event(score=round(random.uniform(0.7,0.9),3),  classification="new_endpoint"))   for _ in range(4)],
            # SAP MCP — suspicious tools
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event("list_users", anomalous=False))     for _ in range(4)],
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event("get_auth_objects", anomalous=True)) for _ in range(3)],
            # Zero-trust challenges and denies
            *[(STREAMS["zero_trust"],   lambda: zero_trust_event("challenge")) for _ in range(5)],
            *[(STREAMS["zero_trust"],   lambda: zero_trust_event("deny"))      for _ in range(3)],
            # First DLP hits
            *[(STREAMS["dlp"],          lambda: dlp_event("bulk_export_detected","high"))    for _ in range(3)],
            *[(STREAMS["dlp"],          lambda: dlp_event("staging_area_write","high"))      for _ in range(2)],
            # Shadow endpoints spotted
            *[(STREAMS["shadow"],       shadow_event) for _ in range(4)],
            # Compliance warnings
            *[(STREAMS["compliance"],   lambda: compliance_event("warning"))   for _ in range(5)],
            *[(STREAMS["compliance"],   lambda: compliance_event("pass"))      for _ in range(3)],
            # Incidents open
            *[(STREAMS["incidents"],    lambda: incident_event("open","high"))          for _ in range(3)],
            *[(STREAMS["incidents"],    lambda: incident_event("investigating","high")) for _ in range(2)],
            # Cloud posture issues
            *[(STREAMS["cloud_posture"],lambda: cloud_event("high"))     for _ in range(4)],
            *[(STREAMS["cloud_posture"],lambda: cloud_event("critical")) for _ in range(2)],
            # Credential rotations triggered
            *[(STREAMS["credentials"],  lambda: credential_event("rotated")) for _ in range(4)],
            *[(STREAMS["credentials"],  lambda: credential_event("revoked"))  for _ in range(2)],
            # SBOM - some CVEs found
            *[(STREAMS["sbom"],         lambda: sbom_event(clean=False)) for _ in range(4)],
            # Alerts feed
            *[(STREAMS["alerts"],       lambda: alert_event("bulk_extraction","high"))     for _ in range(3)],
            *[(STREAMS["alerts"],       lambda: alert_event("velocity_anomaly","high"))    for _ in range(3)],
            *[(STREAMS["alerts"],       lambda: alert_event("off_hours_rfc","medium"))     for _ in range(4)],
        ],
    },
    3: {
        "name": "Phase 3 — Full Attack (Critical Incidents & Breach)",
        "color": "\033[91m",  # red
        "events": [
            # API — full shadow + bulk
            *[(STREAMS["api_calls"],    api_call_shadow)        for _ in range(8)],
            *[(STREAMS["api_calls"],    api_call_bulk)          for _ in range(6)],
            *[(STREAMS["api_calls"],    api_call_offhours)      for _ in range(5)],
            # Anomaly — critical scores
            *[(STREAMS["anomalies"],    lambda: anomaly_event(score=round(random.uniform(0.88,0.99),3), classification="privilege_escalation")) for _ in range(6)],
            *[(STREAMS["anomalies"],    lambda: anomaly_event(score=round(random.uniform(0.80,0.95),3), classification="geo_anomaly"))           for _ in range(4)],
            # SAP MCP — exfil tools
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event("export_payroll_data", anomalous=True))  for _ in range(4)],
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event("delete_table_entries", anomalous=True)) for _ in range(3)],
            *[(STREAMS["sap_mcp"],      lambda: sap_mcp_event("change_user_auth", anomalous=True))     for _ in range(3)],
            # Zero-trust — mass denies
            *[(STREAMS["zero_trust"],   lambda: zero_trust_event("deny"))    for _ in range(8)],
            *[(STREAMS["zero_trust"],   lambda: zero_trust_event("challenge")) for _ in range(4)],
            # DLP — critical exfil
            *[(STREAMS["dlp"],          lambda: dlp_event("pii_exfiltration","critical"))       for _ in range(4)],
            *[(STREAMS["dlp"],          lambda: dlp_event("mass_download","critical"))           for _ in range(3)],
            *[(STREAMS["dlp"],          lambda: dlp_event("blocklist_destination","critical"))   for _ in range(3)],
            # Shadow endpoints — multiple new
            *[(STREAMS["shadow"],       shadow_event) for _ in range(6)],
            # Compliance violations
            *[(STREAMS["compliance"],   lambda: compliance_event("violation")) for _ in range(6)],
            *[(STREAMS["compliance"],   lambda: compliance_event("warning"))   for _ in range(4)],
            # Critical incidents
            *[(STREAMS["incidents"],    lambda: incident_event("open","critical"))          for _ in range(4)],
            *[(STREAMS["incidents"],    lambda: incident_event("investigating","critical")) for _ in range(4)],
            *[(STREAMS["incidents"],    lambda: incident_event("resolved","high"))          for _ in range(2)],
            # Cloud breach
            *[(STREAMS["cloud_posture"],lambda: cloud_event("critical")) for _ in range(6)],
            *[(STREAMS["cloud_posture"],lambda: cloud_event("high"))     for _ in range(4)],
            # Credential breach
            *[(STREAMS["credentials"],  lambda: credential_event("revoked")) for _ in range(5)],
            *[(STREAMS["credentials"],  lambda: credential_event("rotated")) for _ in range(3)],
            # SBOM — critical CVEs
            *[(STREAMS["sbom"],         lambda: sbom_event(clean=False)) for _ in range(5)],
            # Alerts — full cascade
            *[(STREAMS["alerts"],       lambda: alert_event("shadow_endpoint","critical"))       for _ in range(5)],
            *[(STREAMS["alerts"],       lambda: alert_event("credential_abuse","critical"))      for _ in range(4)],
            *[(STREAMS["alerts"],       lambda: alert_event("privilege_escalation","critical"))  for _ in range(4)],
            *[(STREAMS["alerts"],       lambda: alert_event("bulk_extraction","critical"))       for _ in range(3)],
            *[(STREAMS["alerts"],       lambda: alert_event("geo_anomaly","high"))               for _ in range(3)],
            *[(STREAMS["alerts"],       lambda: alert_event("data_staging","high"))              for _ in range(3)],
        ],
    },
}


# ── Runner ────────────────────────────────────────────────────────────────────

def inject_phase(r: redis.Redis, phase_num: int, delay: float):
    phase = PHASES[phase_num]
    events = phase["events"]
    random.shuffle(events)  # mix streams naturally
    color = phase["color"]
    reset = "\033[0m"

    print(f"\n{color}{'═'*60}{reset}")
    print(f"{color}  {phase['name']}{reset}")
    print(f"{color}  {len(events)} events across {len(STREAMS)} streams{reset}")
    print(f"{color}{'═'*60}{reset}\n")

    stream_counts = {}
    for stream_key, factory in events:
        event = factory()
        # Redis XADD requires string values
        str_event = {k: str(v) for k, v in event.items()}
        r.xadd(stream_key, str_event, maxlen=5000, approximate=True)

        name = next((n for n,k in STREAMS.items() if k == stream_key), stream_key)
        stream_counts[name] = stream_counts.get(name, 0) + 1
        sev = event.get("severity", event.get("raw_severity", ""))
        sev_color = "\033[91m" if sev == "critical" else "\033[93m" if sev == "high" else "\033[97m"
        print(f"  {sev_color}→ {name:<16}{reset} {event.get('scenario', event.get('tool_name', event.get('decision', event.get('action', event.get('scan_status', event.get('classification', '')))))):<28} {sev_color}{sev}{reset}")
        if delay > 0:
            time.sleep(delay)

    print(f"\n  Stream counts:")
    for n, c in sorted(stream_counts.items()):
        print(f"    {n:<20} +{c}")


def main():
    parser = argparse.ArgumentParser(description="IntegriShield full mock data injector")
    parser.add_argument("--phase",  type=int, choices=[1,2,3], default=None, help="Run single phase (default: all)")
    parser.add_argument("--speed",  choices=["slow","normal","fast","instant"], default="normal")
    parser.add_argument("--redis",  default=REDIS_URL)
    parser.add_argument("--flush",  action="store_true", help="Flush all streams before injecting")
    args = parser.parse_args()

    delay_map = {"slow": 0.3, "normal": 0.08, "fast": 0.02, "instant": 0.0}
    delay = delay_map[args.speed]

    r = redis.Redis.from_url(args.redis, decode_responses=True)
    try:
        r.ping()
        print(f"\033[92m✓ Redis connected: {args.redis}\033[0m")
    except Exception as e:
        print(f"\033[91m✗ Redis connection failed: {e}\033[0m")
        print("  Start Redis: redis-server --daemonize yes")
        return

    if args.flush:
        print("\033[93mFlushing existing stream data…\033[0m")
        for key in STREAMS.values():
            r.delete(key)
        print("  Done.\n")

    phases_to_run = [args.phase] if args.phase else [1, 2, 3]

    total_start = time.time()
    for p in phases_to_run:
        inject_phase(r, p, delay)
        if p < max(phases_to_run):
            print(f"\n  \033[90mPausing 1s between phases…\033[0m")
            time.sleep(1)

    elapsed = time.time() - total_start
    total = sum(len(PHASES[p]["events"]) for p in phases_to_run)
    print(f"\n\033[92m{'═'*60}")
    print(f"  ✓ Done — {total} events injected in {elapsed:.1f}s")
    print(f"  Dashboard: http://localhost:5173")
    print(f"{'═'*60}\033[0m\n")


if __name__ == "__main__":
    main()
