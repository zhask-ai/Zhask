"""Synthetic event generator for IntegriShield POC demo.

Publishes realistic events to every module's Redis Stream on a short cadence so
the dashboard renders live data for all 15 modules without requiring every
underlying module container to be running. Also exposes replay_scenario() so the
dashboard can trigger a correlated burst across modules on demand.
"""

from __future__ import annotations

import json
import random
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import redis

MAX_STREAM_LEN = 10_000

SAP_USERS   = ["ROOT", "SEC_ADMIN", "SYSADMIN", "BATCHJOB", "SVC_INTEGRATION",
               "JDOE", "ASMITH", "MCURIE", "OLD_ADMIN", "SVC_LEGACY"]
SAP_IPS     = ["10.0.12.34", "10.0.5.117", "192.168.4.22", "172.20.9.8",
               "203.0.113.55", "198.51.100.21"]
RFC_MODULES = ["RFC_READ_TABLE", "BAPI_USER_GET_DETAIL", "SE16N_RFC_DATA",
               "BAPI_SALESORDER_GETLIST", "RFC_PING", "RH_STRUC_GET"]
TABLES      = ["PA0008", "USR02", "BSEG", "BKPF", "KNA1", "VBAK", "LFA1"]

FRAMEWORKS = ["SOC2", "ISO27001", "GDPR", "DORA", "NIS2", "PCI-DSS", "HIPAA"]
CTRL_IDS   = {"SOC2": "CC6.1", "ISO27001": "A.9.2.3", "GDPR": "Art.32",
              "DORA": "Art.9", "NIS2": "Art.21", "PCI-DSS": "10.2.1", "HIPAA": "164.312"}

CLOUDS      = ["aws", "azure", "gcp", "sap_btp"]
CLOUD_FINDS = [
    ("open_s3_bucket", "S3 bucket world-readable", "critical"),
    ("excessive_iam", "IAM role has wildcard permissions", "high"),
    ("public_endpoint", "RDS instance reachable from internet", "critical"),
    ("unencrypted_volume", "EBS volume without encryption", "medium"),
    ("stale_access_key", "Access key not rotated in 180d", "high"),
    ("public_storage_container", "Azure blob container anonymous read", "critical"),
    ("firewall_any_any", "NSG allows 0.0.0.0/0 on 3389", "critical"),
]

CONNECTORS = [
    ("SAP BTP - Payroll", "sap_btp",   "healthy"),
    ("MuleSoft - CRM Sync", "mulesoft", "misconfigured"),
    ("Boomi - Vendor Feed", "boomi",    "alert"),
    ("Workato - HR Automation", "workato", "healthy"),
    ("SAP BTP - Finance", "sap_btp",  "healthy"),
    ("MuleSoft - Legacy AS400", "mulesoft", "alert"),
]

WEBHOOK_SOURCES = ["github", "slack", "pagerduty", "stripe", "sap-btp", "custom"]

SBOM_COMPONENTS = [
    ("mulesoft-connector-sap", "4.2.1", "CVE-2024-21683", 9.1, "critical", "4.3.0"),
    ("pyrfc",                  "2.8.0", "CVE-2023-27561", 7.5, "high",     "2.8.5"),
    ("requests",               "2.28.1","CVE-2023-32681", 6.1, "medium",   "2.31.0"),
    ("log4j-core",             "2.14.1","CVE-2021-44228", 10.0,"critical", "2.17.1"),
    ("openssl",                "1.1.1k","CVE-2022-0778",  7.5, "high",     "1.1.1n"),
    ("fastapi",                "0.95.0","CVE-2024-24762", 7.5, "high",     "0.109.1"),
]

CREDENTIAL_POOL = [
    ("api_key",  "INT-PROD-KEY-001", "svc_integration", 245, 2),
    ("oauth",    "OKTA-OAUTH-789",   "sso_connector",   12,  0),
    ("rfc_password", "SAP_RFC_USER", "rfc-bridge",     410, 38),
    ("cert",     "mtls-cert-btp",    "btp-connector",   95, 5),
    ("api_key",  "STRIPE-LIVE",      "billing",         14, 1),
    ("rfc_password", "BATCH_RFC",    "batch-jobs",     720, 120),
]

ZT_POLICIES = [
    ("allow_business_hours", "ALLOW"),
    ("require_mfa_sensitive", "MASK"),
    ("deny_off_hours_bulk", "BLOCK"),
    ("allow_service_accounts", "ALLOW"),
    ("deny_unknown_endpoint", "BLOCK"),
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _serialise(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)


class DemoGenerator:
    """Publishes synthetic security events to all module Redis streams."""

    def __init__(self, redis_url: str, streams: dict):
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.streams = streams
        self.stop_flag = threading.Event()

    def publish(self, stream_name: str, payload: dict) -> None:
        stream = self.streams.get(stream_name)
        if not stream:
            return
        payload.setdefault("timestamp_utc", _now())
        serialised = {k: _serialise(v) for k, v in payload.items()}
        try:
            self.redis.xadd(stream, serialised, maxlen=MAX_STREAM_LEN, approximate=True)
        except Exception:
            pass

    # ── Individual event builders ──────────────────────────────

    def _api_call(self, scenario: str | None = None) -> dict:
        user = random.choice(SAP_USERS)
        ip   = random.choice(SAP_IPS)
        fn   = random.choice(RFC_MODULES)
        table = random.choice(TABLES)
        off_hours = scenario == "off_hours" or (random.random() < 0.15)
        unknown   = scenario == "shadow" or (random.random() < 0.07)
        bulk      = scenario == "bulk"   or (random.random() < 0.08)
        rows      = random.randint(50_000, 250_000) if bulk else random.randint(10, 500)
        return {
            "event_id":           str(uuid.uuid4()),
            "user_id":            user,
            "source_ip":          ip,
            "function_module":    fn,
            "table":              table,
            "row_count":          rows,
            "bytes_out":          rows * random.randint(200, 1200),
            "off_hours":          off_hours,
            "unknown_endpoint":   unknown,
            "endpoint":           f"/sap/bc/rfc/{fn}" + ("/X9Z" if unknown else ""),
            "scenario":           scenario or ("bulk-extraction" if bulk else
                                               "off-hours-rfc"   if off_hours else
                                               "shadow-endpoint" if unknown else "normal"),
            "severity":           "critical" if (bulk or unknown) else "medium" if off_hours else "low",
        }

    def _alert_from(self, api: dict) -> dict:
        sev = api["severity"]
        msg_map = {
            "bulk-extraction": f"Bulk extraction: {api['row_count']:,} rows from {api['table']} by {api['user_id']}",
            "off-hours-rfc":   f"Off-hours RFC call {api['function_module']} by {api['user_id']} from {api['source_ip']}",
            "shadow-endpoint": f"Shadow endpoint detected: {api['endpoint']} by {api['user_id']}",
            "normal":          f"Normal RFC call {api['function_module']} by {api['user_id']}",
        }
        return {
            "alertId":      str(uuid.uuid4()),
            "scenario":     api["scenario"],
            "severity":     sev,
            "user_id":      api["user_id"],
            "source_ip":    api["source_ip"],
            "endpoint":     api["endpoint"],
            "row_count":    api["row_count"],
            "bytes_out":    api["bytes_out"],
            "message":      msg_map.get(api["scenario"], msg_map["normal"]),
            "source_module":"m12-rules-engine",
            "latencyMs":    random.randint(12, 80),
        }

    def _anomaly(self, api: dict) -> dict:
        score = round(random.uniform(-0.95, -0.05), 3)
        return {
            "event_id":       api["event_id"],
            "user_id":        api["user_id"],
            "function_module": api["function_module"],
            "anomaly_score":  score,
            "anomalous":      score < -0.5,
            "severity":       "critical" if score < -0.7 else "medium" if score < -0.4 else "low",
            "features":       {"bytes": api["bytes_out"], "rows": api["row_count"]},
        }

    def _dlp(self, api: dict) -> dict:
        rules = ["BULK_EXTRACTION", "SENSITIVE_TABLE", "VELOCITY_ANOMALY", "PII_IN_PAYLOAD"]
        rule = "BULK_EXTRACTION" if api["row_count"] > 10_000 else random.choice(rules)
        return {
            "rule":       rule,
            "user_id":    api["user_id"],
            "table":      api["table"],
            "row_count":  api["row_count"],
            "severity":   "critical" if rule in ("BULK_EXTRACTION","SENSITIVE_TABLE") else "high",
            "action":     "block" if rule == "BULK_EXTRACTION" else "mask",
        }

    def _shadow(self, api: dict) -> dict:
        return {
            "endpoint":  api["endpoint"],
            "user_id":   api["user_id"],
            "source_ip": api["source_ip"],
            "severity":  "critical",
            "reason":    "endpoint not in registry baseline",
        }

    def _zero_trust(self, api: dict) -> dict:
        policy, decision = random.choice(ZT_POLICIES)
        if api["scenario"] in ("bulk-extraction","shadow-endpoint"):
            decision = "BLOCK"; policy = "deny_off_hours_bulk"
        elif api["scenario"] == "off-hours-rfc":
            decision = "MASK"; policy = "require_mfa_sensitive"
        return {
            "decision":       decision,
            "policy_matched": policy,
            "user_id":        api["user_id"],
            "endpoint":       api["endpoint"],
            "risk_score":     random.randint(20, 95),
            "mfa_required":   decision == "MASK",
        }

    def _credential(self) -> dict:
        ctype, cname, owner, age, days_since_use = random.choice(CREDENTIAL_POOL)
        actions = ["rotate_needed", "stale", "over_privileged", "rotated_ok", "accessed"]
        if age > 300: action = "rotate_needed"
        elif days_since_use > 90: action = "stale"
        else: action = random.choice(actions)
        return {
            "credential_id":  cname,
            "credential_type": ctype,
            "owner":          owner,
            "age_days":       age,
            "days_since_use": days_since_use,
            "action":         action,
            "severity":       "critical" if action == "rotate_needed" and age > 365 else
                              "high"     if action in ("rotate_needed","stale") else "low",
        }

    def _compliance(self, src_event: dict) -> dict:
        fw = random.choice(FRAMEWORKS)
        return {
            "framework":   fw,
            "control_id":  CTRL_IDS[fw],
            "status":      random.choice(["fail","pass","fail","pass","warn"]),
            "evidence":    src_event.get("scenario","event"),
            "user_id":     src_event.get("user_id",""),
            "severity":    src_event.get("severity","medium"),
            "message":     f"{fw} {CTRL_IDS[fw]} triggered by {src_event.get('scenario','event')}",
        }

    def _incident(self, alert: dict) -> dict:
        steps = ["quarantine","forensics","notify_soc","remediate","closed"]
        step = random.choice(steps[:4])
        return {
            "incident_id": f"INC-{random.randint(1000,9999)}",
            "status":      {"quarantine":"Investigating","forensics":"Investigating",
                            "notify_soc":"Contained","remediate":"Contained"}.get(step,"Open"),
            "step":        step,
            "severity":    alert.get("severity","high"),
            "user_id":     alert.get("user_id"),
            "scenario":    alert.get("scenario"),
            "message":     f"Playbook step: {step} for {alert.get('scenario','incident')}",
            "action":      step,
        }

    def _sap_mcp(self) -> dict:
        tools = ["query_events","get_anomaly_scores","list_alerts","get_user_roles",
                 "get_sod_violations","get_dormant_users","get_failed_logins",
                 "check_critical_auth","read_table","monitor_rfc_calls"]
        tool = random.choice(tools)
        return {
            "tool_name":   tool,
            "user_id":     random.choice(["claude-assistant","soc-analyst","auditor"]),
            "result":      "success",
            "latency_ms":  random.randint(40, 220),
            "rows_returned": random.randint(1, 50),
        }

    def _sbom(self) -> dict:
        comp, ver, cve, cvss, sev, fix = random.choice(SBOM_COMPONENTS)
        return {
            "component":    comp,
            "version":      ver,
            "cve_id":       cve,
            "cvss_score":   cvss,
            "severity":     sev,
            "fix_version":  fix,
            "scan_status":  "vulnerable",
        }

    def _cloud(self) -> dict:
        finding, desc, sev = random.choice(CLOUD_FINDS)
        return {
            "provider":    random.choice(CLOUDS),
            "finding":     finding,
            "description": desc,
            "severity":    sev,
            "resource":    f"arn:aws:s3:::integrishield-{random.randint(100,999)}",
        }

    def _connector(self) -> dict:
        name, platform, status = random.choice(CONNECTORS)
        issues = {
            "healthy":       None,
            "misconfigured": "TLS verification disabled on outbound endpoint",
            "alert":         "Credential leak detected in connector payload",
        }
        return {
            "connector":  name,
            "platform":   platform,
            "status":     status,
            "issue":      issues[status],
            "severity":   "critical" if status == "alert" else "medium" if status == "misconfigured" else "low",
            "data_flow":  f"{platform} → SAP S/4HANA",
        }

    def _webhook(self, result: str | None = None) -> dict:
        src = random.choice(WEBHOOK_SOURCES)
        r   = result or random.choices(["accepted","rejected","rate_limited"], weights=[0.65,0.2,0.15])[0]
        return {
            "source":    src,
            "result":    r,
            "signature_valid": r != "rejected",
            "reason":    {"accepted":"signature verified",
                          "rejected":"missing or invalid HMAC signature",
                          "rate_limited":"exceeded 10 req/sec"}[r],
            "event_type": random.choice(["push","alert","payment","deploy","incident"]),
            "severity":  "high" if r == "rejected" else "low",
        }

    def _traffic(self) -> dict:
        cls = random.choices(["PII","PHI","FINANCIAL","STANDARD"], weights=[0.3,0.15,0.25,0.3])[0]
        return {
            "source":         random.choice(["SAP S/4HANA","SFTP","Salesforce","Workday"]),
            "destination":    random.choice(["MuleSoft","Kafka","S3","SAP BTP"]),
            "classification": cls,
            "direction":      random.choice(["inbound","outbound"]),
            "bytes":          random.randint(1_000, 5_000_000),
            "records":        random.randint(1, 50_000),
            "severity":       "high" if cls in ("PII","PHI") else "low",
        }

    # ── Scenario replay (correlated burst) ──────────────────────

    def replay_scenario(self, scenario: str) -> int:
        """Publish a correlated burst across multiple streams."""
        count = 0
        scenarios = ["off_hours","bulk","shadow"] if scenario == "all" else [scenario]
        for s in scenarios:
            api = self._api_call(s)
            self.publish("api_calls", api); count += 1
            alert = self._alert_from(api)
            self.publish("alerts", alert); count += 1
            self.publish("anomalies", self._anomaly(api)); count += 1
            if s in ("bulk","shadow"):
                self.publish("dlp", self._dlp(api)); count += 1
            if s == "shadow":
                self.publish("shadow", self._shadow(api)); count += 1
            self.publish("zero_trust", self._zero_trust(api)); count += 1
            self.publish("incidents", self._incident(alert)); count += 1
            self.publish("compliance", self._compliance(alert)); count += 1
        return count

    # ── Steady-state loop ──────────────────────────────────────

    def run(self) -> None:
        tick = 0
        while not self.stop_flag.is_set():
            try:
                # Core api-call → alert → anomaly cadence (every tick)
                api = self._api_call()
                self.publish("api_calls", api)
                self.publish("alerts", self._alert_from(api))
                self.publish("anomalies", self._anomaly(api))

                # Rotate across modules every few ticks
                if tick % 2 == 0:
                    self.publish("dlp",         self._dlp(api))
                    self.publish("zero_trust",  self._zero_trust(api))
                if tick % 3 == 0:
                    self.publish("compliance",  self._compliance(api))
                    self.publish("incidents",   self._incident(self._alert_from(api)))
                if tick % 4 == 0:
                    self.publish("credentials", self._credential())
                    self.publish("sap_mcp",     self._sap_mcp())
                if tick % 5 == 0:
                    self.publish("sbom",        self._sbom())
                    self.publish("cloud_posture", self._cloud())
                    self.publish("shadow",      self._shadow(api))
                if tick % 6 == 0:
                    self.publish("connectors",  self._connector())
                    self.publish("webhooks",    self._webhook())
                    self.publish("traffic",     self._traffic())

                tick += 1
                time.sleep(2.0)
            except Exception:
                time.sleep(2.0)

    def stop(self) -> None:
        self.stop_flag.set()


def start_demo_generator(redis_url: str, streams: dict) -> DemoGenerator:
    gen = DemoGenerator(redis_url, streams)
    t = threading.Thread(target=gen.run, daemon=True, name="demo-generator")
    t.start()
    return gen
