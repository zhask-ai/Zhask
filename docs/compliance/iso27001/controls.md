# ISO/IEC 27001:2022 Annex A Controls — IntegriShield Mapping

ISO 27001 Annex A provides a reference set of information security controls. IntegriShield
automates evidence collection for the Annex A controls most directly applicable to SAP
application security.

## Control Summary

| Control ID | Annex A Reference | Status Method | Violation Trigger |
|-----------|------------------|---------------|-------------------|
| A.12.4.1 | Event Logging | Auto-detected | None (evidence-only) |
| A.12.4.3 | Administrator and Operator Logs | Auto-detected | `alert_events` (privilege-escalation) |
| A.16.1.2 | Reporting Information Security Events | Auto-detected | None (evidence-only) |
| A.18.1.3 | Protection of Records | Auto-detected | `dlp_alerts` |

---

## A.12.4.1: Event Logging

**Control objective:** Event logs recording user activities, exceptions, faults, and information
security events shall be produced, kept, and regularly reviewed.

**Evidence collected from:**
- `integrishield:api_call_events` — every SAP RFC call is logged by M01

**Violation conditions:** None — presence of events confirms logging is operational.

**ISO 27001 Auditor Notes:**
- M01 API Gateway intercepts and logs every RFC call with full metadata
- The `audit_events` PostgreSQL table provides the permanent, tamper-evident audit trail
- Log retention must comply with your organisation's retention policy (minimum 90 days recommended)

---

## A.12.4.3: Administrator and Operator Logs

**Control objective:** System administrator and system operator activities shall be logged and
the logs protected and regularly reviewed.

**Evidence collected from:**
- `integrishield:api_call_events` — all RFC calls including admin-level function modules
- `integrishield:alert_events` — privilege-escalation and credential-abuse alerts

**Violation conditions:**
- Alert with scenario `privilege-escalation` (service account calling admin FM)

**ISO 27001 Auditor Notes:**
- M12 Rules Engine detects service accounts calling admin-level function modules
- M12 blocklist (`_ADMIN_FUNCTIONS`) covers RFC_READ_TABLE, BAPI_USER_CHANGE, etc.
- Admin actions are distinguishable from standard user actions via `account_type` field

---

## A.16.1.2: Reporting Information Security Events

**Control objective:** Information security events shall be reported through appropriate
management channels as quickly as possible.

**Evidence collected from:**
- `integrishield:alert_events` — all security alerts from M12
- `integrishield:anomaly_events` — ML-detected anomalies from M08

**Violation conditions:** None — presence of reporting events confirms the channel is operational.

**ISO 27001 Auditor Notes:**
- M10 Incident Response automatically promotes critical alerts to tracked incidents
- Slack and PagerDuty integrations in M10 provide the management reporting channel
- Incident response time (alert → incident creation) is sub-second in the POC

---

## A.18.1.3: Protection of Records

**Control objective:** Records shall be protected from loss, destruction, falsification,
unauthorised access, and unauthorised release, in accordance with statutory, regulatory,
contractual, and business requirements.

**Evidence collected from:**
- `integrishield:dlp_alerts` — DLP violations from M09
- `integrishield:alert_events` — bulk-extraction and data-staging alerts

**Violation conditions:**
- Any `dlp_alert` (indicates records may have been improperly accessed or extracted)

**ISO 27001 Auditor Notes:**
- M09 DLP enforces volume-based and pattern-based rules to detect bulk record exports
- M13 SBOM Scanner detects insecure RFC calls (e.g., RFC_READ_TABLE) in custom code
- Records stored in PostgreSQL are protected by write-once audit log semantics
