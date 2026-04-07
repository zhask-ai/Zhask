# SOX IT-General Controls (ITGC) — IntegriShield Mapping

Sarbanes-Oxley Act Section 404 requires companies to assess the effectiveness of internal controls
over financial reporting. IntegriShield automates evidence collection for the four key ITGC domains.

## Control Summary

| Control ID | Title | Status Method | Violation Trigger |
|-----------|-------|---------------|-------------------|
| SOX-ITGC-01 | Logical Access Controls | Auto-detected | `alert_events` (privilege-escalation, credential-abuse) |
| SOX-ITGC-02 | Change Management | Auto-detected | `shadow_alerts` (unauthorised endpoints) |
| SOX-ITGC-03 | Computer Operations | Auto-detected | `alert_events` (off-hours-rfc) |
| SOX-ITGC-04 | Data Integrity | Auto-detected | `dlp_alerts`, `alert_events` (bulk-extraction) |

---

## SOX-ITGC-01: Logical Access Controls

**Objective:** Ensure that access to SAP systems and sensitive financial data is restricted to
authorised users only via appropriate authentication, authorisation, and access controls.

**Evidence collected from:**
- `integrishield:api_call_events` — all RFC calls with user identity
- `integrishield:alert_events` — access violations (privilege-escalation, credential-abuse, geo-anomaly)

**Violation conditions:**
- Alert with scenario `privilege-escalation` or `credential-abuse`

**Remediation:**
- Review user access assignments quarterly
- Enforce least-privilege on all RFC authorisation objects
- Enable MFA for all privileged (admin/basis) accounts
- Review M04 Zero-Trust access denials

---

## SOX-ITGC-02: Change Management

**Objective:** All changes to SAP production systems must go through an authorised change management
process. Unauthorised or undocumented changes are a control failure.

**Evidence collected from:**
- `integrishield:shadow_alerts` — calls to unregistered RFC endpoints
- `integrishield:alert_events` — shadow-endpoint scenario

**Violation conditions:**
- Any `shadow_alert` event (unregistered endpoint detected)

**Remediation:**
- Maintain an authorised RFC endpoint registry in M11 Shadow Integration
- All new RFC endpoints require a change ticket before production deployment
- Shadow endpoint detections must trigger a change management review within 24h

---

## SOX-ITGC-03: Computer Operations — After-Hours Activity

**Objective:** SAP system activity outside of authorised business hours must be monitored and
investigated. Off-hours RFC calls may indicate unauthorised access or insider threat.

**Evidence collected from:**
- `integrishield:api_call_events` — all RFC calls with timestamp
- `integrishield:alert_events` — off-hours-rfc scenario

**Violation conditions:**
- Alert with scenario `off-hours-rfc`

**Remediation:**
- Restrict off-hours interactive sessions to approved users with business justification
- Distinguish scheduled batch jobs (whitelisted) from interactive off-hours sessions
- Review all off-hours alerts within 48 hours

---

## SOX-ITGC-04: Data Integrity — Bulk Extraction Prevention

**Objective:** Controls must be in place to prevent unauthorised bulk extraction of financial and
sensitive data. DLP alerts and bulk-extraction anomalies are direct evidence of control effectiveness.

**Evidence collected from:**
- `integrishield:dlp_alerts` — data loss prevention violations
- `integrishield:anomaly_events` — ML-detected data volume anomalies
- `integrishield:alert_events` — bulk-extraction and data-staging scenarios

**Violation conditions:**
- Any `dlp_alert` event
- Alert with scenario `bulk-extraction` or `data-staging`

**Remediation:**
- Block RFC_READ_TABLE for non-admin users (use authorisation object S_TABU_DIS)
- Set M12 bulk-extraction threshold to 10MB (configurable via M12_BULK_EXTRACTION_BYTES)
- Any confirmed bulk extraction must be reported to the audit committee
