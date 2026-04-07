# GDPR Compliance — IntegriShield Mapping

The General Data Protection Regulation (GDPR) requires technical and organisational measures to
protect personal data. IntegriShield automates evidence collection for the three GDPR Articles
most directly applicable to SAP application security.

## Control Summary

| Control ID | GDPR Article | Status Method | Violation Trigger |
|-----------|--------------|---------------|-------------------|
| GDPR-Art25 | Article 25 — Data Protection by Design | Auto-detected | `alert_events` (access violations) |
| GDPR-Art32 | Article 32 — Security of Processing | Auto-detected | `dlp_alerts`, `alert_events` |
| GDPR-Art33 | Article 33 — Notification of Breach | Auto-detected | `dlp_alerts` |

---

## GDPR-Art25: Data Protection by Design and by Default

**Requirement:** The controller shall implement appropriate technical and organisational measures
designed to implement data-protection principles (e.g., data minimisation) in an effective manner
and to integrate the necessary safeguards into the processing.

**Evidence collected from:**
- `integrishield:api_call_events` — demonstrates access controls are applied to all data access
- `integrishield:anomaly_events` — demonstrates monitoring is in place

**Violation conditions:**
- Alert with scenario `privilege-escalation` (indicates data minimisation failure)

**GDPR Notes:**
- M04 Zero-Trust Fabric enforces least-privilege access at the session level
- M01 API Gateway's RFC interception demonstrates Privacy by Design at the access control layer
- SAP field-level authorisation objects (e.g., F_BKPF_BUK) should be reviewed alongside IntegriShield logs

---

## GDPR-Art32: Security of Processing

**Requirement:** The controller and processor shall implement appropriate technical and
organisational measures to ensure a level of security appropriate to the risk, including:
(a) pseudonymisation and encryption; (b) ongoing confidentiality, integrity, availability;
(c) regular testing, assessing, and evaluating effectiveness of technical and organisational measures.

**Evidence collected from:**
- `integrishield:dlp_alerts` — indicates a security-of-processing failure
- `integrishield:anomaly_events` — ongoing testing/assessment output from M08
- `integrishield:alert_events` — all security events from M12

**Violation conditions:**
- Any `dlp_alert` involving personal data
- Alert with scenario `bulk-extraction` or `credential-abuse`

**GDPR Notes:**
- Personal data in SAP typically resides in tables: KNA1 (customers), PA0001 (HR), BSEG (financials)
- DLP violations involving these tables require escalation per Article 33 (72-hour notification)
- M08 anomaly detection provides the "regular testing and evaluation" evidence for Article 32(1)(d)

---

## GDPR-Art33: Notification of a Personal Data Breach

**Requirement:** In the case of a personal data breach, the controller shall, without undue delay
and where feasible, not later than 72 hours after becoming aware of it, notify the personal data
breach to the supervisory authority.

**Evidence collected from:**
- `integrishield:dlp_alerts` — potential breach indicators (bulk extraction of personal data)
- `integrishield:alert_events` — bulk-extraction and data-staging alerts

**Violation conditions:**
- Any `dlp_alert` (all DLP violations are potential breach events requiring triage)

**GDPR Notes:**
- M10 Incident Response auto-creates an incident for every DLP violation (when severity >= medium)
- The incident's `created_at` timestamp is the "became aware" timestamp for the 72-hour clock
- Incident notes field should be used to document breach triage outcomes
- Configure `M10_SLACK_WEBHOOK_URL` to notify the Data Protection Officer in real time
- A GDPR breach log should be maintained separately; export M10 incidents to your DPO system
