# SOC 2 Type II — Trust Service Criteria — IntegriShield Mapping

SOC 2 Type II audits assess whether controls were operating effectively over a period of time
(typically 6–12 months). IntegriShield automates continuous evidence collection across the
Common Criteria (CC) series.

## Control Summary

| Control ID | Trust Service Criteria | Status Method | Violation Trigger |
|-----------|----------------------|---------------|-------------------|
| CC6.1 | Logical and Physical Access Controls | Auto-detected | `alert_events` (privilege-escalation, geo-anomaly) |
| CC7.2 | System Monitoring — Anomaly Detection | Auto-detected | `anomaly_events` |
| CC8.1 | Change Management | Auto-detected | `shadow_alerts` |
| CC9.2 | Risk Mitigation — Vendor Management | Auto-detected | `dlp_alerts` |

---

## CC6.1: Logical and Physical Access Controls

**Criteria:** The entity implements logical access security measures to protect against threats
from sources outside its system boundaries.

**Evidence collected from:**
- `integrishield:api_call_events` — all RFC calls with source IP and user identity
- `integrishield:anomaly_events` — access pattern anomalies
- `integrishield:alert_events` — access violations

**Violation conditions:**
- Alert with scenario `privilege-escalation`, `credential-abuse`, or `geo-anomaly`

**SOC 2 Auditor Notes:**
- M01 API Gateway logs every RFC call providing a continuous audit trail
- M04 Zero-Trust Fabric evaluates device posture, MFA, and geo for every session
- Access denials and policy violations are logged in real time

---

## CC7.2: System Monitoring — Anomaly Detection

**Criteria:** The entity monitors system components and the operation of controls, including
the use of automated mechanisms to identify anomalies.

**Evidence collected from:**
- `integrishield:anomaly_events` — IsolationForest ML scores from M08
- `integrishield:alert_events` — rules-based anomaly alerts from M12

**Violation conditions:**
- Any `anomaly_event` with score above threshold (indicates system detected an anomaly)

**SOC 2 Auditor Notes:**
- M08 runs the IsolationForest model against every analyzed RFC event
- M12 rules engine detects velocity, geo, and credential anomalies in real time
- Anomaly events are evidence that monitoring is operational

---

## CC8.1: Change Management

**Criteria:** The entity authorises, designs, develops/acquires, configures, documents, tests,
approves, and implements changes to infrastructure, data, software, and procedures.

**Evidence collected from:**
- `integrishield:shadow_alerts` — unapproved endpoint detections from M11
- `integrishield:api_call_events` — all changes logged

**Violation conditions:**
- Any `shadow_alert` (call to unregistered endpoint = unapproved change)

**SOC 2 Auditor Notes:**
- M11 Shadow Integration maintains a registry of approved RFC endpoints
- Deviations from the registry trigger shadow alerts — direct evidence of change control failure

---

## CC9.2: Risk Mitigation — Vendor and Business Partner Management

**Criteria:** The entity assesses and manages risks associated with vendors and business partners.

**Evidence collected from:**
- `integrishield:dlp_alerts` — data exfiltration attempts from M09
- `integrishield:alert_events` — geo-anomaly alerts (potential vendor access from unexpected locations)

**Violation conditions:**
- Any `dlp_alert` involving external IP ranges or partner namespaces

**SOC 2 Auditor Notes:**
- M09 DLP monitors for data transfers exceeding volume and pattern thresholds
- Geo-anomaly alerts from non-internal IP ranges flag potential vendor access risks
