# IntegriShield Compliance Coverage

IntegriShield's **M07 Compliance Autopilot** provides continuous, automated compliance monitoring
across four major frameworks. This directory documents the control mappings and evidence collection
approach for each framework.

## Supported Frameworks

| Framework | Controls | Module | Documentation |
|-----------|----------|--------|---------------|
| SOX (Sarbanes-Oxley) | 4 IT-General Controls | M07 | [sox/controls.md](sox/controls.md) |
| SOC 2 Type II | 4 Trust Service Criteria | M07 | [soc2/controls.md](soc2/controls.md) |
| ISO 27001:2022 | 4 Annex A Controls | M07 | [iso27001/controls.md](iso27001/controls.md) |
| GDPR | 3 Articles | M07 | [gdpr/controls.md](gdpr/controls.md) |

## How It Works

M07 Compliance Autopilot runs as a microservice that:

1. **Consumes** all IntegriShield event streams in real time
2. **Maps** events to compliance controls using YAML configuration files
3. **Classifies** events as either *evidence* (proves a control is operating) or *violations* (indicates a control failure)
4. **Persists** evidence items and control assessments to PostgreSQL
5. **Publishes** compliance alerts to `integrishield:compliance_alerts` for real-time notification
6. **Exposes** REST API for querying assessments, evidence, and generating reports

## Evidence Types

| Evidence Type | Source Stream | Description |
|--------------|---------------|-------------|
| `api_call_log` | `integrishield:api_call_events` | SAP RFC calls intercepted by M01 |
| `anomaly` | `integrishield:anomaly_events` | ML anomaly scores from M08 |
| `dlp_violation` | `integrishield:dlp_alerts` | Data loss prevention alerts from M09 |
| `shadow_endpoint` | `integrishield:shadow_alerts` | Unknown endpoint detections from M11 |
| `alert` | `integrishield:alert_events` | Security alerts from M12 Rules Engine |

## Control Statuses

| Status | Meaning |
|--------|---------|
| `not_assessed` | No events have been mapped to this control yet |
| `compliant` | Events have been received but no violations detected |
| `non_compliant` | At least one violation event has been recorded |
| `needs_review` | Manual review required (set via API) |

## API Quick Reference

```bash
# Get SOX compliance summary
curl http://localhost:8007/api/v1/compliance/summary?framework=sox

# List all controls for SOC2
curl http://localhost:8007/api/v1/compliance/controls?framework=soc2

# Get evidence for a specific control
curl http://localhost:8007/api/v1/compliance/controls/SOX-ITGC-04/evidence

# Generate a compliance report
curl -X POST http://localhost:8007/api/v1/compliance/reports \
  -H 'Content-Type: application/json' \
  -d '{"framework": "sox", "format": "json"}'
```

## New Streams Introduced in Dev-3

| Stream | Producer | Purpose |
|--------|----------|---------|
| `integrishield:compliance_evidence` | M07 | Evidence items for each control |
| `integrishield:compliance_alerts` | M07 | Control violation alerts |
| `integrishield:incident_events` | M10 | Incident lifecycle events |
| `integrishield:mcp_query_events` | M05 | MCP tool call audit log |
| `integrishield:sbom_scan_events` | M13 | SBOM scan completion events |
