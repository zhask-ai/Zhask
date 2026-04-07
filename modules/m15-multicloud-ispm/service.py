def normalize_finding(provider: str, finding: dict) -> dict:
    provider_key = provider.lower()
    severity_map = {"critical": 90, "high": 75, "medium": 50, "low": 25}

    severity = str(finding.get("severity", "low")).lower()
    risk_score = severity_map.get(severity, 25)

    return {
        "provider": provider_key,
        "resource_id": finding.get("resource_id", "unknown"),
        "control_id": finding.get("control_id", "unknown"),
        "risk_score": risk_score,
        "raw_severity": severity,
    }
