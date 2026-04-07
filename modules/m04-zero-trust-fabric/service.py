from dataclasses import dataclass


@dataclass
class AccessContext:
    user_id: str
    source_ip: str
    device_trusted: bool
    geo_allowed: bool


def evaluate_access(ctx: AccessContext) -> dict:
    risk = 0
    failed_controls = []

    if not ctx.device_trusted:
        risk += 45
        failed_controls.append("device_trust")
    if not ctx.geo_allowed:
        risk += 35
        failed_controls.append("geo_policy")

    # Zero-trust posture: deny if any required control fails.
    allow = len(failed_controls) == 0
    reason = "policy_pass" if allow else "zero_trust_block"
    return {
        "allow": allow,
        "risk_score": risk,
        "reason": reason,
        "failed_controls": failed_controls,
    }
