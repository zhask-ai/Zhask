"""SoD engine tests (Feature #1)."""

from __future__ import annotations

import sys
from pathlib import Path

# Make module src importable without installation
_M17_SRC = Path(__file__).resolve().parents[2] / "modules" / "m17-sod-analyzer" / "src"
sys.path.insert(0, str(_M17_SRC))

from integrishield.m17.engine import evaluate_user, load_risks  # noqa: E402


def test_create_vendor_plus_pay_vendor_flags_violation():
    risks = load_risks()
    role_map = {
        "Z_AP_CLERK": ["FB60", "F110"],
        "Z_VENDOR_MAINT": ["XK01", "FK01"],
    }
    violations = evaluate_user(
        tenant_id="acme",
        sap_user="JDOE",
        roles=["Z_AP_CLERK", "Z_VENDOR_MAINT"],
        role_tcode_map=role_map,
        risks=risks,
    )
    ids = {v.risk_id for v in violations}
    assert "SOD-P2P-01" in ids


def test_single_side_no_violation():
    risks = load_risks()
    role_map = {"Z_AP_CLERK": ["FB60", "F110"]}
    violations = evaluate_user(
        tenant_id="acme",
        sap_user="PAYER_ONLY",
        roles=["Z_AP_CLERK"],
        role_tcode_map=role_map,
        risks=risks,
    )
    assert all(v.risk_id != "SOD-P2P-01" for v in violations)


def test_sap_all_basis_violation():
    risks = load_risks()
    role_map = {"Z_BASIS_ADMIN": ["SU01", "PFCG", "SU10"]}
    violations = evaluate_user(
        tenant_id="acme",
        sap_user="BASIS01",
        roles=["Z_BASIS_ADMIN"],
        role_tcode_map=role_map,
        risks=risks,
    )
    assert any(v.risk_id == "SOD-BASIS-01" for v in violations)
