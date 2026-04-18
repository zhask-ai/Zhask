"""Mock SAP driver — for demos and CI (M05_SAP_DRIVER=mock).

Returns realistic SAP table rows keyed by table name so that Claude
can see plausible data when calling tools. All data is synthetic.
"""

from __future__ import annotations

import random
from datetime import date, timedelta
from typing import Any


def _rand_date(days_back: int = 365) -> str:
    d = date(2026, 4, 18) - timedelta(days=random.randint(0, days_back))
    return d.strftime("%Y-%m-%d")


def _rand_ts(days_back: int = 30) -> str:
    d = date(2026, 4, 18) - timedelta(days=random.randint(0, days_back))
    h, m, s = random.randint(0, 23), random.randint(0, 59), random.randint(0, 59)
    return f"{d} {h:02d}:{m:02d}:{s:02d}"


_BUKRS = ["1000", "1100", "2000", "3000", "US01", "DE01"]
_USERS = [
    "ADMIN", "BAUER_M", "SCHMIDT_K", "MUELLER_A", "JONES_T",
    "PATEL_R", "CHEN_L", "OKONKWO_E", "LINDQVIST_S", "HASSAN_F",
]
_ROLES = [
    "SAP_ALL", "SAP_NEW", "Z_FI_VIEWER", "Z_MM_POSTING",
    "Z_SD_BILLING", "Z_BASIS_ADM", "Z_SEC_AUDITOR", "Z_FI_APPROVER",
]
_VENDORS = [
    ("V-001", "Accenture GmbH", "DE"),
    ("V-002", "SAP SE", "DE"),
    ("V-003", "Oracle Corp", "US"),
    ("V-004", "IBM Deutschland", "DE"),
    ("V-005", "Capgemini SA", "FR"),
    ("V-006", "Infosys Ltd", "IN"),
    ("V-007", "Deloitte AG", "CH"),
    ("V-008", "KPMG SE", "DE"),
    ("V-009", "PwC GmbH", "DE"),
    ("V-010", "Wipro Ltd", "IN"),
]
_TCODES = [
    "SE16", "SM30", "FB01", "FB03", "ME21N", "ME23N",
    "VA01", "VA03", "SU01", "SU53", "SM20", "SM37",
]
_PROFILES = [
    "SAP_ALL", "S_A.SYSTEM", "S_RFCACL", "Z_AUDITOR_PROFILE",
    "Z_FI_VIEWER_PROFILE", "Z_BASIS_ADMIN",
]
_FUNC_MODULES = [
    "RFC_READ_TABLE", "BAPI_USER_GET_DETAIL", "BAPI_USER_GETLIST",
    "SUSR_USER_AUTH_FOR_OBJ_GET", "BAPI_TRANSACTION_COMMIT",
    "RFC_FUNCTION_SEARCH", "DDIF_FIELDINFO_GET",
]


# Per-table generators -------------------------------------------------------

def _gen_bkpf(n: int) -> list[dict]:
    docs = []
    for i in range(n):
        belnr = f"{5100000000 + i}"
        docs.append({
            "MANDT": "100",
            "BUKRS": random.choice(_BUKRS),
            "BELNR": belnr,
            "GJAHR": "2026",
            "BLART": random.choice(["KR", "KZ", "SA", "DR", "DZ"]),
            "BLDAT": _rand_date(90),
            "BUDAT": _rand_date(30),
            "USNAM": random.choice(_USERS),
            "WAERS": random.choice(["EUR", "USD", "GBP", "CHF"]),
            "BKTXT": f"Document {i + 1:04d}",
        })
    return docs


def _gen_bseg(n: int) -> list[dict]:
    lines = []
    for i in range(n):
        lines.append({
            "MANDT": "100",
            "BUKRS": random.choice(_BUKRS),
            "BELNR": f"{5100000000 + i}",
            "GJAHR": "2026",
            "BUZEI": f"{i + 1:03d}",
            "KOART": random.choice(["K", "D", "S"]),
            "DMBTR": str(round(random.uniform(100, 1_000_000), 2)),
            "WRBTR": str(round(random.uniform(100, 1_000_000), 2)),
            "HKONT": f"1{random.randint(10000, 99999)}",
        })
    return lines


def _gen_kna1(n: int) -> list[dict]:
    customers = [
        ("C-001", "Bosch GmbH", "Stuttgart", "DE"),
        ("C-002", "Siemens AG", "Munich", "DE"),
        ("C-003", "BMW AG", "Munich", "DE"),
        ("C-004", "Volkswagen AG", "Wolfsburg", "DE"),
        ("C-005", "Daimler AG", "Stuttgart", "DE"),
        ("C-006", "General Electric", "New York", "US"),
        ("C-007", "Ford Motor Co", "Detroit", "US"),
        ("C-008", "Toyota Ltd", "Toyota City", "JP"),
        ("C-009", "Nestlé SA", "Vevey", "CH"),
        ("C-010", "Philips NV", "Amsterdam", "NL"),
    ]
    result = []
    for i in range(min(n, len(customers))):
        kunnr, name, city, land = customers[i]
        result.append({
            "MANDT": "100",
            "KUNNR": kunnr,
            "NAME1": name,
            "STRAS": f"{random.randint(1, 999)} Hauptstraße",
            "ORT01": city,
            "LAND1": land,
            "KTOKD": "DEBI",
            "ERDAT": _rand_date(730),
            "ERNAM": random.choice(_USERS),
        })
    return result


def _gen_lfa1(n: int) -> list[dict]:
    result = []
    for i in range(min(n, len(_VENDORS))):
        lifnr, name, land = _VENDORS[i]
        result.append({
            "MANDT": "100",
            "LIFNR": lifnr,
            "NAME1": name,
            "STRAS": f"{random.randint(1, 99)} Business Park",
            "ORT01": f"City-{i + 1:02d}",
            "LAND1": land,
            "KTOKK": "KRED",
            "ERDAT": _rand_date(1000),
            "ERNAM": random.choice(_USERS),
        })
    return result


def _gen_usr02(n: int) -> list[dict]:
    rows = []
    for i, user in enumerate(_USERS[:n]):
        rows.append({
            "MANDT": "100",
            "BNAME": user,
            "USTYP": random.choice(["A", "B", "L", "S"]),
            "CLASS": random.choice(["SUPER", "MASTE", ""]),
            "GLTGV": "2024-01-01",
            "GLTGB": random.choice(["9999-12-31", "2026-06-30", "2026-12-31"]),
            "TRDAT": _rand_date(30),
            "LTIME": f"{random.randint(7, 20):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}",
            "UFLAG": random.choice(["0", "0", "0", "64", "128"]),
        })
    return rows


def _gen_agr_users(n: int) -> list[dict]:
    rows = []
    for i in range(n):
        rows.append({
            "MANDT": "100",
            "AGR_NAME": random.choice(_ROLES),
            "UNAME": random.choice(_USERS),
            "FROM_DAT": "2024-01-01",
            "TO_DAT": "9999-12-31",
            "ORG_FLAG": "",
        })
    return rows


def _gen_sm20(n: int) -> list[dict]:
    rows = []
    for i in range(n):
        rows.append({
            "MANDT": "100",
            "TERMINAL": f"SAPGUI-{random.randint(1, 50):02d}",
            "BNAME": random.choice(_USERS),
            "TCODE": random.choice(_TCODES),
            "DATUM": _rand_date(7),
            "UZEIT": f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}",
            "REPID": f"SAPMF{random.randint(1000, 9999)}",
            "MSG_ID": f"AUD-{random.randint(10000, 99999)}",
            "AUCLASS": random.choice(["D", "D", "D", "C", "E"]),
        })
    return rows


def _gen_suim_auth(n: int) -> list[dict]:
    rows = []
    for i in range(n):
        rows.append({
            "MANDT": "100",
            "BNAME": random.choice(_USERS),
            "PROFILE": random.choice(_PROFILES),
            "AGR_NAME": random.choice(_ROLES),
            "OBJECT": random.choice(["S_TCODE", "S_RFC", "S_DEVELOP", "F_KNA1_BUK"]),
            "FIELD": random.choice(["TCD", "RFC_NAME", "DEVCLASS", "BUKRS"]),
            "VON": random.choice(["*", "FB01", "RFC_READ_TABLE", "0001"]),
            "BIS": "*",
        })
    return rows


def _gen_rfclog(n: int) -> list[dict]:
    rows = []
    for i in range(n):
        rows.append({
            "MANDT": "100",
            "LOGDATE": _rand_date(14),
            "LOGTIME": f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}",
            "RFCFNAM": random.choice(_FUNC_MODULES),
            "RFCDEST": random.choice(["NONE", "ABAP_AS_WS", "SAP_MW_CONN"]),
            "CALLER": random.choice(_USERS),
            "RC": random.choice(["0", "0", "0", "4", "8"]),
            "ROWS_RETURNED": str(random.randint(0, 5000)),
        })
    return rows


def _gen_default(table_name: str, n: int) -> list[dict]:
    return [
        {
            "MANDT": "100",
            "TABLE": table_name,
            "KEY": f"{table_name}-{i:04d}",
            "FIELD1": f"VALUE_{i:04d}",
            "FIELD2": random.choice(["A", "B", "C", "X"]),
            "ERDAT": _rand_date(365),
        }
        for i in range(n)
    ]


_TABLE_GENERATORS: dict[str, Any] = {
    "BKPF":      _gen_bkpf,
    "BSEG":      _gen_bseg,
    "KNA1":      _gen_kna1,
    "LFA1":      _gen_lfa1,
    "USR02":     _gen_usr02,
    "AGR_USERS": _gen_agr_users,
    "SM20":      _gen_sm20,
    "SUIM_AUTH": _gen_suim_auth,
    "RFCLOG":    _gen_rfclog,
}


class MockDriver:
    """Returns realistic synthetic SAP table rows. Safe for CI and local dev."""

    def driver_name(self) -> str:
        return "mock"

    def read_table(self, table_name: str, max_rows: int) -> list[dict[str, Any]]:
        n = min(max_rows, 20)
        gen = _TABLE_GENERATORS.get(table_name.upper())
        if gen is not None:
            return gen(n)
        return _gen_default(table_name, n)
