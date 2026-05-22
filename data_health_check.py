"""
Data Health Check — v2 (Enterprise Edition)
============================================
Upgrades over v1:
  1. Context-aware PII detection  — column name + surrounding text scoring
                                    reduces false positives on serial/order numbers
  2. Schema drift detection       — compares against a saved "gold standard" schema,
                                    triggers alerts for risky new columns
  3. Industry packs               — E-commerce, Finance, Healthcare business logic checks
  4. Cross-column validation      — ship date after order date, tax math, date in past
  5. Partial masking              — shows XXX-XX-1234 style previews, not raw values

Usage:
    python data_health_check.py                          # sample data demo
    python data_health_check.py --file data.csv
    python data_health_check.py --file data.csv --pack ecommerce
    python data_health_check.py --file data.csv --sensitivity high
    python data_health_check.py --file data.csv --save-schema  # lock in baseline
    python data_health_check.py --file data.csv --schema baseline.json  # compare

Requirements:
    pip install great_expectations pandas
"""

import re
import sys
import json
import argparse
import warnings
from pathlib import Path
from datetime import datetime
from collections import defaultdict

import pandas as pd
import great_expectations as gx

warnings.filterwarnings("ignore")

# ─────────────────────────────────────────────────────────────────────────────
# 1. CONTEXT-AWARE PII DETECTION
# ─────────────────────────────────────────────────────────────────────────────

PII_PATTERNS = {
    "SSN":           r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "EMAIL":         r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE":         r"\b(?:\+?1[\-.\s]?)?\(?\d{3}\)?[\-.\s]\d{3}[\-.\s]\d{4}\b",
    "CREDIT_CARD":   r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    "IP_ADDRESS":    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "DATE_OF_BIRTH": r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b",
    "PASSPORT":      r"\b[A-Z]{1,2}\d{6,9}\b",
    "IBAN":          r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7,19}\b",
}

SENSITIVITY_LEVELS = {
    "low":    {"SSN", "CREDIT_CARD", "PASSPORT", "IBAN"},
    "medium": {"SSN", "CREDIT_CARD", "PASSPORT", "IBAN", "PHONE", "DATE_OF_BIRTH"},
    "high":   set(PII_PATTERNS.keys()),
}

SAFE_COL_KEYWORDS = {
    "serial", "product", "order", "ref", "sku", "part", "item",
    "tracking", "invoice", "ticket", "model", "batch", "barcode",
    "upc", "isbn", "asin", "code", "number", "num", "no",
}

RISKY_COL_KEYWORDS = {
    "ssn", "sin", "identity", "social", "patient", "member", "employee",
    "person", "contact", "profile", "account", "taxpayer", "national",
    "passport", "driver", "license", "dob", "birth", "gender", "race",
}

RISKY_CONTEXT_WORDS = {
    "social security", "ssn", "identity", "personal id", "date of birth",
    "dob", "taxpayer", "national id", "passport", "confidential", "private",
    "sensitive", "medical", "diagnosis", "patient",
}

ALLOWED_EMAIL_COLS = {"email", "email_address", "contact_email", "user_email"}


def _context_score(col_name: str, cell_text: str) -> float:
    """
    Returns a 0.0-1.0 confidence score that a regex match in this
    (column, cell) is genuine PII rather than a false positive.

    This is the core upgrade: we look at WHERE data lives, not just
    whether a pattern matched.
    """
    col_lower = col_name.lower().strip()
    cell_lower = cell_text.lower()

    if any(kw in col_lower for kw in SAFE_COL_KEYWORDS):
        if any(kw in cell_lower for kw in RISKY_CONTEXT_WORDS):
            return 0.75
        return 0.15

    if any(kw in col_lower for kw in RISKY_COL_KEYWORDS):
        return 1.0

    if any(kw in cell_lower for kw in RISKY_CONTEXT_WORDS):
        return 0.90

    return 0.50


def _mask_value(pii_type: str, value: str) -> str:
    """Partial masking — shows enough to prove risk without exposing the value."""
    if pii_type == "SSN":
        return re.sub(r"^\d{3}-\d{2}-", "XXX-XX-", value)
    if pii_type == "CREDIT_CARD":
        digits = re.sub(r"[^\d]", "", value)
        return f"XXXX-XXXX-XXXX-{digits[-4:]}" if len(digits) >= 4 else "XXXX-XXXX-XXXX-XXXX"
    if pii_type == "PHONE":
        return re.sub(r"^\+?1?[\-.\s]?\(?\d{3}\)?[\-.\s]\d{3}", "XXX-XXX", value)
    if pii_type == "EMAIL":
        parts = value.split("@")
        return f"{parts[0][:2]}***@{parts[1]}" if len(parts) == 2 else "***@***"
    if pii_type == "DATE_OF_BIRTH":
        return re.sub(r"^\d{1,2}[\/\-]\d{1,2}[\/\-]", "**/**/", value)
    if pii_type == "PASSPORT":
        return value[:2] + "****"
    return value[:2] + "•" * max(4, len(value) - 2)


def scan_for_pii(df: pd.DataFrame, sensitivity: str = "medium") -> list:
    """
    Context-aware PII scan. Returns a sorted list of finding dicts.
    Each finding: pii_type, column, row, masked, confidence, risk, reason.
    """
    active_types = SENSITIVITY_LEVELS.get(sensitivity, SENSITIVITY_LEVELS["medium"])
    findings = []

    for col in df.columns:
        col_is_email = col.lower().strip() in ALLOWED_EMAIL_COLS
        for row_idx, cell in df[col].dropna().items():
            cell_str = str(cell)
            for pii_type, pattern in PII_PATTERNS.items():
                if pii_type not in active_types:
                    continue
                if pii_type == "EMAIL" and col_is_email:
                    continue
                for match in re.findall(pattern, cell_str):
                    confidence = _context_score(col, cell_str)
                    risk = "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.40 else "LOW"
                    col_lower = col.lower()
                    if any(kw in col_lower for kw in SAFE_COL_KEYWORDS):
                        reason = f"Pattern in likely-safe column '{col}' — verify manually"
                    elif any(kw in col_lower for kw in RISKY_COL_KEYWORDS):
                        reason = f"High-risk column name '{col}'"
                    else:
                        reason = f"Pattern in free-text column '{col}'"
                    findings.append({
                        "pii_type":   pii_type,
                        "column":     col,
                        "row":        int(row_idx),
                        "raw_value":  match,
                        "masked":     _mask_value(pii_type, match),
                        "confidence": round(confidence, 2),
                        "risk":       risk,
                        "reason":     reason,
                    })

    findings.sort(key=lambda x: ({"HIGH": 0, "MEDIUM": 1, "LOW": 2}[x["risk"]], x["column"]))
    return findings


def pii_findings_by_type(findings: list) -> dict:
    grouped = defaultdict(list)
    for f in findings:
        grouped[f["pii_type"]].append(f)
    return dict(grouped)


# ─────────────────────────────────────────────────────────────────────────────
# 2. SCHEMA DRIFT DETECTION
# ─────────────────────────────────────────────────────────────────────────────

CRITICAL_COL_KEYWORDS = {
    "password", "passwd", "secret", "token", "api_key", "apikey",
    "medical", "diagnosis", "health", "prescription", "treatment",
    "salary", "compensation", "wage", "income",
    "credit_card", "card_number", "cvv", "ssn", "sin",
    "race", "ethnicity", "religion", "political", "biometric",
}


def save_schema_baseline(df: pd.DataFrame, output_path: str):
    baseline = {
        "saved_at": datetime.now().isoformat(),
        "columns": list(df.columns),
        "dtypes": {col: str(df[col].dtype) for col in df.columns},
        "row_count": len(df),
    }
    with open(output_path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline schema saved → {output_path}")
    return baseline


def detect_schema_drift(df: pd.DataFrame, baseline_path: str) -> dict:
    if not Path(baseline_path).exists():
        return {"status": "no_baseline", "alerts": [], "changes": []}

    with open(baseline_path) as f:
        baseline = json.load(f)

    baseline_cols = set(baseline["columns"])
    current_cols  = set(df.columns)
    added   = current_cols - baseline_cols
    removed = baseline_cols - current_cols

    type_changes = []
    for col in baseline_cols & current_cols:
        b_dtype = baseline["dtypes"].get(col, "unknown")
        c_dtype = str(df[col].dtype)
        if b_dtype != c_dtype:
            type_changes.append({"column": col, "before": b_dtype, "after": c_dtype})

    alerts, changes = [], []
    for col in added:
        is_critical = any(kw in col.lower() for kw in CRITICAL_COL_KEYWORDS)
        entry = {
            "type": "column_added", "column": col,
            "severity": "CRITICAL" if is_critical else "WARNING",
            "message": (
                f"HIGH RISK: New column '{col}' contains a sensitive keyword — immediate review required."
                if is_critical else f"New column '{col}' added since last scan."
            ),
        }
        (alerts if is_critical else changes).append(entry)

    for col in removed:
        changes.append({"type": "column_removed", "column": col, "severity": "INFO",
                        "message": f"Column '{col}' was in baseline but is now missing."})
    for tc in type_changes:
        changes.append({"type": "type_changed", "column": tc["column"], "severity": "WARNING",
                        "message": f"Column '{tc['column']}' type changed: {tc['before']} -> {tc['after']}"})

    return {
        "status": "drift_detected" if (added or removed or type_changes) else "stable",
        "baseline_date": baseline.get("saved_at", "unknown"),
        "alerts": alerts, "changes": changes,
        "summary": {"added": list(added), "removed": list(removed), "type_changes": type_changes},
    }


# ─────────────────────────────────────────────────────────────────────────────
# 3. INDUSTRY PACKS
# ─────────────────────────────────────────────────────────────────────────────

def _find_col(df: pd.DataFrame, *keywords):
    for col in df.columns:
        if any(kw in col.lower() for kw in keywords):
            return col
    return None


def run_ecommerce_pack(df: pd.DataFrame) -> list:
    results = []
    order_col = _find_col(df, "order_date", "order_time", "purchase_date")
    ship_col  = _find_col(df, "ship_date", "shipped_date", "delivery_date", "dispatch")
    if order_col and ship_col:
        try:
            o = pd.to_datetime(df[order_col], errors="coerce")
            s = pd.to_datetime(df[ship_col],  errors="coerce")
            bad = df[(s < o) & o.notna() & s.notna()]
            results.append({"check": f"Ship date after order date", "passed": len(bad) == 0,
                             "detail": f"{len(bad)} row(s) shipped before order" if len(bad) else "All OK",
                             "bad_rows": bad.index.tolist()})
        except Exception as e:
            results.append({"check": "Ship/order date comparison", "passed": None,
                             "detail": str(e), "bad_rows": []})

    price_col = _find_col(df, "price", "amount", "total", "subtotal", "revenue")
    if price_col and pd.api.types.is_numeric_dtype(df[price_col]):
        bad = df[df[price_col] < 0]
        results.append({"check": f"Prices non-negative ({price_col})", "passed": len(bad) == 0,
                         "detail": f"{len(bad)} negative price(s)" if len(bad) else "All OK",
                         "bad_rows": bad.index.tolist()})

    qty_col = _find_col(df, "quantity", "qty", "units", "count")
    if qty_col and pd.api.types.is_numeric_dtype(df[qty_col]):
        bad = df[(df[qty_col] <= 0) | (df[qty_col] % 1 != 0)]
        results.append({"check": f"Quantity is positive integer ({qty_col})", "passed": len(bad) == 0,
                         "detail": f"{len(bad)} invalid quantity row(s)" if len(bad) else "All OK",
                         "bad_rows": bad.index.tolist()})

    date_col = _find_col(df, "signup_date", "created_at", "registration", "join_date")
    if date_col:
        try:
            dt = pd.to_datetime(df[date_col], errors="coerce")
            future = df[dt > pd.Timestamp.now()]
            results.append({"check": f"Signup dates are in the past ({date_col})", "passed": len(future) == 0,
                             "detail": f"{len(future)} future-dated row(s)" if len(future) else "All OK",
                             "bad_rows": future.index.tolist()})
        except Exception:
            pass
    return results


def run_finance_pack(df: pd.DataFrame, tax_rate: float = 0.07) -> list:
    results = []
    subtotal_col = _find_col(df, "subtotal", "sub_total", "net", "base_amount")
    tax_col      = _find_col(df, "tax", "vat", "gst", "sales_tax")
    total_col    = _find_col(df, "total", "grand_total", "amount_due", "invoice_total")

    if subtotal_col and tax_col:
        if pd.api.types.is_numeric_dtype(df[subtotal_col]) and pd.api.types.is_numeric_dtype(df[tax_col]):
            expected = (df[subtotal_col] * tax_rate).round(2)
            bad = df[abs(df[tax_col] - expected) > 0.02]
            results.append({"check": f"Tax = {int(tax_rate*100)}% of subtotal",
                             "passed": len(bad) == 0,
                             "detail": f"{len(bad)} incorrect tax row(s)" if len(bad) else "All OK",
                             "bad_rows": bad.index.tolist()})

    if subtotal_col and tax_col and total_col:
        if all(pd.api.types.is_numeric_dtype(df[c]) for c in [subtotal_col, tax_col, total_col]):
            expected_total = (df[subtotal_col] + df[tax_col]).round(2)
            bad = df[abs(df[total_col] - expected_total) > 0.02]
            results.append({"check": "Total = subtotal + tax",
                             "passed": len(bad) == 0,
                             "detail": f"{len(bad)} row(s) where total doesn't balance" if len(bad) else "All OK",
                             "bad_rows": bad.index.tolist()})

    balance_col = _find_col(df, "balance", "outstanding", "due", "owed")
    if balance_col and pd.api.types.is_numeric_dtype(df[balance_col]):
        bad = df[df[balance_col] < 0]
        results.append({"check": f"No negative balances ({balance_col})",
                         "passed": len(bad) == 0,
                         "detail": f"{len(bad)} negative balance(s)" if len(bad) else "All OK",
                         "bad_rows": bad.index.tolist()})
    return results


def run_healthcare_pack(df: pd.DataFrame) -> list:
    results = []
    age_col = _find_col(df, "age", "patient_age")
    if age_col and pd.api.types.is_numeric_dtype(df[age_col]):
        bad = df[(df[age_col] < 0) | (df[age_col] > 130)]
        results.append({"check": f"Patient age in range 0-130 ({age_col})",
                         "passed": len(bad) == 0,
                         "detail": f"{len(bad)} implausible age(s)" if len(bad) else "All OK",
                         "bad_rows": bad.index.tolist()})

    admit_col     = _find_col(df, "admission", "admit_date", "check_in")
    discharge_col = _find_col(df, "discharge", "discharge_date", "check_out")
    if admit_col and discharge_col:
        try:
            a = pd.to_datetime(df[admit_col],     errors="coerce")
            d = pd.to_datetime(df[discharge_col], errors="coerce")
            bad = df[(d < a) & a.notna() & d.notna()]
            results.append({"check": "Discharge after admission",
                             "passed": len(bad) == 0,
                             "detail": f"{len(bad)} discharged before admitted" if len(bad) else "All OK",
                             "bad_rows": bad.index.tolist()})
        except Exception:
            pass

    dosage_col = _find_col(df, "dosage", "dose", "medication_amount")
    if dosage_col and pd.api.types.is_numeric_dtype(df[dosage_col]):
        bad = df[df[dosage_col] <= 0]
        results.append({"check": f"Dosage positive ({dosage_col})",
                         "passed": len(bad) == 0,
                         "detail": f"{len(bad)} zero/negative dosage(s)" if len(bad) else "All OK",
                         "bad_rows": bad.index.tolist()})
    return results


INDUSTRY_PACKS = {
    "ecommerce":  run_ecommerce_pack,
    "finance":    run_finance_pack,
    "healthcare": run_healthcare_pack,
}


# ─────────────────────────────────────────────────────────────────────────────
# 4. DATA QUALITY CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def build_expectation_suite(df: pd.DataFrame, config: dict) -> list:
    expectations = []
    col_names = list(df.columns)
    for col in col_names:
        expectations.append(gx.expectations.ExpectColumnToExist(column=col))
    id_cols = [c for c in col_names if re.search(r"\bid\b|_id$|^id_", c, re.I)]
    for col in id_cols:
        expectations.append(gx.expectations.ExpectColumnValuesToNotBeNull(column=col))
    for col in [c for c in col_names if "email" in c.lower()]:
        expectations.append(gx.expectations.ExpectColumnValuesToMatchRegex(
            column=col, regex=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", mostly=0.95))
    pos_kw = ["revenue", "amount", "price", "quantity", "qty", "count", "score"]
    for col in col_names:
        if any(kw in col.lower() for kw in pos_kw) and pd.api.types.is_numeric_dtype(df[col]):
            expectations.append(gx.expectations.ExpectColumnValuesToBeBetween(column=col, min_value=0))
    for col in [c for c in col_names if "age" in c.lower()]:
        if pd.api.types.is_numeric_dtype(df[col]):
            expectations.append(gx.expectations.ExpectColumnValuesToBeBetween(column=col, min_value=0, max_value=120))
    for col in [c for c in col_names if re.search(r"zip|postal", c, re.I)]:
        expectations.append(gx.expectations.ExpectColumnValuesToMatchRegex(
            column=col, regex=r"^\d{5}(-\d{4})?$", mostly=0.95))
    for rule in config.get("custom_expectations", []):
        col = rule.get("column")
        if col not in col_names:
            continue
        t = rule.get("type")
        if t == "not_null":
            expectations.append(gx.expectations.ExpectColumnValuesToNotBeNull(column=col))
        elif t == "between" and "min" in rule and "max" in rule:
            expectations.append(gx.expectations.ExpectColumnValuesToBeBetween(
                column=col, min_value=rule["min"], max_value=rule["max"]))
        elif t == "regex" and "pattern" in rule:
            expectations.append(gx.expectations.ExpectColumnValuesToMatchRegex(column=col, regex=rule["pattern"]))
        elif t == "unique":
            expectations.append(gx.expectations.ExpectColumnValuesToBeUnique(column=col))
    return expectations


def run_quality_checks(df: pd.DataFrame, expectations: list) -> dict:
    ctx = gx.get_context(mode="ephemeral")
    ds = ctx.data_sources.add_pandas("source")
    da = ds.add_dataframe_asset("dataset")
    batch_def = da.add_batch_definition_whole_dataframe("batch")
    batch = batch_def.get_batch(batch_parameters={"dataframe": df})
    suite = gx.ExpectationSuite(name="suite", expectations=expectations)
    validation = batch.validate(suite)
    results = [{"check": r.expectation_config.type.replace("expect_","").replace("_"," "),
                "column": r.expectation_config.kwargs.get("column","—"),
                "passed": r.success, "details": r.result}
               for r in validation.results]
    return {"overall_success": validation.success, "total_checks": len(results),
            "passed": sum(1 for r in results if r["passed"]),
            "failed": sum(1 for r in results if not r["passed"]), "results": results}


# ─────────────────────────────────────────────────────────────────────────────
# 5. DUPLICATE DETECTION
# ─────────────────────────────────────────────────────────────────────────────

def check_duplicates(df: pd.DataFrame) -> dict:
    total = len(df)
    exact = int(df.duplicated().sum())
    str_cols = df.select_dtypes(include="object").columns.tolist()
    near = int(df[str_cols].fillna("").apply(lambda c: c.str.lower().str.strip()).duplicated().sum()) if str_cols else 0
    return {"total_rows": total, "exact_duplicates": exact, "near_duplicates": near,
            "duplicate_pct": round((exact / total) * 100, 1) if total else 0}


# ─────────────────────────────────────────────────────────────────────────────
# 6. SCORING ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def calculate_score(pii_findings: list, quality: dict, dupes: dict,
                    row_count: int, pack_results: list = None) -> dict:
    real_pii  = [f for f in pii_findings if f["risk"] in ("HIGH", "MEDIUM")]
    total_pii = len(real_pii)
    pii_density = total_pii / max(row_count, 1)
    privacy = max(0, min(100, 100 - int(pii_density * 50) - min(total_pii * 2, 60)))
    quality_score = int((quality["passed"] / quality["total_checks"]) * 100) if quality["total_checks"] else 100
    completeness  = max(0, 100 - int(dupes["duplicate_pct"] * 2))
    pack_penalty  = min(sum(1 for r in (pack_results or []) if r.get("passed") is False) * 5, 20)
    overall = max(0, min(100, int(privacy * 0.38 + quality_score * 0.38 + completeness * 0.18) - pack_penalty))

    def grade(s):
        if s >= 85: return "A — Healthy"
        if s >= 70: return "B — Acceptable"
        if s >= 55: return "C — Needs attention"
        if s >= 40: return "D — At risk"
        return "F — Critical"

    return {"overall": overall, "grade": grade(overall), "privacy": privacy,
            "quality": quality_score, "completeness": completeness, "pack_penalty": pack_penalty,
            "pii_high_count":   sum(1 for f in pii_findings if f["risk"] == "HIGH"),
            "pii_medium_count": sum(1 for f in pii_findings if f["risk"] == "MEDIUM"),
            "pii_low_count":    sum(1 for f in pii_findings if f["risk"] == "LOW")}


# ─────────────────────────────────────────────────────────────────────────────
# 7. REPORT RENDERER
# ─────────────────────────────────────────────────────────────────────────────

BAR = 30
def _bar(s): f = int((s/100)*BAR); return "█"*f + "░"*(BAR-f)
def _c(s): return "\033[32m" if s>=85 else "\033[33m" if s>=55 else "\033[31m"
R="\033[0m"; B="\033[1m"; RED="\033[31m"; YEL="\033[33m"; GRN="\033[32m"


def print_report(file_path, df, pii_findings, quality, dupes, scores,
                 drift=None, pack_results=None, pack_name=None):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows, cols = df.shape
    print()
    print(f"{B}{'═'*64}{R}")
    print(f"{B}  DATA HEALTH REPORT  v2{R}")
    print(f"  File    : {file_path}")
    print(f"  Scanned : {ts}")
    print(f"  Shape   : {rows:,} rows  x  {cols} columns")
    print(f"{'═'*64}{R}")

    ov = scores["overall"]
    print(f"\n{B}  OVERALL SCORE{R}")
    print(f"  {_c(ov)}{B}{ov:>3}/100{R}  {scores['grade']}")
    print(f"  {_c(ov)}{_bar(ov)}{R}")
    if scores.get("pack_penalty"):
        print(f"  {YEL}(minus {scores['pack_penalty']} pts from failed business logic checks){R}")
    print(f"\n  {'Dimension':<16} {'Score':>5}  Bar")
    print(f"  {'─'*16} {'─'*5}  {'─'*BAR}")
    for label, key in [("Privacy","privacy"),("Quality","quality"),("Completeness","completeness")]:
        s = scores[key]
        print(f"  {label:<16} {_c(s)}{s:>4}%{R}  {_c(s)}{_bar(s)}{R}")

    if drift and drift["status"] != "no_baseline":
        print(f"\n{'─'*64}")
        print(f"{B}  SCHEMA DRIFT{R}")
        print(f"{'─'*64}")
        if drift["status"] == "stable":
            print(f"  {GRN}✓ Schema stable (baseline: {drift['baseline_date'][:10]}){R}")
        else:
            for a in drift["alerts"]:  print(f"  {RED}ALERT  {a['message']}{R}")
            for c in drift["changes"]: print(f"  {YEL}CHANGE {c['message']}{R}")

    high = scores["pii_high_count"]; med = scores["pii_medium_count"]; low = scores["pii_low_count"]
    print(f"\n{'─'*64}")
    print(f"{B}  PII EXPOSURE{R}  —  {RED}{high} HIGH{R}  {YEL}{med} MEDIUM{R}  {low} LOW")
    print(f"{'─'*64}")
    if not pii_findings:
        print(f"  {GRN}✓ No PII detected at current sensitivity level.{R}")
    else:
        cur = None
        for f in pii_findings:
            if f["pii_type"] != cur:
                cur = f["pii_type"]
                rc = RED if f["risk"]=="HIGH" else YEL if f["risk"]=="MEDIUM" else ""
                cnt = sum(1 for x in pii_findings if x["pii_type"]==cur)
                print(f"\n  {rc}▲ {cur}{R}  ({cnt} instance(s))")
            rc = RED if f["risk"]=="HIGH" else YEL if f["risk"]=="MEDIUM" else ""
            print(f"    row {f['row']:>4} | col: {f['column']:<22} | {rc}{f['masked']}{R}  [{f['risk']} {f['confidence']:.0%}]")
            print(f"           {f['reason']}")

    if pack_results:
        print(f"\n{'─'*64}")
        print(f"{B}  INDUSTRY PACK: {(pack_name or '').upper()}{R}")
        print(f"{'─'*64}")
        for r in pack_results:
            icon = f"{GRN}✓{R}" if r.get("passed") else f"{RED}✗{R}" if r.get("passed") is False else f"{YEL}?{R}"
            print(f"  {icon}  {r['check']}")
            if not r.get("passed"): print(f"       → {r['detail']}")

    print(f"\n{'─'*64}")
    print(f"{B}  DATA QUALITY{R}  —  {quality['passed']}/{quality['total_checks']} passed")
    print(f"{'─'*64}")
    for r in quality["results"]:
        icon = f"{GRN}✓{R}" if r["passed"] else f"{RED}✗{R}"
        col_label = f"[{r['column']}]" if r["column"] != "—" else ""
        print(f"  {icon}  {r['check']:<44} {col_label}")
        if not r["passed"] and r.get("details"):
            d = r["details"]
            if "unexpected_count" in d:
                print(f"       → {d['unexpected_count']} bad value(s)  ({d.get('unexpected_percent',0):.1f}%)")

    print(f"\n{'─'*64}")
    print(f"{B}  DUPLICATES{R}")
    print(f"{'─'*64}")
    print(f"  Exact : {dupes['exact_duplicates']:,}  ({dupes['duplicate_pct']}%)")
    print(f"  Near  : {dupes['near_duplicates']:,}")

    print(f"\n{'─'*64}")
    print(f"{B}  RECOMMENDATIONS{R}")
    print(f"{'─'*64}")
    recs = []
    if high:    recs.append((RED, f"[CRITICAL] Mask/remove {high} HIGH-confidence PII instance(s) immediately."))
    if med:     recs.append((YEL, f"[WARNING]  Review {med} MEDIUM-confidence PII finding(s)."))
    if low:     recs.append(("",  f"[INFO]     {low} LOW-confidence finding(s) — likely false positives."))
    if quality["failed"]: recs.append((YEL, f"[WARNING]  Fix {quality['failed']} quality rule failure(s)."))
    if dupes["exact_duplicates"]: recs.append((YEL, f"[WARNING]  Deduplicate {dupes['exact_duplicates']} exact row(s)."))
    if drift and drift.get("alerts"): recs.append((RED, "[CRITICAL] Schema drift — review newly added sensitive columns."))
    if ov < 70: recs.append(("",  "[INFO]     Automate scanning on every file upload (Lambda + S3)."))
    if not recs: recs.append((GRN, "Data is healthy. Automate monitoring to maintain this score."))
    for i, (color, rec) in enumerate(recs, 1):
        print(f"  {i}. {color}{rec}{R}")
    print(f"\n{'═'*64}\n")


# ─────────────────────────────────────────────────────────────────────────────
# 8. SAMPLE DATA GENERATOR
# ─────────────────────────────────────────────────────────────────────────────

def generate_sample_csv(path="sample_customers.csv"):
    data = {
        "customer_id": [1,2,3,None,5,6,7,8,9,10],
        "name": ["Alice Johnson","Bob Smith","Carol White","Dave Brown","Eve Davis",
                 "Frank Miller","Grace Wilson","Henry Moore","Iris Taylor","James Anderson"],
        "email": ["alice@acme.com","not-an-email","carol@acme.com","dave@acme.com",
                  "eve@acme.com","frank@acme.com","grace@acme.com","henry@acme.com",
                  "iris@acme.com","james@acme.com"],
        "age": [28,-3,34,150,22,45,31,52,27,38],
        "zip_code": ["30001","30002","XXXXX","30004","30005","30006","30007","30008","30009","30010"],
        "revenue": [1200,450,-50,890,2100,300,780,1500,620,940],
        # serial_number column — should produce LOW confidence for pattern matches
        "serial_number": ["372-88-3412","415-555-0199","SN-00123","SN-00124","SN-00125",
                          "SN-00126","SN-00127","SN-00128","SN-00129","SN-00130"],
        "notes": [
            "Preferred customer. SSN: 372-88-3412",       # HIGH — SSN in free text
            "Call on 415-555-0199 after 3pm",             # HIGH — phone in free text
            "VIP — card on file 4111-1111-1111-1111",     # HIGH — credit card
            "Standard account",
            "Referred by Eve. DOB: 03/15/1985",           # HIGH — DOB in free text
            "Regular customer","Premium tier","Seasonal buyer","New account","New account",
        ],
        "signup_date": pd.date_range("2024-01-01", periods=10, freq="ME").astype(str),
    }
    df = pd.DataFrame(data)
    df = pd.concat([df, df.iloc[[9]]], ignore_index=True)
    df.to_csv(path, index=False)
    print(f"  Sample CSV written → {path}  ({len(df)} rows)")
    return path


# ─────────────────────────────────────────────────────────────────────────────
# 9. MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Data Health Check v2")
    parser.add_argument("--file", "-f")
    parser.add_argument("--config", "-c", default=None)
    parser.add_argument("--output", "-o", default=None)
    parser.add_argument("--sensitivity", choices=["low","medium","high"], default="medium")
    parser.add_argument("--pack", choices=list(INDUSTRY_PACKS.keys()))
    parser.add_argument("--schema", default=None, help="Path to baseline schema JSON")
    parser.add_argument("--save-schema", action="store_true")
    args = parser.parse_args()

    config = {}
    if args.config and Path(args.config).exists():
        with open(args.config) as f: config = json.load(f)

    if not args.file:
        print("\n  No --file specified. Generating sample data...\n")
        file_path = generate_sample_csv()
    else:
        file_path = args.file

    if not Path(file_path).exists():
        print(f"Error: file not found → {file_path}"); sys.exit(1)

    print(f"\n  Loading {file_path} ...")
    df = pd.read_csv(file_path, dtype=str, low_memory=False)
    for col in df.columns:
        try: df[col] = pd.to_numeric(df[col])
        except (ValueError, TypeError): pass

    print(f"  Scanning {len(df):,} rows x {len(df.columns)} columns ...")
    print(f"  Sensitivity: {args.sensitivity.upper()}  |  Pack: {args.pack or 'none'}\n")

    if args.save_schema:
        save_schema_baseline(df, args.schema or file_path.replace(".csv","_schema.json"))
        return

    drift = None
    if args.schema:
        print("  [0/4] Schema drift check ...")
        drift = detect_schema_drift(df, args.schema)

    print(f"  [1/4] PII detection ({args.sensitivity}) ...")
    pii_findings = scan_for_pii(df, sensitivity=args.sensitivity)

    print("  [2/4] Data quality checks ...")
    quality = run_quality_checks(df, build_expectation_suite(df, config))

    print("  [3/4] Duplicate analysis ...")
    dupes = check_duplicates(df)

    pack_results = None
    if args.pack:
        print(f"  [4/4] {args.pack} industry pack ...")
        pack_results = INDUSTRY_PACKS[args.pack](df)
    else:
        print("  [4/4] No industry pack (--pack ecommerce|finance|healthcare)")

    scores = calculate_score(pii_findings, quality, dupes, len(df), pack_results)
    print_report(file_path, df, pii_findings, quality, dupes, scores,
                 drift=drift, pack_results=pack_results, pack_name=args.pack)

    if args.output:
        out = {
            "file": file_path, "scanned_at": datetime.now().isoformat(),
            "sensitivity": args.sensitivity,
            "shape": {"rows": len(df), "columns": len(df.columns)},
            "scores": scores,
            "pii_by_risk": {"HIGH": scores["pii_high_count"],
                            "MEDIUM": scores["pii_medium_count"],
                            "LOW": scores["pii_low_count"]},
            "quality": {"total": quality["total_checks"],
                        "passed": quality["passed"], "failed": quality["failed"]},
            "duplicates": dupes, "schema_drift": drift,
            "pack": args.pack, "pack_results": pack_results,
        }
        with open(args.output, "w") as f:
            json.dump(out, f, indent=2, default=str)
        print(f"  JSON report saved → {args.output}\n")


if __name__ == "__main__":
    main()
