"""
DataGuard-Pro — Azure Function
================================
HTTP-triggered function that:
1. Accepts a CSV file upload via POST request
2. Runs the full DataGuard scanner in memory
3. Saves results JSON to Azure Blob Storage (results container)
4. Returns the health score and findings as JSON response

Deploy with:
    func azure functionapp publish dataguard-func-app

Test locally with:
    func start
"""

import os
import io
import json
import logging
import warnings
import re
from datetime import datetime
from collections import defaultdict

import azure.functions as func
import pandas as pd

warnings.filterwarnings("ignore")

# ── Azure Function App ────────────────────────────────────────────────────────
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── PII Patterns ──────────────────────────────────────────────────────────────
PII_PATTERNS = {
    "SSN":           r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "EMAIL":         r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE":         r"\b(?:\+?1[\-.\s]?)?\(?\d{3}\)?[\-.\s]\d{3}[\-.\s]\d{4}\b",
    "CREDIT_CARD":   r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    "DATE_OF_BIRTH": r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b",
}

SENSITIVITY_LEVELS = {
    "low":    {"SSN", "CREDIT_CARD"},
    "medium": {"SSN", "CREDIT_CARD", "PHONE", "DATE_OF_BIRTH"},
    "high":   set(PII_PATTERNS.keys()),
}

SAFE_COL_KEYWORDS  = {"serial","product","order","ref","sku","part","item","tracking","code","number","num"}
RISKY_COL_KEYWORDS = {"ssn","identity","social","patient","employee","person","contact","dob","birth"}
RISKY_CONTEXT_WORDS= {"social security","ssn","identity","date of birth","dob","confidential","medical"}
ALLOWED_EMAIL_COLS = {"email","email_address","contact_email","user_email"}


def _context_score(col_name: str, cell_text: str) -> float:
    col_lower  = col_name.lower().strip()
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
    return value[:2] + "••••"


def scan_pii(df: pd.DataFrame, sensitivity: str = "medium") -> list:
    active = SENSITIVITY_LEVELS.get(sensitivity, SENSITIVITY_LEVELS["medium"])
    findings = []
    for col in df.columns:
        col_is_email = col.lower().strip() in ALLOWED_EMAIL_COLS
        for row_idx, cell in df[col].dropna().items():
            cell_str = str(cell)
            for pii_type, pattern in PII_PATTERNS.items():
                if pii_type not in active:
                    continue
                if pii_type == "EMAIL" and col_is_email:
                    continue
                for match in re.findall(pattern, cell_str):
                    confidence = _context_score(col, cell_str)
                    risk = "HIGH" if confidence >= 0.75 else "MEDIUM" if confidence >= 0.40 else "LOW"
                    findings.append({
                        "pii_type":   pii_type,
                        "column":     col,
                        "row":        int(row_idx),
                        "masked":     _mask_value(pii_type, match),
                        "confidence": round(confidence, 2),
                        "risk":       risk,
                    })
    findings.sort(key=lambda x: ({"HIGH":0,"MEDIUM":1,"LOW":2}[x["risk"]], x["column"]))
    return findings


def check_quality(df: pd.DataFrame) -> dict:
    results = []
    col_names = list(df.columns)

    # Null checks on ID columns
    id_cols = [c for c in col_names if re.search(r"\bid\b|_id$|^id_", c, re.I)]
    for col in id_cols:
        null_count = int(df[col].isna().sum())
        results.append({
            "check": "not null",
            "column": col,
            "passed": null_count == 0,
            "detail": f"{null_count} null value(s)" if null_count else "OK"
        })

    # Email format
    email_cols = [c for c in col_names if "email" in c.lower()]
    for col in email_cols:
        pattern = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
        bad = df[col].dropna().apply(lambda x: not bool(re.match(pattern, str(x)))).sum()
        results.append({
            "check": "email format",
            "column": col,
            "passed": int(bad) == 0,
            "detail": f"{int(bad)} invalid email(s)" if bad else "OK"
        })

    # Age range
    age_cols = [c for c in col_names if "age" in c.lower()]
    for col in age_cols:
        if pd.api.types.is_numeric_dtype(df[col]):
            bad = int(((df[col] < 0) | (df[col] > 120)).sum())
            results.append({
                "check": "age range 0-120",
                "column": col,
                "passed": bad == 0,
                "detail": f"{bad} out-of-range age(s)" if bad else "OK"
            })

    # Positive numeric columns
    pos_kw = ["revenue","amount","price","quantity","qty","score"]
    for col in col_names:
        if any(kw in col.lower() for kw in pos_kw):
            if pd.api.types.is_numeric_dtype(df[col]):
                bad = int((df[col] < 0).sum())
                results.append({
                    "check": f"non-negative ({col})",
                    "column": col,
                    "passed": bad == 0,
                    "detail": f"{bad} negative value(s)" if bad else "OK"
                })

    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    return {
        "total":   len(results),
        "passed":  passed,
        "failed":  failed,
        "results": results,
    }


def check_duplicates(df: pd.DataFrame) -> dict:
    total = len(df)
    exact = int(df.duplicated().sum())
    return {
        "total_rows":        total,
        "exact_duplicates":  exact,
        "duplicate_pct":     round((exact / total) * 100, 1) if total else 0,
    }


def calculate_score(pii_findings, quality, dupes, row_count) -> dict:
    real_pii    = [f for f in pii_findings if f["risk"] in ("HIGH","MEDIUM")]
    pii_density = len(real_pii) / max(row_count, 1)
    privacy     = max(0, min(100, 100 - int(pii_density * 50) - min(len(real_pii) * 2, 60)))
    quality_score = int((quality["passed"] / quality["total"]) * 100) if quality["total"] else 100
    completeness  = max(0, 100 - int(dupes["duplicate_pct"] * 2))
    overall       = int(privacy * 0.38 + quality_score * 0.38 + completeness * 0.18)

    def grade(s):
        if s >= 85: return "A — Healthy"
        if s >= 70: return "B — Acceptable"
        if s >= 55: return "C — Needs attention"
        if s >= 40: return "D — At risk"
        return "F — Critical"

    return {
        "overall":      overall,
        "grade":        grade(overall),
        "privacy":      privacy,
        "quality":      quality_score,
        "completeness": completeness,
        "pii_high":     sum(1 for f in pii_findings if f["risk"] == "HIGH"),
        "pii_medium":   sum(1 for f in pii_findings if f["risk"] == "MEDIUM"),
        "pii_low":      sum(1 for f in pii_findings if f["risk"] == "LOW"),
    }


def save_to_blob(result: dict, filename: str):
    """Save scan results JSON to Azure Blob Storage results container."""
    try:
        from azure.storage.blob import BlobServiceClient
        conn_str   = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
        container  = os.environ.get("AZURE_RESULTS_CONTAINER", "results")
        if not conn_str:
            logging.warning("No Azure storage connection string — skipping blob save")
            return
        client     = BlobServiceClient.from_connection_string(conn_str)
        blob_name  = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}_results.json"
        blob_client= client.get_blob_client(container=container, blob=blob_name)
        blob_client.upload_blob(json.dumps(result, indent=2, default=str), overwrite=True)
        logging.info(f"Results saved to blob: {blob_name}")
        return blob_name
    except Exception as e:
        logging.error(f"Blob save failed: {e}")
        return None


# ── Main HTTP trigger ─────────────────────────────────────────────────────────
@app.route(route="DataGuardScanner", methods=["POST", "GET"])
def DataGuardScanner(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("DataGuard-Pro scanner triggered")

    # ── Health check (GET request) ────────────────────────────────────────────
    if req.method == "GET":
        return func.HttpResponse(
            json.dumps({
                "status":  "online",
                "service": "DataGuard-Pro Scanner",
                "version": "v3.0",
                "endpoints": {
                    "scan": "POST /api/DataGuardScanner with CSV file in body",
                }
            }),
            mimetype="application/json",
            status_code=200,
        )

    # ── POST — scan the uploaded CSV ──────────────────────────────────────────
    try:
        # Get sensitivity from query params (default medium)
        sensitivity = req.params.get("sensitivity", "medium")
        if sensitivity not in ("low", "medium", "high"):
            sensitivity = "medium"

        # Read CSV from request body
        body = req.get_body()
        if not body:
            return func.HttpResponse(
                json.dumps({"error": "No CSV data in request body"}),
                mimetype="application/json",
                status_code=400,
            )

        # Parse CSV
        try:
            df = pd.read_csv(io.StringIO(body.decode("utf-8")), dtype=str, low_memory=False)
            for col in df.columns:
                try:
                    df[col] = pd.to_numeric(df[col])
                except (ValueError, TypeError):
                    pass
        except Exception as e:
            return func.HttpResponse(
                json.dumps({"error": f"Could not parse CSV: {str(e)}"}),
                mimetype="application/json",
                status_code=400,
            )

        filename = req.params.get("filename", "upload.csv")
        logging.info(f"Scanning {filename}: {len(df)} rows x {len(df.columns)} columns")

        # Run all scanners
        pii_findings = scan_pii(df, sensitivity=sensitivity)
        quality      = check_quality(df)
        dupes        = check_duplicates(df)
        scores       = calculate_score(pii_findings, quality, dupes, len(df))

        # Build result
        result = {
            "file":        filename,
            "scanned_at":  datetime.now().isoformat(),
            "sensitivity": sensitivity,
            "shape":       {"rows": len(df), "columns": len(df.columns)},
            "scores":      scores,
            "pii_by_risk": {
                "HIGH":   scores["pii_high"],
                "MEDIUM": scores["pii_medium"],
                "LOW":    scores["pii_low"],
            },
            "pii_findings": pii_findings,
            "quality":      quality,
            "duplicates":   dupes,
        }

        # Save to Azure Blob Storage
        blob_name = save_to_blob(result, filename)
        if blob_name:
            result["saved_to_blob"] = blob_name

        logging.info(f"Scan complete — score: {scores['overall']}/100")

        return func.HttpResponse(
            json.dumps(result, indent=2, default=str),
            mimetype="application/json",
            status_code=200,
        )

    except Exception as e:
        logging.error(f"Scanner error: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            mimetype="application/json",
            status_code=500,
        )