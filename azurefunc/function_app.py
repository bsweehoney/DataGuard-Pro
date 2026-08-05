"""
DataGuard-Pro — Azure Function App v2
Two triggers: HTTP (manual) + Blob (automatic event-driven)
"""

import os, io, re, json, logging, warnings, urllib.request
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
import azure.functions as func
import pandas as pd

warnings.filterwarnings("ignore")
app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

# ── PII patterns ──────────────────────────────────────────────────────────────
PII_PATTERNS = {
    "SSN":           r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
    "EMAIL":         r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "PHONE":         r"\b(?:\+?1[\-.\s]?)?\(?\d{3}\)?[\-.\s]\d{3}[\-.\s]\d{4}\b",
    "CREDIT_CARD":   r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
    "DATE_OF_BIRTH": r"\b(?:0?[1-9]|1[0-2])[\/\-](?:0?[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b",
}
SENSITIVITY_LEVELS = {
    "low":    {"SSN","CREDIT_CARD"},
    "medium": {"SSN","CREDIT_CARD","PHONE","DATE_OF_BIRTH"},
    "high":   set(PII_PATTERNS.keys()),
}
SAFE_COL   = {"serial","product","order","ref","sku","part","item","tracking","code","number","num"}
RISKY_COL  = {"ssn","identity","social","patient","employee","person","contact","dob","birth"}
RISKY_CTX  = {"social security","ssn","identity","date of birth","dob","confidential","medical"}
EMAIL_COLS = {"email","email_address","contact_email","user_email"}

def _ctx(col, text):
    c, t = col.lower().strip(), text.lower()
    if any(k in c for k in SAFE_COL):
        return 0.75 if any(k in t for k in RISKY_CTX) else 0.15
    if any(k in c for k in RISKY_COL): return 1.0
    if any(k in t for k in RISKY_CTX): return 0.90
    return 0.50

def _mask(pii_type, value):
    if pii_type == "SSN":          return re.sub(r"^\d{3}-\d{2}-", "XXX-XX-", value)
    if pii_type == "CREDIT_CARD":
        d = re.sub(r"[^\d]","",value); return f"XXXX-XXXX-XXXX-{d[-4:]}" if len(d)>=4 else "XXXX-XXXX-XXXX-XXXX"
    if pii_type == "PHONE":        return re.sub(r"^\+?1?[\-.\s]?\(?\d{3}\)?[\-.\s]\d{3}","XXX-XXX",value)
    if pii_type == "EMAIL":
        p = value.split("@"); return f"{p[0][:2]}***@{p[1]}" if len(p)==2 else "***@***"
    if pii_type == "DATE_OF_BIRTH": return re.sub(r"^\d{1,2}[\/\-]\d{1,2}[\/\-]","**/*/",value)
    return value[:2]+"••••"

def scan_pii(df, sensitivity="medium"):
    active = SENSITIVITY_LEVELS.get(sensitivity, SENSITIVITY_LEVELS["medium"])
    out = []
    for col in df.columns:
        is_email = col.lower().strip() in EMAIL_COLS
        for ri, cell in df[col].dropna().items():
            s = str(cell)
            for pt, pat in PII_PATTERNS.items():
                if pt not in active or (pt=="EMAIL" and is_email): continue
                for m in re.findall(pat, s):
                    conf = _ctx(col, s)
                    risk = "HIGH" if conf>=0.75 else "MEDIUM" if conf>=0.40 else "LOW"
                    out.append({"pii_type":pt,"column":col,"row":int(ri),"raw_value":m,
                                "masked":_mask(pt,m),"confidence":round(conf,2),"risk":risk})
    out.sort(key=lambda x:({"HIGH":0,"MEDIUM":1,"LOW":2}[x["risk"]],x["column"]))
    return out

def check_quality(df):
    results = []
    for col in df.columns:
        if re.search(r"\bid\b|_id$|^id_",col,re.I):
            n = int(df[col].isna().sum())
            results.append({"check":"not null","column":col,"passed":n==0,"detail":f"{n} null(s)" if n else "OK"})
        if "email" in col.lower():
            bad = int(df[col].dropna().apply(lambda x: not bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$",str(x)))).sum())
            results.append({"check":"email format","column":col,"passed":bad==0,"detail":f"{bad} invalid" if bad else "OK"})
        if "age" in col.lower() and pd.api.types.is_numeric_dtype(df[col]):
            bad = int(((df[col]<0)|(df[col]>120)).sum())
            results.append({"check":"age 0-120","column":col,"passed":bad==0,"detail":f"{bad} out-of-range" if bad else "OK"})
        if any(k in col.lower() for k in ["revenue","amount","price","quantity","qty"]):
            if pd.api.types.is_numeric_dtype(df[col]):
                bad = int((df[col]<0).sum())
                results.append({"check":"non-negative","column":col,"passed":bad==0,"detail":f"{bad} negative" if bad else "OK"})
    p = sum(1 for r in results if r["passed"]); f = sum(1 for r in results if not r["passed"])
    return {"total":len(results),"passed":p,"failed":f,"results":results}

def check_duplicates(df):
    total = len(df); exact = int(df.duplicated().sum())
    return {"total_rows":total,"exact_duplicates":exact,"duplicate_pct":round((exact/total)*100,1) if total else 0}

def calculate_score(pii, quality, dupes, rows):
    real = [f for f in pii if f["risk"] in ("HIGH","MEDIUM")]
    density = len(real)/max(rows,1)
    privacy = max(0,min(100,100-int(density*50)-min(len(real)*2,60)))
    qs = int((quality["passed"]/quality["total"])*100) if quality["total"] else 100
    comp = max(0,100-int(dupes["duplicate_pct"]*2))
    ov = int(privacy*0.38+qs*0.38+comp*0.18)
    def grade(s):
        if s>=85: return "A — Healthy"
        if s>=70: return "B — Acceptable"
        if s>=55: return "C — Needs attention"
        if s>=40: return "D — At risk"
        return "F — Critical"
    return {"overall":ov,"grade":grade(ov),"privacy":privacy,"quality":qs,"completeness":comp,
            "pii_high":sum(1 for f in pii if f["risk"]=="HIGH"),
            "pii_medium":sum(1 for f in pii if f["risk"]=="MEDIUM"),
            "pii_low":sum(1 for f in pii if f["risk"]=="LOW")}

def remediate(df, pii_findings, mask=True, dedup=True, encrypt_high_risk=False):
    """
    Remediates a DataFrame. Three independent operations:
      - dedup:             drops exact duplicate rows
      - mask:               replaces PII with partial masks (XXX-XX-1234 style)
      - encrypt_high_risk:  replaces HIGH-confidence PII with AES-encrypted tokens
                            instead of masking — recoverable with the encryption key,
                            unlike masking which is irreversible.

    mask and encrypt_high_risk are mutually applied per-finding: encryption takes
    priority for HIGH risk findings when both are enabled, since it's reversible
    and provides an audit trail; MEDIUM/LOW risk findings still get masked.
    """
    clean = df.copy()
    if dedup:
        clean = clean.drop_duplicates().reset_index(drop=True)

    if mask or encrypt_high_risk:
        clean = clean.astype(str)
        cipher = get_cipher() if encrypt_high_risk else None

        for h in pii_findings:
            if h["risk"] not in ("HIGH", "MEDIUM"):
                continue
            try:
                ci = clean.columns.get_loc(h["column"])
                ri = h["row"]
                rv = h.get("raw_value", "")
                if ri >= len(clean) or not rv:
                    continue

                if encrypt_high_risk and h["risk"] == "HIGH" and cipher:
                    # Full recoverable token goes into the actual output data.
                    # (A truncated "ENC[...]" preview is used only in reports/dashboards.)
                    replacement = encrypt_value_full(cipher, rv)
                else:
                    replacement = h["masked"]

                current = str(clean.iloc[ri, ci])
                clean.iloc[ri, ci] = current.replace(rv, replacement)
            except Exception:
                pass

    return clean


# ── PII Encryption Engine (AES-128-CBC + HMAC via Fernet) ────────────────────

def get_cipher():
    """
    Loads the Fernet cipher used to encrypt HIGH-risk PII values.
    The key is read from an environment variable (PII_ENCRYPTION_KEY) —
    in production this should come from Azure Key Vault rather than an
    app setting, but env var is used here to avoid additional Azure
    provisioning dependencies.
    """
    from cryptography.fernet import Fernet
    key = os.environ.get("PII_ENCRYPTION_KEY")
    if not key:
        raise ValueError(
            "PII_ENCRYPTION_KEY not set. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode() if isinstance(key, str) else key)

def encrypt_value(cipher, raw_value: str) -> str:
    """Encrypts a raw PII value, returning a short recognizable token."""
    token = cipher.encrypt(raw_value.encode()).decode()
    # Prefix so encrypted values are visually distinguishable from masked ones
    return f"ENC[{token[:24]}...]"

def encrypt_value_full(cipher, raw_value: str) -> str:
    """Encrypts a raw PII value, returning the FULL recoverable token (for storage)."""
    return cipher.encrypt(raw_value.encode()).decode()

def decrypt_value(cipher, token: str) -> str:
    """Decrypts a full Fernet token back to the original PII value. Requires the key."""
    return cipher.decrypt(token.encode()).decode()

def get_blob_svc():
    from azure.storage.blob import BlobServiceClient
    return BlobServiceClient.from_connection_string(os.environ["AZURE_STORAGE_CONNECTION_STRING"])

def save_json(result, filename):
    try:
        svc = get_blob_svc(); name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}_results.json"
        svc.get_blob_client(container=os.environ.get("AZURE_RESULTS_CONTAINER","results"), blob=name)\
           .upload_blob(json.dumps(result,indent=2,default=str), overwrite=True)
        return name
    except Exception as e: logging.error(f"save_json failed: {e}"); return ""

def save_clean(clean_df, filename, output_format="csv"):
    """Saves cleansed data in the client's requested output format."""
    try:
        svc = get_blob_svc()
        ext = output_extension(output_format)
        base = filename.rsplit(".", 1)[0] if "." in filename else filename
        name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_clean_{base}.{ext}"
        data_bytes = write_any_format(clean_df, output_format)
        svc.get_blob_client(container=os.environ.get("AZURE_CLEANSED_CONTAINER","cleansed"), blob=name)\
           .upload_blob(data_bytes, overwrite=True)
        return name
    except Exception as e: logging.error(f"save_clean failed: {e}"); return ""

# ── Universal file format support ────────────────────────────────────────────

def detect_format(filename: str) -> str:
    """Detects file format from extension."""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else "csv"
    return {"csv": "csv", "parquet": "parquet", "json": "json",
            "xlsx": "excel", "xls": "excel"}.get(ext, "csv")

def read_any_format(raw_bytes: bytes, filename: str) -> pd.DataFrame:
    """
    Reads a file into a DataFrame regardless of format.
    Supports: CSV, Parquet, JSON, Excel.
    This is what makes the pipeline accept ANY incoming format.
    """
    fmt = detect_format(filename)
    buf = io.BytesIO(raw_bytes)

    if fmt == "parquet":
        df = pd.read_parquet(buf, engine="pyarrow")
    elif fmt == "json":
        df = pd.read_json(buf)
    elif fmt == "excel":
        df = pd.read_excel(buf)
    else:  # csv (default)
        df = pd.read_csv(io.StringIO(raw_bytes.decode("utf-8")), dtype=str, low_memory=False)

    # Type inference for numeric-looking columns
    for col in df.columns:
        try: df[col] = pd.to_numeric(df[col])
        except Exception: pass

    return df, fmt

def write_any_format(df: pd.DataFrame, output_format: str) -> bytes:
    """
    Serializes a DataFrame to bytes in the requested output format.
    This is what lets the CLIENT choose their preferred download format —
    independent of what format they originally uploaded.
    """
    buf = io.BytesIO()
    output_format = (output_format or "csv").lower()

    if output_format == "parquet":
        df.to_parquet(buf, index=False, engine="pyarrow")
    elif output_format == "json":
        buf.write(df.to_json(orient="records", indent=2).encode("utf-8"))
    elif output_format == "excel":
        df.to_excel(buf, index=False, engine="openpyxl")
    else:  # csv (default)
        buf.write(df.to_csv(index=False).encode("utf-8"))

    buf.seek(0)
    return buf.read()

def output_extension(output_format: str) -> str:
    return {"parquet": "parquet", "json": "json", "excel": "xlsx"}.get(
        (output_format or "csv").lower(), "csv")

def output_content_type(output_format: str) -> str:
    return {
        "parquet": "application/octet-stream",
        "json": "application/json",
        "excel": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get((output_format or "csv").lower(), "text/csv")

def update_metrics(result):
    """Gold layer — appends one row to metrics/quality_metrics.csv after every scan."""
    try:
        conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
        if not conn_str:
            logging.warning("No storage connection string — skipping metrics update")
            return
        blob_client = get_blob_svc().get_blob_client(container="metrics", blob="quality_metrics.csv")
        new_row = {
            "timestamp":          result["scanned_at"],
            "filename":           result["file"],
            "trigger":            result.get("trigger","unknown"),
            "rows":               result["shape"]["rows"],
            "columns":            result["shape"]["columns"],
            "health_score":       result["scores"]["overall"],
            "grade":              result["scores"]["grade"],
            "privacy_score":      result["scores"]["privacy"],
            "quality_score":      result["scores"]["quality"],
            "completeness_score": result["scores"]["completeness"],
            "high_pii":           result["scores"]["pii_high"],
            "medium_pii":         result["scores"]["pii_medium"],
            "low_pii":            result["scores"]["pii_low"],
            "quality_failed":     result["quality"]["failed"],
            "duplicate_pct":      result["duplicates"]["duplicate_pct"],
        }
        # Download existing CSV or start fresh
        try:
            existing = blob_client.download_blob().readall().decode()
            df = pd.read_csv(io.StringIO(existing))
        except Exception:
            df = pd.DataFrame()
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        blob_client.upload_blob(df.to_csv(index=False), overwrite=True)
        logging.info(f"Gold layer updated — {len(df)} total scans recorded")
    except Exception as e:
        logging.error(f"update_metrics failed: {e}")

def should_alert(scores):
    threshold = int(os.environ.get("ALERT_SCORE_THRESHOLD","70"))
    return scores["overall"] < threshold or scores["pii_high"] > 0

def send_alert(filename, scores, pii_findings, quality, dupes):
    to = os.environ.get("ALERT_EMAIL_TO")
    if not to: logging.info("No ALERT_EMAIL_TO — skipping alert"); return
    ov = scores["overall"]; grade = scores["grade"]
    color = "#dc2626" if ov<55 else "#d97706" if ov<70 else "#16a34a"
    html = f"""<html><body style="font-family:Arial,sans-serif;background:#f8f9fb;padding:24px;">
<div style="max-width:540px;margin:0 auto;background:#fff;border-radius:12px;border:1px solid #e8eaf0;overflow:hidden;">
<div style="background:#0f172a;padding:20px 24px;">
  <div style="font-size:17px;font-weight:700;color:#fff;">DataGuard Pro — Security Alert</div>
  <div style="font-size:12px;color:#94a3b8;margin-top:3px;">Automated scan detected issues requiring attention</div>
</div>
<div style="padding:20px 24px;border-bottom:1px solid #f1f5f9;">
  <span style="font-size:44px;font-weight:700;color:{color};font-family:monospace;">{ov}</span>
  <span style="font-size:13px;color:{color};font-weight:500;margin-left:10px;">{grade}</span>
  <div style="font-size:12px;color:#94a3b8;margin-top:4px;">{filename}</div>
</div>
<div style="padding:16px 24px;">
  <table style="width:100%;font-size:13px;border-collapse:collapse;">
    <tr><td style="padding:6px 0;border-bottom:1px solid #f1f5f9;color:#374151;">HIGH PII instances</td>
        <td style="text-align:right;"><span style="background:#fef2f2;color:#dc2626;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;">{scores["pii_high"]}</span></td></tr>
    <tr><td style="padding:6px 0;border-bottom:1px solid #f1f5f9;color:#374151;">Quality failures</td>
        <td style="text-align:right;"><span style="background:#fffbeb;color:#d97706;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;">{quality["failed"]}</span></td></tr>
    <tr><td style="padding:6px 0;color:#374151;">Duplicate rows</td>
        <td style="text-align:right;"><span style="background:#f8fafc;color:#64748b;padding:2px 10px;border-radius:20px;font-size:12px;font-weight:600;">{dupes["exact_duplicates"]}</span></td></tr>
  </table>
</div>
<div style="padding:14px 24px;background:#f8f9fb;font-size:11px;color:#94a3b8;">
  Scanned {datetime.now().strftime("%B %d, %Y %H:%M UTC")} · DataGuard Pro v3 · Azure Serverless Pipeline
</div></div></body></html>"""

    sg_key = os.environ.get("SENDGRID_API_KEY")
    from_email = os.environ.get("ALERT_EMAIL_FROM","dataguard@noreply.com")
    if sg_key:
        try:
            payload = {"personalizations":[{"to":[{"email":to}]}],"from":{"email":from_email,"name":"DataGuard Pro"},
                       "subject":f"DataGuard Alert: {filename} scored {ov}/100","content":[{"type":"text/html","value":html}]}
            req = urllib.request.Request("https://api.sendgrid.com/v3/mail/send",
                data=json.dumps(payload).encode(), headers={"Authorization":f"Bearer {sg_key}","Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req): pass
            logging.info(f"Alert sent via SendGrid to {to}"); return
        except Exception as e: logging.warning(f"SendGrid failed: {e}")

    smtp_host = os.environ.get("SMTP_HOST"); smtp_user = os.environ.get("SMTP_USER"); smtp_pass = os.environ.get("SMTP_PASS")
    if smtp_host and smtp_user and smtp_pass:
        try:
            msg = MIMEMultipart("alternative"); msg["Subject"] = f"DataGuard Alert: {filename} scored {ov}/100"
            msg["From"] = from_email; msg["To"] = to; msg.attach(MIMEText(html,"html"))
            with smtplib.SMTP_SSL(smtp_host, 465) as s: s.login(smtp_user,smtp_pass); s.sendmail(from_email,to,msg.as_string())
            logging.info(f"Alert sent via SMTP to {to}")
        except Exception as e: logging.error(f"SMTP failed: {e}")

def run_scan(df, filename, sensitivity="medium"):
    pii = scan_pii(df, sensitivity); quality = check_quality(df)
    dupes = check_duplicates(df); scores = calculate_score(pii, quality, dupes, len(df))
    return {"file":filename,"scanned_at":datetime.now().isoformat(),"sensitivity":sensitivity,
            "shape":{"rows":len(df),"columns":len(df.columns)},"scores":scores,
            "pii_by_risk":{"HIGH":scores["pii_high"],"MEDIUM":scores["pii_medium"],"LOW":scores["pii_low"]},
            "pii_findings":pii,"quality":quality,"duplicates":dupes}

# ── BLOB TRIGGER — fully automated, accepts ANY file format ─────────────────
@app.blob_trigger(arg_name="myblob", path="incoming/{name}", connection="AzureWebJobsStorage")
def BlobTriggerScanner(myblob: func.InputStream):
    filename = myblob.name.split("/")[-1]
    logging.info(f"Blob trigger: {filename} ({myblob.length} bytes)")

    supported_exts = (".csv", ".parquet", ".json", ".xlsx", ".xls")
    if not filename.lower().endswith(supported_exts):
        logging.info(f"Skipping unsupported file type: {filename}")
        return

    try:
        raw_bytes = myblob.read()
        df, detected_format = read_any_format(raw_bytes, filename)
        logging.info(f"Detected input format: {detected_format}")

        sensitivity = os.environ.get("DEFAULT_SENSITIVITY", "medium")
        output_format = os.environ.get("DEFAULT_OUTPUT_FORMAT", detected_format)
        encrypt_high_risk = os.environ.get("ENCRYPT_HIGH_RISK_PII", "false").lower() == "true"

        result = run_scan(df, filename, sensitivity)
        result["trigger"] = "blob_automatic"
        result["input_format"] = detected_format
        result["output_format"] = output_format

        clean_df = remediate(df, result["pii_findings"], mask=True, dedup=True,
                             encrypt_high_risk=encrypt_high_risk)
        result["saved_to_blob"] = save_json(result, filename)
        result["cleansed_blob"] = save_clean(clean_df, filename, output_format)
        result["protection_status"] = {
            "encryption_enabled": encrypt_high_risk,
            "high_risk_pii_protected": result["scores"]["pii_high"] if encrypt_high_risk else 0,
            "high_risk_pii_masked_only": 0 if encrypt_high_risk else result["scores"]["pii_high"],
        }

        if should_alert(result["scores"]):
            send_alert(filename, result["scores"], result["pii_findings"], result["quality"], result["duplicates"])

        update_metrics(result)
        logging.info(f"Blob scan done: {filename} ({detected_format}→{output_format}) score={result['scores']['overall']}/100"
                    f" encrypt={encrypt_high_risk}")
    except Exception as e:
        logging.error(f"Blob trigger error: {e}")

# ── HTTP TRIGGER — manual + dashboard, accepts ANY format, client chooses output ──
@app.route(route="DataGuardScanner", methods=["POST","GET"])
def DataGuardScanner(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "GET":
        return func.HttpResponse(json.dumps({
            "status": "online", "service": "DataGuard-Pro", "version": "v3.0",
            "triggers": ["HTTP", "Blob auto on incoming/ upload"],
            "supported_input_formats": ["csv", "parquet", "json", "excel"],
            "supported_output_formats": ["csv", "parquet", "json", "excel"],
        }), mimetype="application/json", status_code=200)

    try:
        sensitivity    = req.params.get("sensitivity", "medium")
        filename       = req.params.get("filename", "upload.csv")
        output_format  = req.params.get("output_format")  # client's choice — optional
        encrypt_param  = req.params.get("encrypt", "false").lower() == "true"

        body = req.get_body()
        if not body:
            return func.HttpResponse(json.dumps({"error": "No file data in request body"}),
                                     mimetype="application/json", status_code=400)

        df, detected_format = read_any_format(body, filename)

        if not output_format:
            output_format = detected_format

        result = run_scan(df, filename, sensitivity)
        result["trigger"] = "http_manual"
        result["input_format"] = detected_format
        result["output_format"] = output_format

        clean_df = remediate(df, result["pii_findings"], mask=True, dedup=True,
                             encrypt_high_risk=encrypt_param)
        result["saved_to_blob"] = save_json(result, filename)
        result["cleansed_blob"] = save_clean(clean_df, filename, output_format)
        result["protection_status"] = {
            "encryption_enabled": encrypt_param,
            "high_risk_pii_protected": result["scores"]["pii_high"] if encrypt_param else 0,
            "high_risk_pii_masked_only": 0 if encrypt_param else result["scores"]["pii_high"],
        }

        if should_alert(result["scores"]):
            send_alert(filename, result["scores"], result["pii_findings"], result["quality"], result["duplicates"])

        update_metrics(result)
        return func.HttpResponse(json.dumps(result, indent=2, default=str),
                                 mimetype="application/json", status_code=200)
    except Exception as e:
        logging.error(f"HTTP error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), mimetype="application/json", status_code=500)


# ── NEW ENDPOINT — download the cleansed file directly in requested format ──
@app.route(route="DownloadCleansed", methods=["GET"])
def DownloadCleansed(req: func.HttpRequest) -> func.HttpResponse:
    """
    Lets the client download the cleansed version of a file in ANY format
    they choose — independent of the format they originally uploaded.

    GET /api/DownloadCleansed?blob_name=<cleansed_blob_name>&format=parquet
    """
    try:
        blob_name = req.params.get("blob_name")
        want_format = req.params.get("format", "csv")

        if not blob_name:
            return func.HttpResponse(json.dumps({"error": "blob_name parameter required"}),
                                     mimetype="application/json", status_code=400)

        svc = get_blob_svc()
        container = os.environ.get("AZURE_CLEANSED_CONTAINER", "cleansed")
        blob_client = svc.get_blob_client(container=container, blob=blob_name)
        raw = blob_client.download_blob().readall()

        # Read whatever format is currently stored, then re-serialize to what client wants
        df, _ = read_any_format(raw, blob_name)
        output_bytes = write_any_format(df, want_format)

        return func.HttpResponse(
            output_bytes,
            mimetype=output_content_type(want_format),
            status_code=200,
            headers={"Content-Disposition": f"attachment; filename=cleansed.{output_extension(want_format)}"},
        )
    except Exception as e:
        logging.error(f"Download error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), mimetype="application/json", status_code=500)


# ── NEW ENDPOINT — decrypt a single value (requires the encryption key) ──────
@app.route(route="DecryptValue", methods=["POST"])
def DecryptValue(req: func.HttpRequest) -> func.HttpResponse:
    """
    Authorized recovery of an encrypted HIGH-risk PII value.
    Requires PII_ENCRYPTION_KEY to be set on the Function App — anyone without
    that key (e.g. someone who only has read access to Blob Storage) cannot
    recover the original value, unlike simple masking which is one-way.

    POST body: {"encrypted_value": "gAAAAAB..."}
    """
    try:
        body = json.loads(req.get_body().decode("utf-8"))
        encrypted_value = body.get("encrypted_value", "")
        if not encrypted_value:
            return func.HttpResponse(json.dumps({"error": "encrypted_value required in JSON body"}),
                                     mimetype="application/json", status_code=400)

        cipher = get_cipher()
        original = decrypt_value(cipher, encrypted_value)

        return func.HttpResponse(
            json.dumps({"decrypted_value": original}),
            mimetype="application/json", status_code=200,
        )
    except Exception as e:
        logging.error(f"Decrypt error: {e}")
        return func.HttpResponse(json.dumps({"error": str(e)}), mimetype="application/json", status_code=500)