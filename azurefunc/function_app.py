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

def remediate(df, pii_findings, mask=True, dedup=True):
    clean = df.copy()
    if dedup: clean = clean.drop_duplicates().reset_index(drop=True)
    if mask:
        clean = clean.astype(str)
        for h in pii_findings:
            if h["risk"] in ("HIGH","MEDIUM"):
                try:
                    ci = clean.columns.get_loc(h["column"]); ri = h["row"]; rv = h.get("raw_value","")
                    if ri < len(clean) and rv:
                        clean.iloc[ri,ci] = str(clean.iloc[ri,ci]).replace(rv, h["masked"])
                except: pass
    return clean

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

def save_clean(clean_df, filename):
    try:
        svc = get_blob_svc(); name = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_clean_{filename}"
        svc.get_blob_client(container=os.environ.get("AZURE_CLEANSED_CONTAINER","cleansed"), blob=name)\
           .upload_blob(clean_df.to_csv(index=False), overwrite=True)
        return name
    except Exception as e: logging.error(f"save_clean failed: {e}"); return ""

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

# ── BLOB TRIGGER — fully automated ───────────────────────────────────────────
@app.blob_trigger(arg_name="myblob", path="incoming/{name}", connection="AzureWebJobsStorage")
def BlobTriggerScanner(myblob: func.InputStream):
    filename = myblob.name.split("/")[-1]
    logging.info(f"Blob trigger: {filename} ({myblob.length} bytes)")
    if not filename.lower().endswith(".csv"): return
    try:
        df = pd.read_csv(io.BytesIO(myblob.read()), dtype=str, low_memory=False)
        for col in df.columns:
            try: df[col] = pd.to_numeric(df[col])
            except: pass
        sensitivity = os.environ.get("DEFAULT_SENSITIVITY","medium")
        result = run_scan(df, filename, sensitivity); result["trigger"] = "blob_automatic"
        result["saved_to_blob"]  = save_json(result, filename)
        result["cleansed_blob"]  = save_clean(remediate(df, result["pii_findings"]), filename)
        if should_alert(result["scores"]):
            send_alert(filename, result["scores"], result["pii_findings"], result["quality"], result["duplicates"])
        # Gold layer — append metrics row
        update_metrics(result)
        logging.info(f"Blob scan done: {filename} score={result['scores']['overall']}/100")
    except Exception as e: logging.error(f"Blob trigger error: {e}")

# ── HTTP TRIGGER — manual + dashboard ────────────────────────────────────────
@app.route(route="DataGuardScanner", methods=["POST","GET"])
def DataGuardScanner(req: func.HttpRequest) -> func.HttpResponse:
    if req.method == "GET":
        return func.HttpResponse(json.dumps({"status":"online","service":"DataGuard-Pro","version":"v3.0",
            "triggers":["HTTP","Blob auto on incoming/ upload"]}), mimetype="application/json", status_code=200)
    try:
        sensitivity = req.params.get("sensitivity","medium"); filename = req.params.get("filename","upload.csv")
        body = req.get_body()
        if not body: return func.HttpResponse(json.dumps({"error":"No CSV in body"}), mimetype="application/json", status_code=400)
        df = pd.read_csv(io.StringIO(body.decode("utf-8")), dtype=str, low_memory=False)
        for col in df.columns:
            try: df[col] = pd.to_numeric(df[col])
            except: pass
        result = run_scan(df, filename, sensitivity); result["trigger"] = "http_manual"
        result["saved_to_blob"] = save_json(result, filename)
        result["cleansed_blob"] = save_clean(remediate(df, result["pii_findings"]), filename)
        if should_alert(result["scores"]):
            send_alert(filename, result["scores"], result["pii_findings"], result["quality"], result["duplicates"])
        # Gold layer — append metrics row
        update_metrics(result)
        return func.HttpResponse(json.dumps(result,indent=2,default=str), mimetype="application/json", status_code=200)
    except Exception as e:
        logging.error(f"HTTP error: {e}")
        return func.HttpResponse(json.dumps({"error":str(e)}), mimetype="application/json", status_code=500)