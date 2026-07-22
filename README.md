# DataGuard-Pro 

> An event-driven data governance platform implementing Medallion Architecture on Azure — automated PII scanning, data quality validation, schema drift detection, and Gold-layer analytics for small and medium enterprises.


---

## Overview

DataGuard-Pro is a production-grade data governance platform targeting SMEs that lack the budget for enterprise compliance tooling. It scans CSV datasets in memory — detecting hidden PII, validating data quality, monitoring schema changes, and generating audit reports — without ever persisting raw data.

GDPR fines reach €20 million. CCPA fines are $750 per consumer per incident. Most SMEs have no tooling to detect the data exposure that triggers these fines. DataGuard-Pro fills that gap at ~$0.001 per scan.

---

## Architecture — Medallion Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                    EVENT-DRIVEN PIPELINE                         │
│                                                                  │
│  CSV Upload                                                      │
│      │                                                           │
│      ▼                                                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           Azure Blob Storage (Bronze Layer)              │    │
│  │                   incoming/                              │    │
│  └─────────────────────────┬───────────────────────────────┘    │
│                             │ Blob Trigger (automatic)           │
│                             ▼                                    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Azure Function (Scanner)                    │    │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │    │
│  │  │   PII    │ │ Quality  │ │  Schema  │ │ Industry │  │    │
│  │  │ Scanner  │ │   Suite  │ │  Drift   │ │  Packs   │  │    │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                          │                                       │
│           ┌──────────────┼──────────────┐                       │
│           ▼              ▼              ▼                        │
│       cleansed/       results/        metrics/                   │
│      (Silver)         (Bronze+)       (Gold)                     │
│    PII masked       Scan JSON      quality_metrics.csv           │
│    Deduped CSV      results        Historical trends             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │     Streamlit Dashboard       │
              │  4 tabs · 6 analytics charts  │
              │  Scan · Cloud · Analytics ·   │
              │       How It Works            │
              └──────────────────────────────┘
```

---

## Features

### 1. Context-Aware PII Detection
Detects 6 PII types using regex with column-name context scoring. A match in a `serial_number` column gets 15% confidence (LOW — likely false positive). A match in a `notes` column next to "social security" gets 90% confidence (HIGH). This reduces actionable false positive alerts by **33%** while maintaining **100% recall** on genuine PII.

| Sensitivity | Detects |
|-------------|---------|
| `low` | SSN, Credit Card |
| `medium` | + Phone, Date of Birth |
| `high` | + Email, IP Address |

All matched values are partially masked before storage — `372-88-3412` → `XXX-XX-3412`.

### 2. Automated Blob Trigger (Event-Driven)
Drop a CSV into the `incoming/` container. Azure fires the Function automatically — no human action required. Results are saved to three destinations simultaneously:
- `results/` — full scan JSON
- `cleansed/` — PII-masked, deduplicated CSV (Silver layer)
- `metrics/quality_metrics.csv` — appended row for Gold layer analytics

### 3. Medallion Architecture (Bronze / Silver / Gold)
```
Bronze  →  incoming/     Raw CSV files as uploaded
Silver  →  cleansed/     PII masked + exact duplicates removed
Gold    →  metrics/      Aggregated quality_metrics.csv for trend analysis
```

Every scan appends 15 metrics columns to the Gold layer: timestamp, filename, health score, privacy/quality/completeness sub-scores, HIGH/MEDIUM/LOW PII counts, quality failures, and duplicate rate.

### 4. Data Quality Validation (Great Expectations v1.x)
Auto-generates a validation suite from column names — zero configuration required. Runs in ephemeral mode (no disk writes, serverless-compatible).

- ID columns → `ExpectColumnValuesToNotBeNull`
- Email columns → RFC 5322 regex validation
- Numeric revenue/price → non-negative check
- Age columns → range 0–120
- Zip codes → US ZIP format

### 5. Schema Drift Detection
Compares incoming dataset structure against a saved JSON baseline. Classifies changes as CRITICAL (new column matches sensitive keywords: password, medical, salary, cvv, biometric) or WARNING (any other structural change). CRITICAL alerts surface at the top of both the dashboard and email notifications.

### 6. Industry Business Logic Packs
Domain-specific cross-column validation beyond generic schema checks:

| Pack | Checks |
|------|--------|
| E-commerce | Ship date after order date · prices ≥ 0 · quantities positive integers · dates in past |
| Finance | Tax = subtotal × rate · total = subtotal + tax · no negative balances |
| Healthcare | Patient age 0–130 · discharge after admission · dosage positive |

Failed pack checks apply a score penalty (up to −20 pts).

### 7. Remediation Engine
Interactive panel in the Streamlit dashboard:
- Toggle PII masking (HIGH/MEDIUM confidence only)
- Toggle exact duplicate removal
- Preview every transformation before executing
- One-click execution → sanitized CSV unlocked in Export Engine

### 8. Analytics Dashboard (Gold Layer)
6 real-time charts reading from `metrics/quality_metrics.csv`:
- Health score trend line with grade zones
- PII exposure stacked bar (HIGH/MEDIUM/LOW per scan)
- Quality score comparison bar
- Duplicate rate area chart
- Radar chart — Privacy/Quality/Completeness dimensions
- Grade distribution donut

### 9. PDF Audit Report
3-page branded report generated by ReportLab — cover with score ring, full PII findings table (masked values + confidence scores), quality check results, prioritised recommendations, next steps. Client-deliverable in under 2 minutes.

### 10. Email Alerts
Sends an HTML email alert via SendGrid (or SMTP fallback) when:
- Health score drops below configurable threshold (default: 70)
- HIGH confidence PII is detected

---

## Quick Start

```bash
# Clone
git clone https://github.com/bsweehoney/DataGuard-Pro.git
cd DataGuard-Pro

# Install dependencies
pip install great_expectations pandas streamlit plotly reportlab azure-storage-blob

# Copy environment template
cp .env.example .env
# Edit .env with your Azure credentials

# Run CLI scanner (auto-generates sample data)
python data_health_check.py

# Launch dashboard
streamlit run dashboard.py

# Generate PDF audit report
python data_health_check.py --file data.csv --output results.json
python generate_report.py --json results.json --client "Client Name"
```

---

## CLI Reference

```bash
# Basic scan
python data_health_check.py --file data.csv

# High sensitivity + healthcare pack
python data_health_check.py --file patients.csv --sensitivity high --pack healthcare

# Save schema baseline for drift detection
python data_health_check.py --file data.csv --save-schema

# Compare against saved baseline
python data_health_check.py --file data.csv --schema baseline_schema.json

# Export JSON for PDF generation
python data_health_check.py --file data.csv --output scan_results.json
```

---

## Live API

The Azure Function accepts CSV files via HTTP POST:

```bash
# Health check
curl https://dataguard-func-app.azurewebsites.net/api/dataguardscanner

# Scan a CSV
curl -X POST \
  "https://dataguard-func-app.azurewebsites.net/api/dataguardscanner?filename=data.csv&sensitivity=high" \
  --data-binary @data.csv \
  -H "Content-Type: text/csv"
```

Response includes: health score, grade, PII findings (masked), quality check results, duplicates, saved blob paths, and Gold layer update confirmation.

---

## File Structure

```
DataGuard-Pro/
├── data_health_check.py      # Core engine — PII, quality, drift, industry packs
├── dashboard.py              # Streamlit UI — 4 tabs, analytics, remediation
├── generate_report.py        # ReportLab PDF — 3-page audit report
├── sample_customers.csv      # Synthetic test dataset
├── .env.example              # Environment variable template (copy to .env)
├── .gitignore                # Protects credentials
└── azurefunc/
    ├── function_app.py       # Azure Function — HTTP + Blob triggers
    ├── requirements.txt      # Function dependencies
    └── host.json             # Function runtime config
```

---

## Environment Variables

Copy `.env.example` to `.env` and fill in your values:

```
AZURE_STORAGE_CONNECTION_STRING=your_connection_string
AZURE_RESULTS_CONTAINER=results
AZURE_INCOMING_CONTAINER=incoming
AZURE_CLEANSED_CONTAINER=cleansed
DEFAULT_SENSITIVITY=medium
ALERT_SCORE_THRESHOLD=70
ALERT_EMAIL_TO=your@email.com
SENDGRID_API_KEY=optional_for_email_alerts
```

---

## Evaluation Results

Against the synthetic test dataset (11 rows × 9 columns):

| Metric | Result |
|--------|--------|
| Overall health score | 72/100 (B — Acceptable) |
| With healthcare pack | 66/100 (C — Needs attention) |
| HIGH PII found | 2 (SSN + DOB in notes column) |
| False positives correctly downgraded | 2 (serial_number column → LOW 15%) |
| False positive reduction vs naive scanner | 33% |
| Quality failures | 5 detected |
| Exact duplicates | 1 row (9.1%) |
| After remediation | 10 rows · PII masked · duplicates removed |

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Language | Python 3.11+ | Core engine |
| Quality validation | Great Expectations v1.x | Ephemeral in-memory validation |
| PII detection | Custom regex + context scoring | Zero cold-start, serverless-ready |
| Cloud compute | Azure Functions | HTTP + Blob event triggers |
| Storage | Azure Blob Storage | Bronze/Silver/Gold containers |
| Dashboard | Streamlit | 4-tab SaaS UI |
| Visualisation | Plotly | 6 analytics charts |
| PDF generation | ReportLab | Client audit reports |
| Email alerts | SendGrid / SMTP | Threshold-based notifications |

---

## Legal

All data is processed in memory only. No raw data is written to disk or transmitted beyond the scan pipeline. The `cleansed/` output contains only masked values — original PII is never stored. Suitable for deployment under a Data Processing Agreement (DPA) as defined by GDPR Article 28.

---

## License

MIT — see [LICENSE](LICENSE) for details.
