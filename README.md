# DataGuard-Pro 🛡️

> Automated PII scanning, data quality validation, schema drift detection, and compliance reporting — built entirely in Python.

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.x-FF4B4B?style=flat&logo=streamlit&logoColor=white)](https://streamlit.io)
[![Great Expectations](https://img.shields.io/badge/Great_Expectations-1.x-FF6B35?style=flat)](https://greatexpectations.io)
[![AWS Lambda](https://img.shields.io/badge/AWS-Lambda%20Ready-FF9900?style=flat&logo=amazonaws&logoColor=white)](https://aws.amazon.com/lambda)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat)](LICENSE)

---

## Overview

DataGuard-Pro is a data governance platform targeting small and medium enterprises (SMEs) that lack the budget for enterprise-grade compliance tooling. It scans CSV datasets in memory — detecting hidden PII, validating data quality, monitoring schema changes, and generating client-facing audit reports — without ever persisting a copy of the raw data.

GDPR fines reach €20 million. CCPA fines are $750 per consumer per incident. Most SMEs have no tooling to detect the data exposure that triggers these fines. DataGuard-Pro fills that gap.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    data_health_check.py                      │
│                    (Backend Engine)                          │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ PII Scanner  │Quality Suite │Schema Drift  │Industry Packs  │
│ Regex +      │Great         │JSON baseline │E-commerce      │
│ Context      │Expectations  │comparison +  │Finance         │
│ Scoring      │v1.x ephemeral│CRITICAL col  │Healthcare      │
│              │mode          │keyword alerts│                │
└──────────────┴──────────────┴──────────────┴────────────────┘
                              │
              ┌───────────────┴────────────────┐
              │                                │
    ┌─────────▼─────────┐           ┌──────────▼──────────┐
    │   dashboard.py    │           │  generate_report.py  │
    │ Streamlit UI      │           │  ReportLab PDF       │
    │ Remediation Engine│           │  3-page audit report │
    │ Session State     │           │  Client deliverable  │
    └───────────────────┘           └─────────────────────┘
```

---

## Features

### 1. Context-Aware PII Detection
Detects 8 PII types using regex — SSN, email, phone, credit card, IP address, date of birth, passport, IBAN. The key differentiator: instead of flagging every pattern match, a confidence scoring function assigns each finding a risk level (HIGH / MEDIUM / LOW) based on column name semantics and surrounding cell text.

- A match in a column named `serial_number` → 15% confidence → **LOW** (likely a false positive)
- A match in a column named `identity` → 100% confidence → **HIGH**
- A match in a `notes` column next to the word "social security" → 90% confidence → **HIGH**

This reduces actionable false positive alerts by ~33% while maintaining 100% recall on genuine PII instances.

Three sensitivity presets: `low` (SSN + credit cards only), `medium` (adds phone + DOB), `high` (all 8 patterns).

### 2. Data Quality Validation (Great Expectations)
Auto-generates a Great Expectations validation suite from column names and dtypes — no manual configuration required. Runs in ephemeral mode (in-memory, zero infrastructure), making it suitable for serverless deployment.

Auto-detected rules include:
- ID columns → `ExpectColumnValuesToNotBeNull`
- Email columns → `ExpectColumnValuesToMatchRegex` (RFC 5322)
- Numeric revenue/price columns → `ExpectColumnValuesToBeBetween(min=0)`
- Age columns → `ExpectColumnValuesToBeBetween(min=0, max=120)`
- Zip/postal columns → US ZIP regex

Custom rules can be added via a `config.json` file.

### 3. Schema Drift Detection
Serializes dataset schema (column names, dtypes, row count) to a JSON baseline. On subsequent scans, compares current schema against the baseline and classifies changes:

- **CRITICAL alert** — new column name contains a sensitive keyword (`password`, `medical`, `salary`, `cvv`, `biometric`, etc.)
- **WARNING** — any other column addition or type change
- **INFO** — column removed since baseline

Baseline can be saved to session memory (persists across Streamlit reruns via `st.session_state`) or downloaded as JSON for cross-session use.

### 4. Industry Business Logic Packs
Pluggable validation modules that enforce domain-specific invariants beyond generic schema checks:

| Pack | Checks |
|------|--------|
| **E-commerce** | Ship date after order date · prices ≥ 0 · quantities are positive integers · signup dates in the past |
| **Finance** | Tax = configured rate × subtotal · total = subtotal + tax · no unexpected negative balances |
| **Healthcare** | Patient age 0–130 · discharge date after admission · dosage values positive |

Failed pack checks apply a score penalty (up to −20 pts) on top of the base health score.

### 5. Remediation Engine
Interactive panel inside the Streamlit dashboard:
- Toggle PII masking (HIGH/MEDIUM confidence findings only)
- Toggle exact duplicate removal
- Preview every intended transformation before executing
- One-click execution: deduplicates then masks in-memory
- Remediated dataset saved to `st.session_state` and unlocked as a download in the Export Engine

### 6. Data Health Score
Composite 0–100 score across three weighted dimensions:

```
Overall = (Privacy × 0.38) + (Quality × 0.38) + (Completeness × 0.18) − pack_penalty
```

| Score | Grade |
|-------|-------|
| 85–100 | A — Healthy |
| 70–84 | B — Acceptable |
| 55–69 | C — Needs attention |
| 40–54 | D — At risk |
| 0–39 | F — Critical |

### 7. PDF Audit Report
3-page branded report generated by ReportLab:
- **Page 1** — Cover, overall score ring, dimension bars, key metric counts
- **Page 2** — Full PII findings table (masked values + confidence scores) + quality check results
- **Page 3** — Prioritised recommendations, next steps, contact footer

---

## Quick Start

```bash
# Clone
git clone https://github.com/bsweehoney/DataGuard-Pro.git
cd DataGuard-Pro

# Install dependencies
pip install great_expectations pandas streamlit plotly reportlab

# Run the CLI scanner (auto-generates sample data)
python data_health_check.py

# Launch the dashboard
streamlit run dashboard.py

# Generate a PDF audit report
python data_health_check.py --file data.csv --output results.json
python generate_report.py --json results.json --client "Client Name"
```

---

## CLI Reference

```bash
# Basic scan
python data_health_check.py --file data.csv

# High sensitivity + healthcare business logic pack
python data_health_check.py --file patients.csv --sensitivity high --pack healthcare

# Save baseline schema for drift detection
python data_health_check.py --file data.csv --save-schema

# Compare against saved baseline
python data_health_check.py --file data.csv --schema baseline_schema.json

# Export JSON for PDF generation
python data_health_check.py --file data.csv --output scan_results.json

# Generate PDF report
python generate_report.py --json scan_results.json \
  --client "Acme Corp" \
  --agency "DataGuard Pro" \
  --contact "hello@youragency.com"
```

---

## File Structure

```
DataGuard-Pro/
├── data_health_check.py    # Core engine — PII scanner, GX quality suite,
│                           # schema drift, industry packs, scoring
├── dashboard.py            # Streamlit UI — scan controls, remediation engine,
│                           # session state baseline, export engine
├── generate_report.py      # ReportLab PDF generator — 3-page audit report
├── sample_customers.csv    # Synthetic test dataset with deliberate issues
└── .gitignore
```

---

## Evaluation Results

Against the included synthetic dataset (`sample_customers.csv`, 11 rows × 8 columns):

| Metric | Result |
|--------|--------|
| Overall health score | 72/100 (B — Acceptable) |
| Score with healthcare pack | 66/100 (C — Needs attention) |
| HIGH confidence PII found | 2 instances (SSN + DOB in notes column) |
| False positives correctly downgraded | 2 instances (patterns in serial_number column → LOW 15%) |
| False positive reduction vs naive scanner | 33% |
| Quality failures detected | 5 (null ID, bad email, impossible ages, invalid zip, negative revenue) |
| Exact duplicates | 1 row (9.1% of dataset) |
| After remediation | 10 rows, PII masked, duplicates removed |

---

## Technology Stack

| Component | Technology | Reason |
|-----------|-----------|--------|
| Language | Python 3.11+ | Dominant data engineering language |
| Quality validation | Great Expectations v1.x | Industry standard; ephemeral mode = no infrastructure |
| PII detection | Custom regex + context scoring | Zero cold-start; no NLP model required |
| Dashboard | Streamlit | Python-native; free community hosting |
| PDF generation | ReportLab | Pure Python; precise layout control |
| Visualisation | Plotly | Interactive gauge and bar charts |
| Cloud target | AWS Lambda + S3 Events | Pay-per-execution; ~$0.01/month per client |

---

## Cloud Deployment (AWS Lambda)

The scanner is designed for serverless deployment:

1. Client drops CSV into an S3 bucket
2. S3 Event Notification triggers a Lambda function
3. Lambda runs `data_health_check.py` against the file in memory
4. Results are saved to DynamoDB / S3
5. Dashboard reads results and updates the client's health score

At Lambda pricing, a daily scan of a 1,000-row CSV costs under **$0.01/month** per client.

---

## Legal

All data is processed in memory only. No copy of any scanned dataset is written to disk or transmitted. Suitable for deployment under a Data Processing Agreement (DPA) as defined by GDPR Article 28.

---

## License

MIT — see [LICENSE](LICENSE) for details.
