"""
DataGuard-Pro — Dashboard v4
Real-world SaaS design. Clean, professional, client-facing.
"""

import re
import json
import warnings
import os
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import importlib.util

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

warnings.filterwarnings("ignore")

# ── Load scanner ──────────────────────────────────────────────────────────────
def _load_scanner():
    p = Path(__file__).parent / "data_health_check.py"
    if p.exists():
        spec = importlib.util.spec_from_file_location("dhc", p)
        mod  = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    return None

_dhc = _load_scanner()
if _dhc:
    scan_for_pii            = _dhc.scan_for_pii
    pii_findings_by_type    = _dhc.pii_findings_by_type
    build_expectation_suite = _dhc.build_expectation_suite
    run_quality_checks      = _dhc.run_quality_checks
    check_duplicates        = _dhc.check_duplicates
    calculate_score         = _dhc.calculate_score
    detect_schema_drift     = _dhc.detect_schema_drift
    INDUSTRY_PACKS          = _dhc.INDUSTRY_PACKS
else:
    scan_for_pii = None

if "memory_baseline"  not in st.session_state: st.session_state.memory_baseline  = None
if "cleansed_df"      not in st.session_state: st.session_state.cleansed_df      = None
if "last_scan"        not in st.session_state: st.session_state.last_scan         = None

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="DataGuard Pro — Data Compliance Platform",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Design System ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

* { box-sizing: border-box; }
html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
#MainMenu, footer, header { visibility: hidden; }

/* ── Base ── */
.stApp { background: #f8f9fb; }
.block-container { padding: 0 !important; max-width: 100% !important; }

/* ── Top nav bar ── */
.topnav {
    background: #ffffff;
    border-bottom: 1px solid #e8eaf0;
    padding: 0 40px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    position: sticky;
    top: 0;
    z-index: 999;
    box-shadow: 0 1px 3px rgba(0,0,0,.06);
}
.nav-brand {
    font-size: 17px;
    font-weight: 700;
    color: #0f172a;
    letter-spacing: -0.3px;
    display: flex;
    align-items: center;
    gap: 8px;
}
.nav-brand span {
    color: #2563eb;
}
.nav-badge {
    background: #eff6ff;
    color: #2563eb;
    font-size: 11px;
    font-weight: 600;
    padding: 2px 8px;
    border-radius: 20px;
    letter-spacing: 0.3px;
}
.nav-links {
    display: flex;
    gap: 32px;
    font-size: 13.5px;
    font-weight: 500;
    color: #64748b;
}
.nav-cta {
    background: #2563eb;
    color: white !important;
    font-size: 13px;
    font-weight: 600;
    padding: 8px 20px;
    border-radius: 8px;
}

/* ── Hero section ── */
.hero {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%);
    padding: 64px 40px 56px;
    position: relative;
    overflow: hidden;
}
.hero::before {
    content: '';
    position: absolute;
    top: -100px; right: -100px;
    width: 400px; height: 400px;
    background: radial-gradient(circle, rgba(37,99,235,0.15) 0%, transparent 70%);
    border-radius: 50%;
}
.hero::after {
    content: '';
    position: absolute;
    bottom: -80px; left: 20%;
    width: 300px; height: 300px;
    background: radial-gradient(circle, rgba(16,185,129,0.1) 0%, transparent 70%);
    border-radius: 50%;
}
.hero-eyebrow {
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    color: #60a5fa;
    margin-bottom: 16px;
}
.hero-title {
    font-size: 40px;
    font-weight: 700;
    color: #ffffff;
    line-height: 1.15;
    letter-spacing: -1px;
    margin-bottom: 16px;
    max-width: 600px;
}
.hero-title em {
    font-style: normal;
    color: #60a5fa;
}
.hero-sub {
    font-size: 16px;
    color: #94a3b8;
    line-height: 1.65;
    max-width: 520px;
    margin-bottom: 32px;
}
.hero-stats {
    display: flex;
    gap: 40px;
    margin-top: 40px;
    padding-top: 32px;
    border-top: 1px solid rgba(255,255,255,0.08);
}
.hero-stat-num {
    font-size: 28px;
    font-weight: 700;
    color: #ffffff;
    font-family: 'JetBrains Mono', monospace;
}
.hero-stat-label {
    font-size: 12px;
    color: #64748b;
    margin-top: 2px;
}

/* ── Upload zone ── */
.upload-zone {
    background: rgba(255,255,255,0.04);
    border: 1.5px dashed rgba(96,165,250,0.4);
    border-radius: 16px;
    padding: 32px;
    text-align: center;
    transition: all .2s;
}
.upload-zone:hover {
    border-color: rgba(96,165,250,0.7);
    background: rgba(255,255,255,0.06);
}

/* ── Main content area ── */
.content-wrap {
    padding: 32px 40px;
    max-width: 1400px;
    margin: 0 auto;
}

/* ── Score card ── */
.score-card {
    background: #ffffff;
    border-radius: 16px;
    border: 1px solid #e8eaf0;
    padding: 28px 32px;
    box-shadow: 0 1px 3px rgba(0,0,0,.05), 0 4px 12px rgba(0,0,0,.04);
}
.score-number {
    font-size: 72px;
    font-weight: 700;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
    letter-spacing: -2px;
}
.score-grade {
    font-size: 13px;
    font-weight: 600;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    margin-top: 6px;
}
.score-meta {
    font-size: 12px;
    color: #94a3b8;
    margin-top: 12px;
    font-family: 'JetBrains Mono', monospace;
}

/* ── Stat cards ── */
.stat-card {
    background: #ffffff;
    border-radius: 12px;
    border: 1px solid #e8eaf0;
    padding: 20px 24px;
    box-shadow: 0 1px 3px rgba(0,0,0,.04);
}
.stat-label {
    font-size: 11.5px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    color: #94a3b8;
    margin-bottom: 8px;
}
.stat-value {
    font-size: 32px;
    font-weight: 700;
    font-family: 'JetBrains Mono', monospace;
    line-height: 1;
}
.stat-sub {
    font-size: 12px;
    color: #94a3b8;
    margin-top: 4px;
}

/* ── Section headers ── */
.sec-header {
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 0.6px;
    text-transform: uppercase;
    color: #64748b;
    margin-bottom: 14px;
    padding-bottom: 10px;
    border-bottom: 1px solid #f1f3f8;
}

/* ── Finding rows ── */
.finding-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 10px 0;
    border-bottom: 1px solid #f1f3f8;
}
.finding-row:last-child { border-bottom: none; }

/* ── Risk badges ── */
.risk-badge {
    display: inline-flex;
    align-items: center;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.4px;
    font-family: 'JetBrains Mono', monospace;
    flex-shrink: 0;
}
.risk-high   { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }
.risk-medium { background: #fffbeb; color: #d97706; border: 1px solid #fde68a; }
.risk-low    { background: #f8fafc; color: #94a3b8; border: 1px solid #e2e8f0; }
.risk-pass   { background: #f0fdf4; color: #16a34a; border: 1px solid #bbf7d0; }
.risk-fail   { background: #fef2f2; color: #dc2626; border: 1px solid #fecaca; }

/* ── Alert banners ── */
.alert-critical {
    background: #fef2f2;
    border: 1px solid #fecaca;
    border-left: 4px solid #dc2626;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 12px;
}
.alert-warning {
    background: #fffbeb;
    border: 1px solid #fde68a;
    border-left: 4px solid #f59e0b;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 12px;
}
.alert-success {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-left: 4px solid #16a34a;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 12px;
}
.alert-info {
    background: #eff6ff;
    border: 1px solid #bfdbfe;
    border-left: 4px solid #2563eb;
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 12px;
}

/* ── Mono text ── */
.mono { font-family: 'JetBrains Mono', monospace; }

/* ── Streamlit overrides ── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background: transparent;
    border-bottom: 1px solid #e8eaf0;
    padding: 0;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Inter', sans-serif;
    font-size: 13.5px;
    font-weight: 500;
    color: #64748b;
    padding: 12px 20px;
    border-radius: 0;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    background: transparent;
}
.stTabs [aria-selected="true"] {
    color: #2563eb !important;
    border-bottom-color: #2563eb !important;
    font-weight: 600 !important;
}
.stTabs [data-baseweb="tab-panel"] { padding: 24px 0 0 0; }

div[data-testid="stFileUploader"] {
    background: transparent;
    border: none;
}
.stButton > button {
    font-family: 'Inter', sans-serif;
    font-weight: 600;
    font-size: 13.5px;
    border-radius: 8px;
    padding: 9px 22px;
    border: 1.5px solid #e2e8f0;
    background: #ffffff;
    color: #0f172a;
    transition: all .15s;
}
.stButton > button:hover {
    background: #f8f9fb;
    border-color: #cbd5e1;
}
.stSelectbox > div > div {
    border-radius: 8px;
    border: 1.5px solid #e2e8f0;
    font-family: 'Inter', sans-serif;
    font-size: 13.5px;
}
.stTextInput > div > div > input {
    border-radius: 8px;
    border: 1.5px solid #e2e8f0;
    font-family: 'Inter', sans-serif;
    font-size: 13.5px;
}
div[data-testid="stDataFrame"] {
    border: 1px solid #e8eaf0;
    border-radius: 10px;
}
.stDownloadButton > button {
    background: #2563eb !important;
    color: white !important;
    border: none !important;
    font-weight: 600 !important;
    border-radius: 8px !important;
}
.stDownloadButton > button:hover {
    background: #1d4ed8 !important;
}
div[data-testid="stExpander"] {
    border: 1px solid #e8eaf0 !important;
    border-radius: 10px !important;
    background: #ffffff !important;
}

/* Progress bar custom */
.prog-track {
    background: #f1f5f9;
    border-radius: 999px;
    height: 8px;
    margin: 6px 0 12px;
    overflow: hidden;
}
.prog-fill {
    height: 100%;
    border-radius: 999px;
    transition: width .6s ease;
}

/* Remediation engine */
.remed-card {
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
}

/* Cloud tab */
.azure-hero {
    background: linear-gradient(135deg, #eff6ff 0%, #f0fdf4 100%);
    border: 1px solid #bfdbfe;
    border-radius: 14px;
    padding: 28px 32px;
    margin-bottom: 24px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────
def sc(s):
    if s >= 85: return "#16a34a"
    if s >= 70: return "#d97706"
    if s >= 55: return "#ea580c"
    return "#dc2626"

def sc_bg(s):
    if s >= 85: return "#f0fdf4"
    if s >= 70: return "#fffbeb"
    if s >= 55: return "#fff7ed"
    return "#fef2f2"

def gauge(score, label):
    c = sc(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"font": {"size": 32, "family": "JetBrains Mono", "color": c}},
        gauge={
            "axis": {"range": [0,100], "tickwidth": 0,
                     "tickfont": {"color": "#cbd5e1", "size": 9}},
            "bar": {"color": c, "thickness": 0.22},
            "bgcolor": "#f8fafc", "borderwidth": 0,
            "steps": [
                {"range": [0,40],   "color": "#fef2f2"},
                {"range": [40,70],  "color": "#fffbeb"},
                {"range": [70,100], "color": "#f0fdf4"},
            ],
            "threshold": {"line": {"color": c, "width": 2}, "thickness": 0.75, "value": score},
        },
        title={"text": label, "font": {"size": 10, "family": "Inter", "color": "#94a3b8"}},
    ))
    fig.update_layout(
        height=170, margin=dict(t=28, b=0, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color="#0f172a",
    )
    return fig

def donut(passed, failed):
    total = passed + failed
    fig = go.Figure(go.Pie(
        values=[passed, failed] if total > 0 else [1, 0],
        labels=["Passed", "Failed"], hole=0.74,
        marker_colors=["#16a34a", "#dc2626"] if total > 0 else ["#16a34a", "#16a34a"],
        textinfo="none", hoverinfo="label+value",
    ))
    pct = int((passed/total)*100) if total > 0 else 100
    fig.add_annotation(
        text=f"<b>{pct}%</b><br><span style='font-size:10px'>passed</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=18, family="JetBrains Mono", color="#0f172a"),
    )
    fig.update_layout(
        height=180, margin=dict(t=10, b=10, l=10, r=10),
        paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
    )
    return fig

def load_csv(f):
    df = pd.read_csv(f, dtype=str, low_memory=False)
    for col in df.columns:
        try: df[col] = pd.to_numeric(df[col])
        except: pass
    return df

def bold(text):
    return re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', text)

def prog_bar(score, color):
    w = max(2, int(score))
    return (f'<div style="background:#f1f5f9;border-radius:999px;height:8px;margin:6px 0 12px;overflow:hidden;">'
            f'<div style="width:{w}%;height:100%;border-radius:999px;background:{color};"></div></div>')


# ── Top Navigation ────────────────────────────────────────────────────────────
st.markdown("""
<div class="topnav">
    <div class="nav-brand">
        🛡 DataGuard<span>Pro</span>
        <span class="nav-badge">v3.0</span>
    </div>
    <div class="nav-links">
        <span>Dashboard</span>
        <span>Reports</span>
        <span>Azure Cloud</span>
        <span>Docs</span>
    </div>
    <div style="font-size:13px;font-weight:600;color:#2563eb;">
        dataguard-func-app.azurewebsites.net ↗
    </div>
</div>
""", unsafe_allow_html=True)

# ── Engine offline check ──────────────────────────────────────────────────────
if scan_for_pii is None:
    st.markdown("""
<div style="padding:40px;max-width:600px;margin:40px auto;">
<div class="alert-critical">
    <strong style="color:#dc2626;font-size:14px;">⚙ Engine Offline</strong>
    <p style="color:#7f1d1d;margin:6px 0 0;font-size:13px;">
        Place <code>data_health_check.py</code> in the same folder as this dashboard and restart.
    </p>
</div>
</div>""", unsafe_allow_html=True)
    st.stop()

# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_scan, tab_cloud, tab_analytics, tab_history = st.tabs([
    "  Scan & Analyze  ",
    "  ☁ Azure Results  ",
    "  📈 Analytics  ",
    "  How It Works  ",
])


# ════════════════════════════════════════════════════════════════════════════════
# TAB 1 — SCAN
# ════════════════════════════════════════════════════════════════════════════════
with tab_scan:

    # ── Hero ─────────────────────────────────────────────────────────────────
    st.markdown("""
<div class="hero">
    <div style="position:relative;z-index:1;display:flex;gap:60px;align-items:flex-start;flex-wrap:wrap;">
        <div style="flex:1;min-width:300px;">
            <div class="hero-eyebrow">GDPR · CCPA · HIPAA Compliance</div>
            <div class="hero-title">Find hidden data risks <em>before</em> regulators do.</div>
            <div class="hero-sub">
                DataGuard Pro scans your datasets for exposed PII, data quality failures,
                and schema changes — in seconds, not weeks. No setup. No data stored.
            </div>
            <div style="display:flex;gap:12px;flex-wrap:wrap;">
                <div style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);
                            border-radius:8px;padding:8px 16px;font-size:13px;color:#e2e8f0;">
                    ✓ Zero data persistence
                </div>
                <div style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);
                            border-radius:8px;padding:8px 16px;font-size:13px;color:#e2e8f0;">
                    ✓ Context-aware AI scoring
                </div>
                <div style="background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.12);
                            border-radius:8px;padding:8px 16px;font-size:13px;color:#e2e8f0;">
                    ✓ Azure cloud powered
                </div>
            </div>
            <div class="hero-stats">
                <div>
                    <div class="hero-stat-num">33%</div>
                    <div class="hero-stat-label">fewer false positives</div>
                </div>
                <div>
                    <div class="hero-stat-num">100%</div>
                    <div class="hero-stat-label">PII recall rate</div>
                </div>
                <div>
                    <div class="hero-stat-num">~$0</div>
                    <div class="hero-stat-label">cost per scan</div>
                </div>
            </div>
        </div>
        <div style="flex:0 0 320px;min-width:280px;">
            <div style="background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);
                        border-radius:16px;padding:24px;">
                <div style="font-size:12px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;
                            color:#60a5fa;margin-bottom:16px;">Quick Scan</div>
    """, unsafe_allow_html=True)

    # Upload widget inside hero
    uploaded = st.file_uploader("Drop your CSV here", type=["csv"], label_visibility="collapsed")

    st.markdown("""
                <div style="margin-top:12px;">
    """, unsafe_allow_html=True)

    col_s, col_p = st.columns(2)
    with col_s:
        sensitivity = st.selectbox("Sensitivity", ["medium", "low", "high"], label_visibility="collapsed")
    with col_p:
        pack_choice = st.selectbox("Industry", ["None", "ecommerce", "finance", "healthcare"], label_visibility="collapsed")
    pack_name = None if pack_choice == "None" else pack_choice

    schema_file = st.file_uploader("Baseline schema (optional)", type=["json"], label_visibility="collapsed")

    st.markdown("""
                </div>
            </div>
        </div>
    </div>
</div>
    """, unsafe_allow_html=True)

    # ── Landing state ─────────────────────────────────────────────────────────
    if uploaded is None:
        st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

        st.markdown("""
<div style="padding:48px 0 24px;text-align:center;">
    <div style="font-size:13px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;
                color:#94a3b8;margin-bottom:12px;">What DataGuard Pro catches</div>
    <div style="font-size:28px;font-weight:700;color:#0f172a;letter-spacing:-0.5px;margin-bottom:8px;">
        Your data has risks you can't see.
    </div>
    <div style="font-size:15px;color:#64748b;max-width:480px;margin:0 auto;">
        A sales rep types an SSN into a notes field. A new column called 
        <code style="background:#f1f5f9;padding:1px 6px;border-radius:4px;">customer_passwords</code> 
        appears in your weekly export. We catch both.
    </div>
</div>
""", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        features = [
            ("#2563eb", "PII Detection", "Finds SSNs, credit cards, DOBs hiding in free-text notes fields — not just dedicated columns."),
            ("#16a34a", "Quality Validation", "Auto-generates business rules from column names. Catches nulls, bad formats, impossible values."),
            ("#d97706", "Schema Drift", "Fires CRITICAL alerts when risky columns like passwords or medical data appear unexpectedly."),
            ("#9333ea", "Industry Packs", "Cross-column logic for e-commerce (ship date), finance (tax math), healthcare (age range)."),
        ]
        for col, (color, title, desc) in zip([c1,c2,c3,c4], features):
            with col:
                st.markdown(f"""
<div class="stat-card" style="height:100%;">
    <div style="width:36px;height:36px;background:{color}15;border-radius:8px;
                display:flex;align-items:center;justify-content:center;margin-bottom:14px;">
        <div style="width:14px;height:14px;background:{color};border-radius:3px;"></div>
    </div>
    <div style="font-size:14px;font-weight:600;color:#0f172a;margin-bottom:6px;">{title}</div>
    <div style="font-size:13px;color:#64748b;line-height:1.6;">{desc}</div>
</div>""", unsafe_allow_html=True)

        st.markdown('</div>', unsafe_allow_html=True)

    # ── Scan results ──────────────────────────────────────────────────────────
    else:
        filename = uploaded.name

        with st.spinner("Scanning your data..."):
            df = load_csv(uploaded)

            drift = None
            active_baseline = None
            if schema_file:
                active_baseline = json.load(schema_file)
            elif st.session_state.memory_baseline:
                active_baseline = st.session_state.memory_baseline
            if active_baseline:
                import tempfile, os as _os
                with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                    json.dump(active_baseline, tmp); tmp_path = tmp.name
                drift = detect_schema_drift(df, tmp_path)
                _os.unlink(tmp_path)

            pii_findings = scan_for_pii(df, sensitivity=sensitivity)
            quality      = run_quality_checks(df, build_expectation_suite(df, {}))
            dupes        = check_duplicates(df)
            pack_results = INDUSTRY_PACKS[pack_name](df) if pack_name else None
            scores       = calculate_score(pii_findings, quality, dupes, len(df), pack_results)
            pii_by_type  = pii_findings_by_type(pii_findings)

        st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

        # Schema drift critical alert
        if drift and drift.get("alerts"):
            for alert in drift["alerts"]:
                st.markdown(f"""
<div class="alert-critical">
    <strong style="color:#dc2626;font-size:13px;">🚨 Critical Schema Alert</strong>
    <p style="color:#7f1d1d;margin:4px 0 0;font-size:13px;">{alert['message']}</p>
</div>""", unsafe_allow_html=True)

        # File info strip
        ts   = datetime.now().strftime("%b %d, %Y  %H:%M")
        sens = {"low": "Low", "medium": "Medium", "high": "High"}[sensitivity]
        st.markdown(f"""
<div style="display:flex;gap:24px;align-items:center;padding:12px 20px;background:#ffffff;
            border:1px solid #e8eaf0;border-radius:10px;margin-bottom:24px;flex-wrap:wrap;">
    <span style="font-size:13px;font-weight:600;color:#0f172a;">{filename}</span>
    <span style="font-size:12px;color:#94a3b8;font-family:'JetBrains Mono',monospace;">
        {len(df):,} rows · {len(df.columns)} columns
    </span>
    <span style="font-size:12px;color:#94a3b8;">{ts}</span>
    <span style="font-size:12px;background:#eff6ff;color:#2563eb;padding:2px 10px;
                border-radius:20px;font-weight:600;">Sensitivity: {sens}</span>
    {f'<span style="font-size:12px;background:#f5f3ff;color:#7c3aed;padding:2px 10px;border-radius:20px;font-weight:600;">{pack_name} pack</span>' if pack_name else ''}
</div>
""", unsafe_allow_html=True)

        # ── Score + gauges ────────────────────────────────────────────────────
        ov = scores["overall"]
        col_score, col_gauges = st.columns([1, 2])

        with col_score:
            color = sc(ov)
            bg    = sc_bg(ov)
            st.markdown(f"""
<div class="score-card" style="height:100%;background:{bg};">
    <div class="stat-label">Data Health Score</div>
    <div class="score-number" style="color:{color};">{ov}</div>
    <div class="score-grade" style="color:{color};">{scores['grade']}</div>
    {f'<div style="margin-top:8px;font-size:12px;color:#d97706;font-weight:500;">−{scores["pack_penalty"]}pts business logic</div>' if scores.get("pack_penalty") else ''}
    <div class="score-meta">{len(df):,} rows scanned · {datetime.now().strftime('%H:%M')}</div>
    <div style="margin-top:20px;">
        <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Privacy</div>
        {prog_bar(scores['privacy'], sc(scores['privacy']))}
        <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Quality</div>
        {prog_bar(scores['quality'], sc(scores['quality']))}
        <div style="font-size:12px;color:#64748b;margin-bottom:4px;">Completeness</div>
        {prog_bar(scores['completeness'], sc(scores['completeness']))}
    </div>
</div>""", unsafe_allow_html=True)

        with col_gauges:
            g1, g2, g3 = st.columns(3)
            for cw, key, lbl in [(g1,"privacy","PRIVACY"),(g2,"quality","QUALITY"),(g3,"completeness","COMPLETENESS")]:
                with cw:
                    st.markdown('<div class="score-card" style="padding:16px;">', unsafe_allow_html=True)
                    st.plotly_chart(gauge(scores[key], lbl), use_container_width=True,
                                    config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Three columns ─────────────────────────────────────────────────────
        col_pii, col_qual, col_dupe = st.columns([1.3, 1.3, 0.8])

        # PII column
        with col_pii:
            st.markdown('<div class="score-card">', unsafe_allow_html=True)
            high   = scores["pii_high_count"]
            medium = scores["pii_medium_count"]
            low    = scores["pii_low_count"]

            st.markdown(f"""
<div class="sec-header">PII Exposure</div>
<div style="display:flex;gap:10px;margin-bottom:18px;flex-wrap:wrap;">
    <div style="flex:1;text-align:center;background:#fef2f2;border-radius:10px;padding:14px 10px;">
        <div style="font-size:26px;font-weight:700;color:#dc2626;font-family:'JetBrains Mono',monospace;">{high}</div>
        <div style="font-size:11px;font-weight:600;color:#dc2626;margin-top:2px;">HIGH</div>
    </div>
    <div style="flex:1;text-align:center;background:#fffbeb;border-radius:10px;padding:14px 10px;">
        <div style="font-size:26px;font-weight:700;color:#d97706;font-family:'JetBrains Mono',monospace;">{medium}</div>
        <div style="font-size:11px;font-weight:600;color:#d97706;margin-top:2px;">MEDIUM</div>
    </div>
    <div style="flex:1;text-align:center;background:#f8fafc;border-radius:10px;padding:14px 10px;">
        <div style="font-size:26px;font-weight:700;color:#94a3b8;font-family:'JetBrains Mono',monospace;">{low}</div>
        <div style="font-size:11px;font-weight:600;color:#94a3b8;margin-top:2px;">LOW</div>
    </div>
</div>
""", unsafe_allow_html=True)

            if not pii_findings:
                st.markdown("""
<div class="alert-success">
    <strong style="color:#16a34a;">All clear</strong>
    <p style="color:#14532d;margin:4px 0 0;font-size:13px;">No PII detected at this sensitivity level.</p>
</div>""", unsafe_allow_html=True)
            else:
                for pii_type, hits in pii_by_type.items():
                    dominant = hits[0]["risk"] if hits else "LOW"
                    risk_cls = {"HIGH":"risk-high","MEDIUM":"risk-medium","LOW":"risk-low"}.get(dominant,"risk-low")
                    with st.expander(f"{pii_type}  ·  {len(hits)} instance{'s' if len(hits)>1 else ''}"):
                        for h in hits[:15]:
                            rc = {"HIGH":"risk-high","MEDIUM":"risk-medium","LOW":"risk-low"}.get(h["risk"],"risk-low")
                            st.markdown(f"""
<div class="finding-row">
    <span class="risk-badge {rc}">{h['risk']}</span>
    <div style="flex:1;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:12.5px;color:#0f172a;font-weight:500;">
            {h['masked']}
        </div>
        <div style="font-size:11.5px;color:#94a3b8;margin-top:2px;">
            Row {h['row']} · <strong>{h['column']}</strong> · {int(h['confidence']*100)}% confidence
        </div>
        <div style="font-size:11px;color:#cbd5e1;margin-top:1px;">{h['reason']}</div>
    </div>
</div>""", unsafe_allow_html=True)
                        if len(hits) > 15:
                            st.caption(f"+ {len(hits)-15} more instances")

            # Schema baseline
            st.markdown("<br>", unsafe_allow_html=True)
            b1, b2 = st.columns(2)
            with b1:
                if st.button("💾  Save baseline"):
                    st.session_state.memory_baseline = {
                        "saved_at": datetime.now().isoformat(),
                        "columns": list(df.columns),
                        "dtypes": {c: str(df[c].dtype) for c in df.columns},
                        "row_count": len(df),
                    }
                    st.success(f"Baseline saved — {len(df.columns)} columns")
                    st.rerun()
            with b2:
                st.download_button(
                    "⬇  Export baseline",
                    data=json.dumps({"saved_at":datetime.now().isoformat(),"columns":list(df.columns),"dtypes":{c:str(df[c].dtype) for c in df.columns},"row_count":len(df)},indent=2),
                    file_name="baseline_schema.json", mime="application/json",
                )
            st.markdown('</div>', unsafe_allow_html=True)

        # Quality column
        with col_qual:
            st.markdown('<div class="score-card">', unsafe_allow_html=True)
            st.markdown('<div class="sec-header">Quality Checks</div>', unsafe_allow_html=True)
            st.plotly_chart(donut(quality["passed"], quality["failed"]),
                            use_container_width=True, config={"displayModeBar": False})

            for r in quality["results"]:
                badge = '<span class="risk-badge risk-pass">PASS</span>' if r["passed"] else '<span class="risk-badge risk-fail">FAIL</span>'
                col_tag = f'<span style="font-size:11px;font-family:\'JetBrains Mono\',monospace;color:#94a3b8;">{r["column"]}</span>' if r["column"] != "—" else ""
                detail = ""
                if not r["passed"] and r.get("details"):
                    d = r["details"]
                    if "unexpected_count" in d:
                        detail = f'<div style="font-size:11.5px;color:#dc2626;padding-left:58px;margin-top:2px;">→ {d["unexpected_count"]} bad value(s) ({d.get("unexpected_percent",0):.1f}%)</div>'
                st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid #f1f5f9;">
    {badge}
    <span style="font-size:13px;color:#374151;flex:1;">{r['check']}</span>
    {col_tag}
</div>{detail}""", unsafe_allow_html=True)

            if pack_results:
                st.markdown(f'<div class="sec-header" style="margin-top:20px;">{pack_name} Pack</div>', unsafe_allow_html=True)
                for r in pack_results:
                    if r.get("passed") is True:    badge = '<span class="risk-badge risk-pass">PASS</span>'
                    elif r.get("passed") is False:  badge = '<span class="risk-badge risk-fail">FAIL</span>'
                    else:                           badge = '<span class="risk-badge risk-low">N/A</span>'
                    detail = ""
                    if not r.get("passed") and r.get("detail","All OK") != "All OK":
                        detail = f'<div style="font-size:11.5px;color:#ea580c;padding-left:58px;margin-top:2px;">→ {r["detail"]}</div>'
                    st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid #f1f5f9;">
    {badge}<span style="font-size:13px;color:#374151;flex:1;">{r['check']}</span>
</div>{detail}""", unsafe_allow_html=True)

            st.markdown('</div>', unsafe_allow_html=True)

        # Duplicates column
        with col_dupe:
            dp    = dupes["duplicate_pct"]
            dpc   = sc(max(0, 100 - dp*5))
            st.markdown(f"""
<div class="score-card" style="margin-bottom:14px;text-align:center;">
    <div class="stat-label">Duplicate Rate</div>
    <div style="font-size:44px;font-weight:700;color:{sc(max(0,100-dp*5))};
                font-family:'JetBrains Mono',monospace;margin:8px 0;">{dp}%</div>
    <div style="font-size:12px;color:#94a3b8;">{dupes['exact_duplicates']} exact duplicates</div>
</div>
<div class="score-card" style="margin-bottom:14px;">
    <div class="stat-label">Dataset Size</div>
    <div style="font-size:32px;font-weight:700;color:#0f172a;font-family:'JetBrains Mono',monospace;">
        {dupes['total_rows']:,}
    </div>
    <div style="font-size:12px;color:#94a3b8;">total rows</div>
</div>
<div class="score-card">
    <div class="stat-label">Near Matches</div>
    <div style="font-size:32px;font-weight:700;color:#d97706;font-family:'JetBrains Mono',monospace;">
        {dupes['near_duplicates']:,}
    </div>
    <div style="font-size:12px;color:#94a3b8;">case / whitespace variation</div>
</div>""", unsafe_allow_html=True)

        # ── Schema drift ──────────────────────────────────────────────────────
        if drift and drift["status"] != "no_baseline":
            st.markdown("<br>", unsafe_allow_html=True)
            if drift["status"] == "stable":
                st.markdown(f"""
<div class="alert-success">
    <strong style="color:#16a34a;">Schema stable</strong>
    <span style="color:#14532d;font-size:13px;margin-left:8px;">
        Matches baseline from {drift['baseline_date'][:10]}
    </span>
</div>""", unsafe_allow_html=True)
            for change in drift.get("changes",[]):
                cls = "alert-warning" if change["severity"]=="WARNING" else "alert-info"
                st.markdown(f'<div class="{cls}"><p style="margin:0;font-size:13px;">{change["message"]}</p></div>',
                            unsafe_allow_html=True)

        # ── Recommendations ───────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sec-header">Recommendations</div>', unsafe_allow_html=True)

        recs = []
        if scores["pii_high_count"]   > 0: recs.append(("alert-critical", f"🔴 Mask or remove **{scores['pii_high_count']} HIGH-confidence PII instance(s)** before sharing this dataset."))
        if scores["pii_medium_count"] > 0: recs.append(("alert-warning",  f"🟡 Review **{scores['pii_medium_count']} MEDIUM-confidence** finding(s) — manual verification recommended."))
        if scores["pii_low_count"]    > 0: recs.append(("alert-info",     f"ℹ **{scores['pii_low_count']} LOW-confidence** finding(s) — likely false positives in product/reference columns."))
        if quality["failed"]          > 0: recs.append(("alert-warning",  f"🟡 **{quality['failed']} quality rule(s) failing** — add input validation at the point of data entry."))
        if dupes["exact_duplicates"]  > 0: recs.append(("alert-warning",  f"🟡 **{dupes['exact_duplicates']} exact duplicate row(s)** — deduplicate to reduce CRM and storage overhead."))
        if pack_results and any(not r.get("passed") for r in pack_results):
            fp = sum(1 for r in pack_results if r.get("passed") is False)
            recs.append(("alert-warning", f"🏭 **{fp} business logic check(s) failed** in the {pack_name} pack."))
        if drift and drift.get("alerts"): recs.append(("alert-critical", "🚨 **Schema drift detected** — a sensitive column was added. Review immediately."))
        if ov < 70: recs.append(("alert-info", "ℹ Set up **automated scanning** — Azure Function triggers on every file upload automatically."))
        if not recs: recs.append(("alert-success", "✅ **Dataset is healthy.** No critical issues detected."))

        rec_cols = st.columns(min(len(recs), 3))
        for i, (cls, text) in enumerate(recs):
            with rec_cols[i % len(rec_cols)]:
                st.markdown(f'<div class="{cls}"><p style="margin:0;font-size:13px;">{bold(text)}</p></div>',
                            unsafe_allow_html=True)

        # ── Remediation ───────────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sec-header">Remediation Engine</div>', unsafe_allow_html=True)

        hmp = scores["pii_high_count"] + scores["pii_medium_count"]
        ed  = dupes["exact_duplicates"]

        if hmp > 0 or ed > 0 or quality["failed"] > 0:
            st.markdown(f"""
<div class="remed-card">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">
        <div style="width:40px;height:40px;background:#dcfce7;border-radius:10px;
                    display:flex;align-items:center;justify-content:center;font-size:20px;">🧹</div>
        <div>
            <div style="font-size:14px;font-weight:600;color:#14532d;">Sanitization available</div>
            <div style="font-size:12.5px;color:#166534;margin-top:2px;">
                {hmp} PII value(s) to mask · {ed} duplicate row(s) to remove
            </div>
        </div>
    </div>
</div>""", unsafe_allow_html=True)

            t1, t2 = st.columns(2)
            with t1: apply_masking = st.checkbox("Mask HIGH/MEDIUM PII", value=True)
            with t2: drop_dupes    = st.checkbox("Drop exact duplicates", value=True)

            with st.expander("Preview — what will change"):
                rows = [{"Risk":f["risk"],"Column":f["column"],"Row":f["row"],"Will become":f["masked"]}
                        for f in pii_findings if f["risk"] in ("HIGH","MEDIUM")]
                if rows: st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
                st.markdown(f"Deduplication: **{dupes['total_rows']}** rows → **{dupes['total_rows']-ed}** rows")

            if st.button("✨  Run Remediation", type="primary"):
                with st.spinner("Applying transformations..."):
                    rem = df.copy()
                    if drop_dupes and ed > 0:
                        rem = rem.drop_duplicates().reset_index(drop=True)
                    if apply_masking and pii_findings:
                        rem = rem.astype(str)
                        for hit in pii_findings:
                            if hit["risk"] in ("HIGH","MEDIUM"):
                                try:
                                    ci = rem.columns.get_loc(hit["column"])
                                    ri = hit["row"]
                                    rv = hit.get("raw_value","")
                                    if ri < len(rem) and rv:
                                        rem.iloc[ri,ci] = str(rem.iloc[ri,ci]).replace(rv, hit["masked"])
                                except: pass
                    st.session_state.cleansed_df = rem
                    st.success(f"✅ Done — {len(rem):,} rows · PII masked · duplicates removed")
                    st.rerun()
        else:
            st.markdown("""
<div class="alert-success">
    <strong style="color:#16a34a;">No remediation needed</strong>
    <p style="color:#14532d;margin:4px 0 0;font-size:13px;">Dataset is clean — no HIGH/MEDIUM PII or duplicates found.</p>
</div>""", unsafe_allow_html=True)

        # ── Preview ───────────────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        with st.expander("Data Preview — first 50 rows"):
            st.dataframe(df.head(50), use_container_width=True)

        # ── Export Engine ─────────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="sec-header">Export</div>', unsafe_allow_html=True)

        json_report = json.dumps({
            "file": filename, "scanned_at": datetime.now().isoformat(),
            "sensitivity": sensitivity,
            "shape": {"rows": len(df), "columns": len(df.columns)},
            "scores": scores,
            "pii_by_risk": {"HIGH":scores["pii_high_count"],"MEDIUM":scores["pii_medium_count"],"LOW":scores["pii_low_count"]},
            "quality": {"total":quality["total_checks"],"passed":quality["passed"],"failed":quality["failed"]},
            "duplicates": dupes, "pack": pack_name, "pack_results": pack_results,
        }, indent=2, default=str)

        summary_csv = pd.DataFrame([
            {"Metric":"Overall score","Value":scores["overall"]},
            {"Metric":"Privacy","Value":scores["privacy"]},
            {"Metric":"Quality","Value":scores["quality"]},
            {"Metric":"Completeness","Value":scores["completeness"]},
            {"Metric":"HIGH PII","Value":scores["pii_high_count"]},
            {"Metric":"MEDIUM PII","Value":scores["pii_medium_count"]},
            {"Metric":"Quality failures","Value":quality["failed"]},
            {"Metric":"Exact duplicates","Value":dupes["exact_duplicates"]},
        ]).to_csv(index=False)

        if st.session_state.cleansed_df is not None:
            st.markdown(f"""
<div class="alert-success" style="margin-bottom:16px;">
    ✅ Remediated dataset ready — <strong>{len(st.session_state.cleansed_df):,} rows</strong>
</div>""", unsafe_allow_html=True)
            e1, e2, e3, e4 = st.columns(4)
            with e1:
                st.download_button("✨ Cleansed CSV",
                    data=st.session_state.cleansed_df.to_csv(index=False),
                    file_name=f"clean_{filename}", mime="text/csv")
            with e2:
                st.download_button("⬇ JSON Report", data=json_report,
                    file_name=f"health_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                    mime="application/json")
            with e3:
                st.download_button("⬇ Summary CSV", data=summary_csv,
                    file_name=f"summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv")
            with e4:
                if st.button("🔄 Reset"): st.session_state.cleansed_df = None; st.rerun()
        else:
            e1, e2, _ = st.columns([1,1,2])
            with e1:
                st.download_button("⬇ JSON Report", data=json_report,
                    file_name=f"health_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                    mime="application/json")
            with e2:
                st.download_button("⬇ Summary CSV", data=summary_csv,
                    file_name=f"summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                    mime="text/csv")

        st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════════
# TAB 2 — AZURE RESULTS
# ════════════════════════════════════════════════════════════════════════════════
with tab_cloud:
    st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

    st.markdown("""
<div class="azure-hero">
    <div style="font-size:32px;margin-bottom:8px;">☁</div>
    <div style="font-size:20px;font-weight:700;color:#0f172a;letter-spacing:-0.3px;margin-bottom:8px;">
        Cloud Scan History
    </div>
    <div style="font-size:13.5px;color:#64748b;max-width:440px;margin:0 auto;">
        Every CSV sent to the Azure Function is scanned and saved automatically.
        Connect below to view your full scan history with visual results.
    </div>
    <div style="margin-top:16px;font-size:12px;font-family:'JetBrains Mono',monospace;
                color:#2563eb;background:#eff6ff;display:inline-block;
                padding:6px 16px;border-radius:8px;">
        dataguard-func-app.azurewebsites.net
    </div>
</div>
""", unsafe_allow_html=True)

    conn_str = st.text_input(
        "Azure Storage Connection String",
        type="password",
        placeholder="DefaultEndpointsProtocol=https;AccountName=dataguardswe2026;AccountKey=...",
        help="Your connection string — never stored or logged",
    )

    if conn_str:
        try:
            from azure.storage.blob import BlobServiceClient
            client    = BlobServiceClient.from_connection_string(conn_str)
            container = client.get_container_client("results")
            blobs     = sorted(list(container.list_blobs()), key=lambda b: b.last_modified, reverse=True)

            if not blobs:
                st.markdown("""
<div class="alert-info">
    <strong style="color:#1d4ed8;">No results yet</strong>
    <p style="color:#1e3a8a;margin:4px 0 0;font-size:13px;">
        Send a CSV to the Azure Function endpoint to generate your first cloud scan result.
    </p>
</div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
<div class="alert-success" style="margin-bottom:16px;">
    <strong style="color:#16a34a;">Connected</strong>
    <span style="color:#14532d;font-size:13px;margin-left:8px;">
        {len(blobs)} scan result(s) found in Azure Blob Storage
    </span>
</div>""", unsafe_allow_html=True)

                selected = st.selectbox(
                    "Select a scan result",
                    [b.name for b in blobs],
                    format_func=lambda x: x.replace("_results.json","").replace("_"," · "),
                )

                if selected:
                    data   = json.loads(container.get_blob_client(selected).download_blob().readall())
                    scores = data.get("scores",{})
                    pii    = data.get("pii_by_risk",{})
                    qual   = data.get("quality",{})
                    dupes  = data.get("duplicates",{})
                    shape  = data.get("shape",{})

                    st.markdown(f"""
<div style="display:flex;gap:20px;padding:12px 20px;background:#ffffff;border:1px solid #e8eaf0;
            border-radius:10px;margin:16px 0;flex-wrap:wrap;">
    <span style="font-size:13px;font-weight:600;color:#0f172a;">{data.get('file','unknown')}</span>
    <span style="font-size:12px;color:#94a3b8;font-family:'JetBrains Mono',monospace;">
        {data.get('scanned_at','')[:19].replace('T','  ')}
    </span>
    <span style="font-size:12px;color:#94a3b8;">{shape.get('rows',0):,} rows · {shape.get('columns',0)} cols</span>
    <span style="font-size:12px;background:#eff6ff;color:#2563eb;padding:2px 10px;border-radius:20px;font-weight:600;">
        Azure Function
    </span>
</div>""", unsafe_allow_html=True)

                    # Score + gauges
                    cs, cg = st.columns([1,2])
                    with cs:
                        ov = scores.get("overall",0)
                        color = sc(ov); bg = sc_bg(ov)
                        st.markdown(f"""
<div class="score-card" style="background:{bg};height:100%;">
    <div class="stat-label">Health Score</div>
    <div class="score-number" style="color:{color};">{ov}</div>
    <div class="score-grade" style="color:{color};">{scores.get("grade","")}</div>
    <div class="score-meta">Sensitivity: {data.get("sensitivity","medium").upper()}</div>
</div>""", unsafe_allow_html=True)
                    with cg:
                        g1,g2,g3 = st.columns(3)
                        for cw,key,lbl in [(g1,"privacy","PRIVACY"),(g2,"quality","QUALITY"),(g3,"completeness","COMPLETENESS")]:
                            with cw:
                                st.markdown('<div class="score-card" style="padding:16px;">', unsafe_allow_html=True)
                                st.plotly_chart(gauge(scores.get(key,0),lbl), use_container_width=True, config={"displayModeBar":False})
                                st.markdown('</div>', unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)
                    m1,m2,m3 = st.columns(3)

                    with m1:
                        h,med,lo = pii.get("HIGH",0),pii.get("MEDIUM",0),pii.get("LOW",0)
                        st.markdown(f"""
<div class="score-card">
    <div class="sec-header">PII Exposure</div>
    <div style="display:flex;gap:8px;margin-bottom:16px;">
        <div style="flex:1;text-align:center;background:#fef2f2;border-radius:8px;padding:12px 8px;">
            <div style="font-size:24px;font-weight:700;color:#dc2626;font-family:'JetBrains Mono',monospace;">{h}</div>
            <div style="font-size:11px;font-weight:600;color:#dc2626;">HIGH</div>
        </div>
        <div style="flex:1;text-align:center;background:#fffbeb;border-radius:8px;padding:12px 8px;">
            <div style="font-size:24px;font-weight:700;color:#d97706;font-family:'JetBrains Mono',monospace;">{med}</div>
            <div style="font-size:11px;font-weight:600;color:#d97706;">MED</div>
        </div>
        <div style="flex:1;text-align:center;background:#f8fafc;border-radius:8px;padding:12px 8px;">
            <div style="font-size:24px;font-weight:700;color:#94a3b8;font-family:'JetBrains Mono',monospace;">{lo}</div>
            <div style="font-size:11px;font-weight:600;color:#94a3b8;">LOW</div>
        </div>
    </div>
</div>""", unsafe_allow_html=True)
                        findings = data.get("pii_findings",[])
                        if findings:
                            with st.expander(f"View {len(findings)} finding(s)"):
                                for f in findings:
                                    rc = {"HIGH":"risk-high","MEDIUM":"risk-medium","LOW":"risk-low"}.get(f["risk"],"risk-low")
                                    st.markdown(f"""
<div class="finding-row">
    <span class="risk-badge {rc}">{f["risk"]}</span>
    <div>
        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#0f172a;">{f["masked"]}</div>
        <div style="font-size:11px;color:#94a3b8;">row {f["row"]} · {f["column"]} · {int(f["confidence"]*100)}%</div>
    </div>
</div>""", unsafe_allow_html=True)

                    with m2:
                        st.markdown('<div class="score-card">', unsafe_allow_html=True)
                        st.markdown('<div class="sec-header">Quality Checks</div>', unsafe_allow_html=True)
                        st.plotly_chart(donut(qual.get("passed",0), qual.get("failed",0)),
                                        use_container_width=True, config={"displayModeBar":False})
                        for r in qual.get("results",[]):
                            badge = '<span class="risk-badge risk-pass">PASS</span>' if r["passed"] else '<span class="risk-badge risk-fail">FAIL</span>'
                            st.markdown(f"""
<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid #f1f5f9;">
    {badge}<span style="font-size:12.5px;color:#374151;">{r["check"]} — {r["column"]}</span>
</div>""", unsafe_allow_html=True)
                        st.markdown('</div>', unsafe_allow_html=True)

                    with m3:
                        dp = dupes.get("duplicate_pct",0)
                        dc = sc(max(0,100-dp*5))
                        st.markdown(f"""
<div class="score-card" style="text-align:center;margin-bottom:12px;">
    <div class="stat-label">Duplicate Rate</div>
    <div style="font-size:44px;font-weight:700;color:{dc};font-family:'JetBrains Mono',monospace;">{dp}%</div>
    <div style="font-size:12px;color:#94a3b8;">{dupes.get("exact_duplicates",0)} exact · {dupes.get("total_rows",0):,} total rows</div>
</div>""", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)
                    st.download_button("⬇  Download JSON result", data=json.dumps(data,indent=2,default=str),
                                       file_name=selected, mime="application/json")

        except Exception as e:
            st.markdown(f"""
<div class="alert-critical">
    <strong style="color:#dc2626;">Connection failed</strong>
    <p style="color:#7f1d1d;margin:4px 0 0;font-size:13px;">{str(e)}</p>
</div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
<div class="alert-info">
    <strong style="color:#1d4ed8;">Connect your Azure storage</strong>
    <p style="color:#1e3a8a;margin:4px 0 0;font-size:13px;">
        Paste your connection string above to browse all cloud scan results visually.
        Find it in Azure Portal → Storage Accounts → dataguardswe2026 → Access keys.
    </p>
</div>""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — HOW IT WORKS
# ════════════════════════════════════════════════════════════════════════════════
# ════════════════════════════════════════════════════════════════════════════════
# TAB 3 — ANALYTICS (Gold layer — historical trends from metrics/quality_metrics.csv)
# ════════════════════════════════════════════════════════════════════════════════
with tab_analytics:
    st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

    st.markdown("""
<div style="padding:32px 0 24px;">
    <div style="font-size:13px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;
                color:#94a3b8;margin-bottom:8px;">Gold Layer — Medallion Architecture</div>
    <div style="font-size:26px;font-weight:700;color:#0f172a;letter-spacing:-0.5px;margin-bottom:8px;">
        Dataset Health Analytics
    </div>
    <div style="font-size:14px;color:#64748b;">
        Historical scan metrics from Azure Blob Storage — every scan appends a row to
        <code style="background:#f1f5f9;padding:2px 6px;border-radius:4px;">metrics/quality_metrics.csv</code>
    </div>
</div>
""", unsafe_allow_html=True)

    # Connection string input
    az_conn = st.text_input(
        "Azure Storage Connection String",
        type="password",
        placeholder="DefaultEndpointsProtocol=https;AccountName=dataguardswe2026;AccountKey=...",
        key="analytics_conn",
        help="Paste your connection string to load Gold layer metrics",
    )

    if az_conn:
        try:
            from azure.storage.blob import BlobServiceClient
            import plotly.express as px

            # Load quality_metrics.csv from Gold layer
            blob_client = BlobServiceClient.from_connection_string(az_conn)\
                .get_blob_client(container="metrics", blob="quality_metrics.csv")
            raw = blob_client.download_blob().readall().decode("utf-8")
            metrics_df = pd.read_csv(pd.io.common.StringIO(raw))
            metrics_df["timestamp"] = pd.to_datetime(metrics_df["timestamp"])
            metrics_df = metrics_df.sort_values("timestamp")

            if len(metrics_df) == 0:
                st.markdown("""
<div class="alert-info">
    No scan history yet. Run a scan first to populate the Gold layer.
</div>""", unsafe_allow_html=True)
            else:
                # ── Summary metrics ───────────────────────────────────────────
                st.markdown("""
<div style="font-size:12px;font-weight:600;letter-spacing:0.6px;text-transform:uppercase;
            color:#94a3b8;margin-bottom:14px;">Summary</div>
""", unsafe_allow_html=True)

                m1, m2, m3, m4, m5 = st.columns(5)
                avg_score  = round(metrics_df["health_score"].mean(), 1)
                total_scans= len(metrics_df)
                total_high = int(metrics_df["high_pii"].sum())
                avg_quality= round(metrics_df["quality_score"].mean(), 1)
                last_score = int(metrics_df["health_score"].iloc[-1])
                trend      = int(metrics_df["health_score"].iloc[-1]) - int(metrics_df["health_score"].iloc[0]) if len(metrics_df) > 1 else 0
                trend_str  = f"↑ {trend}" if trend > 0 else f"↓ {abs(trend)}" if trend < 0 else "→ stable"
                trend_color= "#16a34a" if trend >= 0 else "#dc2626"

                for col_w, val, label, color in [
                    (m1, total_scans,         "Total scans",       "#2563eb"),
                    (m2, f"{avg_score}",      "Avg health score",  sc(int(avg_score))),
                    (m3, total_high,           "Total HIGH PII",    "#dc2626"),
                    (m4, f"{avg_quality}%",   "Avg quality score", sc(int(avg_quality))),
                    (m5, trend_str,           "Score trend",       trend_color),
                ]:
                    with col_w:
                        st.markdown(f"""
<div class="stat-card">
    <div class="stat-label">{label}</div>
    <div style="font-size:28px;font-weight:700;color:{color};
                font-family:'JetBrains Mono',monospace;">{val}</div>
</div>""", unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Health score trend line ───────────────────────────────────
                st.markdown("""
<div style="font-size:12px;font-weight:600;letter-spacing:0.6px;text-transform:uppercase;
            color:#94a3b8;margin-bottom:14px;">Health Score Trend</div>
""", unsafe_allow_html=True)

                fig_trend = go.Figure()
                fig_trend.add_trace(go.Scatter(
                    x=metrics_df["timestamp"],
                    y=metrics_df["health_score"],
                    mode="lines+markers",
                    name="Health Score",
                    line=dict(color="#2563eb", width=2.5),
                    marker=dict(size=8, color=metrics_df["health_score"].apply(sc).tolist()),
                    hovertemplate="<b>%{y}/100</b><br>%{x}<br><extra></extra>",
                ))
                # Grade zones
                fig_trend.add_hrect(y0=85, y1=100, fillcolor="#f0fdf4", opacity=0.4, line_width=0, annotation_text="A — Healthy", annotation_position="right")
                fig_trend.add_hrect(y0=70, y1=85,  fillcolor="#fffbeb", opacity=0.4, line_width=0, annotation_text="B — Acceptable", annotation_position="right")
                fig_trend.add_hrect(y0=0,  y1=70,  fillcolor="#fef2f2", opacity=0.3, line_width=0, annotation_text="Needs attention", annotation_position="right")

                fig_trend.update_layout(
                    height=320,
                    paper_bgcolor="white", plot_bgcolor="white",
                    yaxis=dict(range=[0,100], title="Health Score", gridcolor="#f1f5f9"),
                    xaxis=dict(title="", gridcolor="#f1f5f9"),
                    margin=dict(t=20, b=20, l=40, r=80),
                    showlegend=False,
                    font=dict(family="Inter", size=12, color="#374151"),
                )
                st.plotly_chart(fig_trend, use_container_width=True, config={"displayModeBar": False})

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Three charts row ──────────────────────────────────────────
                ch1, ch2, ch3 = st.columns(3)

                with ch1:
                    st.markdown('<div class="score-card">', unsafe_allow_html=True)
                    st.markdown('<div class="sec-header">PII Exposure Over Time</div>', unsafe_allow_html=True)
                    fig_pii = go.Figure()
                    fig_pii.add_trace(go.Bar(x=metrics_df["filename"], y=metrics_df["high_pii"],
                        name="HIGH", marker_color="#dc2626", hovertemplate="%{y} HIGH<extra></extra>"))
                    fig_pii.add_trace(go.Bar(x=metrics_df["filename"], y=metrics_df["medium_pii"],
                        name="MEDIUM", marker_color="#d97706", hovertemplate="%{y} MEDIUM<extra></extra>"))
                    fig_pii.add_trace(go.Bar(x=metrics_df["filename"], y=metrics_df["low_pii"],
                        name="LOW", marker_color="#cbd5e1", hovertemplate="%{y} LOW<extra></extra>"))
                    fig_pii.update_layout(
                        barmode="stack", height=220,
                        paper_bgcolor="white", plot_bgcolor="white",
                        margin=dict(t=10,b=40,l=30,r=10),
                        legend=dict(orientation="h", y=-0.3, font=dict(size=10)),
                        xaxis=dict(tickfont=dict(size=9), tickangle=-30),
                        yaxis=dict(gridcolor="#f1f5f9"),
                        font=dict(family="Inter", size=11),
                    )
                    st.plotly_chart(fig_pii, use_container_width=True, config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

                with ch2:
                    st.markdown('<div class="score-card">', unsafe_allow_html=True)
                    st.markdown('<div class="sec-header">Quality Score by Scan</div>', unsafe_allow_html=True)
                    colors_q = [sc(int(v)) for v in metrics_df["quality_score"]]
                    fig_q = go.Figure(go.Bar(
                        x=metrics_df["filename"],
                        y=metrics_df["quality_score"],
                        marker_color=colors_q,
                        hovertemplate="%{y}%<extra></extra>",
                    ))
                    fig_q.update_layout(
                        height=220,
                        paper_bgcolor="white", plot_bgcolor="white",
                        margin=dict(t=10,b=40,l=30,r=10),
                        yaxis=dict(range=[0,100], gridcolor="#f1f5f9"),
                        xaxis=dict(tickfont=dict(size=9), tickangle=-30),
                        font=dict(family="Inter", size=11),
                    )
                    st.plotly_chart(fig_q, use_container_width=True, config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

                with ch3:
                    st.markdown('<div class="score-card">', unsafe_allow_html=True)
                    st.markdown('<div class="sec-header">Duplicate Rate Trend</div>', unsafe_allow_html=True)
                    fig_dup = go.Figure(go.Scatter(
                        x=metrics_df["timestamp"],
                        y=metrics_df["duplicate_pct"],
                        mode="lines+markers",
                        fill="tozeroy",
                        fillcolor="rgba(220,38,38,0.08)",
                        line=dict(color="#dc2626", width=2),
                        marker=dict(size=7, color="#dc2626"),
                        hovertemplate="%{y}%<extra></extra>",
                    ))
                    fig_dup.update_layout(
                        height=220,
                        paper_bgcolor="white", plot_bgcolor="white",
                        margin=dict(t=10,b=20,l=30,r=10),
                        yaxis=dict(gridcolor="#f1f5f9", ticksuffix="%"),
                        xaxis=dict(gridcolor="#f1f5f9"),
                        font=dict(family="Inter", size=11),
                    )
                    st.plotly_chart(fig_dup, use_container_width=True, config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Dimension scores radar ────────────────────────────────────
                r1, r2 = st.columns([1.5, 1])

                with r1:
                    st.markdown('<div class="score-card">', unsafe_allow_html=True)
                    st.markdown('<div class="sec-header">Dimension Scores — All Scans</div>', unsafe_allow_html=True)
                    fig_multi = go.Figure()
                    for _, row in metrics_df.iterrows():
                        fig_multi.add_trace(go.Scatterpolar(
                            r=[row["privacy_score"], row["quality_score"],
                               row["completeness_score"], row["privacy_score"]],
                            theta=["Privacy", "Quality", "Completeness", "Privacy"],
                            mode="lines",
                            name=row["filename"][:20],
                            line=dict(width=1.5),
                            opacity=0.75,
                        ))
                    fig_multi.update_layout(
                        polar=dict(
                            radialaxis=dict(visible=True, range=[0,100],
                                           tickfont=dict(size=9), gridcolor="#e2e8f0"),
                            angularaxis=dict(tickfont=dict(size=11)),
                        ),
                        height=280,
                        paper_bgcolor="white",
                        margin=dict(t=20,b=20,l=20,r=20),
                        legend=dict(font=dict(size=9), orientation="h", y=-0.15),
                        font=dict(family="Inter"),
                        showlegend=True,
                    )
                    st.plotly_chart(fig_multi, use_container_width=True, config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

                with r2:
                    st.markdown('<div class="score-card" style="height:100%;">', unsafe_allow_html=True)
                    st.markdown('<div class="sec-header">Grade Distribution</div>', unsafe_allow_html=True)
                    grade_counts = metrics_df["grade"].value_counts()
                    grade_colors = {"A — Healthy":"#16a34a","B — Acceptable":"#d97706",
                                    "C — Needs attention":"#ea580c","D — At risk":"#dc2626","F — Critical":"#7f1d1d"}
                    fig_grade = go.Figure(go.Pie(
                        labels=grade_counts.index,
                        values=grade_counts.values,
                        hole=0.6,
                        marker_colors=[grade_colors.get(g,"#94a3b8") for g in grade_counts.index],
                        textinfo="label+percent",
                        textfont=dict(size=10),
                        hovertemplate="%{label}: %{value} scan(s)<extra></extra>",
                    ))
                    fig_grade.update_layout(
                        height=280,
                        paper_bgcolor="white",
                        margin=dict(t=10,b=10,l=10,r=10),
                        showlegend=False,
                        font=dict(family="Inter"),
                    )
                    st.plotly_chart(fig_grade, use_container_width=True, config={"displayModeBar": False})
                    st.markdown('</div>', unsafe_allow_html=True)

                st.markdown("<br>", unsafe_allow_html=True)

                # ── Raw metrics table ─────────────────────────────────────────
                with st.expander("📊  Raw metrics table — all scan history"):
                    display_df = metrics_df.copy()
                    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M")
                    display_df["health_score"] = display_df["health_score"].astype(str) + "/100"
                    st.dataframe(display_df, use_container_width=True, hide_index=True)

                # ── Download Gold layer ───────────────────────────────────────
                st.download_button(
                    "⬇  Download quality_metrics.csv",
                    data=raw,
                    file_name="quality_metrics.csv",
                    mime="text/csv",
                )

        except Exception as e:
            st.markdown(f"""
<div class="alert-critical">
    <strong style="color:#dc2626;">Failed to load metrics</strong>
    <p style="color:#7f1d1d;margin:4px 0 0;font-size:13px;">{str(e)}</p>
</div>""", unsafe_allow_html=True)
    else:
        st.markdown("""
<div class="alert-info">
    <strong style="color:#1d4ed8;">Connect to Azure</strong>
    <p style="color:#1e3a8a;margin:4px 0 0;font-size:13px;">
        Paste your Azure Storage connection string above to load your Gold layer analytics.
        Every scan you run adds a row to <code>metrics/quality_metrics.csv</code> automatically.
    </p>
</div>""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)


with tab_history:
    st.markdown('<div class="content-wrap">', unsafe_allow_html=True)

    st.markdown("""
<div style="padding:40px 0 32px;text-align:center;">
    <div style="font-size:13px;font-weight:600;letter-spacing:0.8px;text-transform:uppercase;
                color:#94a3b8;margin-bottom:12px;">Under the hood</div>
    <div style="font-size:28px;font-weight:700;color:#0f172a;letter-spacing:-0.5px;">
        Enterprise-grade. Zero infrastructure required.
    </div>
</div>
""", unsafe_allow_html=True)

    steps = [
        ("#2563eb", "Upload", "Drag a CSV into the scanner. Your data is read into memory — never written to disk."),
        ("#7c3aed", "PII Scan", "8 regex patterns run across every cell. A context scoring function assigns HIGH / MEDIUM / LOW confidence based on column name semantics."),
        ("#16a34a", "Quality Suite", "Great Expectations v1.x auto-generates validation rules from column names. Zero configuration."),
        ("#d97706", "Schema Drift", "If you've saved a baseline, the current schema is compared against it. Risky new columns trigger CRITICAL alerts."),
        ("#ea580c", "Industry Pack", "Optional domain-specific checks — ship dates, tax math, patient ages — catch errors generic tools miss."),
        ("#0f172a", "Remediate", "Mask PII values and drop duplicates in one click. Download the sanitized CSV."),
    ]

    c1, c2, c3 = st.columns(3)
    for i, (color, title, desc) in enumerate(steps):
        col = [c1,c2,c3][i%3]
        with col:
            st.markdown(f"""
<div class="stat-card" style="margin-bottom:14px;">
    <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
        <div style="width:32px;height:32px;background:{color};border-radius:8px;
                    display:flex;align-items:center;justify-content:center;
                    font-size:13px;font-weight:700;color:white;font-family:'JetBrains Mono',monospace;">
            {i+1:02d}
        </div>
        <div style="font-size:14px;font-weight:600;color:#0f172a;">{title}</div>
    </div>
    <div style="font-size:13px;color:#64748b;line-height:1.6;">{desc}</div>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("""
<div style="background:#0f172a;border-radius:16px;padding:32px 40px;text-align:center;">
    <div style="font-size:20px;font-weight:700;color:#ffffff;margin-bottom:8px;">
        Live on Azure
    </div>
    <div style="font-size:13.5px;color:#94a3b8;max-width:440px;margin:0 auto 20px;">
        Send any CSV directly to the cloud endpoint. Results save automatically to Azure Blob Storage.
    </div>
    <code style="background:rgba(255,255,255,0.08);color:#60a5fa;padding:10px 20px;
                 border-radius:8px;font-size:13px;display:inline-block;">
        POST https://dataguard-func-app.azurewebsites.net/api/dataguardscanner
    </code>
</div>
""", unsafe_allow_html=True)

    st.markdown('</div>', unsafe_allow_html=True)