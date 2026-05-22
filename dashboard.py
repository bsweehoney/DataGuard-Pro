"""
Data Governance Agency — Health Dashboard v2
=============================================
Upgrades:
  - Sensitivity slider (Low / Medium / High)
  - Industry pack selector (E-commerce / Finance / Healthcare)
  - Schema drift detection panel
  - Risk-level coloring (HIGH / MEDIUM / LOW) with partial masking
  - Cross-column validation results
  - Schema baseline save/compare

Run:
    pip install streamlit plotly
    streamlit run dashboard.py
"""

import re
import json
import warnings
import sys
from datetime import datetime
from collections import defaultdict
from pathlib import Path
import importlib.util

import streamlit as st
import pandas as pd
import plotly.graph_objects as go

warnings.filterwarnings("ignore")

# ── Import scanner from data_health_check.py ─────────────────────────────────
def _load_scanner():
    scanner_path = Path(__file__).parent / "data_health_check.py"
    if scanner_path.exists():
        spec = importlib.util.spec_from_file_location("dhc", scanner_path)
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
    save_schema_baseline    = _dhc.save_schema_baseline
    INDUSTRY_PACKS          = _dhc.INDUSTRY_PACKS
else:
    scan_for_pii = None  # flag — handled gracefully in main UI

# ── Session state initialisation ──────────────────────────────────────────────
if "memory_baseline" not in st.session_state:
    st.session_state.memory_baseline = None
if "cleansed_df" not in st.session_state:
    st.session_state.cleansed_df = None


# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Data Health Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500;600&display=swap');
html, body, [class*="css"] { font-family: 'DM Sans', sans-serif; }
#MainMenu {visibility:hidden;} footer {visibility:hidden;} header {visibility:hidden;}
.stApp { background:#0e0f11; color:#e8e6e0; }
section[data-testid="stSidebar"] { background:#13151a; border-right:1px solid #1e2028; }
section[data-testid="stSidebar"] * { color:#9a9890 !important; }
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3 {
    color:#e8e6e0 !important; font-family:'DM Mono',monospace !important;
    font-size:13px !important; letter-spacing:.08em; text-transform:uppercase;
}
.metric-card { background:#13151a; border:1px solid #1e2028; border-radius:12px; padding:20px 24px; }
.score-hero { font-family:'DM Mono',monospace; font-size:80px; font-weight:500; line-height:1; letter-spacing:-2px; }
.score-grade { font-family:'DM Mono',monospace; font-size:13px; letter-spacing:.1em; text-transform:uppercase; margin-top:4px; }
.section-header { font-family:'DM Mono',monospace; font-size:11px; letter-spacing:.12em; text-transform:uppercase; color:#4a4a52; margin-bottom:12px; padding-bottom:8px; border-bottom:1px solid #1e2028; }
.badge { display:inline-block; padding:2px 9px; border-radius:4px; font-family:'DM Mono',monospace; font-size:11px; margin-right:5px; margin-bottom:3px; }
.badge-high   { background:#2a1515; border:1px solid #5c1f1f; color:#e05555; }
.badge-medium { background:#2a200f; border:1px solid #5c4010; color:#e8a93a; }
.badge-low    { background:#1a1c24; border:1px solid #2a2d38; color:#9a9890; }
.badge-pass   { background:#0f2318; border:1px solid #1a4a2a; color:#3db86a; }
.badge-fail   { background:#2a1515; border:1px solid #5c1f1f; color:#e05555; }
.badge-warn   { background:#1e1a12; border:1px solid #3a3010; color:#c8891a; }
.alert-critical { background:#1a0808; border:1px solid #5c1f1f; border-radius:8px; padding:14px 18px; margin-bottom:10px; }
.alert-warning  { background:#191408; border:1px solid #4a3810; border-radius:8px; padding:14px 18px; margin-bottom:10px; }
.alert-info     { background:#0e1218; border:1px solid #1e2a38; border-radius:8px; padding:14px 18px; margin-bottom:10px; }
[data-testid="stFileUploader"] { background:#13151a; border:1px dashed #2a2d38; border-radius:12px; padding:8px; }
.stButton > button { background:#1a1c24; border:1px solid #2a2d38; color:#e8e6e0; font-family:'DM Mono',monospace; font-size:12px; letter-spacing:.06em; border-radius:6px; padding:8px 20px; }
.stButton > button:hover { background:#22242e; border-color:#3a3d4a; }
h1, h2, h3 { color:#e8e6e0 !important; }
p, li { color:#9a9890; }
.stSlider > div > div { background:#1e2028 !important; }

/* Expanders — match dark theme */
div[data-testid="stExpander"] {
    background:#13151a !important;
    border:1px solid #1e2028 !important;
    border-radius:8px !important;
    margin-bottom:8px !important;
}
div[data-testid="stExpander"] summary {
    font-family:'DM Mono',monospace !important;
    color:#e8e6e0 !important;
    font-size:13px !important;
}

/* DataFrames — prevent white flash */
div[data-testid="stDataFrame"] {
    background:#13151a !important;
    border:1px solid #1e2028 !important;
    border-radius:8px !important;
}

/* Inline code in markdown */
div[data-testid="stMarkdown"] code {
    background:#1a1c24 !important;
    color:#e8a93a !important;
    padding:2px 6px !important;
    border-radius:4px !important;
    font-size:12px !important;
}

/* Success / info toast messages */
div[data-testid="stAlert"] {
    background:#13151a !important;
    border:1px solid #1e2028 !important;
    border-radius:8px !important;
    color:#e8e6e0 !important;
}

/* Sanitized CSV download strip */
.remediation-bar {
    background:#0f1a12;
    border:1px solid #1a4a2a;
    border-radius:8px;
    padding:14px 18px;
    margin-bottom:10px;
    display:flex;
    align-items:center;
    gap:16px;
}
</style>
""", unsafe_allow_html=True)


# ── Helpers ───────────────────────────────────────────────────────────────────

def score_color(s):
    if s >= 85: return "#3db86a"
    if s >= 70: return "#e8a93a"
    if s >= 55: return "#e07a2a"
    return "#e05555"

def gauge(score, label):
    c = score_color(score)
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"font": {"size": 36, "family": "DM Mono", "color": c}, "suffix": ""},
        gauge={"axis": {"range": [0,100], "tickwidth":0, "tickcolor":"#2a2d38",
                        "tickfont": {"color":"#4a4a52","size":10}},
               "bar": {"color": c, "thickness": 0.25},
               "bgcolor": "#13151a", "borderwidth": 0,
               "steps": [{"range":[0,40],"color":"#1a0f0f"},
                         {"range":[40,70],"color":"#1a1508"},
                         {"range":[70,100],"color":"#0f1a12"}],
               "threshold": {"line":{"color":c,"width":2},"thickness":0.75,"value":score}},
        title={"text": label, "font": {"size":11,"family":"DM Mono","color":"#4a4a52"}},
    ))
    fig.update_layout(height=180, margin=dict(t=30,b=0,l=20,r=20),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e8e6e0")
    return fig

def donut(passed, failed):
    fig = go.Figure(go.Pie(
        values=[passed, failed] if (passed+failed) > 0 else [1, 0],
        labels=["Passed","Failed"], hole=0.72,
        marker_colors=["#3db86a","#e05555"] if (passed+failed)>0 else ["#3db86a","#3db86a"],
        textinfo="none", hoverinfo="label+value",
    ))
    fig.add_annotation(text=f"<b>{passed}</b><br><span style='font-size:10px'>passed</span>",
                       x=0.5, y=0.5, showarrow=False,
                       font=dict(size=18, family="DM Mono", color="#e8e6e0"))
    fig.update_layout(height=200, margin=dict(t=10,b=10,l=10,r=10),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", showlegend=False)
    return fig

def pii_bar(pii_by_risk):
    if not pii_by_risk: return None
    labels = list(pii_by_risk.keys())
    counts = [pii_by_risk[k] for k in labels]
    colors = {"HIGH":"#e05555","MEDIUM":"#e8a93a","LOW":"#4a4a52"}
    bar_colors = [colors.get(l,"#4a4a52") for l in labels]
    fig = go.Figure(go.Bar(x=counts, y=labels, orientation="h",
                           marker_color=bar_colors, marker_line_width=0,
                           text=counts, textposition="outside",
                           textfont=dict(family="DM Mono",size=12,color="#e8e6e0")))
    fig.update_layout(height=max(100,len(labels)*50), margin=dict(t=5,b=5,l=10,r=40),
                      paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                      xaxis=dict(showgrid=False,showticklabels=False,zeroline=False),
                      yaxis=dict(tickfont=dict(family="DM Mono",size=12,color="#9a9890")))
    return fig

def load_csv(f):
    df = pd.read_csv(f, dtype=str, low_memory=False)
    for col in df.columns:
        try: df[col] = pd.to_numeric(df[col])
        except (ValueError, TypeError): pass
    return df

def bold(text):
    return re.sub(r'\*\*(.+?)\*\*', r'<strong style="color:#e8e6e0">\1</strong>', text)


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🛡️ Data Governance")
    st.markdown("---")

    st.markdown("### Upload")
    uploaded = st.file_uploader("Drop a CSV file", type=["csv"], label_visibility="collapsed")

    st.markdown("---")
    st.markdown("### Scan settings")

    sensitivity = st.select_slider(
        "PII sensitivity",
        options=["low", "medium", "high"],
        value="medium",
        help="Low = only SSNs & cards. High = all patterns including emails & IPs.",
    )

    pack_choice = st.selectbox(
        "Industry pack",
        options=["None", "ecommerce", "finance", "healthcare"],
        help="Run business-logic checks specific to your industry.",
    )
    pack_name = None if pack_choice == "None" else pack_choice

    st.markdown("---")
    st.markdown("### Schema drift")
    schema_file = st.file_uploader("Upload baseline schema (JSON)", type=["json"],
                                   label_visibility="collapsed")

    # Session memory status
    if st.session_state.memory_baseline:
        cols_count = len(st.session_state.memory_baseline.get("columns", []))
        saved_at   = st.session_state.memory_baseline.get("saved_at","")[:10]
        st.markdown(f"""
<div style="font-family:'DM Mono',monospace;font-size:11px;color:#3db86a;
            padding:8px 10px;background:#0f1a12;border:1px solid #1a4a2a;
            border-radius:6px;margin-top:6px;">
    ✓ Session baseline active<br/>
    <span style="color:#4a4a52">{cols_count} cols · saved {saved_at}</span>
</div>""", unsafe_allow_html=True)
        if st.button("🗑  Clear session baseline"):
            st.session_state.memory_baseline = None
            st.rerun()

    st.markdown("---")
    st.markdown("### About")
    st.markdown("""
Scans for:
- **PII** — SSNs, phones, cards, DOBs in free-text fields
- **Quality** — nulls, bad formats, out-of-range values
- **Duplicates** — exact and near-matches
- **Schema drift** — new columns since last baseline
- **Business logic** — industry-specific math & date rules

Your data is **never stored.**
    """)

    st.markdown("### Scoring")
    st.markdown("""
| Score | Grade |
|-------|-------|
| 85–100 | A — Healthy |
| 70–84 | B — Acceptable |
| 55–69 | C — Needs attention |
| 40–54 | D — At risk |
| 0–39 | F — Critical |
""")


# ── Main ──────────────────────────────────────────────────────────────────────

st.markdown("""
<div style="padding:2rem 0 1.5rem;">
    <div style="font-family:'DM Mono',monospace;font-size:11px;letter-spacing:.14em;
                text-transform:uppercase;color:#4a4a52;margin-bottom:8px;">Data Governance Agency</div>
    <h1 style="font-family:'DM Sans',sans-serif;font-size:32px;font-weight:300;
               color:#e8e6e0;margin:0;letter-spacing:-0.5px;">Data Health Dashboard</h1>
</div>
""", unsafe_allow_html=True)

if scan_for_pii is None:
    st.markdown("""
<div class="alert-critical">
    <strong style="color:#e05555;font-family:'DM Mono',monospace;font-size:14px;">
        ⚙️ CORE ENGINE OFFLINE
    </strong>
    <p style="color:#e07070;margin:6px 0 0;font-size:13px;">
        <code>data_health_check.py</code> was not found in the same folder as this dashboard.
        Place both files together and restart Streamlit.
    </p>
</div>
""", unsafe_allow_html=True)
    st.stop()

if uploaded is None:
    # Landing
    st.markdown("""
<div style="margin-top:3rem;text-align:center;padding:4rem 2rem;
            background:#13151a;border:1px dashed #2a2d38;border-radius:16px;">
    <div style="font-size:48px;margin-bottom:1rem;">🛡️</div>
    <div style="font-family:'DM Mono',monospace;font-size:13px;color:#4a4a52;
                letter-spacing:.08em;text-transform:uppercase;margin-bottom:8px;">Ready to scan</div>
    <p style="color:#6a6860;font-size:15px;max-width:440px;margin:0 auto;">
        Upload a CSV in the sidebar. Choose your sensitivity level and industry pack,
        then get your Data Health Score in seconds.
    </p>
</div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        ("🔍", "PII Detection", "Finds sensitive data hiding in free-text fields, not just dedicated columns."),
        ("📊", "Context Scoring", "HIGH / MEDIUM / LOW confidence — serial numbers won't be flagged as SSNs."),
        ("🔄", "Schema Drift", "Alerts you when risky new columns like `customer_passwords` appear."),
        ("🏭", "Industry Packs", "E-commerce, Finance, Healthcare business logic checks beyond basic validation."),
    ]
    for col, (icon, title, desc) in zip([c1,c2,c3,c4], cards):
        with col:
            st.markdown(f"""
<div class="metric-card">
    <div style="font-size:24px;margin-bottom:8px;">{icon}</div>
    <div style="font-family:'DM Mono',monospace;font-size:11px;color:#4a4a52;
                text-transform:uppercase;letter-spacing:.08em;margin-bottom:6px;">{title}</div>
    <p style="font-size:13px;color:#6a6860;margin:0;">{desc}</p>
</div>""", unsafe_allow_html=True)

else:
    filename = uploaded.name

    with st.spinner("Scanning..."):
        df = load_csv(uploaded)

        # Schema drift — file upload OR session memory (session takes priority if no file)
        drift = None
        active_baseline = None
        if schema_file:
            active_baseline = json.load(schema_file)
        elif st.session_state.memory_baseline:
            active_baseline = st.session_state.memory_baseline

        if active_baseline:
            import tempfile, os
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
                json.dump(active_baseline, tmp)
                tmp_path = tmp.name
            drift = detect_schema_drift(df, tmp_path)
            os.unlink(tmp_path)

        pii_findings = scan_for_pii(df, sensitivity=sensitivity)
        quality = run_quality_checks(df, build_expectation_suite(df, {}))
        dupes = check_duplicates(df)
        pack_results = INDUSTRY_PACKS[pack_name](df) if pack_name else None
        scores = calculate_score(pii_findings, quality, dupes, len(df), pack_results)

    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    pii_by_type = pii_findings_by_type(pii_findings)
    pii_by_risk = {
        "HIGH":   scores["pii_high_count"],
        "MEDIUM": scores["pii_medium_count"],
        "LOW":    scores["pii_low_count"],
    }
    total_real_pii = pii_by_risk["HIGH"] + pii_by_risk["MEDIUM"]

    # ── Schema drift alert (top of page) ─────────────────────────────────────
    if drift and drift.get("alerts"):
        for alert in drift["alerts"]:
            st.markdown(f"""
<div class="alert-critical">
    <strong style="color:#e05555;font-family:'DM Mono',monospace;font-size:12px;">
        🚨 CRITICAL SCHEMA ALERT
    </strong>
    <p style="color:#e07070;margin:4px 0 0;font-size:13px;">{alert['message']}</p>
</div>""", unsafe_allow_html=True)

    # ── File info bar ─────────────────────────────────────────────────────────
    sens_badge = {"low":"🟢 LOW","medium":"🟡 MEDIUM","high":"🔴 HIGH"}[sensitivity]
    st.markdown(f"""
<div style="display:flex;gap:20px;padding:12px 20px;background:#13151a;
            border:1px solid #1e2028;border-radius:10px;margin-bottom:24px;
            font-family:'DM Mono',monospace;font-size:12px;color:#4a4a52;flex-wrap:wrap;">
    <span>📄 <span style="color:#9a9890">{filename}</span></span>
    <span>⏱ <span style="color:#9a9890">{ts}</span></span>
    <span>📐 <span style="color:#9a9890">{len(df):,} rows × {len(df.columns)} columns</span></span>
    <span>🎯 <span style="color:#9a9890">Sensitivity: {sens_badge}</span></span>
    {f'<span>🏭 <span style="color:#9a9890">Pack: {pack_name}</span></span>' if pack_name else ''}
</div>
""", unsafe_allow_html=True)

    # ── Score hero ────────────────────────────────────────────────────────────
    col_score, col_gauges = st.columns([1, 2])
    with col_score:
        ov = scores["overall"]
        c  = score_color(ov)
        penalty_note = f'<div style="margin-top:6px;font-size:11px;color:#e8a93a;font-family:\'DM Mono\',monospace;">−{scores["pack_penalty"]}pts business logic</div>' if scores.get("pack_penalty") else ""
        st.markdown(f"""
<div class="metric-card" style="height:100%;min-height:220px;display:flex;flex-direction:column;justify-content:center;">
    <div class="section-header">Overall health score</div>
    <div class="score-hero" style="color:{c};">{ov}</div>
    <div class="score-grade" style="color:{c};">{scores['grade']}</div>
    {penalty_note}
    <div style="margin-top:14px;font-family:'DM Mono',monospace;font-size:11px;color:#4a4a52;">
        {len(df):,} rows · {datetime.now().strftime('%H:%M')}
    </div>
</div>""", unsafe_allow_html=True)

    with col_gauges:
        g1, g2, g3 = st.columns(3)
        for col_widget, score_key, label in [(g1,"privacy","PRIVACY"),(g2,"quality","QUALITY"),(g3,"completeness","COMPLETENESS")]:
            with col_widget:
                st.plotly_chart(gauge(scores[score_key], label), use_container_width=True,
                                config={"displayModeBar":False})

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Schema drift details ──────────────────────────────────────────────────
    if drift and drift["status"] != "no_baseline":
        st.markdown('<div class="section-header">Schema Drift Analysis</div>', unsafe_allow_html=True)
        if drift["status"] == "stable":
            st.markdown(f"""
<div class="alert-info">
    <span style="color:#3db86a;font-family:'DM Mono',monospace;font-size:12px;">✓ STABLE</span>
    <span style="color:#9a9890;font-size:13px;margin-left:10px;">
        Schema matches baseline saved on {drift['baseline_date'][:10]}
    </span>
</div>""", unsafe_allow_html=True)
        for change in drift.get("changes", []):
            cls = "alert-warning" if change["severity"] == "WARNING" else "alert-info"
            icon = "⚠️" if change["severity"] == "WARNING" else "ℹ️"
            st.markdown(f"""
<div class="{cls}">
    <span style="font-family:'DM Mono',monospace;font-size:12px;">{icon} {change['severity']}</span>
    <p style="color:#c8a060;margin:4px 0 0;font-size:13px;">{change['message']}</p>
</div>""", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

    # ── Three-column layout ───────────────────────────────────────────────────
    col_pii, col_qual, col_dupe = st.columns([1.2, 1.2, 0.8])

    # PII column
    with col_pii:
        st.markdown('<div class="section-header">PII Exposure</div>', unsafe_allow_html=True)

        # Risk summary bar chart
        if any(v > 0 for v in pii_by_risk.values()):
            fig = pii_bar(pii_by_risk)
            if fig: st.plotly_chart(fig, use_container_width=True, config={"displayModeBar":False})
        else:
            st.markdown("""
<div style="padding:20px;background:#0f1a12;border:1px solid #1a4a2a;
            border-radius:8px;text-align:center;margin-bottom:12px;">
    <div style="color:#3db86a;font-size:24px;">✓</div>
    <div style="font-family:'DM Mono',monospace;font-size:12px;color:#3db86a;margin-top:4px;">
        No PII detected
    </div>
</div>""", unsafe_allow_html=True)

        # Grouped by type
        for pii_type, hits in pii_by_type.items():
            # Determine dominant risk color for this type
            dominant_risk = hits[0]["risk"] if hits else "LOW"
            badge_cls = {"HIGH":"badge-high","MEDIUM":"badge-medium","LOW":"badge-low"}.get(dominant_risk,"badge-low")
            with st.expander(f"{pii_type}  —  {len(hits)} instance(s)"):
                for h in hits[:20]:
                    risk_cls = {"HIGH":"badge-high","MEDIUM":"badge-medium","LOW":"badge-low"}.get(h["risk"],"badge-low")
                    st.markdown(f"""
<div style="display:flex;gap:10px;align-items:flex-start;padding:6px 0;border-bottom:1px solid #1e2028;">
    <span class="badge {risk_cls}">{h['risk']}</span>
    <div style="flex:1;">
        <div style="font-family:'DM Mono',monospace;font-size:12px;color:#e8e6e0;">{h['masked']}</div>
        <div style="font-size:11px;color:#4a4a52;margin-top:2px;">
            row {h['row']} · col: {h['column']} · {int(h['confidence']*100)}% confidence
        </div>
        <div style="font-size:11px;color:#6a6860;margin-top:1px;">{h['reason']}</div>
    </div>
</div>""", unsafe_allow_html=True)
                if len(hits) > 20:
                    st.caption(f"… and {len(hits)-20} more")

        # Session baseline save controls
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown('<div class="section-header">Schema Baseline</div>', unsafe_allow_html=True)
        b1, b2 = st.columns(2)
        with b1:
            if st.button("💾  Save to session memory"):
                st.session_state.memory_baseline = {
                    "saved_at": datetime.now().isoformat(),
                    "columns":  list(df.columns),
                    "dtypes":   {col: str(df[col].dtype) for col in df.columns},
                    "row_count": len(df),
                }
                st.success(f"Baseline locked — {len(df.columns)} columns saved.")
                st.rerun()
        with b2:
            baseline_json = json.dumps({
                "saved_at": datetime.now().isoformat(),
                "columns":  list(df.columns),
                "dtypes":   {col: str(df[col].dtype) for col in df.columns},
                "row_count": len(df),
            }, indent=2)
            st.download_button(
                "⬇  Download baseline.json",
                data=baseline_json,
                file_name="baseline_schema.json",
                mime="application/json",
            )

    # Quality column
    with col_qual:
        st.markdown('<div class="section-header">Quality Checks</div>', unsafe_allow_html=True)
        st.plotly_chart(donut(quality["passed"], quality["failed"]),
                        use_container_width=True, config={"displayModeBar":False})

        for r in quality["results"]:
            badge = '<span class="badge badge-pass">PASS</span>' if r["passed"] else '<span class="badge badge-fail">FAIL</span>'
            col_label = f'<code style="font-size:11px;color:#6a6860">{r["column"]}</code>' if r["column"] != "—" else ""
            detail = ""
            if not r["passed"] and r.get("details"):
                d = r["details"]
                if "unexpected_count" in d:
                    detail = f'<div style="font-size:11px;color:#6a6860;padding-left:52px;margin-top:2px;">→ {d["unexpected_count"]} bad value(s) ({d.get("unexpected_percent",0):.1f}%)</div>'
            st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #1e2028;">
    {badge}
    <span style="font-size:12px;color:#9a9890;flex:1;">{r['check']}</span>
    {col_label}
</div>{detail}""", unsafe_allow_html=True)

        # Industry pack results
        if pack_results:
            st.markdown(f'<div class="section-header" style="margin-top:20px;">Industry Pack: {pack_name}</div>', unsafe_allow_html=True)
            for r in pack_results:
                if r.get("passed") is True:
                    badge = '<span class="badge badge-pass">PASS</span>'
                elif r.get("passed") is False:
                    badge = '<span class="badge badge-fail">FAIL</span>'
                else:
                    badge = '<span class="badge badge-low">N/A</span>'
                detail = f'<div style="font-size:11px;color:#e07a2a;padding-left:52px;margin-top:2px;">→ {r["detail"]}</div>' if not r.get("passed") and r.get("detail","All OK") != "All OK" else ""
                st.markdown(f"""
<div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid #1e2028;">
    {badge}
    <span style="font-size:12px;color:#9a9890;flex:1;">{r['check']}</span>
</div>{detail}""", unsafe_allow_html=True)

    # Duplicates column
    with col_dupe:
        st.markdown('<div class="section-header">Duplicates</div>', unsafe_allow_html=True)
        dupe_pct = dupes["duplicate_pct"]
        dupe_color = "#3db86a" if dupe_pct < 2 else "#e8a93a" if dupe_pct < 10 else "#e05555"
        st.markdown(f"""
<div class="metric-card" style="text-align:center;margin-bottom:12px;">
    <div style="font-family:'DM Mono',monospace;font-size:40px;color:{dupe_color};font-weight:500;">{dupe_pct}%</div>
    <div style="font-family:'DM Mono',monospace;font-size:10px;color:#4a4a52;text-transform:uppercase;letter-spacing:.08em;">duplicate rate</div>
</div>
<div class="metric-card" style="margin-bottom:12px;">
    <div style="font-family:'DM Mono',monospace;font-size:11px;color:#4a4a52;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">Breakdown</div>
    <div style="display:flex;justify-content:space-between;margin-bottom:8px;">
        <span style="font-size:13px;color:#9a9890;">Exact</span>
        <span style="font-family:'DM Mono',monospace;font-size:13px;color:{dupe_color};">{dupes['exact_duplicates']:,}</span>
    </div>
    <div style="display:flex;justify-content:space-between;">
        <span style="font-size:13px;color:#9a9890;">Near-match</span>
        <span style="font-family:'DM Mono',monospace;font-size:13px;color:#e8a93a;">{dupes['near_duplicates']:,}</span>
    </div>
</div>
<div class="metric-card">
    <div style="font-family:'DM Mono',monospace;font-size:11px;color:#4a4a52;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;">Total rows</div>
    <div style="font-family:'DM Mono',monospace;font-size:28px;color:#e8e6e0;">{dupes['total_rows']:,}</div>
</div>""", unsafe_allow_html=True)

    # ── Recommendations ───────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">Recommendations</div>', unsafe_allow_html=True)

    recs = []
    if scores["pii_high_count"] > 0:
        recs.append(("alert-critical", f"🔴 **CRITICAL** — Mask or remove **{scores['pii_high_count']} HIGH-confidence PII instance(s)** before storing or sharing."))
    if scores["pii_medium_count"] > 0:
        recs.append(("alert-warning", f"🟡 Review **{scores['pii_medium_count']} MEDIUM-confidence** PII finding(s) — may need manual verification."))
    if scores["pii_low_count"] > 0:
        recs.append(("alert-info", f"ℹ️ **{scores['pii_low_count']} LOW-confidence** finding(s) recorded — likely false positives in product/serial columns."))
    if quality["failed"] > 0:
        recs.append(("alert-warning", f"🟡 **{quality['failed']} quality rule(s) failing** — add validation at the point of data entry."))
    if dupes["exact_duplicates"] > 0:
        recs.append(("alert-warning", f"🟡 **{dupes['exact_duplicates']} exact duplicate row(s)** — deduplicate to reduce CRM and storage costs."))
    if pack_results and any(not r.get("passed") for r in pack_results):
        failed_pack = sum(1 for r in pack_results if r.get("passed") is False)
        recs.append(("alert-warning", f"🏭 **{failed_pack} business logic check(s) failed** in the {pack_name} pack — review financial or date integrity."))
    if drift and drift.get("alerts"):
        recs.append(("alert-critical", "🚨 **Schema drift detected** — a new sensitive column was added. Review immediately."))
    if scores["overall"] < 70:
        recs.append(("alert-info", "ℹ️ Set up **automated scanning** on every file upload — AWS Lambda + S3 trigger keeps this score current."))
    if not recs:
        recs.append(("alert-info", "✅ Data looks healthy. Automate this scan to stay that way."))

    rec_cols = st.columns(min(len(recs), 3))
    for i, (cls, text) in enumerate(recs):
        with rec_cols[i % len(rec_cols)]:
            st.markdown(f'<div class="{cls}"><p style="margin:0;font-size:13px;">{bold(text)}</p></div>',
                        unsafe_allow_html=True)

    # ── Data preview ──────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    with st.expander("📄  Data preview (first 50 rows)"):
        st.dataframe(df.head(50), use_container_width=True)

    # ── Remediation Engine ────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">Remediation Engine 🧹</div>', unsafe_allow_html=True)

    high_med_pii_count = scores["pii_high_count"] + scores["pii_medium_count"]
    exact_dupes_count  = dupes["exact_duplicates"]

    if high_med_pii_count > 0 or exact_dupes_count > 0 or quality["failed"] > 0:
        st.markdown(f"""
<div class="alert-warning">
    <span style="font-family:'DM Mono',monospace;font-size:12px;">🧹 SANITIZATION READY</span>
    <p style="color:#c8a060;margin:4px 0 0;font-size:13px;">
        Found <strong>{high_med_pii_count}</strong> high/medium PII exposure(s) and
        <strong>{exact_dupes_count}</strong> exact duplicate row(s).
        Choose your actions below and execute in one click.
    </p>
</div>""", unsafe_allow_html=True)

        # Action toggles
        col_toggle1, col_toggle2 = st.columns(2)
        with col_toggle1:
            apply_masking = st.checkbox(
                "Mask HIGH/MEDIUM PII instances", value=True,
                help="Replaces SSNs, DOBs, credit cards with safe tokens. LOW-confidence findings are left unchanged."
            )
        with col_toggle2:
            drop_dupes = st.checkbox(
                "Drop exact duplicate rows", value=True,
                help="Removes redundant row copies to clear your duplicate rate."
            )

        # Preview of what changes
        with st.expander("ℹ️  View intended transformations"):
            st.markdown(f"""
- **PII Masking:** `{high_med_pii_count}` value(s) across targeted columns will be redacted.
  *LOW-confidence findings (e.g. serial numbers) are left unchanged.*
- **Deduplication:** Row count will shift from `{dupes['total_rows']}` → `{dupes['total_rows'] - exact_dupes_count}` rows.
- **Quality issues:** Bad emails, zip codes, and out-of-bounds age/revenue values are
  flagged in the scan — fix at source or filter in the remediated CSV.
""")
            # Show PII change table
            change_rows = [
                {"Risk": f["risk"], "Column": f["column"],
                 "Row": f["row"], "Will become": f["masked"]}
                for f in pii_findings if f["risk"] in ("HIGH", "MEDIUM")
            ]
            if change_rows:
                st.dataframe(pd.DataFrame(change_rows), hide_index=True,
                             use_container_width=True)

        # Execute button
        if st.button("✨  Execute Data Remediation"):
            with st.spinner("Executing transformations..."):
                remediated_df = df.copy()

                # 1. Drop exact duplicates
                if drop_dupes and exact_dupes_count > 0:
                    remediated_df = remediated_df.drop_duplicates().reset_index(drop=True)

                # 2. Mask PII in-place using findings trace
                if apply_masking and pii_findings:
                    remediated_df = remediated_df.astype(str)
                    for hit in pii_findings:
                        if hit["risk"] in ("HIGH", "MEDIUM"):
                            row_idx  = hit["row"]
                            col_name = hit["column"]
                            raw_val  = hit.get("raw_value", "")
                            masked   = hit.get("masked", "REDACTED")
                            try:
                                col_loc = remediated_df.columns.get_loc(col_name)
                                # Find the row in the (possibly deduplicated) df
                                if row_idx < len(remediated_df) and raw_val:
                                    current = str(remediated_df.iloc[row_idx, col_loc])
                                    remediated_df.iloc[row_idx, col_loc] = current.replace(
                                        raw_val, masked
                                    )
                            except Exception:
                                pass

                st.session_state.cleansed_df = remediated_df
                st.success(
                    f"✅ Remediation complete — "
                    f"{'PII masked · ' if apply_masking else ''}"
                    f"{'Duplicates dropped · ' if drop_dupes else ''}"
                    f"{len(remediated_df):,} rows remaining. "
                    f"Download your clean file in the Export section below."
                )
                st.rerun()
    else:
        st.markdown("""
<div style="padding:20px;background:#0f1a12;border:1px solid #1a4a2a;
            border-radius:8px;text-align:center;">
    <div style="color:#3db86a;font-size:18px;font-family:'DM Mono',monospace;">✓ Clean Pass</div>
    <p style="color:#9a9890;font-size:12px;margin:4px 0 0;">
        No structural remediation actions required for this file profile.
    </p>
</div>""", unsafe_allow_html=True)

    # ── Export Engine ─────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown('<div class="section-header">Export Engine</div>', unsafe_allow_html=True)

    json_report = json.dumps({
        "file": filename, "scanned_at": datetime.now().isoformat(),
        "sensitivity": sensitivity,
        "shape": {"rows": len(df), "columns": len(df.columns)},
        "scores": scores,
        "pii_by_risk": pii_by_risk,
        "quality": {"total": quality["total_checks"], "passed": quality["passed"], "failed": quality["failed"]},
        "duplicates": dupes,
        "schema_drift": drift,
        "pack": pack_name, "pack_results": pack_results,
    }, indent=2, default=str)

    summary_df = pd.DataFrame([
        {"Metric":"Overall score",       "Value":scores["overall"]},
        {"Metric":"Privacy score",       "Value":scores["privacy"]},
        {"Metric":"Quality score",       "Value":scores["quality"]},
        {"Metric":"Completeness score",  "Value":scores["completeness"]},
        {"Metric":"HIGH PII instances",  "Value":scores["pii_high_count"]},
        {"Metric":"MEDIUM PII instances","Value":scores["pii_medium_count"]},
        {"Metric":"LOW PII instances",   "Value":scores["pii_low_count"]},
        {"Metric":"Quality failures",    "Value":quality["failed"]},
        {"Metric":"Exact duplicates",    "Value":dupes["exact_duplicates"]},
    ])

    if st.session_state.cleansed_df is not None:
        # Premium 3-column layout — remediated dataset is unlocked
        rows_clean = len(st.session_state.cleansed_df)
        st.markdown(f"""
<div style="padding:8px 14px;background:#0f1a12;border:1px solid #1a4a2a;border-radius:8px;
            font-family:'DM Mono',monospace;font-size:11px;color:#3db86a;margin-bottom:12px;">
    ✓ Remediated dataset ready &nbsp;·&nbsp; {rows_clean:,} rows
</div>""", unsafe_allow_html=True)

        dl_col1, dl_col2, dl_col3 = st.columns(3)
        with dl_col1:
            st.download_button(
                label="✨  Download Cleansed Dataset",
                data=st.session_state.cleansed_df.to_csv(index=False),
                file_name=f"cleansed_{filename}",
                mime="text/csv",
            )
        with dl_col2:
            st.download_button(
                "⬇  Structural JSON Report",
                data=json_report,
                file_name=f"health_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
            )
        with dl_col3:
            st.download_button(
                "⬇  Executive Summary CSV",
                data=summary_df.to_csv(index=False),
                file_name=f"summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",
            )

        # Reset option
        if st.button("🔄  Clear remediation & reset"):
            st.session_state.cleansed_df = None
            st.rerun()

    else:
        # Standard 2-column layout before remediation is run
        dl1, dl2, _ = st.columns([1, 1, 2])
        with dl1:
            st.download_button(
                "⬇  Structural JSON Report",
                data=json_report,
                file_name=f"health_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
            )
        with dl2:
            st.download_button(
                "⬇  Executive Summary CSV",
                data=summary_df.to_csv(index=False),
                file_name=f"summary_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",
            )
        st.markdown("""
<div style="font-family:'DM Mono',monospace;font-size:11px;color:#4a4a52;margin-top:8px;">
    💡 Execute the Remediation Engine above to unlock the cleansed dataset download.
</div>""", unsafe_allow_html=True)