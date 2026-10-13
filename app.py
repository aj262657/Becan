"""
app.py - Enterprise Digital Risk Protection (DRP) Platform
SOC Threat Intelligence Console for Brand Defense, Impersonation Monitoring & Forensic Attribution
Target Enterprise: Revolut Ltd | Global Security Operations Center (GSOC)
Design System: Enterprise Crisp Light Theme (Inter, Slate, Electric Cobalt, Vivid Coral & Emerald)
"""

import os
import json
import copy
from pathlib import Path
from typing import Dict, Any, List

import streamlit as st
from PIL import Image

# Anchor all relative paths to the folder containing app.py
APP_DIR = Path(__file__).resolve().parent


def resolve_asset_path(path_str):
    if not path_str:
        return None
    if str(path_str).startswith("http://") or str(path_str).startswith("https://"):
        return path_str

    # Check relative to app.py directory
    candidate_path = APP_DIR / path_str
    if candidate_path.exists():
        return str(candidate_path)

    # Check directly by path_str
    if os.path.exists(path_str):
        return path_str

    # Check inside APP_DIR / 'assets' / basename
    fallback_assets = APP_DIR / "assets" / Path(path_str).name
    if fallback_assets.exists():
        return str(fallback_assets)

    return None


# Import modular detection engine
import detection_engine as de

# Setup page configuration
_app_icon = resolve_asset_path("logo.png") or "logo.png"
st.set_page_config(
    page_title="Becan",
    page_icon=_app_icon,
    layout="wide",
    initial_sidebar_state="expanded"
)
# Custom Top Enterprise Header
col_logo, col_title, col_status = st.columns([1, 6, 2])

with col_logo:
    _header_logo = resolve_asset_path("logo.png")
    if _header_logo:
        st.image(_header_logo, width=55)

with col_title:
    st.markdown("""
        <div style="line-height: 1.2;">
            <span style="font-size: 1.6rem; font-weight: 700; color: #0F172A; letter-spacing: -0.5px;">
                BECAN
            </span><br>
            <span style="font-size: 0.85rem; color: #64748B; font-weight: 500;">
                Autonomous External Brand Defense & Impersonation Triage
            </span>
        </div>
    """, unsafe_allow_html=True)

with col_status:
    st.markdown("""
        <div style="text-align: right; padding-top: 5px;">
            <span style="background: #DCFCE7; color: #166534; font-size: 0.75rem; font-weight: 600; padding: 4px 10px; border-radius: 9999px; border: 1px solid #BBF7D0;">
                ● LIVE SOC SURVEILLANCE
            </span>
        </div>
    """, unsafe_allow_html=True)
st.divider()

# Custom High-End Enterprise Crisp Light CSS Theme
ENTERPRISE_LIGHT_CSS = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    /* Global canvas */
    .stApp {
        background-color: #F8FAFC;
        color: #0F172A;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }

    /* Monospace elements */
    code, pre, .mono-font, .stCodeBlock {
        font-family: 'JetBrains Mono', 'Courier New', monospace !important;
    }

    /* Sidebar background */
    [data-testid="stSidebar"] {
        background-color: #FFFFFF;
        border-right: 1px solid #E2E8F0;
    }

    /* Top Enterprise Navigation Header */
    .soc-nav-masthead {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 18px 24px;
        margin-bottom: 22px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        display: flex;
        justify-content: space-between;
        align-items: center;
        flex-wrap: wrap;
        gap: 14px;
    }

    .soc-brand-group {
        display: flex;
        align-items: center;
        gap: 14px;
    }

    .soc-brand-icon {
        width: 42px;
        height: 42px;
        background: #EEF2FF;
        border: 1px solid #C7D2FE;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #2563EB;
    }

    .soc-brand-title {
        font-size: 1.25rem;
        font-weight: 800;
        color: #0F172A;
        letter-spacing: -0.02em;
        margin: 0;
        line-height: 1.2;
    }

    .soc-brand-subtitle {
        font-size: 0.82rem;
        color: #64748B;
        font-weight: 500;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    .soc-meta-pills {
        display: flex;
        align-items: center;
        gap: 10px;
        flex-wrap: wrap;
    }

    .pill-version {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 600;
        background: #F1F5F9;
        border: 1px solid #E2E8F0;
        color: #475569;
        padding: 4px 10px;
        border-radius: 9999px;
    }

    .pill-status-live {
        display: flex;
        align-items: center;
        gap: 6px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.72rem;
        font-weight: 700;
        background: #ECFDF5;
        border: 1px solid #A7F3D0;
        color: #059669;
        padding: 4px 12px;
        border-radius: 9999px;
    }

    .live-pulse-dot {
        width: 8px;
        height: 8px;
        background-color: #10B981;
        border-radius: 50%;
        display: inline-block;
        box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
        animation: pulse-green 1.8s infinite;
    }

    @keyframes pulse-green {
        0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
        70% { transform: scale(1); box-shadow: 0 0 0 6px rgba(16, 185, 129, 0); }
        100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
    }

    /* KPI Metric Cards */
    .kpi-container {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
        gap: 16px;
        margin-bottom: 24px;
    }

    .kpi-card {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 8px;
        padding: 18px 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
        transition: transform 0.15s ease, box-shadow 0.15s ease;
    }
    .kpi-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.08);
    }

    .kpi-top-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 8px;
    }

    .kpi-label {
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        color: #64748B;
    }

    .kpi-icon-badge {
        width: 32px;
        height: 32px;
        border-radius: 6px;
        display: flex;
        align-items: center;
        justify-content: center;
    }

    .kpi-value {
        font-size: 2.1rem;
        font-weight: 800;
        color: #0F172A;
        line-height: 1.1;
        letter-spacing: -0.03em;
    }

    .kpi-subtext {
        font-size: 0.78rem;
        color: #94A3B8;
        font-weight: 500;
        margin-top: 4px;
    }

    /* Severity Badges */
    .badge-critical {
        background-color: #FEE2E2;
        color: #EF4444;
        border: 1px solid #FCA5A5;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #EA580C;
        border: 1px solid #FDBA74;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #D97706;
        border: 1px solid #FDE68A;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-low {
        background-color: #DBEAFE;
        color: #2563EB;
        border: 1px solid #BFDBFE;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .badge-clean {
        background-color: #D1FAE5;
        color: #059669;
        border: 1px solid #A7F3D0;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 10px;
        border-radius: 9999px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Lifecycle State Badges */
    .status-new-discovery {
        background-color: #E0F2FE;
        color: #0284C7;
        border: 1px solid #BAE6FD;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .status-under-triage {
        background-color: #FEF3C7;
        color: #B45309;
        border: 1px solid #FDE68A;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .status-takedown-dispatched {
        background-color: #FEE2E2;
        color: #DC2626;
        border: 1px solid #FCA5A5;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .status-resolved {
        background-color: #DCFCE7;
        color: #15803D;
        border: 1px solid #86EFAC;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }
    .status-dismissed {
        background-color: #F1F5F9;
        color: #64748B;
        border: 1px solid #CBD5E1;
        font-family: 'JetBrains Mono', monospace;
        padding: 3px 9px;
        border-radius: 4px;
        font-size: 0.72rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Phishing Token & Homoglyph Badges */
    .badge-token {
        background-color: #FEE2E2;
        color: #EF4444;
        border: 1px solid #FCA5A5;
        font-family: 'JetBrains Mono', monospace;
        padding: 1px 7px;
        border-radius: 4px;
        font-size: 0.70rem;
        font-weight: 600;
        display: inline-block;
        margin-right: 4px;
        margin-bottom: 3px;
    }
    .badge-homoglyph {
        background-color: #F3E8FF;
        color: #9333EA;
        border: 1px solid #D8B4FE;
        font-family: 'JetBrains Mono', monospace;
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 0.70rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Risk Score Progress Bar Container */
    .risk-meter-wrapper {
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .risk-meter-track {
        flex-grow: 1;
        max-width: 80px;
        height: 6px;
        background-color: #E2E8F0;
        border-radius: 9999px;
        overflow: hidden;
    }
    .risk-meter-fill {
        height: 100%;
        border-radius: 9999px;
    }

    /* Comparison Panels */
    .panel-official {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-top: 3px solid #2563EB;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        height: 100%;
    }
    .panel-threat {
        background: #FFFFFF;
        border: 1px solid #FCA5A5;
        border-top: 3px solid #EF4444;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        height: 100%;
    }
    .panel-benign {
        background: #FFFFFF;
        border: 1px solid #A7F3D0;
        border-top: 3px solid #10B981;
        border-radius: 8px;
        padding: 20px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.05);
        height: 100%;
    }

    .panel-header-title {
        font-size: 0.88rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 14px;
        display: flex;
        align-items: center;
        gap: 8px;
    }

    /* Bitstring forensic display */
    .bit-display {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 12px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        color: #475569;
        word-break: break-all;
        line-height: 1.5;
    }
    .bit-match { color: #059669; font-weight: 600; }
    .bit-diff { color: #DC2626; font-weight: 800; background: #FEE2E2; padding: 0 1px; border-radius: 2px; }

    /* Custom Table Row Card */
    .threat-card-row {
        background: #FFFFFF;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 12px 16px;
        margin-bottom: 8px;
        box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    .threat-card-row:hover {
        border-color: #CBD5E1;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.06);
    }

    /* Math Formula Box */
    .math-callout-light {
        background: #F1F5F9;
        border: 1px solid #CBD5E1;
        border-left: 4px solid #2563EB;
        border-radius: 6px;
        padding: 14px 18px;
        margin-bottom: 16px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        color: #1E293B;
    }

    /* Audit log terminal */
    .audit-terminal-light {
        background: #F8FAFC;
        border: 1px solid #E2E8F0;
        border-radius: 6px;
        padding: 10px 14px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.76rem;
        color: #475569;
        max-height: 220px;
        overflow-y: auto;
    }

    /* Explicit Streamlit Metric Text Color Fix */
    [data-testid="stMetric"] {
        background: #FFFFFF !important;
        border: 1px solid #E2E8F0 !important;
        border-radius: 8px !important;
        padding: 12px 16px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04) !important;
    }

    [data-testid="stMetricLabel"] p {
        color: #0F172A !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
    }

    [data-testid="stMetricLabel"],
    [data-testid="stMetricLabel"] div,
    [data-testid="stMetricLabel"] span,
    [data-testid="stMetricLabel"] label {
        color: #0F172A !important;
        font-weight: 600 !important;
        font-size: 0.95rem !important;
    }

    [data-testid="stMetricValue"] div {
        color: #0F172A !important;
        font-weight: 700 !important;
    }

    [data-testid="stMetricValue"],
    [data-testid="stMetricValue"] span,
    [data-testid="stMetricValue"] p {
        color: #0F172A !important;
        font-weight: 700 !important;
    }
</style>
"""
st.markdown(ENTERPRISE_LIGHT_CSS, unsafe_allow_html=True)


# ==========================================
# Data Initialization and State Management
# ==========================================

DATA_FILE = APP_DIR / "mock_data.json"
ASSETS_DIR = APP_DIR / "assets"

def ensure_assets_exist():
    """Ensure authentic Revolut enterprise mock logo assets exist."""
    if not (ASSETS_DIR / "revolut_official_logo.png").exists():
        try:
            import generate_assets
            generate_assets.generate_all_assets()
        except Exception:
            ASSETS_DIR.mkdir(parents=True, exist_ok=True)
            fallback = Image.new("RGB", (200, 200), (8, 8, 10))
            fallback.save(ASSETS_DIR / "revolut_official_logo.png")

ensure_assets_exist()


def load_initial_data() -> Dict[str, Any]:
    """Load mock data from json file."""
    if DATA_FILE.exists():
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "brand_configuration": {
            "brand_name": "Revolut Ltd",
            "brand_aliases": ["Revolut", "Revolut Bank", "Revolut Technologies", "Revolut Business", "Ultra by Revolut"],
            "official_handles": ["@RevolutApp", "@RevolutSupport", "@RevolutInsider"],
            "official_packages": ["com.revolut.revolut", "com.revolut.business"],
            "domain": "revolut.com",
            "logo_path": "assets/revolut_official_logo.png"
        },
        "discovered_entities": []
    }


raw_dataset = load_initial_data()
all_presets = raw_dataset.get("presets", {})

if "selected_brand_preset" not in st.session_state:
    st.session_state["selected_brand_preset"] = "Revolut"

if "brand_config" not in st.session_state:
    curr_preset_key = st.session_state["selected_brand_preset"]
    if curr_preset_key in all_presets:
        st.session_state["brand_config"] = copy.deepcopy(all_presets[curr_preset_key]["brand_configuration"])
        st.session_state["discovered_entities"] = copy.deepcopy(all_presets[curr_preset_key]["discovered_entities"])
    else:
        st.session_state["brand_config"] = copy.deepcopy(raw_dataset.get("brand_configuration", {}))
        st.session_state["discovered_entities"] = copy.deepcopy(raw_dataset.get("discovered_entities", []))
    st.session_state["triage_log"] = []
    first_sel = st.session_state["discovered_entities"][1]["id"] if len(st.session_state["discovered_entities"]) > 1 else (st.session_state["discovered_entities"][0]["id"] if st.session_state["discovered_entities"] else None)
    st.session_state["selected_entity_id"] = first_sel


def run_threat_evaluations():
    brand = st.session_state["brand_config"]
    entities = st.session_state["discovered_entities"]
    results = []

    for ent in entities:
        res = de.compute_composite_risk(
            entity=ent,
            official_brand=brand,
            discovered_logo_path=resolve_asset_path(ent.get("logo_path")),
            official_logo_path=resolve_asset_path(brand.get("logo_path"))
        )
        ent_copy = dict(ent)
        ent_copy["risk_analysis"] = res
        ent_copy["composite_score"] = res["composite_score"]
        ent_copy["severity"] = res["severity"]
        results.append(ent_copy)

    return results


evaluated_entities = run_threat_evaluations()


# Helper for state badge class
def get_status_badge_html(status: str) -> str:
    s_upper = (status or "").upper()
    if "NEW" in s_upper or "DISCOVERY" in s_upper:
        cls = "status-new-discovery"
        label = "NEW DISCOVERY"
    elif "TRIAGE" in s_upper:
        cls = "status-under-triage"
        label = "UNDER TRIAGE"
    elif "TAKEDOWN" in s_upper or "DISPATCH" in s_upper:
        cls = "status-takedown-dispatched"
        label = "TAKEDOWN DISPATCHED"
    elif "RESOLVED" in s_upper:
        cls = "status-resolved"
        label = "RESOLVED"
    elif "ALLOWLIST" in s_upper:
        cls = "status-resolved"
        label = "ALLOWLISTED"
    elif "DISMISS" in s_upper:
        cls = "status-dismissed"
        label = "DISMISSED"
    else:
        cls = "status-under-triage"
        label = s_upper
    return f"<span class='{cls}'>{label}</span>"


# Helper for risk severity meter
def get_risk_meter_html(score: float, severity: str) -> str:
    if severity == "Critical":
        color = "#EF4444"
    elif severity == "High":
        color = "#EA580C"
    elif severity == "Medium":
        color = "#F59E0B"
    elif severity == "Low":
        color = "#2563EB"
    else:
        color = "#10B981"

    width_pct = max(4, min(100, int(score)))
    return (
        f"<div class='risk-meter-wrapper'>"
        f"<div class='risk-meter-track'>"
        f"<div class='risk-meter-fill' style='width: {width_pct}%; background-color: {color};'></div>"
        f"</div>"
        f"<span style='font-family: JetBrains Mono; font-weight: 700; font-size: 0.86rem; color: {color};'>{score:.1f}</span>"
        f"</div>"
    )


# ==========================================
# Sidebar: Target Brand Configuration
# ==========================================

with st.sidebar:
    st.markdown("#### ENTERPRISE BRAND SCOPE")
    st.caption("Active Trademark Assets & Authorized Identity Baseline")

    preset_list = ["Revolut", "Binance", "Nike", "Custom Brand"]
    curr_preset = st.session_state.get("selected_brand_preset", "Revolut")
    if curr_preset not in preset_list:
        curr_preset = "Custom Brand"

    def on_brand_scope_change():
        new_sel = st.session_state["sidebar_preset_selector"]
        st.session_state["selected_brand_preset"] = new_sel
        if new_sel in all_presets:
            st.session_state["brand_config"] = copy.deepcopy(all_presets[new_sel]["brand_configuration"])
            st.session_state["discovered_entities"] = copy.deepcopy(all_presets[new_sel]["discovered_entities"])
            # Auto-select first high-severity threat candidate if present
            threat_ids = [e["id"] for e in st.session_state["discovered_entities"] if not e.get("is_allowlisted")]
            st.session_state["selected_entity_id"] = threat_ids[0] if threat_ids else (st.session_state["discovered_entities"][0]["id"] if st.session_state["discovered_entities"] else None)
            st.session_state["triage_log"].append(f"[SYSTEM] Switched brand scope to preset '{new_sel}' ({len(st.session_state['discovered_entities'])} candidates loaded).")
        elif new_sel == "Custom Brand":
            st.session_state["triage_log"].append("[SYSTEM] Activated Custom Brand mode. Enter brand details and add live candidates below.")

    selected_preset = st.selectbox(
        "Monitored Brand Scope Preset",
        preset_list,
        index=preset_list.index(curr_preset),
        key="sidebar_preset_selector",
        on_change=on_brand_scope_change,
        help="Select a monitored brand preset to load tailored trademark baseline and discovered threat candidates."
    )

    current_brand = st.session_state["brand_config"]
    is_custom = (selected_preset == "Custom Brand")

    brand_name = st.text_input(
        "Registered Trademark Name",
        value=current_brand.get("brand_name", ""),
        key=f"cfg_brand_name_{selected_preset}",
        help="Primary registered corporate trademark."
    )

    aliases_str = st.text_area(
        "Authorized Brand Aliases (CSV)",
        value=", ".join(current_brand.get("brand_aliases", [])),
        key=f"cfg_aliases_{selected_preset}",
        help="Subsidiaries, banking license names, and commercial trade styles."
    )

    handles_str = st.text_area(
        "Official Handles (Allowlist)",
        value=", ".join(current_brand.get("official_handles", [])),
        key=f"cfg_handles_{selected_preset}",
        help="Authorized social handles exempted from adversarial scoring."
    )

    packages_str = st.text_area(
        "Official Application Packages",
        value=", ".join(current_brand.get("official_packages", [])),
        key=f"cfg_packages_{selected_preset}",
        help="Authorized package IDs in Google Play Store & Apple App Store."
    )

    domain = st.text_input(
        "Corporate Domain Namespace",
        value=current_brand.get("domain", ""),
        key=f"cfg_domain_{selected_preset}",
        help="Authoritative corporate apex domain for developer verification."
    )

    st.markdown("**Authorized Trademark Monogram**")
    logo_path = current_brand.get("logo_path", "")
    resolved_brand_logo = resolve_asset_path(logo_path)
    if resolved_brand_logo:
        st.image(resolved_brand_logo, caption=f"Baseline: {brand_name}", width=110)
    else:
        st.info("No baseline trademark visual set.")

    uploaded_logo = st.file_uploader("Upload Baseline Logo", type=["png", "jpg", "jpeg"], key=f"uploader_{selected_preset}")
    if uploaded_logo is not None:
        save_path = ASSETS_DIR / f"custom_{uploaded_logo.name}"
        with open(save_path, "wb") as f:
            f.write(uploaded_logo.getbuffer())
        st.session_state["brand_config"]["logo_path"] = str(save_path)
        st.success("Uploaded custom baseline visual asset.")

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1:
        if st.button("Commit Scope", use_container_width=True, type="primary"):
            st.session_state["brand_config"]["brand_name"] = brand_name
            st.session_state["brand_config"]["brand_aliases"] = [a.strip() for a in aliases_str.split(",") if a.strip()]
            st.session_state["brand_config"]["official_handles"] = [h.strip() for h in handles_str.split(",") if h.strip()]
            st.session_state["brand_config"]["official_packages"] = [p.strip() for p in packages_str.split(",") if p.strip()]
            st.session_state["brand_config"]["domain"] = domain
            st.toast("Brand baseline updated. Threat feed rescanned.", icon="ℹ️")
            st.rerun()

    with col_btn2:
        if st.button("Reload Dataset", use_container_width=True):
            if selected_preset in all_presets:
                st.session_state["brand_config"] = copy.deepcopy(all_presets[selected_preset]["brand_configuration"])
                st.session_state["discovered_entities"] = copy.deepcopy(all_presets[selected_preset]["discovered_entities"])
            else:
                st.session_state["brand_config"] = copy.deepcopy(raw_dataset.get("brand_configuration", {}))
                st.session_state["discovered_entities"] = copy.deepcopy(raw_dataset.get("discovered_entities", []))
            st.session_state["triage_log"] = []
            first_id = st.session_state["discovered_entities"][0]["id"] if st.session_state["discovered_entities"] else None
            st.session_state["selected_entity_id"] = first_id
            st.toast(f"Reloaded '{selected_preset}' baseline dataset.", icon="ℹ️")
            st.rerun()

    # Live candidate injection form for Custom Brand or ad-hoc threat discovery
    st.markdown("---")
    with st.expander("➕ ADD CANDIDATE ENTITY LIVE", expanded=is_custom):
        st.caption("Inject discovered social handle, rogue APK, or spoof URL into active threat telemetry.")
        with st.form("form_add_live_candidate", clear_on_submit=True):
            cand_name = st.text_input("Candidate Asset Name", placeholder="e.g. Binance VIP Claims or Acme Pay APK", key="live_cand_name")
            cand_handle = st.text_input("Discovered Identifier / Handle", placeholder="e.g. @binance_claims or com.acme.pay.apk", key="live_cand_handle")
            cand_platform = st.selectbox("Platform Channel", ["Twitter / X", "Telegram", "Instagram", "Facebook", "Google Play Store / APK Sideload", "Web Domain / Phishing Host"], key="live_cand_platform")
            cand_type = st.selectbox("Asset Classification", ["social_media", "mobile_app", "web_domain"], key="live_cand_type")
            cand_url = st.text_input("Target URL (Optional)", placeholder="https://...", key="live_cand_url")
            cand_email = st.text_input("Developer Webmail (Optional)", placeholder="e.g. support-agent@gmail.com", key="live_cand_email")
            cand_bio = st.text_area("Bio / Lure Description", placeholder="e.g. 24/7 priority disputes desk. Sideload APK to verify...", key="live_cand_bio")

            add_btn = st.form_submit_button("ADD CANDIDATE TO THREAT FEED", use_container_width=True, type="primary")
            if add_btn:
                if not cand_name.strip():
                    st.error("Candidate asset name is required.")
                else:
                    count = len(st.session_state["discovered_entities"]) + 1
                    prefix = "CUST" if is_custom else selected_preset[:3].upper()
                    new_id = f"{prefix}-{count:03d}"
                    preset_logo = current_brand.get("logo_path")
                    new_item = {
                        "id": new_id,
                        "name": cand_name.strip(),
                        "handle": cand_handle.strip() if cand_handle else f"@{cand_name.strip().replace(' ', '_')}",
                        "platform": cand_platform,
                        "type": cand_type,
                        "is_verified": False,
                        "is_official_verified": False,
                        "is_allowlisted": False,
                        "followers": 25,
                        "bio": cand_bio.strip() if cand_bio else "Discovered unverified telemetry record matching brand keywords.",
                        "url": cand_url.strip() if cand_url else None,
                        "logo_path": preset_logo,
                        "developer_email": cand_email.strip() if cand_email else None,
                        "package_name": cand_handle.strip() if cand_type == "mobile_app" else None,
                        "category": "Live Telemetry Injection",
                        "discovery_date": "2026-10-13",
                        "status": "NEW DISCOVERY"
                    }
                    st.session_state["discovered_entities"].append(new_item)
                    st.session_state["selected_entity_id"] = new_id
                    st.session_state["triage_log"].append(f"[{new_id}] Injected live candidate '{cand_name}' into active feed.")
                    st.toast(f"Candidate '{cand_name}' successfully added to threat feed!", icon="ℹ️")
                    st.rerun()

    st.markdown("---")
    st.markdown("#### GSOC AUDIT LOG")
    if st.session_state["triage_log"]:
        st.markdown(f"<div class='audit-terminal-light'>{'<br>'.join(st.session_state['triage_log'][-8:])}</div>", unsafe_allow_html=True)
    else:
        st.caption("No SOC operational events logged in session.")


# ==========================================
# Top Enterprise Navigation Header
# ==========================================

active_brand_name = st.session_state["brand_config"].get("brand_name", "Enterprise Baseline")
active_domain = st.session_state["brand_config"].get("domain", "apex-domain.com")

st.markdown(f"""
<div class="soc-nav-masthead">
    <div class="soc-brand-group">
        <div class="soc-brand-icon">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
        </div>
        <div>
            <div class="soc-brand-title">{active_brand_name} Global Brand Monitor</div>
            <div class="soc-brand-subtitle">
                <span>Enterprise Brand Protection & Anti-Impersonation GSOC</span>
                <span>•</span>
                <span style="font-family: 'JetBrains Mono', monospace; color: #2563EB;">https://{active_domain}</span>
            </div>
        </div>
    </div>
    <div class="soc-meta-pills">
        <span class="pill-version">Engine v2.4.1 Production</span>
        <div class="pill-status-live">
            <span class="live-pulse-dot"></span>
            <span>LIVE DEFENSE: ACTIVE</span>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)


# ==========================================
# KPI Metrics Cards (Pure White with Subtle Elevation)
# ==========================================

total_scanned = len(evaluated_entities)
critical_alerts = sum(1 for e in evaluated_entities if e["severity"] == "Critical")
takedowns_dispatched = sum(1 for e in evaluated_entities if "TAKEDOWN" in e.get("status", "").upper())
resolved_count = sum(1 for e in evaluated_entities if "RESOLVED" in e.get("status", "").upper() or "ALLOWLIST" in e.get("status", "").upper())

st.markdown(f"""
<div class="kpi-container">
    <div class="kpi-card">
        <div class="kpi-top-row">
            <span class="kpi-label">Discovered Assets</span>
            <div class="kpi-icon-badge" style="background: #EFF6FF; color: #2563EB;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                </svg>
            </div>
        </div>
        <div class="kpi-value">{total_scanned}</div>
        <div class="kpi-subtext">Continuous Surface Reconnaissance</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-top-row">
            <span class="kpi-label">Critical Threats</span>
            <div class="kpi-icon-badge" style="background: #FEE2E2; color: #EF4444;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
            </div>
        </div>
        <div class="kpi-value" style="color: #EF4444;">{critical_alerts}</div>
        <div class="kpi-subtext">Active Brand Impersonations</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-top-row">
            <span class="kpi-label">Takedowns Active</span>
            <div class="kpi-icon-badge" style="background: #FEF3C7; color: #D97706;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/>
                </svg>
            </div>
        </div>
        <div class="kpi-value" style="color: #D97706;">{takedowns_dispatched}</div>
        <div class="kpi-subtext">Statutory DMCA Notices Dispatched</div>
    </div>
    <div class="kpi-card">
        <div class="kpi-top-row">
            <span class="kpi-label">Resolved / Clean</span>
            <div class="kpi-icon-badge" style="background: #D1FAE5; color: #059669;">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
            </div>
        </div>
        <div class="kpi-value" style="color: #059669;">{resolved_count}</div>
        <div class="kpi-subtext">Mitigated & Baseline Assets</div>
    </div>
</div>
""", unsafe_allow_html=True)


# ==========================================
# Primary Navigation Tabs
# ==========================================

tab_feed, tab_threat_surface, tab_live_scan, tab_scope = st.tabs([
    "ACTIVE THREAT INTELLIGENCE FEED & FORENSICS",
    "TARGET THREAT SURFACE INSPECTOR (DNS / INFRASTRUCTURE)",
    "LIVE TARGET INSPECTOR (ANALYST SANDBOX)",
    "STATUTORY LEGAL FRAMEWORK & POLICIES"
])


# =========================================================================
# TAB 1: ACTIVE THREAT INTELLIGENCE FEED & DEEP FORENSICS
# =========================================================================

with tab_feed:
    st.markdown("##### Discovered Impersonation Candidates & Triage Lifecycle")

    # Filter Toolbar
    f_col1, f_col2, f_col3 = st.columns([2, 2, 3])
    with f_col1:
        sev_filter = st.selectbox("Severity Classification", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"], index=0)
    with f_col2:
        lifecycle_options = ["ALL", "NEW DISCOVERY", "UNDER TRIAGE", "TAKEDOWN DISPATCHED", "RESOLVED"]
        lifecycle_filter = st.selectbox("Triage Lifecycle State", lifecycle_options, index=0)
    with f_col3:
        search_slug = st.session_state["brand_config"].get("domain", "revolut.com").split(".")[0]
        search_kw = st.text_input("Filter Candidates by Identifier / Keyword", placeholder=f"e.g. support, dispute, apk, @{search_slug}, claim")

    # Filter evaluation
    filtered = []
    for ent in evaluated_entities:
        if sev_filter != "ALL" and ent["severity"].upper() != sev_filter:
            continue
        if lifecycle_filter != "ALL":
            s_u = ent.get("status", "").upper()
            if lifecycle_filter == "NEW DISCOVERY" and "NEW" not in s_u and "DISCOVERY" not in s_u:
                continue
            if lifecycle_filter == "UNDER TRIAGE" and "TRIAGE" not in s_u:
                continue
            if lifecycle_filter == "TAKEDOWN DISPATCHED" and ("TAKEDOWN" not in s_u and "DISPATCH" not in s_u):
                continue
            if lifecycle_filter == "RESOLVED" and ("RESOLVED" not in s_u and "ALLOWLIST" not in s_u):
                continue
        if search_kw:
            if not de.entity_matches_search(ent, st.session_state["brand_config"], search_kw):
                continue
        filtered.append(ent)

    # Render Table in Custom Crisp Cards
    if not filtered:
        st.info("No discovered entities match the specified telemetry filter.")
    else:
        # Table Header
        h_cols = st.columns([1.1, 3.2, 1.8, 1.8, 1.3, 2.0, 1.0])
        h_cols[0].markdown("<span style='font-family: JetBrains Mono; font-size: 0.76rem; font-weight: 700; color: #64748B;'>ASSET ID</span>", unsafe_allow_html=True)
        h_cols[1].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>DISCOVERED ENTITY</span>", unsafe_allow_html=True)
        h_cols[2].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>PLATFORM</span>", unsafe_allow_html=True)
        h_cols[3].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>RISK METER</span>", unsafe_allow_html=True)
        h_cols[4].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>SEVERITY</span>", unsafe_allow_html=True)
        h_cols[5].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>LIFECYCLE STATE</span>", unsafe_allow_html=True)
        h_cols[6].markdown("<span style='font-size: 0.78rem; font-weight: 700; color: #475569;'>ACTION</span>", unsafe_allow_html=True)
        st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 4px 0 12px 0;'>", unsafe_allow_html=True)

        for ent in filtered:
            r_cols = st.columns([1.1, 3.2, 1.8, 1.8, 1.3, 2.0, 1.0])
            
            # Asset ID
            r_cols[0].markdown(f"<span style='font-family: JetBrains Mono; font-size: 0.82rem; font-weight: 600; color: #475569;'>{ent['id']}</span>", unsafe_allow_html=True)
            
            # Name & Handle
            h_str = ent.get('handle') or 'N/A'
            r_cols[1].markdown(
                f"<div style='line-height: 1.3;'>"
                f"<span style='font-weight: 700; color: #0F172A; font-size: 0.90rem;'>{ent['name']}</span><br>"
                f"<span style='font-family: JetBrains Mono; font-size: 0.76rem; color: #64748B;'>{h_str}</span>"
                f"</div>",
                unsafe_allow_html=True
            )
            
            # Platform & Type
            r_cols[2].markdown(
                f"<div style='line-height: 1.3; font-size: 0.85rem; color: #334155; font-weight: 500;'>"
                f"{ent['platform']}<br>"
                f"<span style='font-family: JetBrains Mono; font-size: 0.70rem; color: #94A3B8;'>[{ent.get('type', 'generic').upper()}]</span>"
                f"</div>",
                unsafe_allow_html=True
            )
            
            # Risk Progress Meter
            r_cols[3].markdown(get_risk_meter_html(ent["composite_score"], ent["severity"]), unsafe_allow_html=True)
            
            # Severity Badge
            sev_str = ent["severity"].upper()
            badge_cls = f"badge-{ent['severity'].lower()}"
            r_cols[4].markdown(f"<span class='{badge_cls}'>{sev_str}</span>", unsafe_allow_html=True)
            
            # Dynamic Lifecycle State Badge
            status_html = get_status_badge_html(ent.get('status', 'NEW DISCOVERY'))
            r_cols[5].markdown(status_html, unsafe_allow_html=True)
            
            # Inspect Button
            if r_cols[6].button("INSPECT", key=f"btn_inspect_{ent['id']}", use_container_width=True):
                st.session_state["selected_entity_id"] = ent["id"]
                st.rerun()

    st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 24px 0;'>", unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # FORENSIC EVIDENCE INSPECTOR
    # -------------------------------------------------------------------------
    
    if not filtered:
        st.markdown("""
        <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-radius: 8px; padding: 36px 24px; text-align: center; margin: 12px 0 24px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.04);">
            <div style="color: #94A3B8; margin-bottom: 12px;">
                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="display: inline-block;"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
            </div>
            <div style="font-size: 0.95rem; font-weight: 700; color: #0F172A; margin-bottom: 6px;">NO MATCHING FORENSIC COMPARISON RECORDS</div>
            <div style="font-size: 0.82rem; color: #64748B; max-width: 520px; margin: 0 auto; line-height: 1.5;">
                No candidate entities or comparison records match your active search query and filter criteria. Adjust or clear the filter keywords and severity/lifecycle selectors above to inspect candidate records.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        # Select active entity strictly from filtered candidates
        curr_id = st.session_state.get("selected_entity_id")
        selected_ent = next((e for e in filtered if e["id"] == curr_id), filtered[0])
        st.session_state["selected_entity_id"] = selected_ent["id"]

        # Resolve authoritative comparison asset (entity-specific baseline or active scope)
        off_brand = selected_ent.get("official_brand") if isinstance(selected_ent.get("official_brand"), dict) else st.session_state["brand_config"]

        risk_analysis = selected_ent["risk_analysis"]
        logo_forensics = risk_analysis.get("logo_forensics", {})
        math_breakdown = risk_analysis.get("math_breakdown", {})
        breakdown = risk_analysis.get("breakdown", {})

        st.markdown(f"#### FORENSIC EVIDENCE INSPECTOR // TARGET: `{selected_ent['name']}` ({selected_ent['id']})")

        # Side-by-Side Asset Panel
        col_insp_l, col_insp_r = st.columns(2)

        with col_insp_l:
            st.markdown("""
            <div class="panel-official">
                <div class="panel-header-title" style="color: #2563EB;">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                    <span>OFFICIAL AUTHORIZED ENTERPRISE ASSET</span>
                </div>
            """, unsafe_allow_html=True)

            c_l_img, c_l_meta = st.columns([1, 2])
            with c_l_img:
                off_logo_path = off_brand.get("logo_path", "assets/revolut_official_logo.png")
                resolved_off_logo = resolve_asset_path(off_logo_path)
                if resolved_off_logo:
                    st.image(resolved_off_logo, caption="Authorized Trademark", use_container_width=True)
                else:
                    st.markdown("<div style='height: 80px; display: flex; align-items: center; justify-content: center; background: #F1F5F9; border-radius: 6px; color: #64748B; font-size: 0.78rem;'>Authorized visual missing</div>", unsafe_allow_html=True)
            with c_l_meta:
                st.markdown(f"**Enterprise:** `{off_brand.get('brand_name', 'N/A')}`")
                st.markdown(f"**Apex Domain:** `https://{off_brand.get('domain', 'N/A')}`")
                st.markdown(f"**Whitelisted Handles:** `{', '.join(off_brand.get('official_handles', [])) or 'None'}`")
                st.markdown(f"**App Packages:** `{', '.join(off_brand.get('official_packages', [])) or 'None'}`")
                st.markdown("<span class='badge-clean'>REGULATED INSTITUTIONAL BASELINE</span>", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        with col_insp_r:
            is_threat = selected_ent["severity"] in ["Critical", "High"]
            panel_cls = "panel-threat" if is_threat else "panel-benign"
            title_col = "#EF4444" if is_threat else "#059669"

            st.markdown(f"""
            <div class="{panel_cls}">
                <div class="panel-header-title" style="color: {title_col};">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                    <span>DISCOVERED IMPERSONATION CANDIDATE</span>
                </div>
            """, unsafe_allow_html=True)

            c_r_img, c_r_meta = st.columns([1, 2])
            with c_r_img:
                disc_logo = selected_ent.get("logo_path")
                resolved_disc_logo = resolve_asset_path(disc_logo)
                if resolved_disc_logo:
                    st.image(resolved_disc_logo, caption="Discovered Asset Visual", use_container_width=True)
                else:
                    st.info("No visual asset extracted")

            with c_r_meta:
                st.markdown(f"**Discovered Identifier:** `{selected_ent.get('handle') or selected_ent['name']}`")
                st.markdown(f"**Platform Channel:** `{selected_ent['platform']}`")
                if selected_ent.get("url"):
                    st.markdown(f"**Target URL:** `{selected_ent['url']}`")
                if selected_ent.get("developer_email"):
                    dev_m = selected_ent["developer_email"]
                    if any(free in dev_m for free in ["@gmail.com", "@yahoo.com", "@hotmail.com"]):
                        st.markdown(f"**Developer Email:** `{dev_m}` <span class='badge-critical'>MISMATCHED WEBMAIL</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"**Developer Email:** `{dev_m}`")

                # Scam tokens & homoglyphs
                if breakdown.get("has_homoglyphs"):
                    st.markdown("<span class='badge-homoglyph'>CYRILLIC HOMOGLYPH DETECTED</span>", unsafe_allow_html=True)
                
                scam_toks = breakdown.get("scam_tokens", [])
                if scam_toks:
                    st.markdown(f"**Phishing Tokens:** {''.join([f'<span class=\"badge-token\">{t.upper()}</span>' for t in scam_toks])}", unsafe_allow_html=True)

            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # -------------------------------------------------------------------------
        # FORENSIC MATHEMATICAL COMPOSITE SCORING BREAKDOWN
        # -------------------------------------------------------------------------
        
        st.markdown("##### 1. Composite Risk Mathematical Attribution")

        st.markdown(r"""
        <div class="math-callout-light">
            <strong>FORMAL MULTI-FACTOR RISK FORMULATION:</strong><br>
            <code>Composite_Score = min(100.0, max(0.0, (w_t &times; S_text) + (w_l &times; S_logo) + (w_m &times; S_meta) + &Delta;_boost - &Delta;_damp))</code><br>
            <span style="color: #64748B;">Component Weights: w_text = 0.35 (35%) | w_logo = 0.35 (35%) | w_meta = 0.30 (30%)</span>
        </div>
        """, unsafe_allow_html=True)

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        m_col1.metric("Composite Risk Score", f"{selected_ent['composite_score']:.1f} / 100", delta=selected_ent['severity'])
        m_col2.metric("Text Vector S_text (35%)", f"{risk_analysis.get('text_score', 0):.1f}%", f"+{math_breakdown['components']['weighted_text']:.1f} pts")
        m_col3.metric("Visual pHash S_logo (35%)", f"{risk_analysis.get('logo_score', 0):.1f}%", f"+{math_breakdown['components']['weighted_logo']:.1f} pts")
        m_col4.metric("Metadata Risk S_meta (30%)", f"{risk_analysis.get('metadata_score', 0):.1f}%", f"+{math_breakdown['components']['weighted_meta']:.1f} pts")

        trace_b = math_breakdown.get("boosters", [])
        trace_d = math_breakdown.get("dampeners", [])
        if trace_b or trace_d:
            st.markdown("**Telemetry Dynamic Modifiers:**")
            for b in trace_b:
                st.markdown(f"- <span style='color: #EF4444; font-family: JetBrains Mono; font-weight: 700;'>[BOOST: {b['delta']}]</span> **{b['factor']}**", unsafe_allow_html=True)
            for d in trace_d:
                st.markdown(f"- <span style='color: #10B981; font-family: JetBrains Mono; font-weight: 700;'>[DAMP: {d['delta']}]</span> **{d['factor']}**", unsafe_allow_html=True)

        # -------------------------------------------------------------------------
        # PERCEPTUAL HASH BITSTRING & HAMMING DISTANCE FORENSICS
        # -------------------------------------------------------------------------
        
        st.markdown("##### 2. Perceptual Hash (pHash) Bit-Level Hamming Forensics")
        
        h_col1, h_col2, h_col3 = st.columns([2, 2, 2])
        h_col1.markdown(f"**Official Asset Hash:** `{logo_forensics.get('official_hash_hex')}`")
        h_col2.markdown(f"**Discovered Asset Hash:** `{logo_forensics.get('discovered_hash_hex')}`")
        h_col3.markdown(f"**Hamming Distance (d_H):** `{logo_forensics.get('hamming_distance')} bits` (Threshold &le; {logo_forensics.get('threshold')} bits)")

        off_bin = logo_forensics.get("official_hash_bin", "0" * 64)
        disc_bin = logo_forensics.get("discovered_hash_bin", "0" * 64)
        xor_diff = logo_forensics.get("xor_diff_bin", "1" * 64)

        bit_html = ""
        for idx, (b_off, b_disc, b_xor) in enumerate(zip(off_bin, disc_bin, xor_diff)):
            if idx > 0 and idx % 16 == 0:
                bit_html += "  "
            if b_xor == "0":
                bit_html += f"<span class='bit-match'>{b_disc}</span>"
            else:
                bit_html += f"<span class='bit-diff'>{b_disc}</span>"

        st.markdown(
            f"<div class='bit-display'>"
            f"<span style='color: #64748B;'>OFFICIAL BITSTRING (64-BIT):</span><br>{' '.join([off_bin[i:i+16] for i in range(0, 64, 16)])}<br><br>"
            f"<span style='color: #64748B;'>DISCOVERED BITSTRING (RED HIGHLIGHT = DIFFERING BIT):</span><br>{bit_html}<br><br>"
            f"<span style='color: #64748B;'>FORENSIC VERDICT:</span> <strong style='color: #DC2626;'>{logo_forensics.get('verdict')}</strong> (Match Ratio: {logo_forensics.get('bit_match_ratio', 0) * 100:.1f}%)"
            f"</div>",
            unsafe_allow_html=True
        )

        # -------------------------------------------------------------------------
        # UNICODE HEX CODEPOINT & HOMOGLYPH TABLE
        # -------------------------------------------------------------------------

        if breakdown.get("has_homoglyphs"):
            st.markdown("##### 3. Cyrillic / IDN Homoglyph Character Attribution")
            homo_list = breakdown.get("detected_homoglyphs", [])
            
            homo_rows = []
            for h in homo_list:
                homo_rows.append({
                    "Position": h.get("position"),
                    "Discovered Glyph": h.get("char"),
                    "Unicode Hex": h.get("unicode_hex"),
                    "Decimal Codepoint": h.get("decimal_codepoint"),
                    "Script / Block": h.get("script"),
                    "Latin Replacement": h.get("replacement"),
                    "Latin Unicode Hex": h.get("latin_hex"),
                    "Standard Name": h.get("name")
                })
            st.table(homo_rows)
            if breakdown.get("punycode"):
                st.markdown(f"**RFC 3492 Punycode Deobfuscation:** `{breakdown.get('punycode')}`")

        # -------------------------------------------------------------------------
        # INCIDENT TRIAGE LIFECYCLE CONTROLS
        # -------------------------------------------------------------------------
        
        st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 24px 0;'>", unsafe_allow_html=True)
        st.markdown(f"#### Triage Lifecycle State Machine // Current: {get_status_badge_html(selected_ent.get('status', 'NEW DISCOVERY'))}", unsafe_allow_html=True)
        st.caption("Advance or resolve candidate lifecycle states with dynamic audit log tracking.")

        t_btn1, t_btn2, t_btn3, t_btn4 = st.columns(4)

        with t_btn1:
            if st.button("MOVE TO UNDER TRIAGE", key="btn_move_triage", use_container_width=True):
                for e in st.session_state["discovered_entities"]:
                    if e["id"] == selected_ent["id"]:
                        e["status"] = "UNDER TRIAGE"
                        break
                st.session_state["triage_log"].append(f"[{selected_ent['id']}] Advanced state to 'UNDER TRIAGE' for analyst forensic review.")
                st.toast("State advanced to UNDER TRIAGE.", icon="ℹ️")
                st.rerun()

        with t_btn2:
            if st.button("DISPATCH TAKEDOWN NOTICE", key="btn_act_takedown", use_container_width=True, type="primary"):
                for e in st.session_state["discovered_entities"]:
                    if e["id"] == selected_ent["id"]:
                        e["status"] = "TAKEDOWN DISPATCHED"
                        break
                log_msg = f"[{selected_ent['id']}] Dispatched statutory DMCA takedown notice for {selected_ent.get('handle') or selected_ent['name']} on {selected_ent['platform']}."
                st.session_state["triage_log"].append(log_msg)
                st.session_state["show_notice_for"] = selected_ent["id"]
                st.toast("Status updated to TAKEDOWN DISPATCHED.", icon="ℹ️")
                st.rerun()

        with t_btn3:
            if st.button("MARK RESOLVED (CONFIRMED)", key="btn_mark_resolved", use_container_width=True):
                for e in st.session_state["discovered_entities"]:
                    if e["id"] == selected_ent["id"]:
                        e["status"] = "RESOLVED"
                        break
                st.session_state["triage_log"].append(f"[{selected_ent['id']}] Confirmed takedown execution and de-indexing. Marked RESOLVED.")
                st.toast("Incident marked RESOLVED.", icon="ℹ️")
                st.rerun()

        with t_btn4:
            if st.button("ADD TO ALLOWLIST", key="btn_act_allowlist", use_container_width=True):
                h_val = selected_ent.get("handle")
                pkg_val = selected_ent.get("package_name")
                cfg = st.session_state["brand_config"]

                if h_val and h_val not in cfg["official_handles"]:
                    cfg["official_handles"].append(h_val)
                if pkg_val and pkg_val not in cfg["official_packages"]:
                    cfg["official_packages"].append(pkg_val)

                for e in st.session_state["discovered_entities"]:
                    if e["id"] == selected_ent["id"]:
                        e["is_allowlisted"] = True
                        e["status"] = "RESOLVED (ALLOWLISTED)"
                        break

                log_msg = f"[{selected_ent['id']}] Whitelisted asset {selected_ent.get('handle') or selected_ent['name']}."
                st.session_state["triage_log"].append(log_msg)
                st.toast("Asset added to Allowlist. Marked RESOLVED.", icon="ℹ️")
                st.rerun()

        # -------------------------------------------------------------------------
        # DUAL SOC DELIVERABLES: DMCA TAKEDOWN & STIX 2.1 CTI EXPORT
        # -------------------------------------------------------------------------

        st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 20px 0;'>", unsafe_allow_html=True)
        st.markdown("##### SOC Threat Packet & CTI Deliverables")

        d_col1, d_col2 = st.columns(2)

        with d_col1:
            st.markdown("**1. Statutory DMCA & Trademark Abuse Takedown Packet**")
            takedown_text = de.generate_takedown_notice(
                entity=selected_ent,
                brand_config=off_brand,
                risk_analysis=selected_ent["risk_analysis"]
            )
            st.text_area("Cease & Desist Statutory Notice", value=takedown_text, height=220)
            st.download_button(
                label="DOWNLOAD FORMAL TAKEDOWN PACKET (.TXT)",
                data=takedown_text,
                file_name=f"TAKEDOWN_NOTICE_{selected_ent['id']}_{selected_ent['name'].replace(' ', '_')}.txt",
                mime="text/plain",
                use_container_width=True
            )

        with d_col2:
            st.markdown("**2. Enterprise STIX 2.1 Cyber Threat Intelligence (CTI) Bundle**")
            stix_bundle = de.generate_stix2_bundle(
                entity=selected_ent,
                brand_config=off_brand,
                risk_analysis=selected_ent["risk_analysis"]
            )
            stix_json_str = json.dumps(stix_bundle, indent=2)
            st.text_area("OASIS STIX 2.1 JSON Payload", value=stix_json_str, height=220)
            st.download_button(
                label="DOWNLOAD STIX 2.1 BUNDLE (threat_incident_STIX2.json)",
                data=stix_json_str,
                file_name=f"threat_incident_STIX2.json",
                mime="application/json",
                use_container_width=True
            )


# =========================================================================
# TAB 2: TARGET THREAT SURFACE INSPECTOR (DNS / INFRASTRUCTURE)
# =========================================================================

with tab_threat_surface:
    st.markdown("##### Target Threat Surface Inspector // DNS & Infrastructure Recon")
    st.caption("Live socket-level DNS resolution, reverse PTR lookup, suspicious TLD detection, and MX mail spoofing posture check.")

    dns_input_col, dns_res_col = st.columns([1.5, 2.5])

    with dns_input_col:
        st.markdown("**Infrastructure Target Input**")
        curr_b_slug = st.session_state["brand_config"].get("domain", "revolut.com").split(".")[0]
        curr_apex = st.session_state["brand_config"].get("domain", "revolut.com")
        curr_p_name = st.session_state.get("selected_brand_preset", "default")

        target_domain_input = st.text_input(
            "Target Hostname / Domain or URL",
            value=f"{curr_b_slug}-verify-auth.xyz",
            key=f"infra_target_input_{curr_p_name}",
            help=f"Enter any suspicious domain, host, or URL (e.g. {curr_b_slug}-login-portal.top or https://{curr_b_slug}-kyc-check.net)"
        )

        st.markdown("**Or Test With High-Risk Phishing Domain Vector:**")
        sample_infra_choice = st.selectbox(
            "Quick Forensic Infrastructure Vector",
            [
                f"{curr_b_slug}-verify-auth.xyz (Typosquat + .xyz TLD)",
                f"{curr_b_slug}-login-portal.net (Typosquat + Active MX)",
                f"{curr_b_slug}-internal-auth.corp (Private Bogon IP Leak)",
                f"{curr_apex} (Official Legitimate Domain)"
            ],
            key=f"infra_sample_choice_{curr_p_name}"
        )

        run_recon_btn = st.button("EXECUTE INFRASTRUCTURE RESOLUTION", type="primary", use_container_width=True)

    with dns_res_col:
        st.markdown("**Live DNS & Infrastructure Telemetry Output**")

        chosen_input = target_domain_input
        if sample_infra_choice and not target_domain_input:
            chosen_input = sample_infra_choice.split(" ")[0]

        if run_recon_btn:
            recon_res = de.inspect_threat_surface(
                target_input=chosen_input,
                brand_name=st.session_state["brand_config"].get("brand_name", "Revolut"),
                brand_domain=st.session_state["brand_config"].get("domain", "revolut.com")
            )

            if "error" in recon_res:
                st.error(recon_res["error"])
            else:
                score_inf = recon_res["threat_score"]
                sev_inf = recon_res["severity"]
                c_inf = "#EF4444" if sev_inf == "Critical" else "#EA580C" if sev_inf == "High" else "#D97706" if sev_inf == "Medium" else "#059669"

                st.markdown(f"""
                <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 4px solid {c_inf}; padding: 18px 22px; border-radius: 8px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; font-weight: 700; color: #64748B;">INFRASTRUCTURE THREAT RATING:</span>
                            <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.85rem; font-weight: 800; color: {c_inf};">{score_inf:.1f} / 100</div>
                        </div>
                        <div>
                            <span class="badge-{sev_inf.lower()}" style="font-size: 0.90rem; padding: 6px 14px;">{sev_inf.upper()} INFRASTRUCTURE RISK</span>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                d1, d2, d3 = st.columns(3)
                d1.metric("Resolved IP Address", recon_res["resolved_ip"], recon_res["ip_classification"])
                d2.metric("Reverse DNS (PTR)", recon_res["ptr_record"])
                d3.metric("Mail Posture (MX)", "ACTIVE (SPOOF RISK)" if recon_res["has_mx"] else "INACTIVE", delta="Active MX" if recon_res["has_mx"] else "Web Only")

                st.markdown("##### High-Risk Infrastructure Indicators:")
                if recon_res["flags"]:
                    for f in recon_res["flags"]:
                        st.markdown(f"- 🔴 **{f}**" if "Critical" in f or "Phishing" in f or "Private" in f or "High-Abuse" in f else f"- 🔹 {f}")
                else:
                    st.success("No anomalous DNS or infrastructure risks detected.")

                if recon_res["mx_records"]:
                    st.markdown("**Discovered Mail Exchanger (MX) Records:**")
                    st.code("\n".join(recon_res["mx_records"]), language="text")

                st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 16px 0;'>", unsafe_allow_html=True)
                st_inf_col1, st_inf_col2 = st.columns(2)
                
                with st_inf_col1:
                    infra_mock_ent = {
                        "id": f"INFRA-{recon_res['clean_domain']}",
                        "name": recon_res["clean_domain"],
                        "handle": recon_res["clean_domain"],
                        "url": f"https://{recon_res['clean_domain']}",
                    }
                    infra_mock_risk = {
                        "composite_score": recon_res["threat_score"],
                        "severity": recon_res["severity"],
                        "reasons": recon_res["flags"]
                    }
                    infra_stix = de.generate_stix2_bundle(
                        infra_mock_ent,
                        st.session_state["brand_config"],
                        infra_mock_risk
                    )
                    st.download_button(
                        label="EXPORT INFRASTRUCTURE STIX 2.1 BUNDLE",
                        data=json.dumps(infra_stix, indent=2),
                        file_name=f"STIX2_{recon_res['clean_domain']}.json",
                        mime="application/json",
                        use_container_width=True
                    )

                with st_inf_col2:
                    if st.button("IMPORT DOMAIN INTO ACTIVE THREAT FEED", use_container_width=True):
                        new_id = f"ENT-00{len(st.session_state['discovered_entities']) + 1}"
                        new_ent = {
                            "id": new_id,
                            "name": recon_res["clean_domain"],
                            "handle": recon_res["clean_domain"],
                            "platform": "Domain / Web Infrastructure",
                            "type": "domain",
                            "is_verified": False,
                            "url": f"https://{recon_res['clean_domain']}",
                            "bio": f"Host resolved to IP {recon_res['resolved_ip']}. PTR: {recon_res['ptr_record']}.",
                            "followers": None,
                            "status": "UNDER TRIAGE",
                            "discovery_date": "2026-10-13"
                        }
                        st.session_state["discovered_entities"].append(new_ent)
                        st.session_state["selected_entity_id"] = new_id
                        st.session_state["triage_log"].append(f"[{new_id}] Imported infrastructure domain {recon_res['clean_domain']} into active feed.")
                        st.toast(f"Imported {recon_res['clean_domain']} as {new_id}!", icon="ℹ️")
                        st.rerun()

        else:
            st.info("Enter a target domain or select a test vector, then click 'EXECUTE INFRASTRUCTURE RESOLUTION'.")


# =========================================================================
# TAB 3: LIVE TARGET INSPECTOR (ANALYST SANDBOX)
# =========================================================================

with tab_live_scan:
    st.markdown("##### Live Target Inspector // Arbitrary Asset Forensics")
    st.caption("Execute on-demand threat classification against unindexed social handles, Telegram bots, or rogue APK packages.")

    live_c1, live_c2 = st.columns([1.5, 2.5])

    with live_c1:
        st.markdown("**Target Candidate Input**")
        curr_b_name = st.session_state["brand_config"].get("brand_name", "Enterprise")
        curr_b_slug = st.session_state["brand_config"].get("domain", "revolut.com").split(".")[0]
        curr_p_name = st.session_state.get("selected_brand_preset", "default")
        preset_logo = st.session_state["brand_config"].get("logo_path", "assets/revolut_official_logo.png")

        target_name = st.text_input(
            "Candidate Display Name",
            value=f"{curr_b_name} VIP Priority Support",
            placeholder=f"e.g. {curr_b_name} Instant HelpDesk",
            key=f"live_scan_name_{curr_p_name}"
        )
        target_handle = st.text_input(
            "Discovered Handle / Package ID",
            value=f"@{curr_b_slug}_VIP_Support",
            placeholder=f"e.g. @{curr_b_slug}_Escalations or com.{curr_b_slug}.vip",
            key=f"live_scan_handle_{curr_p_name}"
        )
        target_platform = st.selectbox(
            "Distribution Platform",
            ["Telegram", "Twitter / X", "Google Play Store / APK Sideload", "Instagram", "Discord", "Web Domain"],
            key=f"live_scan_plat_{curr_p_name}"
        )
        target_type = "mobile_app" if "APK" in target_platform or "Google Play" in target_platform else "social_media"
        
        target_email = st.text_input(
            "Registered Developer Email",
            value=f"{curr_b_slug}-vip-escalations@gmail.com",
            placeholder="e.g. support@gmail.com or dev@domain.com",
            key=f"live_scan_email_{curr_p_name}"
        )
        target_bio = st.text_area(
            "Discovered Profile Bio / Phishing Lure",
            value=f"Official {curr_b_name} priority support & dispute escalation desk. DM account credentials or join Telegram for instant account unfreezing.",
            height=110,
            key=f"live_scan_bio_{curr_p_name}"
        )

        uploaded_scan_logo = st.file_uploader("Upload Target Logo / Favicon (Optional)", type=["png", "jpg", "jpeg"], key=f"live_scan_uploader_{curr_p_name}")
        
        st.markdown("**Or Test With Forensic Logo Sample:**")
        sample_img_choice = st.selectbox(
            "Select Pre-generated Asset",
            [
                "Cloned Official Monogram (100% Match)",
                "Modified Red Alert Badge (High Visual Match)",
                "Rogue Mobile / Loan Utility (Medium Match)",
                "Unrelated Commercial Logo (Low Match)"
            ],
            key=f"live_scan_choice_{curr_p_name}"
        )

        execute_btn = st.button("EXECUTE FORENSIC ANALYSIS", type="primary", use_container_width=True)

    with live_c2:
        st.markdown("**Real-Time Forensic Attribution Output**")

        if execute_btn:
            support_logo = f"assets/{curr_b_slug}_support_logo.png" if Path(f"assets/{curr_b_slug}_support_logo.png").exists() else "assets/revolut_support_logo.png"
            rogue_logo = f"assets/{curr_b_slug}_auth_logo.png" if Path(f"assets/{curr_b_slug}_auth_logo.png").exists() else (f"assets/{curr_b_slug}_cash_logo.png" if Path(f"assets/{curr_b_slug}_cash_logo.png").exists() else "assets/revolut_cash_logo.png")
            merch_logo = f"assets/{curr_b_slug}_merch_logo.png" if Path(f"assets/{curr_b_slug}_merch_logo.png").exists() else "assets/revolut_detailing_logo.png"

            sample_map = {
                "Cloned Official Monogram (100% Match)": preset_logo,
                "Modified Red Alert Badge (High Visual Match)": support_logo,
                "Rogue Mobile / Loan Utility (Medium Match)": rogue_logo,
                "Unrelated Commercial Logo (Low Match)": merch_logo
            }
            chosen_logo = sample_map.get(sample_img_choice, preset_logo)

            if uploaded_scan_logo is not None:
                tmp_path = ASSETS_DIR / f"live_{uploaded_scan_logo.name}"
                with open(tmp_path, "wb") as f:
                    f.write(uploaded_scan_logo.getbuffer())
                chosen_logo = str(tmp_path)

            live_entity = {
                "id": "LIVE-SCAN-01",
                "name": target_name,
                "handle": target_handle,
                "platform": target_platform,
                "type": target_type,
                "is_verified": False,
                "developer_email": target_email,
                "package_name": target_handle if target_type == "mobile_app" else None,
                "bio": target_bio,
                "logo_path": chosen_logo,
                "followers": 12,
                "status": "UNDER TRIAGE"
            }

            live_res = de.compute_composite_risk(
                entity=live_entity,
                official_brand=st.session_state["brand_config"],
                discovered_logo_path=chosen_logo,
                official_logo_path=st.session_state["brand_config"].get("logo_path")
            )

            score_val = live_res["composite_score"]
            sev_val = live_res["severity"]
            sev_color = "#EF4444" if sev_val == "Critical" else "#EA580C" if sev_val == "High" else "#D97706" if sev_val == "Medium" else "#059669"

            st.markdown(f"""
            <div style="background: #FFFFFF; border: 1px solid #E2E8F0; border-left: 4px solid {sev_color}; padding: 18px 22px; border-radius: 8px; margin-bottom: 18px; box-shadow: 0 1px 3px rgba(0,0,0,0.05);">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; font-weight: 700; color: #64748B;">CALCULATED FORENSIC RISK:</span>
                        <div style="font-family: 'JetBrains Mono', monospace; font-size: 1.85rem; font-weight: 800; color: {sev_color};">{score_val:.1f} / 100</div>
                    </div>
                    <div>
                        <span class="badge-{sev_val.lower()}" style="font-size: 0.90rem; padding: 6px 14px;">{sev_val.upper()} RISK</span>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            k1, k2, k3 = st.columns(3)
            k1.metric("Text Vector S_text", f"{live_res['text_score']:.1f}%")
            k2.metric("Perceptual pHash Match", f"{live_res['logo_score']:.1f}%")
            k3.metric("Metadata Risk Score", f"{live_res['metadata_score']:.1f}%")

            st.markdown("##### Threat Attribution Evidence Triggers:")
            for r in live_res["reasons"]:
                st.markdown(f"- 🔴 **{r}**" if "detected" in r.lower() or "infringement" in r.lower() or "critical" in r.lower() else f"- 🔹 {r}")

            st.markdown("<hr style='border: 0; border-top: 1px solid #E2E8F0; margin: 16px 0;'>", unsafe_allow_html=True)
            if st.button("IMPORT TARGET INTO ACTIVE INCIDENT FEED", key="btn_import_live"):
                new_id = f"ENT-00{len(st.session_state['discovered_entities']) + 1}"
                live_entity["id"] = new_id
                live_entity["discovery_date"] = "2026-10-13"
                st.session_state["discovered_entities"].append(live_entity)
                st.session_state["selected_entity_id"] = new_id
                st.session_state["triage_log"].append(f"[{new_id}] Analyst manually imported target {target_handle} into active feed.")
                st.toast(f"Imported {target_name} as {new_id} into Active Threat Feed!", icon="ℹ️")
                st.rerun()
        else:
            st.info("Input target metadata on the left and click 'EXECUTE FORENSIC ANALYSIS' to run live detection.")


# =========================================================================
# TAB 4: STATUTORY LEGAL FRAMEWORK & POLICIES
# =========================================================================

with tab_scope:
    st.markdown("##### Statutory Legal Framework & Remediation Policies")
    st.caption("Legal authorities and automated compliance standards governing takedown execution.")

    st.markdown(r"""
    ##### 1. United States Code (U.S.C.)
    - **17 U.S.C. § 512(c)(3) (DMCA Statutory Notice & Action)**:
      Requires online service providers to act expeditiously to remove or disable access to materials claimed to be infringing upon receipt of formal notification.
    - **Lanham Act 15 U.S.C. § 1125(a) (False Designations of Origin)**:
      Prohibits false representations that cause consumer confusion regarding affiliation, connection, or origin of goods or commercial services.
    - **15 U.S.C. § 1125(d) (Anti-Cybersquatting Consumer Protection Act - ACPA)**:
      Provides legal remedies against entities registering, trafficking in, or using domain names confusingly similar to protected registered trademarks with bad-faith intent.

    ##### 2. European Union Regulations
    - **Regulation (EU) 2022/2065 (Digital Services Act - DSA Article 16)**:
      Mandates notice-and-action mechanisms for online platforms to process notices against illegal content without undue delay.
    - **Directive 2000/31/EC (E-Commerce Directive Article 14)**:
      Establishes host provider intermediary liability exemptions conditioned upon prompt removal of infringing material upon obtaining actual knowledge.

    ##### 3. Digital Asset Protection Thresholds
    - **Perceptual Hash Threshold ($\tau \le 10$ bits)**:
      A normalized Hamming distance $\le 10$ bits between 64-bit DCT frequency coefficients establishes high-probability visual replication under judicial copyright evidence standards.
    - **Homoglyph & Punycode Deobfuscation**:
      Internationalized Domain Name (IDN) visually identical glyphs originating from the Cyrillic or Greek Unicode blocks are tracked as intentional deceptive apparatus under fraud and phishing statutes.
    """)
