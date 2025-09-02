# app.py
import streamlit as st
import re
import whois
from datetime import datetime
import tldextract
import requests
import plotly.graph_objects as go
import time
import hashlib
import os


import streamlit as st

import streamlit as st

# Futuristic sci-fi gradient background
st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
        background-size: 400% 400%;
        animation: gradient 15s ease infinite;
        color: #e0e0e0;

    
    }

    @keyframes gradient {
        0% {background-position: 0% 50%;}
        50% {background-position: 100% 50%;}
        100% {background-position: 0% 50%;}
    }

    h1, h2, h3, h4, h5, h6, p, label {
        color: #00ffe7 !important;  /* Futuristic neon cyan */
    }
    </style>
    """,
    unsafe_allow_html=True
)

st.title("🚀 Cybersecurity Analyzer")
st.write("Secure Your Browsing!")
# ----------------------
# Safe API key retrieval
# ----------------------
def get_secret(key: str, default=None):
    """Get a key from st.secrets or environment; never crash if secrets.toml is missing."""
    try:
        if "st" in globals() and hasattr(st, "secrets") and key in st.secrets:
            return st.secrets[key]
    except Exception:
        pass
    return os.getenv(key, default)

VT_API_KEY = get_secret("VIRUSTOTAL_API_KEY", default=None)
GSB_API_KEY = get_secret("GOOGLE_SAFE_BROWSING_API_KEY", default=None)

MAX_HISTORY = 30

# Heuristics lists
MALWARE_EXTENSIONS = [
    ".exe", ".apk", ".msi", ".scr", ".bat", ".js", ".vbs", ".jar", ".com",
    ".pif", ".cmd", ".ps1", ".dll", ".bin", ".run", ".dmg", ".zip", ".rar"
]
SUSPICIOUS_KEYWORDS = ["login", "free", "verify", "update", "win", "secure", "account", "bank", "confirm"]
SUSPICIOUS_PATH_KEYWORDS = ["download", "update", "install", "setup", "payload", "bin", "exe", "apk"]

# ----------------------
# Helpers
# ----------------------
def normalize_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url):
        url = "http://" + url
    return url

def extract_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

def whois_age_days(domain: str):
    try:
        w = whois.whois(domain)
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if not cd:
            return None
        # Some providers return datetime, some string
        if isinstance(cd, str):
            try:
                # Try common ISO-ish formats; if fails just return None
                return None
            except Exception:
                return None
        return (datetime.now() - cd).days
    except Exception:
        return None

def compute_hashes(uploaded_file) -> dict:
    data = uploaded_file.read()
    uploaded_file.seek(0)
    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    return {"sha256": sha256, "md5": md5, "size": len(data)}

# ----------------------
# External checks (optional)
# ----------------------
def query_virustotal_hash(sha256: str):
    """Query VirusTotal for a file hash. Returns parsed JSON or warning dict."""
    if not VT_API_KEY:
        return {"warning": "VirusTotal API key not set — skipping hash scan."}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            return resp.json()
        else:
            return {"status_code": resp.status_code, "detail": resp.text}
    except Exception as e:
        return {"warning": f"VirusTotal error: {e}"}

def check_google_safe_browsing(url: str):
    """Check URL with Google Safe Browsing. Returns result or warning dict."""
    if not GSB_API_KEY:
        return {"warning": "Google Safe Browsing API key not set — skipping URL check."}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    body = {
        "client": {"clientId": "cybersec-app", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        r = requests.post(endpoint, json=body, timeout=15)
        if r.status_code == 200:
            return r.json()  # may contain {"matches": [...]}
        return {"warning": f"GSB HTTP {r.status_code}"}
    except Exception as e:
        return {"warning": f"Google Safe Browsing error: {e}"}

# ----------------------
# URL analysis
# ----------------------
def analyze_url(url: str):
    url = normalize_url(url)
    reasons = []
    score = 0
    meta = {"original_url": url}

    # Basic heuristics
    if len(url) > 75:
        reasons.append("URL is very long")
        score += 8
    if "@" in url:
        reasons.append("Contains '@' which can mask real destination")
        score += 12
    if "//" in url[7:]:
        reasons.append("Extra '//' after scheme — suspicious redirection pattern")
        score += 8
    matched_kw = [k for k in SUSPICIOUS_KEYWORDS if k in url.lower()]
    if matched_kw:
        reasons.append(f"Suspicious keywords present: {', '.join(matched_kw)}")
        score += 6 * min(len(matched_kw), 3)

    # Domain age via WHOIS
    try:
        domain = extract_domain(url)
        age = whois_age_days(domain)
        meta["domain"] = domain
        meta["whois_age_days"] = age
        if age is None:
            reasons.append("WHOIS lookup failed or private")
            score += 6
        else:
            if age < 90:
                reasons.append(f"Domain very new ({age} days)")
                score += 16
            elif age < 365:
                reasons.append(f"Domain somewhat new ({age} days)")
                score += 6
    except Exception:
        reasons.append("WHOIS error during lookup")

    # Suspicious path & extension
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path or ""
    for ext in MALWARE_EXTENSIONS:
        if path.lower().endswith(ext):
            reasons.append(f"Points to file with suspicious extension: {ext}")
            score += 30
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in path.lower():
            reasons.append(f"Suspicious path keyword: {kw}")
            score += 8

    # Google Safe Browsing
    gsb = check_google_safe_browsing(url)
    meta["gsb_raw"] = gsb
    if isinstance(gsb, dict):
        if gsb.get("warning"):
            reasons.append(gsb["warning"])
        elif gsb.get("matches"):
            reasons.append("Google Safe Browsing: URL is flagged")
            score += 40

    # Final label
    label = "Low Risk ✅"
    if score >= 60:
        label = "High Risk 🚨"
    elif score >= 30:
        label = "Medium Risk ⚠"

    meta["score_components"] = score
    return {"label": label, "score": min(100, score)}, reasons, meta

# ----------------------
# File analysis
# ----------------------
def analyze_file(uploaded_file):
    info = compute_hashes(uploaded_file)
    sha256 = info["sha256"]
    md5 = info["md5"]
    size = info["size"]
    reasons = []
    score = 0
    meta = {"sha256": sha256, "md5": md5, "size": size, "filename": uploaded_file.name}

    # Heuristic: suspicious extension
    filename = uploaded_file.name.lower()
    for ext in MALWARE_EXTENSIONS:
        if filename.endswith(ext):
            reasons.append(f"File has suspicious extension: {ext}")
            score += 30

    # Heuristic: size
    if size > 100 * 1024 * 1024:  # >100MB
        reasons.append("Large file size (>100MB) — inspect carefully")
        score += 6
    elif size == 0:
        reasons.append("Empty file — suspicious")
        score += 10

    # VirusTotal lookup by hash (optional)
    vt_result = query_virustotal_hash(sha256)
    meta["virustotal_raw"] = vt_result
    if isinstance(vt_result, dict):
        if vt_result.get("warning"):
            reasons.append(vt_result["warning"])
        elif vt_result.get("data"):
            stats = vt_result["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0)
            if malicious_count > 0:
                reasons.append(f"VirusTotal: {malicious_count} engines flagged the file")
                score += 50
            else:
                reasons.append("VirusTotal: no engines flagged the file")
        else:
            reasons.append("VirusTotal: no record for this hash or API error")

    # Final label
    label = "Low Risk ✅"
    if score >= 60:
        label = "High Risk 🚨"
    elif score >= 30:
        label = "Medium Risk ⚠"

    return {"label": label, "score": min(100, score)}, reasons, meta

# ----------------------
# Streamlit UI
# ----------------------
st.set_page_config(page_title="Phishing & Malware URL Detector", page_icon="🔐", layout="centered")
st.markdown("""
<style>
.header {text-align: center; font-size: 34px; color:#00C2C7; font-weight:700; animation: fadeIn 1.6s ease-in-out}
.card {border-radius: 12px; padding: 16px; background: #f7f9fb; box-shadow: 0 6px 18px rgba(11,79,108,0.08); margin-bottom: 12px}
@keyframes fadeIn {0%{opacity:0; transform: translateY(8px)}100%{opacity:1; transform: translateY(0);}}
</style>
""", unsafe_allow_html=True)

st.markdown("<div class='header'> 🔐 Phishing & Malware URL Detector</div>", unsafe_allow_html=True)
st.caption("Combined URL & File scanner — heuristics + VirusTotal/Google Safe Browsing integration (optional)")

mode = st.selectbox("Choose scan mode", ["URL", "File", "Batch URLs (one per line)"])

if "history" not in st.session_state:
    st.session_state.history = []

# URL mode
if mode == "URL":
    url = st.text_input("Enter website URL:")
    if st.button("🔍 Scan URL"):
        if not url.strip():
            st.warning("Please enter a URL")
        else:
            with st.spinner("Scanning URL..."):
                time.sleep(0.8)
                summary, reasons, meta = analyze_url(url)

            st.metric("Risk Score (numeric)", f"{summary['score']} / 100")
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=summary['score'],
                gauge={'axis': {'range': [0, 100]}, 'steps': [
                    {'range': [0, 40], 'color': "lightgreen"},
                    {'range': [40, 70], 'color': "yellow"},
                    {'range': [70, 100], 'color': "red"}
                ]},
                title={'text': "Risk Score"}
            ))
            st.plotly_chart(fig, use_container_width=True)

            if "High Risk" in summary['label']:
                st.error(f"{summary['label']}")
            elif "Medium Risk" in summary['label']:
                st.warning(f"{summary['label']}")
            else:
                st.success(f"{summary['label']}")
                st.balloons()

            st.markdown("*Reasons:*")
            for r in reasons:
                st.write(f"- {r}")

            st.session_state.history.insert(0, {"type": "url", "value": url, "label": summary['label'], "score": summary['score'], "meta": meta, "time": datetime.now().isoformat()})
            st.session_state.history = st.session_state.history[:MAX_HISTORY]

# Batch URLs mode
elif mode == "Batch URLs (one per line)":
    text = st.text_area("Enter one URL per line", height=200)
    if st.button("🔍 Scan Batch"):
        urls = [u.strip() for u in text.splitlines() if u.strip()]
        if not urls:
            st.warning("No URLs provided")
        else:
            for u in urls:
                with st.spinner(f"Scanning {u}..."):
                    time.sleep(0.4)
                    summary, reasons, meta = analyze_url(u)
                st.write(f"{u}** — {summary['label']} — {summary['score']}/100")
                if reasons:
                    for r in reasons:
                        st.write(f"- {r}")
                st.session_state.history.insert(0, {"type": "url", "value": u, "label": summary['label'], "score": summary['score'], "meta": meta, "time": datetime.now().isoformat()})
            st.session_state.history = st.session_state.history[:MAX_HISTORY]


        

# File mode
else:
    uploaded = st.file_uploader("Upload file(s) to scan", accept_multiple_files=True)
    if uploaded:
        for f in uploaded:
            if st.button(f"Scan: {f.name}"):
                with st.spinner(f"Analyzing {f.name}..."):
                    time.sleep(0.6)
                    summary, reasons, meta = analyze_file(f)

                st.metric("Risk Score (numeric)", f"{summary['score']} / 100")
                fig = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=summary['score'],
                    gauge={'axis': {'range': [0, 100]}, 'steps': [
                        {'range': [0, 40], 'color': "lightgreen"},
                        {'range': [40, 70], 'color': "yellow"},
                        {'range': [70, 100], 'color': "red"}
                    ]},
                    title={'text': "File Risk Score"}
                ))
                st.plotly_chart(fig, use_container_width=True)

                if "High Risk" in summary['label']:
                    st.error(f"{summary['label']}")
                elif "Medium Risk" in summary['label']:
                    st.warning(f"{summary['label']}")
                else:
                    st.success(f"{summary['label']}")

                st.markdown("*Reasons:*")
                for r in reasons:
                    st.write(f"- {r}")

                st.markdown("*Meta:*")
                st.json(meta)

                st.session_state.history.insert(0, {"type": "file", "value": f.name, "label": summary['label'], "score": summary['score'], "meta": meta, "time": datetime.now().isoformat()})
                st.session_state.history = st.session_state.history[:MAX_HISTORY]
# History panel
if st.session_state.history:
    st.markdown("---")
    st.markdown("## 🕘 Recent Scans")
    for entry in st.session_state.history[:20]:
        icon = "🟢" if "Low Risk" in entry['label'] else ("🟡" if "Medium Risk" in entry['label'] else "🔴")
        st.write(f"{icon} {entry['type'].upper()}: {entry['value']} — *{entry['label']}* — {entry['score']}/100 — {entry['time']}")
        with st.expander("Details"):
            st.write("Meta:")
            st.json(entry.get('meta', {}))

st.markdown("---")
st.caption("Developed for the CyberSecurity project — URL + File scanning with heuristics and VirusTotal/Google Safe Browsing integration.")