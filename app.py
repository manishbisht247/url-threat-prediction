# app.py - Dark / Neon UI (Style B)
import streamlit as st
import pickle
import pandas as pd
import importlib.util
import os
from urllib.parse import urlparse

# ---------------------------
# CONFIG / ASSET PATH
# ---------------------------
st.set_page_config(page_title="Phishing Detector — Dark Neon", layout="centered", page_icon="🛡️")
LOGO_PATH = "/mnt/data/9d31d4b4-6be3-49b3-9754-c770133396fc.png"  # local asset path (from your session)

# ---------------------------
# STYLE (Dark / Neon)
# ---------------------------
st.markdown(
    """
    <style>
    :root{
      --bg:#0b0f12;
      --card:#0f171a;
      --muted:#9aa7b2;
      --accent:#00ff99;
      --danger:#ff4d6d;
      --glass: rgba(255,255,255,0.03);
    }
    .stApp { background-color: var(--bg); color: white; }
    .header {
      display:flex; align-items:center; gap:12px;
      padding:10px 0;
    }
    .logo {
      border-radius:8px;
      box-shadow: 0 6px 20px rgba(0,255,153,0.06);
    }
    .card {
      background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.02));
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 12px;
      box-shadow: 0 8px 30px rgba(0,0,0,0.6);
      border: 1px solid rgba(255,255,255,0.03);
    }
    .muted { color: var(--muted); font-size:13px; }
    .neon { color: var(--accent); font-weight:700; }
    .risk-bar {
      height: 18px; border-radius: 10px; overflow: hidden; background: #061017; border: 1px solid rgba(255,255,255,0.03);
    }
    .risk-fill { height:100%; background: linear-gradient(90deg, #00ff99, #00b3ff); }
    .danger-fill { background: linear-gradient(90deg, #ff4d6d, #ff8a6b); }
    .small { font-size:13px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# FORCE-LOAD EXTRACTOR (safe import)
# ---------------------------
EXTRACTOR_FILE = "features_extract.py"
ex_path = os.path.join(os.getcwd(), EXTRACTOR_FILE)
spec = importlib.util.spec_from_file_location("features_extract", ex_path)
fe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fe)
extract_features = fe.extract_features

# ---------------------------
# LOAD MODEL & SCALER
# ---------------------------
MODEL_FILE = "phishing_model.pkl"
SCALER_FILE = "scaler.pkl"
model = pickle.load(open(MODEL_FILE, "rb"))
scaler = pickle.load(open(SCALER_FILE, "rb"))

# ---------------------------
# FEATURE ORDER (must match your training)
# ---------------------------
feature_order = [
    'url_length', 'is_ip', 'keyword_hits', 'domain_length',
    'path_length', 'query_length', 'subdomain_count', 'has_ip',
    'dot_count', 'hyphen_count', 'slash_count', 'question_count',
    'equal_count', 'percent_count', 'at_count', 'digit_ratio',
    'letter_ratio', 'special_char_ratio', 'path_depth', 'url_entropy',
    'domain_entropy', 'suspicious_tld', 'has_php', 'has_html',
    'has_exe', 'is_shortened', 'is_https', 'tld_grp'
]

# ---------------------------
# TLD GROUPING
# ---------------------------
suspicious_tlds = {"tk","ml","ga","cf","gq","xyz","zip","mov","top","live","work"}
common_tlds = {"com","org","net","edu","gov","in","co","io","info","biz"}
def make_tld_grp(tld):
    tld = str(tld).lower().strip()
    if tld in suspicious_tlds: return 1
    if tld in common_tlds: return 0
    return 2

# ---------------------------
# PREDICTION PIPELINE
# ---------------------------
def predict_url(url):
    feats = extract_features(url)

    # patch missing engineered features
    feats["is_ip"] = int(feats.get("has_ip", 0))
    feats["tld_grp"] = make_tld_grp(feats.get("tld", ""))

    # ensure full schema
    for col in feature_order:
        if col not in feats:
            feats[col] = 0

    df = pd.DataFrame([feats])[feature_order]
    X_scaled = scaler.transform(df)
    pred = model.predict(X_scaled)[0]
    
    # Get probability properly
    if hasattr(model, "predict_proba"):
        prob_array = model.predict_proba(X_scaled)[0]
        # prob_array[0] = prob of class 0 (safe), prob_array[1] = prob of class 1 (phishing)
        # Return the probability of class 1 (phishing/malicious)
        prob = prob_array[1] if len(prob_array) > 1 else prob_array[0]
    else:
        prob = float(pred)
    
    return pred, float(prob), feats

# ---------------------------
# UI: Header + Logo
# ---------------------------
col1, col2 = st.columns([1,9])
with col1:
    try:
        st.image(LOGO_PATH, width=64, caption=None, output_format="PNG")
    except Exception:
        st.markdown("<div class='logo' style='width:64px;height:64px;background:#071017;border-radius:8px'></div>", unsafe_allow_html=True)
with col2:
    st.markdown("<div class='header'><div><h2 class='neon'>Phishing URL Detector</h2><div class='muted small'>Dark mode • Neon UI • Real-time ML</div></div></div>", unsafe_allow_html=True)

st.markdown("<div class='card'>", unsafe_allow_html=True)

# ---------------------------
# INPUT
# ---------------------------
url_input = st.text_input("Enter URL to analyze", placeholder="https://example.com/login")
col_a, col_b = st.columns([3,1])
with col_b:
    analyze = st.button("ANALYZE", help="Run detection")

st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------
# SESSION HISTORY
# ---------------------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------------------
# ANALYZE BLOCK
# ---------------------------
if analyze:
    if not url_input or url_input.strip() == "":
        st.warning("Enter a URL first.")
    else:
        try:
            pred, prob, feats = predict_url(url_input)

            # domain breakdown
            parsed = urlparse(url_input if "://" in url_input else ("http://" + url_input))
            domain = parsed.netloc
            path = parsed.path or "/"
            query = parsed.query or ""

            # determine risk level
            risk_percent = int(prob * 100)
            risk_label = "LEGIT" if pred == 0 else "MALICIOUS"
            color_class = "danger-fill" if pred == 1 else "risk-fill"

            # push history
            st.session_state.history.insert(0, {
                "url": url_input,
                "pred": risk_label,
                "prob": prob
            })
            if len(st.session_state.history) > 25:
                st.session_state.history = st.session_state.history[:25]

            # result panel
            st.markdown("<div class='card'>", unsafe_allow_html=True)
            st.markdown(f"<h3 style='color:var(--accent)'>Result: <span style='color: white'>{risk_label}</span></h3>", unsafe_allow_html=True)
            st.markdown(f"<div class='muted small'>Malicious Probability: <span class='neon'>{prob:.4f}</span> ({risk_percent}%)</div>", unsafe_allow_html=True)

            # visual risk bar
            bar_html = f"""
            <div class='risk-bar' title='Risk: {risk_percent}%'>
              <div class='{color_class}' style='width: {risk_percent}%;'></div>
            </div>
            <div class='small muted' style='margin-top:6px;'>Risk score: {risk_percent}%</div>
            """
            st.markdown(bar_html, unsafe_allow_html=True)

            # domain breakdown + quick features
            c1, c2 = st.columns([2,3])
            with c1:
                st.markdown("**Domain breakdown**", unsafe_allow_html=True)
                st.write(domain)
                st.markdown("**Path**")
                st.write(path)
                st.markdown("**Query**")
                st.write(query or "-")
            with c2:
                st.markdown("**Top extracted signals**", unsafe_allow_html=True)
                top_table = {
                    "Feature": ["url_length","subdomain_count","keyword_hits","suspicious_tld","is_shortened","is_https"],
                    "Value": [feats.get("url_length"), feats.get("subdomain_count"), feats.get("keyword_hits"), feats.get("suspicious_tld"), feats.get("is_shortened"), feats.get("is_https")]
                }
                st.table(pd.DataFrame(top_table))

            st.markdown("</div>", unsafe_allow_html=True)

        except Exception as e:
            st.error("Error during analysis: " + str(e))

# ---------------------------
# HISTORY + DETAILS PANEL
# ---------------------------
st.markdown("<div class='card'>", unsafe_allow_html=True)
st.markdown("<h4 class='neon'>Recent checks</h4>", unsafe_allow_html=True)
if st.session_state.history:
    for item in st.session_state.history[:10]:
        lbl = item["pred"]
        p = item["prob"]
        p_percent = int(p * 100)
        color = "#ff4d6d" if lbl == "MALICIOUS" else "#00ff99"
        st.markdown(f"<div style='padding:8px;border-radius:8px;background:var(--glass);display:flex;justify-content:space-between;align-items:center;'>"
                    f"<div style='max-width:75%;'><b style='color:{color}'>{lbl}</b> &nbsp; <span class='muted small'>{item['url']}</span></div>"
                    f"<div style='min-width:80px;text-align:right;'><span class='muted small'>{p_percent}%</span></div></div>",
                    unsafe_allow_html=True)
else:
    st.markdown("<div class='muted small'>No checks yet. Try analyzing a URL.</div>", unsafe_allow_html=True)
st.markdown("</div>", unsafe_allow_html=True)

# ---------------------------
# FOOTER / ABOUT
# ---------------------------
st.markdown("<div style='height:8px'></div>", unsafe_allow_html=True)
st.markdown("<div class='muted small'>Built with ❤️ · Dark Neon UI · Model loaded from <code>phishing_model.pkl</code></div>", unsafe_allow_html=True)
