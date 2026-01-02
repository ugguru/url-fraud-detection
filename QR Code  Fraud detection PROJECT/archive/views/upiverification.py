from Tools.upi import VerifyUPI, CheckInvalidUPIPattern
import streamlit as st
import time

def circular_risk_meter(score):
    radius = 70
    stroke = 12
    normalized = min(max(score, 0), 100)
    circumference = 2 * 3.1416 * radius
    offset = circumference - (normalized / 100) * circumference

    if score <= 30:
        color = "#2ecc71"   # green
        level = "LOW"
    elif score <= 60:
        color = "#f39c12"   # orange
        level = "MEDIUM"
    else:
        color = "#e74c3c"   # red
        level = "HIGH"

    st.markdown(f"""
    <div style="display:flex;justify-content:center;">
    <svg width="180" height="180">
        <circle cx="90" cy="90" r="{radius}"
            stroke="#e6e6e6"
            stroke-width="{stroke}"
            fill="none" />
        <circle cx="90" cy="90" r="{radius}"
            stroke="{color}"
            stroke-width="{stroke}"
            fill="none"
            stroke-dasharray="{circumference}"
            stroke-dashoffset="{offset}"
            stroke-linecap="round"
            transform="rotate(-90 90 90)" />
        <text x="90" y="90"
            text-anchor="middle"
            dy="8"
            font-size="26"
            font-weight="bold"
            fill="{color}">
            {normalized}
        </text>
        <text x="90" y="120"
            text-anchor="middle"
            font-size="14"
            fill="#555">
            {level} RISK
        </text>
    </svg>
    </div>
    """, unsafe_allow_html=True)

if "upi" not in st.session_state:
    st.session_state.upi = None
if "status" not in st.session_state:
    st.session_state.status=None

col1,col2=st.columns([0.5,1])
placeholder=st.empty()

with col1:
    data=st.text_input("Enter UPI ID:")
    if st.button("Verify UPI ID"):
        # First check for invalid patterns
        invalid_check = CheckInvalidUPIPattern(data)
        if not invalid_check["is_valid"]:
            st.session_state.upi = {
                "status": "Invalid",
                "upiid": data,
                "error_type": invalid_check["error_type"],
                "error_message": invalid_check["error_message"],
                "riskscore": 100,
                "risklevel": "High"
            }
        else:
            st.session_state.upi=VerifyUPI(data)
        
with col2:
    if st.session_state.upi:
        upi=st.session_state.upi
        if upi["status"]=='Success':
            st.session_state.status="Success"
            st.text(f'''
                UPI ID: {upi["upiid"]}
                Bank: {upi["bank"]}
                Risk Score: {upi["riskscore"]}
                Risk Level: {upi["risklevel"]}
            ''')
            circular_risk_meter(upi["riskscore"])
            
        elif upi["status"] == "Invalid":
            st.session_state.status="Fail"
            error_type = upi.get("error_type", "")
            error_message = upi.get("error_message", "")
            st.text(f'''
                UPI ID: {upi["upiid"]}
                Error Type: {error_type}
                Error: {error_message}
                Risk Score: {upi["riskscore"]}
                Risk Level: {upi["risklevel"]}
            ''')
            circular_risk_meter(upi["riskscore"])
            if st.session_state.status=="Fail":
                placeholder.error(f"🚨 INVALID UPI PATTERN: {error_message}")
                time.sleep(5)
                placeholder.empty()
                st.session_state.status=None
            
        else:
            st.session_state.status="Fail"
            st.text(f'''
                UPI ID: {upi["upiid"]}
                Bank: {upi["bank"]}
                Risk Score: {upi["riskscore"]}
                Risk Level: {upi["risklevel"]}
            ''')
            circular_risk_meter(upi["riskscore"])
            if st.session_state.status=="Fail":
                placeholder.error("Invalid UPI")
                time.sleep(3)
                placeholder.empty()
                st.session_state.status=None
