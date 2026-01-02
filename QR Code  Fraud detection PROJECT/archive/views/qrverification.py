import streamlit as st
import tempfile
import os
from PIL import Image
from Tools.qr_analysis import analyze_qr_tampering
from Tools.url_analysis import analyze_url_realtime
from Tools.upi import VerifyUPI, CheckInvalidUPIPattern
from urllib.parse import urlparse, parse_qs
import re
import time


def analyze_qr_content(decoded_content):
    """Analyze decoded QR code content (URL, UPI, or text)"""
    if not decoded_content:
        return None
    
    result = {"content": decoded_content, "type": None, "details": None}
    
    # Strip whitespace
    cleaned_content = decoded_content.strip()
    
    # Check for UPI URL (e.g., upi://pay?pa= gururock9159@oksbi&pn=NAME&aid=...)
    if cleaned_content.startswith('upi://'):
        try:
            parsed = urlparse(cleaned_content)
            params = parse_qs(parsed.query)
            # Get the 'pa' (payee address) parameter
            if 'pa' in params and params['pa']:
                upi_id = params['pa'][0]
                
                # First check for invalid patterns
                invalid_check = CheckInvalidUPIPattern(upi_id)
                if not invalid_check["is_valid"]:
                    result["type"] = "upi"
                    result["details"] = {
                        "status": "Invalid",
                        "upiid": upi_id,
                        "error_type": invalid_check["error_type"],
                        "error_message": invalid_check["error_message"],
                        "riskscore": 100,
                        "risklevel": "High"
                    }
                    return result
                
                # If valid pattern, proceed with normal verification
                result["type"] = "upi"
                result["details"] = VerifyUPI(upi_id)
                return result
        except Exception as e:
            print(f"UPI parsing error: {e}")
            pass
    
    # Check UPI ID directly
    upi_pattern = r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$'
    if '@' in cleaned_content:
        cleaned = cleaned_content.strip()
        
        # First check for invalid patterns (like multiple @ symbols)
        invalid_check = CheckInvalidUPIPattern(cleaned)
        if not invalid_check["is_valid"]:
            result["type"] = "upi"
            result["details"] = {
                "status": "Invalid",
                "upiid": cleaned,
                "error_type": invalid_check["error_type"],
                "error_message": invalid_check["error_message"],
                "riskscore": 100,
                "risklevel": "High"
            }
            return result
        
        # If valid format, proceed with normal verification
        if re.match(upi_pattern, cleaned):
            result["type"] = "upi"
            result["details"] = VerifyUPI(cleaned)
            return result
    
    # Check URL - including www. URLs and other common URL formats
    url_patterns = [
        'http://', 'https://', 'ftp://',  # Standard protocols
        'www.', 'WWW.',  # www prefix
    ]
    
    is_url = any(cleaned_content.startswith(prefix) for prefix in url_patterns)
    
    # Also check if it looks like a URL (contains . and has no spaces)
    if not is_url:
        if '.' in cleaned_content and ' ' not in cleaned_content:
            # Might be a URL without protocol
            is_url = True
    
    if is_url:
        # Add protocol if missing
        url_to_check = cleaned_content
        if cleaned_content.lower().startswith('www.'):
            url_to_check = 'https://' + cleaned_content
        
        result["type"] = "url"
        result["details"] = analyze_url_realtime(url_to_check)
        return result
    
    result["type"] = "text"
    return result

def circular_risk_meter(score, title="QR Code Risk"):
    """Display circular risk meter similar to UPI verification"""
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
        <text x="90" y="140"
            text-anchor="middle"
            font-size="12"
            fill="#777">
            {title}
        </text>
    </svg>
    </div>
    """, unsafe_allow_html=True)

def red_alert_screen():
    """Display red alert screen for masked QR codes"""
    st.markdown("""
    <div style="
        background: linear-gradient(45deg, #ff4444, #cc0000);
        color: white;
        padding: 30px;
        border-radius: 15px;
        text-align: center;
        border: 3px solid #990000;
        box-shadow: 0 4px 15px rgba(204, 0, 0, 0.3);
        margin: 20px 0;
    ">
        <h1 style="margin: 0; font-size: 2.5em;">🚨 FRAUD ALERT 🚨</h1>
        <h2 style="margin: 10px 0; font-weight: normal;">QR CODE TAMPERING DETECTED</h2>
        <p style="font-size: 1.2em; margin: 15px 0;">
            This QR code appears to be <strong>MASKED</strong> or <strong>TAMPERED</strong>
        </p>
        <p style="font-size: 1em; margin: 10px 0; opacity: 0.9;">
            ⚠️ DO NOT TRUST THIS QR CODE ⚠️<br>
            It may lead to fraudulent websites or malicious content
        </p>
    </div>
    """, unsafe_allow_html=True)

def analysis_details_card(details):
    """Display detailed analysis results"""
    with st.expander("📊 Detailed Analysis", expanded=False):
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Image Quality", f"{details['quality_score']:.1f}%", delta=None)
            st.metric("Structure Integrity", f"{details['structure_score']:.1f}%", delta=None)
            st.metric("Noise Pattern", f"{details['noise_score']:.1f}%", delta=None)
        
        with col2:
            st.metric("Symmetry Score", f"{details['symmetry_score']:.1f}%", delta=None)
            st.metric("Finder Patterns", f"{details['finder_pattern_score']:.1f}%", delta=None)
            st.metric("Overall Risk", f"{100 - sum(details.values())/len(details):.1f}%", delta=None)

# Initialize session state
if "qr_analysis" not in st.session_state:
    st.session_state.qr_analysis = None
if "uploaded_image" not in st.session_state:
    st.session_state.uploaded_image = None

# Main interface
st.title("🔍 QR Code Fraud Detection")
st.markdown("---")

# Create tabs for different functionalities
tab1, tab3 = st.tabs(["📷 Upload QR Code", "ℹ️ Information"])

with tab1:
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Upload QR Code Image")
        uploaded_file = st.file_uploader(
            "Choose a QR code image", 
            type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'],
            help="Upload a QR code image to analyze for tampering"
        )
        
        if uploaded_file is not None:
            # Save uploaded file temporarily
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                tmp_path = tmp_file.name
                st.session_state.uploaded_image = tmp_path
            
            # Display uploaded image
            st.subheader("📷 Uploaded Image")
            image = Image.open(uploaded_file)
            st.image(image, caption="Uploaded QR Code", use_column_width=True)
            
            # Analyze button
            if st.button("🔍 Analyze QR Code", type="primary", use_container_width=True):
                # Create containers for progressive UI updates
                progress_container = st.empty()
                progress_bar = st.empty()
                status_text = st.empty()
                
                # Progress callback function
                def update_progress(progress_pct, message):
                    """Update progress display"""
                    progress_bar.progress(progress_pct / 100)
                    status_text.text(f"🔄 {message}")
                
                # Start with initial progress
                progress_container.info("🔍 Analyzing QR Code...")
                progress_bar.progress(0)
                status_text.text("Initializing...")
                
                # Perform analysis with progress updates
                result = analyze_qr_tampering(tmp_path, progress_callback=update_progress)
                st.session_state.qr_analysis = result
                
                # Clear progress indicators
                progress_container.empty()
                progress_bar.empty()
                status_text.empty()
    
    with col2:
        st.subheader("📊 Analysis Results")
        
        if st.session_state.qr_analysis:
            result = st.session_state.qr_analysis
            
            if result["status"] == "success":
                # Display risk meter
                circular_risk_meter(result["risk_score"], "QR Tampering")
                
                # Show red alert for masked QR codes
                if result["is_masked"]:
                    st.error("🚨 MASKED QR CODE DETECTED!")
                    red_alert_screen()
                else:
                    st.success("✅ QR Code appears legitimate")
                
                # Display decoded content if available
                if result["decoded_data"]:
                    st.info(f"**Decoded Content:** {result['decoded_data']}")
                    
                    # Analyze the content type and show appropriate results
                    content_analysis = analyze_qr_content(result["decoded_data"])
                    if content_analysis:
                        ctype = content_analysis.get("type")
                        
                        if ctype == "url":
                            st.markdown("### 🌐 URL Analysis")
                            url_details = content_analysis.get("details", {})
                            if url_details:
                                col_url_meter, col_url_status = st.columns([1, 2])
                                with col_url_meter:
                                    # URL risk meter
                                    url_risk = url_details.get("risk_score", 0)
                                    radius = 50
                                    stroke = 8
                                    circumference = 2 * 3.1416 * radius
                                    offset = circumference - (url_risk / 100) * circumference
                                    if url_risk <= 30:
                                        color = "#2ecc71"
                                        level = "LOW"
                                    elif url_risk <= 60:
                                        color = "#f39c12"
                                        level = "MEDIUM"
                                    else:
                                        color = "#e74c3c"
                                        level = "HIGH"
                                    
                                    st.markdown(f"""
                                    <div style="display:flex;justify-content:center;">
                                    <svg width="120" height="120">
                                        <circle cx="60" cy="60" r="{radius}" stroke="#e6e6e6" stroke-width="{stroke}" fill="none" />
                                        <circle cx="60" cy="60" r="{radius}" stroke="{color}" stroke-width="{stroke}" fill="none"
                                            stroke-dasharray="{circumference}" stroke-dashoffset="{offset}" stroke-linecap="round" transform="rotate(-90 60 60)" />
                                        <text x="60" y="60" text-anchor="middle" dy="8" font-size="20" font-weight="bold" fill="{color}">{url_risk}</text>
                                    </svg>
                                    </div>
                                    """, unsafe_allow_html=True)
                                
                                with col_url_status:
                                    risk_level = url_details.get("risk_level", "Unknown")
                                    if risk_level == "Low":
                                        st.success("✅ URL Safe")
                                    elif risk_level in ["Medium", "High"]:
                                        st.warning(f"⚠️ Caution: {risk_level}")
                                    else:
                                        st.error("🚨 High Risk")
                                
                                # Show URL warnings
                                warnings = url_details.get("warnings", [])
                                if warnings:
                                    st.markdown("**⚠️ Security Warnings:**")
                                    for w in warnings:
                                        st.warning(w)
                                
                                st.info(f"💡 **{url_details.get('recommendation', '')}**")
                        
                        elif ctype == "upi":
                            st.markdown("### 📱 UPI Analysis")
                            upi_details = content_analysis.get("details", {})
                            if upi_details:
                                col_upi_meter, col_upi_status = st.columns([1, 2])
                                with col_upi_meter:
                                    upi_risk = upi_details.get("riskscore", 0)
                                    radius = 50
                                    stroke = 8
                                    circumference = 2 * 3.1416 * radius
                                    offset = circumference - (upi_risk / 100) * circumference
                                    if upi_risk <= 30:
                                        color = "#2ecc71"
                                        level = "LOW"
                                    elif upi_risk <= 60:
                                        color = "#f39c12"
                                        level = "MEDIUM"
                                    else:
                                        color = "#e74c3c"
                                        level = "HIGH"
                                    
                                    st.markdown(f"""
                                    <div style="display:flex;justify-content:center;">
                                    <svg width="120" height="120">
                                        <circle cx="60" cy="60" r="{radius}" stroke="#e6e6e6" stroke-width="{stroke}" fill="none" />
                                        <circle cx="60" cy="60" r="{radius}" stroke="{color}" stroke-width="{stroke}" fill="none"
                                            stroke-dasharray="{circumference}" stroke-dashoffset="{offset}" stroke-linecap="round" transform="rotate(-90 60 60)" />
                                        <text x="60" y="60" text-anchor="middle" dy="8" font-size="20" font-weight="bold" fill="{color}">{upi_risk}</text>
                                    </svg>
                                    </div>
                                    """, unsafe_allow_html=True)
                                
                                with col_upi_status:
                                    if upi_details.get("status") == "Success":
                                        st.success("✅ Valid UPI ID")
                                    elif upi_details.get("status") == "Invalid":
                                        st.error("🚨 INVALID UPI PATTERN DETECTED")
                                        # Show error type and message
                                        error_type = upi_details.get("error_type", "")
                                        error_message = upi_details.get("error_message", "")
                                        if error_type:
                                            st.warning(f"**Error Type:** {error_type}")
                                        if error_message:
                                            st.error(f"**{error_message}**")
                                        st.markdown("⚠️ **This pattern indicates potential QR code tampering or fraud!**")
                                    else:
                                        st.error("❌ Invalid UPI ID")
                                
                                st.markdown(f"**UPI ID:** `{upi_details.get('upiid', '')}`")
                                st.markdown(f"**Bank/Provider:** {upi_details.get('bank', 'N/A')}")
                                st.markdown(f"**Risk Level:** {upi_details.get('risklevel', 'Unknown')}")
                        
                        elif ctype == "text":
                            st.info("ℹ️ Plain Text Content")
                            st.markdown(f"**Content:** {content_analysis['content']}")
                
                # Show analysis details
                analysis_details_card(result["analysis_details"])
                
                # Clean up temporary file
                try:
                    os.unlink(tmp_path)
                except:
                    pass
                    
            else:
                st.error(f"❌ Analysis failed: {result['message']}")
                
        else:
            # Default placeholder
            st.info("👆 Upload a QR code image to begin analysis")
            st.markdown("""
            ### Features:
            - ✅ **Tampering Detection**: Identifies masked QR codes
            - ✅ **Risk Assessment**: Provides detailed risk scores
            - ✅ **Content Decoding**: Reads QR code content when possible
            - ✅ **Visual Alerts**: Clear indicators for fraudulent codes
            """)

with tab3:
    st.subheader("ℹ️ How QR Code Tampering Detection Works")
    
    st.markdown("""
    ### 🔍 Detection Methods
    
    Our advanced AI system analyzes multiple aspects of QR codes:
    
    **1. Image Quality Analysis**
    - Sharpness and clarity assessment
    - Blur and distortion detection
    - Resolution quality evaluation
    
    **2. Structural Integrity**
    - QR code pattern recognition
    - Square and geometric shape validation
    - Code structure consistency
    
    **3. Noise Pattern Analysis**
    - Unusual noise detection
    - Artifact identification
    - Digital manipulation signs
    
    **4. Symmetry Assessment**
    - Pattern symmetry verification
    - Balance analysis
    - Regular structure validation
    
    **5. Finder Pattern Recognition**
    - Corner marker detection
    - Standard QR pattern validation
    - Authentication marker verification
    
    ### 🎯 Risk Levels
    
    - **🟢 LOW (0-30)**: QR code appears legitimate
    - **🟡 MEDIUM (31-60)**: Some anomalies detected, use caution
    - **🔴 HIGH (61-100)**: QR code likely tampered or masked
    
    ### ⚠️ Security Warnings
    
    - Always verify QR codes from trusted sources
    - Avoid scanning QR codes from unknown websites
    - Be cautious of QR codes that appear damaged or modified
    - Use official QR codes from verified organizations
    """)

# Add footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666; font-size: 0.9em;">
    🔒 QR Code Fraud Detection System | Secure Your Digital Transactions
</div>
""", unsafe_allow_html=True)
