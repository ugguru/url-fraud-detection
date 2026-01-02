"""
QR Code Fraud Detection System - Single Page Application
Upload QR Code → Analyze Tampering → Extract Content → Check Safety → Show Results
"""

import streamlit as st
import tempfile
import os
from PIL import Image
from urllib.parse import urlparse, parse_qs
from Tools.qrcode import analyze_qr_tampering
from Tools.url_analysis import analyze_url_realtime
from Tools.upi import VerifyUPI
import cv2
import numpy as np

# Page configuration
st.set_page_config(
    page_title="QR Code Fraud Detection",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling and mobile responsiveness
st.markdown("""
<style>
    .main-header {
        text-align: center;
        padding: 1rem;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        color: white;
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    
    /* Better button styling */
    .stButton > button {
        width: 100%;
    }
    
    /* Hide Streamlit branding on mobile */
    @media (max-width: 768px) {
        .stDeployButton {
            display: none !important;
        }
    }
</style>
""", unsafe_allow_html=True)


def circular_risk_meter(score, title="Risk", size=120):
    """Display circular risk meter"""
    radius = 50
    stroke = 8
    normalized = min(max(score, 0), 100)
    circumference = 2 * 3.1416 * radius
    offset = circumference - (normalized / 100) * circumference
    
    if score <= 30:
        color = "#2ecc71"
        level = "LOW"
    elif score <= 60:
        color = "#f39c12"
        level = "MEDIUM"
    else:
        color = "#e74c3c"
        level = "HIGH"
    
    st.markdown(f"""
    <div style="display:flex;justify-content:center;flex-direction:column;align-items:center;">
    <svg width="{size}" height="{size}">
        <circle cx="{size/2}" cy="{size/2}" r="{radius}"
            stroke="#e6e6e6" stroke-width="{stroke}" fill="none" />
        <circle cx="{size/2}" cy="{size/2}" r="{radius}"
            stroke="{color}" stroke-width="{stroke}" fill="none"
            stroke-dasharray="{circumference}" stroke-dashoffset="{offset}"
            stroke-linecap="round" transform="rotate(-90 {size/2} {size/2})" />
        <text x="{size/2}" y="{size/2}" text-anchor="middle" dy="8"
            font-size="{size/5}" font-weight="bold" fill="{color}">{normalized}</text>
        <text x="{size/2}" y="{size/2 + 20}" text-anchor="middle"
            font-size="12" fill="#555">{level}</text>
    </svg>
    <p style="margin:5px 0 0 0;font-size:12px;color:#777;">{title}</p>
    </div>
    """, unsafe_allow_html=True)


def analyze_content(decoded_content):
    """Analyze decoded content"""
    if not decoded_content:
        return None
    
    import re
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


def decode_qr_from_image(image_source):
    """
    Decode QR code from various image sources
    
    Args:
        image_source: PIL Image, file path, or numpy array
    
    Returns:
        Decoded QR data string or None
    """
    try:
        # If it's a PIL Image, convert to cv2 format
        if isinstance(image_source, Image.Image):
            img_array = np.array(image_source)
            if len(img_array.shape) == 3:
                img = cv2.cvtColor(img_array, cv2.COLOR_RGB2BGR)
            else:
                img = img_array
        elif isinstance(image_source, np.ndarray):
            img = image_source
        else:
            # Assume it's a file path
            img = cv2.imread(image_source)
        
        if img is None:
            return None
        
        # Use OpenCV's built-in QR code detector
        detector = cv2.QRCodeDetector()
        data, vertices_array, binary_qrcode = detector.detectAndDecode(img)
        
        if data and len(data) > 0:
            return data
        
        # Try with different preprocessing
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Adaptive threshold
        thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                                       cv2.THRESH_BINARY, 11, 2)
        data, _, _ = detector.detectAndDecode(thresh)
        if data and len(data) > 0:
            return data
        
        # Otsu's threshold
        _, thresh_otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        data, _, _ = detector.detectAndDecode(thresh_otsu)
        if data and len(data) > 0:
            return data
        
        return None
    except Exception as e:
        print(f"QR decode error: {e}")
        return None


def main():
    """Main application"""
    
    # Header
    st.markdown("""
    <div class="main-header">
        <h1>🔍 QR Code Fraud Detection System</h1>
        <p>Upload a QR Code to analyze tampering, extract content, and check safety</p>
    </div>
    """, unsafe_allow_html=True)
    
    # Session state
    if "qr_result" not in st.session_state:
        st.session_state.qr_result = None
    if "content_result" not in st.session_state:
        st.session_state.content_result = None
    if "uploaded_image_path" not in st.session_state:
        st.session_state.uploaded_image_path = None
    if "analyze_clicked" not in st.session_state:
        st.session_state.analyze_clicked = False
    if "current_file_name" not in st.session_state:
        st.session_state.current_file_name = None
    
    # Upload and Preview columns
    col_upload, col_preview = st.columns([1, 1])
    
    with col_upload:
        st.markdown("### 📷 Upload QR Code")
        uploaded_file = st.file_uploader("Choose QR Code image",
            type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'])
        
        # Check if a new file was uploaded
        if uploaded_file is not None:
            # Reset results if a new file is uploaded (different name or first upload)
            if st.session_state.current_file_name != uploaded_file.name:
                st.session_state.qr_result = None
                st.session_state.content_result = None
                st.session_state.analyze_clicked = False
                st.session_state.current_file_name = uploaded_file.name
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                st.session_state.uploaded_image_path = tmp_file.name
        
        if st.session_state.uploaded_image_path:
            if st.button("🔍 Analyze QR Code", type="primary", use_container_width=True):
                st.session_state.analyze_clicked = True
                st.session_state.qr_result = None
                st.session_state.content_result = None
    
    with col_preview:
        st.markdown("### 👁️ Preview")
        if st.session_state.uploaded_image_path and os.path.exists(st.session_state.uploaded_image_path):
            try:
                image = Image.open(st.session_state.uploaded_image_path)
                st.image(image, caption="Uploaded QR Code", width=400)
                
                # Show decoded content preview if available
                if st.session_state.qr_result and st.session_state.qr_result.get("decoded_data"):
                    decoded = st.session_state.qr_result.get("decoded_data")
                    st.markdown("**📄 Decoded Content:**")
                    st.code(decoded, language="text")
                elif st.session_state.analyze_clicked and st.session_state.qr_result:
                    # Show warning if analysis ran but no content was decoded
                    st.warning("⚠️ No content could be decoded from this QR code")
            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.info("👆 Upload a QR code image")
    
    # Analysis Results
    if st.session_state.analyze_clicked and st.session_state.uploaded_image_path:
        tmp_path = st.session_state.uploaded_image_path
        
        if st.session_state.qr_result is None:
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
            st.session_state.qr_result = analyze_qr_tampering(tmp_path, progress_callback=update_progress)
            
            # Clear progress indicators and show final status
            decoded = st.session_state.qr_result.get("decoded_data", None)
            if decoded:
                status_text.text("📄 Decoding content...")
                content_analysis = analyze_content(decoded)
                # Always set content_result if decoded data exists
                if content_analysis:
                    st.session_state.content_result = content_analysis
                else:
                    # Create a basic content result for display purposes
                    st.session_state.content_result = {
                        "content": decoded,
                        "type": "text",
                        "details": None
                    }
            
            # Clear progress indicators
            progress_container.empty()
            progress_bar.empty()
            status_text.empty()
        
        # Display results
        display_analysis_results(st.session_state.qr_result, st.session_state.content_result)
        
        # Clean up
        try:
            if st.session_state.uploaded_image_path and os.path.exists(st.session_state.uploaded_image_path):
                os.unlink(st.session_state.uploaded_image_path)
                st.session_state.uploaded_image_path = None
                st.session_state.analyze_clicked = False
        except:
            pass
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style="text-align:center;color:#666;font-size:0.9em;">
        🔒 QR Code Fraud Detection System | Secure Your Digital Transactions
    </div>
    """, unsafe_allow_html=True)


def display_analysis_results(qr_result, content_result):
    """Display analysis results in a formatted manner"""
    if qr_result["status"] == "success":
        st.markdown("---")
        st.markdown("## 📊 Analysis Results")
        
        col_tampering, col_content = st.columns(2, gap="large")
        
        # Column 1: Image Tampering Analysis
        with col_tampering:
            st.markdown("### 🔍 Image Tampering Analysis")
            
            col_meter, col_status = st.columns([1, 2])
            with col_meter:
                circular_risk_meter(qr_result["risk_score"], "Tampering Risk")
            with col_status:
                if qr_result["is_masked"]:
                    st.error("🚨 **MASKED QR CODE**")
                else:
                    st.success("✅ **QR Appears Legitimate**")
            
            details = qr_result.get("analysis_details", {})
            if details:
                st.markdown("**Analysis Metrics:**")
                m1, m2, m3 = st.columns(3)
                m1.metric("Quality", f"{details.get('quality_score', 0):.0f}%")
                m2.metric("Structure", f"{details.get('structure_score', 0):.0f}%")
                m3.metric("Noise", f"{details.get('noise_score', 0):.0f}%")
                
                m4, m5 = st.columns(2)
                m4.metric("Symmetry", f"{details.get('symmetry_score', 0):.0f}%")
                m5.metric("Finder", f"{details.get('finder_pattern_score', 0):.0f}%")
        
        # Column 2: Content Analysis
        with col_content:
            display_content_analysis(content_result)


def display_content_analysis(content_result):
    """Display content analysis results"""
    st.markdown("### 📄 Content Analysis")
    
    if content_result:
        ctype = content_result.get("type")
        
        if ctype == "url":
            ud = content_result.get("details", {})
            if ud:
                col_m, col_s = st.columns([1, 2])
                with col_m:
                    circular_risk_meter(ud.get("risk_score", 0), "URL Risk")
                with col_s:
                    rl = ud.get("risk_level", "Unknown")
                    if rl == "Low":
                        st.success("✅ **URL Safe**")
                    elif rl in ["Medium", "High"]:
                        st.warning(f"⚠️ **Caution: {rl}**")
                    else:
                        st.error("🚨 **High Risk**")
                
                # Show if URL is shortened
                is_shortened = ud.get("is_shortened", False)
                expanded_url = ud.get("expanded_url")
                
                st.markdown("**Original URL:**")
                st.code(content_result["content"], language="text")
                
                # Show expanded URL if it was shortened
                if is_shortened and expanded_url:
                    st.markdown("""
                    <div style="background-color: #fff3cd; padding: 10px; border-radius: 5px; margin-top: 10px;">
                        <strong>🔗 Expanded URL (from shortener):</strong>
                    </div>
                    """, unsafe_allow_html=True)
                    st.code(expanded_url, language="text")
                    
                    # Show expanded URL analysis if available
                    expanded_analysis = ud.get("expanded_analysis")
                    if expanded_analysis and isinstance(expanded_analysis, dict):
                        exp_risk = expanded_analysis.get("risk_score", 0)
                        exp_level = expanded_analysis.get("risk_level", "Unknown")
                        st.markdown(f"**Expanded URL Risk:** {exp_risk}/100 ({exp_level})")
                
                warnings = ud.get("warnings", [])
                if warnings:
                    st.markdown("**⚠️ Security Warnings:**")
                    for w in warnings:
                        st.warning(w)
                
                st.info(f"💡 **{ud.get('recommendation', '')}**")
        
        elif ctype == "upi":
            ud = content_result.get("details", {})
            if ud:
                col_m, col_s = st.columns([1, 2])
                with col_m:
                    circular_risk_meter(ud.get("riskscore", 0), "UPI Risk")
                with col_s:
                    if ud.get("status") == "Success":
                        st.success("✅ **Valid UPI ID**")
                    else:
                        st.error("❌ **Invalid UPI ID**")
                
                st.markdown(f"**UPI ID:** `{ud.get('upiid', '')}`")
                st.markdown(f"**Bank/Provider:** {ud.get('bank', 'Unknown')}")
                st.markdown(f"**Risk Level:** {ud.get('risklevel', 'Unknown')}")
        
        elif ctype == "text":
            st.info("ℹ️ **Plain Text Content**")
            st.markdown(f"**Content:** {content_result['content']}")
    
    elif content_result.get("decoded_data"):
        # Show decoded content even if content analysis wasn't performed
        st.info("ℹ️ **Decoded Content (Type not recognized)**")
        st.markdown("**Content:**")
        st.code(content_result["decoded_data"], language="text")
        
        # Show content type detection info
        decoded_data = content_result["decoded_data"]
        if decoded_data.startswith('http'):
            st.markdown("*This appears to be a URL but URL analysis failed*")
        elif '@' in decoded_data:
            st.markdown("*This appears to be a UPI ID but UPI verification failed*")
    
    else:
        st.warning("⚠️ No content decoded")


if __name__ == "__main__":
    main()

