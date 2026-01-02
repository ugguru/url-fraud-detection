# QR Code Fraud Detection - Refactoring Plan

## Current File Structure Analysis

### Tools/ folder:
- `qr_analysis.py` - QR image tampering analysis + QR API integration
- `qr_api.py` - ~~(duplicated)~~ **DELETED**
- `url_analysis.py` - URL phishing detection
- `upi.py` - UPI ID verification
- Other files: arya.py, safebrowsing.py, urlhauss.py, VT.py

### views/ folder:
- ~~`qrverification.py`~~ - **MOVED TO ARCHIVE**
- ~~`upiverification.py`~~ - **MOVED TO ARCHIVE**
- ~~`urlverification.py`~~ - **MOVED TO ARCHIVE**

### app.py - Main Streamlit app combining all features

## Merge Plan

### Feature 1: QR Analysis (Tools/qrcode.py)
**Source files:**
- `Tools/qr_analysis.py` (image analysis + APIs)
- `views/qrverification.py` (content analysis, UI components)

**Merged file:** `Tools/qrcode.py` - **PENDING CREATION**
- QRAnalyzer class
- analyze_qr_tampering() function
- QRCodeAPIs class
- analyze_qr_content() function
- UI components (circular_risk_meter, red_alert_screen, etc.)

### Feature 2: URL Analysis (Tools/url_analysis.py)
**Source files:**
- `Tools/url_analysis.py` - Keep as is (already a single, clean file)

### Feature 3: UPI Analysis (Tools/upi.py)
**Source files:**
- `Tools/upi.py` - Keep as is (already a single, clean file)

## Completed Tasks ✅
- [x] Analyzed codebase structure
- [x] Moved `views/` folder to `archive/views/`
- [x] Deleted duplicate `Tools/qr_api.py`

## Remaining Tasks
- [ ] Create merged `Tools/qrcode.py` file
- [ ] Delete `Tools/qr_analysis.py` (merged into qrcode.py)
- [ ] Update `app.py` imports to use `Tools.qrcode`

## Proposed New Structure

```
QR Code Fraud detection PROJECT/
├── app.py                          # Main Streamlit app (needs updated imports)
├── requirements.txt                # Dependencies
├── archive/                        # Archived files
│   └── views/                      # Moved from views/
│       ├── qrverification.py
│       ├── upiverification.py
│       └── urlverification.py
└── Tools/                          # All analysis modules
    ├── qrcode.py                   # [TO CREATE] QR analysis + content analysis + UI
    ├── qr_analysis.py              # [TO DELETE] Will be merged into qrcode.py
    ├── url_analysis.py             # URL analysis (unchanged)
    ├── upi.py                      # UPI verification (unchanged)
    ├── image/
    ├── arya.py
    ├── safebrowsing.py
    ├── urlhauss.py
    └── VT.py
```

## Files to Delete
- `Tools/qr_api.py` - ✅ Deleted
- `Tools/qr_analysis.py` - Pending (merge into qrcode.py)
- `views/qrverification.py` - ✅ Moved to archive

## Update Required
- [ ] Update `app.py` imports: `from Tools.qr_analysis import analyze_qr_tampering` → `from Tools.qrcode import analyze_qr_tampering`

