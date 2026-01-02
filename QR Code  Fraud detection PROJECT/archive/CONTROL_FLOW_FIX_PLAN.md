# Control Flow Fix Plan

## Problem Identified
The QR code analysis in both `app.py` and `views/qrverification.py` runs **synchronously**, blocking the UI display until complete analysis finishes. This creates a poor user experience where:
- No intermediate results are shown during analysis
- UI appears frozen during the analysis process
- Users cannot see partial results even when some analysis steps complete

## Root Cause
In `app.py` (lines ~150-170), the control flow is:
```python
if st.session_state.analyze_clicked and st.session_state.uploaded_image_path:
    tmp_path = st.session_state.uploaded_image_path
    
    if st.session_state.qr_result is None:
        with st.spinner("🔍 Analyzing QR Code..."):
            st.session_state.qr_result = analyze_qr_tampering(tmp_path)  # BLOCKING
            decoded = st.session_state.qr_result.get("decoded_data", None)
            if decoded:
                st.session_state.content_result = analyze_content(decoded)  # BLOCKING
```

Similarly in `views/qrverification.py` (lines ~95-105):
```python
if st.button("🔍 Analyze QR Code", type="primary", use_container_width=True):
    with st.spinner("Analyzing QR code for tampering..."):
        result = analyze_qr_tampering(tmp_path)  # BLOCKING
        st.session_state.qr_analysis = result
        time.sleep(1)  # Artificial delay for UX
```

## Solution Strategy
1. **Use `st.empty()` containers** for incremental UI updates
2. **Show progress with `st.progress()`** for each analysis step
3. **Break down analysis into steps** with visible progress
4. **Update UI between steps** so users see progress

## Implementation Plan

### Step 1: Modify `Tools/qr_analysis.py`
- Add optional progress callback to `analyze_qr_image()` method
- Allow reporting individual metric scores as they complete
- Create step-by-step analysis with callbacks

### Step 2: Modify `app.py`
- Add progress display using `st.progress()`
- Break QR analysis into visual steps:
  - Image Quality Analysis (0-20%)
  - Structure Analysis (20-40%)
  - Noise Analysis (40-60%)
  - Symmetry Analysis (60-80%)
  - Finder Pattern Analysis (80-100%)
- Update progress bar after each step
- Show partial results as they become available

### Step 3: Modify `views/qrverification.py`
- Add similar progress display
- Show analysis steps with progress bar
- Update results incrementally

### Step 4: Testing
- Verify all functionality still works
- Test with various QR code images
- Ensure no regressions in analysis accuracy

## Files to Modify
1. `Tools/qr_analysis.py` - Add progress callback support
2. `app.py` - Implement progressive UI updates
3. `views/qrverification.py` - Implement progressive UI updates

## Expected Outcome
- Users see real-time progress during analysis
- Partial results display as analysis completes
- UI remains responsive during long analysis
- Better user experience with visual feedback
