import cv2
import numpy as np
from PIL import Image
import qrcode
import os
import tempfile

# Try to import pyzbar, make it optional
try:
    from pyzbar.pyzbar import decode as decode_qr
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

# Try to import QR API module, make it optional
try:
    from Tools.qr_api import QRCodeAPIs, decode_qr_with_free_apis
    QR_API_AVAILABLE = True
except ImportError:
    try:
        from qr_api import QRCodeAPIs, decode_qr_with_free_apis
        QR_API_AVAILABLE = True
    except ImportError:
        QR_API_AVAILABLE = False

class QRAnalyzer:
    def __init__(self):
        self.min_quality_threshold = 0.7
        self.tampering_threshold = 30
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        """Set a callback function for progress updates"""
        self.progress_callback = callback
        
    def _report_progress(self, step, total_steps, message, progress=None):
        """Report progress to callback if available"""
        if self.progress_callback:
            # If explicit progress provided, use it, otherwise calculate
            if progress is not None:
                self.progress_callback(progress, message)
            else:
                # Calculate progress as percentage
                pct = (step / total_steps) * 100
                self.progress_callback(pct, message)
        
    def analyze_qr_image(self, image_path, progress_callback=None):
        """
        Comprehensive QR code analysis for tampering detection
        Returns: Dictionary with analysis results
        
        Args:
            image_path: Path to QR code image
            progress_callback: Optional function(progress_pct, message) for updates
        """
        # Set progress callback
        self.set_progress_callback(progress_callback)
        
        try:
            # Load image
            img = cv2.imread(image_path)
            if img is None:
                return {
                    "status": "error",
                    "message": "Could not load image",
                    "is_masked": True,
                    "risk_score": 100,
                    "risk_level": "High"
                }
            
            self._report_progress(0, 5, "Loading image...", 0)
            
            # Multiple analysis techniques with progress reporting
            self._report_progress(1, 5, "Analyzing image quality...", 20)
            quality_score = self._analyze_image_quality(img)
            
            self._report_progress(2, 5, "Analyzing QR structure...", 40)
            structure_score = self._analyze_qr_structure(img)
            
            self._report_progress(3, 5, "Analyzing noise patterns...", 60)
            noise_score = self._analyze_noise_patterns(img)
            
            self._report_progress(4, 5, "Analyzing symmetry...", 80)
            symmetry_score = self._analyze_qr_symmetry(img)
            
            self._report_progress(5, 5, "Analyzing finder patterns...", 100)
            finder_pattern_score = self._analyze_finder_patterns(img)
            
            # Calculate overall risk score
            risk_score = self._calculate_risk_score(
                quality_score, structure_score, noise_score, 
                symmetry_score, finder_pattern_score
            )
            
            # Determine if QR is masked
            is_masked = risk_score >= self.tampering_threshold
            
            # Determine risk level
            if risk_score <= 30:
                risk_level = "Low"
            elif risk_score <= 60:
                risk_level = "Medium"
            else:
                risk_level = "High"
            
            # Try to decode QR content
            decoded_data = self._decode_qr_content(image_path)
            
            return {
                "status": "success",
                "is_masked": is_masked,
                "risk_score": int(risk_score),
                "risk_level": risk_level,
                "decoded_data": decoded_data,
                "analysis_details": {
                    "quality_score": quality_score,
                    "structure_score": structure_score,
                    "noise_score": noise_score,
                    "symmetry_score": symmetry_score,
                    "finder_pattern_score": finder_pattern_score
                }
            }
            
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "is_masked": True,
                "risk_score": 100,
                "risk_level": "High"
            }
    
    def _analyze_image_quality(self, img):
        """Analyze image sharpness and quality"""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Calculate variance of Laplacian (sharpness measure)
        laplacian_var = cv2.Laplacian(gray, cv2.CV_64F).var()
        
        # Normalize to 0-100 scale
        quality_score = min(100, (laplacian_var / 500) * 100)
        
        # Lower quality indicates potential tampering
        if quality_score < 50:
            return 40  # High risk
        elif quality_score < 70:
            return 60  # Medium risk
        else:
            return 85  # Low risk
    
    def _analyze_qr_structure(self, img):
        """Analyze QR code structural integrity"""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Apply edge detection
        edges = cv2.Canny(gray, 50, 150)
        
        # Find contours
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        # QR codes should have square patterns
        square_count = 0
        total_contours = len(contours)
        
        for contour in contours:
            # Approximate contour
            epsilon = 0.02 * cv2.arcLength(contour, True)
            approx = cv2.approxPolyDP(contour, epsilon, True)
            
            # Check if it's approximately square-like
            if len(approx) >= 4:
                area = cv2.contourArea(contour)
                if area > 100:  # Filter out noise
                    square_count += 1
        
        # Calculate structure integrity
        if total_contours > 0:
            structure_ratio = square_count / total_contours
            structure_score = structure_ratio * 100
        else:
            structure_score = 0
        
        return min(100, structure_score)
    
    def _analyze_noise_patterns(self, img):
        """Analyze noise patterns that might indicate tampering"""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Apply median filter to get clean image
        median = cv2.medianBlur(gray, 5)
        
        # Calculate difference between original and median filtered
        diff = cv2.absdiff(gray, median)
        
        # Calculate noise percentage
        noise_pixels = np.sum(diff > 30)
        total_pixels = diff.shape[0] * diff.shape[1]
        noise_percentage = (noise_pixels / total_pixels) * 100
        
        # Lower noise score indicates more tampering
        if noise_percentage > 15:
            return 20  # High risk
        elif noise_percentage > 8:
            return 40  # Medium risk
        else:
            return 80  # Low risk
    
    def _analyze_qr_symmetry(self, img):
        """Analyze symmetry of QR code patterns"""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Find QR code boundaries
        edges = cv2.Canny(gray, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        
        if not contours:
            return 30  # High risk
        
        # Find the largest contour (likely the QR code)
        largest_contour = max(contours, key=cv2.contourArea)
        x, y, w, h = cv2.boundingRect(largest_contour)
        
        # Extract QR code region
        qr_region = gray[y:y+h, x:x+w]
        
        if qr_region.size == 0:
            return 30
        
        # Split into quadrants and compare
        h_mid, w_mid = qr_region.shape[0] // 2, qr_region.shape[1] // 2
        
        top_left = qr_region[0:h_mid, 0:w_mid]
        top_right = qr_region[0:h_mid, w_mid:2*w_mid]
        bottom_left = qr_region[h_mid:2*h_mid, 0:w_mid]
        bottom_right = qr_region[h_mid:2*h_mid, w_mid:2*w_mid]
        
        # Calculate symmetry scores
        def compare_regions(reg1, reg2):
            if reg1.size == 0 or reg2.size == 0:
                return 0
            diff = cv2.absdiff(reg1, reg2)
            return 100 - (np.mean(diff) * 100 / 255)
        
        symmetry_scores = [
            compare_regions(top_left, top_right),
            compare_regions(top_left, bottom_left),
            compare_regions(bottom_left, bottom_right)
        ]
        
        avg_symmetry = np.mean(symmetry_scores)
        return avg_symmetry
    
    def _analyze_finder_patterns(self, img):
        """Analyze QR code finder patterns (the three corner squares)"""
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        
        # Template matching for finder patterns
        finder_template = np.array([
            [0, 0, 0, 0, 0],
            [0, 255, 255, 255, 0],
            [0, 255, 0, 255, 0],
            [0, 255, 255, 255, 0],
            [0, 0, 0, 0, 0]
        ], dtype=np.uint8)
        
        # Try to find finder patterns
        matches = []
        for scale in [0.8, 1.0, 1.2]:
            # Resize template
            if scale != 1.0:
                w, h = finder_template.shape[1], finder_template.shape[0]
                new_w, new_h = int(w * scale), int(h * scale)
                template_resized = cv2.resize(finder_template, (new_w, new_h))
            else:
                template_resized = finder_template
            
            # Template matching
            result = cv2.matchTemplate(gray, template_resized, cv2.TM_CCOEFF_NORMED)
            min_val, max_val, min_loc, max_loc = cv2.minMaxLoc(result)
            matches.append(max_val)
        
        # Average match score
        avg_match = np.mean(matches)
        
        # Convert to score (higher match = lower risk)
        if avg_match > 0.7:
            return 85
        elif avg_match > 0.5:
            return 60
        else:
            return 30
    
    def _calculate_risk_score(self, quality, structure, noise, symmetry, finder):
        """Calculate overall risk score from individual metrics"""
        # Weights for different factors
        weights = {
            'quality': 0.25,
            'structure': 0.20,
            'noise': 0.20,
            'symmetry': 0.20,
            'finder': 0.15
        }
        
        # Calculate weighted average (inverted because lower scores = higher risk)
        weighted_score = (
            (100 - quality) * weights['quality'] +
            (100 - structure) * weights['structure'] +
            (100 - noise) * weights['noise'] +
            (100 - symmetry) * weights['symmetry'] +
            (100 - finder) * weights['finder']
        )
        
        return min(100, weighted_score)
    
    def _preprocess_image(self, img):
        """Preprocess image for better QR code detection"""
        try:
            # Convert to grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            
            # Apply adaptive thresholding for better contrast
            binary = cv2.adaptiveThreshold(
                gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
                cv2.THRESH_BINARY, 11, 2
            )
            
            # Apply median blur to reduce noise
            blurred = cv2.medianBlur(binary, 3)
            
            # Apply dilation to strengthen QR patterns
            kernel = np.ones((2, 2), np.uint8)
            dilated = cv2.dilate(blurred, kernel, iterations=1)
            
            # Apply erosion
            eroded = cv2.erode(dilated, kernel, iterations=1)
            
            return eroded
        except Exception as e:
            print(f"Preprocessing error: {e}")
            return img
    
    def _decode_qr_content(self, image_path):
        """
        Attempt to decode QR code content using multiple methods
        Returns: decoded data string or None
        """
        import traceback
        
        try:
            # Method 1: Try OpenCV's built-in QR code detector with original image
            img = cv2.imread(image_path)
            if img is None:
                raise ValueError("Could not read image file")
            
            detector = cv2.QRCodeDetector()
            
            # Try with original image
            data, vertices_array, binary_qrcode = detector.detectAndDecode(img)
            if data and len(data) > 0:
                return data
            
            # Method 2: Try with different color channels
            for channel in [0, 1, 2]:
                try:
                    channel_img = img[:,:,channel] if len(img.shape) == 3 else img
                    data, _, _ = detector.detectAndDecode(channel_img)
                    if data and len(data) > 0:
                        return data
                except:
                    continue
            
            # Method 3: Try with preprocessed image
            processed = self._preprocess_image(img)
            data, vertices_array, binary_qrcode = detector.detectAndDecode(processed)
            if data and len(data) > 0:
                return data
            
            # Method 4: Try with increased contrast (histogram equalization)
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            equ = cv2.equalizeHist(gray)
            data, vertices_array, binary_qrcode = detector.detectAndDecode(equ)
            if data and len(data) > 0:
                return data
            
            # Method 5: Try with gamma correction (helps with dark/light images)
            for gamma in [0.5, 1.5, 2.0]:
                try:
                    inv_gamma = 1.0 / gamma
                    table = np.array([((i / 255.0) ** inv_gamma) * 255 for i in np.arange(0, 256)]).astype("uint8")
                    gamma_corrected = cv2.LUT(gray, table)
                    data, _, _ = detector.detectAndDecode(gamma_corrected)
                    if data and len(data) > 0:
                        return data
                except:
                    continue
            
            # Method 6: Try with different thresholding methods
            try:
                # Adaptive threshold
                thresh1 = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 11, 2)
                data, _, _ = detector.detectAndDecode(thresh1)
                if data and len(data) > 0:
                    return data
                
                # Otsu's threshold
                _, thresh2 = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                data, _, _ = detector.detectAndDecode(thresh2)
                if data and len(data) > 0:
                    return data
            except:
                pass
            
            # Method 7: Try pyzbar if available
            if PYZBAR_AVAILABLE:
                img_pil = Image.open(image_path)
                
                # Try with original image
                try:
                    decoded_objects = decode_qr(img_pil)
                    if decoded_objects:
                        for obj in decoded_objects:
                            decoded_data = obj.data.decode('utf-8', errors='ignore')
                            if decoded_data:
                                return decoded_data
                except:
                    pass
                
                # Try with different image modes
                for mode in ['L', 'RGB', 'RGBA', '1']:
                    try:
                        img_mode = img_pil.convert(mode)
                        decoded_objects = decode_qr(img_mode)
                        if decoded_objects:
                            for obj in decoded_objects:
                                decoded_data = obj.data.decode('utf-8', errors='ignore')
                                if decoded_data:
                                    return decoded_data
                    except Exception:
                        continue
                
                # Try with resized image (some QR codes are too small)
                try:
                    w, h = img_pil.size
                    if w < 200 or h < 200:
                        img_resized = img_pil.resize((w*2, h*2), Image.Resampling.LANCZOS)
                        decoded_objects = decode_qr(img_resized)
                        if decoded_objects:
                            for obj in decoded_objects:
                                decoded_data = obj.data.decode('utf-8', errors='ignore')
                                if decoded_data:
                                    return decoded_data
                except:
                    pass
            
            # Method 8: Try free QR code APIs if available
            if QR_API_AVAILABLE:
                try:
                    api_handler = QRCodeAPIs(timeout=15, max_retries=3)
                    api_result = api_handler.decode_qr_with_apis(image_path)
                    if api_result:
                        return api_result
                except Exception as e:
                    print(f"API decoding error: {e}")
            
            return None
        except Exception as e:
            print(f"QR decoding error: {e}")
            traceback.print_exc()
            return None

def analyze_qr_tampering(image_path, progress_callback=None):
    """
    Main function to analyze QR code for tampering
    
    Args:
        image_path: Path to QR code image
        progress_callback: Optional function(progress_pct, message) for updates
        
    Returns:
        Dictionary with analysis results
    """
    analyzer = QRAnalyzer()
    return analyzer.analyze_qr_image(image_path, progress_callback=progress_callback)
