"""
QR Code Fraud Detection - Combined Module
Features: Image tampering detection, content analysis
"""

import cv2
import numpy as np
from PIL import Image
import os
import re
from urllib.parse import urlparse, parse_qs
import requests

try:
    from pyzbar.pyzbar import decode as decode_qr
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False


class QRAnalyzer:
    def __init__(self):
        self.tampering_threshold = 30
        self.progress_callback = None
        
    def set_progress_callback(self, callback):
        self.progress_callback = callback
        
    def analyze_qr_image(self, image_path, progress_callback=None):
        self.progress_callback = progress_callback
        
        try:
            img = cv2.imread(image_path)
            if img is None:
                return {"status": "error", "message": "Could not load image", 
                       "is_masked": True, "risk_score": 100, "risk_level": "High"}
            
            if self.progress_callback:
                self.progress_callback(0, "Loading image...")
            
            quality = self._analyze_image_quality(img)
            structure = self._analyze_qr_structure(img)
            noise = self._analyze_noise_patterns(img)
            symmetry = self._analyze_qr_symmetry(img)
            finder = self._analyze_finder_patterns(img)
            
            risk = self._calculate_risk(quality, structure, noise, symmetry, finder)
            
            return {
                "status": "success", "is_masked": risk >= self.tampering_threshold,
                "risk_score": int(risk), "risk_level": ["Low", "Medium", "High"][min(2, int(risk/33))],
                "decoded_data": self._decode_qr_content(image_path),
                "analysis_details": {"quality_score": quality, "structure_score": structure,
                    "noise_score": noise, "symmetry_score": symmetry, "finder_pattern_score": finder}
            }
        except Exception as e:
            return {"status": "error", "message": str(e), "is_masked": True, 
                   "risk_score": 100, "risk_level": "High"}
    
    def _analyze_image_quality(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        score = min(100, (cv2.Laplacian(gray, cv2.CV_64F).var() / 500) * 100)
        return 40 if score < 50 else (60 if score < 70 else 85)
    
    def _analyze_qr_structure(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray, 50, 150)
        contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        squares = sum(1 for c in contours if len(cv2.approxPolyDP(c, 0.02*cv2.arcLength(c, True), True)) >= 4 
                     and cv2.contourArea(c) > 100)
        return min(100, (squares / max(1, len(contours))) * 100) if contours else 0
    
    def _analyze_noise_patterns(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        noise = np.sum(cv2.absdiff(gray, cv2.medianBlur(gray, 5)) > 30) / (gray.shape[0] * gray.shape[1]) * 100
        return 20 if noise > 15 else (40 if noise > 8 else 80)
    
    def _analyze_qr_symmetry(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        contours, _ = cv2.findContours(cv2.Canny(gray, 50, 150), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours: return 30
        x, y, w, h = cv2.boundingRect(max(contours, key=cv2.contourArea))
        qr = gray[y:y+h, x:x+w]
        if qr.size == 0: return 30
        h_mid, w_mid = qr.shape[0] // 2, qr.shape[1] // 2
        tl, tr = qr[0:h_mid, 0:w_mid], qr[0:h_mid, w_mid:2*w_mid]
        bl, br = qr[h_mid:2*h_mid, 0:w_mid], qr[h_mid:2*h_mid, w_mid:2*w_mid]
        def comp(a, b): return 0 if a.size == 0 or b.size == 0 else 100 - np.mean(cv2.absdiff(a, b)) * 100 / 255
        return np.mean([comp(tl, tr), comp(tl, bl), comp(bl, br)])
    
    def _analyze_finder_patterns(self, img):
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        tmpl = np.array([[0,0,0,0,0],[0,255,255,255,0],[0,255,0,255,0],[0,255,255,255,0],[0,0,0,0,0]], dtype=np.uint8)
        matches = [cv2.matchTemplate(gray, cv2.resize(tmpl, (int(5*s), int(5*s))), cv2.TM_CCOEFF_NORMED).max() 
                   for s in [0.8, 1.0, 1.2]]
        avg = np.mean(matches)
        return 85 if avg > 0.7 else (60 if avg > 0.5 else 30)
    
    def _calculate_risk(self, q, s, n, sy, f):
        return min(100, (100-q)*0.25 + (100-s)*0.20 + (100-n)*0.20 + (100-sy)*0.20 + (100-f)*0.15)
    
    def _decode_qr_content(self, image_path):
        try:
            img = cv2.imread(image_path)
            detector = cv2.QRCodeDetector()
            
            for method in [
                lambda: detector.detectAndDecode(img),
                lambda: detector.detectAndDecode(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)),
                lambda: detector.detectAndDecode(cv2.equalizeHist(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)))
            ]:
                data, _, _ = method()
                if data: return data
            
            for gamma in [0.5, 1.5, 2.0]:
                table = np.array([((i/255.0)**(1/gamma))*255 for i in range(256)]).astype("uint8")
                data, _, _ = detector.detectAndDecode(cv2.LUT(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), table))
                if data: return data
            
            for thresh in [cv2.adaptiveThreshold(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), 255, 
                        cv2.ADAPTIVE_THRESH_MEAN_C, cv2.THRESH_BINARY, 11, 2),
                        cv2.threshold(cv2.cvtColor(img, cv2.COLOR_BGR2GRAY), 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]]:
                data, _, _ = detector.detectAndDecode(thresh)
                if data: return data
            
            if PYZBAR_AVAILABLE:
                for im in [Image.open(image_path)] + [Image.open(image_path).convert(m) for m in ['L', 'RGB']]:
                    for obj in decode_qr(im):
                        d = obj.data.decode('utf-8', errors='ignore')
                        if d: return d
            
            try:
                with open(image_path, 'rb') as f:
                    r = requests.post("https://api.qrserver.com/v1/read-qr-code/", files={'file': f}, timeout=10)
                    if r.status_code == 200:
                        d = r.json()
                        if d and isinstance(d, list) and d[0].get('symbol'):
                            return d[0]['symbol'][0].get('data', '')
            except: pass
            
            return None
        except:
            return None


def analyze_qr_content(content):
    """Analyze QR content type (URL, UPI, or text)"""
    try:
        from Tools.upi import VerifyUPI, CheckInvalidUPIPattern
    except:
        from upi import VerifyUPI, CheckInvalidUPIPattern
    
    try:
        from Tools.url_analysis import analyze_url_realtime
    except:
        from url_analysis import analyze_url_realtime
    
    if not content:
        return None
    
    result = {"content": content, "type": None, "details": None}
    c = content.strip()
    
    if c.startswith('upi://'):
        try:
            p = parse_qs(urlparse(c).query)
            if 'pa' in p and p['pa']:
                uid = p['pa'][0]
                inv = CheckInvalidUPIPattern(uid)
                if not inv["is_valid"]:
                    result["type"] = "upi"
                    result["details"] = {"status": "Invalid", "upiid": uid, "riskscore": 100, "risklevel": "High"}
                    return result
                result["type"] = "upi"
                result["details"] = VerifyUPI(uid)
                return result
        except: pass
    
    if '@' in c:
        inv = CheckInvalidUPIPattern(c) if 'CheckInvalidUPIPattern' in dir() else {"is_valid": True}
        if not inv["is_valid"]:
            result["type"] = "upi"
            result["details"] = {"status": "Invalid", "upiid": c, "riskscore": 100, "risklevel": "High"}
            return result
        if re.match(r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$', c):
            result["type"] = "upi"
            result["details"] = VerifyUPI(c)
            return result
    
    if any(c.startswith(p) for p in ['http://', 'https://', 'ftp://', 'www.', 'WWW.']) or ('.' in c and ' ' not in c):
        url = c if not c.lower().startswith('www.') else 'https://' + c
        result["type"] = "url"
        result["details"] = analyze_url_realtime(url)
        return result
    
    result["type"] = "text"
    return result


def analyze_qr_tampering(image_path, progress_callback=None):
    """Analyze QR code for tampering"""
    return QRAnalyzer().analyze_qr_image(image_path, progress_callback)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        r = analyze_qr_tampering(sys.argv[1])
        print(f"Status: {r['status']}, Risk: {r['risk_score']}/100, Masked: {r['is_masked']}")
    else:
        print("Usage: python qrcode.py <image_path>")

