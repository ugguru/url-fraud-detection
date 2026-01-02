"""
Debug script to test QR code decoding
Run this to diagnose issues with URL QR codes
"""

import sys
import os
import cv2
from PIL import Image

# Add the project directory to the path
sys.path.insert(0, '/Users/macbook/Desktop/QR Code  Fraud detection PROJECT')

from Tools.qr_analysis import QRAnalyzer
from Tools.qr_api import QRCodeAPIs

def test_qr_decoding(image_path):
    """Test various QR code decoding methods"""
    print(f"\n{'='*60}")
    print(f"Testing QR code decoding for: {image_path}")
    print(f"{'='*60}")
    
    # Check if file exists
    if not os.path.exists(image_path):
        print(f"❌ Error: File not found: {image_path}")
        return
    
    # Display image info
    try:
        img = Image.open(image_path)
        print(f"📷 Image format: {img.format}")
        print(f"📷 Image size: {img.size}")
        print(f"📷 Image mode: {img.mode}")
    except Exception as e:
        print(f"Error reading image info: {e}")
    
    # Test 1: OpenCV QR Code detector
    print("\n--- Test 1: OpenCV QR Code Detector ---")
    try:
        cv_img = cv2.imread(image_path)
        if cv_img is not None:
            detector = cv2.QRCodeDetector()
            data, vertices, binary_qrcode = detector.detectAndDecode(cv_img)
            if data and len(data) > 0:
                print(f"✅ OpenCV decoded: {data}")
            else:
                print("❌ OpenCV failed to decode")
        else:
            print("❌ Could not read image with OpenCV")
    except Exception as e:
        print(f"❌ OpenCV error: {e}")
    
    # Test 2: OpenCV with grayscale
    print("\n--- Test 2: OpenCV with Grayscale ---")
    try:
        cv_img = cv2.imread(image_path)
        if cv_img is not None:
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            detector = cv2.QRCodeDetector()
            data, vertices, binary_qrcode = detector.detectAndDecode(gray)
            if data and len(data) > 0:
                print(f"✅ OpenCV (grayscale) decoded: {data}")
            else:
                print("❌ OpenCV (grayscale) failed to decode")
    except Exception as e:
        print(f"❌ OpenCV grayscale error: {e}")
    
    # Test 3: pyzbar
    print("\n--- Test 3: pyzbar ---")
    try:
        from pyzbar.pyzbar import decode as decode_qr
        img_pil = Image.open(image_path)
        decoded_objects = decode_qr(img_pil)
        if decoded_objects:
            for obj in decoded_objects:
                decoded_data = obj.data.decode('utf-8', errors='ignore')
                print(f"✅ pyzbar decoded: {decoded_data}")
        else:
            print("❌ pyzbar failed to decode")
    except ImportError:
        print("⚠️ pyzbar not installed")
    except Exception as e:
        print(f"❌ pyzbar error: {e}")
    
    # Test 4: GoQR.me API
    print("\n--- Test 4: GoQR.me API ---")
    try:
        api = QRCodeAPIs(timeout=10)
        result = api.decode_with_goqr_me(image_path)
        if result:
            print(f"✅ GoQR.me decoded: {result}")
        else:
            print("❌ GoQR.me failed to decode")
    except Exception as e:
        print(f"❌ GoQR.me error: {e}")
    
    # Test 5: Full analyzer
    print("\n--- Test 5: Full QR Analyzer ---")
    try:
        analyzer = QRAnalyzer()
        result = analyzer.analyze_qr_image(image_path)
        print(f"Status: {result.get('status')}")
        print(f"Decoded data: {result.get('decoded_data')}")
        print(f"Risk score: {result.get('risk_score')}")
        
        if result.get('decoded_data'):
            print(f"\n✅ Successfully decoded: {result['decoded_data']}")
        else:
            print("\n❌ Failed to decode with full analyzer")
    except Exception as e:
        print(f"❌ Full analyzer error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Test with sample images
    test_images = [
        "test_qr.png",
        "test_upi_qr.png",
        "Tools/image/QRCode.png",
        "Tools/image/url.png"
    ]
    
    for img in test_images:
        if os.path.exists(img):
            test_qr_decoding(img)
            print("\n")
        else:
            print(f"File not found: {img}")
    
    # Also allow command line argument
    if len(sys.argv) > 1:
        test_qr_decoding(sys.argv[1])

