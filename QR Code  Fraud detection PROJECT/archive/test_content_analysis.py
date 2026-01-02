"""
Test content analysis for URL and UPI QR codes
"""

import sys
sys.path.insert(0, '/Users/macbook/Desktop/QR Code  Fraud detection PROJECT')

from Tools.url_analysis import analyze_url_realtime
from Tools.upi import VerifyUPI

# Test URL content analysis
print("="*60)
print("Testing URL Content Analysis")
print("="*60)

test_urls = [
    "https://example.com",
    "http://192.168.1.1:8080/login.php",
    "www.google.com",
    "ftp://files.example.com",
]

for url in test_urls:
    print(f"\nURL: {url}")
    print("-" * 40)
    result = analyze_url_realtime(url)
    print(f"Status: {result.get('status')}")
    print(f"Risk Score: {result.get('risk_score')}")
    print(f"Risk Level: {result.get('risk_level')}")
    print(f"Recommendation: {result.get('recommendation')}")
    print(f"Warnings: {result.get('warnings', [])}")

# Test UPI content analysis
print("\n" + "="*60)
print("Testing UPI Content Analysis")
print("="*60)

test_upis = [
    "merchant@upi",
    "gururock9159@oksbi",
]

for upi in test_upis:
    print(f"\nUPI ID: {upi}")
    print("-" * 40)
    result = VerifyUPI(upi)
    print(f"Status: {result.get('status')}")
    print(f"UPI ID: {result.get('upiid')}")
    print(f"Bank: {result.get('bank')}")
    print(f"Risk Score: {result.get('riskscore')}")
    print(f"Risk Level: {result.get('risklevel')}")

# Test the analyze_content function from app.py
print("\n" + "="*60)
print("Testing analyze_content function from app.py")
print("="*60)

from urllib.parse import urlparse, parse_qs
import re

def analyze_content(decoded_content):
    """Analyze decoded content - copied from app.py"""
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

test_contents = [
    "https://example.com",
    "http://192.168.1.1:8080/login.php",
    "upi://pay?pa=merchant@upi&pn=Merchant&am=100&cu=INR",
    "gururock9159@oksbi",
    "plain text",
    "notaurlorupi",
]

for content in test_contents:
    print(f"\nContent: {content}")
    print("-" * 40)
    result = analyze_content(content)
    if result:
        print(f"Type: {result.get('type')}")
        print(f"Content: {result.get('content')}")
        if result.get('details'):
            print(f"Details: {result['details']}")
    else:
        print("Failed to analyze content")

