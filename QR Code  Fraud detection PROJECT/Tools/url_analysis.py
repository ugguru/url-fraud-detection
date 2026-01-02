"""
Real-time URL Analysis Tool for Phishing and Malicious Website Detection
Analyzes URL structure and characteristics to identify potential phishing attempts
Enhanced with URL expansion for shortened URLs
"""

import re
from urllib.parse import urlparse
import socket
from datetime import datetime
import requests


class URLAnalyzer:
    """Real-time URL analysis for phishing and malicious website detection"""
    
    def __init__(self):
        # Suspicious TLDs often used in phishing
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
            '.click', '.review', '.country', '.kim', '.science', '.cricket',
            '.date', '.faith', '.accountant', '.loan', '.win', '.download',
            '.pw', '.cc', '.su', '.ws', '.stream', '.review', '.country'
        }
        
        # Known URL shorteners - comprehensive list
        self.url_shorteners = {
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'j.mp', 'tr.im', 'cli.gs', 'short.to',
            'budurl.com', 'ping.fm', 'post.ly', 'just.as', 'bkite.com',
            'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie',
            'kl.am', 'wp.me', 'rubyurl.com', 'om.ly', 'to.ly', 'bit.do',
            'lnkd.in', 'db.tt', 'qr.ae', 'cur.lv', 'ity.im', 'q.gs',
            'po.st', 'bc.vc', 'twitthis.com', 'u.telecom', 'yourls.org',
            'v.gd', 'rb.gy', 'shorturl.at', 'qrco.de', 'cutt.ly', 'bitly.com',
            'tiny.cc', 'shorte.st', 'linktr.ee', 't.ly', 'zaplink.net',
            'mcaf.ee', 'shorturl.支', 'is.gd', 'clck.ru', 'git.io', 'shorturl.io'
        }
        
        # Phishing keywords commonly found in malicious URLs
        self.phishing_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update',
            'confirm', 'password', 'credential', 'banking', 'paypal',
            'ebay', 'amazon', 'apple', 'microsoft', 'google', 'netflix',
            'support', 'service', 'help', 'confirm', 'wallet', 'crypto',
            'bitcoin', 'eth', 'free', 'gift', 'winner', 'lucky', 'claim',
            'verifyyour', 'securelogin', 'accountverify', 'updateinfo',
            'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'sbi',
            'hdfc', 'icici', 'axisbank', 'okxd', 'upi', 'paytm'
        ]
        
        # Suspicious patterns in URLs
        self.suspicious_patterns = [
            r'@',                           # @ symbol redirect
            r'\-\-',                        # Double hyphen
            r'\.\.',                        # Directory traversal
            r'%[0-9a-fA-F]{2}',             # URL encoding (possible obfuscation)
            r'\.php',                       # PHP endpoints (often phishing)
            r'\.asp',                       # ASP endpoints
            r'\.jsp',                       # JSP endpoints
            r'admin',                       # Admin paths
            r'login',                       # Login paths
            r'secure',                      # Secure paths
            r'account',                     # Account paths
            r'verify',                      # Verify paths
            r'update',                      # Update paths
            r'confirm',                     # Confirm paths
            r'auth',                        # Auth paths
            r'credential',                  # Credential paths
        ]
    
    def expand_url(self, url, timeout=10):
        """
        Expand shortened URL by following redirects
        Returns the final URL after all redirects
        """
        try:
            # Use GET request with redirects to get final URL
            response = requests.get(url, allow_redirects=True, timeout=timeout)
            return response.url
        except requests.exceptions.Timeout:
            return {"error": "timeout", "message": "URL expansion timed out"}
        except requests.exceptions.ConnectionError:
            return {"error": "connection", "message": "Could not connect to URL"}
        except requests.exceptions.RequestException as e:
            return {"error": "request", "message": str(e)}
        except Exception as e:
            return {"error": "unknown", "message": str(e)}
    
    def is_shortened_url(self, url):
        """Check if URL is from a known shortener"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check exact domain match
        if domain in self.url_shorteners:
            return True
        
        # Check for subdomain of known shorteners
        for shortener in self.url_shorteners:
            if domain.endswith('.' + shortener) or domain == shortener:
                return True
        
        return False
    
    def analyze_url(self, url, expand_shortened=True):
        """
        Comprehensive URL analysis for phishing indicators
        Returns: Dictionary with analysis results
        
        Args:
            url: The URL to analyze
            expand_shortened: Whether to expand shortened URLs (default: True)
        """
        result = {
            "status": "success",
            "url": url,
            "is_shortened": False,
            "expanded_url": None,
            "expanded_analysis": None,
            "is_valid": False,
            "risk_score": 0,
            "risk_level": "Unknown",
            "checks": {},
            "warnings": [],
            "recommendation": ""
        }
        
        # Check if URL is valid format
        if not self._is_valid_url(url):
            result["status"] = "error"
            result["message"] = "Invalid URL format"
            result["risk_score"] = 100
            result["risk_level"] = "High"
            result["recommendation"] = "Do not visit this URL"
            return result
        
        result["is_valid"] = True
        
        # Check if URL is shortened
        if self.is_shortened_url(url):
            result["is_shortened"] = True
            
            # Expand the URL if requested
            if expand_shortened:
                expansion_result = self.expand_url(url)
                
                if isinstance(expansion_result, dict) and "error" in expansion_result:
                    # Expansion failed - still flag as suspicious
                    result["expanded_url"] = None
                    result["warnings"].append(f"URL shortener detected - could not expand: {expansion_result.get('message', 'Unknown error')}")
                else:
                    result["expanded_url"] = expansion_result
                    
                    # Analyze the expanded URL
                    if expansion_result and self._is_valid_url(expansion_result):
                        expanded_analysis = self._analyze_full(expansion_result)
                        result["expanded_analysis"] = expanded_analysis
        
        # Run all checks on the original URL
        result["checks"] = {
            "structure_analysis": self._analyze_structure(url),
            "domain_analysis": self._analyze_domain(url),
            "tld_analysis": self._analyze_tld(url),
            "shortener_check": self._check_url_shortener(url),
            "phishing_keywords": self._check_phishing_keywords(url),
            "suspicious_patterns": self._check_suspicious_patterns(url),
            "https_check": self._check_https(url),
            "url_length_check": self._check_url_length(url),
            "subdomain_check": self._check_subdomains(url),
            "ip_address_check": self._check_ip_address(url)
        }
        
        # Calculate overall risk score
        base_risk_score = self._calculate_overall_risk(result["checks"])
        
        # Calculate expanded URL risk if available
        expanded_risk = 0
        if result.get("expanded_analysis") and isinstance(result["expanded_analysis"], dict):
            expanded_risk = result["expanded_analysis"].get("risk_score", 0)
            result["warnings"].extend(result["expanded_analysis"].get("warnings", []))
        
        # Calculate final risk score with penalties for shortened URLs
        if result["is_shortened"]:
            # High penalty for shortened URLs (40 points base)
            shortener_penalty = 40
            
            # Take the maximum of original and expanded risk, plus shortener penalty
            # This ensures suspicious expanded URLs get high scores
            final_risk = max(base_risk_score, expanded_risk) + shortener_penalty
            
            # Cap at 100
            final_risk = min(100, final_risk)
            
            # If expanded URL is suspicious (risk > 50), boost the original risk
            if expanded_risk > 50:
                # Combine risks more aggressively when expanded URL is risky
                final_risk = max(final_risk, (base_risk_score + expanded_risk) // 2 + 35)
                final_risk = min(100, final_risk)
        else:
            final_risk = base_risk_score
        
        result["risk_score"] = final_risk
        result["risk_level"] = self._get_risk_level(final_risk)
        result["warnings"] = self._collect_warnings(result["checks"], result["is_shortened"], expanded_risk)
        result["recommendation"] = self._get_recommendation(final_risk, result["warnings"], result["is_shortened"])
        
        return result
    
    def _analyze_full(self, url):
        """Full analysis of a URL (used for expanded URLs)"""
        if not self._is_valid_url(url):
            return {"risk_score": 100, "risk_level": "High", "warnings": ["Invalid URL"]}
        
        checks = {
            "structure_analysis": self._analyze_structure(url),
            "domain_analysis": self._analyze_domain(url),
            "tld_analysis": self._analyze_tld(url),
            "shortener_check": self._check_url_shortener(url),
            "phishing_keywords": self._check_phishing_keywords(url),
            "suspicious_patterns": self._check_suspicious_patterns(url),
            "https_check": self._check_https(url),
            "url_length_check": self._check_url_length(url),
            "subdomain_check": self._check_subdomains(url),
            "ip_address_check": self._check_ip_address(url)
        }
        
        risk_score = self._calculate_overall_risk(checks)
        risk_level = self._get_risk_level(risk_score)
        warnings = self._collect_warnings(checks, False, 0)
        recommendation = self._get_recommendation(risk_score, warnings, False)
        
        return {
            "url": url,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "checks": checks,
            "warnings": warnings,
            "recommendation": recommendation
        }
    
    def _is_valid_url(self, url):
        """Check if URL has valid structure"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _analyze_structure(self, url):
        """Analyze URL structure for suspicious elements"""
        score = 0
        details = []
        
        # Check for username:password pattern (often phishing)
        if '@' in url:
            score += 40
            details.append("Contains '@' symbol (potential redirect)")
        
        # Check for unusual port
        parsed = urlparse(url)
        if parsed.port and parsed.port not in [80, 443]:
            score += 20
            details.append(f"Non-standard port: {parsed.port}")
        
        # Check for IP address in hostname
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, parsed.netloc):
            score += 35
            details.append("Uses IP address instead of domain name")
        
        return {
            "score": score,
            "details": details,
            "is_suspicious": score > 0
        }
    
    def _analyze_domain(self, url):
        """Analyze domain characteristics"""
        parsed = urlparse(url)
        domain = parsed.netloc
        score = 0
        details = []
        
        # Check for hyphenated domain (common in phishing)
        if '-' in domain:
            score += 15
            details.append("Domain contains hyphens")
        
        # Check for numbers in domain (often phishing)
        if any(c.isdigit() for c in domain):
            score += 20
            details.append("Domain contains numbers")
        
        # Check for very long domain
        if len(domain) > 30:
            score += 15
            details.append("Unusually long domain name")
        
        # Check for multiple dots
        if domain.count('.') > 2:
            score += 15
            details.append("Multiple subdomains")
        
        # Check for lookalike domains (common phishing technique)
        known_brands = ['google', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay', 'facebook', 'instagram', 'twitter', 'netflix', 'whatsapp', 'telegram']
        domain_lower = domain.lower()
        for brand in known_brands:
            if brand in domain_lower and domain_lower != f'www.{brand}.com' and domain_lower != f'{brand}.com':
                score += 25
                details.append(f"Possible lookalike domain for {brand}")
                break
        
        return {
            "score": score,
            "details": details,
            "is_suspicious": score > 0
        }
    
    def _analyze_tld(self, url):
        """Analyze Top-Level Domain"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Extract TLD
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = '.' + parts[-1]
        else:
            tld = ''
        
        is_suspicious = tld.lower() in self.suspicious_tlds
        score = 35 if is_suspicious else 0
        
        return {
            "score": score,
            "tld": tld,
            "is_suspicious": is_suspicious
        }
    
    def _check_url_shortener(self, url):
        """Check if URL is from a known shortener"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        is_shortener = domain in self.url_shorteners
        
        return {
            "is_shortener": is_shortener,
            "score": 25 if is_shortener else 0,
            "warning": "URL shortener detected (masks original URL)" if is_shortener else None
        }
    
    def _check_phishing_keywords(self, url):
        """Check for phishing-related keywords in URL"""
        url_lower = url.lower()
        found_keywords = []
        
        for keyword in self.phishing_keywords:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        score = min(len(found_keywords) * 10, 50)
        
        return {
            "keywords_found": found_keywords,
            "score": score,
            "is_suspicious": len(found_keywords) > 0
        }
    
    def _check_suspicious_patterns(self, url):
        """Check for suspicious URL patterns"""
        found_patterns = []
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                found_patterns.append(pattern)
        
        score = len(found_patterns) * 15
        
        return {
            "patterns": found_patterns,
            "score": min(score, 50),
            "is_suspicious": len(found_patterns) > 0
        }
    
    def _check_https(self, url):
        """Check if URL uses HTTPS"""
        parsed = urlparse(url)
        
        is_https = parsed.scheme.lower() == 'https'
        
        return {
            "is_https": is_https,
            "warning": "URL does not use HTTPS" if not is_https else None
        }
    
    def _check_url_length(self, url):
        """Check URL length (very long URLs are suspicious)"""
        length = len(url)
        
        if length > 200:
            return {
                "length": length,
                "score": 25,
                "is_suspicious": True,
                "warning": "Unusually long URL"
            }
        elif length > 100:
            return {
                "length": length,
                "score": 10,
                "is_suspicious": True,
                "warning": "Long URL (possible obfuscation)"
            }
        
        return {
            "length": length,
            "score": 0,
            "is_suspicious": False
        }
    
    def _check_subdomains(self, url):
        """Check number of subdomains"""
        parsed = urlparse(url)
        domain = parsed.netloc
        
        subdomain_count = domain.count('.') - 1
        if subdomain_count < 0:
            subdomain_count = 0
        
        if subdomain_count > 3:
            return {
                "count": subdomain_count,
                "score": 20,
                "is_suspicious": True,
                "warning": "Multiple subdomains (possible phishing)"
            }
        
        return {
            "count": subdomain_count,
            "score": 0,
            "is_suspicious": False
        }
    
    def _check_ip_address(self, url):
        """Check if URL uses IP address"""
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        # Extract hostname without port
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Pattern for IPv4 address
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        is_ip = bool(re.match(ip_pattern, hostname))
        
        # Check for private IP addresses (more suspicious)
        is_private_ip = False
        if is_ip:
            # Check if it's a private IP range
            first_octet = int(hostname.split('.')[0])
            second_octet = int(hostname.split('.')[1]) if '.' in hostname else 0
            
            # Private IP ranges: 10.x.x.x, 192.168.x.x, 172.16-31.x.x
            if first_octet == 10 or (first_octet == 192 and second_octet == 168) or (first_octet == 172 and 16 <= second_octet <= 31):
                is_private_ip = True
        
        # Higher score for private IPs (very suspicious - often phishing)
        score = 0
        if is_ip:
            if is_private_ip:
                score = 50  # Private IP is more suspicious
            else:
                score = 35
        
        return {
            "is_ip_address": is_ip,
            "is_private_ip": is_private_ip,
            "score": score,
            "warning": "Uses private IP address (highly suspicious)" if is_private_ip else ("Uses IP address instead of domain" if is_ip else None)
        }
    
    def _calculate_overall_risk(self, checks):
        """Calculate overall risk score from all checks"""
        weights = {
            "structure_analysis": 0.15,
            "domain_analysis": 0.15,
            "tld_analysis": 0.10,
            "shortener_check": 0.10,
            "phishing_keywords": 0.20,
            "suspicious_patterns": 0.15,
            "https_check": 0.05,
            "url_length_check": 0.05,
            "subdomain_check": 0.03,
            "ip_address_check": 0.02
        }
        
        total_score = 0
        for check_name, weight in weights.items():
            if check_name in checks:
                check_result = checks[check_name]
                if isinstance(check_result, dict) and "score" in check_result:
                    total_score += check_result["score"] * weight
        
        base_score = min(100, int(total_score))
        
        # Check for high-risk combinations that warrant immediate elevation
        # Private IP + login = Critical
        ip_check = checks.get("ip_address_check", {})
        if isinstance(ip_check, dict) and ip_check.get("is_private_ip"):
            # Check for login-related paths
            pattern_check = checks.get("suspicious_patterns", {})
            if isinstance(pattern_check, dict) and pattern_check.get("score", 0) > 0:
                # Private IP with suspicious patterns = likely phishing
                # Boost the score significantly
                base_score = max(base_score, 65)
            
            # Even without patterns, private IP is suspicious
            base_score = max(base_score, 40)
        
        # HTTP + login = High risk
        https_check = checks.get("https_check", {})
        if isinstance(https_check, dict) and not https_check.get("is_https", True):
            pattern_check = checks.get("suspicious_patterns", {})
            if isinstance(pattern_check, dict) and pattern_check.get("score", 0) >= 15:
                base_score = max(base_score, 55)
        
        return min(100, base_score)
    
    def _get_risk_level(self, score):
        """Get risk level based on score"""
        if score <= 25:
            return "Low"
        elif score <= 50:
            return "Medium"
        elif score <= 75:
            return "High"
        else:
            return "Critical"
    
    def _collect_warnings(self, checks, is_shortened=False, expanded_risk=0):
        """Collect all warnings from checks"""
        warnings = []
        
        warning_mappings = {
            "structure_analysis": "Suspicious URL structure detected",
            "tld_analysis": "Suspicious domain extension",
            "shortener_check": "URL shortener masks original destination",
            "https_check": "Connection is not secure (no HTTPS)",
            "url_length_check": "Unusually long URL",
            "subdomain_check": "Abnormal number of subdomains",
            "ip_address_check": "Uses IP address instead of domain",
            "phishing_keywords": "Contains phishing-related keywords",
            "suspicious_patterns": "Contains suspicious URL patterns"
        }
        
        for check_name, mapping in warning_mappings.items():
            if check_name in checks:
                check_result = checks[check_name]
                if isinstance(check_result, dict):
                    if check_result.get("is_suspicious") or check_result.get("warning"):
                        warnings.append(mapping)
        
        # Add warning about shortened URL
        if is_shortened:
            warnings.append("URL uses a shortening service (true destination hidden)")
        
        # Add warning if expanded URL is risky
        if expanded_risk > 50:
            warnings.append(f"Expanded URL shows high risk ({expanded_risk}/100)")
        elif expanded_risk > 0 and expanded_risk <= 25:
            warnings.append(f"Expanded URL shows some risk ({expanded_risk}/100)")
        
        return warnings
    
    def _get_recommendation(self, score, warnings, is_shortened=False):
        """Get recommendation based on risk analysis"""
        if is_shortened:
            if score >= 80:
                return "🚨 CRITICAL RISK - URL shortener hides potentially malicious destination. DO NOT VISIT."
            elif score >= 60:
                return "🔴 HIGH RISK - Shortened URL leads to suspicious destination. Not recommended."
            elif score >= 40:
                return "🔶 MODERATE RISK - Exercise extreme caution with shortened URLs."
        
        if score <= 25:
            return "⚠️ Proceed with caution - URL appears relatively safe but always verify"
        elif score <= 50:
            return "🔶 Exercise caution - Some suspicious elements detected"
        elif score <= 75:
            return "🔴 High risk detected - Not recommended to visit this URL"
        else:
            return "🚨 CRITICAL RISK - Do not visit this URL under any circumstances"


def analyze_url_realtime(url, expand_shortened=True):
    """
    Main function to perform real-time URL analysis
    
    Args:
        url: The URL to analyze
        expand_shortened: Whether to expand shortened URLs (default: True)
    
    Returns:
        Dictionary with analysis results
    """
    analyzer = URLAnalyzer()
    return analyzer.analyze_url(url, expand_shortened=expand_shortened)


# Example usage
if __name__ == "__main__":
    # Test URLs including shortened ones
    test_urls = [
        "https://www.google.com",
        "http://221.142.48.141:5399/.i",
        "https://login-secure-amazon.com.account-verify.tk/login",
        "https://bit.ly/abc123",
        "https://paypal.com.verify-account.com",
        "http://192.168.1.1:8080/login.php",
        "https://qrco.de/bgXr2G",  # Test the specific URL
        "https://tinyurl.com/example"
    ]
    
    for url in test_urls:
        print(f"\n{'='*60}")
        print(f"Analyzing: {url}")
        print('='*60)
        
        result = analyze_url_realtime(url)
        
        print(f"Risk Score: {result['risk_score']}/100")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Recommendation: {result['recommendation']}")
        
        if result.get('is_shortened'):
            print(f"⚠️ Shortened URL detected!")
            if result.get('expanded_url'):
                print(f"   Expanded to: {result['expanded_url']}")
            if result.get('expanded_analysis'):
                print(f"   Expanded URL risk: {result['expanded_analysis']['risk_score']}/100")
        
        if result.get('warnings'):
            print(f"Warnings: {', '.join(result['warnings'])}")

