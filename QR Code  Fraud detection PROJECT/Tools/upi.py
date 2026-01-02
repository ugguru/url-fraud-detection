import re

def VerifyUPI(upiId):
    # UPI ID format: username@bank
    pattern = r'^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$'
    MIN_SCORE = 5
    MAX_SCORE = 25
    bank= {
        "sbi":        {"bank": "State Bank of India", "risk": 5},
        "hdfc":       {"bank": "HDFC Bank", "risk": 5},
        "icici":      {"bank": "ICICI Bank", "risk": 5},
        "axisbank":   {"bank": "Axis Bank", "risk": 5},
        "barodampay": {"bank": "Bank of Baroda", "risk": 5},
        "pnb":        {"bank": "Punjab National Bank", "risk": 5},
        "cnrb":       {"bank": "Canara Bank", "risk": 5},
        "kotak":      {"bank": "Kotak Mahindra Bank", "risk": 5},
        "kotak811":   {"bank": "Kotak Mahindra Bank (811)", "risk": 5},
        "centralbank":{"bank": "Central Bank of India", "risk": 5},
        "federal":    {"bank": "Federal Bank", "risk": 5},

        "upi":        {"bank": "BHIM (NPCI)", "risk": 15},
        "ybl":        {"bank": "PhonePe – Yes Bank", "risk": 15},
        "ibl":        {"bank": "PhonePe – ICICI Bank", "risk": 15},
        "axl":        {"bank": "PhonePe – Axis Bank", "risk": 15},
        "okhdfcbank": {"bank": "Google Pay – HDFC Bank", "risk": 10},
        "okicici":    {"bank": "Google Pay – ICICI Bank", "risk": 10},
        "oksbi":      {"bank": "Google Pay – SBI", "risk": 10},
        "okaxis":     {"bank": "Google Pay – Axis Bank", "risk": 10},
        "yes":        {"bank": "Yes Bank", "risk": 15},
        "yesbank":    {"bank": "Yes Bank", "risk": 15},

        "apl":        {"bank": "Amazon Pay", "risk": 12},
        "yapl":       {"bank": "Amazon Pay – Yes Bank", "risk": 12},
        "rapl":       {"bank": "Amazon Pay – ICICI Bank", "risk": 12},

        "paytm":      {"bank": "Paytm Payments Bank", "risk": 25},
        "ptyes":      {"bank": "Paytm – Yes Bank", "risk": 25},
        "ptaxis":     {"bank": "Paytm – Axis Bank", "risk": 25},
        "ptsbi":      {"bank": "Paytm – SBI", "risk": 25},
        "pthdfc":     {"bank": "Paytm – HDFC Bank", "risk": 25},
        "airtel":     {"bank": "Airtel Payments Bank", "risk": 25}
    }

    if re.match(pattern, upiId):
        if '@' in upiId:
            riskscore=0
            risk_level="Unknown"
            # Split the ID at the '@' symbol and get the part after it (the suffix)
            suffix = upiId.split('@')[-1].lower()
            if suffix in bank:
                # Look up the suffix in our map
                bank_name = bank.get(suffix, f"Unknown Bank or App (suffix: '{suffix}')")
                riskscore+=bank[suffix]["risk"] 
                normalized = int(
                    ((riskscore - MIN_SCORE) / (MAX_SCORE - MIN_SCORE)) * 100
                )


                if riskscore==0:
                    riskscore=25
                    print(riskscore)
                    risk_level="High"
                elif riskscore<=10:
                    risk_level="Low"
                elif riskscore<=20:
                    risk_level="Medium"
                elif riskscore>20:
                    risk_level="High"
                    

                return {
                    "status":'Success',
                    "upiid": upiId,
                    "bank": bank_name["bank"],
                    "riskscore": normalized,
                    "risklevel": risk_level
                }
            else:
                return {
                    "status":'Fail',
                    "upiid": upiId,
                    "bank": 'Unknown Bank or App',
                    "riskscore": int(((25 - MIN_SCORE) / (MAX_SCORE - MIN_SCORE)) * 100),
                    "risklevel": 'High'
                }


def CheckInvalidUPIPattern(upiId):
    """
    Check for invalid UPI ID patterns that indicate potential fraud.
    Returns a dictionary with validation result and error details.
    """
    result = {
        "is_valid": True,
        "error_type": None,
        "error_message": None,
        "upiid": upiId
    }
    
    if not upiId:
        result["is_valid"] = True
        return result
    
    # Check for multiple @ symbols (fraud indicator)
    # Example: "gururock9159@oksbi@oksbi" - this is suspicious
    at_count = upiId.count('@')
    if at_count > 1:
        result["is_valid"] = False
        result["error_type"] = "MULTIPLE_AT_SYMBOLS"
        result["error_message"] = f"Invalid UPI ID - Contains {at_count} @ symbols (suspicious pattern detected)"
        return result
    
    # Check if it looks like a UPI-like pattern (has @ but invalid format)
    if '@' in upiId:
        # Check if the prefix (before @) is too short or too long
        parts = upiId.split('@')
        prefix = parts[0] if parts else ""
        
        if len(prefix) < 2:
            result["is_valid"] = False
            result["error_type"] = "INVALID_PREFIX"
            result["error_message"] = "Invalid UPI ID - Username part too short (less than 2 characters)"
            return result
        
        if len(prefix) > 256:
            result["is_valid"] = False
            result["error_type"] = "INVALID_PREFIX"
            result["error_message"] = "Invalid UPI ID - Username part too long (more than 256 characters)"
            return result
        
        # Check suffix (after @) for valid bank/app code
        if len(parts) > 1:
            suffix = parts[-1].lower()
            if len(suffix) < 2:
                result["is_valid"] = False
                result["error_type"] = "INVALID_SUFFIX"
                result["error_message"] = "Invalid UPI ID - Bank/App code too short (less than 2 characters)"
                return result
            if len(suffix) > 64:
                result["is_valid"] = False
                result["error_type"] = "INVALID_SUFFIX"
                result["error_message"] = "Invalid UPI ID - Bank/App code too long (more than 64 characters)"
                return result
            
            # Check for invalid characters in suffix
            if not re.match(r'^[a-zA-Z0-9]+$', suffix):
                result["is_valid"] = False
                result["error_type"] = "INVALID_SUFFIX"
                result["error_message"] = "Invalid UPI ID - Bank/App code contains invalid characters"
                return result
    
    return result
