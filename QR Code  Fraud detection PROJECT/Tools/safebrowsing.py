import requests

API_KEY = "AIzaSyDDjlKlVo9fBujiOKkcjqwwXBZtUHZvZ3M"
API_ENDPOINT = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_url_malicious(url_to_check):
    request_body = {
        "client": {
            "clientId": "url-fraud-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url_to_check}
            ]
        }
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(API_ENDPOINT, headers=headers, json=request_body)

    if response.status_code != 200:
        return {
            "status": "error",
            "message": response.text
        }

    data = response.json()

    if "matches" in data:
        return {
            "status": "malicious",
            "details": data["matches"]
        }
    else:
        return {
            "status": "safe",
            "message": "No threats found"
        }


# Example usage
if __name__ == "__main__":
    url = "http://http://221.142.48.141:5399/.i"
    result = check_url_malicious(url)
    print(result)
