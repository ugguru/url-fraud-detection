import os
import time
import base64
import requests

VT_API_KEY = "816e2563c2555dede7785b21639d82b6a5a474bdd59f008a78698887093481ff"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": VT_API_KEY,
    "accept": "application/json"
}


def submit_url(url):
    """
    Step 1: Submit URL for scanning
    """
    response = requests.post(
        f"{VT_BASE_URL}/urls",
        headers=HEADERS,
        data={"url": url}
    )

    if response.status_code != 200:
        raise RuntimeError(f"Submit failed: {response.text}")

    return response.json()["data"]["id"]


def get_analysis(analysis_id):
    """
    Step 2: Get scan report
    """
    response = requests.get(
        f"{VT_BASE_URL}/analyses/{analysis_id}",
        headers=HEADERS
    )

    if response.status_code != 200:
        raise RuntimeError(f"Analysis fetch failed: {response.text}")

    return response.json()


def check_url_virustotal(url):
    analysis_id = submit_url(url)

    # Free API needs delay
    time.sleep(15)

    result = get_analysis(analysis_id)
    stats = result["data"]["attributes"]["stats"]

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    verdict = "SAFE"
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"

    return {
        "url": url,
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected
    }


if __name__ == "__main__":
    test_url = "http://testsafebrowsing.appspot.com/s/phishing.html"
    report = check_url_virustotal(test_url)

    print("\nVirusTotal URL Scan Result")
    print("-" * 30)
    for k, v in report.items():
        print(f"{k}: {v}")
