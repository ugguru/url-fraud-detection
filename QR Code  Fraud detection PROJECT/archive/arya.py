

import requests
import base64
import uuid

# Arya.ai API details
API_URL = "https://ping.arya.ai/api/v1/qr-mask"
API_TOKEN = '9c7cfe99f4626f93a925e6b11b87ad4c'

def image_to_base64(image_path):
    """Convert QR image to base64"""
    with open(image_path, "rb") as img:
        return base64.b64encode(img.read()).decode("utf-8")

def check_qr_masking(image_path):
    base64_image = image_to_base64(image_path)

    payload = {
        "doc_base64": base64_image,
        "req_id": str(uuid.uuid4())  # unique request id
    }

    headers = {
        "token": API_TOKEN,
        "content-type": "application/json"
    }

    response = requests.post(
        API_URL,
        json=payload,
        headers=headers,
        timeout=30
    )

    if response.status_code != 200:
        return {
            "status": "error",
            "message": response.text
        }

    return response.json()


if __name__ == "__main__":
    qr_image_path = "/Users/macbook/Desktop/QR Code  Fraud detection PROJECT/Tools/image/QRCode.png"  # QR image file
    result = check_qr_masking(qr_image_path)

    print("\nArya.ai QR Mask Detection Result")
    print("-" * 40)
    print(result)
