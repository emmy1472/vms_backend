# utils/sms.py
import requests # type: ignore
from django.conf import settings

def send_sms(recipient, message, sender="NETCO"):
    url = "https://api.brevo.com/v3/transactionalSMS/sms"
    headers = {
        "accept": "application/json",
        "api-key": settings.BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": sender,
        "recipient": recipient,
        "content": message
    }
    response = requests.post(url, json=payload, headers=headers)
    return response.json()
