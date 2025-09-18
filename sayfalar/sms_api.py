# utils/sms.py
import requests
from django.conf import settings

SEVEN_IO_BASE_URL = getattr(settings, "SEVEN_IO_BASE_URL", "https://gateway.seven.io/api/sms")
SEVEN_IO_API_KEY = getattr(settings, "SEVEN_IO_API_KEY", None)  # settings.py'ye koy: SEVEN_IO_API_KEY="..."

def send_sms(to: str, text: str, sender: str = None):
    """
    seven.io SMS gönderimi. Prod'da SEVEN_IO_API_KEY'i settings'e koy.
    """
    if not SEVEN_IO_API_KEY:
        raise RuntimeError("SEVEN_IO_API_KEY tanımlı değil")

    headers = {
        "X-Api-Key": SEVEN_IO_API_KEY,
        "Accept": "application/json",
    }
    data = { "to": to, "text": text }
    if sender:
        data["from"] = sender

    r = requests.post(SEVEN_IO_BASE_URL, headers=headers, data=data, timeout=15)
    r.raise_for_status()
    return r.json()
