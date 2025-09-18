import hmac, random
from datetime import timedelta
from django.utils import timezone

OTP_PHONE_SESSION_KEY = "otp_phone"
OTP_TTL = timedelta(minutes=5)         # Kod 5 dk geçerli
OTP_COOLDOWN_SEC = 5                 # 5 sn'de 1 gönderim
OTP_MAX_SEND = 100                      # Toplam 100 gönderim
OTP_MAX_VERIFY_FAIL = 100               # En fazla 100 yanlış deneme

def gen_code(n=6):
    # 0-9 arası gerçek 6 haneli kod
    return ''.join(str(random.randint(0, 9)) for _ in range(n))

def now_iso():
    return timezone.now().isoformat()

def normalize_phone(phone: str) -> str:
    p = (phone or "").strip()
    for ch in " ()-+":
        p = p.replace(ch, "")
    # Örn: 05xx... -> 5xx... (senin backend beklentine göre)
    if p.startswith("0") and len(p) >= 10:
        p = p[1:]
    return p

def is_expired(ts_iso: str) -> bool:
    try:
        ts = timezone.datetime.fromisoformat(ts_iso)
        if timezone.is_naive(ts):
            ts = timezone.make_aware(ts, timezone.get_current_timezone())
    except Exception:
        return True
    return timezone.now() - ts > OTP_TTL

def seconds_since(ts_iso: str) -> int:
    try:
        ts = timezone.datetime.fromisoformat(ts_iso)
        if timezone.is_naive(ts):
            ts = timezone.make_aware(ts, timezone.get_current_timezone())
        return int((timezone.now() - ts).total_seconds())
    except Exception:
        return 999999