# utils/otp.py
import hmac, random, time
from datetime import timedelta
from django.utils import timezone

OTP_EMAIL_SESSION_KEY = "otp_email"
OTP_TTL = timedelta(minutes=5)        # 5 dk geçerlilik
OTP_COOLDOWN_SEC = 5                # 5 sn'de 1 gönderim
OTP_MAX_SEND = 100                     # toplam 100 gönderim
OTP_MAX_VERIFY_FAIL = 100              # max 100 hatalı deneme

def gen_code(n=6):
    # 0-9 aralığında gerçek 6 haneli kod
    return ''.join(str(random.randint(0, 9)) for _ in range(n))

def now_iso():
    return timezone.now().isoformat()

def normalize_email(email: str) -> str:
    return (email or "").strip().lower()

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

def clear_email_session(request):
    if OTP_EMAIL_SESSION_KEY in request.session:
        del request.session[OTP_EMAIL_SESSION_KEY]
        request.session.modified = True
