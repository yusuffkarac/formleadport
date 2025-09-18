from django.shortcuts import render, redirect, get_object_or_404
from django.urls import reverse
from django.http import Http404, HttpResponseForbidden, JsonResponse, HttpResponseBadRequest, HttpResponse
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string
from .models import MusteriFormModel, MusteriFormModelCocukYasi, MusteriFormModelPaylasim, Sehir, MusteriFormModelDurum, MusteriFormModelNot, SigortaSirket, SigortaAltSirket, EmailGonderimleri
from decimal import Decimal
from django.db.models import Q, Count, Subquery, Exists, OuterRef
import json, random, hmac, time, re
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from django.utils import timezone, translation
from django.utils.dateparse import parse_date, parse_datetime
from yonetim.models import Firma
from django.utils.timezone import localtime
from .models import Sehir, MusteriFormModel, MusteriFormModelCocukYasi
from datetime import datetime, date, time, timedelta, timezone as dt_timezone
from django.core.mail import EmailMultiAlternatives, get_connection
from yonetim.models import Smtp
from django.utils.html import strip_tags
from .sms_api import send_sms
from django.db import IntegrityError, transaction
from .utils.otp import OTP_EMAIL_SESSION_KEY, clear_email_session, normalize_email
from user.models import CustomUser
from django.utils.formats import date_format
import json
from urllib.parse import urljoin
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.http import require_POST, require_GET
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.shortcuts import get_object_or_404
from django.core.mail import get_connection, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.conf import settings
from .models import MusteriFormModel, EmailGonderimleri
from .utils.otp import (
    OTP_EMAIL_SESSION_KEY, OTP_TTL, OTP_COOLDOWN_SEC, OTP_MAX_SEND, OTP_MAX_VERIFY_FAIL,
    gen_code, normalize_email, is_expired, seconds_since, clear_email_session, now_iso
)
from .utils.otp_phone import (
    OTP_PHONE_SESSION_KEY, OTP_TTL, OTP_COOLDOWN_SEC, OTP_MAX_SEND, OTP_MAX_VERIFY_FAIL,
    gen_code, normalize_phone, is_expired, seconds_since, now_iso
)
# Create your views here.

def _day_range_local_to_utc(d: date):
    tz = timezone.get_current_timezone()
    start_local = datetime.combine(d, time.min)
    end_local   = datetime.combine(d + timedelta(days=1), time.min)
    start_aware = timezone.make_aware(start_local, tz)
    end_aware   = timezone.make_aware(end_local, tz)
    return start_aware.astimezone(dt_timezone.utc), end_aware.astimezone(dt_timezone.utc)

def _month_range_local_to_utc(d: date):
    tz = timezone.get_current_timezone()
    month_start_local = d.replace(day=1)
    if month_start_local.month == 12:
        next_month_local = date(month_start_local.year + 1, 1, 1)
    else:
        next_month_local = date(month_start_local.year, month_start_local.month + 1, 1)
    start_aware = timezone.make_aware(datetime.combine(month_start_local, time.min), tz)
    end_aware   = timezone.make_aware(datetime.combine(next_month_local, time.min), tz)
    return start_aware.astimezone(dt_timezone.utc), end_aware.astimezone(dt_timezone.utc)

@login_required(login_url='giris')
def panel(request):
    user = request.user
    base_qs = (MusteriFormModel.objects.select_related("kullanici", "posta_kodu", "durum"))
    is_privileged = (user.is_superuser or getattr(user, "rol", "") in ("Admin", "Yönetici", "Personel"))
    if not is_privileged:
        shared_exists = Exists(MusteriFormModelPaylasim.objects.filter(form=OuterRef("pk"), kullanici=user))
        base_qs = base_qs.filter(Q(kullanici=user) | shared_exists)
    formlar = base_qs.order_by("-randevu_tarihi")
    top_kullanicilar = (
        formlar.values("kullanici_id", "kullanici__username", "kullanici__first_name", "kullanici__last_name", "kullanici__resim",).annotate(cnt=Count("id")).order_by("-cnt", "kullanici__username")[:4])
    today = timezone.localdate()
    tomorrow = today + timedelta(days=1)
    t_start, t_end = _day_range_local_to_utc(today)
    m_start, m_end = _month_range_local_to_utc(today)
    r_today_start, r_today_end = _day_range_local_to_utc(today)
    r_tom_start, r_tom_end = _day_range_local_to_utc(tomorrow)
    today_count = formlar.filter(olusturma_tarihi__gte=t_start, olusturma_tarihi__lt=t_end).count()
    month_count = formlar.filter(olusturma_tarihi__gte=m_start, olusturma_tarihi__lt=m_end).count()
    tomorrow_appt_count = formlar.filter(randevu_tarihi__gte=r_tom_start, randevu_tarihi__lt=r_tom_end).count()
    total_count = formlar.count()
    medeni_durum_choices = MusteriFormModel._meta.get_field('medeni_durum').choices
    durumlar = MusteriFormModelDurum.objects.all()
    paylasilabilir_kullanicilar = (CustomUser.objects.filter(aktif=True, silinme_tarihi__isnull=True, is_superuser=False).exclude(rol="Admin").exclude(pk=user.pk).order_by("first_name", "last_name", "username").only("id", "first_name", "last_name", "username"))
    ctx = {
        "formlar": formlar,
        "today_count": today_count,
        "total_count": total_count,
        "tomorrow_appt_count": tomorrow_appt_count,
        "month_count": month_count,
        "MEDENI_DURUM_CHOICES": medeni_durum_choices,
        "top_kullanicilar": top_kullanicilar,
        "durumlar": durumlar,
        "paylasilabilir_kullanicilar": paylasilabilir_kullanicilar,
    }
    return render(request, "index.html", ctx)

@require_POST
def musteri_formu_durum_guncelle(request, pk):
    form = get_object_or_404(MusteriFormModel, pk=pk)

    try:
        durum_id = int(request.POST.get("durum_id", "").strip())
    except (TypeError, ValueError):
        return HttpResponseBadRequest("Geçersiz durum ID.")

    durum = get_object_or_404(MusteriFormModelDurum, pk=durum_id)
    
    # Eski durumu kaydet (log için)
    old_status = form.durum.isim if form.durum else "Durum Yok"

    form.durum = durum
    form.save(update_fields=["durum"])
    
    # Log oluştur
    from .utils.logger import log_status_change
    log_status_change(
        form=form,
        old_status=old_status,
        new_status=durum.isim,
        user=request.user,
        request=request
    )

    return JsonResponse({
        "ok": True,
        "durum_id": durum.id,
        "isim": durum.isim,
    })

def _gen_kod(n=6):
    return ''.join(str(random.randint(0, 6)) for _ in range(n))

@require_POST
def ajax_otp_send_phone(request):
    firma = Firma.objects.first()
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Ungültiges JSON")

    telefon = normalize_phone(payload.get("telefon"))
    if not telefon:
        return HttpResponseBadRequest("Telefon ist erforderlich")

    sess = request.session.get(OTP_PHONE_SESSION_KEY) or {}

    # Abkühlzeit für dieselbe Nummer
    if sess.get("telefon") == telefon and "last_sent" in sess:
        if seconds_since(sess["last_sent"]) < OTP_COOLDOWN_SEC:
            return HttpResponseBadRequest("Bitte versuchen Sie es in 5 Sekunden erneut.")

    # Sende-Limit
    send_count = int(sess.get("send_count") or 0)
    if send_count >= OTP_MAX_SEND:
        return HttpResponseBadRequest("Sendelimit überschritten. Bitte versuchen Sie es später erneut.")

    code = gen_code()

    # SMS-Text
    text = f"{firma.sms_yazisi}: {code}"

    # SMS senden
    try:
        send_sms(telefon, text, sender=firma.isim)  # seven.io "from" bei Bedarf einstellen
    except Exception as e:
        # Gibt den Fehlertext zurück (für Dev/Ops Diagnose)
        return HttpResponseBadRequest(f"SMS-Fehler: {e}")

    # Session schreiben
    request.session[OTP_PHONE_SESSION_KEY] = {
        "telefon": telefon,
        "kod": code,
        "ts": now_iso(),          # Erstellungszeit für TTL
        "last_sent": now_iso(),   # Rate-Limit
        "send_count": send_count + 1,
        "verify_fail": int(sess.get("verify_fail") or 0),
        "verified": False,
    }
    request.session.modified = True
    return JsonResponse({"ok": True})

@require_POST
def ajax_otp_verify_phone(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:
        return HttpResponseBadRequest("Ungültiges JSON")

    telefon = normalize_phone(payload.get("telefon"))
    kod = (payload.get("kod") or "").strip()

    sess = request.session.get(OTP_PHONE_SESSION_KEY)
    if not sess:
        return JsonResponse({"valid": False, "reason": "no_session"})

    # Telefonnummer muss übereinstimmen
    if normalize_phone(sess.get("telefon")) != telefon:
        return JsonResponse({"valid": False, "reason": "phone_mismatch"})

    # TTL-Prüfung
    if is_expired(sess.get("ts", "")):
        return JsonResponse({"valid": False, "reason": "expired"})

    # Fehlversuchs-Limit
    verify_fail = int(sess.get("verify_fail") or 0)
    if verify_fail >= OTP_MAX_VERIFY_FAIL:
        return JsonResponse({"valid": False, "reason": "too_many_attempts"})

    # Sichere Vergleich
    ok = hmac.compare_digest(str(sess.get("kod") or ""), kod)
    if ok:
        sess["verified"] = True
        request.session[OTP_PHONE_SESSION_KEY] = sess
        request.session.modified = True
        return JsonResponse({"valid": True})
    else:
        sess["verify_fail"] = verify_fail + 1
        request.session[OTP_PHONE_SESSION_KEY] = sess
        request.session.modified = True
        return JsonResponse({"valid": False, "reason": "wrong_code"})
    
    
def _send_otp_email(to_email: str, code: str):
    subject = "Ihr E-Mail-Bestätigungscode"
    text_body = f"Ihr Bestätigungscode lautet: {code}\nDieser Code ist 5 Minuten gültig."
    html_body = f"""
    <div style="font-family:Arial,sans-serif;font-size:14px">
      <p>Ihr Bestätigungscode lautet:</p>
      <p style="font-size:24px;font-weight:bold;letter-spacing:3px">{code}</p>
      <p>Dieser Code ist 5 Minuten gültig.</p>
    </div>
    """

    smtp = Smtp.objects.first()
    if not smtp:
        raise Exception("Keine SMTP-Einstellungen gefunden")

    # Django Mail-Backend-Verbindung
    connection = get_connection(
        host=smtp.host,
        port=smtp.port,
        username=smtp.username,
        password=smtp.password,
        use_tls=smtp.use_tls,
        use_ssl=smtp.use_ssl,
    )

    msg = EmailMultiAlternatives(
        subject,
        text_body,
        smtp.username,   # Absender
        [to_email],
        connection=connection,
    )
    msg.attach_alternative(html_body, "text/html")
    msg.send(fail_silently=False)

@require_POST
def ajax_otp_send_email(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
        email = normalize_email(payload.get("email"))
        if not email:
            return HttpResponseBadRequest("E-Mail ist erforderlich")

        sess = request.session.get(OTP_EMAIL_SESSION_KEY) or {}
        # Gleiches E-Mail → Cooldown
        if sess.get("email") == email and "last_sent" in sess:
            if seconds_since(sess["last_sent"]) < OTP_COOLDOWN_SEC:
                return HttpResponseBadRequest("Bitte versuchen Sie es in 5 Sekunden erneut.")

        # Sende-Limit
        send_count = int(sess.get("send_count") or 0)
        if send_count >= OTP_MAX_SEND:
            return HttpResponseBadRequest("Sende-Limit erreicht. Bitte versuchen Sie es später erneut.")

        code = gen_code()
        # Mail senden
        _send_otp_email(email, code)

        # Session schreiben
        request.session[OTP_EMAIL_SESSION_KEY] = {
            "email": email,
            "kod": code,
            "ts": now_iso(),          # Code-Erstellungszeit (TTL)
            "last_sent": now_iso(),   # Rate-Limit
            "send_count": send_count + 1,
            "verify_fail": int(sess.get("verify_fail") or 0),
            "verified": False,
        }
        request.session.modified = True
        return JsonResponse({"ok": True})
    except Exception as e:
        return HttpResponseBadRequest(str(e))

@require_POST
def ajax_otp_verify_email(request):
    try:
        payload = json.loads(request.body.decode("utf-8"))
        email = normalize_email(payload.get("email"))
        kod = (payload.get("kod") or "").strip()

        sess = request.session.get(OTP_EMAIL_SESSION_KEY)
        if not sess:
            return JsonResponse({"valid": False, "reason": "no_session"})

        # E-Mail muss übereinstimmen
        if normalize_email(sess.get("email")) != email:
            return JsonResponse({"valid": False, "reason": "email_mismatch"})

        # TTL-Prüfung
        if is_expired(sess.get("ts", "")):
            return JsonResponse({"valid": False, "reason": "expired"})

        # Fehlversuchs-Limit
        verify_fail = int(sess.get("verify_fail") or 0)
        if verify_fail >= OTP_MAX_VERIFY_FAIL:
            return JsonResponse({"valid": False, "reason": "too_many_attempts"})

        # Sicherer Vergleich
        ok = hmac.compare_digest(str(sess.get("kod") or ""), kod)
        if ok:
            sess["verified"] = True
            request.session[OTP_EMAIL_SESSION_KEY] = sess
            request.session.modified = True
            return JsonResponse({"valid": True})
        else:
            sess["verify_fail"] = verify_fail + 1
            request.session[OTP_EMAIL_SESSION_KEY] = sess
            request.session.modified = True
            return JsonResponse({"valid": False, "reason": "wrong_code"})
    except Exception as e:
        return HttpResponseBadRequest(str(e))

@require_GET
def posta_kodu_lookup(request):
    q = (request.GET.get("q") or "").strip()
    if len(q) < 3:
        return HttpResponseBadRequest("Mindestens 3 Zeichen erforderlich")
    sehir = (
        Sehir.objects.filter(posta_kodu__istartswith=q)
        .order_by("posta_kodu")
        .values("id", "il", "ilce", "posta_kodu")
        .first()
    )
    return JsonResponse(sehir or {})

OTP_EMAIL_SESSION_KEY = "otp_email"
OTP_PHONE_SESSION_KEY = "otp_phone"

# === Yardımcılar ===
def _normalize_email(s: str) -> str:
    return (s or "").strip().lower()

def _normalize_phone(phone: str) -> str:
    p = (phone or "").strip()
    for ch in " ()-+":
        p = p.replace(ch, "")
    if p.startswith("0") and len(p) >= 10:
        p = p[1:]
    return p

def _clear_otp_sessions(request):
    changed = False
    for key in (OTP_EMAIL_SESSION_KEY, OTP_PHONE_SESSION_KEY):
        if key in request.session:
            del request.session[key]
            changed = True
    if changed:
        request.session.modified = True

@require_GET
def ajax_sigorta_sirketleri(request):
    # Seçilen sigorta türüne göre filtreleme
    sigorta_turu = request.GET.get('typ', '').strip()
    print(f"DEBUG: Gelen sigorta türü: '{sigorta_turu}'")
    
    # Türkçe değerleri Almanca karşılıklarına çevir
    if sigorta_turu == 'Özel':
        kapsam_filter = 'Privat'
    elif sigorta_turu == 'Yasal':
        kapsam_filter = 'Gesetzlich'
    else:
        kapsam_filter = None
    
    print(f"DEBUG: Kapsam filtresi: '{kapsam_filter}'")
    
    # Filtreleme uygula
    if kapsam_filter:
        items = SigortaSirket.objects.filter(
            Q(kapsam=kapsam_filter) | Q(kapsam='Beides')
        ).order_by('sira', 'id')
    else:
        items = SigortaSirket.objects.all().order_by('sira', 'id')
    
    data = [{
        "id": s.id,
        "isim": s.isim,
        "resim": s.resim.url if s.resim else "",
        "kapsam": s.kapsam
    } for s in items]
    
    print(f"DEBUG: Dönen {len(data)} şirket:")
    for item in data:
        print(f"  - ID: {item['id']}, İsim: {item['isim']}, Kapsam: {item['kapsam']}")
    
    return JsonResponse({"ok": True, "items": data})


@require_GET
def ajax_sigorta_alt_list(request):
    sirket_id = request.GET.get("sirket_id")
    if not sirket_id:
        return JsonResponse({"ok": False, "error": "Parameter 'sirket_id' ist erforderlich."}, status=400)

    try:
        sirket = SigortaSirket.objects.get(pk=sirket_id)
    except SigortaSirket.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Ungültige 'sirket_id'."}, status=400)

    items = [
        {"id": a.id, "isim": a.isim, "sira": a.sira}
        for a in SigortaAltSirket.objects.filter(sirket=sirket).order_by("sira", "id")
    ]
    return JsonResponse({"ok": True, "gesellschaft": {"id": sirket.id, "name": sirket.isim}, "items": items})


@require_POST
@transaction.atomic
def musteri_form_olustur(request):
    def done(resp: JsonResponse) -> JsonResponse:
        _clear_otp_sessions(request)
        return resp

    data = request.POST

    # 1) Zorunlu alanlar
    zorunlu = [
        "randevu_tarihi",
        "firma_adi",
        "musteri_isim",
        "musteri_soyisim",
        "musteri_dogum_tarihi",
        "adres",
    ]
    eksik = [f for f in zorunlu if not data.get(f)]
    if eksik:
        return done(JsonResponse(
            {"ok": False, "hata": f"Pflichtfeld fehlt: {', '.join(eksik)}"},
            status=400,
        ))

    # 2) Tarih parse
    randevu_dt = parse_datetime(data.get("randevu_tarihi"))
    dogum_dt   = parse_date(data.get("musteri_dogum_tarihi"))
    if not randevu_dt or not dogum_dt:
        return done(JsonResponse({"ok": False, "hata": "Ungültiges Datumsformat."}, status=400))

    # 3) Posta kodu → şehir/ilçe (FK)
    sehir_obj = None
    posta_kodu_id = data.get("posta_kodu_id")
    if posta_kodu_id:
        try:
            sehir_obj = Sehir.objects.get(pk=posta_kodu_id)
        except Sehir.DoesNotExist:
            sehir_obj = None
    # Fallback: id gelmediyse, yazılan PLZ'den çöz
    if not sehir_obj:
        raw_plz = (data.get("posta_kodu") or "").strip()
        if raw_plz:
            sehir_obj = Sehir.objects.filter(posta_kodu__istartswith=raw_plz).order_by("posta_kodu").first()

    # 4) OTP doğrulama flag’leri (session bazlı)
    posted_email = _normalize_email(data.get("email"))
    ses_email = request.session.get(OTP_EMAIL_SESSION_KEY) or {}
    email_onayli_mi = bool(
        ses_email.get("verified") and _normalize_email(ses_email.get("email")) == posted_email
    )

    posted_tel = _normalize_phone(data.get("telefon"))
    ses_tel = request.session.get(OTP_PHONE_SESSION_KEY) or {}
    telefon_onayli_mi = bool(
        ses_tel.get("verified") and _normalize_phone(ses_tel.get("telefon")) == posted_tel
    )

    # 5) Helpers
    def to_int(val):
        try:
            return int(val) if val not in (None, "",) else None
        except Exception:
            return None

    def to_decimal(val):
        try:
            return Decimal(str(val)) if val not in (None, "",) else None
        except Exception:
            return None

    # 6) Sigorta tarihleri
    sigorta_baslangic = parse_date(data.get("sigorta_baslangic_tarihi")) if data.get("sigorta_baslangic_tarihi") else None
    
    # 6.1) Sigorta Tarif (FK)
    sigorta_vade_obj = None
    sigorta_vade_id = data.get("sigorta_tarife_vadesi")
    if sigorta_vade_id:
        try:
            sigorta_vade_obj = SigortaAltSirket.objects.get(pk=sigorta_vade_id)
        except SigortaAltSirket.DoesNotExist:
            sigorta_vade_obj = None

    # 6.1) Sigorta Şirketi (FK)
    sigorta_sirket_obj = None
    sigorta_sirket_id = data.get("sigorta_sirket")
    if sigorta_sirket_id:
        try:
            sigorta_sirket_obj = SigortaSirket.objects.get(pk=int(sigorta_sirket_id))
        except (SigortaSirket.DoesNotExist, ValueError, TypeError):
            sigorta_sirket_obj = None
    print("cinsiyet: ", data.get("musteri_cinsiyet"))
    # 7) Kayıt
    form = MusteriFormModel.objects.create(
        kullanici=request.user if getattr(request, "user", None) and request.user.is_authenticated else None,
        randevu_tarihi=randevu_dt,
        randevu_tipi=data.get("randevu_tipi") or "",
        firma_adi=data.get("firma_adi"),
        musteri_isim=data.get("musteri_isim"),
        musteri_soyisim=data.get("musteri_soyisim"),
        musteri_dogum_tarihi=dogum_dt,
        musteri_cinsiyet=data.get("musteri_cinsiyet"),
        adres=data.get("adres"),
        sehir=data.get("ilce") or None,
        posta_kodu=sehir_obj,
        posta_kodu_raw=(data.get("posta_kodu") or None),
        telefon=data.get("telefon") or None,
        telefon_onayli_mi=telefon_onayli_mi,
        email=data.get("email") or None,
        email_onayli_mi=email_onayli_mi,
        sabit_telefon=data.get("sabit_telefon") or None,
        medeni_durum=data.get("medeni_durum") or "Bekar",
        calisma_durumu=data.get("calisma_durumu") or None,
        aile_cocuk_sayisi=to_int(data.get("aile_cocuk_sayisi")),
        sigorta=data.get("sigorta") or None,
        sigorta_ek_yazi=data.get("sigorta_ek_yazi") or None,
        sigorta_katki_payi=to_decimal(data.get("sigorta_katki_payi")),
        sigorta_sirket=sigorta_sirket_obj,
        sigorta_baslangic_tarihi=sigorta_baslangic,
        sigorta_tarife_vadesi=sigorta_vade_obj,
        sigorta_katilim_payi=to_decimal(data.get("sigorta_katilim_payi")),
        es_cocuk_sigorta=data.get("es_cocuk_sigorta") or None,
        es_yasi=to_int(data.get("es_yasi")),
    )

    # 8) Çocuk yaşları
    yas_list = []
    yas_json = data.get("cocuk_yaslari_json")
    try:
        if yas_json:
            yas_list = [int(x) for x in json.loads(yas_json) if str(x).strip() != ""]
        else:
            yas_list = [int(x) for x in request.POST.getlist("cocuk_yasi[]") if str(x).strip() != ""]
    except Exception:
        yas_list = []

    if yas_list:
        MusteriFormModelCocukYasi.objects.bulk_create(
            [MusteriFormModelCocukYasi(form=form, cocuk_yasi=y) for y in yas_list]
        )

    # 9) İlk not (ayrı model)
    first_note = (data.get("paylasim_notu") or "").strip()
    if first_note and getattr(request, "user", None) and request.user.is_authenticated:
        note = MusteriFormModelNot.objects.create(
            form=form,
            kullanici=request.user,
            not_icerigi=first_note
        )
        # Not ekleme logu
        from .utils.logger import log_note_add
        log_note_add(form=form, note_content=first_note, user=request.user, request=request)

    # 10) Log oluştur
    from .utils.logger import log_form_create
    log_form_create(form=form, user=request.user, request=request)

    # 11) Yanıt
    return done(JsonResponse({
        "ok": True,
        "id": form.id,
        "redirect": reverse("panel"),
    }))

def _fmt_dt_human(dt):
    if not dt:
        return None
    local = timezone.localtime(dt)
    # "25.09.2025 Donnerstag - 12:45 Uhr"
    return f"{date_format(local, 'd.m.Y l')} - {date_format(local, 'H:i')} Uhr"

def _user_display(u):
    if not u:
        return None
    return (u.get_full_name() or u.username or "").strip() or None


# ---------------------------
# EDIT: KAYDET (GÜNCEL)
# ---------------------------
@require_POST
@transaction.atomic
def musteri_form_duzenle(request, form_id):
    if request.user.rol != 'Yönetici' and not request.user.is_superuser and not request.user.rol == 'Admin':
        return redirect('panel')

    def done(resp: JsonResponse) -> JsonResponse:
        _clear_otp_sessions(request)
        return resp

    inst = get_object_or_404(MusteriFormModel, pk=form_id)
    data = request.POST

    # 1) Zorunlu alanlar
    zorunlu = ["randevu_tarihi","firma_adi","musteri_isim","musteri_soyisim","musteri_dogum_tarihi","adres"]
    eksik = [f for f in zorunlu if not data.get(f)]
    if eksik:
        return done(JsonResponse({"ok": False, "hata": f"Pflichtfeld fehlt: {', '.join(eksik)}"}, status=400))

    # 2) Tarihler
    randevu_dt = parse_datetime(data.get("randevu_tarihi"))
    dogum_dt   = parse_date(data.get("musteri_dogum_tarihi"))
    if not randevu_dt or not dogum_dt:
        return done(JsonResponse({"ok": False, "hata": "Ungültiges Datumsformat."}, status=400))

    # 3) Posta kodu -> şehir
    sehir_obj = None
    posta_kodu_id = data.get("posta_kodu_id")
    if posta_kodu_id:
        try:
            sehir_obj = Sehir.objects.get(pk=posta_kodu_id)
        except Sehir.DoesNotExist:
            sehir_obj = None
    # Fallback: id gelmediyse yazılan PLZ'den çöz
    if not sehir_obj:
        raw_plz = (data.get("posta_kodu") or "").strip()
        if raw_plz:
            sehir_obj = Sehir.objects.filter(posta_kodu__istartswith=raw_plz).order_by("posta_kodu").first()

    # 4) Onay bayrakları
    posted_email = _normalize_email(data.get("email"))
    posted_tel   = _normalize_phone(data.get("telefon"))
    old_email = _normalize_email(inst.email)
    old_tel   = _normalize_phone(inst.telefon)
    ses_email = request.session.get(OTP_EMAIL_SESSION_KEY) or {}
    ses_tel   = request.session.get(OTP_PHONE_SESSION_KEY) or {}
    
    # 4.1) Eski değerleri kaydet (form güncellemesinden ÖNCE) - TÜM ALANLAR
    def normalize_value(value):
        """Boş değerleri None'a normalize et"""
        if value is None or value == '' or (isinstance(value, str) and value.strip() == ''):
            return None
        return value
    
    def normalize_datetime(dt_obj):
        """Datetime objelerini tutarlı ISO formatına çevir"""
        if not dt_obj:
            return None
        try:
            # Eğer string ise datetime nesnesine çevir
            if isinstance(dt_obj, str):
                from datetime import datetime
                # Timezone bilgilerini temizle
                clean_str = dt_obj.replace('Z', '').split('+')[0]
                dt_obj = datetime.fromisoformat(clean_str)
            
            # Datetime nesnesini tutarlı formatta string'e çevir
            # Mikrosaniyeleri kaldır ve sadece saniyeye kadar al
            return dt_obj.replace(microsecond=0).isoformat()
        except:
            # Hata durumunda None döndür
            return None
    
    old_values = {
        'musteri_isim': normalize_value(inst.musteri_isim),
        'musteri_soyisim': normalize_value(inst.musteri_soyisim),
        'musteri_dogum_tarihi': normalize_datetime(inst.musteri_dogum_tarihi),
        'musteri_cinsiyet': normalize_value(inst.musteri_cinsiyet),
        'telefon': normalize_value(inst.telefon),
        'sabit_telefon': normalize_value(inst.sabit_telefon),
        'email': normalize_value(inst.email),
        'randevu_tarihi': normalize_datetime(inst.randevu_tarihi),
        'firma_adi': normalize_value(inst.firma_adi),
        'adres': normalize_value(inst.adres),
        'sehir': normalize_value(inst.sehir),
        'posta_kodu': inst.posta_kodu.posta_kodu if inst.posta_kodu else None,
        'medeni_durum': normalize_value(inst.medeni_durum),
        'calisma_durumu': normalize_value(inst.calisma_durumu),
        'aile_cocuk_sayisi': inst.aile_cocuk_sayisi if inst.aile_cocuk_sayisi is not None else None,
        'sigorta': normalize_value(inst.sigorta),
        'sigorta_ek_yazi': normalize_value(inst.sigorta_ek_yazi),
        'sigorta_katki_payi': str(inst.sigorta_katki_payi) if inst.sigorta_katki_payi else None,
        'sigorta_sirket': inst.sigorta_sirket.isim if inst.sigorta_sirket else None,
        'sigorta_baslangic_tarihi': normalize_datetime(inst.sigorta_baslangic_tarihi),
        'sigorta_tarife_vadesi': inst.sigorta_tarife_vadesi.isim if inst.sigorta_tarife_vadesi else None,
        'sigorta_katilim_payi': str(inst.sigorta_katilim_payi) if inst.sigorta_katilim_payi else None,
        'es_cocuk_sigorta': normalize_value(inst.es_cocuk_sigorta),
        'es_yasi': inst.es_yasi if inst.es_yasi is not None else None,
        'durum': inst.durum.isim if inst.durum else None,
    }

    if posted_email == old_email:
        email_onayli_mi = bool(inst.email_onayli_mi)
    else:
        email_onayli_mi = bool(ses_email.get("verified") and _normalize_email(ses_email.get("email")) == posted_email)

    if posted_tel == old_tel:
        telefon_onayli_mi = bool(inst.telefon_onayli_mi)
    else:
        telefon_onayli_mi = bool(ses_tel.get("verified") and _normalize_phone(ses_tel.get("telefon")) == posted_tel)

    def to_int(val):
        try: return int(val) if val not in (None,"") else None
        except: return None

    def to_decimal(val):
        try: return Decimal(str(val)) if val not in (None,"") else None
        except: return None

    sigorta_baslangic = parse_date(data.get("sigorta_baslangic_tarihi")) if data.get("sigorta_baslangic_tarihi") else None
    
    # Sigorta Tarif (FK)
    sigorta_vade_obj = None
    sigorta_vade_id = data.get("sigorta_tarife_vadesi")
    if sigorta_vade_id:
        try:
            sigorta_vade_obj = SigortaAltSirket.objects.get(pk=sigorta_vade_id)
        except SigortaAltSirket.DoesNotExist:
            sigorta_vade_obj = None

    # Sigorta Şirketi (FK)
    sigorta_sirket_id = (data.get("sigorta_sirket") or "").strip()
    sigorta_sirket_obj = None
    if sigorta_sirket_id:
        try:
            sigorta_sirket_obj = SigortaSirket.objects.get(pk=int(sigorta_sirket_id))
        except (SigortaSirket.DoesNotExist, ValueError, TypeError):
            sigorta_sirket_obj = None

    # 7) Güncelle
    inst.randevu_tarihi           = randevu_dt
    inst.randevu_tipi             = data.get("randevu_tipi") or ""
    inst.firma_adi                = data.get("firma_adi")
    inst.musteri_cinsiyet         = data.get("musteri_cinsiyet")
    inst.musteri_isim             = data.get("musteri_isim")
    inst.musteri_soyisim          = data.get("musteri_soyisim")
    inst.musteri_dogum_tarihi     = dogum_dt
    inst.adres                    = data.get("adres")
    inst.sehir                    = data.get("ilce") or None
    inst.posta_kodu               = sehir_obj
    inst.posta_kodu_raw           = (data.get("posta_kodu") or None)
    inst.telefon                  = data.get("telefon") or None
    inst.telefon_onayli_mi        = telefon_onayli_mi
    inst.sabit_telefon            = data.get("sabit_telefon") or None
    inst.email                    = data.get("email") or None
    inst.email_onayli_mi          = email_onayli_mi
    inst.medeni_durum             = data.get("medeni_durum") or "Bekar"
    inst.calisma_durumu           = data.get("calisma_durumu") or None
    inst.aile_cocuk_sayisi        = to_int(data.get("aile_cocuk_sayisi"))
    inst.sigorta                  = data.get("sigorta") or None
    inst.sigorta_ek_yazi          = data.get("sigorta_ek_yazi") or None
    inst.sigorta_katki_payi       = to_decimal(data.get("sigorta_katki_payi"))
    inst.sigorta_sirket           = sigorta_sirket_obj
    inst.sigorta_baslangic_tarihi = sigorta_baslangic
    inst.sigorta_tarife_vadesi    = sigorta_vade_obj
    inst.sigorta_katilim_payi     = to_decimal(data.get("sigorta_katilim_payi"))
    inst.es_cocuk_sigorta         = data.get("es_cocuk_sigorta") or None
    inst.es_yasi                  = to_int(data.get("es_yasi"))
    inst.save()

    # 8) Çocuk yaşları
    yas_list = []
    yas_json = data.get("cocuk_yaslari_json")
    try:
        if yas_json:
            yas_list = [int(x) for x in json.loads(yas_json) if str(x).strip() != ""]
        else:
            yas_list = [int(x) for x in request.POST.getlist("cocuk_yasi[]") if str(x).strip() != ""]
    except Exception:
        yas_list = []

    MusteriFormModelCocukYasi.objects.filter(form=inst).delete()
    if yas_list:
        MusteriFormModelCocukYasi.objects.bulk_create(
            [MusteriFormModelCocukYasi(form=inst, cocuk_yasi=y) for y in yas_list]
        )

    # 9) NOT — Güncelle/ekle mantığı
    raw_new_note = (data.get("duzenle_yeni_not") or "").strip()     # mini alan: her zaman YENİ kayıt
    edited_note  = (data.get("paylasim_notu") or "").strip()        # büyük textarea: mevcut notu güncelle

    if request.user.is_authenticated:
        # Kullanıcının bu formdaki son notunu al
        last_note_obj = (
            MusteriFormModelNot.objects
            .filter(form=inst, kullanici=request.user)
            .order_by('-id')
            .first()
        )

        if raw_new_note:
            # Mini alandan geliyorsa her zaman yeni not ekle
            note = MusteriFormModelNot.objects.create(
                form=inst,
                kullanici=request.user,
                not_icerigi=raw_new_note,
            )
            # Not ekleme logu
            from .utils.logger import log_note_add
            log_note_add(form=inst, note_content=raw_new_note, user=request.user, request=request)
        else:
            # Mevcut not editlendi ise: aynıysa dokunma; farklıysa GÜNCELLE
            if edited_note:
                if last_note_obj:
                    if edited_note.strip() != (last_note_obj.not_icerigi or "").strip():
                        old_content = last_note_obj.not_icerigi
                        last_note_obj.not_icerigi = edited_note
                        last_note_obj.save(update_fields=["not_icerigi"])
                        # Not güncelleme logu
                        from .utils.logger import log_custom_action
                        log_custom_action(
                            action_type='NOTE_UPDATE',
                            title='Not Güncellendi',
                            description=f'"{inst.musteri_isim} {inst.musteri_soyisim}" adlı müşterinin formundaki not güncellendi.',
                            user=request.user,
                            request=request,
                            related_form=inst,
                            details={
                                'musteri_adi': f"{inst.musteri_isim} {inst.musteri_soyisim}",
                                'form_id': inst.id,
                                'eski_not': old_content,
                                'yeni_not': edited_note,
                            }
                        )
                else:
                    # Daha önce not yoksa yeni oluştur
                    note = MusteriFormModelNot.objects.create(
                        form=inst,
                        kullanici=request.user,
                        not_icerigi=edited_note,
                    )
                    # Not ekleme logu
                    from .utils.logger import log_note_add
                    log_note_add(form=inst, note_content=edited_note, user=request.user, request=request)
            else:
                # edited_note boş ise hiçbir şey yapma (mevcut notu silmiyoruz)
                pass

    # 10) Log oluştur - değişen alanları tespit et
    from .utils.logger import log_form_update
    
    # Yeni değerleri kaydet - TÜM ALANLAR
    new_values = {
        'musteri_isim': normalize_value(data.get("musteri_isim")),
        'musteri_soyisim': normalize_value(data.get("musteri_soyisim")),
        'musteri_dogum_tarihi': normalize_datetime(dogum_dt),
        'musteri_cinsiyet': normalize_value(data.get("musteri_cinsiyet")),
        'telefon': normalize_value(data.get("telefon")),
        'sabit_telefon': normalize_value(data.get("sabit_telefon")),
        'email': normalize_value(data.get("email")),
        'randevu_tarihi': normalize_datetime(randevu_dt),
        'firma_adi': normalize_value(data.get("firma_adi")),
        'adres': normalize_value(data.get("adres")),
        'sehir': normalize_value(data.get("ilce")),
        'posta_kodu': sehir_obj.posta_kodu if sehir_obj else None,
        'medeni_durum': normalize_value(data.get("medeni_durum")),
        'calisma_durumu': normalize_value(data.get("calisma_durumu")),
        'aile_cocuk_sayisi': to_int(data.get("aile_cocuk_sayisi")) if to_int(data.get("aile_cocuk_sayisi")) is not None else None,
        'sigorta': normalize_value(data.get("sigorta")),
        'sigorta_ek_yazi': normalize_value(data.get("sigorta_ek_yazi")),
        'sigorta_katki_payi': str(to_decimal(data.get("sigorta_katki_payi"))) if to_decimal(data.get("sigorta_katki_payi")) else None,
        'sigorta_sirket': sigorta_sirket_obj.isim if sigorta_sirket_obj else None,
        'sigorta_baslangic_tarihi': normalize_datetime(sigorta_baslangic),
        'sigorta_tarife_vadesi': sigorta_vade_obj.isim if sigorta_vade_obj else None,
        'sigorta_katilim_payi': str(to_decimal(data.get("sigorta_katilim_payi"))) if to_decimal(data.get("sigorta_katilim_payi")) else None,
        'es_cocuk_sigorta': normalize_value(data.get("es_cocuk_sigorta")),
        'es_yasi': to_int(data.get("es_yasi")) if to_int(data.get("es_yasi")) is not None else None,
        'durum': inst.durum.isim if inst.durum else None,  # Durum ayrı değişiyor
    }
    
    # Sadece değişen alanları filtrele
    changed_fields = {}
    for key in old_values:
        if old_values[key] != new_values[key]:
            changed_fields[key] = {
                'old': old_values[key],
                'new': new_values[key]
            }
    
    log_form_update(
        form=inst, 
        user=request.user, 
        request=request,
        old_values=old_values,
        new_values=new_values,
        details={'changed_fields': changed_fields}
    )

    return done(JsonResponse({"ok": True, "id": inst.id, "redirect": reverse("panel")}))


# ---------------------------
# EDIT: DETAY (JS: /ajax/forms/musteri/<id>/detail/) – GÜNCEL
# ---------------------------
@require_GET
def musteri_form_detay(request, form_id):
    f = get_object_or_404(MusteriFormModel, pk=form_id)

    # FK'den il/ilçe (varsa)
    fk_il   = getattr(getattr(f, "posta_kodu", None), "il", "") or ""
    fk_ilce = getattr(getattr(f, "posta_kodu", None), "ilce", "") or ""

    last_note = (
        MusteriFormModelNot.objects
        .filter(form=f, kullanici=request.user)
        .order_by('-id')
        .values_list('not_icerigi', flat=True)
        .first()
    ) or ""

    sigorta_sirket_id = f.sigorta_sirket_id or ""
    sigorta_sirket_ad = None
    sigorta_sirket_logo = None
    if f.sigorta_sirket:
        sigorta_sirket_ad = f.sigorta_sirket.isim
        if getattr(f.sigorta_sirket, 'resim', None) and getattr(f.sigorta_sirket.resim, 'url', None):
            try:
                sigorta_sirket_logo = request.build_absolute_uri(f.sigorta_sirket.resim.url)
            except Exception:
                sigorta_sirket_logo = f.sigorta_sirket.resim.url

    return JsonResponse({
        "id": f.id,
        "randevu_tarihi": f.randevu_tarihi.isoformat() if f.randevu_tarihi else "",
        "randevu_tipi": f.randevu_tipi or "",
        "firma_adi": f.firma_adi or "",
        "musteri_cinsiyet": f.musteri_cinsiyet or "",
        "musteri_isim": f.musteri_isim or "",
        "musteri_soyisim": f.musteri_soyisim or "",
        "musteri_dogum_tarihi": f.musteri_dogum_tarihi.isoformat() if f.musteri_dogum_tarihi else "",
        "adres": f.adres or "",
        "sehir": f.sehir or "",
        "ilce": fk_ilce,
        "posta_kodu": (getattr(getattr(f, "posta_kodu", None), "posta_kodu", "") or (f.posta_kodu_raw or "")),
        "posta_kodu_id": f.posta_kodu_id or "",
        "telefon": f.telefon or "",
        "telefon_onayli_mi": f.telefon_onayli_mi,
        "email": f.email or "",
        "email_onayli_mi": f.email_onayli_mi,
        "sabit_telefon": f.sabit_telefon or "",
        "medeni_durum": f.medeni_durum or "",
        "aile_cocuk_sayisi": f.aile_cocuk_sayisi,
        "sigorta": f.sigorta or "",
        "sigorta_ek_yazi": f.sigorta_ek_yazi or "",
        "sigorta_katki_payi": str(f.sigorta_katki_payi or ""),
        "sigorta_sirket_id": sigorta_sirket_id,
        "sigorta_sirket_ad": sigorta_sirket_ad,
        "sigorta_sirket_adi": sigorta_sirket_ad,
        "sigorta_sirket_isim": sigorta_sirket_ad,
        "sigorta_sirket_logo": sigorta_sirket_logo,
        "sigorta_baslangic_tarihi": f.sigorta_baslangic_tarihi.isoformat() if f.sigorta_baslangic_tarihi else "",
        "sigorta_tarife_vadesi": f.sigorta_tarife_vadesi.id if f.sigorta_tarife_vadesi else "",
        "sigorta_katilim_payi": str(f.sigorta_katilim_payi or ""),
        "es_cocuk_sigorta": f.es_cocuk_sigorta or "",
        "es_yasi": f.es_yasi,
        "cocuk_yaslari": list(f.musteriformmodelcocukyasi_set.values_list("cocuk_yasi", flat=True)),
        "calisma_durumu": f.calisma_durumu or "",
        "paylasim_notu": last_note,

        # 🔑 Stadt inputu için değer: önce serbest alan, yoksa FK'den ilçe
        "sehir_for_input": (f.sehir or fk_ilce or ""),
    })


# ---------------------------
# NOTLAR: Listele (GET) + Ekle (POST)
# (JS: /ajax/forms/musteri/<id>/notlar/)
# ---------------------------
@require_GET
def musteri_form_notlar(request, form_id):
    f = get_object_or_404(MusteriFormModel, pk=form_id)

    qs = (
        MusteriFormModelNot.objects
        .filter(form=f)
        .select_related('kullanici')
        .order_by('-id')
    )

    items = []
    for n in qs:
        items.append({
            "id": n.id,
            "kullanici": _user_display(n.kullanici) or "—",
            "icerik": n.not_icerigi or "",
            "created_human": _fmt_dt_human(n.olusturma_tarihi),
            "updated_human": _fmt_dt_human(n.son_guncelleme_tarihi),
            "tarih_human":  _fmt_dt_human(n.son_guncelleme_tarihi or n.olusturma_tarihi),
        })

    return JsonResponse({
        "ok": True,
        "not_sayisi": len(items),
        "notlar": items,   # JS renderNotes bunu okuyacak
    })


@require_POST
@transaction.atomic
def musteri_form_not_ekle(request, form_id):
    if not request.user.is_authenticated:
        return JsonResponse({"ok": False, "error": "Auth erforderlich"}, status=401)

    f = get_object_or_404(MusteriFormModel, pk=form_id)

    try:
        payload = json.loads(request.body.decode('utf-8'))
    except Exception:
        payload = request.POST

    content = (payload.get('icerik') or payload.get('content') or '').strip()
    if not content:
        return JsonResponse({"ok": False, "error": "Notiz-Inhalt fehlt."}, status=400)

    n = MusteriFormModelNot.objects.create(
        form=f,
        kullanici=request.user,
        not_icerigi=content
    )
    
    # Not ekleme logu
    from .utils.logger import log_note_add
    log_note_add(form=f, note_content=content, user=request.user, request=request)

    return JsonResponse({
        "ok": True,
        "id": n.id,
        "kullanici": _user_display(n.kullanici),
        "icerik": n.not_icerigi or "",
        "created_human": _fmt_dt_human(n.olusturma_tarihi),
    }, status=201)


@login_required(login_url='giris')
@require_GET
def form_detail_json(request, form_id: int):
    try:
        form = (
            MusteriFormModel.objects
            .select_related('kullanici', 'posta_kodu', 'durum', 'sigorta_sirket')
            .get(pk=form_id)
        )
    except MusteriFormModel.DoesNotExist:
        raise Http404

    # --- Almanca tarih/hafta günü formatı ---
    def fmt_dt(dt):
        if not dt:
            return None
        with translation.override('de'):
            local = timezone.localtime(dt)
            return date_format(local, "d.m.Y - l H:i") + " Uhr"

    def fmt_d(d):
        if not d:
            return None
        with translation.override('de'):
            return date_format(d, "d.m.Y")
        
    # Sigorta Şirketi
    sigorta_sirket_ad = None
    sigorta_sirket_logo = None
    if form.sigorta_sirket:
        sigorta_sirket_ad = form.sigorta_sirket.isim
        if getattr(form.sigorta_sirket, 'resim', None) and getattr(form.sigorta_sirket.resim, 'url', None):
            try:
                sigorta_sirket_logo = request.build_absolute_uri(form.sigorta_sirket.resim.url)
            except Exception:
                sigorta_sirket_logo = form.sigorta_sirket.resim.url

    # Çocuk yaşları
    cocuk_yaslari = list(
        form.musteriformmodelcocukyasi_set.values_list('cocuk_yasi', flat=True)
    )

    # Paylaşım geçmişi
    paylasimlar_qs = (
        MusteriFormModelPaylasim.objects
        .filter(form=form)
        .select_related('kullanici')
        .order_by('-son_guncelleme_tarihi')
    )
    paylasimlar = [{
        "kullanici": ((p.kullanici.get_full_name() or p.kullanici.username) if p.kullanici else None),
        "son_guncelleme_human": fmt_dt(p.son_guncelleme_tarihi),
    } for p in paylasimlar_qs]

    # Notlar
    notlar_qs = (
        MusteriFormModelNot.objects
        .filter(form=form)
        .select_related('kullanici')
        .order_by('-son_guncelleme_tarihi')
    )
    notlar = [{
        "kullanici": ((n.kullanici.get_full_name() or n.kullanici.username) if n.kullanici else None),
        "icerik": n.not_icerigi,
        "tarih_human": fmt_dt(getattr(n, 'son_guncelleme_tarihi', None) or getattr(n, 'olusturma_tarihi', None)),
    } for n in notlar_qs]

    # Eski alan (geri uyumluluk)
    paylasim = None

    # Adres parçaları
    posta = form.posta_kodu
    sehir_ilce = posta_kodu_str = il = ilce = None
    if posta:
        il_raw   = getattr(posta, "il", None)      # örn: "Baden-Württemberg"
        ilce_raw = getattr(posta, "ilce", None)    # örn: "Stuttgart"
        pkod     = getattr(posta, "posta_kodu", None)

        # İL: tamamını kullan
        il = (str(il_raw).strip() or None) if il_raw is not None else None
        # İLÇE: tamamını kullan (ilk kelime istersen .split(None,1)[0] uygula)
        ilce = (str(ilce_raw).strip() or None) if ilce_raw is not None else None

        parts = [x for x in (il, ilce) if x]
        sehir_ilce = " / ".join(parts) if parts else None  # --> "Baden-Württemberg / Stuttgart"
        posta_kodu_str = str(pkod) if pkod not in (None, "") else None

    # --- ÖNEMLİ: choices => Almanca display isimleri ---
    medeni_display = form.get_medeni_durum_display() if form.medeni_durum else None
    sigorta_display = form.get_sigorta_display() if form.sigorta else None
    es_cocuk_display = form.get_es_cocuk_sigorta_display() if form.es_cocuk_sigorta else None
    data = {
        "id": form.id,
        "musteri_cinsiyet": form.get_musteri_cinsiyet_display() if form.musteri_cinsiyet else None,
        "tam_ad": f"{(form.musteri_isim or '').strip()} {(form.musteri_soyisim or '').strip()}".strip() or None,
        "randevu_human": fmt_dt(form.randevu_tarihi),
        "randevu_tipi": form.randevu_tipi or "",
        "olusturma_human": fmt_dt(form.olusturma_tarihi),
        "created_by": (form.kullanici.get_full_name() or form.kullanici.username if form.kullanici else None),
        "created_by_id": form.kullanici.id if form.kullanici else None,
        "created_by_rol": form.kullanici.rol if form.kullanici else None,

        # Durum adın Almanca tutulmuyorsa burada gerekirse bir map uygularsın.
        "durum_human": (form.durum.isim if form.durum else None),

        "telefon": form.telefon,
        "telefon_onayli_mi": form.telefon_onayli_mi,
        "email": form.email,
        "email_onayli_mi": form.email_onayli_mi,
        "sabit_telefon": form.sabit_telefon,

        "il": il,
        "ilce": ilce,
        "adres": form.adres,
        "sehir_ilce": sehir_ilce,
        "posta_kodu": posta_kodu_str,

        "firma_adi": form.firma_adi,
        "dogum_human": fmt_d(form.musteri_dogum_tarihi),

        # Almanca görünen değerler
        "medeni_durum": medeni_display,
        "calisma_durumu": form.calisma_durumu or None,
        "aile_cocuk_sayisi": form.aile_cocuk_sayisi,
        "cocuk_yaslari": cocuk_yaslari,

        "sigorta": sigorta_display,
        "sigorta_sirket": sigorta_sirket_ad,
        "sigorta_sirket_ad": sigorta_sirket_ad,
        "sigorta_sirket_logo": sigorta_sirket_logo,
        "sigorta_baslangic_human": fmt_d(form.sigorta_baslangic_tarihi),
        "sigorta_vade_human": form.sigorta_tarife_vadesi.isim if form.sigorta_tarife_vadesi else "—",
        "sigorta_katilim_payi": str(form.sigorta_katilim_payi) if form.sigorta_katilim_payi is not None else None,
        "sigorta_katki_payi": str(form.sigorta_katki_payi) if form.sigorta_katki_payi is not None else None,
        "sigorta_ek_yazi": form.sigorta_ek_yazi,

        "es_cocuk_sigorta": es_cocuk_display,
        "es_yasi": form.es_yasi,

        # Geriye dönük
        "paylasim": paylasim,

        # Yeni
        "paylasimlar": paylasimlar,
        "notlar": notlar,
        "not_sayisi": len(notlar),
        "paylasim_sayisi": len(paylasimlar),
        "son_not": (notlar[0] if notlar else None),
    }
    return JsonResponse(data)


def form_detail_pdf(request, form_id: int):
    form = get_object_or_404(MusteriFormModel, pk=form_id)

    # Yetki kontrolü (örnek)
    if request.user.rol != 'Yönetici' and not request.user.is_superuser and not request.user.rol == 'Admin':
        return redirect('panel')

    # İsteğe göre ek erişim kuralları
    if (MusteriFormModelNot.objects.filter(form=form, kullanici=request.user).count() == 0) and (form.kullanici != request.user):
        # pass veya redirect — kuralına göre güncelle
        pass

    # Almanca yerelleştirme
    translation.activate('de')

    # Firma bilgisi
    firma = Firma.objects.first()
    firma_isim = getattr(firma, "isim", None) or "Leadport"
    firma_logo_field = None
    if hasattr(firma, "logo") and getattr(firma, "logo"):
        firma_logo_field = firma.logo
    elif hasattr(firma, "resim") and getattr(firma, "resim"):
        firma_logo_field = firma.resim
    firma_logo_url = getattr(firma_logo_field, "url", None)

    # Yardımcılar (Almanca biçim)
    def fmt_dt(dt):
        if not dt:
            return "—"
        dt = localtime(dt)
        # Örn: 11.09.2025 - Donnerstag 10:24 Uhr
        return date_format(dt, "d.m.Y - l H:i \\U\\h\\r", use_l10n=True)

    def fmt_d(d):
        if not d:
            return "—"
        return date_format(d, "d.m.Y", use_l10n=True)

    def ja_nein(v):
        return "Ja" if v else "Nein"

    # Choices (Almanca display)
    medeni_human = form.get_medeni_durum_display() if hasattr(form, "get_medeni_durum_display") else (form.medeni_durum or "—")
    sigorta_human = form.get_sigorta_display() if hasattr(form, "get_sigorta_display") else (form.sigorta or "—")
    es_cocuk_human = form.get_es_cocuk_sigorta_display() if hasattr(form, "get_es_cocuk_sigorta_display") else (form.es_cocuk_sigorta or "—")

    # Sigorta şirketi adı + logo
    sigorta_sirket_ad = getattr(getattr(form, "sigorta_sirket", None), "isim", None)
    sigorta_sirket_logo = None
    if getattr(form, "sigorta_sirket", None):
        img_field = getattr(form.sigorta_sirket, "resim", None)
        if img_field:
            sigorta_sirket_logo = getattr(img_field, "url", None)

    # Çocuk yaşları
    cocuk_yaslari = list(
        MusteriFormModelCocukYasi.objects
        .filter(form=form)
        .order_by('id')
        .values_list('cocuk_yasi', flat=True)
    )

    # Oluşturan kullanıcının adı (fallback'li)
    kullanici_fullname = "—"
    if form.kullanici:
        try:
            full = form.kullanici.get_full_name()
            kullanici_fullname = (full or "").strip() or getattr(form.kullanici, "username", str(form.kullanici))
        except Exception:
            kullanici_fullname = getattr(form.kullanici, "username", str(form.kullanici))

    # İLK NOT (en eski not)
    ilk_not = (
        MusteriFormModelNot.objects
        .filter(form=form)
        .order_by('olusturma_tarihi')
        .first()
    )
    not_ilk_icerik = getattr(ilk_not, "not_icerigi", None)
    not_kullanici_fullname = None
    not_tarih_human = None
    if ilk_not:
        if ilk_not.kullanici:
            try:
                nf = ilk_not.kullanici.get_full_name()
                not_kullanici_fullname = (nf or "").strip() or getattr(ilk_not.kullanici, "username", str(ilk_not.kullanici))
            except Exception:
                not_kullanici_fullname = getattr(ilk_not.kullanici, "username", str(ilk_not.kullanici))
        not_tarih_human = fmt_dt(getattr(ilk_not, "olusturma_tarihi", None))

    if form.posta_kodu:
        il_raw   = getattr(form.posta_kodu, "il", "")
        ilce_raw = getattr(form.posta_kodu, "ilce", "")
        pkod     = getattr(form.posta_kodu, "posta_kodu", "")

        il = (str(il_raw or "").strip())
        _ilce = str(ilce_raw or "").strip()
        ilce_first = re.split(r"[\s\-]+", _ilce, maxsplit=1)[0] if _ilce else ""
        ilce = _ilce
        sehir_ilce = " / ".join([x for x in (il, ilce_first) if x]) or ""
        posta_kodu_str = str(pkod or "")
    else:
        il = ilce = ilce_first = ""
        sehir_ilce = ""
        posta_kodu_str = str(form.posta_kodu_raw or "")

    context = {
        # Üst şerit
        "kullanici_fullname": kullanici_fullname,
        "olusturma_human": fmt_dt(getattr(form, "olusturma_tarihi", None)),
        "randevu_human": fmt_dt(getattr(form, "randevu_tarihi", None)),
        "randevu_tipi": form.randevu_tipi or "",
        "durum_human": getattr(getattr(form, "durum", None), "isim", None),

        # Firma
        "firma_isim": firma_isim,
        "firma_logo_url": firma_logo_url,

        # Kundenübersicht
        "firma_adi": form.firma_adi or "—",
        "musteri_cinsiyet": form.get_musteri_cinsiyet_display() if form.musteri_cinsiyet else None,
        "musteri_tam_ad": f"{form.musteri_isim} {form.musteri_soyisim}".strip(),
        "dogum_human": fmt_d(form.musteri_dogum_tarihi) if form.musteri_dogum_tarihi else "—",

        # İletişim
        "telefon": form.telefon or "—",
        "telefon_onayli_mi": bool(form.telefon_onayli_mi),
        "email": form.email or "—",
        "email_onayli_mi": bool(form.email_onayli_mi),
        "sabit_telefon": form.sabit_telefon,

        # Adres
        "il": il,
        "ilce": ilce,
        "ilce_first": ilce_first,
        "adres": form.adres or "",
        "sehir_ilce": sehir_ilce,
        "posta_kodu": posta_kodu_str,

        # Aile & medeni
        "medeni_durum_human": medeni_human,
        "calisma_durumu": form.calisma_durumu,
        "aile_cocuk_sayisi": form.aile_cocuk_sayisi if form.aile_cocuk_sayisi is not None else "—",
        "cocuk_yaslari": cocuk_yaslari if cocuk_yaslari else None,

        # Sigorta & partner
        "sigorta_human": sigorta_human,
        "sigorta_sirket_ad": sigorta_sirket_ad,
        "sigorta_sirket_logo": sigorta_sirket_logo,
        "sigorta_baslangic_human": fmt_d(form.sigorta_baslangic_tarihi) if form.sigorta_baslangic_tarihi else "—",
        "sigorta_vade_human": form.sigorta_tarife_vadesi.isim if form.sigorta_tarife_vadesi else "—",
        "sigorta_katilim_payi": form.sigorta_katilim_payi if form.sigorta_katilim_payi is not None else "—",
        "sigorta_katki_payi": form.sigorta_katki_payi if form.sigorta_katki_payi is not None else "—",
        "sigorta_ek_yazi": form.sigorta_ek_yazi or "—",
        "es_cocuk_sigorta_human": es_cocuk_human,
        "es_yasi": form.es_yasi if form.es_yasi is not None else "—",

        # İlk not (Notizen kutusu)
        "not_ilk_icerik": not_ilk_icerik,
        "not_kullanici_fullname": not_kullanici_fullname,
        "not_tarih_human": not_tarih_human,
    }

    html = render_to_string("forms/form_detail_pdf.html", context=context, request=request)
    return HttpResponse(html)


@login_required
@require_POST
def form_sil(request, pk):
    if request.user.rol != 'Yönetici' and not request.user.is_superuser and request.user.rol != 'Admin':
        if request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return JsonResponse({"ok": False, "error": "Yetkiniz yok"}, status=403)
        return redirect('panel')
    try:
        obj = MusteriFormModel.objects.get(pk=pk)
    except MusteriFormModel.DoesNotExist:
        raise Http404
    if request.user != obj.kullanici and request.user.rol != 'Yönetici' and not request.user.is_superuser:
        return JsonResponse({"ok": False, "error": "Yetkiniz yok"}, status=403)
    
    # Log oluştur (silmeden önce)
    from .utils.logger import log_form_delete
    log_form_delete(form=obj, user=request.user, request=request)
    
    obj.delete()
    if request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return JsonResponse({"ok": True})
    return redirect("panel")




def _user_is_privileged(user):
    return user.is_superuser or getattr(user, "rol", "") in ("Admin", "Yönetici")

def _user_can_view_form(user, form_obj: MusteriFormModel) -> bool:
    if _user_is_privileged(user):
        return True
    if form_obj.kullanici_id == user.id:
        return True
    # Kendisiyle paylaşılmış mı?
    return MusteriFormModelPaylasim.objects.filter(form=form_obj, kullanici=user).exists()

def _user_can_edit_note(user, note: MusteriFormModelNot) -> bool:
    # SADECE SAHİBİ düzenleyebilir/silebilir (admin/süperuser dahil kimse başkasını editleyemez)
    return note.kullanici_id == user.id

@login_required
@require_http_methods(["GET", "POST"])
def ajax_form_notlar(request, form_id: int):
    form = get_object_or_404(MusteriFormModel, pk=form_id)
    if not _user_can_view_form(request.user, form):
        return HttpResponseForbidden("Yetkisiz erişim.")

    if request.method == "GET":
        # En eskiden yeniye
        notlar = (
            MusteriFormModelNot.objects
            .filter(form=form)
            .select_related("kullanici")
            .order_by("-olusturma_tarihi", "id")
        )
        data = []
        for n in notlar:
            data.append({
                "id": n.id,
                "kullanici": n.kullanici.get_full_name() or n.kullanici.username if n.kullanici else "—",
                "kullanici_id": n.kullanici_id,
                "icerik": n.not_icerigi or "",
                "olusturma": timezone.localtime(n.olusturma_tarihi).strftime("%d.%m.%Y %H:%M") if n.olusturma_tarihi else "",
                "guncelleme": timezone.localtime(n.son_guncelleme_tarihi).strftime("%d.%m.%Y %H:%M") if n.son_guncelleme_tarihi else "",
                "duzenlenebilir": (n.kullanici_id == request.user.id),
            })
        return JsonResponse({"ok": True, "items": data})

    # POST -> yeni not
    icerik = (request.POST.get("icerik") or "").strip()
    if not icerik:
        return JsonResponse({"ok": False, "error": "Not içeriği boş olamaz."}, status=400)

    note = MusteriFormModelNot.objects.create(
        form=form,
        kullanici=request.user,
        not_icerigi=icerik,
    )
    
    # Not ekleme logu
    from .utils.logger import log_note_add
    log_note_add(form=form, note_content=icerik, user=request.user, request=request)
    return JsonResponse({
        "ok": True,
        "item": {
            "id": note.id,
            "kullanici": request.user.get_full_name() or request.user.username,
            "kullanici_id": request.user.id,
            "icerik": note.not_icerigi,
            "olusturma": timezone.localtime(note.olusturma_tarihi).strftime("%d.%m.%Y %H:%M") if note.olusturma_tarihi else "",
            "guncelleme": timezone.localtime(note.son_guncelleme_tarihi).strftime("%d.%m.%Y %H:%M") if note.son_guncelleme_tarihi else "",
            "duzenlenebilir": True,
        }
    })
    

@login_required
@require_http_methods(["PATCH", "POST", "DELETE"])
def ajax_not_guncelle(request, not_id: int):
    note = get_object_or_404(MusteriFormModelNot.objects.select_related("form"), pk=not_id)

    if not _user_can_view_form(request.user, note.form):
        return HttpResponseForbidden("Yetkisiz erişim.")
    if request.method in ("PATCH", "POST"):
        if not _user_can_edit_note(request.user, note):
            return HttpResponseForbidden("Bu notu düzenleme yetkiniz yok.")
        # PATCH/POST ile içerik güncelle
        icerik = (request.POST.get("icerik") or "").strip()
        if not icerik:
            return JsonResponse({"ok": False, "error": "Not içeriği boş olamaz."}, status=400)
            
        # Eski değeri kaydet
        old_content = note.not_icerigi
        
        # Güncelle
        note.not_icerigi = icerik
        note.save(update_fields=["not_icerigi", "son_guncelleme_tarihi"])
        
        # Not güncelleme logu
        from .utils.logger import log_custom_action
        log_custom_action(
            action_type='NOTE_UPDATE',
            title='Not Güncellendi',
            description=f'"{note.form.musteri_isim} {note.form.musteri_soyisim}" adlı müşterinin formundaki not güncellendi.',
            user=request.user,
            request=request,
            related_form=note.form,
            old_values={'not_icerigi': old_content},
            new_values={'not_icerigi': icerik},
            details={
                'musteri_adi': f"{note.form.musteri_isim} {note.form.musteri_soyisim}",
                'form_id': note.form.id,
                'not_id': note.id,
            }
        )
        
        return JsonResponse({"ok": True})
    else:
        # DELETE
        if not _user_can_edit_note(request.user, note):
            return HttpResponseForbidden("Bu notu silme yetkiniz yok.")
            
        # Not silme logu
        from .utils.logger import log_custom_action
        log_custom_action(
            action_type='NOTE_DELETE',
            title='Not Silindi',
            description=f'"{note.form.musteri_isim} {note.form.musteri_soyisim}" adlı müşterinin formundaki not silindi.',
            user=request.user,
            request=request,
            related_form=note.form,
            old_values={'not_icerigi': note.not_icerigi},
            details={
                'musteri_adi': f"{note.form.musteri_isim} {note.form.musteri_soyisim}",
                'form_id': note.form.id,
                'not_id': note.id,
            }
        )
        
        note.delete()
        return JsonResponse({"ok": True})
    


def _is_privileged(user):
    return user.is_superuser or getattr(user, "rol", "") in ("Admin", "Yönetici")

@login_required(login_url='giris')
@require_GET
def api_form_paylasimlari(request, form_id):
    if not _is_privileged(request.user):
        return HttpResponseForbidden("Forbidden")

    try:
        form = MusteriFormModel.objects.select_related("kullanici").get(pk=form_id)
    except MusteriFormModel.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Form nicht gefunden."}, status=404)

    paylasimlar = (MusteriFormModelPaylasim.objects
                   .select_related("kullanici")
                   .filter(form=form, kullanici__isnull=False)
                   .order_by("kullanici__first_name", "kullanici__last_name"))

    data = [{
        "id": p.id,
        "kullanici_id": p.kullanici_id,
        "ad": f"{p.kullanici.first_name} {p.kullanici.last_name}".strip() or p.kullanici.username,
        "username": p.kullanici.username,
    } for p in paylasimlar]

    return JsonResponse({"ok": True, "items": data})

@login_required(login_url='giris')
@require_POST
@transaction.atomic
def api_form_paylasim_ekle(request):
    if not _is_privileged(request.user):
        return HttpResponseForbidden("Forbidden")

    form_id = request.POST.get("form_id")
    kullanici_id = request.POST.get("kullanici_id")

    if not form_id or not kullanici_id:
        return JsonResponse({"ok": False, "error": "Pflichtfelder fehlen."}, status=400)

    try:
        form = MusteriFormModel.objects.get(pk=form_id)
        hedef = CustomUser.objects.get(pk=kullanici_id, aktif=True, silinme_tarihi__isnull=True)
    except (MusteriFormModel.DoesNotExist, CustomUser.DoesNotExist):
        return JsonResponse({"ok": False, "error": "Form oder Benutzer nicht gefunden."}, status=404)

    # Kendine paylaşmayı engellemek (opsiyonel)
    # if form.kullanici_id == hedef.id:
    #     return JsonResponse({"ok": False, "error": "Kann nicht mit sich selbst teilen."}, status=400)

    try:
        paylasim, created = MusteriFormModelPaylasim.objects.get_or_create(form=form, kullanici=hedef)
        if not created:
            return JsonResponse({"ok": False, "error": "Bereits freigegeben."}, status=409)
    except IntegrityError:
        return JsonResponse({"ok": False, "error": "Bereits freigegeben."}, status=409)

    # Form paylaşım logu
    from .utils.logger import log_form_share
    log_form_share(
        form=form,
        shared_with_user=hedef,
        user=request.user,
        request=request
    )

    return JsonResponse({"ok": True, "id": paylasim.id})

@login_required(login_url='giris')
@require_POST
@transaction.atomic
def api_form_paylasim_sil(request):
    if not _is_privileged(request.user):
        return HttpResponseForbidden("Forbidden")

    paylasim_id = request.POST.get("paylasim_id")
    if not paylasim_id:
        return JsonResponse({"ok": False, "error": "Pflichtfelder fehlen."}, status=400)

    deleted = MusteriFormModelPaylasim.objects.filter(pk=paylasim_id).delete()[0]
    if not deleted:
        return JsonResponse({"ok": False, "error": "Freigabe nicht gefunden."}, status=404)

    return JsonResponse({"ok": True})








def abs_url(request, url_or_path: str | None) -> str | None:
    """
    Görselleri absolute URL'e çevirir (e-posta için şart).
    request varsa onu kullan (doğru host), yoksa settings.SITE_URL'e düşer.
    """
    if not url_or_path:
        return None
    if request is not None:
        return request.build_absolute_uri(url_or_path)
    base = getattr(settings, "SITE_URL", "")
    return urljoin(base, url_or_path)

def get_firma_context(request):
    """
    Tekil Firma kaydını okuyup şablon context'i döner.
    Logo/Icon absolute URL'e çevrilir (e-posta uyumlu).
    """
    f = Firma.objects.first()
    if not f:
        return {
            "firma_isim": "—",
            "firma_logo_url": None,
            "firma_icon_url": None,
            "firma_telefon": None,
            "firma_adres": None,
        }
    return {
        "firma_isim": f.isim or "—",
        "firma_logo_url": abs_url(request, f.logo.url) if f.logo else None,
        "firma_icon_url": abs_url(request, f.icon.url) if f.icon else None,
        "firma_telefon": f.telefon,
        "firma_adres": f.adres,
    }


def _get_smtp_connection():
    smtp = Smtp.objects.first()
    if not smtp:
        raise Exception("SMTP ayarları bulunamadı. Lütfen admin panelinden SMTP ayarlarını yapılandırın.")
    return get_connection(
        host=smtp.host,
        port=smtp.port,
        username=smtp.username,
        password=smtp.password,
        use_tls=smtp.use_tls,
        use_ssl=smtp.use_ssl,
        timeout=60,
    )

def send_form_mail_html(subject, recipients:list[str], template_name:str, context:dict, from_email:str|None=None):
    """
    HTML + text alternatifli mail gönderir.
    context içindeki görsel URL'leri daha önce absolute yapılmış olmalı.
    """
    html = render_to_string(template_name, context)
    text = strip_tags(html)
    conn = _get_smtp_connection()

    if not from_email:
        smtp = Smtp.objects.first()
        if not smtp:
            raise Exception("SMTP ayarları bulunamadı. Lütfen admin panelinden SMTP ayarlarını yapılandırın.")
        from_email = smtp.username

    msg = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=from_email,
        to=recipients,
        connection=conn,
    )
    msg.attach_alternative(html, "text/html")
    return msg.send()

def _split_and_validate_emails(raw:str) -> list[str]:
    emails = [e.strip() for e in (raw or "").replace(";", ",").split(",") if e.strip()]
    valid = []
    for e in emails:
        try:
            validate_email(e)
            valid.append(e)
        except ValidationError:
            pass
    # uniq + preserve order
    return list(dict.fromkeys(valid))

def _status_to_de(name:str|None) -> str|None:
    """
    Durum adını Almanca'ya çevirir; bilinmiyorsa aynen bırakır.
    """
    if not name:
        return None
    m = {
        "Beklemede": "Ausstehend",
        "Onaylandı": "Bestätigt",
        "Randevu Alındı": "Termin vereinbart",
        "İptal": "Storniert",
        "Ret": "Abgelehnt",
        "Açık": "Offen",
        # EN varyantları:
        "Pending": "Ausstehend",
        "Approved": "Bestätigt",
        "Cancelled": "Storniert",
        "Rejected": "Abgelehnt",
    }
    return m.get(name, name)

@login_required
def logs_view(request):
    """Sistem logları görüntüleme sayfası - sadece adminler erişebilir"""
    # Sadece admin ve yöneticiler erişebilir
    if not (request.user.is_superuser or request.user.rol in ['Admin', 'Yönetici']):
        return redirect('panel')
    
    from .models import SystemLog
    from django.utils import timezone
    
    # Filtreleme parametreleri
    action_type = request.GET.get('action_type', '')
    severity = request.GET.get('severity', '')
    user_id = request.GET.get('user_id', '')
    date_from = request.GET.get('date_from', '')
    date_to = request.GET.get('date_to', '')
    time_from = request.GET.get('time_from', '')
    time_to = request.GET.get('time_to', '')
    last_days = request.GET.get('last_days', '')
    ip_address = request.GET.get('ip_address', '')
    customer_name = request.GET.get('customer_name', '')
    company_name = request.GET.get('company_name', '')
    has_changes = request.GET.get('has_changes', '')
    search = request.GET.get('search', '')
    
    # Query oluştur
    logs = SystemLog.objects.select_related('kullanici', 'related_form', 'related_user').all()
    
    # Filtreler
    if action_type:
        logs = logs.filter(action_type=action_type)
    if severity:
        logs = logs.filter(severity=severity)
    if user_id:
        logs = logs.filter(kullanici_id=user_id)
    
    # Tarih filtreleri
    if last_days:
        from datetime import timedelta
        days_ago = timezone.now() - timedelta(days=int(last_days))
        logs = logs.filter(timestamp__gte=days_ago)
    else:
        if date_from:
            if time_from:
                # Tarih + saat kombinasyonu
                from datetime import datetime
                datetime_from = datetime.strptime(f"{date_from} {time_from}", "%Y-%m-%d %H:%M")
                logs = logs.filter(timestamp__gte=datetime_from)
            else:
                logs = logs.filter(timestamp__date__gte=date_from)
        
        if date_to:
            if time_to:
                # Tarih + saat kombinasyonu
                from datetime import datetime
                datetime_to = datetime.strptime(f"{date_to} {time_to}", "%Y-%m-%d %H:%M")
                logs = logs.filter(timestamp__lte=datetime_to)
            else:
                logs = logs.filter(timestamp__date__lte=date_to)
    
    # IP adresi filtresi
    if ip_address:
        logs = logs.filter(ip_address__icontains=ip_address)
    
    # Müşteri adı filtresi
    if customer_name:
        logs = logs.filter(
            Q(related_form__musteri_isim__icontains=customer_name) |
            Q(related_form__musteri_soyisim__icontains=customer_name)
        )
    
    # Firma adı filtresi
    if company_name:
        logs = logs.filter(related_form__firma_adi__icontains=company_name)
    
    # Değişiklik filtresi
    if has_changes == 'true':
        logs = logs.exclude(details__changed_fields={})
    elif has_changes == 'false':
        logs = logs.filter(details__changed_fields={})
    
    # Genel arama
    if search:
        logs = logs.filter(
            Q(title__icontains=search) | 
            Q(description__icontains=search) |
            Q(kullanici__username__icontains=search) |
            Q(kullanici__first_name__icontains=search) |
            Q(kullanici__last_name__icontains=search) |
            Q(related_form__musteri_isim__icontains=search) |
            Q(related_form__musteri_soyisim__icontains=search) |
            Q(related_form__firma_adi__icontains=search)
        )
    
    # Sayfalama
    from django.core.paginator import Paginator
    paginator = Paginator(logs.order_by('-timestamp'), 50)  # Sayfa başına 50 log
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # İstatistikler
    stats = {
        'total_logs': SystemLog.objects.count(),
        'today_logs': SystemLog.objects.filter(timestamp__date=timezone.now().date()).count(),
        'status_changes': SystemLog.objects.filter(action_type='STATUS_CHANGE').count(),
        'form_creates': SystemLog.objects.filter(action_type='FORM_CREATE').count(),
        'form_updates': SystemLog.objects.filter(action_type='FORM_UPDATE').count(),
        'form_deletes': SystemLog.objects.filter(action_type='FORM_DELETE').count(),
    }
    
    # Son aktiviteler (dashboard için)
    recent_activities = SystemLog.objects.select_related('kullanici', 'related_form').order_by('-timestamp')[:10]
    
    # Kullanıcı listesi (filtre için)
    from user.models import CustomUser
    users = CustomUser.objects.filter(aktif=True).order_by('username')
    
    context = {
        'page_obj': page_obj,
        'stats': stats,
        'recent_activities': recent_activities,
        'users': users,
        'action_types': SystemLog.ACTION_TYPES,
        'severity_levels': SystemLog.SEVERITY_LEVELS,
        'current_filters': {
            'action_type': action_type,
            'severity': severity,
            'user_id': user_id,
            'date_from': date_from,
            'date_to': date_to,
            'time_from': time_from,
            'time_to': time_to,
            'last_days': last_days,
            'ip_address': ip_address,
            'customer_name': customer_name,
            'company_name': company_name,
            'has_changes': has_changes,
            'search': search,
        }
    }
    
    # Dışa aktar isteği
    if request.GET.get('export') == 'csv':
        import csv
        from django.http import HttpResponse
        
        response = HttpResponse(content_type='text/csv; charset=utf-8')
        response['Content-Disposition'] = 'attachment; filename="sistem_loglari.csv"'
        
        # BOM ekle (Excel uyumluluğu için)
        response.write('\ufeff')
        
        writer = csv.writer(response)
        
        # Başlık satırı
        writer.writerow([
            'Zaman', 'Kullanıcı', 'E-posta', 'Aksiyon', 'Başlık', 'Önem', 
            'Açıklama', 'IP Adresi', 'Müşteri', 'Firma', 'Tarayıcı'
        ])
        
        # Log verileri
        for log in logs.order_by('-timestamp'):
            writer.writerow([
                log.get_formatted_timestamp(),
                log.kullanici.username if log.kullanici else 'Sistem',
                log.kullanici.email if log.kullanici and log.kullanici.email else '',
                log.get_action_type_display(),
                log.title,
                log.get_severity_display(),
                log.description,
                log.ip_address or '',
                f"{log.related_form.musteri_isim} {log.related_form.musteri_soyisim}" if log.related_form else '',
                log.related_form.firma_adi if log.related_form else '',
                log.user_agent or ''
            ])
        
        return response
    
    return render(request, 'logs.html', context)


@require_GET
@login_required
def ajax_email_paylasim_gecmis(request):
    form_id = request.GET.get("form_id")
    if not form_id:
        return HttpResponseBadRequest("form_id erforderlich")
    try:
        form = MusteriFormModel.objects.get(pk=form_id)
    except MusteriFormModel.DoesNotExist:
        return HttpResponseBadRequest("Formular nicht gefunden")

    items = (EmailGonderimleri.objects
             .filter(form=form)
             .order_by("-gonderim_tarihi")
             .values("gonderilen_email","gonderim_tarihi"))
    data = [{
        "gonderilen_email": i["gonderilen_email"],
        "gonderim_tarihi": timezone.localtime(i["gonderim_tarihi"]).strftime("%d.%m.%Y %H:%M")
    } for i in items]
    return JsonResponse({"ok": True, "items": data})

def _fmt_dt_de(dt):
    if not dt:
        return None
    dt = timezone.localtime(dt)
    # Örn: 11.09.2025 - Donnerstag 10:24 Uhr
    return date_format(dt, "d.m.Y - l H:i \\U\\h\\r", use_l10n=True)

def _fmt_d_de(d):
    if not d:
        return None
    return date_format(d, "d.m.Y", use_l10n=True)

@require_POST
@login_required
def ajax_email_paylasim_gonder(request):
    form_id = request.POST.get("form_id")
    to_raw  = request.POST.get("to")
    subject = request.POST.get("subject") or "Formulardetails"

    if not form_id or not to_raw:
        return JsonResponse({"ok": False, "error": "Formular und Empfänger sind erforderlich."}, status=400)

    try:
        form = (
            MusteriFormModel.objects
            .select_related("kullanici", "sigorta_sirket", "posta_kodu", "durum")
            .get(pk=form_id)
        )
    except MusteriFormModel.DoesNotExist:
        return JsonResponse({"ok": False, "error": "Formular nicht gefunden."}, status=404)

    recipients = _split_and_validate_emails(to_raw)
    if not recipients:
        return JsonResponse({"ok": False, "error": "Bitte mindestens eine gültige E-Mail-Adresse eingeben."}, status=400)

    # Yerelleştirme
    translation.activate('de')

    # Firma (ABS URL ile)
    firma_ctx = get_firma_context(request)  # { "firma_isim": ..., "firma_logo_url": ... }

    # Sigorta logo absolute URL
    sigorta_logo_abs = None
    if getattr(form, "sigorta_sirket_id", None) and getattr(form.sigorta_sirket, "resim", None):
        try:
            sigorta_logo_abs = abs_url(request, form.sigorta_sirket.resim.url)
        except Exception:
            sigorta_logo_abs = getattr(form.sigorta_sirket.resim, "url", None)

    # Oluşturan kullanıcı adı
    if form.kullanici:
        try:
            full = (form.kullanici.get_full_name() or "").strip()
            kullanici_fullname = full or getattr(form.kullanici, "username", str(form.kullanici))
        except Exception:
            kullanici_fullname = getattr(form.kullanici, "username", str(form.kullanici))
    else:
        kullanici_fullname = "—"

    # İlk not (en eski)
    ilk_not = (
        MusteriFormModelNot.objects
        .filter(form=form)
        .order_by('olusturma_tarihi')
        .first()
    )
    not_ilk_icerik = getattr(ilk_not, "not_icerigi", None)
    if ilk_not and ilk_not.kullanici:
        try:
            nf = (ilk_not.kullanici.get_full_name() or "").strip()
            not_kullanici_fullname = nf or getattr(ilk_not.kullanici, "username", str(ilk_not.kullanici))
        except Exception:
            not_kullanici_fullname = getattr(ilk_not.kullanici, "username", str(ilk_not.kullanici))
    else:
        not_kullanici_fullname = None
    not_tarih_human = _fmt_dt_de(getattr(ilk_not, "olusturma_tarihi", None)) if ilk_not else None

    # Adres parçaları — Sehir FK'sından doğru çıkarım
    if form.posta_kodu_id:
        il   = getattr(form.posta_kodu, "il", None)
        ilce = getattr(form.posta_kodu, "ilce", None)
        sehir_ilce = " / ".join([x for x in [il, ilce] if x]) or ""
        posta_kodu_str = str(getattr(form.posta_kodu, "posta_kodu", "") or "")
    else:
        sehir_ilce = ""
        posta_kodu_str = str(getattr(form, "posta_kodu_raw", "") or "")

    # Context (PDF ile aynı alan isimleri, e-posta için ABS logolar)
    ctx = {
        # Üst şerit
        "kullanici_fullname": kullanici_fullname,
        "musteri_cinsiyet": form.get_musteri_cinsiyet_display() if form.musteri_cinsiyet else None,
        "olusturma_human": _fmt_dt_de(getattr(form, "olusturma_tarihi", None)) or "—",
        "randevu_human": _fmt_dt_de(getattr(form, "randevu_tarihi", None)) or "—",
        "randevu_tipi": form.randevu_tipi or "",
        "durum_human": _status_to_de(getattr(getattr(form, "durum", None), "isim", None)) or "—",

        # Firma (header ortası)
        **firma_ctx,  # firma_isim, firma_logo_url (ABS)

        # Kundenübersicht
        "firma_adi": form.firma_adi or "—",
        "musteri_tam_ad": f"{form.musteri_isim} {form.musteri_soyisim}".strip() or "—",
        "dogum_human": _fmt_d_de(form.musteri_dogum_tarihi) if form.musteri_dogum_tarihi else "—",
        "telefon": form.telefon or "—",
        "sabit_telefon": form.sabit_telefon or "—",
        "email": form.email or "—",

        # Adres
        "adres": form.adres or "",
        "sehir_ilce": sehir_ilce,
        "posta_kodu": posta_kodu_str,

        # Familie & Zivilstand
        "medeni_durum_human": form.get_medeni_durum_display() if form.medeni_durum else "—",
        "calisma_durumu": form.calisma_durumu,
        "aile_cocuk_sayisi": form.aile_cocuk_sayisi if form.aile_cocuk_sayisi is not None else "—",
        "cocuk_yaslari": list(form.musteriformmodelcocukyasi_set.values_list("cocuk_yasi", flat=True)) or None,

        # Sigorta & partner
        "sigorta_sirket_logo": sigorta_logo_abs,
        "sigorta_sirket_ad": getattr(form.sigorta_sirket, "isim", None) if form.sigorta_sirket_id else None,
        "sigorta_human": form.get_sigorta_display() if form.sigorta else None,
        "sigorta_baslangic_human": _fmt_d_de(form.sigorta_baslangic_tarihi) if form.sigorta_baslangic_tarihi else "—",
        "sigorta_vade_human": form.sigorta_tarife_vadesi.isim if form.sigorta_tarife_vadesi else "—",
        "sigorta_katilim_payi": form.sigorta_katilim_payi if form.sigorta_katilim_payi is not None else "—",
        "sigorta_katki_payi": form.sigorta_katki_payi if form.sigorta_katki_payi is not None else "—",
        "es_cocuk_sigorta_human": form.get_es_cocuk_sigorta_display() if form.es_cocuk_sigorta else None,
        "es_yasi": form.es_yasi if form.es_yasi is not None else "—",
        "sigorta_ek_yazi": form.sigorta_ek_yazi or "—",

        # Notizen (ilk not)
        "not_ilk_icerik": not_ilk_icerik,
        "not_kullanici_fullname": not_kullanici_fullname,
        "not_tarih_human": not_tarih_human,
    }

    try:
        sent_count = send_form_mail_html(
            subject=subject,
            recipients=recipients,
            template_name="emails/form_detail_email_inline.html",
            context=ctx,
        )
    except Exception as e:
        return JsonResponse({"ok": False, "error": f"E-Mail konnte nicht gesendet werden: {e}"}, status=500)

    EmailGonderimleri.objects.create(
        form=form,
        kullanici=request.user if request.user.is_authenticated else None,
        gonderilen_email=", ".join(recipients),
    )

    # E-posta gönderim logu
    from .utils.logger import log_email_send
    for recipient in recipients:
        log_email_send(
            form=form,
            email_address=recipient,
            user=request.user,
            request=request
        )

    return JsonResponse({"ok": True, "sent": sent_count})
