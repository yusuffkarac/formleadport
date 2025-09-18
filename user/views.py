from django.shortcuts import render, redirect
from django.contrib.auth import login
from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm
from django.conf import settings
from datetime import timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model, logout, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.core.mail import get_connection, EmailMultiAlternatives
from django.template.loader import render_to_string
from yonetim.models import Smtp
from django.contrib.auth.forms import SetPasswordForm
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from user.models import CustomUser, SifreSifirlamaTalebi
from .forms import ProfilForm, PasswortAendernForm
import secrets
import logging

# Logger'ı ayarla
logger = logging.getLogger(__name__)
# Create your views here.

def giris(request):
    if request.method == "POST":
        form = AuthenticationForm(request, data=request.POST)
        remember = request.POST.get("remember") == "on"
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            if remember:
                request.session.set_expiry(getattr(settings, "REMEMBER_ME_AGE", 60 * 60 * 24 * 30))
            else:
                request.session.set_expiry(0)
            
            # Log oluştur
            from sayfalar.utils.logger import log_user_login
            log_user_login(user=user, request=request)
            
            return redirect("panel")
    else:
        form = AuthenticationForm(request)
    return render(request, "auth/giris.html", {"form": form})

@login_required(login_url='giris')
def cikis(request):
    if request.user.is_authenticated:
        # Log oluştur (çıkış yapmadan önce)
        from sayfalar.utils.logger import log_user_logout
        log_user_logout(user=request.user, request=request)
        
        logout(request)
        return redirect("giris")
    return redirect("giris")

@login_required(login_url='giris')
def profil_goruntule(request):
    return render(request, "user/profil_goruntule.html", {"user": request.user})

@login_required(login_url='giris')
def profil_duzenle(request):
    profile_form = ProfilForm(instance=request.user)
    password_form = PasswortAendernForm(user=request.user)

    if request.method == "POST":
        form_type = request.POST.get("form_type")

        if form_type == "profile":
            profile_form = ProfilForm(request.POST, request.FILES, instance=request.user)
            if profile_form.is_valid():
                # Eski değerleri kaydet
                old_values = {
                    'first_name': request.user.first_name,
                    'last_name': request.user.last_name,
                    'email': request.user.email,
                    'resim': request.user.resim.url if request.user.resim else None,
                    'resim_changed': False,
                }
                
                # Formu kaydet
                user = profile_form.save()
                
                # Yeni değerleri al
                new_values = {
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'email': user.email,
                    'resim': user.resim.url if user.resim else None,
                    'resim_changed': 'resim' in request.FILES,
                }
                
                # Değişen alanları tespit et
                changed_fields = {}
                for key in old_values:
                    if old_values[key] != new_values[key]:
                        changed_fields[key] = {
                            'old': old_values[key],
                            'new': new_values[key]
                        }
                
                # Profil güncelleme logu
                from sayfalar.utils.logger import log_custom_action
                log_custom_action(
                    action_type='PROFILE_UPDATE',
                    title='Profil Güncellendi',
                    description=f'"{request.user.username}" kullanıcısının profili güncellendi.',
                    user=request.user,
                    request=request,
                    related_user=request.user,
                    old_values=old_values,
                    new_values=new_values,
                    details={
                        'kullanici_adi': request.user.username,
                        'kullanici_rol': getattr(request.user, 'rol', 'Bilinmiyor'),
                        'changed_fields': changed_fields,
                    }
                )
                messages.success(request, "Profil wurde erfolgreich aktualisiert.")
                return redirect("profil_duzenle")
            else:
                messages.error(request, "Bitte prüfe die markierten Felder.")

        elif form_type == "password":
            password_form = PasswortAendernForm(user=request.user, data=request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                # Şifre değiştirme logu
                from sayfalar.utils.logger import log_custom_action
                log_custom_action(
                    action_type='PASSWORD_CHANGE',
                    title='Şifre Değiştirildi',
                    description=f'"{request.user.username}" kullanıcısının şifresi değiştirildi.',
                    user=request.user,
                    request=request,
                    related_user=request.user,
                    details={
                        'kullanici_adi': request.user.username,
                        'kullanici_rol': getattr(request.user, 'rol', 'Bilinmiyor'),
                    }
                )
                messages.success(request, "Passwort wurde erfolgreich geändert.")
                return redirect("profil_duzenle")
            else:
                messages.error(request, "Passwort konnte nicht geändert werden. Bitte prüfe die Eingaben.")
                return render(request, "user/profil_duzenle.html", {
                    "form": profile_form,
                    "password_form": password_form,
                    "open_password_modal": True,
                    "user": request.user
                })

    return render(request, "user/profil_duzenle.html", {
        "form": profile_form,
        "password_form": password_form,
        "user": request.user
    })


def get_client_ip(request):
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR", "")

def sifremi_unuttum(request):
    PASSWORD_RESET_TTL_MIN = getattr(settings, "PASSWORD_RESET_TTL_MIN", 30)
    form_errors = None
    email_error = None
    email_value = ""
    
    if request.method == "POST":
        email_value = (request.POST.get("email") or "").strip()
        
        if not email_value:
            email_error = "Bitte geben Sie eine E-Mail-Adresse ein."
        else:
            try:
                validate_email(email_value)
            except ValidationError:
                email_error = "Bitte geben Sie eine gültige E-Mail-Adresse ein."
        
        if email_error:
            return render(request, "auth/sifremi_unuttum.html", {"form_errors": form_errors, "email_error": email_error, "email": email_value})
        
        user = CustomUser.objects.filter(email__iexact=email_value, is_active=True).first()
        
        if user:
            # Eski token'ları temizle
            SifreSifirlamaTalebi.objects.filter(user=user, used_at__isnull=True, expires_at__lt=timezone.now()).delete()
            
            # Yeni token oluştur
            token = secrets.token_hex(32)
            
            prr = SifreSifirlamaTalebi.objects.create(
                user=user,
                token=token,
                expires_at=timezone.now() + timedelta(minutes=PASSWORD_RESET_TTL_MIN),
                ip=get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", "")[:1024],
            )
            
            reset_url = request.build_absolute_uri(reverse("sifre_yenile", args=[prr.token]))
            
            # SMTP ayarlarını kontrol et
            smtp = Smtp.objects.first()
            if not smtp:
                messages.error(request, "SMTP ayarları bulunamadı. Lütfen admin panelinden SMTP ayarlarını yapılandırın.")
                return redirect("giris")
            
            # Email bağlantısı oluştur
            try:
                connection = get_connection(
                    "django.core.mail.backends.smtp.EmailBackend",
                    host=smtp.host,
                    port=smtp.port,
                    username=smtp.username,
                    password=smtp.password,
                    use_tls=smtp.use_tls,
                    use_ssl=smtp.use_ssl,
                )
            except Exception as e:
                messages.error(request, f"SMTP bağlantısı oluşturulamadı: {e}")
                return redirect("giris")
            
            # Email içeriği hazırla
            ctx = { "reset_url": reset_url, "firma": getattr(request, "firma", None), "ttl_min": PASSWORD_RESET_TTL_MIN, "ip": get_client_ip(request),}
            subject = f"Passwort zurücksetzen – {getattr(settings, 'PROJECT_NAME', smtp.username)}".strip() or "Passwort zurücksetzen"
            
            try:
                html_body = render_to_string("auth/email/password_reset.html", ctx)
                text_body = render_to_string("auth/email/password_reset.txt", ctx)
            except Exception as e:
                messages.error(request, f"Email template hatası: {e}")
                return redirect("giris")
            
            from_email = smtp.username
            msg = EmailMultiAlternatives(subject=subject, body=text_body, from_email=from_email, to=[email_value], connection=connection)
            msg.attach_alternative(html_body, "text/html")
            
            # Email gönder
            try:
                result = msg.send()
                print(f"Email başarıyla gönderildi: {email_value}")  # Debug için
            except Exception as e:
                print(f"Email gönderim hatası: {e}")  # Debug için
                messages.error(request, f"E-Mail konnte nicht gesendet werden: {e}")
                return redirect("giris")
        
        messages.success(request, "Wenn ein Konto mit dieser E-Mail existiert, haben wir Ihnen einen Link zum Zurücksetzen des Passworts gesendet.")
        return redirect("giris")

    return render(request, "auth/sifremi_unuttum.html", {"form_errors": form_errors, "email_error": email_error, "email": email_value})



def sifre_yenile(request, token):
    ONE_TIME_SESSION_FLAG = "reset_grant"
    token = (token or "").strip()
    prr = SifreSifirlamaTalebi.objects.select_related("user").filter(token=token).first()
    if not prr:
        messages.error(request, "Dieser Link ist ungültig oder abgelaufen.")
        return redirect("giris")
    if prr.used_at is not None:
        messages.error(request, "Dieser Link wurde bereits verwendet.")
        return redirect("giris")
    now = timezone.now()
    if now > prr.expires_at:
        messages.error(request, "Dieser Link ist ungültig oder abgelaufen.")
        return redirect("giris")
    grant_key = f"{ONE_TIME_SESSION_FLAG}:{prr.id}"
    if request.method == "GET":
        request.session[grant_key] = True
    if request.method == "POST":
        if not request.session.get(grant_key, False):
            messages.error(request, "Dieser Link wurde bereits verwendet.")
            return redirect("giris")
        form = SetPasswordForm(prr.user, request.POST)
        if form.is_valid():
            form.save()
            prr.used_at = timezone.now()
            prr.save(update_fields=["used_at"])
            request.session.pop(grant_key, None)
            messages.success(request, "Ihr Passwort wurde erfolgreich aktualisiert.")
            return redirect("giris")
        else:
            messages.error(request, "Bitte prüfen Sie die Eingaben.")
    else:
        form = SetPasswordForm(prr.user)

    return render(request, "auth/sifre_yenile.html", {"form": form})