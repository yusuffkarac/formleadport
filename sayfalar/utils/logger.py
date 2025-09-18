"""
Sistem logları için utility fonksiyonları
Bu modül sayesinde herhangi bir yerde kolayca log ekleyebilirsiniz.
"""

import json
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from ..models import SystemLog, MusteriFormModel

User = get_user_model()


def get_client_ip(request):
    """İstekten IP adresini alır"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_user_agent(request):
    """İstekten user agent bilgisini alır"""
    return request.META.get('HTTP_USER_AGENT', '')


def create_log(
    action_type,
    title,
    description,
    user=None,
    request=None,
    severity='INFO',
    related_form=None,
    related_user=None,
    old_values=None,
    new_values=None,
    details=None
):
    """
    Sistem logu oluşturur
    
    Args:
        action_type (str): Aksiyon tipi (SystemLog.ACTION_TYPES'dan biri)
        title (str): Log başlığı
        description (str): Log açıklaması
        user (User, optional): İşlemi yapan kullanıcı
        request (HttpRequest, optional): HTTP isteği (IP ve user agent için)
        severity (str): Önem derecesi (INFO, WARNING, ERROR, SUCCESS)
        related_form (MusteriFormModel, optional): İlgili form
        related_user (User, optional): İlgili kullanıcı
        old_values (dict, optional): Eski değerler
        new_values (dict, optional): Yeni değerler
        details (dict, optional): Ek detaylar
    
    Returns:
        SystemLog: Oluşturulan log objesi
    """
    
    # Kullanıcı bilgisi
    if not user and request and hasattr(request, 'user'):
        user = request.user if request.user.is_authenticated else None
    
    # IP ve User Agent bilgisi
    ip_address = None
    user_agent = None
    if request:
        ip_address = get_client_ip(request)
        user_agent = get_user_agent(request)
    
    # Log oluştur
    log = SystemLog.objects.create(
        kullanici=user,
        action_type=action_type,
        severity=severity,
        ip_address=ip_address,
        user_agent=user_agent,
        title=title,
        description=description,
        details=details,
        related_form=related_form,
        related_user=related_user,
        old_values=old_values,
        new_values=new_values
    )
    
    return log


# Kolay kullanım için özel fonksiyonlar

def log_form_create(form, user=None, request=None):
    """Form oluşturma logu"""
    return create_log(
        action_type='FORM_CREATE',
        title=f'Yeni Form Oluşturuldu',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşteri için yeni form oluşturuldu.',
        user=user,
        request=request,
        severity='SUCCESS',
        related_form=form,
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'randevu_tarihi': form.randevu_tarihi.isoformat() if form.randevu_tarihi else None,
            'firma_adi': form.firma_adi,
        }
    )


def log_form_update(form, user=None, request=None, old_values=None, new_values=None, details=None):
    """Form güncelleme logu"""
    
    # Değişen alanları tespit et
    changed_fields = details.get('changed_fields', {}) if details else {}
    
    # Açıklama oluştur
    if changed_fields:
        field_names = {
            'musteri_isim': 'Müşteri Adı',
            'musteri_soyisim': 'Müşteri Soyadı',
            'telefon': 'Telefon',
            'email': 'E-posta',
            'randevu_tarihi': 'Randevu Tarihi',
            'firma_adi': 'Firma Adı',
            'adres': 'Adres',
            'durum': 'Durum'
        }
        
        changed_field_names = []
        for field_key, changes in changed_fields.items():
            field_name = field_names.get(field_key, field_key)
            changed_field_names.append(field_name)
        
        description = f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formu güncellendi. Değişen alanlar: {", ".join(changed_field_names)}'
    else:
        description = f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formu güncellendi.'
    
    # Detayları birleştir
    log_details = {
        'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
        'form_id': form.id,
    }
    
    if details:
        log_details.update(details)
    
    return create_log(
        action_type='FORM_UPDATE',
        title=f'Form Güncellendi',
        description=description,
        user=user,
        request=request,
        severity='INFO',
        related_form=form,
        old_values=old_values,
        new_values=new_values,
        details=log_details
    )


def log_form_delete(form, user=None, request=None):
    """Form silme logu"""
    # Tam anlık görüntü (snapshot) çıkar
    try:
        snapshot = {
            'musteri_isim': form.musteri_isim,
            'musteri_soyisim': form.musteri_soyisim,
            'musteri_dogum_tarihi': form.musteri_dogum_tarihi.isoformat() if getattr(form, 'musteri_dogum_tarihi', None) else None,
            'musteri_cinsiyet': getattr(form, 'musteri_cinsiyet', None),
            'telefon': getattr(form, 'telefon', None),
            'email': getattr(form, 'email', None),
            'randevu_tarihi': form.randevu_tarihi.isoformat() if getattr(form, 'randevu_tarihi', None) else None,
            'randevu_tipi': getattr(form, 'randevu_tipi', None),
            'firma_adi': getattr(form, 'firma_adi', None),
            'adres': getattr(form, 'adres', None),
            'sehir': getattr(form, 'sehir', None),
            'posta_kodu': getattr(getattr(form, 'posta_kodu', None), 'posta_kodu', None) or getattr(form, 'posta_kodu_raw', None),
            'medeni_durum': getattr(form, 'medeni_durum', None),
            'calisma_durumu': getattr(form, 'calisma_durumu', None),
            'aile_cocuk_sayisi': getattr(form, 'aile_cocuk_sayisi', None),
            'sigorta': getattr(form, 'sigorta', None),
            'sigorta_ek_yazi': getattr(form, 'sigorta_ek_yazi', None),
            'sigorta_katki_payi': str(getattr(form, 'sigorta_katki_payi', None) or '') or None,
            'sigorta_sirket': getattr(getattr(form, 'sigorta_sirket', None), 'isim', None),
            'sigorta_baslangic_tarihi': form.sigorta_baslangic_tarihi.isoformat() if getattr(form, 'sigorta_baslangic_tarihi', None) else None,
            'sigorta_tarife_vadesi': getattr(getattr(form, 'sigorta_tarife_vadesi', None), 'isim', None),
            'sigorta_katilim_payi': str(getattr(form, 'sigorta_katilim_payi', None) or '') or None,
            'es_cocuk_sigorta': getattr(form, 'es_cocuk_sigorta', None),
            'es_yasi': getattr(form, 'es_yasi', None),
            'durum': getattr(getattr(form, 'durum', None), 'isim', None),
        }
    except Exception:
        snapshot = {}

    return create_log(
        action_type='FORM_DELETE',
        title=f'Form Silindi',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formu silindi.',
        user=user,
        request=request,
        severity='WARNING',
        related_form=form,
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'form_id': form.id,
            'snapshot': snapshot,
        },
        old_values=snapshot,
        new_values=None,
    )


def log_status_change(form, old_status, new_status, user=None, request=None):
    """Durum değişikliği logu"""
    return create_log(
        action_type='STATUS_CHANGE',
        title=f'Durum Değiştirildi',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin durumu "{old_status}" → "{new_status}" olarak değiştirildi.',
        user=user,
        request=request,
        severity='INFO',
        related_form=form,
        old_values={'durum': old_status},
        new_values={'durum': new_status},
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'form_id': form.id,
            'eski_durum': old_status,
            'yeni_durum': new_status,
        }
    )


def log_form_share(form, shared_with_user, user=None, request=None):
    """Form paylaşım logu"""
    return create_log(
        action_type='FORM_SHARE',
        title=f'Form Paylaşıldı',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formu "{shared_with_user.username}" ile paylaşıldı.',
        user=user,
        request=request,
        severity='INFO',
        related_form=form,
        related_user=shared_with_user,
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'form_id': form.id,
            'paylasilan_kullanici': shared_with_user.username,
        }
    )


def log_email_send(form, email_address, user=None, request=None):
    """E-posta gönderim logu"""
    return create_log(
        action_type='EMAIL_SEND',
        title=f'E-posta Gönderildi',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formu "{email_address}" adresine e-posta ile gönderildi.',
        user=user,
        request=request,
        severity='SUCCESS',
        related_form=form,
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'form_id': form.id,
            'gonderilen_email': email_address,
        }
    )


def log_note_add(form, note_content, user=None, request=None):
    """Not ekleme logu"""
    return create_log(
        action_type='NOTE_ADD',
        title=f'Not Eklendi',
        description=f'"{form.musteri_isim} {form.musteri_soyisim}" adlı müşterinin formuna not eklendi.',
        user=user,
        request=request,
        severity='INFO',
        related_form=form,
        details={
            'musteri_adi': f"{form.musteri_isim} {form.musteri_soyisim}",
            'form_id': form.id,
            'not_uzunlugu': len(note_content),
        }
    )


def log_user_login(user, request=None):
    """Kullanıcı giriş logu"""
    return create_log(
        action_type='USER_LOGIN',
        title=f'Kullanıcı Girişi',
        description=f'"{user.username}" kullanıcısı sisteme giriş yaptı.',
        user=user,
        request=request,
        severity='SUCCESS',
        related_user=user,
        details={
            'kullanici_adi': user.username,
            'kullanici_rol': getattr(user, 'rol', 'Bilinmiyor'),
        }
    )


def log_user_logout(user, request=None):
    """Kullanıcı çıkış logu"""
    return create_log(
        action_type='USER_LOGOUT',
        title=f'Kullanıcı Çıkışı',
        description=f'"{user.username}" kullanıcısı sistemden çıkış yaptı.',
        user=user,
        request=request,
        severity='INFO',
        related_user=user,
        details={
            'kullanici_adi': user.username,
            'kullanici_rol': getattr(user, 'rol', 'Bilinmiyor'),
        }
    )


def log_custom_action(action_type, title, description, user=None, request=None, **kwargs):
    """Özel aksiyon logu"""
    return create_log(
        action_type=action_type,
        title=title,
        description=description,
        user=user,
        request=request,
        **kwargs
    )


# Decorator fonksiyonları

def log_action(action_type, title_template, description_template, severity='INFO'):
    """
    Fonksiyon decorator'ı - fonksiyon çalıştığında otomatik log oluşturur
    
    Kullanım:
    @log_action('FORM_CREATE', 'Form Oluşturuldu', 'Yeni form oluşturuldu')
    def create_form(request, ...):
        ...
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            # Fonksiyonu çalıştır
            result = func(*args, **kwargs)
            
            # Request objesini bul
            request = None
            for arg in args:
                if isinstance(arg, HttpRequest):
                    request = arg
                    break
            
            # Log oluştur
            try:
                create_log(
                    action_type=action_type,
                    title=title_template,
                    description=description_template,
                    user=request.user if request and hasattr(request, 'user') and request.user.is_authenticated else None,
                    request=request,
                    severity=severity
                )
            except Exception as e:
                # Log oluşturma hatası ana işlemi etkilemesin
                print(f"Log oluşturma hatası: {e}")
            
            return result
        return wrapper
    return decorator
