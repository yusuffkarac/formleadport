from django.shortcuts import render, redirect, get_object_or_404
from django.core.exceptions import ValidationError
from .models import Firma, Smtp, FooterYazi
from django.contrib.auth.decorators import login_required
from .forms import FirmaForm, SmtpForm
from django.contrib import messages
from user.models import CustomUser
from django.views.decorators.http import require_POST, require_GET
from .forms import CustomUserCreateForm, CustomUserUpdateForm
from django.utils import timezone
from django.db.models import Q
from django.urls import reverse
from takip.decorators import rol_kontrol
from sayfalar.models import MusteriFormModelDurum, SigortaSirket, SigortaAltSirket
from django.db import transaction, IntegrityError
from django.http import JsonResponse, HttpResponseBadRequest
# Create your views here.

@login_required(login_url='giris')
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
def kullanicilar(request):
    status = request.GET.get('status', 'active')
    qs = CustomUser.objects.exclude(rol='Admin')
    if status == 'deleted':
        users = qs.filter(Q(aktif=False) | Q(silinme_tarihi__isnull=False)).order_by('-date_joined')
    else:
        status = 'active'
        users = qs.filter(aktif=True).order_by('-date_joined')
    add_errors = request.session.pop('add_user_errors', None)
    add_data   = request.session.pop('add_user_data', None)
    edit_errors = request.session.pop('edit_user_errors', None)
    edit_data   = request.session.pop('edit_user_data', None)
    edit_open   = request.session.pop('edit_user_open', None)
    return render(request, "yonetim/kullanicilar.html", {
        "kullanicilar": users,
        "selected_status": status,
        "add_user_errors": add_errors,
        "add_user_data": add_data,
        "edit_user_errors": edit_errors,
        "edit_user_data": edit_data,
        "edit_user_open": edit_open,
    })

@login_required(login_url='giris')
@require_POST
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
def kullanici_ekle(request):
    form = CustomUserCreateForm(request.POST)
    if form.is_valid():
        new_user = form.save()
        
        # Kullanıcı ekleme logu
        from sayfalar.utils.logger import log_custom_action
        log_custom_action(
            action_type='USER_CREATE',
            title='Kullanıcı Oluşturuldu',
            description=f'"{new_user.username}" kullanıcısı oluşturuldu.',
            user=request.user,
            request=request,
            related_user=new_user,
            details={
                'yeni_kullanici': new_user.username,
                'olusturan_kullanici': request.user.username,
                'kullanici_rol': new_user.rol,
                'kullanici_email': new_user.email,
            }
        )
        
        messages.success(request, "Benutzer wurde erfolgreich erstellt.")
        return redirect('kullanicilar')
    request.session['add_user_errors'] = form.errors.get_json_data()
    data = request.POST.dict()
    data.pop('password1', None)
    data.pop('password2', None)
    request.session['add_user_data'] = data
    messages.error(request, "Bitte prüfen Sie die Eingaben.")
    return redirect('kullanicilar')

@login_required(login_url='giris')
@require_POST
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
def kullanici_duzenle(request):
    user_id = request.POST.get('user_id')
    user_obj = get_object_or_404(CustomUser, pk=user_id)
    
    # Eski değerleri kaydet (log için)
    old_values = {
        'first_name': user_obj.first_name,
        'last_name': user_obj.last_name,
        'email': user_obj.email,
        'username': user_obj.username,
        'rol': user_obj.rol,
        'aktif': user_obj.aktif,
    }
    
    form = CustomUserUpdateForm(request.POST, instance=user_obj)
    if form.is_valid():
        u = form.save(commit=False)
        if u.aktif:
            u.silinme_tarihi = None
            status_param = 'active'
        else:
            if u.silinme_tarihi is None:
                u.silinme_tarihi = timezone.now()
            status_param = 'deleted'
        u.save()
        
        # Yeni değerleri kaydet
        new_values = {
            'first_name': u.first_name,
            'last_name': u.last_name,
            'email': u.email,
            'username': u.username,
            'rol': u.rol,
            'aktif': u.aktif,
        }
        
        # Değişen alanları tespit et
        changed_fields = {}
        for key in old_values:
            if old_values[key] != new_values[key]:
                changed_fields[key] = {
                    'old': old_values[key],
                    'new': new_values[key]
                }
        
        # Kullanıcı düzenleme logu
        from sayfalar.utils.logger import log_custom_action
        log_custom_action(
            action_type='USER_UPDATE',
            title='Kullanıcı Düzenlendi',
            description=f'"{user_obj.username}" kullanıcısı düzenlendi.',
            user=request.user,
            request=request,
            related_user=user_obj,
            old_values=old_values,
            new_values=new_values,
            details={
                'duzenlenen_kullanici': user_obj.username,
                'duzenleyen_kullanici': request.user.username,
                'changed_fields': changed_fields,
            }
        )
        
        messages.success(request, "Benutzer wurde erfolgreich aktualisiert.")
        return redirect(f"{reverse('kullanicilar')}?status={status_param}")
    data = request.POST.dict()
    data.pop('password1', None)
    data.pop('password2', None)
    request.session['edit_user_errors'] = form.errors.get_json_data()
    request.session['edit_user_data']   = data
    request.session['edit_user_open']   = user_id
    messages.error(request, "Bitte prüfen Sie die Eingaben.")
    return redirect('kullanicilar')

@login_required(login_url='giris')
@require_POST
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
def kullanici_sil(request):
    user_id = request.POST.get('user_id')
    user_obj = get_object_or_404(CustomUser, pk=user_id)

    # Güvenlik: Admini veya kendini silmeyi engelle
    if user_obj.rol == 'Admin':
        messages.error(request, "Administrator kann nicht gelöscht werden.")
        return redirect('kullanicilar')
    if user_obj == request.user:
        messages.error(request, "Sie können Ihr eigenes Konto nicht löschen.")
        return redirect('kullanicilar')

    # SOFT DELETE (önerilen)
    user_obj.aktif = False
    user_obj.silinme_tarihi = timezone.now()
    user_obj.save()
    
    # Kullanıcı silme logu
    from sayfalar.utils.logger import log_custom_action
    log_custom_action(
        action_type='USER_DELETE',
        title='Kullanıcı Silindi',
        description=f'"{user_obj.username}" kullanıcısı silindi (deaktive edildi).',
        user=request.user,
        request=request,
        related_user=user_obj,
        details={
            'silinen_kullanici': user_obj.username,
            'silen_kullanici': request.user.username,
            'kullanici_rol': user_obj.rol,
            'silme_tarihi': user_obj.silinme_tarihi.isoformat() if user_obj.silinme_tarihi else None,
        }
    )
    
    messages.success(request, "Benutzer wurde deaktiviert.")
    return redirect(f"{reverse('kullanicilar')}?status=deleted")

@login_required(login_url='giris')
@require_POST
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
def kullanici_aktif_et(request):
    user_id = request.POST.get('user_id')
    user_obj = get_object_or_404(CustomUser, pk=user_id)
    if user_obj.aktif:
        messages.info(request, "Benutzer ist bereits aktiv.")
        return redirect('kullanicilar')
    user_obj.aktif = True
    user_obj.silinme_tarihi = None
    user_obj.save()
    
    # Kullanıcı aktif etme logu
    from sayfalar.utils.logger import log_custom_action
    log_custom_action(
        action_type='USER_UPDATE',
        title='Kullanıcı Aktif Edildi',
        description=f'"{user_obj.username}" kullanıcısı aktif edildi.',
        user=request.user,
        request=request,
        related_user=user_obj,
        details={
            'aktif_edilen_kullanici': user_obj.username,
            'aktif_eden_kullanici': request.user.username,
            'kullanici_rol': user_obj.rol,
        }
    )
    
    messages.success(request, "Benutzer wurde reaktiviert.")
    return redirect('kullanicilar')

@login_required(login_url='giris')
@rol_kontrol(("Admin" ), redirect_url="panel")
def firma_goruntule(request):
    return redirect("firma_duzenle")

@login_required(login_url='giris')
@rol_kontrol(("Admin"), redirect_url="panel")
def firma_duzenle(request):
    firma  = Firma.objects.first()
    smtp   = Smtp.objects.first()
    footer = FooterYazi.objects.first()

    if request.method == "POST":
        form_type = request.POST.get("form_type")
        if form_type == "firma":
            firma_form = FirmaForm(request.POST, request.FILES, instance=firma if firma else None)
            smtp_form  = SmtpForm(instance=smtp)  # diğer form boş görünmesin
            try:
                if firma_form.is_valid():
                    # Console debug - form validation
                    print(f"=== FORM VALIDATION DEBUG ===")
                    print(f"Firma objesi: {firma}")
                    print(f"Form cleaned_data: {firma_form.cleaned_data}")
                    print("=== END FORM DEBUG ===")
                    
                    # Eski değerleri kaydet
                    old_values = {
                        'isim': firma.isim if firma else None,
                        'slogan': firma.slogan if firma else None,
                        'telefon': firma.telefon if firma else None,
                        'adres': firma.adres if firma else None,
                        'sms_yazisi': firma.sms_yazisi if firma else None,
                        'logo': firma.logo.url if firma and firma.logo else None,
                        'icon': firma.icon.url if firma and firma.icon else None,
                        # Varsayılan olarak değişim bayrakları
                        'logo_changed': False,
                        'icon_changed': False,
                    }
                    
                    # Formu kaydet
                    firma = firma_form.save()
                    
                    # Yeni değerleri form verilerinden al
                    new_values = {
                        'isim': firma_form.cleaned_data.get('isim'),
                        'slogan': firma_form.cleaned_data.get('slogan'),
                        'telefon': firma_form.cleaned_data.get('telefon'),
                        'adres': firma_form.cleaned_data.get('adres'),
                        'sms_yazisi': firma_form.cleaned_data.get('sms_yazisi'),
                        'logo': firma.logo.url if firma.logo else None,
                        'icon': firma.icon.url if firma.icon else None,
                        # Dosya alanları için güvenli değişim bayrakları
                        'logo_changed': 'logo' in request.FILES,
                        'icon_changed': 'icon' in request.FILES,
                    }
                    
                    # Değişen alanları tespit et
                    changed_fields = {}
                    for key in old_values:
                        old_val = old_values[key]
                        new_val = new_values[key]
                        
                        # String değerleri normalize et
                        if isinstance(old_val, str):
                            old_val = old_val.strip()
                        if isinstance(new_val, str):
                            new_val = new_val.strip()
                        
                        # None değerleri boş string olarak kabul et
                        if old_val is None:
                            old_val = ""
                        if new_val is None:
                            new_val = ""
                            
                        if old_val != new_val:
                            changed_fields[key] = {
                                'old': old_values[key],  # Orijinal değerleri kaydet
                                'new': new_values[key]
                            }
                    
                    # Debug: hangi alanların karşılaştırıldığını logla
                    debug_info = {
                        'comparison_results': {}
                    }
                    for key in old_values:
                        old_val = old_values[key]
                        new_val = new_values[key]
                        
                        # Normalize edilmiş değerleri de kaydet
                        old_val_norm = old_val.strip() if isinstance(old_val, str) else ("" if old_val is None else old_val)
                        new_val_norm = new_val.strip() if isinstance(new_val, str) else ("" if new_val is None else new_val)
                        
                        debug_info['comparison_results'][key] = {
                            'old': old_val,
                            'new': new_val,
                            'old_normalized': old_val_norm,
                            'new_normalized': new_val_norm,
                            'changed': old_val_norm != new_val_norm
                        }
                    
                    # Console debug (geliştirme için)
                    print("=== FIRMA AYARLARI DEBUG ===")
                    print(f"Old values: {old_values}")
                    print(f"New values: {new_values}")
                    print(f"Changed fields: {changed_fields}")
                    for key, comp in debug_info['comparison_results'].items():
                        if comp['changed']:
                            print(f"CHANGED {key}: '{comp['old']}' -> '{comp['new']}'")
                    print("=== END DEBUG ===")
                    
                    # Açıklama oluştur
                    field_names = {
                        'isim': 'Firma Adı',
                        'slogan': 'Slogan',
                        'telefon': 'Telefon',
                        'adres': 'Adres',
                        'sms_yazisi': 'SMS Yazısı',
                        'logo_changed': 'Logo',
                        'icon_changed': 'Icon'
                    }
                    
                    if changed_fields:
                        changed_field_names = []
                        for field_key in changed_fields.keys():
                            field_name = field_names.get(field_key, field_key)
                            changed_field_names.append(field_name)
                        description = f'Firma ayarları güncellendi. Değişen alanlar: {", ".join(changed_field_names)}'
                    else:
                        description = 'Firma ayarları güncellendi (değişiklik tespit edilmedi).'
                    
                    # Firma ayarları güncelleme logu
                    from sayfalar.utils.logger import log_custom_action
                    log_custom_action(
                        action_type='SETTINGS_UPDATE',
                        title='Firma Ayarları Güncellendi',
                        description=description,
                        user=request.user,
                        request=request,
                        old_values=old_values,
                        new_values=new_values,
                        details={
                            'ayar_tipi': 'firma',
                            'changed_fields': changed_fields,
                            'debug_info': debug_info,
                        }
                    )
                    
                    messages.success(request, "Firmendaten wurden erfolgreich aktualisiert.")
                    return redirect("firma_duzenle")
                else:
                    messages.error(request, "Bitte prüfe die markierten Felder bei den Firmendaten.")
            except ValidationError as e:
                messages.error(request, f"Fehler: {e}")
        elif form_type == "smtp":
            firma_form = FirmaForm(instance=firma)
            smtp_form  = SmtpForm(request.POST, instance=smtp if smtp else None)
            try:
                if smtp_form.is_valid():
                    # Eski değerleri kaydet
                    old_values = {
                        'host': smtp.host if smtp else None,
                        'port': smtp.port if smtp else None,
                        'username': smtp.username if smtp else None,
                        'use_tls': smtp.use_tls if smtp else None,
                        'use_ssl': smtp.use_ssl if smtp else None,
                        # Şifreyi açık göstermeden değişim bayrağı
                        'password_changed': False,
                    }

                    # Şifre değişti mi? (değeri göstermeden)
                    posted_password = smtp_form.cleaned_data.get('password')
                    previous_password = smtp.password if smtp else None
                    password_changed_flag = bool(posted_password) and (posted_password != previous_password)

                    # Formu kaydet
                    smtp = smtp_form.save()
                    
                    # Yeni değerleri form verilerinden al
                    new_values = {
                        'host': smtp_form.cleaned_data.get('host'),
                        'port': smtp_form.cleaned_data.get('port'),
                        'username': smtp_form.cleaned_data.get('username'),
                        'use_tls': smtp_form.cleaned_data.get('use_tls'),
                        'use_ssl': smtp_form.cleaned_data.get('use_ssl'),
                        'password_changed': password_changed_flag,
                    }
                    
                    # Değişen alanları tespit et
                    changed_fields = {}
                    for key in old_values:
                        if old_values[key] != new_values[key]:  # Şifreyi değer olarak loglamıyoruz, sadece bayrak
                            changed_fields[key] = {
                                'old': old_values[key],
                                'new': new_values[key]
                            }
                    
                    # Açıklama oluştur
                    field_names = {
                        'host': 'SMTP Sunucusu',
                        'port': 'Port',
                        'username': 'Kullanıcı Adı',
                        'use_tls': 'TLS Kullanımı',
                        'use_ssl': 'SSL Kullanımı',
                        'password_changed': 'Şifre'
                    }
                    
                    if changed_fields:
                        changed_field_names = []
                        for field_key in changed_fields.keys():
                            field_name = field_names.get(field_key, field_key)
                            changed_field_names.append(field_name)
                        description = f'SMTP ayarları güncellendi. Değişen alanlar: {", ".join(changed_field_names)}'
                    else:
                        description = 'SMTP ayarları güncellendi (değişiklik tespit edilmedi).'
                    
                    # SMTP ayarları güncelleme logu
                    from sayfalar.utils.logger import log_custom_action
                    log_custom_action(
                        action_type='SETTINGS_UPDATE',
                        title='SMTP Ayarları Güncellendi',
                        description=description,
                        user=request.user,
                        request=request,
                        old_values=old_values,
                        new_values=new_values,
                        details={
                            'ayar_tipi': 'smtp',
                            'changed_fields': changed_fields,
                        }
                    )
                    
                    messages.success(request, "SMTP-Einstellungen wurden erfolgreich aktualisiert.")
                    return redirect("firma_duzenle")
                else:
                    messages.error(request, "Bitte prüfe die markierten Felder bei den SMTP-Einstellungen.")
            except ValidationError as e:
                messages.error(request, f"Fehler: {e}")
        elif form_type == "durum":
            firma_form = FirmaForm(instance=firma)
            smtp_form  = SmtpForm(instance=smtp)
            ids   = request.POST.getlist('durum_id[]')
            names = request.POST.getlist('durum_isim[]')
            order = list(range(1, len(names) + 1))
            pairs = []
            for _id, _name, _sira in zip(ids, names, order):
                name_clean = (_name or '').strip()
                if name_clean:
                    pairs.append(((_id or '').strip(), name_clean, int(_sira)))
            if not pairs:
                messages.error(request, "Bitte füge mindestens einen Status hinzu.")
                return redirect("firma_duzenle")
            lowered = [n.lower() for _, n, __ in pairs]
            if len(lowered) != len(set(lowered)):
                messages.error(request, "Doppelte Status-Namen sind nicht erlaubt.")
                return redirect("firma_duzenle")
            try:
                with transaction.atomic():
                    mevcut_qs    = MusteriFormModelDurum.objects.all()
                    mevcut_by_id = {str(m.id): m for m in mevcut_qs}
                    gelen_idler = {i for i, _, __ in pairs if i}
                    for _id, isim, sira in pairs:
                        if _id and _id in mevcut_by_id:
                            obj = mevcut_by_id[_id]
                            fields_to_update = []
                            if obj.isim != isim:
                                obj.isim = isim
                                fields_to_update.append('isim')
                            if obj.sira != sira:
                                obj.sira = sira
                                fields_to_update.append('sira')
                            if fields_to_update:
                                obj.save(update_fields=fields_to_update)
                        else:
                            MusteriFormModelDurum.objects.create(isim=isim, sira=sira)
                    if gelen_idler:
                        for m in mevcut_qs:
                            if str(m.id) not in gelen_idler:
                                m.delete()
                messages.success(request, "Formstatus wurde erfolgreich aktualisiert.")
                return redirect("firma_duzenle")
            except IntegrityError:
                messages.error(request, "Der Status-Name muss eindeutig sein.")
                return redirect("firma_duzenle")
            except Exception as e:
                messages.error(request, f"Fehler beim Speichern der Statusliste: {e}")
                return redirect("firma_duzenle")
        elif form_type == "footer":
            firma_form = FirmaForm(instance=firma)
            smtp_form  = SmtpForm(instance=smtp)

            icerik_sol                 = (request.POST.get("icerik_sol") or "").strip()
            buton_yazi_sag             = (request.POST.get("buton_yazi_sag") or "").strip()
            buton_modal_icerik_sag     = (request.POST.get("buton_modal_icerik_sag") or "").strip()
            buton_yazi_sag_iki         = (request.POST.get("buton_yazi_sag_iki") or "").strip()
            buton_modal_icerik_sag_iki = (request.POST.get("buton_modal_icerik_sag_iki") or "").strip()

            try:
                if not footer:
                    footer = FooterYazi.objects.create(
                        icerik_sol=icerik_sol,
                        buton_yazi_sag=buton_yazi_sag,
                        buton_modal_icerik_sag=buton_modal_icerik_sag,
                        buton_yazi_sag_iki=buton_yazi_sag_iki or None,
                        buton_modal_icerik_sag_iki=buton_modal_icerik_sag_iki or None,
                    )
                else:
                    FooterYazi.objects.filter(pk=footer.pk).update(
                        icerik_sol=icerik_sol,
                        buton_yazi_sag=buton_yazi_sag,
                        buton_modal_icerik_sag=buton_modal_icerik_sag,
                        buton_yazi_sag_iki=buton_yazi_sag_iki or None,
                        buton_modal_icerik_sag_iki=buton_modal_icerik_sag_iki or None,
                    )

                messages.success(request, "Footer-Inhalte wurden erfolgreich aktualisiert.")
                return redirect("firma_duzenle")
            except ValidationError as e:
                messages.error(request, f"Fehler: {e}")
            except Exception as e:
                messages.error(request, f"Fehler beim Speichern der Footer-Inhalte: {e}")
        elif form_type == "sigorta":
            firma_form = FirmaForm(instance=firma)
            smtp_form  = SmtpForm(instance=smtp)

            ids        = request.POST.getlist('ss_id[]')
            names      = request.POST.getlist('ss_isim[]')
            del_flags  = request.POST.getlist('ss_resim_sil[]')  # "0" veya "1"
            kapsam_list = request.POST.getlist('ss_kapsam[]')    # "Privat", "Gesetzlich", "Beides"
            keys       = request.POST.getlist('ss_key[]')        # unique keys

            # Key bazlı eşleştirme yap
            data_by_key = {}
            
            # Tüm verileri key'e göre grupla
            for i, key in enumerate(keys):
                if key:  # key varsa
                    data_by_key[key] = {
                        'id': ids[i] if i < len(ids) else '',
                        'name': names[i] if i < len(names) else '',
                        'del_flag': del_flags[i] if i < len(del_flags) else '0',
                        'kapsam': kapsam_list[i] if i < len(kapsam_list) else 'Beides',
                        'file': None  # file'ları ayrı işleyeceğiz
                    }
            
            # File'ları name attribute'undan ID'ye göre eşleştir
            for file_name, file_obj in request.FILES.items():
                if file_name.startswith('ss_resim_'):
                    # ss_resim_123 -> 123, ss_resim_new_456 -> new_456
                    item_id = file_name.replace('ss_resim_', '')
                    # Bu ID'ye sahip key'i bul
                    for key, data in data_by_key.items():
                        if key.endswith(f'_{item_id}') or key == item_id:
                            data['file'] = file_obj
                            break

            # Temizle ve pairs oluştur
            pairs = []
            for i, (key, data) in enumerate(data_by_key.items()):
                name_clean = (data['name'] or '').strip()
                if name_clean:
                    pairs.append((
                        (data['id'] or '').strip(), 
                        name_clean, 
                        str(data['del_flag'] or '0'), 
                        data['file'], 
                        (data['kapsam'] or 'Beides').strip(), 
                        i + 1
                    ))

            if not pairs:
                messages.error(request, "Bitte füge mindestens eine Gesellschaft hinzu.")
                return redirect("firma_duzenle")

            lowered = [n.lower() for _, n, __, ___, ____, _____ in pairs]
            if len(lowered) != len(set(lowered)):
                messages.error(request, "Doppelte Namen sind nicht erlaubt.")
                return redirect("firma_duzenle")

            try:
                with transaction.atomic():
                    mevcut_qs = SigortaSirket.objects.all()
                    mevcut_by_id = {str(m.id): m for m in mevcut_qs}
                    gelen_idler = {i for i, _, __, ___, ____, _____ in pairs if i}

                    # Güncelle / Ekle
                    for _id, isim, del_flag, file_obj, kapsam, sira in pairs:
                        if _id and _id in mevcut_by_id:
                            obj = mevcut_by_id[_id]
                            fields_to_update = []

                            if obj.isim != isim:
                                obj.isim = isim
                                fields_to_update.append('isim')

                            if obj.sira != sira:
                                obj.sira = sira
                                fields_to_update.append('sira')

                            if obj.kapsam != kapsam:
                                obj.kapsam = kapsam
                                fields_to_update.append('kapsam')

                            # Resim sil/güncelle
                            if del_flag == '1':
                                if obj.resim:
                                    obj.resim.delete(save=False)
                                obj.resim = None
                                fields_to_update.append('resim')
                            elif file_obj:
                                # yeni dosya yüklendiyse değiştir
                                obj.resim = file_obj
                                fields_to_update.append('resim')

                            if fields_to_update:
                                obj.save(update_fields=list(set(fields_to_update)))

                        else:
                            # Yeni kayıt
                            create_kwargs = {'isim': isim, 'sira': sira, 'kapsam': kapsam}
                            if file_obj:
                                create_kwargs['resim'] = file_obj
                            SigortaSirket.objects.create(**create_kwargs)

                    # Silinenleri temizle
                    if gelen_idler:
                        for m in mevcut_qs:
                            if str(m.id) not in gelen_idler:
                                m.delete()

                messages.success(request, "Versicherungsgesellschaften wurden erfolgreich aktualisiert.")
                return redirect("firma_duzenle")

            except IntegrityError:
                messages.error(request, "Der Gesellschaftsname muss eindeutig sein.")
                return redirect("firma_duzenle")
            except Exception as e:
                messages.error(request, f"Fehler beim Speichern der Gesellschaftsliste: {e}")
                return redirect("firma_duzenle")
        elif form_type == "email":
            email_dogrulama = request.POST.get("email_dogrulama") in ("on", "true", "1", "yes")
            email_onay_yazisi = (request.POST.get("email_onay_yazisi") or "").strip()

            try:
                if not firma:
                    firma = Firma.objects.create(
                        isim="Firma", slogan="", logo=None, icon=None,
                        telefon="", adres="", sms_yazisi="",
                        email_onay_yazisi=email_onay_yazisi or None,
                        email_dogrulama=email_dogrulama
                    )
                else:
                    Firma.objects.filter(pk=firma.pk).update(
                        email_onay_yazisi=email_onay_yazisi or None,
                        email_dogrulama=email_dogrulama
                    )
                messages.success(request, "E-Mail-Benachrichtigungseinstellungen wurden erfolgreich aktualisiert.")
                return redirect("firma_duzenle")
            except Exception as e:
                messages.error(request, f"Fehler beim Speichern der E-Mail-Einstellungen: {e}")
                return redirect("firma_duzenle")
        else:
            if any(k in request.POST for k in ["isim", "telefon", "adres"]):
                firma_form = FirmaForm(request.POST, request.FILES, instance=firma if firma else None)
                smtp_form  = SmtpForm(instance=smtp)
                if firma_form.is_valid():
                    firma_form.save()
                    messages.success(request, "Firmendaten wurden erfolgreich aktualisiert.")
                    return redirect("firma_duzenle")
            elif any(k in request.POST for k in ["host", "port", "username", "password", "use_tls", "use_ssl"]):
                firma_form = FirmaForm(instance=firma)
                smtp_form  = SmtpForm(request.POST, instance=smtp if smtp else None)
                if smtp_form.is_valid():
                    smtp_form.save()
                    messages.success(request, "SMTP-Einstellungen wurden erfolgreich aktualisiert.")
                    return redirect("firma_duzenle")
            elif any(k in request.POST for k in ["durum_id[]", "durum_isim[]"]):
                return redirect("firma_duzenle")
            elif any(k in request.POST for k in ["icerik_sol", "icerik_sag"]):
                return redirect("firma_duzenle")
    firma_form = FirmaForm(instance=firma)
    smtp_form  = SmtpForm(instance=smtp)
    form_durumlari = MusteriFormModelDurum.objects.all().order_by("sira", "id")
    sigorta_sirketleri = SigortaSirket.objects.all().order_by("sira", "id")
    return render(request, "yonetim/firma_duzenle.html", {
        "firma_form": firma_form,
        "smtp_form":  smtp_form,
        "firma":      firma,
        "smtp":       smtp,
        "footer":     footer,  # frontend-only CKEditor başlangıç içeriği için
        "form_durumlari": form_durumlari,
        "sigorta_sirketleri": sigorta_sirketleri
    })


@login_required(login_url='giris')
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
@require_GET
def ajax_sigorta_alt_list(request):
    sirket_id = request.GET.get("sirket_id")
    if not sirket_id:
        return HttpResponseBadRequest("Parameter 'sirket_id' ist erforderlich.")

    try:
        sirket = SigortaSirket.objects.get(pk=sirket_id)
    except SigortaSirket.DoesNotExist:
        return HttpResponseBadRequest("Ungültige 'sirket_id'.")

    items = [
        {"id": a.id, "isim": a.isim, "sira": a.sira}
        for a in SigortaAltSirket.objects.filter(sirket=sirket).order_by("sira", "id")
    ]
    return JsonResponse({"ok": True, "gesellschaft": {"id": sirket.id, "name": sirket.isim}, "items": items})


@login_required(login_url='giris')
@rol_kontrol(("Admin", "Yönetici"), redirect_url="panel")
@require_POST
def ajax_sigorta_alt_save(request):
    sirket_id = request.POST.get("sirket_id")
    if not sirket_id:
        return HttpResponseBadRequest("Parameter 'sirket_id' ist erforderlich.")

    try:
        sirket = SigortaSirket.objects.get(pk=sirket_id)
    except SigortaSirket.DoesNotExist:
        return HttpResponseBadRequest("Ungültige 'sirket_id'.")

    ids   = request.POST.getlist("as_id[]")
    names = request.POST.getlist("as_isim[]")

    order = list(range(1, len(names) + 1))
    pairs = []
    for _id, _name, _sira in zip(ids, names, order):
        name_clean = (_name or "").strip()
        if name_clean:
            pairs.append(((_id or "").strip(), name_clean, int(_sira)))

    # LEERES ABSENDEN = ALLE UNTERGESELLSCHAFTEN LÖSCHEN
    if not pairs:
        SigortaAltSirket.objects.filter(sirket=sirket).delete()
        return JsonResponse({"ok": True, "msg": "Alle Untergesellschaften wurden gelöscht."})

    # Duplikate (nur unter den nicht-leeren Namen) verhindern
    lowered = [n.lower() for _, n, __ in pairs]
    if len(lowered) != len(set(lowered)):
        return JsonResponse({"ok": False, "msg": "Doppelte Namen sind nicht erlaubt."}, status=400)

    try:
        with transaction.atomic():
            mevcut_qs = SigortaAltSirket.objects.filter(sirket=sirket)
            mevcut_by_id = {str(m.id): m for m in mevcut_qs}
            gelen_idler = {i for i, _, __ in pairs if i}

            # Upsert nach DOM-Reihenfolge (sira = 1..N)
            for _id, isim, sira in pairs:
                if _id and _id in mevcut_by_id:
                    obj = mevcut_by_id[_id]
                    fields = []
                    if obj.isim != isim:
                        obj.isim = isim
                        fields.append("isim")
                    if obj.sira != sira:
                        obj.sira = sira
                        fields.append("sira")
                    if fields:
                        obj.save(update_fields=list(set(fields)))
                else:
                    SigortaAltSirket.objects.create(sirket=sirket, isim=isim, sira=sira)

            # Nicht mehr übermittelte Einträge löschen
            for m in mevcut_qs:
                if str(m.id) not in gelen_idler:
                    m.delete()

        return JsonResponse({"ok": True, "msg": "Untergesellschaften wurden erfolgreich gespeichert."})
    except IntegrityError:
        return JsonResponse({"ok": False, "msg": "Der Name der Untergesellschaft muss pro Gesellschaft eindeutig sein."}, status=400)
    except Exception as e:
        return JsonResponse({"ok": False, "msg": f"Fehler: {e}"}, status=400)