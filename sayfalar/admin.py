# admin.py
from django.contrib import admin
from django.utils.html import format_html
from django.urls import path, reverse
from django.shortcuts import render
from django.http import JsonResponse
from django.db.models import Q
from django.utils import timezone
from .models import MusteriFormModel, MusteriFormModelCocukYasi, MusteriFormModelPaylasim, Sehir, MusteriFormModelDurum, MusteriFormModelNot, SigortaSirket, SigortaAltSirket, SystemLog



class CocukYasiInline(admin.TabularInline):
    model = MusteriFormModelCocukYasi
    fk_name = "form"
    fields = ("cocuk_yasi",)
    extra = 0

class PaylasimInline(admin.TabularInline):
    model = MusteriFormModelPaylasim
    fk_name = "form"
    fields = ("kullanici",)
    readonly_fields = ("olusturma_tarihi", "son_guncelleme_tarihi")
    extra = 0

class NotInline(admin.TabularInline):
    model = MusteriFormModelNot
    fk_name = "form"
    fields = ("kullanici", "not_icerigi")
    readonly_fields = ("olusturma_tarihi", "son_guncelleme_tarihi")
    extra = 0

@admin.register(MusteriFormModel)
class MusteriFormModelAdmin(admin.ModelAdmin):
    inlines = [CocukYasiInline, PaylasimInline, NotInline]

    # Minimal liste görünümü
    list_display = ("id", "musteri_isim", "musteri_soyisim", "randevu_tarihi", "randevu_tipi", "calisma_durumu")
    list_display_links = ("id", "musteri_isim", "musteri_soyisim")

    # Sadece 3 sade bölüm
    fieldsets = (
        ("Sayfa 1", {
            "fields": (
                "kullanici",
                "randevu_tarihi",
                "randevu_tipi",
                "firma_adi",
                ("musteri_isim", "musteri_soyisim"),
                ("musteri_cinsiyet", "musteri_dogum_tarihi"),
                "adres",
                ("sehir", "posta_kodu"),
                ("telefon", "telefon_onayli_mi", "sabit_telefon"),
                ("email", "email_onayli_mi"),
            )
        }),
        ("Sayfa 2", {
            "fields": (
                "medeni_durum",
                ("aile_durumu_aktif", "aile_durumu_s"),
                ("aile_cocuk_sayisi", "calisma_durumu"),
                "sigorta",
                "sigorta_ek_yazi",
                ("sigorta_katki_payi", "sigorta_katilim_payi"),
                "sigorta_sirket",
                ("sigorta_baslangic_tarihi", "sigorta_tarife_vadesi"),
            )
        }),
        ("Sayfa 3", {
            "fields": (
                "es_cocuk_sigorta",
                "es_yasi",
            )
        }),
    )

@admin.register(Sehir)
class SehirAdmin(admin.ModelAdmin):
    list_display = ("id",)
    search_fields = ("sehir_adi",)

@admin.register(MusteriFormModelDurum)
class MusteriFormModelDurumAdmin(admin.ModelAdmin):
    list_display = ("id", "isim", "sira")
    search_fields = ("isim", "sira")


class SigortaAltSirketInline(admin.TabularInline):
    model = SigortaAltSirket
    extra = 0

@admin.register(SigortaSirket)
class SigortaSirketAdmin(admin.ModelAdmin):
    list_display = ("id", "isim", "kapsam", "sira")
    inlines = [SigortaAltSirketInline]
    search_fields = ("isim",)
    list_editable = ("sira", "kapsam")
    list_filter = ("kapsam",)


@admin.register(SystemLog)
class SystemLogAdmin(admin.ModelAdmin):
    list_display = ("id", "get_timestamp", "get_user", "get_action_type", "get_severity_badge", "title", "get_short_description")
    list_filter = ("action_type", "severity", "timestamp", "kullanici")
    search_fields = ("title", "description", "kullanici__username", "kullanici__first_name", "kullanici__last_name")
    readonly_fields = ("timestamp", "ip_address", "user_agent", "details", "old_values", "new_values")
    date_hierarchy = "timestamp"
    ordering = ("-timestamp",)
    list_per_page = 50
    
    fieldsets = (
        ("Temel Bilgiler", {
            "fields": ("kullanici", "action_type", "severity", "timestamp")
        }),
        ("İçerik", {
            "fields": ("title", "description")
        }),
        ("İlişkili Nesneler", {
            "fields": ("related_form", "related_user"),
            "classes": ("collapse",)
        }),
        ("Teknik Detaylar", {
            "fields": ("ip_address", "user_agent", "details", "old_values", "new_values"),
            "classes": ("collapse",)
        }),
    )
    
    def get_timestamp(self, obj):
        return obj.get_formatted_timestamp()
    get_timestamp.short_description = "Zaman"
    get_timestamp.admin_order_field = "timestamp"
    
    def get_user(self, obj):
        if obj.kullanici:
            return f"{obj.kullanici.username} ({obj.kullanici.get_full_name() or 'İsim Yok'})"
        return "Sistem"
    get_user.short_description = "Kullanıcı"
    get_user.admin_order_field = "kullanici__username"
    
    def get_action_type(self, obj):
        return obj.get_action_type_display()
    get_action_type.short_description = "Aksiyon"
    get_action_type.admin_order_field = "action_type"
    
    def get_severity_badge(self, obj):
        colors = {
            'INFO': 'blue',
            'SUCCESS': 'green', 
            'WARNING': 'orange',
            'ERROR': 'red'
        }
        color = colors.get(obj.severity, 'gray')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_severity_display()
        )
    get_severity_badge.short_description = "Önem"
    get_severity_badge.admin_order_field = "severity"
    
    def get_short_description(self, obj):
        return obj.get_short_description()
    get_short_description.short_description = "Açıklama"
    
    def has_add_permission(self, request):
        return False
    
    def has_change_permission(self, request, obj=None):
        return False
    
    def has_delete_permission(self, request, obj=None):
        return request.user.is_superuser
    
    def get_urls(self):
        urls = super().get_urls()
        custom_urls = [
            path('logs-dashboard/', self.admin_site.admin_view(self.logs_dashboard_view), name='systemlog_dashboard'),
        ]
        return custom_urls + urls
    
    def logs_dashboard_view(self, request):
        """Log dashboard görünümü"""
        # Filtreleme
        action_type = request.GET.get('action_type', '')
        severity = request.GET.get('severity', '')
        user_id = request.GET.get('user_id', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')
        
        # Query oluştur
        logs = SystemLog.objects.all()
        
        if action_type:
            logs = logs.filter(action_type=action_type)
        if severity:
            logs = logs.filter(severity=severity)
        if user_id:
            logs = logs.filter(kullanici_id=user_id)
        if date_from:
            logs = logs.filter(timestamp__date__gte=date_from)
        if date_to:
            logs = logs.filter(timestamp__date__lte=date_to)
        
        logs = logs.order_by('-timestamp')[:100]  # Son 100 log
        
        # İstatistikler
        stats = {
            'total_logs': SystemLog.objects.count(),
            'today_logs': SystemLog.objects.filter(timestamp__date=timezone.now().date()).count(),
            'status_changes': SystemLog.objects.filter(action_type='STATUS_CHANGE').count(),
            'form_creates': SystemLog.objects.filter(action_type='FORM_CREATE').count(),
        }
        
        # Son aktiviteler
        recent_activities = SystemLog.objects.select_related('kullanici', 'related_form').order_by('-timestamp')[:10]
        
        context = {
            'logs': logs,
            'stats': stats,
            'recent_activities': recent_activities,
            'action_types': SystemLog.ACTION_TYPES,
            'severity_levels': SystemLog.SEVERITY_LEVELS,
            'title': 'Sistem Logları Dashboard',
        }
        
        return render(request, 'admin/systemlog_dashboard.html', context)

