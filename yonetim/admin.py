from django.contrib import admin
from .models import Smtp, Firma, FooterYazi
from django.http import HttpResponseRedirect
from django.urls import reverse
# Register your models here.
admin.site.site_header = "Müşteri Takip Yönetim Paneli"
admin.site.site_title = "Müşteri Takip"
admin.site.index_title = "Müşteri Takip Yönetim Paneli"

@admin.register(Firma)
class FirmaAdmin(admin.ModelAdmin):
    list_display = ("isim", "telefon", "adres")
    def has_add_permission(self, request):
        if Firma.objects.exists():
            return False
        return True
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def changelist_view(self, request, extra_context=None):
        qs = Firma.objects.all()
        if qs.count() == 1:
            obj = qs.first()
            url = reverse(f'admin:{Firma._meta.app_label}_{Firma._meta.model_name}_change', args=[obj.pk])
            return HttpResponseRedirect(url)
        return super().changelist_view(request, extra_context)

@admin.register(Smtp)
class SmtpAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'username', 'use_tls', 'use_ssl')
    search_fields = ('host', 'username')
    list_filter = ('use_tls', 'use_ssl')

    def has_add_permission(self, request):
        return not Smtp.objects.exists()

    def has_delete_permission(self, request, obj=None):
        return False

    def changelist_view(self, request, extra_context=None):
        qs = Smtp.objects.all()
        if qs.count() == 1:
            obj = qs.first()
            url = reverse(f'admin:{Smtp._meta.app_label}_{Smtp._meta.model_name}_change', args=[obj.pk])
            return HttpResponseRedirect(url)
        return super().changelist_view(request, extra_context)
    
@admin.register(FooterYazi)
class FooterYaziAdmin(admin.ModelAdmin):
    list_display = ('icerik_sol', 'buton_yazi_sag', 'buton_modal_icerik_sag', 'buton_yazi_sag_iki', 'buton_modal_icerik_sag_iki')
    def has_add_permission(self, request):
        if FooterYazi.objects.exists():
            return False
        return True
    
    def has_delete_permission(self, request, obj=None):
        return False
    
    def changelist_view(self, request, extra_context=None):
        qs = FooterYazi.objects.all()
        if qs.count() == 1:
            obj = qs.first()
            url = reverse(f'admin:{FooterYazi._meta.app_label}_{FooterYazi._meta.model_name}_change', args=[obj.pk])
            return HttpResponseRedirect(url)
        return super().changelist_view(request, extra_context)