from django.urls import path
from . import views

urlpatterns = [
    path('', views.panel, name='panel'),
    path("musteri-formlari/<int:pk>/durum/", views.musteri_formu_durum_guncelle, name="musteri_formu_durum_guncelle"),

    path("ajax/posta-kodu/lookup/", views.posta_kodu_lookup, name="posta_kodu_lookup"),
    path("ajax/otp/send/phone/", views.ajax_otp_send_phone, name="ajax_otp_send_phone"),
    path("ajax/otp/verify/phone/", views.ajax_otp_verify_phone, name="ajax_otp_verify_phone"),
    path("ajax/otp/send/email/", views.ajax_otp_send_email, name="ajax_otp_send_email"),
    path("ajax/otp/verify/email/", views.ajax_otp_verify_email, name="ajax_otp_verify_email"),
    path("forms/musteri/olustur/", views.musteri_form_olustur, name="musteri_form_olustur"),
    path("forms/musteri/duzenle/<int:form_id>/", views.musteri_form_duzenle, name="musteri_form_duzenle"),
    path("ajax/forms/musteri/<int:form_id>/detail/", views.musteri_form_detay, name="musteri_form_detay"),
    path('forms/<int:form_id>/detail/', views.form_detail_json, name='form_detail_json'),
    path("forms/<int:pk>/sil/", views.form_sil, name="form_sil"),
    path("ajax/forms/musteri/<int:form_id>/notlar/", views.musteri_form_not_ekle),
    path("ajax/forms/musteri/<int:form_id>/notes/", views.musteri_form_not_ekle),
    path("ajax/forms/musteri/<int:form_id>/notlar/", views.musteri_form_notlar, name="musteri_form_notlar"),
    path("ajax/form/<int:form_id>/notlar/", views.ajax_form_notlar, name="ajax_form_notlar"),
    path("ajax/not/<int:not_id>/", views.ajax_not_guncelle, name="ajax_not_guncelle"),
    path("api/form-paylasimlari/<int:form_id>/", views.api_form_paylasimlari, name="api_form_paylasimlari"),
    path("api/form-paylasim-ekle/", views.api_form_paylasim_ekle, name="api_form_paylasim_ekle"),
    path("api/form-paylasim-sil/", views.api_form_paylasim_sil, name="api_form_paylasim_sil"),
    path("bilden/<int:form_id>/pdf/", views.form_detail_pdf, name="form_detail_pdf"),
    path('ajax/sigorta-sirketleri/', views.ajax_sigorta_sirketleri, name='ajax_sigorta_sirketleri'),
    path('ajax/sigorta-alt-list/', views.ajax_sigorta_alt_list, name='ajax_sigorta_alt_list'),
    path("ajax/email-paylasim/gecmis/", views.ajax_email_paylasim_gecmis, name="ajax_email_paylasim_gecmis"),
    path("ajax/email-paylasim/gonder/", views.ajax_email_paylasim_gonder, name="ajax_email_paylasim_gonder"),

    # Kaydet
    path("forms/musteri/duzenle/<int:form_id>/", views.musteri_form_duzenle, name="musteri_form_duzenle"),
    
    # Loglar
    path("logs/", views.logs_view, name="logs"),

]