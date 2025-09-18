from django.urls import path
from . import views

urlpatterns = [
    path("firma/ansehen/", views.firma_goruntule, name="firma_goruntule"),
    path("firma/bearbeiten/", views.firma_duzenle, name="firma_duzenle"),
    path("benutzer/", views.kullanicilar, name="kullanicilar"),
    path("benutzer/hinzufügen/", views.kullanici_ekle, name="kullanici_ekle"),
    path("benutzer/bearbeiten/", views.kullanici_duzenle, name="kullanici_duzenle"),
    path("benutzer/löschen/", views.kullanici_sil, name="kullanici_sil"),
    path("benutzer/aktivieren/", views.kullanici_aktif_et, name="kullanici_aktif_et"),



    path("versicherung/unter/list/", views.ajax_sigorta_alt_list, name="sigorta_alt_list"),
    path("versicherung/unter/save/", views.ajax_sigorta_alt_save, name="sigorta_alt_save"),
]
