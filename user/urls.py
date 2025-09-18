from django.urls import path
from . import views

urlpatterns = [
    path("anmeldung/", views.giris, name="giris"),
    path("abmeldung/cks", views.cikis, name="cikis"),
    path("passwort-vergessen/", views.sifremi_unuttum, name="sifremi_unuttum"),
    path("passwort-zuruecksetzen/<str:token>/", views.sifre_yenile, name="sifre_yenile"),

    path("profil-anzeigen/", views.profil_goruntule, name="profil_goruntule"),
    path("profil-bearbeiten/", views.profil_duzenle, name="profil_duzenle"),
]