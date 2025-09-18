from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from .models import Firma, Smtp
from user.models import CustomUser

User = get_user_model()

class FirmaForm(forms.ModelForm):
    class Meta:
        model = Firma
        fields = ["isim", "slogan", "logo", "icon", "telefon", "adres", "sms_yazisi"]
        labels = {
            "isim": "Firmenname",
            "slogan": "Slogan",
            "logo": "Logo",
            "icon": "Icon",
            "telefon": "Telefonnummer",
            "adres": "Adresse",
        }
        widgets = {
            "isim": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Firmenname"
            }),
            "slogan": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Slogan"
            }),
            "telefon": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Telefonnummer"
            }),
            "adres": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Adresse"
            }),
            "logo": forms.FileInput(attrs={
                "id": "id_logo",
                "accept": "image/*",
                "class": "d-none",
            }),
            "icon": forms.FileInput(attrs={
                "id": "id_icon",
                "accept": "image/*",
                "class": "d-none",
            }),
            "sms_yazisi": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
            }),
        }


class SmtpForm(forms.ModelForm):
    class Meta:
        model = Smtp
        fields = ["host", "port", "username", "password", "use_tls", "use_ssl"]
        labels = {
            "host": "SMTP-Server",
            "port": "Port",
            "username": "Benutzername",
            "password": "Passwort",
            "use_tls": "TLS verwenden",
            "use_ssl": "SSL verwenden",
        }
        widgets = {
            "host": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "SMTP-Server"
            }),
            "port": forms.NumberInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Port"
            }),
            "username": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Benutzername"
            }),
            "password": forms.PasswordInput(render_value=True, attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Passwort"
            }),
            "use_tls": forms.CheckboxInput(attrs={"class": "form-check-input w-45px h-30px"}),
            "use_ssl": forms.CheckboxInput(attrs={"class": "form-check-input w-45px h-30px"}),
        }

class CustomUserCreateForm(forms.ModelForm):
    password1 = forms.CharField(label="Passwort", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Passwort (Wiederholung)", widget=forms.PasswordInput)
    class Meta:
        model = CustomUser
        fields = ["first_name", "last_name", "email", "username", "rol", "aktif"]
        widgets = {
            "rol": forms.RadioSelect(choices=CustomUser._meta.get_field("rol").choices),
        }
    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1") or ""
        p2 = cleaned.get("password2") or ""
        if p1 != p2:
            self.add_error("password2", "Die Passwörter stimmen nicht überein.")
        if p1 and len(p1) < 8:
            self.add_error("password1", "Mindestens 8 Zeichen.")

        return cleaned
    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
    
class CustomUserUpdateForm(forms.ModelForm):
    password1 = forms.CharField(label="Neues Passwort", widget=forms.PasswordInput, required=False)
    password2 = forms.CharField(label="Neues Passwort (Wiederholung)", widget=forms.PasswordInput, required=False)
    class Meta:
        model = CustomUser
        fields = ["first_name", "last_name", "email", "username", "rol", "aktif"]
        widgets = {
            "rol": forms.RadioSelect(choices=CustomUser._meta.get_field("rol").choices),
        }
    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1") or ""
        p2 = cleaned.get("password2") or ""
        if p1 or p2:
            if p1 != p2:
                self.add_error("password2", "Die Passwörter stimmen nicht überein.")
            elif len(p1) < 8:
                self.add_error("password1", "Mindestens 8 Zeichen.")
        return cleaned
    def save(self, commit=True):
        user = super().save(commit=False)
        p1 = self.cleaned_data.get("password1")
        if p1:
            user.set_password(p1)
        if commit:
            user.save()
        return user
    