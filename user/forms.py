from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from PIL import Image
from pathlib import Path
from django.core.files.uploadedfile import UploadedFile
User = get_user_model()
# forms.py
from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class ProfilForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "username", "email", "resim"]
        labels = {
            "first_name": "Vorname",
            "last_name": "Nachname",
            "username": "Benutzername",
            "email": "E-Mail",
            "resim": "Profilbild",
        }
        widgets = {
            "first_name": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Vorname"
            }),
            "last_name": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Nachname"
            }),
            "username": forms.TextInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "Benutzername"
            }),
            "email": forms.EmailInput(attrs={
                "class": "form-control form-control-lg form-control-solid",
                "placeholder": "E-Mail"
            }),
            "resim": forms.ClearableFileInput(attrs={
                "class": "form-control form-control-lg",
                "accept": "image/*",
                "id": "id_resim"
            }),
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.get("instance", None)
        super().__init__(*args, **kwargs)

    def clean_email(self):
        email = self.cleaned_data.get("email")
        if email:
            qs = User.objects.filter(email=email)
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("Diese E-Mail wird bereits verwendet.")
        return email

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if username:
            qs = User.objects.filter(username=username)
            if self.instance and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("Dieser Benutzername ist bereits vergeben.")
        return username

    def clean_resim(self):
        img = self.cleaned_data.get("resim")
        if not img:
            return img  # resim yüklenmemişse (veya temizlenmişse) çık

        # Yeni yükleme mi? (InMemoryUploadedFile / TemporaryUploadedFile)
        if isinstance(img, UploadedFile):
            max_mb = 5
            if img.size and img.size > max_mb * 1024 * 1024:
                raise forms.ValidationError(f"Das Bild darf maximal {max_mb} MB groß sein.")

            # content_type sadece UploadedFile'da var
            ct = (img.content_type or "").lower()
            if not ct.startswith("image/"):
                raise forms.ValidationError("Bitte laden Sie eine gültige Bilddatei hoch.")

            # (Opsiyonel ama sağlam) Pillow ile hızlı doğrulama
            try:
                img.file.seek(0)
                Image.open(img.file).verify()
                img.file.seek(0)
            except Exception:
                raise forms.ValidationError("Die Bilddatei ist beschädigt oder ungültig.")
        else:
            # Mevcut dosya (ImageFieldFile): content_type yok.
            # İstersen sadece uzantı kontrolü yap.
            valid_exts = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
            ext = Path(getattr(img, "name", "")).suffix.lower()
            if ext and ext not in valid_exts:
                raise forms.ValidationError("Nur JPG, PNG, GIF oder WEBP werden unterstützt.")

            # (Opsiyonel) Pillow ile yine doğrulayabilirsin:
            try:
                img.file.seek(0)
                Image.open(img.file).verify()
                img.file.seek(0)
            except Exception:
                raise forms.ValidationError("Vorhandenes Profilbild ist ungültig/beschädigt.")

        return img


class PasswortAendernForm(PasswordChangeForm):
    # Django'nun yerleşik doğrulamaları + Almanca hata mesajları
    error_messages = {
        "password_incorrect": "Das alte Passwort ist falsch. Bitte erneut versuchen.",
        "password_mismatch": "Die beiden neuen Passwörter stimmen nicht überein.",
        "password_too_similar": "Das neue Passwort ist zu ähnlich zu den persönlichen Informationen.",
        "password_too_short": "Das neue Passwort ist zu kurz.",
        "password_too_common": "Das neue Passwort ist zu häufig verwendet.",
        "password_entirely_numeric": "Das neue Passwort darf nicht nur aus Zahlen bestehen.",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["old_password"].label = "Altes Passwort"
        self.fields["new_password1"].label = "Neues Passwort"
        self.fields["new_password2"].label = "Neues Passwort (Wiederholung)"

        self.fields["old_password"].widget = forms.PasswordInput(attrs={
            "class": "form-control form-control-lg form-control-solid",
            "autocomplete": "current-password",
        })
        self.fields["new_password1"].widget = forms.PasswordInput(attrs={
            "class": "form-control form-control-lg form-control-solid",
            "autocomplete": "new-password",
        })
        self.fields["new_password2"].widget = forms.PasswordInput(attrs={
            "class": "form-control form-control-lg form-control-solid",
            "autocomplete": "new-password",
        })

        # (İsteğe bağlı) Yardım metni
        self.fields["new_password1"].help_text = "Mindestens 8 Zeichen, nicht zu ähnlich zu persönlichen Daten."