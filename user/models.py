from django.db import models
from django.contrib.auth.models import AbstractUser
# Create your models here.

class CustomUser(AbstractUser):
    rol=models.CharField(max_length=255, choices=[('Admin', 'Admin'), ('Yönetici', 'Manager'), ('Personel', 'Mitarbeiter'), ('Benutzer', 'Benutzer')], default='Personel', verbose_name="Rol")
    resim = models.ImageField(upload_to='kullanici_resimleri/', null=True, blank=True, verbose_name="Profil Resmi")
    email = models.EmailField(unique=True, verbose_name="E-posta")
    silinme_tarihi = models.DateTimeField(null=True, blank=True, verbose_name="Silinme Tarihi")
    aktif = models.BooleanField(default=True, verbose_name="Aktif")
    class Meta:
        verbose_name = 'Kullanıcı'
        verbose_name_plural = 'Kullanıcılar'

    def __str__(self):
        return self.username

class SifreSifirlamaTalebi(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name="password_reset_requests")
    token = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)

    class Meta:
        verbose_name = "Şifre Sıfırlama İsteği"
        verbose_name_plural = "Şifre Sıfırlama İstekleri"

    def __str__(self):
        return f"{self.user.username}"

    def is_active(self):
        from django.utils import timezone
        return self.used_at is None and timezone.now() < self.expires_at
