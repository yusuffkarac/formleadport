from django.db import models
from django.core.exceptions import ValidationError
from user.models import CustomUser

# Create your models here.

class Firma(models.Model):
    isim = models.CharField(max_length=255, verbose_name="Firma İsmi")
    slogan = models.CharField(max_length=255, verbose_name="Firma Sloganı", blank=True, null=True)
    logo = models.ImageField(upload_to='firma_logo/', verbose_name="Firma Logosu")
    icon = models.ImageField(upload_to='firma_icon/', verbose_name="Firma İkonu")
    telefon = models.CharField(max_length=30, verbose_name="Telefon Numarası")
    adres = models.CharField(max_length=255, verbose_name="Adres")
    sms_yazisi = models.CharField(max_length=255, verbose_name="SMS Yazısı", blank=True, null=True)
    email_onay_yazisi = models.TextField(verbose_name="Email Onay Yazısı", blank=True, null=True)
    termin_onay_yazisi = models.TextField(verbose_name="Termin Bestätigung Yazısı", blank=True, null=True)
    email_dogrulama = models.BooleanField(default=False, verbose_name="Email Doğrulama")

    class Meta:
        verbose_name = 'Firma'
        verbose_name_plural = 'Firmalar'

    def __str__(self):
        return self.isim
    
    def clean(self):
        if not self.pk and Firma.objects.exists():
            raise ValidationError("Yalnızca bir adet firma kaydı oluşturulabilir.")

class Smtp(models.Model):
    host = models.CharField(max_length=255, verbose_name="SMTP Sunucusu")
    port = models.IntegerField(verbose_name="Port Numarası")
    username = models.CharField(max_length=255, verbose_name="Kullanıcı Adı")
    password = models.CharField(max_length=255, verbose_name="Şifre")
    use_tls = models.BooleanField(default=True, verbose_name="TLS Kullan")
    use_ssl = models.BooleanField(default=False, verbose_name="SSL Kullan")

    class Meta:
        verbose_name = 'SMTP Ayarı'
        verbose_name_plural = 'SMTP Ayarları'

    def __str__(self):
        return "SMTP Ayarları"

    def clean(self):
        if not self.pk and Smtp.objects.exists():
            raise ValidationError("Yalnızca bir adet SMTP kaydı oluşturulabilir.")

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)


class FooterYazi(models.Model):
    icerik_sol = models.TextField(verbose_name="Footer Sol İçeriği")
    buton_yazi_sag = models.CharField(max_length=100, verbose_name="Footer Sağ Buton Yazısı", blank=True, null=True)
    buton_modal_icerik_sag = models.TextField(verbose_name="Footer Sağ İçeriği", blank=True, null=True)
    buton_yazi_sag_iki = models.CharField(max_length=100, verbose_name="Footer Sağ İki Buton Yazısı", blank=True, null=True)
    buton_modal_icerik_sag_iki = models.TextField(verbose_name="Footer Sağ İki İçeriği", blank=True, null=True)

    class Meta:
        verbose_name = 'Footer Yazısı'
        verbose_name_plural = 'Footer Yazıları'

    def __str__(self):
        return "Footer Yazısı"

    def clean(self):
        if not self.pk and FooterYazi.objects.exists():
            raise ValidationError("Yalnızca bir adet footer yazısı kaydı oluşturulabilir.")