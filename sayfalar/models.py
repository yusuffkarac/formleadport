from django.db import models
from user.models import CustomUser
# Create your models here.

class Sehir(models.Model):
    il = models.CharField(max_length=255, verbose_name="Şehir Adı")
    ilce = models.CharField(max_length=255, verbose_name="İlçe Adı")
    posta_kodu = models.CharField(max_length=10, verbose_name="Posta Kodu")

    class Meta:
        verbose_name = "Şehir"
        verbose_name_plural = "Şehirler"

    def __str__(self):
        return f"{self.il} - {self.ilce} - {self.posta_kodu}"

class MusteriFormModelCocukYasi(models.Model):
    form = models.ForeignKey('MusteriFormModel', on_delete=models.CASCADE)
    cocuk_yasi = models.IntegerField()

    class Meta:
        verbose_name = "Çocuk Yaşı"
        verbose_name_plural = "Çocuk Yaşları"

    def __str__(self):
        return f"{self.cocuk_yasi} Yaşında Çocuk"

class MusteriFormModelPaylasim(models.Model):
    form = models.ForeignKey('MusteriFormModel', on_delete=models.CASCADE)
    kullanici = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    olusturma_tarihi = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    son_guncelleme_tarihi = models.DateTimeField(auto_now=True, blank=True, null=True)

    class Meta:
        verbose_name = "Form Paylaşımı"
        verbose_name_plural = "Form Paylaşımları"

    def __str__(self):
        return f"{self.form} - Paylaşım - {self.kullanici}"
    
class MusteriFormModelNot(models.Model):
    form = models.ForeignKey('MusteriFormModel', on_delete=models.CASCADE)
    kullanici = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    not_icerigi = models.TextField(blank=True, null=True)
    olusturma_tarihi = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    son_guncelleme_tarihi = models.DateTimeField(auto_now=True, blank=True, null=True)

    class Meta:
        verbose_name = "Form Notu"
        verbose_name_plural = "Form Notları"

    def __str__(self):
        return f"{self.form} - Not - {self.kullanici}"
    
class MusteriFormModelDurum(models.Model):
    isim = models.CharField(max_length=50, unique=True)
    sira = models.IntegerField(default=0)

    class Meta:
        verbose_name = "Form Durumu"
        verbose_name_plural = "Form Durumları"
        ordering = ["sira", "id"]

    def __str__(self):
        return self.isim
    
class SigortaSirket(models.Model):
    isim = models.CharField(max_length=255, unique=True)
    resim = models.ImageField(upload_to='sigorta_sirketleri/', null=True, blank=True)
    sira = models.IntegerField(default=0)
    kapsam = models.CharField(max_length=10, choices=[('Privat', 'Privat'), ('Gesetzlich', 'Gesetzlich'), ('Beides', 'Beides')], default='Beides')

    class Meta:
        verbose_name = "Sigorta Şirketi"
        verbose_name_plural = "Sigorta Şirketleri"
        ordering = ["sira", "id"]

    def __str__(self):
        return self.isim
    
class SigortaAltSirket(models.Model):
    sirket = models.ForeignKey(SigortaSirket, on_delete=models.CASCADE, related_name="altlar")
    isim = models.CharField(max_length=255)
    sira = models.IntegerField(default=0)

    class Meta:
        verbose_name = "Sigorta Alt Şirketi"
        verbose_name_plural = "Sigorta Alt Şirketleri"
        ordering = ["sira", "id"]

    def __str__(self):
        return f"{self.sirket.isim} - {self.isim}"

class MusteriFormModel(models.Model):
    kullanici = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    olusturma_tarihi = models.DateTimeField(auto_now_add=True)
    durum = models.ForeignKey(MusteriFormModelDurum, on_delete=models.SET_NULL, null=True, blank=True)
    # Page 1
    randevu_tarihi = models.DateTimeField()
    randevu_tipi = models.CharField(
        max_length=20,
        choices=[('Video', 'Video'), ('Telefon', 'Telefon'), ('Vor Ort', 'Vor Ort')],
        null=True,
        blank=True,
    )
    firma_adi = models.CharField(max_length=255)
    musteri_isim = models.CharField(max_length=255)
    musteri_soyisim = models.CharField(max_length=255)
    musteri_cinsiyet = models.CharField(max_length=10, choices=[('Erkek', 'Herr'), ('Kadın', 'Frau')], blank=True, null=True)
    musteri_dogum_tarihi = models.DateField()
    adres = models.TextField()
    sehir = models.CharField(max_length=255, null=True, blank=True)
    posta_kodu = models.ForeignKey(Sehir, on_delete=models.SET_NULL, null=True, blank=True)
    posta_kodu_raw = models.CharField(max_length=10, null=True, blank=True)
    telefon = models.CharField(max_length=50, null=True, blank=True)
    telefon_onayli_mi = models.BooleanField(default=False)
    email = models.EmailField(max_length=255, null=True, blank=True)
    email_onayli_mi = models.BooleanField(default=False)
    sabit_telefon = models.CharField(max_length=50, null=True, blank=True)
    # Page 2
    medeni_durum = models.CharField(max_length=50, choices=[('Bekar', 'Ledig'), ('Evli', 'Verheiratet'), ('Boşanmış', 'Geschieden'), ('Dul', 'Verwitwet'), ('Kayıtlı Ortaklık', 'Eingetragene Partnerschaft'), ('Diğer', 'Sonstiges')], default='Bekar')
    calisma_durumu = models.CharField(max_length=50, choices=[('Arbeitnehmer', 'Arbeitnehmer'), ('Selbstständig', 'Selbstständig')], blank=True, null=True)
    aile_durumu_aktif = models.BooleanField(default=False)
    aile_durumu_s = models.BooleanField(default=False)
    aile_cocuk_sayisi = models.IntegerField(null=True, blank=True)
    sigorta = models.CharField(max_length=255, choices=[('Özel', 'Privat'), ('Yasal', 'Gesetzlich'), ('Sigorta Yok', 'Nicht Versichert')], blank=True, null=True)
    sigorta_ek_yazi = models.TextField(blank=True, null=True)
    sigorta_katki_payi = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    sigorta_sirket = models.ForeignKey(SigortaSirket, on_delete=models.SET_NULL, null=True, blank=True)
    sigorta_baslangic_tarihi = models.DateField(null=True, blank=True)
    sigorta_tarife_vadesi = models.ForeignKey(SigortaAltSirket, on_delete=models.SET_NULL, null=True, blank=True)
    sigorta_katilim_payi = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    es_cocuk_sigorta = models.CharField(max_length=255, choices=[('Özel/Ortak Sigortalı', 'Privat/Mitversichert'), ('Yasal/Ortak Sigortalı', 'Gesetzlich/Mitversichert')], blank=True, null=True)
    es_yasi = models.IntegerField(null=True, blank=True)
    es_calisma_durumu = models.CharField(max_length=255, choices=[('Çalışan', 'Arbeitnehmer'), ('Kendi İşinin Patronu', 'Selbstständig')], blank=True, null=True)

    class Meta:
        verbose_name = "Müşteri Formu"
        verbose_name_plural = "Müşteri Formları"

    def __str__(self):
        return f"{self.kullanici} - {self.musteri_isim} {self.musteri_soyisim} - {self.randevu_tarihi}"


class EmailGonderimleri(models.Model):
    form = models.ForeignKey(MusteriFormModel, on_delete=models.CASCADE)
    kullanici = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    gonderilen_email = models.TextField()
    gonderim_tarihi = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "E-Posta Gönderimi"
        verbose_name_plural = "E-Posta Gönderimleri"

    def __str__(self):
        return f"{self.form} - {self.gonderilen_email} - {self.gonderim_tarihi}"


class SystemLog(models.Model):
    """Sistem logları için model - tüm önemli işlemler burada kaydedilir"""
    
    ACTION_TYPES = [
        ('FORM_CREATE', 'Form Oluşturuldu'),
        ('FORM_UPDATE', 'Form Güncellendi'),
        ('FORM_DELETE', 'Form Silindi'),
        ('STATUS_CHANGE', 'Durum Değiştirildi'),
        ('FORM_SHARE', 'Form Paylaşıldı'),
        ('EMAIL_SEND', 'E-posta Gönderildi'),
        ('NOTE_ADD', 'Not Eklendi'),
        ('NOTE_UPDATE', 'Not Güncellendi'),
        ('NOTE_DELETE', 'Not Silindi'),
        ('USER_LOGIN', 'Kullanıcı Girişi'),
        ('USER_LOGOUT', 'Kullanıcı Çıkışı'),
        ('USER_CREATE', 'Kullanıcı Oluşturuldu'),
        ('USER_UPDATE', 'Kullanıcı Güncellendi'),
        ('USER_DELETE', 'Kullanıcı Silindi'),
        ('PROFILE_UPDATE', 'Profil Güncellendi'),
        ('PASSWORD_CHANGE', 'Şifre Değiştirildi'),
        ('SETTINGS_UPDATE', 'Ayarlar Güncellendi'),
        ('OTHER', 'Diğer'),
    ]
    
    SEVERITY_LEVELS = [
        ('INFO', 'Bilgi'),
        ('WARNING', 'Uyarı'),
        ('ERROR', 'Hata'),
        ('SUCCESS', 'Başarılı'),
    ]
    
    # Temel bilgiler
    kullanici = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="Kullanıcı")
    action_type = models.CharField(max_length=20, choices=ACTION_TYPES, verbose_name="Aksiyon Tipi")
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS, default='INFO', verbose_name="Önem Derecesi")
    
    # Zaman bilgisi
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Zaman")
    ip_address = models.GenericIPAddressField(null=True, blank=True, verbose_name="IP Adresi")
    user_agent = models.TextField(null=True, blank=True, verbose_name="Tarayıcı Bilgisi")
    
    # İçerik bilgileri
    title = models.CharField(max_length=255, verbose_name="Başlık")
    description = models.TextField(verbose_name="Açıklama")
    details = models.JSONField(null=True, blank=True, verbose_name="Detaylar (JSON)")
    
    # İlişkili nesneler
    related_form = models.ForeignKey(MusteriFormModel, on_delete=models.SET_NULL, null=True, blank=True, verbose_name="İlgili Form")
    related_user = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='related_logs', verbose_name="İlgili Kullanıcı")
    
    # Ek bilgiler
    old_values = models.JSONField(null=True, blank=True, verbose_name="Eski Değerler")
    new_values = models.JSONField(null=True, blank=True, verbose_name="Yeni Değerler")
    
    class Meta:
        verbose_name = "Sistem Logu"
        verbose_name_plural = "Sistem Logları"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['kullanici']),
            models.Index(fields=['action_type']),
            models.Index(fields=['severity']),
        ]

    def __str__(self):
        return f"{self.get_action_type_display()} - {self.kullanici} - {self.timestamp.strftime('%d.%m.%Y %H:%M')}"
    
    def get_short_description(self):
        """Kısa açıklama döndürür"""
        return self.description[:100] + "..." if len(self.description) > 100 else self.description
    
    def get_formatted_timestamp(self):
        """Formatlanmış zaman döndürür"""
        return self.timestamp.strftime('%d.%m.%Y %H:%M:%S')