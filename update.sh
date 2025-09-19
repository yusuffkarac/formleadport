#!/bin/bash

echo "========================================="
echo "Kod Güncelleme Başlatılıyor"
echo "========================================="

cd /home/django/formleadport

# Güvenlik için database backup al
echo "Database backup alınıyor..."
mkdir -p /home/django/backups
cp db.sqlite3 /home/django/backups/db_backup_$(date +%Y%m%d_%H%M%S).sqlite3

# Git durumunu kontrol et ve temizle
echo "Git durumu kontrol ediliyor..."
git status
echo "Local değişiklikler yedekleniyor..."
git stash push -m "Local changes backup $(date +%Y%m%d_%H%M%S)"

# Kodu çek
echo "Kod güncelleniyor..."
git pull origin main

# Eğer pull başarısız olursa
if [ $? -ne 0 ]; then
    echo "HATA: Git pull başarısız! Manuel müdahale gerekli."
    exit 1
fi

# Virtual environment aktif et
source venv/bin/activate

# Requirements güncelle
echo "Python paketleri güncelleniyor..."
pip install -r requirements.txt

# Migration'ları otomatik çalıştır
echo "Migration'lar kontrol ediliyor ve uygulanıyor..."
python3 manage.py migrate

# Migration durumunu kontrol et
echo "Migration durumu:"
python3 manage.py showmigrations | grep -E "\[ \]|\[X\]"

# Static files topla
echo "Static dosyalar toplanıyor..."
python3 manage.py collectstatic --noinput

# Sunucuyu yeniden başlat
echo "Sunucu yeniden başlatılıyor..."
sudo systemctl restart django

# Sunucu durumunu kontrol et
sleep 3
if systemctl is-active --quiet django; then
    echo "✅ Django servisi başarıyla yeniden başlatıldı"
else
    echo "❌ UYARI: Django servisi başlatılamadı!"
    echo "Durumu kontrol edin: sudo systemctl status django"
fi

echo "========================================="
echo "Kod güncellemesi tamamlandı!"
echo "Database backup: /home/django/backups/"
echo "Son backup: db_backup_$(date +%Y%m%d_%H%M%S).sqlite3"
echo "========================================="

# Log dosyasına da kaydet
echo "$(date): Kod güncelleme tamamlandı" >> /home/django/update.log
