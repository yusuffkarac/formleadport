#!/usr/bin/env bash
set -euo pipefail

# Proje köküne geç
cd "$(dirname "$0")"

# Sanal ortam (venv) yoksa oluştur
if [ ! -d "venv" ]; then
  echo "[setup] Sanal ortam oluşturuluyor..."
  python3 -m venv venv
fi

VENV_PY="$(pwd)/venv/bin/python"
VENV_PIP="$(pwd)/venv/bin/pip"

echo "[setup] pip/setuptools/wheel güncelleniyor..."
"$VENV_PIP" install --upgrade --disable-pip-version-check pip setuptools wheel

if [ -f requirements.txt ]; then
  echo "[setup] requirements.txt kuruluyor..."
  "$VENV_PIP" install --disable-pip-version-check -r requirements.txt
fi

echo "[db] migrate çalıştırılıyor..."
"$VENV_PY" manage.py migrate --noinput

# İsteğe bağlı: statikler (geliştirme için gerekli değil)
# "$VENV_PY" manage.py collectstatic --noinput

HOST=${HOST:-0.0.0.0}
PORT=${PORT:-8000}
echo "[run] Sunucu başlıyor: http://127.0.0.1:${PORT}/ (HOST=${HOST})"
exec "$VENV_PY" manage.py runserver "${HOST}:${PORT}"


