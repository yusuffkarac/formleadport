import json
import os
from django.core.management.base import BaseCommand, CommandError
from django.apps import apps

class Command(BaseCommand):
    help = "il_ilce.json dosyasından Sehir modeline verileri yükler."
    def handle(self, *args, **options):
        Sehir = apps.get_model("sayfalar", "Sehir")
        current_dir = os.path.dirname(__file__)
        json_path = os.path.join(current_dir, "il_ilce.json")
        if not os.path.exists(json_path):
            raise CommandError(f"JSON dosyası bulunamadı: {json_path}")
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        created, skipped = 0, 0
        for rec in data:
            il = rec.get("state")
            ilce = rec.get("place")
            posta_kodu = rec.get("zipcode")
            if not il or not ilce or not posta_kodu:
                continue
            obj, is_created = Sehir.objects.get_or_create(il=il, ilce=ilce, posta_kodu=posta_kodu)
            if is_created:
                created += 1
            else:
                skipped += 1
        self.stdout.write(self.style.SUCCESS(f"Bitti ✅ Eklenen: {created}, Atlanan (zaten vardı): {skipped}"))
