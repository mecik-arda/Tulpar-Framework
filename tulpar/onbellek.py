import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("Tulpar")

def onbellege_kaydet(dosya_yolu, veri):
    try:
        with open(dosya_yolu, "w", encoding="utf-8") as dosya:
            json.dump(veri, dosya, ensure_ascii=False, indent=4)
        
        # Security fix: chmod 0o600 (owner read/write only)
        os.chmod(dosya_yolu, 0o600)
        
        logger.info("Tarama sonuclari onbellege kaydedildi: %s", dosya_yolu)
        return True
    except Exception as hata:
        logger.warning("Onbellege kaydetme basarisiz: %s", hata)
        return False

def onbellekten_yukle(dosya_yolu):
    if not os.path.exists(dosya_yolu):
        return None
    try:
        with open(dosya_yolu, "r", encoding="utf-8") as dosya:
            veri = json.load(dosya)
        logger.info("Onbellekten tarama sonuclari yuklendi: %s", dosya_yolu)
        return veri
    except Exception as hata:
        logger.warning("Onbellekten yukleme basarisiz: %s", hata)
        return None

def onbellek_suresi_gecerli_mi(onbellek_dosyasi, maksimum_sure_saat=24):
    if not os.path.exists(onbellek_dosyasi):
        return False
    dosya_zamani = os.path.getmtime(onbellek_dosyasi)
    guncel_zaman = datetime.now().timestamp()
    fark_saat = (guncel_zaman - dosya_zamani) / 3600.0
    return fark_saat < maksimum_sure_saat
