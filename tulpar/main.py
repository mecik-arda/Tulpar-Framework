import argparse
import sys
import os
import json
import logging
from datetime import datetime
from tulpar.yardimcilar import (
    loglama_yapilandir, onbellege_kaydet, onbellekten_yukle,
    onbellek_suresi_gecerli_mi, konfigurasyon_yukle
)
from tulpar.tarayici import GekSizmaScanner
from tulpar.analiz import ExploitationMappingEngine
from tulpar.rapor import ReportWriter, AttackGraphGenerator, CokluFormatRaporlayici
from tulpar.sabitler import SURUM, CIKTI_FORMATLARI

logger = logging.getLogger('Tulpar')

def ana_fonksiyon():
    loglama_yapilandir()

    arguman_isleyici = argparse.ArgumentParser(
        description="Tulpar AWS IAM Yetki Yukseltme ve Ileri Seviye Istismar Araci v{}".format(SURUM)
    )
    arguman_isleyici.add_argument("--erisim-anahtari", required=False, default=None, help="AWS Erisim Anahtari Kimligi")
    arguman_isleyici.add_argument("--gizli-anahtar", required=False, default=None, help="AWS Gizli Erisim Anahtari")
    arguman_isleyici.add_argument("--oturum-belirteci", required=False, default=None, help="AWS Oturum Belirteci Istege Bagli")
    arguman_isleyici.add_argument("--aws-profil", required=False, default=None, help="AWS profil adi (~/.aws/credentials) Istege Bagli")
    arguman_isleyici.add_argument("--json-cikti", required=False, default="raporlar/tulpar_rapor.json", help="JSON rapor dosyasi yolu")
    arguman_isleyici.add_argument("--html-cikti", required=False, default="raporlar/tulpar_grafik.html", help="HTML grafik dosyasi yolu")
    arguman_isleyici.add_argument("--cevrimdisi", action="store_true", required=False, default=False, help="HTML raporu icin CDN assetlerini yerel olarak indir")
    arguman_isleyici.add_argument("--onbellek", required=False, default=None, help="Tarama sonuclarini onbellek JSON dosyasina kaydet/oku")
    arguman_isleyici.add_argument("--onbellek-suresi", required=False, type=int, default=24, help="Onbellek gecerlilik suresi (saat, varsayilan: 24)")
    arguman_isleyici.add_argument("--format", required=False, default="json", choices=CIKTI_FORMATLARI, help="Ek cikti formati: " + ", ".join(CIKTI_FORMATLARI))
    arguman_isleyici.add_argument("--format-cikti", required=False, default=None, help="Formatli cikti dosyasi yolu")
    arguman_isleyici.add_argument("--konfig", required=False, default=None, help="Konfigurasyon dosyasi (JSON veya YAML)")

    argumanlar = arguman_isleyici.parse_args()

    konfig = {}
    if argumanlar.konfig:
        konfig = konfigurasyon_yukle(argumanlar.konfig)
        if konfig is None:
            logger.error("Konfigurasyon dosyasi yuklenemedi, varsayilan degerlerle devam ediliyor")
            konfig = {}
        for anahtar in ['erisim_anahtari', 'gizli_anahtar', 'oturum_belirteci', 'aws_profil',
                         'json_cikti', 'html_cikti', 'onbellek', 'format', 'format_cikti', 'cevrimdisi']:
            konfig_anahtari = anahtar.replace('_', '-')
            if konfig_anahtari in konfig and getattr(argumanlar, anahtar) == arguman_isleyici.get_default(anahtar):
                setattr(argumanlar, anahtar, konfig[konfig_anahtari])

    logger.info("Tulpar AWS IAM Yetki Yukseltme Tarayicisi v%s baslatiliyor...", SURUM)

    onbellek_kullaniliyor = False
    if argumanlar.onbellek:
        if onbellek_suresi_gecerli_mi(argumanlar.onbellek, argumanlar.onbellek_suresi):
            onbellek_verisi = onbellekten_yukle(argumanlar.onbellek)
            if onbellek_verisi:
                logger.info("Onbellek gecerli, onceki tarama sonuclari kullaniliyor")
                logger.info("Onbellek tarihi bilgisi mevcut, API cagrilari atlaniyor")
                onbellek_kullaniliyor = True
        else:
            if os.path.exists(argumanlar.onbellek):
                logger.info("Onbellek suresi dolmus, yeni tarama yapilacak")

    if not onbellek_kullaniliyor:
        if argumanlar.aws_profil or konfig.get('aws-profil'):
            profil = argumanlar.aws_profil or konfig.get('aws-profil')
            logger.info("AWS profili kullaniliyor: %s", profil)
            tarayici = GekSizmaScanner(profil_adi=profil)
        elif argumanlar.erisim_anahtari and argumanlar.gizli_anahtar:
            logger.info("CLI argumanlarindan saglanan kimlik bilgileri kullaniliyor")
            tarayici = GekSizmaScanner(
                erisim_anahtari=argumanlar.erisim_anahtari,
                gizli_anahtar=argumanlar.gizli_anahtar,
                oturum_belirteci=argumanlar.oturum_belirteci
            )
        elif os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
            logger.info("Ortam degiskenlerinden alinan kimlik bilgileri kullaniliyor")
            tarayici = GekSizmaScanner(
                erisim_anahtari=os.environ.get('AWS_ACCESS_KEY_ID'),
                gizli_anahtar=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                oturum_belirteci=os.environ.get('AWS_SESSION_TOKEN')
            )
        else:
            logger.info("Varsayilan boto3 kimlik bilgisi zinciri kullaniliyor (~/.aws/credentials, EC2 instance profile, vb.)")
            tarayici = GekSizmaScanner()

        analiz_motoru = ExploitationMappingEngine(tarayici)
        analiz_motoru.analiz_baslat()

        bulunan_zafiyetler = analiz_motoru.bulunan_zafiyetler
        saldiri_yollari = analiz_motoru.saldiri_yollari
        scp_durumu = tarayici.scp_kisitlamasi_var

        if argumanlar.onbellek:
            onbellek_verisi = {
                "onbellek_tarihi": datetime.now().isoformat(),
                "kimlik_bilgileri": tarayici.kimlik_bilgileri,
                "scp_kisitlamasi_var": tarayici.scp_kisitlamasi_var,
                "scp_detaylari": tarayici.scp_detaylari,
                "bulunan_zafiyetler": bulunan_zafiyetler,
                "saldiri_yollari": saldiri_yollari,
                "coklu_bolge_bulgu_listesi": tarayici.coklu_bolge_bulgu_listesi
            }
            onbellege_kaydet(argumanlar.onbellek, onbellek_verisi)
    else:
        bulunan_zafiyetler = onbellek_verisi.get('bulunan_zafiyetler', [])
        saldiri_yollari = onbellek_verisi.get('saldiri_yollari', [])
        scp_durumu = onbellek_verisi.get('scp_kisitlamasi_var')
        logger.info("Onbellekten %d zafiyet yuklendi", len(bulunan_zafiyetler))

    rapor_yazici = ReportWriter(bulunan_zafiyetler, argumanlar.json_cikti)
    rapor_yazici.rapor_yaz()

    if saldiri_yollari:
        grafik_olusturucu = AttackGraphGenerator(
            saldiri_yollari,
            bulunan_zafiyetler,
            argumanlar.html_cikti,
            cevrimdisi_mod=argumanlar.cevrimdisi
        )
        grafik_olusturucu.html_olustur()
    else:
        logger.warning("Gorsellestirilecek saldiri yolu bulunamadi, HTML raporu atlaniyor")

    if argumanlar.format != 'json' and argumanlar.format_cikti:
        coklu_format = CokluFormatRaporlayici(bulunan_zafiyetler, scp_durumu)
        coklu_format.formatli_rapor_yaz(argumanlar.format_cikti, argumanlar.format)
    elif argumanlar.format != 'json' and not argumanlar.format_cikti:
        varsayilan_cikti = argumanlar.json_cikti.replace('.json', '.' + argumanlar.format)
        coklu_format = CokluFormatRaporlayici(bulunan_zafiyetler, scp_durumu)
        coklu_format.formatli_rapor_yaz(varsayilan_cikti, argumanlar.format)

    logger.info("Tarama tamamlandi. %d zafiyet bulundu. Raporlar olusturuldu: %s, %s",
                len(bulunan_zafiyetler),
                argumanlar.json_cikti,
                argumanlar.html_cikti)

if __name__ == "__main__":
    ana_fonksiyon()
