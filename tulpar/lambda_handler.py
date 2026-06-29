"""Tulpar AWS Lambda Handler - Surekli Guvenlik Taramasi.

Bu modul, Tulpar'in AWS Lambda fonksiyonu olarak calismasini saglar.
Her gece otomatik tarama yaparak sonuclari SNS/Slack uzerinden bildirir.

Onerilen Lambda Yapilandirmasi:
- Runtime: Python 3.9+
- Memory: 512 MB
- Timeout: 5 dakika
- Trigger: EventBridge (cron: 0 3 * * ? *)
- Ortam Degiskenleri:
  - TULPAR_SNS_TOPIC_ARN (opsiyonel): Sonuclari gonderecek SNS konusu
  - TULPAR_SLACK_WEBHOOK (opsiyonel): Slack bildirimi icin webhook URL'i
  - TULPAR_HIZLI_MOD (opsiyonel): "true" ise hizli tarama modu
  - TULPAR_CLOUDTRAIL_ANALIZ (opsiyonel): "true" ise CloudTrail analizi
"""

import os
import json
import logging
from datetime import datetime
from tulpar.yardimcilar import loglama_yapilandir
from tulpar.dogrulayici import vektorleri_yukle
from tulpar.tarayici import GekSizmaScanner
from tulpar.analiz import ExploitationMappingEngine

logger = logging.getLogger("TulparLambda")

SNS_TOPIC_ARN = os.environ.get("TULPAR_SNS_TOPIC_ARN", "")
SLACK_WEBHOOK_URL = os.environ.get("TULPAR_SLACK_WEBHOOK", "")
HIZLI_MOD = os.environ.get("TULPAR_HIZLI_MOD", "false").lower() == "true"
CLOUDTRAIL_ANALIZ = os.environ.get("TULPAR_CLOUDTRAIL_ANALIZ", "false").lower() == "true"


def slack_bildirimi_gonder(webhook_url, mesaj):
    """Slack kanalina bildirim gonderir."""
    import urllib.request

    if not webhook_url.startswith("https://hooks.slack.com/"):
        logger.error("Guvenlik: Gecersiz Slack webhook URL'i. Yalnizca https://hooks.slack.com/ kabul edilir.")
        return False

    try:
        veri = json.dumps({"text": mesaj}).encode("utf-8")
        istek = urllib.request.Request(
            webhook_url,
            data=veri,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(istek, timeout=10)  # nosec B310
        logger.info("Slack bildirimi gonderildi")
        return True
    except Exception as hata:
        logger.error("Slack bildirimi gonderilemedi: %s", hata)
        return False


def sns_bildirimi_gonder(topic_arn, konu, mesaj):
    """AWS SNS uzerinden bildirim gonderir."""
    try:
        import boto3

        sns_istemicisi = boto3.client("sns")
        tam_mesaj = "{}\n\n{}".format(konu, mesaj)
        sns_istemicisi.publish(
            TopicArn=topic_arn,
            Subject=konu[:100],
            Message=tam_mesaj,
        )
        logger.info("SNS bildirimi gonderildi: %s", topic_arn)
        return True
    except Exception as hata:
        logger.error("SNS bildirimi gonderilemedi: %s", hata)
        return False


def ozet_mesaji_olustur(bulunan_zafiyetler, scp_durumu, surum):
    """Insan-okunabilir ozet mesaji olusturur."""
    kritik_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Kritik")
    yuksek_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Yuksek")
    orta_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Orta")
    dusuk_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Dusuk")

    satirlar = []
    satirlar.append(":mag: *Tulpar AWS IAM Guvenlik Taramasi Tamamlandi* (v{})".format(surum))
    satirlar.append("")
    satirlar.append("*Tarama Tarihi:* {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    satirlar.append("*Toplam Zafiyet:* {}".format(len(bulunan_zafiyetler)))
    satirlar.append("")
    satirlar.append("*Kritiklik Dagilimi:*")
    satirlar.append("  :red_circle: Kritik: *{}*".format(kritik_sayisi))
    satirlar.append("  :orange_circle: Yuksek: *{}*".format(yuksek_sayisi))
    satirlar.append("  :yellow_circle: Orta: *{}*".format(orta_sayisi))
    satirlar.append("  :green_circle: Dusuk: *{}*".format(dusuk_sayisi))

    if scp_durumu is not None:
        scp_metni = ":warning: SCP Kisitlamasi Var" if scp_durumu else ":white_check_mark: SCP Kisitlamasi Yok"
        satirlar.append("")
        satirlar.append(scp_metni)

    if kritik_sayisi > 0:
        satirlar.append("")
        satirlar.append(":rotating_light: *KRITIK ZAFIYETLER TESPIT EDILDI!*")
        satirlar.append("")
        for b in bulunan_zafiyetler:
            if b.get("kritiklik_seviyesi") == "Kritik":
                satirlar.append("  • *{}* (Risk: {}/10)".format(b.get("zafiyet_adi", ""), b.get("risk_skoru", "-")))
                if b.get("somuru_komutu"):
                    satirlar.append("    `{}`".format(b["somuru_komutu"][:120]))

    if yuksek_sayisi > 0:
        satirlar.append("")
        satirlar.append(":warning: *Yuksek Riskli Zafiyetler:*")
        for b in bulunan_zafiyetler:
            if b.get("kritiklik_seviyesi") == "Yuksek":
                satirlar.append("  • *{}* (Risk: {}/10)".format(b.get("zafiyet_adi", ""), b.get("risk_skoru", "-")))

    satirlar.append("")
    satirlar.append("---")
    satirlar.append(":robot_face: Bu rapor Tulpar tarafindan otomatik olusturulmustur.")

    return "\n".join(satirlar)


def lambda_handler(event, context):
    """AWS Lambda handler - Tulpar taramasini calistirir ve bildirim gonderir."""
    loglama_yapilandir()
    logger.info("Tulpar Lambda taramasi baslatiliyor...")
    logger.info("Event: %s", json.dumps(event, default=str))

    try:
        tarayici = GekSizmaScanner(thread_sayisi=5)

        analiz_motoru = ExploitationMappingEngine(tarayici)

        if HIZLI_MOD:
            vektor_verisi = vektorleri_yukle()
            tum_vektorler = vektor_verisi.get("vektorler", [])
            kritik_vektorler = sorted(tum_vektorler, key=lambda v: v.get("risk_skoru", 0), reverse=True)[:15]
            analiz_motoru.vektorler = kritik_vektorler
            logger.info("Hizli mod aktif: 15 vektor taranacak")

        analiz_motoru.analiz_baslat(cloudtrail_analizi=CLOUDTRAIL_ANALIZ)

        bulunan_zafiyetler = analiz_motoru.bulunan_zafiyetler
        scp_durumu = tarayici.scp_kisitlamasi_var

        from tulpar.sabitler import SURUM

        ozet = ozet_mesaji_olustur(bulunan_zafiyetler, scp_durumu, SURUM)

        bildirim_gonderildi = False

        if SLACK_WEBHOOK_URL:
            slack_bildirimi_gonder(SLACK_WEBHOOK_URL, ozet)
            bildirim_gonderildi = True

        if SNS_TOPIC_ARN:
            konu = "Tulpar Tarama Sonucu - {} Zafiyet Bulundu".format(len(bulunan_zafiyetler))
            kritik_var = any(b.get("kritiklik_seviyesi") == "Kritik" for b in bulunan_zafiyetler)
            if kritik_var:
                konu = ":rotating_light: " + konu + " (KRITIK VAR!)"
            sns_bildirimi_gonder(SNS_TOPIC_ARN, konu, ozet)
            bildirim_gonderildi = True

        if not bildirim_gonderildi:
            logger.info("Bildirim kanali yapilandirilmamis. Sonuclar sadece Lambda loglarinda.")

        logger.info(ozet)

        kritik_var = any(b.get("kritiklik_seviyesi") == "Kritik" for b in bulunan_zafiyetler)
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "durum": "tamamlandi",
                    "tarih": datetime.now().isoformat(),
                    "zafiyet_sayisi": len(bulunan_zafiyetler),
                    "kritik_zafiyet_var": kritik_var,
                    "scp_kisitlamasi_var": scp_durumu,
                    "zafiyetler": [
                        {
                            "adi": b.get("zafiyet_adi", ""),
                            "kritiklik": b.get("kritiklik_seviyesi", ""),
                            "risk_skoru": b.get("risk_skoru", "-"),
                        }
                        for b in bulunan_zafiyetler
                    ],
                },
                ensure_ascii=False,
            ),
        }

    except Exception as hata:
        logger.error("Lambda taramasi basarisiz: %s", hata, exc_info=True)
        if SLACK_WEBHOOK_URL:
            slack_bildirimi_gonder(
                SLACK_WEBHOOK_URL,
                ":x: *Tulpar Lambda Taramasi Basarisiz!*\nHata: {}".format(str(hata)),
            )
        return {
            "statusCode": 500,
            "body": json.dumps({"durum": "hata", "hata": str(hata)}, ensure_ascii=False),
        }
