import logging
import json
import os

logger = logging.getLogger("Tulpar")

def loglama_yapilandir():
    kok_logger = logging.getLogger()
    if kok_logger.hasHandlers():
        return
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

def aws_hatasi_yonet(hata, islem_adi):
    hata_kodu = hata.response["Error"]["Code"]
    hata_mesaji = hata.response["Error"]["Message"]
    if hata_kodu == "AccessDenied":
        logger.warning("%s - Erisim Reddedildi: Bu API cagrisi icin yetkiniz bulunmamaktadir", islem_adi)
    elif hata_kodu == "TokenExpired":
        logger.error("%s - Oturum Belirteci Suresi Doldu: Yeni bir oturum belirteci edinin", islem_adi)
    elif hata_kodu == "InvalidClientTokenId":
        logger.error("%s - Gecersiz Erisim Anahtari: AWS kimlik bilgilerinizi kontrol edin", islem_adi)
    elif hata_kodu == "UnauthorizedOperation":
        logger.warning("%s - Yetkisiz Islem: Bu eylemi gerceklestirme izniniz yok", islem_adi)
    elif hata_kodu == "Throttling":
        logger.warning("%s - Istek Kisitlamasi: API istek limitine ulasildi, bekleyip tekrar deneyin", islem_adi)
    elif hata_kodu == "ExpiredToken":
        logger.error("%s - Oturum Belirteci Gecersiz: Belirtecin suresi dolmus veya gecersiz", islem_adi)
    elif hata_kodu == "SignatureDoesNotMatch":
        logger.error("%s - Imza Uyusmazligi: Gizli anahtariniz hatali olabilir", islem_adi)
    elif hata_kodu == "RequestExpired":
        logger.error("%s - Istek Zamani Gecti: Sistem saatinizin dogru oldugundan emin olun", islem_adi)
    else:
        logger.error("%s - Beklenmeyen Hata [%s]: %s", islem_adi, hata_kodu, hata_mesaji)

def konfigurasyon_yukle(konfig_dosyasi):
    if not os.path.exists(konfig_dosyasi):
        logger.error("Konfigurasyon dosyasi bulunamadi: %s", konfig_dosyasi)
        return None
    try:
        with open(konfig_dosyasi, "r", encoding="utf-8") as dosya:
            if konfig_dosyasi.endswith(".yaml") or konfig_dosyasi.endswith(".yml"):
                try:
                    import yaml
                    konfig = yaml.safe_load(dosya)
                except ImportError:
                    logger.error("YAML konfigurasyon icin PyYAML kutuphanesi gerekli: pip install pyyaml")
                    return None
            else:
                konfig = json.load(dosya)
        logger.info("Konfigurasyon dosyasi yuklendi: %s", konfig_dosyasi)
        return konfig
    except Exception as hata:
        logger.error("Konfigurasyon dosyasi yuklenemedi: %s", hata)
        return None

def servis_adi_ayristir(iam_eylemi):
    """IAM eylem adini servis ve eylem bilesenlerine ayirir.

    Args:
        iam_eylemi: 'servis:EylemAdi' formatinda IAM eylem adi.

    Returns:
        (servis, eylem) ikilisi. Iki nokta yoksa her ikisi de ayni deger.
    """
    if ":" not in iam_eylemi:
        return iam_eylemi, iam_eylemi
    servis, eylem = iam_eylemi.split(":", 1)
    return servis, eylem

def servis_eylem_listesini_grupla(eylem_listesi):
    """IAM eylem listesini servis adina gore gruplandirir.

    Args:
        eylem_listesi: 'servis:eylem' formatinda eylem adlarindan olusan liste.

    Returns:
        {servis_adi: [eylem1, eylem2, ...]} seklinde sozluk.
    """
    gruplar = {}
    for eylem in eylem_listesi:
        servis, _ = servis_adi_ayristir(eylem)
        if servis not in gruplar:
            gruplar[servis] = []
        gruplar[servis].append(eylem)
    return gruplar
