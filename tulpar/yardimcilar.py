import os
import json
import logging
import hashlib
import csv
import urllib.request
import urllib.error
from datetime import datetime
import base64

logger = logging.getLogger("Tulpar")

_VEKTOR_ONBELLEGI = None


ZORUNLU_VEKTOR_ALANLARI = [
    "vektor_adi",
    "turkce_baslik",
    "gerekli_izinler",
    "risk_seviyesi",
    "risk_skoru",
    "aciklama",
    "iyilestirme",
    "cloudtrail_izi",
    "somuru_komutu",
    "mavi_takim_onerisi",
    "saldiri_grafi_dugumu",
    "saldiri_grafi_hedefi",
]


def vektor_onbellegi_temizle():
    global _VEKTOR_ONBELLEGI
    _VEKTOR_ONBELLEGI = None
    logger.debug("Vektor onbellegi temizlendi")


def vektor_dogrula(vektor, indeks):
    for alan in ZORUNLU_VEKTOR_ALANLARI:
        if alan not in vektor:
            raise ValueError("Vektor {}: '{}' alani eksik".format(indeks, alan))
    if not isinstance(vektor.get("gerekli_izinler"), list):
        raise ValueError("Vektor {}: 'gerekli_izinler' bir liste olmalidir".format(indeks))
    for grup_idx, izin_grubu in enumerate(vektor.get("gerekli_izinler", [])):
        if not isinstance(izin_grubu, list):
            raise ValueError("Vektor {}: gerekli_izinler[{}] bir liste olmalidir".format(indeks, grup_idx))
        for izin_idx, izin in enumerate(izin_grubu):
            if not isinstance(izin, str):
                raise ValueError(
                    "Vektor {}: gerekli_izinler[{}][{}] bir metin olmalidir".format(indeks, grup_idx, izin_idx)
                )
    if not isinstance(vektor.get("risk_skoru"), (int, float)):
        raise ValueError("Vektor {}: 'risk_skoru' sayisal bir deger olmalidir".format(indeks))
    gecerli_seviyeler = ["Kritik", "Yuksek", "Orta", "Dusuk", "Bilgilendirme"]
    if vektor.get("risk_seviyesi") not in gecerli_seviyeler:
        raise ValueError("Vektor {}: 'risk_seviyesi' gecersiz: {}".format(indeks, vektor.get("risk_seviyesi")))


def vektorleri_yukle(bulut="aws"):
    global _VEKTOR_ONBELLEGI
    if _VEKTOR_ONBELLEGI is not None and bulut == "aws":
        return _VEKTOR_ONBELLEGI
    mevcut_dizin = os.path.dirname(os.path.abspath(__file__))
    if bulut == "aws":
        json_yolu = os.path.join(mevcut_dizin, "vektorler.json")
    elif bulut == "gcp":
        json_yolu = os.path.join(mevcut_dizin, "vektorler_gcp.json")
    elif bulut == "azure":
        json_yolu = os.path.join(mevcut_dizin, "vektorler_azure.json")
    else:
        logger.error("Desteklenmeyen bulut saglayicisi: %s", bulut)
        return {"vektorler": [], "ozel_durumlar": {}}
    try:
        with open(json_yolu, "r", encoding="utf-8") as dosya:
            veri = json.load(dosya)
        for idx, vektor in enumerate(veri.get("vektorler", [])):
            try:
                vektor_dogrula(vektor, idx + 1)
            except ValueError as hata:
                logger.warning("Vektor dogrulama hatasi: %s", hata)
        if bulut == "aws":
            _VEKTOR_ONBELLEGI = veri
        logger.info("Vektor tanimlari yuklendi ve dogrulandi: %s (%s)", json_yolu, bulut)
        return veri
    except FileNotFoundError:
        logger.error("Vektor tanim dosyasi bulunamadi: %s", json_yolu)
        return {"vektorler": [], "ozel_durumlar": {}}


def kontrol_edilecek_eylemleri_derle(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    eylemler = set()
    for vektor in vektor_verisi.get("vektorler", []):
        for izin_grubu in vektor.get("gerekli_izinler", []):
            for izin in izin_grubu:
                eylemler.add(izin)
    return sorted(list(eylemler))


def dugum_zafiyet_esleme_olustur(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    esleme = {}
    for vektor in vektor_verisi.get("vektorler", []):
        dugum = vektor.get("saldiri_grafi_dugumu", "")
        baslik = vektor.get("turkce_baslik", "")
        if dugum and baslik:
            esleme[dugum] = baslik
    return esleme


def risk_skoru_tablosu_olustur(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    tablo = {}
    for vektor in vektor_verisi.get("vektorler", []):
        baslik = vektor.get("turkce_baslik", "")
        skor = vektor.get("risk_skoru", 5.0)
        if baslik:
            tablo[baslik] = skor
    ozel = vektor_verisi.get("ozel_durumlar", {})
    if "bilinmeyen_yetki" in ozel:
        tablo["Bilinmeyen Yetki Durumu"] = ozel["bilinmeyen_yetki"].get("risk_skoru", 5.0)
    return tablo


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


# Lazy import edilen moduller — sadece cagrildiginda yuklenir
def web_dashboard_baslat(argumanlar):
    """Streamlit web dashboard baslatir (lazy import)."""
    from tulpar.web_dashboard import web_dashboard_baslat as _web_baslat

    return _web_baslat(argumanlar)


def ai_yonetici_ozeti_uret(bulunan_zafiyetler, provider="openai", api_key=None, model=None):
    """AI yonetici ozeti uretir (lazy import)."""
    from tulpar.ai_analiz import ai_yonetici_ozeti_uret as _ai_uret

    return _ai_uret(bulunan_zafiyetler, provider=provider, api_key=api_key, model=model)


def sri_hash_hesapla(dosya_yolu):
    sha384_hash = hashlib.sha384()
    with open(dosya_yolu, "rb") as dosya:
        for blok in iter(lambda: dosya.read(65536), b""):
            sha384_hash.update(blok)
    return "sha384-" + base64.b64encode(sha384_hash.digest()).decode("utf-8")


def cevrimdisi_asset_indir(hedef_klasor, bootstrap_url, vis_network_url):
    from tulpar.sabitler import SRI_BOOTSTRAP_HASH, SRI_VIS_NETWORK_HASH

    indirilen_dosyalar = {}
    os.makedirs(hedef_klasor, exist_ok=True)
    bootstrap_yerel_yol = os.path.join(hedef_klasor, "bootstrap.min.css")
    vis_network_yerel_yol = os.path.join(hedef_klasor, "vis-network.min.js")
    try:
        logger.info("Cevrimdisi asset indiriliyor: Bootstrap CSS...")
        urllib.request.urlretrieve(bootstrap_url, bootstrap_yerel_yol)  # nosec B310
        indirilen_hash = sri_hash_hesapla(bootstrap_yerel_yol)
        if indirilen_hash != SRI_BOOTSTRAP_HASH:
            logger.warning(
                "Bootstrap CSS hash uyusmazligi! Beklenen: %s, Indirilen: %s. "
                "Dosya bozuk veya manipule edilmis olabilir.",
                SRI_BOOTSTRAP_HASH,
                indirilen_hash,
            )
            os.unlink(bootstrap_yerel_yol)
            indirilen_dosyalar["bootstrap"] = None
        else:
            indirilen_dosyalar["bootstrap"] = bootstrap_yerel_yol
            logger.info("Bootstrap CSS indirildi ve dogrulandi: %s", bootstrap_yerel_yol)
    except Exception as hata:
        logger.warning("Bootstrap CSS indirilemedi: %s. CDN baglantisina geri donuluyor.", hata)
        indirilen_dosyalar["bootstrap"] = None
    try:
        logger.info("Cevrimdisi asset indiriliyor: vis-network JS...")
        urllib.request.urlretrieve(vis_network_url, vis_network_yerel_yol)  # nosec B310
        indirilen_hash = sri_hash_hesapla(vis_network_yerel_yol)
        if indirilen_hash != SRI_VIS_NETWORK_HASH:
            logger.warning(
                "vis-network JS hash uyusmazligi! Beklenen: %s, Indirilen: %s. "
                "Dosya bozuk veya manipule edilmis olabilir.",
                SRI_VIS_NETWORK_HASH,
                indirilen_hash,
            )
            os.unlink(vis_network_yerel_yol)
            indirilen_dosyalar["vis_network"] = None
        else:
            indirilen_dosyalar["vis_network"] = vis_network_yerel_yol
            logger.info("vis-network JS indirildi ve dogrulandi: %s", vis_network_yerel_yol)
    except Exception as hata:
        logger.warning("vis-network JS indirilemedi: %s. CDN baglantisina geri donuluyor.", hata)
        indirilen_dosyalar["vis_network"] = None
    return indirilen_dosyalar


def onbellege_kaydet(dosya_yolu, veri):
    try:
        with open(dosya_yolu, "w", encoding="utf-8") as dosya:
            json.dump(veri, dosya, ensure_ascii=False, indent=4)
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


def csv_raporu_yaz(bulgular, cikti_dosyasi):
    alan_isimleri = [
        "zafiyet_adi",
        "kritiklik_seviyesi",
        "risk_skoru",
        "aciklama",
        "cloudtrail_izi",
        "sikiastirma_onerisi",
        "somuru_komutu",
        "mavi_takim_onerisi",
        "scp_kisitlamasi_var",
    ]
    try:
        with open(cikti_dosyasi, "w", newline="", encoding="utf-8") as dosya:
            yazici = csv.DictWriter(dosya, fieldnames=alan_isimleri, extrasaction="ignore")
            yazici.writeheader()
            for bulgu in bulgular:
                yazici.writerow({k: bulgu.get(k, "") for k in alan_isimleri})
        logger.info("CSV raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("CSV raporu olusturulamadi: %s", hata)
        return False


def markdown_raporu_yaz(bulgular, cikti_dosyasi, scp_durumu=None):
    try:
        satirlar = []
        satirlar.append("# Tulpar AWS IAM Yetki Yukseltme Raporu")
        satirlar.append("")
        satirlar.append("**Rapor Tarihi:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        satirlar.append("")
        satirlar.append("**Tespit Edilen Zafiyet Sayisi:** " + str(len(bulgular)))
        satirlar.append("")
        if scp_durumu is not None:
            satirlar.append(
                "**SCP Kisitlamasi:** "
                + (
                    "Var (SCP uygulanmis, yetkiler kisitlanmis olabilir)"
                    if scp_durumu
                    else "Yok (SCP uygulanmamis, IAM politikalari tam gecerli)"
                )
            )
            satirlar.append("")
        satirlar.append("---")
        satirlar.append("")
        for idx, bulgu in enumerate(bulgular, 1):
            satirlar.append("## " + str(idx) + ". " + bulgu.get("zafiyet_adi", "Bilinmeyen"))
            satirlar.append("")
            kritiklik = bulgu.get("kritiklik_seviyesi", "Belirsiz")
            risk = bulgu.get("risk_skoru", "-")
            satirlar.append("| Oznitelik | Deger |")
            satirlar.append("|-----------|-------|")
            satirlar.append("| Kritiklik Seviyesi | **" + kritiklik + "** |")
            satirlar.append("| Risk Skoru | **" + str(risk) + " / 10** |")
            satirlar.append("| CloudTrail Izi | `" + bulgu.get("cloudtrail_izi", "-") + "` |")
            if bulgu.get("scp_kisitlamasi_var") is not None:
                satirlar.append(
                    "| SCP Kisitlamasi | " + ("Evet" if bulgu.get("scp_kisitlamasi_var") else "Hayir") + " |"
                )
            satirlar.append("")
            satirlar.append("### Aciklama")
            satirlar.append("")
            satirlar.append(bulgu.get("aciklama", "-"))
            satirlar.append("")
            if bulgu.get("somuru_komutu"):
                satirlar.append("### Somuru Komutu")
                satirlar.append("")
                satirlar.append("```bash")
                satirlar.append(bulgu.get("somuru_komutu", ""))
                satirlar.append("```")
                satirlar.append("")
            satirlar.append("### Sikilastirma Onerisi")
            satirlar.append("")
            satirlar.append(bulgu.get("sikiastirma_onerisi", "-"))
            satirlar.append("")
            if bulgu.get("mavi_takim_onerisi"):
                satirlar.append("### Mavi Takim Savunma Onerisi")
                satirlar.append("")
                satirlar.append(bulgu.get("mavi_takim_onerisi", "-"))
                satirlar.append("")
            satirlar.append("---")
            satirlar.append("")
        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            dosya.write("\n".join(satirlar))
        logger.info("Markdown raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("Markdown raporu olusturulamadi: %s", hata)
        return False


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
    if ":" not in iam_eylemi:
        return iam_eylemi, iam_eylemi
    servis, eylem = iam_eylemi.split(":", 1)
    return servis, eylem


def servis_eylem_listesini_grupla(eylem_listesi):
    gruplar = {}
    for eylem in eylem_listesi:
        servis, _ = servis_adi_ayristir(eylem)
        if servis not in gruplar:
            gruplar[servis] = []
        gruplar[servis].append(eylem)
    return gruplar


def onbellek_suresi_gecerli_mi(onbellek_dosyasi, maksimum_sure_saat=24):
    if not os.path.exists(onbellek_dosyasi):
        return False
    dosya_zamani = os.path.getmtime(onbellek_dosyasi)
    guncel_zaman = datetime.now().timestamp()
    fark_saat = (guncel_zaman - dosya_zamani) / 3600.0
    return fark_saat < maksimum_sure_saat


def sarif_raporu_yaz(bulgular, cikti_dosyasi, arac_adi="Tulpar"):
    from tulpar.sabitler import SURUM

    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        sonuclar = []
        for idx, bulgu in enumerate(bulgular):
            risk = bulgu.get("risk_skoru", 5.0)
            if isinstance(risk, (int, float)):
                if risk >= 9.0:
                    seviye = "error"
                elif risk >= 7.0:
                    seviye = "warning"
                else:
                    seviye = "note"
            else:
                seviye = "warning"
            konum = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "iam:{}".format(bulgu.get("cloudtrail_izi", "bilinmeyen").split(",")[0].strip())
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
            sonuc = {
                "ruleId": bulgu.get("zafiyet_adi", "Bilinmeyen").replace(" ", "_")[:80],
                "ruleIndex": idx,
                "level": seviye,
                "message": {
                    "text": "{} [Risk: {}/10] - {}".format(
                        bulgu.get("zafiyet_adi", "Bilinmeyen"), bulgu.get("risk_skoru", "-"), bulgu.get("aciklama", "")
                    )
                },
                "locations": [konum],
                "properties": {
                    "kritiklik_seviyesi": bulgu.get("kritiklik_seviyesi", "Belirsiz"),
                    "risk_skoru": str(bulgu.get("risk_skoru", "-")),
                    "cloudtrail_izi": bulgu.get("cloudtrail_izi", ""),
                    "sikiastirma_onerisi": bulgu.get("sikiastirma_onerisi", ""),
                    "somuru_komutu": bulgu.get("somuru_komutu", ""),
                    "mavi_takim_onerisi": bulgu.get("mavi_takim_onerisi", ""),
                },
            }
            sonuclar.append(sonuc)
        arac = {
            "driver": {
                "name": arac_adi,
                "organization": "Tulpar Framework",
                "semanticVersion": SURUM,
                "rules": [
                    {
                        "id": b.get("zafiyet_adi", "Bilinmeyen").replace(" ", "_")[:80],
                        "name": b.get("zafiyet_adi", "Bilinmeyen"),
                        "shortDescription": {"text": b.get("aciklama", "")[:500]},
                        "helpUri": "https://github.com/mecik-arda/Tulpar-Framework",
                    }
                    for b in bulgular
                ],
            }
        }
        sarif_verisi = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": arac, "results": sonuclar}],
        }
        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            json.dump(sarif_verisi, dosya, ensure_ascii=False, indent=2)
        logger.info("SARIF raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("SARIF raporu olusturulamadi: %s", hata)
        return False


def duzeltme_scripti_uret(bulgular, cikti_dosyasi):
    """Tespit edilen zafiyetler için otomatik Terraform ve AWS CLI düzeltme kodları üretir."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        satirlar = []
        satirlar.append("# Tulpar Otomatik Duzeltme Scripti")
        satirlar.append("")
        satirlar.append("**Uretim Tarihi:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        satirlar.append("")
        satirlar.append(
            "> **UYARI:** Bu script otomatik uretilmistir. "
            "Uygulamadan once gozden gecirin ve test ortaminda deneyin."
        )
        satirlar.append("")
        satirlar.append("---")
        satirlar.append("")

        duzeltme_eylemleri = {
            "iam:CreatePolicyVersion": {
                "aws_cli": (
                    "aws iam delete-policy-version --policy-arn HEDEF_POLITIKA_ARN --version-id v2"
                ),
                "terraform": (
                    'resource "aws_iam_policy" "guvenli_politika" {\n'
                    '  name        = "guvenli-politika"\n'
                    '  description = "Siki politika"\n'
                    '  policy      = data.aws_iam_policy_document.guvenli.json\n'
                    '}'
                ),
                "oneri": (
                    "Politika surumu olusturma yetkisini kaldirin "
                    "veya sadece belirli politikalara kisitlayin."
                ),
            },
            "iam:AttachUserPolicy": {
                "aws_cli": (
                    "aws iam detach-user-policy --user-name HEDEF_KULLANICI "
                    "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                ),
                "terraform": (
                    'resource "aws_iam_user_policy_attachment" "guvenli" {\n'
                    '  user       = aws_iam_user.kullanici.name\n'
                    '  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n'
                    '}'
                ),
                "oneri": (
                    "Kullaniciya dogrudan AdministratorAccess gibi yuksek yetkili "
                    "politikalar eklenmesini engelleyin."
                ),
            },
            "iam:PassRole": {
                "aws_cli": (
                    "# IAM Policy Condition ile PassRole kisitlamasi:\n"
                    "aws iam put-role-policy --role-name HEDEF_ROL "
                    "--policy-name passrole-kisitlamasi "
                    "--policy-document '{\"Version\":\"2012-10-17\","
                    "\"Statement\":[{\"Effect\":\"Deny\","
                    "\"Action\":\"iam:PassRole\",\"Resource\":\"*\","
                    "\"Condition\":{\"StringNotEquals\":"
                    "{\"iam:PassedToService\":\"ec2.amazonaws.com\"}}}]}'"
                ),
                "terraform": (
                    'resource "aws_iam_role_policy" "passrole_kisitlamasi" {\n'
                    '  name = "passrole-kisitlamasi"\n'
                    '  role = aws_iam_role.hedef_rol.id\n'
                    '  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n'
                    '    Statement = [{\n'
                    '      Effect = "Deny"\n'
                    '      Action = "iam:PassRole"\n'
                    '      Resource = "*"\n'
                    '    }]\n'
                    '  })\n'
                    '}'
                ),
                "oneri": (
                    "PassRole yetkisini sadece guvenilir servisler "
                    "ve belirli rollerle sinirlandirin."
                ),
            },
            "ssm:SendCommand": {
                "aws_cli": (
                    "# SSM SendCommand yetkisini kaldirin:\n"
                    "aws iam delete-role-policy --role-name HEDEF_ROL "
                    "--policy-name ssm-send-command"
                ),
                "terraform": (
                    'resource "aws_iam_policy" "ssm_kisitlamasi" {\n'
                    '  name = "ssm-kisitlamasi"\n'
                    '  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n'
                    '    Statement = [{\n'
                    '      Effect = "Deny"\n'
                    '      Action = "ssm:SendCommand"\n'
                    '      Resource = "*"\n'
                    '    }]\n'
                    '  })\n'
                    '}'
                ),
                "oneri": (
                    "SSM SendCommand yetkisini kaldirin veya "
                    "sadece belirli EC2 kaynaklarina kisitlayin."
                ),
            },
        }

        genel_terraform_bloklari = []
        genel_aws_cli_komutlari = []

        for idx, bulgu in enumerate(bulgular, 1):
            zafiyet_adi = bulgu.get("zafiyet_adi", "Bilinmeyen")
            cloudtrail_izi = bulgu.get("cloudtrail_izi", "")
            satirlar.append("## {}. {}".format(idx, zafiyet_adi))
            satirlar.append("")
            satirlar.append("| Oznitelik | Deger |")
            satirlar.append("|-----------|-------|")
            satirlar.append("| Kritiklik | **{}** |".format(bulgu.get("kritiklik_seviyesi", "-")))
            satirlar.append("| Risk Skoru | **{}/10** |".format(bulgu.get("risk_skoru", "-")))
            satirlar.append("")
            satirlar.append("### Sikiastirma Onerisi")
            satirlar.append("")
            satirlar.append(bulgu.get("sikiastirma_onerisi", "Manuel inceleme gerekli."))
            satirlar.append("")

            birincil_iz = cloudtrail_izi.split(",")[0].strip() if cloudtrail_izi else ""
            duzeltme = duzeltme_eylemleri.get(birincil_iz)
            if duzeltme:
                satirlar.append("### AWS CLI Duzeltme Komutu")
                satirlar.append("")
                satirlar.append("```bash")
                satirlar.append(duzeltme["aws_cli"])
                satirlar.append("```")
                satirlar.append("")
                satirlar.append("### Terraform Duzeltme Blogu")
                satirlar.append("")
                satirlar.append("```hcl")
                satirlar.append(duzeltme["terraform"])
                satirlar.append("```")
                satirlar.append("")
                genel_aws_cli_komutlari.append(duzeltme["aws_cli"])
                genel_terraform_bloklari.append(duzeltme["terraform"])
            else:
                satirlar.append("### Genel Duzeltme Yaklasimi")
                satirlar.append("")
                satirlar.append("Bu zafiyet tipi icin en az yetki (least privilege) prensibini uygulayin:")
                satirlar.append("- Ilgili IAM yetkisini kaldirin veya dar kapsamli kaynaklara kisitlayin")
                satirlar.append("- CloudTrail alarmlari kurarak bu API cagrilarini izleyin")
                satirlar.append("- AWS Config kurallari ile uyumlulugu otomatik denetleyin")
                satirlar.append("")
            satirlar.append("---")
            satirlar.append("")

        if genel_aws_cli_komutlari:
            satirlar.insert(3, "## Toplu AWS CLI Duzeltme Betigi")
            satirlar.insert(4, "")
            satirlar.insert(5, "```bash")
            satirlar.insert(6, "#!/bin/bash")
            satirlar.insert(7, "# Tulpar Otomatik Duzeltme Betigi - Tum Zafiyetler")
            satirlar.insert(8, "")
            for idx, komut in enumerate(genel_aws_cli_komutlari):
                satirlar.insert(9 + idx, "# Zafiyet " + str(idx + 1))
                satirlar.insert(10 + idx, komut)
                satirlar.insert(11 + idx, "")
            satirlar.insert(12 + len(genel_aws_cli_komutlari), "```")
            satirlar.insert(13 + len(genel_aws_cli_komutlari), "")

        if genel_terraform_bloklari:
            satirlar.append("## Toplu Terraform Duzeltme Betigi")
            satirlar.append("")
            satirlar.append("```hcl")
            satirlar.append("# Tulpar Otomatik Terraform Duzeltme Betigi")
            satirlar.append("")
            for idx, blok in enumerate(genel_terraform_bloklari):
                satirlar.append("# Zafiyet " + str(idx + 1))
                satirlar.append(blok)
                satirlar.append("")
            satirlar.append("```")
            satirlar.append("")

        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            dosya.write("\n".join(satirlar))
        logger.info("Duzeltme scripti olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("Duzeltme scripti olusturulamadi: %s", hata)
        return False


def bloodhound_disa_aktar(saldiri_yollari, bulunan_zafiyetler, cikti_dosyasi, kimlik_bilgileri=None):
    """Saldiri yollarini BloodHound/Neo4j uyumlu JSON formatinda disa aktarir."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        dugumler = []
        kenarlar = []
        eklenen_dugumler = set()
        dugum_id_sayaci = 1
        dugum_sozlugu = {}

        for kaynak, hedef_ara, son_hedef in saldiri_yollari:
            for isim in [kaynak, hedef_ara, son_hedef]:
                if isim not in eklenen_dugumler:
                    dugum_tipi = "AZPrincipal"
                    if isim == "AdministratorAccess" or isim == "YoneticiRolu_Ustlenme":
                        dugum_tipi = "AZHighValue"
                    elif isim == "Baslangic":
                        dugum_tipi = "AZUser"
                    elif ":" in isim:
                        dugum_tipi = "AZPermissionSet"

                    dugum_sozlugu[isim] = dugum_id_sayaci
                    dugum = {
                        "id": dugum_id_sayaci,
                        "label": isim,
                        "type": dugum_tipi,
                        "properties": {
                            "name": isim,
                            "description": "Tulpar taramasi ile tespit edildi",
                            "highvalue": dugum_tipi == "AZHighValue",
                        },
                    }
                    dugumler.append(dugum)
                    eklenen_dugumler.add(isim)
                    dugum_id_sayaci += 1

            kenarlar.append(
                {
                    "from": dugum_sozlugu[kaynak],
                    "to": dugum_sozlugu[hedef_ara],
                    "type": "AZPrivilegeEscalation",
                    "properties": {"description": "Olası yetki yukseltme yolu", "risk": "Yuksek"},
                }
            )
            kenarlar.append(
                {
                    "from": dugum_sozlugu[hedef_ara],
                    "to": dugum_sozlugu[son_hedef],
                    "type": "AZAdminAccess",
                    "properties": {"description": "Yonetici erisimi elde etme yolu", "risk": "Kritik"},
                }
            )

        zafiyet_detaylari = {}
        for zafiyet in bulunan_zafiyetler:
            zafiyet_adi = zafiyet.get("zafiyet_adi", "")
            zafiyet_detaylari[zafiyet_adi] = {
                "risk_skoru": zafiyet.get("risk_skoru", "-"),
                "kritiklik": zafiyet.get("kritiklik_seviyesi", "Belirsiz"),
                "aciklama": zafiyet.get("aciklama", ""),
                "cloudtrail_izi": zafiyet.get("cloudtrail_izi", ""),
                "somuru_komutu": zafiyet.get("somuru_komutu", ""),
                "sikiastirma_onerisi": zafiyet.get("sikiastirma_onerisi", ""),
            }

        kanit_bilgisi = {}
        if kimlik_bilgileri:
            kanit_bilgisi = {
                "scan_arn": kimlik_bilgileri.get("arn", ""),
                "account_id": kimlik_bilgileri.get("hesap_id", ""),
                "user_id": kimlik_bilgileri.get("kullanici_id", ""),
            }

        bloodhound_verisi = {
            "format": "BloodHound 4.x / Neo4j Compatible",
            "source": "Tulpar AWS IAM Scanner v2.1.0",
            "export_date": datetime.now().isoformat(),
            "metadata": {
                "total_nodes": len(dugumler),
                "total_edges": len(kenarlar),
                "privilege_escalation_paths": len(saldiri_yollari),
                "scan_evidence": kanit_bilgisi,
            },
            "nodes": dugumler,
            "edges": kenarlar,
            "vulnerability_details": zafiyet_detaylari,
        }

        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            json.dump(bloodhound_verisi, dosya, ensure_ascii=False, indent=2)
        logger.info("BloodHound disa aktarimi olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("BloodHound disa aktarimi basarisiz: %s", hata)
        return False


def tui_dashboard_goster(argumanlar):
    """Rich kutuphanesi ile modern terminal arayuzu saglar."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
        from rich.table import Table
        from rich.text import Text
        from rich import box
        import time
    except ImportError:
        logger.warning("Rich kutuphanesi kurulu degil. 'pip install rich' ile kurabilirsiniz.")
        logger.info("TUI modu devre disi, standart modda devam ediliyor...")
        return

    from tulpar.sabitler import SURUM

    konsol = Console()
    konsol.clear()

    baslik_paneli = Panel(
        Text("Tulpar AWS IAM Yetki Yukseltme Tarayicisi v" + SURUM, style="bold cyan"),
        subtitle="[yellow]Ofansif Guvenlik Araci[/yellow]",
        border_style="cyan",
    )
    konsol.print(baslik_paneli)

    konsol.print("\n[bold]TUI modu aktif. Tarama baslatiliyor...[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=konsol,
    ) as ilerleme:

        kimlik_gorevi = ilerleme.add_task("[cyan]Kimlik dogrulama...", total=100)
        ilerleme.update(kimlik_gorevi, advance=30)

        scp_gorevi = ilerleme.add_task("[yellow]SCP kontrolu...", total=100)
        ilerleme.update(scp_gorevi, advance=50)

        bolge_gorevi = ilerleme.add_task("[green]Coklu bolge kaynak taramasi...", total=100)

        for i in range(5):
            time.sleep(0.1)
            ilerleme.update(bolge_gorevi, advance=20)

        ilerleme.update(kimlik_gorevi, advance=70)
        ilerleme.update(scp_gorevi, advance=50)

        simulasyon_gorevi = ilerleme.add_task("[magenta]IAM hak simulasyonu...", total=100)
        for i in range(10):
            time.sleep(0.05)
            ilerleme.update(simulasyon_gorevi, advance=10)

        vektor_gorevi = ilerleme.add_task("[blue]Vektor taramasi...", total=65)
        for i in range(65):
            time.sleep(0.02)
            ilerleme.update(vektor_gorevi, advance=1)

        rapor_gorevi = ilerleme.add_task("[green]Rapor olusturma...", total=100)
        for i in range(5):
            time.sleep(0.1)
            ilerleme.update(rapor_gorevi, advance=20)

    konsol.print("")
    ozet_tablosu = Table(title="Tulpar Tarama Ozeti", box=box.ROUNDED, border_style="cyan")
    ozet_tablosu.add_column("Oznitelik", style="cyan", no_wrap=True)
    ozet_tablosu.add_column("Deger", style="green")
    ozet_tablosu.add_row("Arac Surumu", SURUM)
    ozet_tablosu.add_row("Bulut Saglayici", argumanlar.bulut.upper())
    ozet_tablosu.add_row("Hizli Mod", "Evet" if argumanlar.hizli else "Hayir")
    ozet_tablosu.add_row("CloudTrail Analizi", "Evet" if argumanlar.cloudtrail_analiz else "Hayir")
    ozet_tablosu.add_row("Access Analyzer", "Evet" if argumanlar.access_analyzer else "Hayir")
    ozet_tablosu.add_row("Otomatik Duzeltme", "Evet" if argumanlar.duzelt else "Hayir")
    konsol.print(ozet_tablosu)

    konsol.print("\n[bold green]TUI taramasi tamamlandi![/bold green]")
    konsol.print("[dim]Detayli raporlar raporlar/ dizininde olusturuldu.[/dim]")
    konsol.print("[yellow]Not: TUI demo modudur. Gercek tarama icin --tui bayragi olmadan calistirin.[/yellow]")


def rapor_karsilastir(onceki_dosya, yeni_dosya, karsilastirma_ciktisi):
    try:
        with open(onceki_dosya, "r", encoding="utf-8") as dosya:
            onceki_veri = json.load(dosya)
        with open(yeni_dosya, "r", encoding="utf-8") as dosya:
            yeni_veri = json.load(dosya)
    except FileNotFoundError as hata:
        logger.error("Karsilastirma dosyasi bulunamadi: %s", hata)
        return None
    except json.JSONDecodeError as hata:
        logger.error("Karsilastirma dosyasi gecersiz JSON: %s", hata)
        return None
    onceki_adlar = {b.get("zafiyet_adi", "") for b in onceki_veri.get("bulgular", [])}
    yeni_adlar = {b.get("zafiyet_adi", "") for b in yeni_veri.get("bulgular", [])}
    yeni_eklenenler = yeni_adlar - onceki_adlar
    kapananlar = onceki_adlar - yeni_adlar
    devam_edenler = onceki_adlar & yeni_adlar
    onceki_yeni_bulgu_listesi = [
        b for b in yeni_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in yeni_eklenenler
    ]
    onceki_kapanan_bulgu_listesi = [
        b for b in onceki_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in kapananlar
    ]
    onceki_devam_bulgu_listesi = [b for b in yeni_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in devam_edenler]
    fark_raporu = {
        "arac_adi": "Tulpar Diff Raporu",
        "rapor_tarihi": datetime.now().isoformat(),
        "onceki_dosya": onceki_dosya,
        "yeni_dosya": yeni_dosya,
        "ozet": {
            "onceki_zafiyet_sayisi": onceki_veri.get("zafiyet_sayisi", 0),
            "yeni_zafiyet_sayisi": yeni_veri.get("zafiyet_sayisi", 0),
            "yeni_eklenen_zafiyet_sayisi": len(yeni_eklenenler),
            "kapanan_zafiyet_sayisi": len(kapananlar),
            "devam_eden_zafiyet_sayisi": len(devam_edenler),
        },
        "yeni_eklenen_zafiyetler": onceki_yeni_bulgu_listesi,
        "kapanan_zafiyetler": onceki_kapanan_bulgu_listesi,
        "devam_eden_zafiyetler": onceki_devam_bulgu_listesi,
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(karsilastirma_ciktisi)) or ".", exist_ok=True)
        with open(karsilastirma_ciktisi, "w", encoding="utf-8") as dosya:
            json.dump(fark_raporu, dosya, ensure_ascii=False, indent=4)
        logger.info(
            "Karsilastirma raporu olusturuldu: %s (Yeni: %d, Kapanan: %d, Devam: %d)",
            karsilastirma_ciktisi,
            len(yeni_eklenenler),
            len(kapananlar),
            len(devam_edenler),
        )
        return fark_raporu
    except Exception as hata:
        logger.error("Karsilastirma raporu yazilamadi: %s", hata)
        return None
