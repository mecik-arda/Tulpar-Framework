import os
import json
import logging
import hashlib
import base64
import urllib.request
import urllib.error

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
    
    # URL security check
    allowed_domains = ["https://cdn.jsdelivr.net/", "https://cdnjs.cloudflare.com/", "https://stackpath.bootstrapcdn.com/"]
    def is_safe_url(url):
        return any(url.startswith(domain) for domain in allowed_domains)

    try:
        if not is_safe_url(bootstrap_url):
            raise ValueError(f"Guvenli olmayan URL: {bootstrap_url}")
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
        if not is_safe_url(vis_network_url):
            raise ValueError(f"Guvenli olmayan URL: {vis_network_url}")
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
