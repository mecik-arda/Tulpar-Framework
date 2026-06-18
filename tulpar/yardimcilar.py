import os
import json
import logging
import hashlib
import csv
import urllib.request
import urllib.error
from datetime import datetime

logger = logging.getLogger('Tulpar')

_VEKTOR_ONBELLEGI = None


ZORUNLU_VEKTOR_ALANLARI = ['vektor_adi', 'turkce_baslik', 'gerekli_izinler', 'risk_seviyesi', 'risk_skoru', 'aciklama', 'iyilestirme', 'cloudtrail_izi', 'somuru_komutu', 'mavi_takim_onerisi', 'saldiri_grafi_dugumu', 'saldiri_grafi_hedefi']


def vektor_onbellegi_temizle():
    global _VEKTOR_ONBELLEGI
    _VEKTOR_ONBELLEGI = None
    logger.debug("Vektor onbellegi temizlendi")


def vektor_dogrula(vektor, indeks):
    for alan in ZORUNLU_VEKTOR_ALANLARI:
        if alan not in vektor:
            raise ValueError("Vektor {}: '{}' alani eksik".format(indeks, alan))
    if not isinstance(vektor.get('gerekli_izinler'), list):
        raise ValueError("Vektor {}: 'gerekli_izinler' bir liste olmalidir".format(indeks))
    for grup_idx, izin_grubu in enumerate(vektor.get('gerekli_izinler', [])):
        if not isinstance(izin_grubu, list):
            raise ValueError("Vektor {}: gerekli_izinler[{}] bir liste olmalidir".format(indeks, grup_idx))
        for izin_idx, izin in enumerate(izin_grubu):
            if not isinstance(izin, str):
                raise ValueError("Vektor {}: gerekli_izinler[{}][{}] bir metin olmalidir".format(indeks, grup_idx, izin_idx))
    if not isinstance(vektor.get('risk_skoru'), (int, float)):
        raise ValueError("Vektor {}: 'risk_skoru' sayisal bir deger olmalidir".format(indeks))
    gecerli_seviyeler = ['Kritik', 'Yuksek', 'Orta', 'Dusuk', 'Bilgilendirme']
    if vektor.get('risk_seviyesi') not in gecerli_seviyeler:
        raise ValueError("Vektor {}: 'risk_seviyesi' gecersiz: {}".format(indeks, vektor.get('risk_seviyesi')))


def vektorleri_yukle():
    global _VEKTOR_ONBELLEGI
    if _VEKTOR_ONBELLEGI is not None:
        return _VEKTOR_ONBELLEGI
    mevcut_dizin = os.path.dirname(os.path.abspath(__file__))
    json_yolu = os.path.join(mevcut_dizin, 'vektorler.json')
    try:
        with open(json_yolu, 'r', encoding='utf-8') as dosya:
            veri = json.load(dosya)
        for idx, vektor in enumerate(veri.get('vektorler', [])):
            try:
                vektor_dogrula(vektor, idx + 1)
            except ValueError as hata:
                logger.warning("Vektor dogrulama hatasi: %s", hata)
        _VEKTOR_ONBELLEGI = veri
        logger.info("Vektor tanimlari yuklendi ve dogrulandi: %s", json_yolu)
        return veri
    except FileNotFoundError:
        logger.error("Vektor tanim dosyasi bulunamadi: %s", json_yolu)
        return {"vektorler": [], "ozel_durumlar": {}}
    except json.JSONDecodeError as hata:
        logger.error("Vektor JSON dosyasi bozuk (satir %s, kolon %s): %s", hata.lineno, hata.colno, hata.msg)
        return {"vektorler": [], "ozel_durumlar": {}}


def kontrol_edilecek_eylemleri_derle(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    eylemler = set()
    for vektor in vektor_verisi.get('vektorler', []):
        for izin_grubu in vektor.get('gerekli_izinler', []):
            for izin in izin_grubu:
                eylemler.add(izin)
    return sorted(list(eylemler))


def dugum_zafiyet_esleme_olustur(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    esleme = {}
    for vektor in vektor_verisi.get('vektorler', []):
        dugum = vektor.get('saldiri_grafi_dugumu', '')
        baslik = vektor.get('turkce_baslik', '')
        if dugum and baslik:
            esleme[dugum] = baslik
    return esleme


def risk_skoru_tablosu_olustur(vektor_verisi=None):
    if vektor_verisi is None:
        vektor_verisi = vektorleri_yukle()
    tablo = {}
    for vektor in vektor_verisi.get('vektorler', []):
        baslik = vektor.get('turkce_baslik', '')
        skor = vektor.get('risk_skoru', 5.0)
        if baslik:
            tablo[baslik] = skor
    ozel = vektor_verisi.get('ozel_durumlar', {})
    if 'bilinmeyen_yetki' in ozel:
        tablo['Bilinmeyen Yetki Durumu'] = ozel['bilinmeyen_yetki'].get('risk_skoru', 5.0)
    return tablo

def loglama_yapilandir():
    kok_logger = logging.getLogger()
    if kok_logger.hasHandlers():
        return
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def aws_hatasi_yonet(hata, islem_adi):
    hata_kodu = hata.response['Error']['Code']
    hata_mesaji = hata.response['Error']['Message']
    if hata_kodu == 'AccessDenied':
        logger.warning("%s - Erisim Reddedildi: Bu API cagrisi icin yetkiniz bulunmamaktadir", islem_adi)
    elif hata_kodu == 'TokenExpired':
        logger.error("%s - Oturum Belirteci Suresi Doldu: Yeni bir oturum belirteci edinin", islem_adi)
    elif hata_kodu == 'InvalidClientTokenId':
        logger.error("%s - Gecersiz Erisim Anahtari: AWS kimlik bilgilerinizi kontrol edin", islem_adi)
    elif hata_kodu == 'UnauthorizedOperation':
        logger.warning("%s - Yetkisiz Islem: Bu eylemi gerceklestirme izniniz yok", islem_adi)
    elif hata_kodu == 'Throttling':
        logger.warning("%s - Istek Kisitlamasi: API istek limitine ulasildi, bekleyip tekrar deneyin", islem_adi)
    elif hata_kodu == 'ExpiredToken':
        logger.error("%s - Oturum Belirteci Gecersiz: Belirtecin suresi dolmus veya gecersiz", islem_adi)
    elif hata_kodu == 'SignatureDoesNotMatch':
        logger.error("%s - Imza Uyusmazligi: Gizli anahtariniz hatali olabilir", islem_adi)
    elif hata_kodu == 'RequestExpired':
        logger.error("%s - Istek Zamani Gecti: Sistem saatinizin dogru oldugundan emin olun", islem_adi)
    else:
        logger.error("%s - Beklenmeyen Hata [%s]: %s", islem_adi, hata_kodu, hata_mesaji)

def sri_hash_hesapla(dosya_yolu):
    sha384_hash = hashlib.sha384()
    with open(dosya_yolu, 'rb') as dosya:
        for blok in iter(lambda: dosya.read(65536), b''):
            sha384_hash.update(blok)
    return 'sha384-' + sha384_hash.hexdigest()

def cevrimdisi_asset_indir(hedef_klasor, bootstrap_url, vis_network_url):
    from tulpar.sabitler import SRI_BOOTSTRAP_HASH, SRI_VIS_NETWORK_HASH
    indirilen_dosyalar = {}
    os.makedirs(hedef_klasor, exist_ok=True)
    bootstrap_yerel_yol = os.path.join(hedef_klasor, 'bootstrap.min.css')
    vis_network_yerel_yol = os.path.join(hedef_klasor, 'vis-network.min.js')
    try:
        logger.info("Cevrimdisi asset indiriliyor: Bootstrap CSS...")
        urllib.request.urlretrieve(bootstrap_url, bootstrap_yerel_yol)
        indirilen_hash = sri_hash_hesapla(bootstrap_yerel_yol)
        if indirilen_hash != SRI_BOOTSTRAP_HASH:
            logger.warning("Bootstrap CSS hash uyusmazligi! Beklenen: %s, Indirilen: %s. Dosya bozuk veya manipule edilmis olabilir.", SRI_BOOTSTRAP_HASH, indirilen_hash)
            os.unlink(bootstrap_yerel_yol)
            indirilen_dosyalar['bootstrap'] = None
        else:
            indirilen_dosyalar['bootstrap'] = bootstrap_yerel_yol
            logger.info("Bootstrap CSS indirildi ve dogrulandi: %s", bootstrap_yerel_yol)
    except Exception as hata:
        logger.warning("Bootstrap CSS indirilemedi: %s. CDN baglantisina geri donuluyor.", hata)
        indirilen_dosyalar['bootstrap'] = None
    try:
        logger.info("Cevrimdisi asset indiriliyor: vis-network JS...")
        urllib.request.urlretrieve(vis_network_url, vis_network_yerel_yol)
        indirilen_hash = sri_hash_hesapla(vis_network_yerel_yol)
        if indirilen_hash != SRI_VIS_NETWORK_HASH:
            logger.warning("vis-network JS hash uyusmazligi! Beklenen: %s, Indirilen: %s. Dosya bozuk veya manipule edilmis olabilir.", SRI_VIS_NETWORK_HASH, indirilen_hash)
            os.unlink(vis_network_yerel_yol)
            indirilen_dosyalar['vis_network'] = None
        else:
            indirilen_dosyalar['vis_network'] = vis_network_yerel_yol
            logger.info("vis-network JS indirildi ve dogrulandi: %s", vis_network_yerel_yol)
    except Exception as hata:
        logger.warning("vis-network JS indirilemedi: %s. CDN baglantisina geri donuluyor.", hata)
        indirilen_dosyalar['vis_network'] = None
    return indirilen_dosyalar

def onbellege_kaydet(dosya_yolu, veri):
    try:
        with open(dosya_yolu, 'w', encoding='utf-8') as dosya:
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
        with open(dosya_yolu, 'r', encoding='utf-8') as dosya:
            veri = json.load(dosya)
        logger.info("Onbellekten tarama sonuclari yuklendi: %s", dosya_yolu)
        return veri
    except Exception as hata:
        logger.warning("Onbellekten yukleme basarisiz: %s", hata)
        return None

def csv_raporu_yaz(bulgular, cikti_dosyasi):
    alan_isimleri = [
        'zafiyet_adi', 'kritiklik_seviyesi', 'risk_skoru', 'aciklama',
        'cloudtrail_izi', 'sikiastirma_onerisi', 'somuru_komutu', 'mavi_takim_onerisi',
        'scp_kisitlamasi_var'
    ]
    try:
        with open(cikti_dosyasi, 'w', newline='', encoding='utf-8') as dosya:
            yazici = csv.DictWriter(dosya, fieldnames=alan_isimleri, extrasaction='ignore')
            yazici.writeheader()
            for bulgu in bulgular:
                yazici.writerow({k: bulgu.get(k, '') for k in alan_isimleri})
        logger.info("CSV raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("CSV raporu olusturulamadi: %s", hata)
        return False

def markdown_raporu_yaz(bulgular, cikti_dosyasi, scp_durumu=None):
    try:
        satirlar = []
        satirlar.append('# Tulpar AWS IAM Yetki Yukseltme Raporu')
        satirlar.append('')
        satirlar.append('**Rapor Tarihi:** ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        satirlar.append('')
        satirlar.append('**Tespit Edilen Zafiyet Sayisi:** ' + str(len(bulgular)))
        satirlar.append('')
        if scp_durumu is not None:
            satirlar.append('**SCP Kisitlamasi:** ' + ('Var (SCP uygulanmis, yetkiler kisitlanmis olabilir)' if scp_durumu else 'Yok (SCP uygulanmamis, IAM politikalari tam gecerli)'))
            satirlar.append('')
        satirlar.append('---')
        satirlar.append('')
        for idx, bulgu in enumerate(bulgular, 1):
            satirlar.append('## ' + str(idx) + '. ' + bulgu.get('zafiyet_adi', 'Bilinmeyen'))
            satirlar.append('')
            kritiklik = bulgu.get('kritiklik_seviyesi', 'Belirsiz')
            risk = bulgu.get('risk_skoru', '-')
            satirlar.append('| Oznitelik | Deger |')
            satirlar.append('|-----------|-------|')
            satirlar.append('| Kritiklik Seviyesi | **' + kritiklik + '** |')
            satirlar.append('| Risk Skoru | **' + str(risk) + ' / 10** |')
            satirlar.append('| CloudTrail Izi | `' + bulgu.get('cloudtrail_izi', '-') + '` |')
            if bulgu.get('scp_kisitlamasi_var') is not None:
                satirlar.append('| SCP Kisitlamasi | ' + ('Evet' if bulgu.get('scp_kisitlamasi_var') else 'Hayir') + ' |')
            satirlar.append('')
            satirlar.append('### Aciklama')
            satirlar.append('')
            satirlar.append(bulgu.get('aciklama', '-'))
            satirlar.append('')
            if bulgu.get('somuru_komutu'):
                satirlar.append('### Somuru Komutu')
                satirlar.append('')
                satirlar.append('```bash')
                satirlar.append(bulgu.get('somuru_komutu', ''))
                satirlar.append('```')
                satirlar.append('')
            satirlar.append('### Sikilastirma Onerisi')
            satirlar.append('')
            satirlar.append(bulgu.get('sikiastirma_onerisi', '-'))
            satirlar.append('')
            if bulgu.get('mavi_takim_onerisi'):
                satirlar.append('### Mavi Takim Savunma Onerisi')
                satirlar.append('')
                satirlar.append(bulgu.get('mavi_takim_onerisi', '-'))
                satirlar.append('')
            satirlar.append('---')
            satirlar.append('')
        with open(cikti_dosyasi, 'w', encoding='utf-8') as dosya:
            dosya.write('\n'.join(satirlar))
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
        with open(konfig_dosyasi, 'r', encoding='utf-8') as dosya:
            if konfig_dosyasi.endswith('.yaml') or konfig_dosyasi.endswith('.yml'):
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
    if ':' not in iam_eylemi:
        return iam_eylemi, iam_eylemi
    servis, eylem = iam_eylemi.split(':', 1)
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
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or '.', exist_ok=True)
        sonuclar = []
        for idx, bulgu in enumerate(bulgular):
            risk = bulgu.get('risk_skoru', 5.0)
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
                        "uri": "iam:{}".format(bulgu.get('cloudtrail_izi', 'bilinmeyen').split(',')[0].strip())
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1
                    }
                }
            }
            sonuc = {
                "ruleId": bulgu.get('zafiyet_adi', 'Bilinmeyen').replace(' ', '_')[:80],
                "ruleIndex": idx,
                "level": seviye,
                "message": {
                    "text": "{} [Risk: {}/10] - {}".format(
                        bulgu.get('zafiyet_adi', 'Bilinmeyen'),
                        bulgu.get('risk_skoru', '-'),
                        bulgu.get('aciklama', '')
                    )
                },
                "locations": [konum],
                "properties": {
                    "kritiklik_seviyesi": bulgu.get('kritiklik_seviyesi', 'Belirsiz'),
                    "risk_skoru": str(bulgu.get('risk_skoru', '-')),
                    "cloudtrail_izi": bulgu.get('cloudtrail_izi', ''),
                    "sikiastirma_onerisi": bulgu.get('sikiastirma_onerisi', ''),
                    "somuru_komutu": bulgu.get('somuru_komutu', ''),
                    "mavi_takim_onerisi": bulgu.get('mavi_takim_onerisi', '')
                }
            }
            sonuclar.append(sonuc)
        arac = {
            "driver": {
                "name": arac_adi,
                "organization": "Tulpar Framework",
                "semanticVersion": SURUM,
                "rules": [
                    {
                        "id": b.get('zafiyet_adi', 'Bilinmeyen').replace(' ', '_')[:80],
                        "name": b.get('zafiyet_adi', 'Bilinmeyen'),
                        "shortDescription": {
                            "text": b.get('aciklama', '')[:500]
                        },
                        "helpUri": "https://github.com/mecik-arda/Tulpar-Framework"
                    }
                    for b in bulgular
                ]
            }
        }
        sarif_verisi = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": arac,
                    "results": sonuclar
                }
            ]
        }
        with open(cikti_dosyasi, 'w', encoding='utf-8') as dosya:
            json.dump(sarif_verisi, dosya, ensure_ascii=False, indent=2)
        logger.info("SARIF raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("SARIF raporu olusturulamadi: %s", hata)
        return False


def rapor_karsilastir(onceki_dosya, yeni_dosya, karsilastirma_ciktisi):
    try:
        with open(onceki_dosya, 'r', encoding='utf-8') as dosya:
            onceki_veri = json.load(dosya)
        with open(yeni_dosya, 'r', encoding='utf-8') as dosya:
            yeni_veri = json.load(dosya)
    except FileNotFoundError as hata:
        logger.error("Karsilastirma dosyasi bulunamadi: %s", hata)
        return None
    except json.JSONDecodeError as hata:
        logger.error("Karsilastirma dosyasi gecersiz JSON: %s", hata)
        return None
    onceki_adlar = {b.get('zafiyet_adi', '') for b in onceki_veri.get('bulgular', [])}
    yeni_adlar = {b.get('zafiyet_adi', '') for b in yeni_veri.get('bulgular', [])}
    yeni_eklenenler = yeni_adlar - onceki_adlar
    kapananlar = onceki_adlar - yeni_adlar
    devam_edenler = onceki_adlar & yeni_adlar
    onceki_yeni_bulgu_listesi = [b for b in yeni_veri.get('bulgular', []) if b.get('zafiyet_adi', '') in yeni_eklenenler]
    onceki_kapanan_bulgu_listesi = [b for b in onceki_veri.get('bulgular', []) if b.get('zafiyet_adi', '') in kapananlar]
    onceki_devam_bulgu_listesi = [b for b in yeni_veri.get('bulgular', []) if b.get('zafiyet_adi', '') in devam_edenler]
    fark_raporu = {
        "arac_adi": "Tulpar Diff Raporu",
        "rapor_tarihi": datetime.now().isoformat(),
        "onceki_dosya": onceki_dosya,
        "yeni_dosya": yeni_dosya,
        "ozet": {
            "onceki_zafiyet_sayisi": onceki_veri.get('zafiyet_sayisi', 0),
            "yeni_zafiyet_sayisi": yeni_veri.get('zafiyet_sayisi', 0),
            "yeni_eklenen_zafiyet_sayisi": len(yeni_eklenenler),
            "kapanan_zafiyet_sayisi": len(kapananlar),
            "devam_eden_zafiyet_sayisi": len(devam_edenler)
        },
        "yeni_eklenen_zafiyetler": onceki_yeni_bulgu_listesi,
        "kapanan_zafiyetler": onceki_kapanan_bulgu_listesi,
        "devam_eden_zafiyetler": onceki_devam_bulgu_listesi
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(karsilastirma_ciktisi)) or '.', exist_ok=True)
        with open(karsilastirma_ciktisi, 'w', encoding='utf-8') as dosya:
            json.dump(fark_raporu, dosya, ensure_ascii=False, indent=4)
        logger.info("Karsilastirma raporu olusturuldu: %s (Yeni: %d, Kapanan: %d, Devam: %d)",
                    karsilastirma_ciktisi, len(yeni_eklenenler), len(kapananlar), len(devam_edenler))
        return fark_raporu
    except Exception as hata:
        logger.error("Karsilastirma raporu yazilamadi: %s", hata)
        return None
