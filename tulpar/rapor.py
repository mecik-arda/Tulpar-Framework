import json
import os
import logging
from tulpar.sabitler import (
    CDN_BOOTSTRAP_URL,
    CDN_VIS_NETWORK_URL,
    SRI_BOOTSTRAP_HASH,
    SRI_VIS_NETWORK_HASH,
    YEREL_BOOTSTRAP_ADI,
    YEREL_VIS_NETWORK_ADI,
    SURUM,
)
from tulpar.dogrulayici import (
    cevrimdisi_asset_indir,
    dugum_zafiyet_esleme_olustur,
)
from tulpar.raporlayici import (
    csv_raporu_yaz,
    markdown_raporu_yaz,
    sarif_raporu_yaz,
)
import string

logger = logging.getLogger("Tulpar")


class AttackGraphGenerator:
    def __init__(self, saldiri_yollari, bulunan_zafiyetler, cikti_dosyasi, cevrimdisi_mod=False):
        self.saldiri_yollari = saldiri_yollari
        self.bulunan_zafiyetler = bulunan_zafiyetler
        self.cikti_dosyasi = cikti_dosyasi
        self.cevrimdisi_mod = cevrimdisi_mod
        self.cevrimdisi_dosyalar = {}

    def _asset_yollari_belirle(self):
        surum_eki = "?v=" + SURUM
        bootstrap_url = CDN_BOOTSTRAP_URL + surum_eki
        vis_network_url = CDN_VIS_NETWORK_URL + surum_eki
        bootstrap_integrity = SRI_BOOTSTRAP_HASH
        vis_network_integrity = SRI_VIS_NETWORK_HASH

        if self.cevrimdisi_mod:
            cikti_dizini = os.path.dirname(os.path.abspath(self.cikti_dosyasi))
            if not cikti_dizini:
                cikti_dizini = "."
            asset_klasoru = os.path.join(cikti_dizini, "tulpar_assets")
            self.cevrimdisi_dosyalar = cevrimdisi_asset_indir(asset_klasoru, CDN_BOOTSTRAP_URL, CDN_VIS_NETWORK_URL)
            if self.cevrimdisi_dosyalar.get("bootstrap") and self.cevrimdisi_dosyalar.get("vis_network"):
                bootstrap_url = "./tulpar_assets/" + YEREL_BOOTSTRAP_ADI
                vis_network_url = "./tulpar_assets/" + YEREL_VIS_NETWORK_ADI
                bootstrap_integrity = ""
                vis_network_integrity = ""
                logger.info("Cevrimdisi mod aktif: Yerel asset yollari kullaniliyor")
            else:
                logger.warning("Bazi assetler indirilemedi, CDN baglantilarina geri donuluyor")

        return bootstrap_url, vis_network_url, bootstrap_integrity, vis_network_integrity

    def html_olustur(self):
        bootstrap_url, vis_network_url, bootstrap_integ, vis_network_integ = self._asset_yollari_belirle()

        dugumler = []
        kenarlar = []
        eklenen_dugumler = set()
        dugum_id = 1
        dugum_sozlugu = {}

        for kaynak, hedef_ara, son_hedef in self.saldiri_yollari:
            for isim in [kaynak, hedef_ara, son_hedef]:
                if isim not in eklenen_dugumler:
                    dugum_sozlugu[isim] = dugum_id
                    renk = "rgb(52, 152, 219)"
                    if isim == "AdministratorAccess" or isim == "YoneticiRolu_Ustlenme":
                        renk = "rgb(231, 76, 60)"
                    elif isim == "Baslangic":
                        renk = "rgb(46, 204, 113)"
                    dugumler.append({"id": dugum_id, "label": isim, "color": renk})
                    eklenen_dugumler.add(isim)
                    dugum_id += 1

            kenarlar.append({"from": dugum_sozlugu[kaynak], "to": dugum_sozlugu[hedef_ara], "arrows": "to"})
            kenarlar.append({"from": dugum_sozlugu[hedef_ara], "to": dugum_sozlugu[son_hedef], "arrows": "to"})

        zafiyet_sozlugu = {}
        for zafiyet in self.bulunan_zafiyetler:
            zafiyet_adi = zafiyet.get("zafiyet_adi", "")
            zafiyet_sozlugu[zafiyet_adi] = {
                "aciklama": zafiyet.get("aciklama", ""),
                "kritiklik": zafiyet.get("kritiklik_seviyesi", "Belirsiz"),
                "risk_skoru": zafiyet.get("risk_skoru", "-"),
                "cloudtrail_izi": zafiyet.get("cloudtrail_izi", ""),
                "sikiastirma": zafiyet.get("sikiastirma_onerisi", ""),
                "somuru_komutu": zafiyet.get("somuru_komutu", "Bilgi mevcut degil"),
                "mavi_takim": zafiyet.get("mavi_takim_onerisi", "Oneri mevcut degil"),
                "scp_kisitlamasi_var": zafiyet.get("scp_kisitlamasi_var"),
            }

        dugum_zafiyet_esleme = dugum_zafiyet_esleme_olustur()

        zafiyet_json = json.dumps(zafiyet_sozlugu, ensure_ascii=False)
        dugum_zafiyet_json = json.dumps(dugum_zafiyet_esleme, ensure_ascii=False)
        dugumler_json = json.dumps(dugumler, ensure_ascii=False)
        kenarlar_json = json.dumps(kenarlar, ensure_ascii=False)

        bootstrap_integrity_attr = ""
        vis_network_integrity_attr = ""
        if bootstrap_integ:
            bootstrap_integrity_attr = " integrity='{}' crossorigin='anonymous'".format(bootstrap_integ)
        if vis_network_integ:
            vis_network_integrity_attr = " integrity='{}' crossorigin='anonymous'".format(vis_network_integ)

        template_yolu = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "grafik.html")
        try:
            with open(template_yolu, "r", encoding="utf-8") as t_dosya:
                template_metni = t_dosya.read()
            html_template = string.Template(template_metni)
            html_icerigi = html_template.substitute(
                bootstrap_url=bootstrap_url,
                bootstrap_integrity_attr=bootstrap_integrity_attr,
                vis_network_url=vis_network_url,
                vis_network_integrity_attr=vis_network_integrity_attr,
                zafiyet_json=zafiyet_json,
                dugum_zafiyet_json=dugum_zafiyet_json,
                dugumler_json=dugumler_json,
                kenarlar_json=kenarlar_json
            )
        except Exception as e:
            logger.error("HTML sablonu okunamadi veya islenemedi: %s", e)
            return

        os.makedirs(os.path.dirname(os.path.abspath(self.cikti_dosyasi)) or ".", exist_ok=True)
        with open(self.cikti_dosyasi, "w", encoding="utf-8") as dosya:
            dosya.write(html_icerigi)
        logger.info("HTML saldiri grafi olusturuldu: %s", self.cikti_dosyasi)


class ReportWriter:
    def __init__(self, bulgular, cikti_dosyasi):
        self.bulgular = bulgular
        self.cikti_dosyasi = cikti_dosyasi

    def rapor_yaz(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.cikti_dosyasi)) or ".", exist_ok=True)
        from datetime import datetime
        rapor_icerigi = {
            "arac_adi": "Tulpar",
            "rapor_tarihi": datetime.now().isoformat(),
            "zafiyet_sayisi": len(self.bulgular),
            "bulgular": self.bulgular,
        }
        with open(self.cikti_dosyasi, "w", encoding="utf-8") as dosya:
            json.dump(rapor_icerigi, dosya, ensure_ascii=False, indent=4)
        logger.info("JSON rapor olusturuldu: %s", self.cikti_dosyasi)


class CokluFormatRaporlayici:
    def __init__(self, bulgular, scp_durumu=None):
        self.bulgular = bulgular
        self.scp_durumu = scp_durumu

    def formatli_rapor_yaz(self, cikti_dosyasi, format_turu):
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        if format_turu == "csv":
            csv_raporu_yaz(self.bulgular, cikti_dosyasi)
            return True
        elif format_turu == "markdown":
            markdown_raporu_yaz(self.bulgular, cikti_dosyasi, self.scp_durumu)
            return True
        elif format_turu == "sarif":
            sarif_raporu_yaz(self.bulgular, cikti_dosyasi)
            return True
        else:
            logger.error("Desteklenmeyen format: %s", format_turu)
            return False
