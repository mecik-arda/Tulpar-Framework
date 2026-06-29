import argparse
import sys
import os
import json
import logging
from datetime import datetime
from tulpar.yardimcilar import (
    loglama_yapilandir,
    konfigurasyon_yukle,
)
from tulpar.onbellek import (
    onbellege_kaydet,
    onbellekten_yukle,
    onbellek_suresi_gecerli_mi,
)
from tulpar.dogrulayici import (
    vektorleri_yukle,
    risk_skoru_tablosu_olustur,
)
from tulpar.raporlayici import (
    rapor_karsilastir,
    sarif_raporu_yaz,
    duzeltme_scripti_uret,
)
from tulpar.entegrasyon import (
    bloodhound_disa_aktar,
    tui_dashboard_goster,
    ai_yonetici_ozeti_uret,
)
from tulpar.tarayici import GekSizmaScanner
from tulpar.analiz import ExploitationMappingEngine
from tulpar.rapor import ReportWriter, AttackGraphGenerator, CokluFormatRaporlayici
from tulpar.sabitler import SURUM, CIKTI_FORMATLARI

logger = logging.getLogger("Tulpar")


def ana_fonksiyon():
    loglama_yapilandir()

    arguman_isleyici = argparse.ArgumentParser(
        description="Tulpar AWS IAM Yetki Yukseltme ve Ileri Seviye Istismar Araci v{}".format(SURUM)
    )
    arguman_isleyici.add_argument("--erisim-anahtari", required=False, default=None, help="AWS Erisim Anahtari Kimligi")
    arguman_isleyici.add_argument("--gizli-anahtar", required=False, default=None, help="AWS Gizli Erisim Anahtari")
    arguman_isleyici.add_argument(
        "--oturum-belirteci", required=False, default=None, help="AWS Oturum Belirteci Istege Bagli"
    )
    arguman_isleyici.add_argument(
        "--aws-profil", required=False, default=None, help="AWS profil adi (~/.aws/credentials) Istege Bagli"
    )
    arguman_isleyici.add_argument(
        "--json-cikti", required=False, default="raporlar/tulpar_rapor.json", help="JSON rapor dosyasi yolu"
    )
    arguman_isleyici.add_argument(
        "--html-cikti", required=False, default="raporlar/tulpar_grafik.html", help="HTML grafik dosyasi yolu"
    )
    arguman_isleyici.add_argument(
        "--cevrimdisi",
        action="store_true",
        required=False,
        default=False,
        help="HTML raporu icin CDN assetlerini yerel olarak indir",
    )
    arguman_isleyici.add_argument(
        "--onbellek", required=False, default=None, help="Tarama sonuclarini onbellek JSON dosyasina kaydet/oku"
    )
    arguman_isleyici.add_argument(
        "--onbellek-suresi",
        required=False,
        type=int,
        default=24,
        help="Onbellek gecerlilik suresi (saat, varsayilan: 24)",
    )
    arguman_isleyici.add_argument(
        "--format",
        required=False,
        default="json",
        choices=CIKTI_FORMATLARI,
        help="Ek cikti formati: " + ", ".join(CIKTI_FORMATLARI),
    )
    arguman_isleyici.add_argument("--format-cikti", required=False, default=None, help="Formatli cikti dosyasi yolu")
    arguman_isleyici.add_argument(
        "--konfig", required=False, default=None, help="Konfigurasyon dosyasi (JSON veya YAML)"
    )
    arguman_isleyici.add_argument(
        "--hizli",
        action="store_true",
        required=False,
        default=False,
        help="Sadece en kritik 15 vektoru tara (hizli triage)",
    )
    arguman_isleyici.add_argument(
        "--sessiz",
        action="store_true",
        required=False,
        default=False,
        help="Sadece bulunan zafiyetleri JSON olarak stdout'a bas, loglari gosterme",
    )
    arguman_isleyici.add_argument(
        "--sadece-kontrol",
        action="store_true",
        required=False,
        default=False,
        help="AWS baglantisini dogrula ve kimlik bilgisi testi yap, tarama yapma",
    )
    arguman_isleyici.add_argument(
        "--karsilastir", required=False, default=None, help="Onceki JSON raporu ile karsilastirma yap (diff rapor)"
    )
    arguman_isleyici.add_argument(
        "--karsilastirma-cikti",
        required=False,
        default="raporlar/tulpar_karsilastirma.json",
        help="Karsilastirma raporu cikti dosyasi",
    )
    arguman_isleyici.add_argument("--sarif-cikti", required=False, default=None, help="SARIF formatinda cikti dosyasi")
    arguman_isleyici.add_argument(
        "--thread-sayisi",
        required=False,
        type=int,
        default=5,
        help="Paralel bolge taramasi icin thread sayisi (varsayilan: 5)",
    )
    arguman_isleyici.add_argument(
        "--hedef-arn",
        required=False,
        default="*",
        help="PassRole gibi ozel ARN gerektiren aksiyonlar icin hedef kaynak ARN (Varsayilan: *)",
    )
    arguman_isleyici.add_argument(
        "--cloudtrail-analiz",
        action="store_true",
        required=False,
        default=False,
        help="Bulunan zafiyetlerin son 7 gunluk CloudTrail loglarinda istismar izlerini arar",
    )
    arguman_isleyici.add_argument(
        "--cloudtrail-gun",
        required=False,
        type=int,
        default=7,
        help="CloudTrail analizi icin geriye donuk gun sayisi (varsayilan: 7)",
    )
    arguman_isleyici.add_argument(
        "--access-analyzer",
        action="store_true",
        required=False,
        default=False,
        help="IAM Access Analyzer ile cross-account ve public rol bulgularini tarar",
    )
    arguman_isleyici.add_argument(
        "--duzelt",
        action="store_true",
        required=False,
        default=False,
        help="Tespit edilen zafiyetler icin otomatik Terraform ve AWS CLI duzeltme kodlari uret",
    )
    arguman_isleyici.add_argument(
        "--duzeltme-cikti",
        required=False,
        default=None,
        help="Duzeltme script cikti dosyasi (varsayilan: raporlar/tulpar_remediation.md)",
    )
    arguman_isleyici.add_argument(
        "--bloodhound-cikti",
        required=False,
        default=None,
        help="BloodHound/Neo4j uyumlu JSON cikti dosyasi",
    )
    arguman_isleyici.add_argument(
        "--tui",
        action="store_true",
        required=False,
        default=False,
        help="Modern terminaller icin Rich tabanli TUI arayuzu kullan",
    )
    arguman_isleyici.add_argument(
        "--bulut",
        required=False,
        default="aws",
        choices=["aws", "gcp", "azure"],
        help="Tarama yapilacak bulut saglayicisi: aws, gcp, azure (varsayilan: aws)",
    )
    arguman_isleyici.add_argument(
        "--web",
        action="store_true",
        required=False,
        default=False,
        help="Streamlit tabanli web dashboard baslat",
    )
    arguman_isleyici.add_argument(
        "--ai-analiz",
        action="store_true",
        required=False,
        default=False,
        help="AI/LLM destekli yonetici ozeti uret",
    )
    arguman_isleyici.add_argument(
        "--ai-provider",
        required=False,
        default="openai",
        choices=["openai", "claude", "bedrock"],
        help="AI saglayici: openai, claude, bedrock (varsayilan: openai)",
    )
    arguman_isleyici.add_argument(
        "--ai-api-key",
        required=False,
        default=None,
        help="AI API anahtari (ortam degiskeninden de alinabilir)",
    )
    arguman_isleyici.add_argument(
        "--k8s-tarama",
        action="store_true",
        required=False,
        default=False,
        help="Kubernetes (EKS) RBAC yetki yukseltme taramasi yap",
    )
    arguman_isleyici.add_argument(
        "--kubeconfig",
        required=False,
        default=None,
        help="Kubernetes kubeconfig dosya yolu (varsayilan: ~/.kube/config)",
    )
    arguman_isleyici.add_argument(
        "--k8s-cikti",
        required=False,
        default="raporlar/tulpar_k8s_rapor.json",
        help="Kubernetes tarama raporu cikti dosyasi",
    )

    argumanlar = arguman_isleyici.parse_args()

    def guvenli_yol_al(yol):
        if not yol:
            return yol
        gercek_yol = os.path.realpath(yol)
        izin_verilen_dizin = os.path.realpath(os.getcwd())
        if not gercek_yol.startswith(izin_verilen_dizin):
            logger.error("Guvenlik: Cikti dizini calisma dizini sinirinin disinda: %s", yol)
            sys.exit(1)
        return gercek_yol
    
    argumanlar.json_cikti = guvenli_yol_al(argumanlar.json_cikti)
    argumanlar.html_cikti = guvenli_yol_al(argumanlar.html_cikti)
    if argumanlar.onbellek:
        argumanlar.onbellek = guvenli_yol_al(argumanlar.onbellek)
    if argumanlar.format_cikti:
        argumanlar.format_cikti = guvenli_yol_al(argumanlar.format_cikti)
    if argumanlar.karsilastir:
        argumanlar.karsilastir = guvenli_yol_al(argumanlar.karsilastir)
    argumanlar.karsilastirma_cikti = guvenli_yol_al(argumanlar.karsilastirma_cikti)
    if argumanlar.sarif_cikti:
        argumanlar.sarif_cikti = guvenli_yol_al(argumanlar.sarif_cikti)
    if argumanlar.duzeltme_cikti:
        argumanlar.duzeltme_cikti = guvenli_yol_al(argumanlar.duzeltme_cikti)
    if argumanlar.bloodhound_cikti:
        argumanlar.bloodhound_cikti = guvenli_yol_al(argumanlar.bloodhound_cikti)
    argumanlar.k8s_cikti = guvenli_yol_al(argumanlar.k8s_cikti)

    if argumanlar.sessiz:
        logging.getLogger().setLevel(logging.ERROR)

    konfig = {}
    if argumanlar.konfig:
        konfig = konfigurasyon_yukle(argumanlar.konfig)
        if konfig is None:
            logger.error("Konfigurasyon dosyasi yuklenemedi, varsayilan degerlerle devam ediliyor")
            konfig = {}
        for anahtar in [
            "erisim_anahtari",
            "gizli_anahtar",
            "oturum_belirteci",
            "aws_profil",
            "json_cikti",
            "html_cikti",
            "onbellek",
            "format",
            "format_cikti",
            "cevrimdisi",
            "hizli",
            "sessiz",
            "sadece_kontrol",
            "karsilastir",
            "karsilastirma_cikti",
            "sarif_cikti",
            "thread_sayisi",
        ]:
            konfig_anahtari = anahtar.replace("_", "-")
            if konfig_anahtari in konfig and getattr(argumanlar, anahtar) == arguman_isleyici.get_default(anahtar):
                setattr(argumanlar, anahtar, konfig[konfig_anahtari])

    logger.info("Tulpar AWS IAM Yetki Yukseltme Tarayicisi v%s baslatiliyor...", SURUM)

    if argumanlar.tui:
        tui_dashboard_goster(argumanlar)
        return

    if argumanlar.web:
        import subprocess  # nosec B404

        dashboard_path = os.path.join(os.path.dirname(__file__), "web_dashboard.py")
        logger.info("Web dashboard baslatiliyor (Streamlit)...")
        print("🚀 Web arayüzü başlatılıyor...")
        try:
            subprocess.run([sys.executable, "-m", "streamlit", "run", dashboard_path])  # nosec B603
        except KeyboardInterrupt:
            pass
        return

    if argumanlar.k8s_tarama:
        from tulpar.k8s_tarayici import K8sRBACTarayici

        logger.info("Kubernetes RBAC taramasi baslatiliyor...")
        k8s_tarayici = K8sRBACTarayici(kubeconfig=argumanlar.kubeconfig)
        k8s_bulgulari = k8s_tarayici.rbac_tarama_yap()
        if k8s_bulgulari:
            k8s_tarayici.k8s_raporu_yaz(argumanlar.k8s_cikti)
            logger.info("K8s taramasi tamamlandi: %d bulgu -> %s", len(k8s_bulgulari), argumanlar.k8s_cikti)
        sys.exit(0 if k8s_bulgulari else 1)

    if argumanlar.karsilastir:
        if not os.path.exists(argumanlar.karsilastir):
            logger.error("Karsilastirma icin belirtilen onceki rapor bulunamadi: %s", argumanlar.karsilastir)
            sys.exit(1)
        if not os.path.exists(argumanlar.json_cikti):
            logger.error("Karsilastirma icin yeni JSON raporu bulunamadi: %s", argumanlar.json_cikti)
            logger.info(
                "Once onceki rapor belirtildi. Once Tulpar'i calistirip "
                "yeni raporu olusturun, sonra karsilastirma yapin."
            )
            sys.exit(1)
        fark_raporu = rapor_karsilastir(argumanlar.karsilastir, argumanlar.json_cikti, argumanlar.karsilastirma_cikti)
        if fark_raporu:
            ozet = fark_raporu["ozet"]
            print(
                json.dumps(
                    {
                        "onceki_zafiyet_sayisi": ozet["onceki_zafiyet_sayisi"],
                        "yeni_zafiyet_sayisi": ozet["yeni_zafiyet_sayisi"],
                        "yeni_eklenen_zafiyet_sayisi": ozet["yeni_eklenen_zafiyet_sayisi"],
                        "kapanan_zafiyet_sayisi": ozet["kapanan_zafiyet_sayisi"],
                        "devam_eden_zafiyet_sayisi": ozet["devam_eden_zafiyet_sayisi"],
                        "yeni_eklenen_zafiyetler": [
                            b.get("zafiyet_adi") for b in fark_raporu.get("yeni_eklenen_zafiyetler", [])
                        ],
                        "kapanan_zafiyetler": [b.get("zafiyet_adi") for b in fark_raporu.get("kapanan_zafiyetler", [])],
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            if fark_raporu["ozet"]["yeni_eklenen_zafiyet_sayisi"] > 0:
                yeni_kritik = any(
                    b.get("kritiklik_seviyesi") == "Kritik" for b in fark_raporu.get("yeni_eklenen_zafiyetler", [])
                )
                if yeni_kritik:
                    sys.exit(1)
        sys.exit(0)

    bulunan_zafiyetler = []
    saldiri_yollari = []
    scp_durumu = None
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
        if argumanlar.aws_profil or konfig.get("aws-profil"):
            profil = argumanlar.aws_profil or konfig.get("aws-profil")
            logger.info("AWS profili kullaniliyor: %s", profil)
            tarayici = GekSizmaScanner(
                profil_adi=profil, thread_sayisi=argumanlar.thread_sayisi, hedef_arn=argumanlar.hedef_arn
            )
        elif argumanlar.erisim_anahtari and argumanlar.gizli_anahtar:
            logger.info("CLI argumanlarindan saglanan kimlik bilgileri kullaniliyor")
            tarayici = GekSizmaScanner(
                erisim_anahtari=argumanlar.erisim_anahtari,
                gizli_anahtar=argumanlar.gizli_anahtar,
                oturum_belirteci=argumanlar.oturum_belirteci,
                thread_sayisi=argumanlar.thread_sayisi,
                hedef_arn=argumanlar.hedef_arn,
            )
        elif os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
            logger.info("Ortam degiskenlerinden alinan kimlik bilgileri kullaniliyor")
            tarayici = GekSizmaScanner(
                erisim_anahtari=os.environ.get("AWS_ACCESS_KEY_ID"),
                gizli_anahtar=os.environ.get("AWS_SECRET_ACCESS_KEY"),
                oturum_belirteci=os.environ.get("AWS_SESSION_TOKEN"),
                thread_sayisi=argumanlar.thread_sayisi,
                hedef_arn=argumanlar.hedef_arn,
            )
        else:
            logger.info(
                "Varsayilan boto3 kimlik bilgisi zinciri kullaniliyor (~/.aws/credentials, EC2 instance profile, vb.)"
            )
            tarayici = GekSizmaScanner(thread_sayisi=argumanlar.thread_sayisi, hedef_arn=argumanlar.hedef_arn)

        if argumanlar.sadece_kontrol:
            logger.info("Baglanti testi yapiliyor...")
            basarili = tarayici.kimlik_bilgilerini_getir()
            if basarili:
                kimlik = tarayici.kimlik_bilgileri
                sonuc = {
                    "durum": "basarili",
                    "arn": kimlik.get("arn", ""),
                    "hesap_id": kimlik.get("hesap_id", ""),
                    "kullanici_id": kimlik.get("kullanici_id", ""),
                }
                print(json.dumps(sonuc, ensure_ascii=False, indent=2))
                logger.info("Baglanti testi basarili: %s", kimlik.get("arn", ""))
                sys.exit(0)
            else:
                sonuc = {"durum": "basarisiz", "hata": "Kimlik bilgileri dogrulanamadi"}
                print(json.dumps(sonuc, ensure_ascii=False, indent=2))
                logger.error("Baglanti testi basarisiz")
                sys.exit(1)

        analiz_motoru = ExploitationMappingEngine(tarayici)

        if argumanlar.bulut != "aws":
            logger.info("Bulut saglayici: %s. Vektor dosyasi: vektorler_%s.json", argumanlar.bulut, argumanlar.bulut)
            vektor_verisi = vektorleri_yukle(bulut=argumanlar.bulut)
            analiz_motoru.vektor_verisi = vektor_verisi
            analiz_motoru.vektorler = vektor_verisi.get("vektorler", [])
            analiz_motoru.risk_skoru_tablosu = risk_skoru_tablosu_olustur(vektor_verisi)

        if argumanlar.hizli:
            if argumanlar.bulut == "aws":
                vektor_verisi = vektorleri_yukle()
            tum_vektorler = analiz_motoru.vektorler
            kritik_vektorler = sorted(tum_vektorler, key=lambda v: v.get("risk_skoru", 0), reverse=True)[:15]
            analiz_motoru.vektorler = kritik_vektorler
            logger.info("Hizli mod aktif: sadece en kritik %d vektor taranacak", len(kritik_vektorler))

        analiz_motoru.analiz_baslat(
            cloudtrail_analizi=argumanlar.cloudtrail_analiz,
            access_analyzer=argumanlar.access_analyzer,
        )

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
                "coklu_bolge_bulgu_listesi": tarayici.coklu_bolge_bulgu_listesi,
            }
            onbellege_kaydet(argumanlar.onbellek, onbellek_verisi)
    else:
        bulunan_zafiyetler = onbellek_verisi.get("bulunan_zafiyetler", [])
        saldiri_yollari = onbellek_verisi.get("saldiri_yollari", [])
        scp_durumu = onbellek_verisi.get("scp_kisitlamasi_var")
        logger.info("Onbellekten %d zafiyet yuklendi", len(bulunan_zafiyetler))

    if argumanlar.sessiz:
        sessiz_meta = {
            "tarama_tarihi": datetime.now().isoformat(),
            "arac_surumu": SURUM,
            "zafiyet_sayisi": len(bulunan_zafiyetler),
            "scp_kisitlamasi_var": scp_durumu,
            "kritik_zafiyet_sayisi": sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Kritik"),
            "yuksek_zafiyet_sayisi": sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Yuksek"),
            "zafiyetler": [b.get("zafiyet_adi") for b in bulunan_zafiyetler],
        }
        print(json.dumps(sessiz_meta, ensure_ascii=False, indent=2))
    else:
        rapor_yazici = ReportWriter(bulunan_zafiyetler, argumanlar.json_cikti)
        rapor_yazici.rapor_yaz()

        if saldiri_yollari:
            grafik_olusturucu = AttackGraphGenerator(
                saldiri_yollari, bulunan_zafiyetler, argumanlar.html_cikti, cevrimdisi_mod=argumanlar.cevrimdisi
            )
            grafik_olusturucu.html_olustur()
        else:
            logger.warning("Gorsellestirilecek saldiri yolu bulunamadi, HTML raporu atlaniyor")

        if argumanlar.format != "json" and argumanlar.format_cikti:
            coklu_format = CokluFormatRaporlayici(bulunan_zafiyetler, scp_durumu)
            coklu_format.formatli_rapor_yaz(argumanlar.format_cikti, argumanlar.format)
        elif argumanlar.format != "json" and not argumanlar.format_cikti:
            varsayilan_cikti = argumanlar.json_cikti.replace(".json", "." + argumanlar.format)
            if varsayilan_cikti == argumanlar.json_cikti:
                varsayilan_cikti = argumanlar.json_cikti + "." + argumanlar.format
            coklu_format = CokluFormatRaporlayici(bulunan_zafiyetler, scp_durumu)
            coklu_format.formatli_rapor_yaz(varsayilan_cikti, argumanlar.format)

        if argumanlar.format == "sarif" or argumanlar.sarif_cikti:
            sarif_cikti_yolu = argumanlar.sarif_cikti or "raporlar/tulpar_rapor.sarif"
            sarif_raporu_yaz(bulunan_zafiyetler, sarif_cikti_yolu)

        if argumanlar.duzelt:
            duzeltme_cikti_yolu = argumanlar.duzeltme_cikti or "raporlar/tulpar_remediation.md"
            duzeltme_scripti_uret(bulunan_zafiyetler, duzeltme_cikti_yolu)
            logger.info("Duzeltme scripti olusturuldu: %s", duzeltme_cikti_yolu)

        if argumanlar.bloodhound_cikti:
            bh_cikti_yolu = argumanlar.bloodhound_cikti
            bloodhound_disa_aktar(saldiri_yollari, bulunan_zafiyetler, bh_cikti_yolu, tarayici.kimlik_bilgileri)
            logger.info("BloodHound cikti dosyasi olusturuldu: %s", bh_cikti_yolu)

        if argumanlar.ai_analiz:
            logger.info("AI yonetici ozeti uretiliyor (%s)...", argumanlar.ai_provider)
            ai_ozet = ai_yonetici_ozeti_uret(
                bulunan_zafiyetler,
                provider=argumanlar.ai_provider,
                api_key=argumanlar.ai_api_key,
            )
            ai_cikti = argumanlar.json_cikti.replace(".json", "_ai_ozet.json")
            with open(ai_cikti, "w", encoding="utf-8") as af:
                json.dump(ai_ozet, af, ensure_ascii=False, indent=2)
            logger.info("AI yonetici ozeti olusturuldu: %s", ai_cikti)
            print("\n" + "=" * 60)
            print("🤖 AI YÖNETİCİ ÖZETİ ({})".format(argumanlar.ai_provider.upper()))
            print("=" * 60)
            print(ai_ozet.get("ozet", ""))
            print("-" * 60)
            print("Genel Risk Seviyesi:", ai_ozet.get("genel_risk_seviyesi", "Bilinmiyor"))
            print("=" * 60 + "\n")

        logger.info(
            "Tarama tamamlandi. %d zafiyet bulundu. Raporlar olusturuldu: %s, %s",
            len(bulunan_zafiyetler),
            argumanlar.json_cikti,
            argumanlar.html_cikti,
        )

    kritik_var = any(b.get("kritiklik_seviyesi") == "Kritik" for b in bulunan_zafiyetler)
    if kritik_var:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    ana_fonksiyon()
