import logging
from tulpar.tarayici import GekSizmaScanner
from tulpar.yardimcilar import vektorleri_yukle, kontrol_edilecek_eylemleri_derle, risk_skoru_tablosu_olustur

logger = logging.getLogger('Tulpar')

class ExploitationMappingEngine:
    def __init__(self, tarayici):
        self.tarayici = tarayici
        self.bulunan_zafiyetler = []
        self.saldiri_yollari = []
        self.vektor_verisi = vektorleri_yukle()
        self.vektorler = self.vektor_verisi.get('vektorler', [])
        self.risk_skoru_tablosu = risk_skoru_tablosu_olustur(self.vektor_verisi)

    def _risk_skoru_ata(self, zafiyet_adi):
        if zafiyet_adi in self.risk_skoru_tablosu:
            return self.risk_skoru_tablosu[zafiyet_adi]
        for anahtar, skor in self.risk_skoru_tablosu.items():
            if anahtar in zafiyet_adi:
                return skor
            if len(anahtar) > 20 and zafiyet_adi.startswith(anahtar[:20]):
                return skor
        if 'Coklu Bolge' in zafiyet_adi:
            return 2.0
        return 5.0

    def _bulgu_ekle(self, bulgu_sozlugu):
        zafiyet_adi = bulgu_sozlugu.get('zafiyet_adi', '')
        if 'risk_skoru' not in bulgu_sozlugu:
            bulgu_sozlugu['risk_skoru'] = self._risk_skoru_ata(zafiyet_adi)
        if self.tarayici.scp_kisitlamasi_var is not None:
            bulgu_sozlugu['scp_kisitlamasi_var'] = self.tarayici.scp_kisitlamasi_var
            if self.tarayici.scp_detaylari:
                bulgu_sozlugu['scp_detaylari'] = self.tarayici.scp_detaylari
        self.bulunan_zafiyetler.append(bulgu_sozlugu)

    def _bilinmeyen_durum_ekle(self):
        self._bulgu_ekle({
            "zafiyet_adi": "Bilinmeyen Yetki Durumu",
            "kritiklik_seviyesi": "Belirsiz",
            "aciklama": "iam:SimulatePrincipalPolicy API erisimi engellendigi icin haklar simule edilemedi.",
            "cloudtrail_izi": "SimulatePrincipalPolicy",
            "sikiastirma_onerisi": "Rol uzerinde yetki kisitlamalarini manuel kontrol edin."
        })

    def _vektor_izin_kontrolu(self, vektor, simulasyon_sonucu):
        izin_gruplari = vektor.get('gerekli_izinler', [])
        if not izin_gruplari:
            return False
        for izin_grubu in izin_gruplari:
            grup_sonucu = True
            for izin in izin_grubu:
                if simulasyon_sonucu.get(izin) != 'allowed':
                    grup_sonucu = False
                    break
            if grup_sonucu:
                return True
        return False

    def _vektor_kontrol_et(self, vektor, simulasyon_sonucu):
        if not self._vektor_izin_kontrolu(vektor, simulasyon_sonucu):
            return
        self._bulgu_ekle({
            "zafiyet_adi": vektor['turkce_baslik'],
            "kritiklik_seviyesi": vektor['risk_seviyesi'],
            "risk_skoru": vektor['risk_skoru'],
            "aciklama": vektor['aciklama'],
            "cloudtrail_izi": vektor['cloudtrail_izi'],
            "sikiastirma_onerisi": vektor['iyilestirme'],
            "somuru_komutu": vektor['somuru_komutu'],
            "mavi_takim_onerisi": vektor['mavi_takim_onerisi']
        })
        dugum = vektor.get('saldiri_grafi_dugumu', '')
        hedef = vektor.get('saldiri_grafi_hedefi', 'AdministratorAccess')
        if dugum:
            self.saldiri_yollari.append(("Baslangic", dugum, hedef))

    def analiz_baslat(self):
        self.tarayici.kimlik_bilgilerini_getir()

        if not self.tarayici.kimlik_bilgileri:
            logger.error("Kimlik bilgileri alinamadigi icin analiz durduruldu")
            return

        logger.info("AWS Organizations ve SCP kontrolu yapiliyor...")
        self.tarayici.scp_kontrolu_yap()

        logger.info("Coklu bolge kaynak taramasi baslatiliyor...")
        self.tarayici.coklu_bolge_kaynak_tarama()
        if self.tarayici.coklu_bolge_bulgu_listesi:
            for bulgu in self.tarayici.coklu_bolge_bulgu_listesi:
                self._bulgu_ekle({
                    "zafiyet_adi": "Coklu Bolge Kaynak Kesfi: {} - {}".format(bulgu['kaynak_turu'], bulgu['bolge']),
                    "kritiklik_seviyesi": "Bilgilendirme",
                    "aciklama": "{} bolgesinde {} adet {} kaynagi bulundu. {}".format(bulgu['bolge'], bulgu['kaynak_sayisi'], bulgu['kaynak_turu'], bulgu['onem']),
                    "cloudtrail_izi": "{}:Describe/List API cagrilari".format(bulgu['kaynak_turu']),
                    "sikiastirma_onerisi": "{} bolgesindeki {} kaynaklarinin guvenlik yapilandirmalarini gozden gecirin.".format(bulgu['bolge'], bulgu['kaynak_turu'])
                })

        kontrol_edilecek_eylemler = kontrol_edilecek_eylemleri_derle(self.vektor_verisi)

        simulasyon_sonucu = self.tarayici.hak_simulasyonu_yap(kontrol_edilecek_eylemler)

        if simulasyon_sonucu == "UNKNOWN_RESTRICTED":
            self._bilinmeyen_durum_ekle()
            return

        for vektor in self.vektorler:
            self._vektor_kontrol_et(vektor, simulasyon_sonucu)
