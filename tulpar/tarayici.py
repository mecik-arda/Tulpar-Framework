import os
import logging
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from tulpar.sabitler import VARSAYILAN_BOLGELER
from tulpar.yardimcilar import aws_hatasi_yonet
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger('Tulpar')

try:
    from tqdm import tqdm
    TQDM_VAR = True
except ImportError:
    TQDM_VAR = False

YENIDEN_DENEME_KONFIG = Config(retries={'max_attempts': 5, 'mode': 'adaptive'})

class GekSizmaScanner:
    def __init__(self, erisim_anahtari=None, gizli_anahtar=None, oturum_belirteci=None, profil_adi=None, thread_sayisi=5):
        self.yeniden_deneme_konfig = YENIDEN_DENEME_KONFIG
        self.thread_sayisi = max(1, min(thread_sayisi, 20))
        if profil_adi:
            self.oturum = boto3.Session(profile_name=profil_adi)
            logger.info("AWS profili kullaniliyor: %s", profil_adi)
        elif erisim_anahtari and gizli_anahtar:
            self.oturum = boto3.Session(
                aws_access_key_id=erisim_anahtari,
                aws_secret_access_key=gizli_anahtar,
                aws_session_token=oturum_belirteci
            )
            logger.info("CLI ile saglanan kimlik bilgileri kullaniliyor")
        elif os.environ.get('AWS_ACCESS_KEY_ID') and os.environ.get('AWS_SECRET_ACCESS_KEY'):
            self.oturum = boto3.Session(
                aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY'),
                aws_session_token=os.environ.get('AWS_SESSION_TOKEN')
            )
            logger.info("Ortam degiskenlerinden alinan kimlik bilgileri kullaniliyor")
        else:
            self.oturum = boto3.Session()
            logger.info("Varsayilan boto3 kimlik bilgisi zinciri kullaniliyor")
        self.sts_istemicisi = self.oturum.client('sts', config=self.yeniden_deneme_konfig)
        self.iam_istemicisi = self.oturum.client('iam', config=self.yeniden_deneme_konfig)
        self.kimlik_bilgileri = {}
        self.hak_simulasyon_sonuclari = {}
        self.aktif_bolgeler = []
        self.coklu_bolge_bulgu_listesi = []
        self.scp_kisitlamasi_var = None
        self.scp_detaylari = []

    def _aws_hatasi_yonet(self, hata, islem_adi):
        aws_hatasi_yonet(hata, islem_adi)

    def scp_kontrolu_yap(self):
        try:
            org_istemicisi = self.oturum.client('organizations', config=self.yeniden_deneme_konfig)
            yanit = org_istemicisi.describe_organization()
            org_id = yanit.get('Organization', {}).get('Id', '')
            if not org_id:
                logger.info("AWS Organizations yapisi bulunamadi, SCP kontrolu atlaniyor")
                self.scp_kisitlamasi_var = False
                return False
            logger.info("AWS Organizations tespit edildi: %s", org_id)
            hesap_id = self.kimlik_bilgileri.get('hesap_id', '')
            if not hesap_id:
                self.scp_kisitlamasi_var = False
                return False
            try:
                politika_yanit = org_istemicisi.list_policies_for_target(
                    TargetId=hesap_id,
                    Filter='SERVICE_CONTROL_POLICY'
                )
                scp_listesi = politika_yanit.get('Policies', [])
                if scp_listesi:
                    self.scp_kisitlamasi_var = True
                    for scp in scp_listesi:
                        self.scp_detaylari.append({
                            "scp_adi": scp.get('PolicyName', 'Bilinmeyen'),
                            "scp_id": scp.get('Id', ''),
                            "scp_tipi": scp.get('Type', 'SERVICE_CONTROL_POLICY')
                        })
                    logger.warning("%d adet SCP (Service Control Policy) tespit edildi. IAM politikalari bu SCP'ler tarafindan kisitlaniyor olabilir!", len(scp_listesi))
                    for detay in self.scp_detaylari:
                        logger.info("SCP: %s (%s)", detay['scp_adi'], detay['scp_id'])
                else:
                    self.scp_kisitlamasi_var = False
                    logger.info("Hesaba atanmis SCP bulunamadi")
            except ClientError as hata:
                hata_kodu = hata.response['Error']['Code']
                if hata_kodu == 'AccessDenied':
                    logger.warning("SCP listeleme yetkisi reddedildi, SCP varligi dogrulanamadi")
                    self.scp_kisitlamasi_var = None
                else:
                    logger.warning("SCP listeleme hatasi: %s", hata_kodu)
                    self.scp_kisitlamasi_var = None
            return self.scp_kisitlamasi_var
        except ClientError as hata:
            hata_kodu = hata.response['Error']['Code']
            if hata_kodu == 'AccessDenied':
                logger.info("Organizations API erisimi reddedildi, SCP kontrolu atlaniyor")
            elif hata_kodu == 'UnrecognizedClientException':
                logger.debug("Organizations API kullanilamiyor, SCP kontrolu atlaniyor")
            else:
                logger.debug("Organizations kontrol hatasi: %s", hata_kodu)
            self.scp_kisitlamasi_var = None
            return None

    def bolgeleri_listele(self):
        try:
            ec2_istemicisi = self.oturum.client('ec2', region_name='us-east-1', config=self.yeniden_deneme_konfig)
            yanit = ec2_istemicisi.describe_regions(AllRegions=False)
            self.aktif_bolgeler = [bolge['RegionName'] for bolge in yanit['Regions']]
            logger.info("%d aktif AWS bolgesi dinamik olarak listelendi", len(self.aktif_bolgeler))
            return self.aktif_bolgeler
        except ClientError as hata:
            hata_kodu = hata.response['Error']['Code']
            if hata_kodu == 'AccessDenied':
                logger.warning("Bolge listeleme yetkisi reddedildi, varsayilan bolgeler kullaniliyor")
            elif hata_kodu == 'TokenExpired':
                logger.error("Bolge listeleme - Oturum belirtecinin suresi dolmus")
            elif hata_kodu == 'InvalidClientTokenId':
                logger.error("Bolge listeleme - Gecersiz erisim anahtari kimligi")
            else:
                logger.error("Bolge listeleme hatasi: %s", hata_kodu)
            self.aktif_bolgeler = list(VARSAYILAN_BOLGELER)
            logger.info("%d varsayilan bolge kullanilacak", len(self.aktif_bolgeler))
            return self.aktif_bolgeler

    def _tek_bolge_tara(self, bolge):
        sonuc = {"bolge": bolge, "ec2_sayisi": 0, "lambda_sayisi": 0, "hatalar": []}
        try:
            ec2_bolgesel = self.oturum.client('ec2', region_name=bolge, config=self.yeniden_deneme_konfig)
            ec2_yanit = ec2_bolgesel.describe_instances(MaxResults=100)
            bolge_sayisi = 0
            for rezervasyon in ec2_yanit.get('Reservations', []):
                bolge_sayisi += len(rezervasyon.get('Instances', []))
            if bolge_sayisi > 0:
                sonuc["ec2_sayisi"] = bolge_sayisi
        except ClientError as hata:
            hata_kodu = hata.response['Error']['Code']
            if hata_kodu == 'AccessDenied':
                logger.debug("Bolge %s: EC2 DescribeInstances erisimi reddedildi", bolge)
            elif hata_kodu not in ('AuthFailure', 'UnauthorizedOperation'):
                logger.debug("Bolge %s: EC2 tarama hatasi - %s", bolge, hata_kodu)
        try:
            lambda_bolgesel = self.oturum.client('lambda', region_name=bolge, config=self.yeniden_deneme_konfig)
            lambda_yanit = lambda_bolgesel.list_functions(MaxItems=100)
            bolge_lambda_sayisi = len(lambda_yanit.get('Functions', []))
            if bolge_lambda_sayisi > 0:
                sonuc["lambda_sayisi"] = bolge_lambda_sayisi
        except ClientError as hata:
            hata_kodu = hata.response['Error']['Code']
            if hata_kodu == 'AccessDenied':
                logger.debug("Bolge %s: Lambda ListFunctions erisimi reddedildi", bolge)
            elif hata_kodu not in ('AuthFailure', 'UnauthorizedOperation'):
                logger.debug("Bolge %s: Lambda tarama hatasi - %s", bolge, hata_kodu)
        return sonuc

    def coklu_bolge_kaynak_tarama(self):
        if not self.aktif_bolgeler:
            self.bolgeleri_listele()
        toplam_ec2_sayisi = 0
        toplam_lambda_sayisi = 0
        ec2_bulunan_bolgeler = []
        lambda_bulunan_bolgeler = []
        toplam_bolge = len(self.aktif_bolgeler)

        logger.info("Paralel coklu bolge taramasi basliyor (%d bolge, %d is parcacigi)...", toplam_bolge, self.thread_sayisi)
        tum_sonuclar = []
        with ThreadPoolExecutor(max_workers=self.thread_sayisi) as yurutucu:
            gelecekler = {yurutucu.submit(self._tek_bolge_tara, bolge): bolge for bolge in self.aktif_bolgeler}
            tamamlanan = 0
            for gelecek in as_completed(gelecekler):
                bolge = gelecekler[gelecek]
                tamamlanan += 1
                try:
                    sonuc = gelecek.result()
                    tum_sonuclar.append(sonuc)
                    if sonuc["ec2_sayisi"] > 0:
                        logger.info("[%d/%d] Bolge %s: %d EC2 bulutusu tespit edildi", tamamlanan, toplam_bolge, bolge, sonuc["ec2_sayisi"])
                    if sonuc["lambda_sayisi"] > 0:
                        logger.info("[%d/%d] Bolge %s: %d Lambda fonksiyonu tespit edildi", tamamlanan, toplam_bolge, bolge, sonuc["lambda_sayisi"])
                except Exception as hata:
                    logger.debug("Bolge %s: Tarama is parcacigi hatasi - %s", bolge, hata)

        for sonuc in tum_sonuclar:
            if sonuc["ec2_sayisi"] > 0:
                ec2_bulunan_bolgeler.append({"bolge": sonuc["bolge"], "ec2_sayisi": sonuc["ec2_sayisi"]})
                toplam_ec2_sayisi += sonuc["ec2_sayisi"]
            if sonuc["lambda_sayisi"] > 0:
                lambda_bulunan_bolgeler.append({"bolge": sonuc["bolge"], "lambda_sayisi": sonuc["lambda_sayisi"]})
                toplam_lambda_sayisi += sonuc["lambda_sayisi"]

        self.coklu_bolge_bulgu_listesi = []
        if ec2_bulunan_bolgeler:
            for kayit in ec2_bulunan_bolgeler:
                self.coklu_bolge_bulgu_listesi.append({
                    "kaynak_turu": "EC2",
                    "bolge": kayit["bolge"],
                    "kaynak_sayisi": kayit["ec2_sayisi"],
                    "onem": "Bu bolgede EC2 bulutulari mevcut, rol calma saldirilari icin hedef olabilir"
                })
        if lambda_bulunan_bolgeler:
            for kayit in lambda_bulunan_bolgeler:
                self.coklu_bolge_bulgu_listesi.append({
                    "kaynak_turu": "Lambda",
                    "bolge": kayit["bolge"],
                    "kaynak_sayisi": kayit["lambda_sayisi"],
                    "onem": "Bu bolgede Lambda fonksiyonlari mevcut, yetki yukseltme icin hedef olabilir"
                })
        logger.info("Paralel coklu bolge taramasi tamamlandi: Toplam %d EC2, %d Lambda bulundu", toplam_ec2_sayisi, toplam_lambda_sayisi)
        return self.coklu_bolge_bulgu_listesi

    def kimlik_bilgilerini_getir(self):
        try:
            yanit = self.sts_istemicisi.get_caller_identity()
            self.kimlik_bilgileri['arn'] = yanit['Arn']
            self.kimlik_bilgileri['hesap_id'] = yanit['Account']
            self.kimlik_bilgileri['kullanici_id'] = yanit['UserId']
            logger.info("Kimlik dogrulandi: %s", self.kimlik_bilgileri['arn'])
            return True
        except ClientError as hata:
            self._aws_hatasi_yonet(hata, "Kimlik Bilgisi Alma")
            return False

    def hak_simulasyonu_yap(self, eylem_listesi, kaynak_arn="*"):
        if not self.kimlik_bilgileri.get('arn'):
            return "UNKNOWN_RESTRICTED"

        prennsip_arn = self.kimlik_bilgileri['arn']
        tum_sonuclar = {}
        sayfa_boyutu = 200
        for i in range(0, len(eylem_listesi), sayfa_boyutu):
            sayfa_eylemleri = eylem_listesi[i:i + sayfa_boyutu]
            try:
                yanit = self.iam_istemicisi.simulate_principal_policy(
                    PolicySourceArn=prennsip_arn,
                    ActionNames=sayfa_eylemleri,
                    ResourceArns=[kaynak_arn]
                )
                for degerlendirme in yanit['EvaluationResults']:
                    tum_sonuclar[degerlendirme['EvalActionName']] = degerlendirme['EvalDecision']
            except ClientError as hata:
                self._aws_hatasi_yonet(hata, "Hak Simulasyonu (sayfa %d-%d)" % (i, min(i + sayfa_boyutu, len(eylem_listesi))))
                return "UNKNOWN_RESTRICTED"
        return tum_sonuclar
