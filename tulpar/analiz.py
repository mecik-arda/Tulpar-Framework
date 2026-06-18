import logging
from tulpar.tarayici import GekSizmaScanner
from tulpar.sabitler import RISK_SKORU_TABLOSU

logger = logging.getLogger('Tulpar')

class ExploitationMappingEngine:
    def __init__(self, tarayici):
        self.tarayici = tarayici
        self.bulunan_zafiyetler = []
        self.saldiri_yollari = []

    def _risk_skoru_ata(self, zafiyet_adi):
        for anahtar, skor in RISK_SKORU_TABLOSU.items():
            if anahtar in zafiyet_adi or zafiyet_adi.startswith(anahtar[:20]) if len(anahtar) > 20 else anahtar == zafiyet_adi:
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

        kontrol_edilecek_eylemler = [
            'iam:CreateNewPolicyVersion',
            'iam:AttachUserPolicy',
            'iam:PutUserPolicy',
            'iam:PassRole',
            'ec2:RunInstances',
            'lambda:CreateFunction',
            'iam:UpdateAssumeRolePolicy',
            'glue:CreateDevEndpoint',
            'cloudformation:CreateStack',
            'datapipeline:CreatePipeline',
            'sagemaker:CreatePresignedNotebookInstanceUrl',
            'iam:CreateAccessKey',
            'iam:CreateLoginProfile',
            'ec2:ModifyInstanceAttribute',
            'sts:AssumeRole',
            'secretsmanager:GetSecretValue',
            's3:GetObject',
            's3:PutObject'
        ]

        simulasyon_sonucu = self.tarayici.hak_simulasyonu_yap(kontrol_edilecek_eylemler)

        if simulasyon_sonucu == "UNKNOWN_RESTRICTED":
            self._bilinmeyen_durum_ekle()
            return

        self._politika_surumu_manipulasyonu_kontrol_et(simulasyon_sonucu)
        self._dogrudan_hak_enjeksiyonu_kontrol_et(simulasyon_sonucu)
        self._ec2_rol_calma_kontrol_et(simulasyon_sonucu)
        self._lambda_admin_tetikleme_kontrol_et(simulasyon_sonucu)
        self._guven_iliskisi_suistimali_kontrol_et(simulasyon_sonucu)
        self._glue_endpoint_rol_calma_kontrol_et(simulasyon_sonucu)
        self._cloudformation_stack_yukseltme_kontrol_et(simulasyon_sonucu)
        self._datapipeline_manipulasyonu_kontrol_et(simulasyon_sonucu)
        self._sagemaker_konsol_sizma_kontrol_et(simulasyon_sonucu)
        self._erisim_anahtari_uretme_kontrol_et(simulasyon_sonucu)
        self._konsol_parolasi_atama_kontrol_et(simulasyon_sonucu)
        self._ec2_var_olan_rol_atama_kontrol_et(simulasyon_sonucu)
        self._rol_zincirleme_kontrol_et(simulasyon_sonucu)
        self._secrets_manager_veri_sizdirma_kontrol_et(simulasyon_sonucu)
        self._s3_lambda_tetikleme_kontrol_et(simulasyon_sonucu)

    def _bilinmeyen_durum_ekle(self):
        self._bulgu_ekle({
            "zafiyet_adi": "Bilinmeyen Yetki Durumu",
            "kritiklik_seviyesi": "Belirsiz",
            "aciklama": "iam:SimulatePrincipalPolicy API erisimi engellendigi icin haklar simule edilemedi.",
            "cloudtrail_izi": "SimulatePrincipalPolicy",
            "sikiastirma_onerisi": "Rol uzerinde yetki kisitlamalarini manuel kontrol edin."
        })

    def _politika_surumu_manipulasyonu_kontrol_et(self, simulasyon_sonucu):
        if simulasyon_sonucu.get('iam:CreateNewPolicyVersion') == 'allowed':
            self._bulgu_ekle({
                "zafiyet_adi": "Politika Surumu Manipulasyonu",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, mevcut politikalara yeni surumler ekleyerek Administrator yetkilerine ulasabilir.",
                "cloudtrail_izi": "CreateNewPolicyVersion",
                "sikiastirma_onerisi": "iam:CreateNewPolicyVersion yetkisini kaldirin veya sadece belirli politikalara kisitlayin.",
                "somuru_komutu": "aws iam create-policy-version --policy-arn arn:aws:iam::HESAP_ID:policy/HEDEF_POLITIKA --policy-document file://admin_politikasi.json --set-as-default",
                "mavi_takim_onerisi": "CloudTrail'de CreateNewPolicyVersion olaylarini izleyin; beklenmeyen politika surumu guncellemeleri icin anlik alarm kurun. IAM politikalarinda surum kilitlemesi aktif edin."
            })
            self.saldiri_yollari.append(("Baslangic", "CreateNewPolicyVersion", "AdministratorAccess"))

    def _dogrudan_hak_enjeksiyonu_kontrol_et(self, simulasyon_sonucu):
        attach_izni = simulasyon_sonucu.get('iam:AttachUserPolicy') == 'allowed'
        put_izni = simulasyon_sonucu.get('iam:PutUserPolicy') == 'allowed'

        if attach_izni or put_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Dogrudan Hak Enjeksiyonu",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Kullanici, kendi uzerine veya baska kullanicilara yuksek yetkili politikalar ekleyebilir.",
                "cloudtrail_izi": "AttachUserPolicy, PutUserPolicy",
                "sikiastirma_onerisi": "iam:AttachUserPolicy ve iam:PutUserPolicy haklarini iptal edin.",
                "somuru_komutu": "aws iam attach-user-policy --user-name HEDEF_KULLANICI --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
                "mavi_takim_onerisi": "CloudTrail'de AttachUserPolicy ve PutUserPolicy olaylarini gercek zamanli izleyin; beklenmedik politika eklemelerinde otomatik olarak politikayi kaldiran duzeltici aksiyon tanimlayin."
            })
            adim = "AttachUserPolicy" if attach_izni else "PutUserPolicy"
            self.saldiri_yollari.append(("Baslangic", adim, "AdministratorAccess"))

    def _ec2_rol_calma_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        run_instances_izni = simulasyon_sonucu.get('ec2:RunInstances') == 'allowed'

        if pass_role_izni and run_instances_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Metadata IMDSv2 Uzerinden Rol Calma",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili bir rol ile EC2 baslatip metadata servisi uzerinden rol kimlik bilgilerini calabilir.",
                "cloudtrail_izi": "RunInstances, PassRole",
                "sikiastirma_onerisi": "iam:PassRole hakkini belirli rollerle sinirlandirin ve sartli erisim (Condition) ekleyin.",
                "somuru_komutu": "aws ec2 run-instances --image-id ami-KIMLIK --instance-type t2.micro --iam-instance-profile Name=YUKSEK_YETKILI_ROL --user-data '#!/bin/bash\\ncurl http://169.254.169.254/latest/meta-data/iam/security-credentials/'",
                "mavi_takim_onerisi": "EC2 bulutularinda IMDSv2'yi zorunlu kilin (MetadataOptions.HttpTokens=required); PassRole iznini rol-tabanli kaynak etiketleriyle sinirlandirin; CloudTrail RunInstances olaylarini izleyin."
            })
            self.saldiri_yollari.append(("Baslangic", "PassRole_EC2", "AdministratorAccess"))

    def _lambda_admin_tetikleme_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        create_function_izni = simulasyon_sonucu.get('lambda:CreateFunction') == 'allowed'

        if pass_role_izni and create_function_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Lambda Fonksiyonu Ile Admin Tetikleme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yonetici rolune sahip bir Lambda fonksiyonu olusturarak kodu calistirabilir ve yetkisini yukseltebilir.",
                "cloudtrail_izi": "CreateFunction, PassRole",
                "sikiastirma_onerisi": "lambda:CreateFunction hakkini guvenilir kaynaklara kilitleyin, PassRole izinlerini sadece belirli rollere atayin.",
                "somuru_komutu": "aws lambda create-function --function-name kotu_amacli_fonksiyon --runtime python3.9 --role arn:aws:iam::HESAP_ID:role/YONETICI_ROLU --handler index.lambda_handler --zip-file fileb://paket.zip",
                "mavi_takim_onerisi": "CloudTrail'de CreateFunction olaylarini izleyin; beklenmeyen Lambda olusturmalarinda alarm tetikleyin. Lambda kod imzalama (Code Signing) ozelligini aktif edin."
            })
            self.saldiri_yollari.append(("Baslangic", "PassRole_Lambda", "AdministratorAccess"))

    def _guven_iliskisi_suistimali_kontrol_et(self, simulasyon_sonucu):
        if simulasyon_sonucu.get('iam:UpdateAssumeRolePolicy') == 'allowed':
            self._bulgu_ekle({
                "zafiyet_adi": "Guven Iliskisi Suistimali",
                "kritiklik_seviyesi": "Yuksek",
                "aciklama": "Saldirgan, baska bir rolun AssumeRole politikasini degistirerek o rolu ustlenebilir.",
                "cloudtrail_izi": "UpdateAssumeRolePolicy",
                "sikiastirma_onerisi": "iam:UpdateAssumeRolePolicy iznini kullanicilardan kaldirin.",
                "somuru_komutu": "aws iam update-assume-role-policy --role-name HEDEF_ROL --policy-document file://kotu_amaci_guven_politikasi.json",
                "mavi_takim_onerisi": "CloudTrail'de UpdateAssumeRolePolicy olaylarini anlik olarak izleyin; bu yetkiye sahip kullanicilari sifira indirin; rol guven politikalarini duzgun araliklarla denetleyin."
            })
            self.saldiri_yollari.append(("Baslangic", "UpdateAssumeRolePolicy", "YoneticiRolu_Ustlenme"))

    def _glue_endpoint_rol_calma_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        glue_dev_endpoint_izni = simulasyon_sonucu.get('glue:CreateDevEndpoint') == 'allowed'

        if pass_role_izni and glue_dev_endpoint_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "AWS Glue Endpoint Uzerinden Rol Calma",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili bir IAM rolu atanmis Glue gelistirme endpointi olusturarak bu rolun kimlik bilgilerine erisebilir ve yetkisini yukseltebilir.",
                "cloudtrail_izi": "CreateDevEndpoint, PassRole",
                "sikiastirma_onerisi": "glue:CreateDevEndpoint ve iam:PassRole yetkilerini birbirinden ayirin; PassRole icin sartli erisim politikalari tanimlayin; sadece guvenilir rollerin Glue endpointlerine atanmasina izin verin.",
                "somuru_komutu": "aws glue create-dev-endpoint --endpoint-name kotu_amaci_endpoint --role-arn arn:aws:iam::HESAP_ID:role/YONETICI_ROLU --public-keys 'ssh-rsa AAAA...'",
                "mavi_takim_onerisi": "CloudTrail'de CreateDevEndpoint olaylarini anlik alarm ile izleyin; Glue endpoint olusturmayi sadece belirli IAM kullanicilarina kisitlayin; endpoint olusturulduktan sonra otomatik dogrulama ve tarama yapin."
            })
            self.saldiri_yollari.append(("Baslangic", "Glue_Endpoint_RolCalma", "AdministratorAccess"))

    def _cloudformation_stack_yukseltme_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        cf_create_stack_izni = simulasyon_sonucu.get('cloudformation:CreateStack') == 'allowed'

        if pass_role_izni and cf_create_stack_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "CloudFormation Stack Yoluyla Yetki Yukseltme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili bir IAM rolu ile CloudFormation stack'i olusturarak o rolun yetkileriyle kaynak yonetimi yapabilir ve yetkisini yukseltebilir.",
                "cloudtrail_izi": "CreateStack, PassRole",
                "sikiastirma_onerisi": "cloudformation:CreateStack ve iam:PassRole yetkilerini ayirin; CloudFormation servis rolunu sadece guvenilir rollerle sinirlandirin; stack olusturma iznini belirli sablonlarla kisitlayin.",
                "somuru_komutu": "aws cloudformation create-stack --stack-name kotu_amaci_stack --template-url https://s3.amazonaws.com/KOVA/yuksek_yetkili_kaynak_sablonu.json --role-arn arn:aws:iam::HESAP_ID:role/YONETICI_ROLU",
                "mavi_takim_onerisi": "CloudTrail'de CreateStack olaylarini izleyin; beklenmeyen stack olusturmalarinda otomatik roller ve stack silme tetikleyin; CloudFormation sartli erisim ile sadece belirli roller ve kaynak tiplerine izin verin."
            })
            self.saldiri_yollari.append(("Baslangic", "CloudFormation_Stack_Yukseltme", "AdministratorAccess"))

    def _datapipeline_manipulasyonu_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        dp_create_pipeline_izni = simulasyon_sonucu.get('datapipeline:CreatePipeline') == 'allowed'

        if pass_role_izni and dp_create_pipeline_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "DataPipeline Manipulasyonu Ile Yetki Yukseltme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili bir rol ile DataPipeline olusturarak bu rolun yetkileriyle her turlu islem yapabilir ve sistem genelinde yetki yukseltebilir.",
                "cloudtrail_izi": "CreatePipeline, PassRole",
                "sikiastirma_onerisi": "datapipeline:CreatePipeline ve iam:PassRole yetkilerini birbirinden ayirin; DataPipeline kaynak rolunu sadece guvenilir rollerle sinirlandirin; pipeline olusturma iznini IP kosulu veya MFA sarti ile koruyun.",
                "somuru_komutu": "aws datapipeline create-pipeline --name kotu_amaci_pipeline --unique-id kotu_amaci_token --description 'Yetki yukseltme amaciyla olusturuldu'",
                "mavi_takim_onerisi": "CloudTrail'de CreatePipeline ve PutPipelineDefinition olaylarini izleyin; DataPipeline hizmetini kullanmayan hesaplarda servisi tamamen devre disi birakin; pipeline tanimlarini duzgun araliklarla denetleyin."
            })
            self.saldiri_yollari.append(("Baslangic", "DataPipeline_Manipulasyonu", "AdministratorAccess"))

    def _sagemaker_konsol_sizma_kontrol_et(self, simulasyon_sonucu):
        sagemaker_presigned_izni = simulasyon_sonucu.get('sagemaker:CreatePresignedNotebookInstanceUrl') == 'allowed'

        if sagemaker_presigned_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "SageMaker Notebook Uzerinden Yetki Yukseltme",
                "kritiklik_seviyesi": "Yuksek",
                "aciklama": "Saldirgan, baska bir kullanicinin SageMaker notebook'una on-imzali URL olusturarak o kullanicinin yetkileriyle notebook konsoluna erisip komut calistirabilir ve yetki yukseltebilir.",
                "cloudtrail_izi": "CreatePresignedNotebookInstanceUrl",
                "sikiastirma_onerisi": "sagemaker:CreatePresignedNotebookInstanceUrl yetkisini sadece notebook sahibi kullanicilara kisitlayin; notebook IAM rollerini en az yetki prensibiyle yapilandirin; notebook internet erisimini VPC ile sinirlandirin.",
                "somuru_komutu": "aws sagemaker create-presigned-notebook-instance-url --notebook-instance-name HEDEF_NOTEBOOK_KIMLIGI",
                "mavi_takim_onerisi": "CloudTrail'de CreatePresignedNotebookInstanceUrl olaylarini izleyin; notebook'a erisimin kullanicinin IP adresiyle uyumlu olup olmadigini kontrol edin; SageMaker notebooklarina dogrudan internet erisimini kaldirin."
            })
            self.saldiri_yollari.append(("Baslangic", "SageMaker_Konsol_Sizma", "AdministratorAccess"))

    def _erisim_anahtari_uretme_kontrol_et(self, simulasyon_sonucu):
        create_access_key_izni = simulasyon_sonucu.get('iam:CreateAccessKey') == 'allowed'

        if create_access_key_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Baska Kullanici Adina Erisim Anahtari Uretme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili baska bir IAM kullanicisi adina yeni erisim anahtari (Access Key) olusturarak o kullanicinin tum yetkilerini ele gecirebilir.",
                "cloudtrail_izi": "CreateAccessKey",
                "sikiastirma_onerisi": "iam:CreateAccessKey yetkisini tum kullanicilardan kaldirin; sadece hesap yoneticilerinin kendi anahtarlarini yonetmesine izin verin; erisim anahtari olusturmayi MFA ile koruyun.",
                "somuru_komutu": "aws iam create-access-key --user-name HEDEF_YUKSEK_YETKILI_KULLANICI",
                "mavi_takim_onerisi": "CloudTrail'de CreateAccessKey olaylarini en yuksek oncelikle izleyin; baska bir kullanici adina anahtar uretildiginde anlik alarm ve otomatik anahtar deaktivasyonu tetikleyin; kullanicilarin kendi anahtarlarini yonetmesi disinda bu yetkiyi tamamen kaldirin."
            })
            self.saldiri_yollari.append(("Baslangic", "CreateAccessKey_Yukseltme", "AdministratorAccess"))

    def _konsol_parolasi_atama_kontrol_et(self, simulasyon_sonucu):
        create_login_profile_izni = simulasyon_sonucu.get('iam:CreateLoginProfile') == 'allowed'

        if create_login_profile_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Konsol Parolasi Atama Ile Yetki Yukseltme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, yuksek yetkili baska bir IAM kullanicisina AWS Yonetim Konsolu icin yeni bir parola atayarak o kullanicinin tum yetkilerini ele gecirebilir.",
                "cloudtrail_izi": "CreateLoginProfile",
                "sikiastirma_onerisi": "iam:CreateLoginProfile yetkisini tum kullanicilardan kaldirin; sadece hesap yoneticilerinin ve kullanicinin kendisinin parola yonetmesine izin verin.",
                "somuru_komutu": "aws iam create-login-profile --user-name HEDEF_YUKSEK_YETKILI_KULLANICI --password 'KarmasikParola123!' --no-password-reset-required",
                "mavi_takim_onerisi": "CloudTrail'de CreateLoginProfile olaylarini en yuksek oncelikle izleyin; baska bir kullanici adina parola atandiginda anlik alarm ve otomatik parola iptali tetikleyin; IAM kullanicilarinda MFA zorunlulugunu aktif edin."
            })
            self.saldiri_yollari.append(("Baslangic", "CreateLoginProfile_Yukseltme", "AdministratorAccess"))

    def _ec2_var_olan_rol_atama_kontrol_et(self, simulasyon_sonucu):
        pass_role_izni = simulasyon_sonucu.get('iam:PassRole') == 'allowed'
        modify_instance_izni = simulasyon_sonucu.get('ec2:ModifyInstanceAttribute') == 'allowed'

        if pass_role_izni and modify_instance_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Var Olan EC2'ya Rol Atama Yoluyla Yetki Yukseltme",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Saldirgan, hali hazirda calisan bir EC2 bulutusuna yuksek yetkili bir IAM rolu atayarak, bulutunun metadata servisinden bu rolun kimlik bilgilerini calabilir.",
                "cloudtrail_izi": "ModifyInstanceAttribute, PassRole",
                "sikiastirma_onerisi": "ec2:ModifyInstanceAttribute ve iam:PassRole yetkilerini birbirinden ayirin; mevcut EC2 bulutularina sonradan rol atanmasini engelleyin; sadece yeni bulutu olustururken rol atanabilmesine izin verin.",
                "somuru_komutu": "aws ec2 modify-instance-attribute --instance-id i-HEDEF_BULUTU_KIMLIGI --iam-instance-profile Name=YUKSEK_YETKILI_ROL",
                "mavi_takim_onerisi": "CloudTrail'de ModifyInstanceAttribute olaylarini izleyin; IamInstanceProfile degisikliklerinde anlik alarm tetikleyin; EC2 bulutularinda IMDSv2'yi zorunlu kilin; mevcut bulutularin IAM rollerini duzgun araliklarla denetleyin."
            })
            self.saldiri_yollari.append(("Baslangic", "EC2_ModifyInstanceAttribute_RolAtama", "AdministratorAccess"))

    def _rol_zincirleme_kontrol_et(self, simulasyon_sonucu):
        assume_role_izni = simulasyon_sonucu.get('sts:AssumeRole') == 'allowed'

        if assume_role_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Zincirleme Rol Ustlenme Yoluyla Yetki Yukseltme",
                "kritiklik_seviyesi": "Yuksek",
                "aciklama": "Saldirgan, sts:AssumeRole yetkisine sahipse, mevcut rolunden daha yuksek yetkili baska bir rolu ustlenebilir ve zincirleme olarak yetki yukseltebilir. Bu vektor ozellikle cross-account guven iliskilerinde tehlikelidir.",
                "cloudtrail_izi": "AssumeRole",
                "sikiastirma_onerisi": "sts:AssumeRole yetkisini sadece gerekli roller ve guvenilir hesaplarla kisitlayin; rol guven politikalarinda PrincipalArn ve SourceAccount gibi kosullar kullanin; duzgun araliklarla rol guven iliskilerini denetleyin.",
                "somuru_komutu": "aws sts assume-role --role-arn arn:aws:iam::HEDEP_HESAP_ID:role/YONETICI_ROLU --role-session-name kotu_amacli_oturum",
                "mavi_takim_onerisi": "CloudTrail'de AssumeRole olaylarini izleyin; beklenmeyen rol ustlenme kaliplarini tespit etmek icin behavioral analytics kullanin; cross-account rol ustlenmelerinde MFA zorunlulugu getirin; rol oturum adlarini anomali tespiti icin izleyin."
            })
            self.saldiri_yollari.append(("Baslangic", "AssumeRole_Zincirleme", "AdministratorAccess"))

    def _secrets_manager_veri_sizdirma_kontrol_et(self, simulasyon_sonucu):
        get_secret_izni = simulasyon_sonucu.get('secretsmanager:GetSecretValue') == 'allowed'

        if get_secret_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "Secrets Manager Uzerinden Hassas Kimlik Bilgisi Okuma",
                "kritiklik_seviyesi": "Yuksek",
                "aciklama": "Saldirgan, AWS Secrets Manager'da saklanan hassas kimlik bilgilerini (veritabani parolalari, API anahtarlari, baska AWS hesaplarinin credential bilgileri) okuyarak yatay veya dikey yetki yukseltmesi yapabilir.",
                "cloudtrail_izi": "GetSecretValue",
                "sikiastirma_onerisi": "secretsmanager:GetSecretValue yetkisini sadece belirli secret'lara ve sadece ihtiyaci olan rollere kisitlayin; secret erisimini kaynak tabanli politikalarla (resource-based policy) koruyun; secret rotasyonunu otomatiklestirin.",
                "somuru_komutu": "aws secretsmanager get-secret-value --secret-id URETIM_VERITABANI_PAROLASI",
                "mavi_takim_onerisi": "CloudTrail'de GetSecretValue olaylarini izleyin; normal olmayan secret erisimlerinde anlik alarm tetikleyin; Secrets Manager'a erisimi VPC Endpoint ile sinirlandirin; Secret erisim loglarini SIEM sistemine aktarin."
            })
            self.saldiri_yollari.append(("Baslangic", "SecretsManager_VeriSizdirma", "AdministratorAccess"))

    def _s3_lambda_tetikleme_kontrol_et(self, simulasyon_sonucu):
        s3_get_izni = simulasyon_sonucu.get('s3:GetObject') == 'allowed'
        s3_put_izni = simulasyon_sonucu.get('s3:PutObject') == 'allowed'

        if s3_get_izni or s3_put_izni:
            self._bulgu_ekle({
                "zafiyet_adi": "S3 Bucket Uzerinden Kod Calistirma ve Yetki Yukseltme",
                "kritiklik_seviyesi": "Yuksek",
                "aciklama": "Saldirgan, S3 bucket'ina yazma yetkisi varsa, bu bucket uzerinde tetiklenmis bir Lambda fonksiyonuna kotu amacli kod enjekte edebilir. Okuma yetkisi varsa, bucket icindeki hassas yapilandirma dosyalarini veya kimlik bilgilerini ele gecirebilir.",
                "cloudtrail_izi": "GetObject, PutObject",
                "sikiastirma_onerisi": "S3 bucket'larina erisimi en az yetki prensibiyle sinirlandirin; bucket politikalariyla sadece belirli kaynaklardan erisime izin verin; S3 Block Public Access ayarlarini aktif edin; bucket uzerinde tetiklenen Lambda fonksiyonlarinin kodlarini duzgun araliklarla denetleyin.",
                "somuru_komutu": "aws s3 cp kotu_amaci_payload.zip s3://hedef-bucket/lambda-tetikleyici/ && aws s3 ls s3://hedef-bucket/hassas-dosyalar/ --recursive",
                "mavi_takim_onerisi": "CloudTrail'de S3 GetObject ve PutObject olaylarini izleyin; beklenmeyen veri yukleme veya toplu indirme kaliplarinda alarm tetikleyin; S3 bucket'larinda versiyonlama ve MFA Delete ozelliklerini aktif edin; S3 erisim loglarini CloudTrail Data Events ile detayli izleyin."
            })
            adim = "S3_Lambda_Tetikleme"
            self.saldiri_yollari.append(("Baslangic", adim, "AdministratorAccess"))
