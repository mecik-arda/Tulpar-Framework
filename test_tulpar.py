import unittest
import os
import sys
import json
import tempfile
import logging
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from botocore.exceptions import ClientError

logging.disable(logging.CRITICAL)


class TestGekSizmaScannerKimlik(unittest.TestCase):
    def setUp(self):
        self.tarayici = None

    @patch('boto3.Session')
    def test_kimlik_bilgilerini_getir_basarili(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test_kullanici',
            'Account': '123456789012',
            'UserId': 'AIDATESTKULLANICIID'
        }
        mock_iam = MagicMock()
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_sts if servis == 'sts' else mock_iam
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam

        sonuc = self.tarayici.kimlik_bilgilerini_getir()
        self.assertTrue(sonuc)
        self.assertEqual(self.tarayici.kimlik_bilgileri['arn'], 'arn:aws:iam::123456789012:user/test_kullanici')
        self.assertEqual(self.tarayici.kimlik_bilgileri['hesap_id'], '123456789012')
        self.assertEqual(self.tarayici.kimlik_bilgileri['kullanici_id'], 'AIDATESTKULLANICIID')

    @patch('boto3.Session')
    def test_kimlik_bilgilerini_getir_hata_durumu(self, mock_session_sinifi):
        mock_sts = MagicMock()
        hata_yaniti = {
            'Error': {'Code': 'InvalidClientTokenId', 'Message': 'The security token included in the request is invalid'}
        }
        mock_sts.get_caller_identity.side_effect = ClientError(hata_yaniti, 'GetCallerIdentity')
        mock_iam = MagicMock()
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_sts if servis == 'sts' else mock_iam
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam

        sonuc = self.tarayici.kimlik_bilgilerini_getir()
        self.assertFalse(sonuc)

    @patch('boto3.Session')
    def test_sadece_kontrol_basarili(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test_kullanici',
            'Account': '123456789012',
            'UserId': 'AIDATESTKULLANICIID'
        }
        mock_iam = MagicMock()
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_sts if servis == 'sts' else mock_iam
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam

        sonuc = self.tarayici.kimlik_bilgilerini_getir()
        self.assertTrue(sonuc)
        self.assertIn('arn', self.tarayici.kimlik_bilgileri)
        self.assertIn('hesap_id', self.tarayici.kimlik_bilgileri)
        self.assertIn('kullanici_id', self.tarayici.kimlik_bilgileri)


class TestGekSizmaScannerHakSimulasyonu(unittest.TestCase):
    def setUp(self):
        self.tarayici = None

    @patch('boto3.Session')
    def test_hak_simulasyonu_izin_verildi(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test_kullanici',
            'Account': '123456789012',
            'UserId': 'AIDATEST'
        }
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            'EvaluationResults': [
                {'EvalActionName': 'iam:CreateNewPolicyVersion', 'EvalDecision': 'allowed'},
                {'EvalActionName': 'iam:PassRole', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ec2:RunInstances', 'EvalDecision': 'allowed'},
            ]
        }
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_sts if servis == 'sts' else mock_iam
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam
        self.tarayici.kimlik_bilgileri = {'arn': 'arn:aws:iam::123456789012:user/test_kullanici'}

        eylemler = ['iam:CreateNewPolicyVersion', 'iam:PassRole', 'ec2:RunInstances']
        sonuc = self.tarayici.hak_simulasyonu_yap(eylemler)
        self.assertIsInstance(sonuc, dict)
        self.assertEqual(sonuc['iam:CreateNewPolicyVersion'], 'allowed')
        self.assertEqual(sonuc['iam:PassRole'], 'implicitDeny')
        self.assertEqual(sonuc['ec2:RunInstances'], 'allowed')

    @patch('boto3.Session')
    def test_hak_simulasyonu_arn_yok(self, mock_session_sinifi):
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.kimlik_bilgileri = {}

        sonuc = self.tarayici.hak_simulasyonu_yap(['iam:PassRole'])
        self.assertEqual(sonuc, 'UNKNOWN_RESTRICTED')

    @patch('boto3.Session')
    def test_hak_simulasyonu_client_error(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_iam = MagicMock()
        hata_yaniti = {
            'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}
        }
        mock_iam.simulate_principal_policy.side_effect = ClientError(hata_yaniti, 'SimulatePrincipalPolicy')
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_sts if servis == 'sts' else mock_iam
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam
        self.tarayici.kimlik_bilgileri = {'arn': 'arn:aws:iam::123456789012:user/test_kullanici'}

        sonuc = self.tarayici.hak_simulasyonu_yap(['iam:PassRole'])
        self.assertEqual(sonuc, 'UNKNOWN_RESTRICTED')


class TestGekSizmaScannerSCPKontrolu(unittest.TestCase):
    def setUp(self):
        self.tarayici = None

    @patch('boto3.Session')
    def test_scp_kontrolu_organizations_yok(self, mock_session_sinifi):
        mock_org = MagicMock()
        mock_org.describe_organization.return_value = {'Organization': {}}
        mock_sts = MagicMock()
        mock_iam = MagicMock()
        mock_oturum = MagicMock()
        def client_secici(servis, **kwargs):
            if servis == 'sts': return mock_sts
            if servis == 'iam': return mock_iam
            if servis == 'organizations': return mock_org
            return MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        self.tarayici.sts_istemicisi = mock_sts
        self.tarayici.iam_istemicisi = mock_iam

        sonuc = self.tarayici.scp_kontrolu_yap()
        self.assertFalse(sonuc)

    @patch('boto3.Session')
    def test_scp_kontrolu_access_denied(self, mock_session_sinifi):
        hata_yaniti = {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}
        mock_org = MagicMock()
        mock_org.describe_organization.side_effect = ClientError(hata_yaniti, 'DescribeOrganization')
        mock_oturum = MagicMock()
        def client_secici(servis, **kwargs):
            if servis == 'organizations': return mock_org
            return MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        sonuc = self.tarayici.scp_kontrolu_yap()
        self.assertIsNone(sonuc)


class TestGekSizmaScannerBolgeListeleme(unittest.TestCase):
    def setUp(self):
        self.tarayici = None

    @patch('boto3.Session')
    def test_bolgeleri_listele_basarili(self, mock_session_sinifi):
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.return_value = {
            'Regions': [
                {'RegionName': 'us-east-1'},
                {'RegionName': 'eu-west-1'},
                {'RegionName': 'ap-southeast-1'}
            ]
        }
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_ec2 if servis == 'ec2' else MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        sonuc = self.tarayici.bolgeleri_listele()
        self.assertEqual(len(sonuc), 3)
        self.assertIn('us-east-1', sonuc)

    @patch('boto3.Session')
    def test_bolgeleri_listele_access_denied(self, mock_session_sinifi):
        hata_yaniti = {'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}}
        mock_ec2 = MagicMock()
        mock_ec2.describe_regions.side_effect = ClientError(hata_yaniti, 'DescribeRegions')
        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = lambda servis, **kwargs: mock_ec2 if servis == 'ec2' else MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        sonuc = self.tarayici.bolgeleri_listele()
        self.assertGreater(len(sonuc), 0)


class TestExploitationMappingEngine(unittest.TestCase):
    def setUp(self):
        self.motor = None

    @patch('boto3.Session')
    def test_zafiyet_tespiti_politika_surumu(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test_kullanici',
            'Account': '123456789012',
            'UserId': 'AIDATEST'
        }
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            'EvaluationResults': [
                {'EvalActionName': 'iam:CreateNewPolicyVersion', 'EvalDecision': 'allowed'},
                {'EvalActionName': 'iam:AttachUserPolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:PutUserPolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:PassRole', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ec2:RunInstances', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'lambda:CreateFunction', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:UpdateAssumeRolePolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'glue:CreateDevEndpoint', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'cloudformation:CreateStack', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'datapipeline:CreatePipeline', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'sagemaker:CreatePresignedNotebookInstanceUrl', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreateAccessKey', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreateLoginProfile', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ec2:ModifyInstanceAttribute', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'sts:AssumeRole', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'secretsmanager:GetSecretValue', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 's3:GetObject', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 's3:PutObject', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:UpdateLoginProfile', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:AddUserToGroup', 'EvalDecision': 'allowed'},
                {'EvalActionName': 'iam:SetDefaultPolicyVersion', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'lambda:UpdateFunctionCode', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'codebuild:CreateProject', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'codebuild:StartBuild', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ssm:SendCommand', 'EvalDecision': 'allowed'},
                {'EvalActionName': 'ssm:StartSession', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:PutRolePolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:AttachRolePolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'lambda:UpdateFunctionConfiguration', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreatePolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ec2:AssociateIamInstanceProfile', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'lambda:AddPermission', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'lambda:CreateEventSourceMapping', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreateRole', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:DeleteRolePolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:UpdateSAMLProvider', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'sts:GetFederationToken', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'dynamodb:PutItem', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'sns:Publish', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'sqs:SendMessage', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'kms:CreateGrant', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 's3:PutBucketNotification', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 's3:PutBucketPolicy', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:UploadSigningCertificate', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:UpdateOpenIDConnectProviderThumbprint', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreateSAMLProvider', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'cloudformation:CreateChangeSet', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'cloudformation:ExecuteChangeSet', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'apigateway:POST', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ecs:RegisterTaskDefinition', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ecs:RunTask', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'eks:CreateCluster', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'mediaconvert:CreateJob', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:CreateInstanceProfile', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'iam:AddRoleToInstanceProfile', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'codestar:CreateProject', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'redshift:CreateCluster', 'EvalDecision': 'implicitDeny'},
                {'EvalActionName': 'ec2:GetPasswordData', 'EvalDecision': 'implicitDeny'},
            ]
        }
        mock_ec2_global = MagicMock()
        mock_ec2_global.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}, {'RegionName': 'eu-west-1'}]
        }
        mock_ec2_bolgesel = MagicMock()
        mock_ec2_bolgesel.describe_instances.return_value = {'Reservations': []}
        mock_lambda_bolgesel = MagicMock()
        mock_lambda_bolgesel.list_functions.return_value = {'Functions': []}

        def client_secici(servis, **kwargs):
            if servis == 'sts':
                return mock_sts
            elif servis == 'iam':
                return mock_iam
            elif servis == 'ec2':
                if kwargs.get('region_name') == 'us-east-1' and 'describe_regions' in str(mock_ec2_global.describe_regions):
                    return mock_ec2_global
                return mock_ec2_bolgesel
            elif servis == 'lambda':
                return mock_lambda_bolgesel
            return MagicMock()

        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        from tulpar.analiz import ExploitationMappingEngine

        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        tarayici.sts_istemicisi = mock_sts
        tarayici.iam_istemicisi = mock_iam
        tarayici.aktif_bolgeler = ['us-east-1', 'eu-west-1']

        self.motor = ExploitationMappingEngine(tarayici)
        self.motor.analiz_baslat()

        self.assertGreater(len(self.motor.bulunan_zafiyetler), 0)
        self.assertGreater(len(self.motor.saldiri_yollari), 0)

        zafiyet_adlari = [z['zafiyet_adi'] for z in self.motor.bulunan_zafiyetler]
        self.assertIn('Politika Surumu Manipulasyonu', zafiyet_adlari)
        self.assertIn('Grup Yonetimi Manipulasyonu', zafiyet_adlari)
        self.assertIn('SSM Komut Enjeksiyonu Ile Rol Calma', zafiyet_adlari)

    @patch('boto3.Session')
    def test_yeni_vektor_risk_skoru_ata(self, mock_session_sinifi):
        from tulpar.analiz import ExploitationMappingEngine
        from tulpar.tarayici import GekSizmaScanner

        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        tarayici.scp_kisitlamasi_var = False
        motor = ExploitationMappingEngine(tarayici)

        motor._bulgu_ekle({"zafiyet_adi": "CodeBuild Projesi Ile Rol Calma", "kritiklik_seviyesi": "Kritik"})
        motor._bulgu_ekle({"zafiyet_adi": "Grup Yonetimi Manipulasyonu", "kritiklik_seviyesi": "Kritik"})
        motor._bulgu_ekle({"zafiyet_adi": "Lambda Konfigurasyon Guncelleme", "kritiklik_seviyesi": "Yuksek"})

        skorlar = {b['zafiyet_adi']: b['risk_skoru'] for b in motor.bulunan_zafiyetler}
        self.assertEqual(skorlar.get('CodeBuild Projesi Ile Rol Calma'), 9.5)
        self.assertEqual(skorlar.get('Grup Yonetimi Manipulasyonu'), 9.2)
        self.assertEqual(skorlar.get('Lambda Konfigurasyon Guncelleme'), 8.5)

    @patch('boto3.Session')
    def test_bilinmeyen_durum_fallback(self, mock_session_sinifi):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            'Arn': 'arn:aws:iam::123456789012:user/test_kullanici',
            'Account': '123456789012',
            'UserId': 'AIDATEST'
        }
        mock_iam = MagicMock()
        hata_yaniti = {
            'Error': {'Code': 'AccessDenied', 'Message': 'Access denied'}
        }
        mock_iam.simulate_principal_policy.side_effect = ClientError(hata_yaniti, 'SimulatePrincipalPolicy')
        mock_ec2_global = MagicMock()
        mock_ec2_global.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }
        mock_ec2_bolgesel = MagicMock()
        mock_ec2_bolgesel.describe_instances.return_value = {'Reservations': []}
        mock_lambda_bolgesel = MagicMock()
        mock_lambda_bolgesel.list_functions.return_value = {'Functions': []}

        def client_secici(servis, **kwargs):
            if servis == 'sts':
                return mock_sts
            elif servis == 'iam':
                return mock_iam
            elif servis == 'ec2':
                if kwargs.get('region_name') == 'us-east-1' and hasattr(mock_ec2_global, 'describe_regions'):
                    return mock_ec2_global
                return mock_ec2_bolgesel
            elif servis == 'lambda':
                return mock_lambda_bolgesel
            return MagicMock()

        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        from tulpar.analiz import ExploitationMappingEngine

        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        tarayici.sts_istemicisi = mock_sts
        tarayici.iam_istemicisi = mock_iam
        tarayici.aktif_bolgeler = ['us-east-1']

        self.motor = ExploitationMappingEngine(tarayici)
        self.motor.analiz_baslat()

        zafiyet_adlari = [z['zafiyet_adi'] for z in self.motor.bulunan_zafiyetler]
        self.assertIn('Bilinmeyen Yetki Durumu', zafiyet_adlari)

    @patch('boto3.Session')
    def test_hizli_mod_vektor_sayisi(self, mock_session_sinifi):
        from tulpar.analiz import ExploitationMappingEngine
        from tulpar.tarayici import GekSizmaScanner
        from tulpar.yardimcilar import vektorleri_yukle, vektor_onbellegi_temizle

        vektor_onbellegi_temizle()
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        motor = ExploitationMappingEngine(tarayici)

        vektor_verisi = vektorleri_yukle()
        tum_vektorler = vektor_verisi.get('vektorler', [])
        kritik_vektorler = sorted(tum_vektorler, key=lambda v: v.get('risk_skoru', 0), reverse=True)[:15]

        self.assertEqual(len(kritik_vektorler), 15)
        self.assertGreater(kritik_vektorler[0]['risk_skoru'], 7.0)


class TestYardimcilarVektorYukleme(unittest.TestCase):
    def setUp(self):
        from tulpar.yardimcilar import vektor_onbellegi_temizle
        vektor_onbellegi_temizle()

    def test_vektorleri_yukle_basarili(self):
        from tulpar.yardimcilar import vektorleri_yukle
        veri = vektorleri_yukle()
        self.assertIn('vektorler', veri)
        self.assertIsInstance(veri['vektorler'], list)
        self.assertGreater(len(veri['vektorler']), 0)

    def test_vektor_dogrula_gecerli(self):
        from tulpar.yardimcilar import vektor_dogrula
        gecerli_vektor = {
            "vektor_adi": "Test",
            "turkce_baslik": "Test Vektoru",
            "gerekli_izinler": [["iam:TestAction"]],
            "risk_seviyesi": "Kritik",
            "risk_skoru": 9.0,
            "aciklama": "Test aciklamasi",
            "iyilestirme": "Test onerisi",
            "cloudtrail_izi": "TestAction",
            "somuru_komutu": "aws test",
            "mavi_takim_onerisi": "Test mavi takim",
            "saldiri_grafi_dugumu": "TestDugum",
            "saldiri_grafi_hedefi": "AdministratorAccess"
        }
        try:
            vektor_dogrula(gecerli_vektor, 1)
        except ValueError:
            self.fail("vektor_dogrula gecerli vektor icin hata firlatti")

    def test_vektor_dogrula_eksik_alan(self):
        from tulpar.yardimcilar import vektor_dogrula
        eksik_vektor = {"vektor_adi": "Test"}
        with self.assertRaises(ValueError):
            vektor_dogrula(eksik_vektor, 1)

    def test_vektor_dogrula_gecersiz_risk_skoru(self):
        from tulpar.yardimcilar import vektor_dogrula
        gecersiz_vektor = {
            "vektor_adi": "Test",
            "turkce_baslik": "Test",
            "gerekli_izinler": [],
            "risk_seviyesi": "Kritik",
            "risk_skoru": "dokuz",
            "aciklama": "Test",
            "iyilestirme": "Test",
            "cloudtrail_izi": "Test",
            "somuru_komutu": "Test",
            "mavi_takim_onerisi": "Test",
            "saldiri_grafi_dugumu": "Test",
            "saldiri_grafi_hedefi": "Test"
        }
        with self.assertRaises(ValueError):
            vektor_dogrula(gecersiz_vektor, 1)

    def test_vektor_dogrula_gecersiz_seviye(self):
        from tulpar.yardimcilar import vektor_dogrula
        gecersiz_vektor = {
            "vektor_adi": "Test",
            "turkce_baslik": "Test",
            "gerekli_izinler": [["test:Test"]],
            "risk_seviyesi": "CokKritik",
            "risk_skoru": 9.0,
            "aciklama": "Test",
            "iyilestirme": "Test",
            "cloudtrail_izi": "Test",
            "somuru_komutu": "Test",
            "mavi_takim_onerisi": "Test",
            "saldiri_grafi_dugumu": "Test",
            "saldiri_grafi_hedefi": "Test"
        }
        with self.assertRaises(ValueError):
            vektor_dogrula(gecersiz_vektor, 1)

    def test_vektor_onbellegi_temizle(self):
        from tulpar.yardimcilar import vektorleri_yukle, vektor_onbellegi_temizle
        vektor_onbellegi_temizle()
        veri1 = vektorleri_yukle()
        self.assertIsNotNone(veri1)
        vektor_onbellegi_temizle()
        veri2 = vektorleri_yukle()
        self.assertIsNotNone(veri2)
        self.assertEqual(len(veri1['vektorler']), len(veri2['vektorler']))

    def test_kontrol_edilecek_eylemleri_derle(self):
        from tulpar.yardimcilar import kontrol_edilecek_eylemleri_derle, vektor_onbellegi_temizle
        vektor_onbellegi_temizle()
        eylemler = kontrol_edilecek_eylemleri_derle()
        self.assertIsInstance(eylemler, list)
        self.assertGreater(len(eylemler), 0)
        self.assertIn('iam:CreateNewPolicyVersion', eylemler)
        self.assertIn('iam:PassRole', eylemler)

    def test_dugum_zafiyet_esleme_olustur(self):
        from tulpar.yardimcilar import dugum_zafiyet_esleme_olustur, vektor_onbellegi_temizle
        vektor_onbellegi_temizle()
        esleme = dugum_zafiyet_esleme_olustur()
        self.assertIsInstance(esleme, dict)
        self.assertGreater(len(esleme), 0)
        for dugum, baslik in esleme.items():
            self.assertIsInstance(dugum, str)
            self.assertIsInstance(baslik, str)


class TestReportWriter(unittest.TestCase):
    def test_gecerli_json_ciktisi(self):
        from tulpar.rapor import ReportWriter

        bulgular = [
            {
                "zafiyet_adi": "Test Zafiyeti",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Test aciklama metni",
                "cloudtrail_izi": "TestAPI",
                "sikiastirma_onerisi": "Test oneri metni"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as gecici_dosya:
            gecici_dosya_yolu = gecici_dosya.name

        try:
            rapor_yazici = ReportWriter(bulgular, gecici_dosya_yolu)
            rapor_yazici.rapor_yaz()

            with open(gecici_dosya_yolu, 'r', encoding='utf-8') as dosya:
                icerik = json.load(dosya)

            self.assertEqual(icerik['arac_adi'], 'Tulpar')
            self.assertEqual(icerik['zafiyet_sayisi'], 1)
            self.assertEqual(len(icerik['bulgular']), 1)
            self.assertEqual(icerik['bulgular'][0]['zafiyet_adi'], 'Test Zafiyeti')
        finally:
            if os.path.exists(gecici_dosya_yolu):
                os.unlink(gecici_dosya_yolu)

    def test_json_rapor_dizini_otomatik_olusturma(self):
        from tulpar.rapor import ReportWriter

        with tempfile.TemporaryDirectory() as gecici_dizin:
            alt_dizin = os.path.join(gecici_dizin, 'alt', 'dizin')
            cikti_yolu = os.path.join(alt_dizin, 'rapor.json')
            bulgular = [{"zafiyet_adi": "Test", "kritiklik_seviyesi": "Orta"}]
            rapor_yazici = ReportWriter(bulgular, cikti_yolu)
            rapor_yazici.rapor_yaz()
            self.assertTrue(os.path.exists(cikti_yolu))


class TestAttackGraphGenerator(unittest.TestCase):
    def test_gecerli_html_ciktisi(self):
        from tulpar.rapor import AttackGraphGenerator

        saldiri_yollari = [
            ("Baslangic", "CreateNewPolicyVersion", "AdministratorAccess"),
        ]
        bulunan_zafiyetler = [
            {
                "zafiyet_adi": "Politika Surumu Manipulasyonu",
                "kritiklik_seviyesi": "Kritik",
                "aciklama": "Test politika manipulasyonu aciklamasi",
                "cloudtrail_izi": "CreateNewPolicyVersion",
                "sikiastirma_onerisi": "Test sikilastirma onerisi",
                "somuru_komutu": "aws iam create-policy-version",
                "mavi_takim_onerisi": "CloudTrail izleme onerisi"
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False, encoding='utf-8') as gecici_dosya:
            gecici_dosya_yolu = gecici_dosya.name

        try:
            grafik_olusturucu = AttackGraphGenerator(saldiri_yollari, bulunan_zafiyetler, gecici_dosya_yolu, cevrimdisi_mod=False)
            grafik_olusturucu.html_olustur()

            with open(gecici_dosya_yolu, 'r', encoding='utf-8') as dosya:
                html_icerigi = dosya.read()

            self.assertIn('<!DOCTYPE html>', html_icerigi)
            self.assertIn('<title>Tulpar Saldiri Yollari Grafi</title>', html_icerigi)
            self.assertIn('vis.Network', html_icerigi)
            self.assertIn('Politika Surumu Manipulasyonu', html_icerigi)
            self.assertIn('saldiri_agi', html_icerigi)
            self.assertIn('detay_icerik', html_icerigi)
            self.assertIn('zafiyet_sozlugu', html_icerigi)
            self.assertIn('CreateNewPolicyVersion', html_icerigi)
        finally:
            if os.path.exists(gecici_dosya_yolu):
                os.unlink(gecici_dosya_yolu)


class TestCokluFormatRaporlayici(unittest.TestCase):
    def test_csv_formatli_rapor(self):
        from tulpar.rapor import CokluFormatRaporlayici
        bulgular = [
            {
                "zafiyet_adi": "Test Zafiyeti",
                "kritiklik_seviyesi": "Kritik",
                "risk_skoru": 9.0,
                "aciklama": "Test aciklamasi",
                "cloudtrail_izi": "TestAction",
                "sikiastirma_onerisi": "Test oneri",
                "somuru_komutu": "test",
                "mavi_takim_onerisi": "test oneri"
            }
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            raporlayici = CokluFormatRaporlayici(bulgular)
            sonuc = raporlayici.formatli_rapor_yaz(yol, 'csv')
            self.assertTrue(sonuc)
            with open(yol, 'r', encoding='utf-8') as dosya:
                icerik = dosya.read()
            self.assertIn('Test Zafiyeti', icerik)
        finally:
            if os.path.exists(yol):
                os.unlink(yol)

    def test_markdown_formatli_rapor(self):
        from tulpar.rapor import CokluFormatRaporlayici
        bulgular = [
            {
                "zafiyet_adi": "Test Zafiyeti",
                "kritiklik_seviyesi": "Kritik",
                "risk_skoru": 9.0,
                "aciklama": "Test aciklamasi",
                "cloudtrail_izi": "TestAction",
                "sikiastirma_onerisi": "Test oneri"
            }
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            raporlayici = CokluFormatRaporlayici(bulgular, scp_durumu=False)
            sonuc = raporlayici.formatli_rapor_yaz(yol, 'markdown')
            self.assertTrue(sonuc)
            with open(yol, 'r', encoding='utf-8') as dosya:
                icerik = dosya.read()
            self.assertIn('Test Zafiyeti', icerik)
            self.assertIn('Tulpar AWS IAM', icerik)
        finally:
            if os.path.exists(yol):
                os.unlink(yol)

    def test_sarif_formatli_rapor(self):
        from tulpar.rapor import CokluFormatRaporlayici
        bulgular = [
            {
                "zafiyet_adi": "Test Zafiyeti",
                "kritiklik_seviyesi": "Kritik",
                "risk_skoru": 9.5,
                "aciklama": "Test aciklamasi",
                "cloudtrail_izi": "TestAction",
                "sikiastirma_onerisi": "Test oneri",
                "somuru_komutu": "test",
                "mavi_takim_onerisi": "test oneri"
            }
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            raporlayici = CokluFormatRaporlayici(bulgular)
            sonuc = raporlayici.formatli_rapor_yaz(yol, 'sarif')
            self.assertTrue(sonuc)
            with open(yol, 'r', encoding='utf-8') as dosya:
                icerik = json.load(dosya)
            self.assertEqual(icerik['version'], '2.1.0')
            self.assertIn('runs', icerik)
            self.assertEqual(len(icerik['runs'][0]['results']), 1)
        finally:
            if os.path.exists(yol):
                os.unlink(yol)

    def test_gecersiz_format(self):
        from tulpar.rapor import CokluFormatRaporlayici
        bulgular = [{"zafiyet_adi": "Test"}]
        raporlayici = CokluFormatRaporlayici(bulgular)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xxx', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            sonuc = raporlayici.formatli_rapor_yaz(yol, 'xml')
            self.assertFalse(sonuc)
        finally:
            if os.path.exists(yol):
                os.unlink(yol)


class TestSarifRaporu(unittest.TestCase):
    def test_sarif_raporu_yaz_basarili(self):
        from tulpar.yardimcilar import sarif_raporu_yaz
        bulgular = [
            {
                "zafiyet_adi": "Test Kritik Zafiyet",
                "kritiklik_seviyesi": "Kritik",
                "risk_skoru": 9.5,
                "aciklama": "Test aciklamasi",
                "cloudtrail_izi": "TestAction",
                "sikiastirma_onerisi": "Test oneri",
                "somuru_komutu": "test komut",
                "mavi_takim_onerisi": "test mavi takim"
            }
        ]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            sonuc = sarif_raporu_yaz(bulgular, yol)
            self.assertTrue(sonuc)
            with open(yol, 'r', encoding='utf-8') as dosya:
                icerik = json.load(dosya)
            self.assertEqual(icerik['version'], '2.1.0')
            sonuclar = icerik['runs'][0]['results']
            self.assertEqual(len(sonuclar), 1)
            self.assertEqual(sonuclar[0]['level'], 'error')
        finally:
            if os.path.exists(yol):
                os.unlink(yol)

    def test_sarif_raporu_orta_risk(self):
        from tulpar.yardimcilar import sarif_raporu_yaz
        bulgular = [{"zafiyet_adi": "Test Orta", "kritiklik_seviyesi": "Orta", "risk_skoru": 5.0, "aciklama": "Test"}]
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sarif', delete=False, encoding='utf-8') as gecici:
            yol = gecici.name
        try:
            sarif_raporu_yaz(bulgular, yol)
            with open(yol, 'r', encoding='utf-8') as dosya:
                icerik = json.load(dosya)
            self.assertEqual(icerik['runs'][0]['results'][0]['level'], 'note')
        finally:
            if os.path.exists(yol):
                os.unlink(yol)


class TestRaporKarsilastir(unittest.TestCase):
    def setUp(self):
        self.onceki_yol = None
        self.yeni_yol = None
        self.karsilastirma_yol = None

    def test_rapor_karsilastir_yeni_eklenen(self):
        from tulpar.yardimcilar import rapor_karsilastir
        onceki = {
            "arac_adi": "Tulpar",
            "zafiyet_sayisi": 1,
            "bulgular": [{"zafiyet_adi": "Eski Zafiyet", "kritiklik_seviyesi": "Kritik", "risk_skoru": 9.0}]
        }
        yeni = {
            "arac_adi": "Tulpar",
            "zafiyet_sayisi": 2,
            "bulgular": [
                {"zafiyet_adi": "Eski Zafiyet", "kritiklik_seviyesi": "Kritik", "risk_skoru": 9.0},
                {"zafiyet_adi": "Yeni Zafiyet", "kritiklik_seviyesi": "Yuksek", "risk_skoru": 8.0}
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g1:
            json.dump(onceki, g1)
            self.onceki_yol = g1.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g2:
            json.dump(yeni, g2)
            self.yeni_yol = g2.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g3:
            self.karsilastirma_yol = g3.name
        try:
            fark = rapor_karsilastir(self.onceki_yol, self.yeni_yol, self.karsilastirma_yol)
            self.assertIsNotNone(fark)
            self.assertEqual(fark['ozet']['yeni_eklenen_zafiyet_sayisi'], 1)
            self.assertEqual(fark['ozet']['kapanan_zafiyet_sayisi'], 0)
            self.assertEqual(fark['ozet']['devam_eden_zafiyet_sayisi'], 1)
        finally:
            for yol in [self.onceki_yol, self.yeni_yol, self.karsilastirma_yol]:
                if yol and os.path.exists(yol):
                    os.unlink(yol)

    def test_rapor_karsilastir_kapanan(self):
        from tulpar.yardimcilar import rapor_karsilastir
        onceki = {
            "arac_adi": "Tulpar",
            "zafiyet_sayisi": 2,
            "bulgular": [
                {"zafiyet_adi": "Kapanan Zafiyet", "kritiklik_seviyesi": "Orta", "risk_skoru": 5.0},
                {"zafiyet_adi": "Devam Eden", "kritiklik_seviyesi": "Yuksek", "risk_skoru": 7.0}
            ]
        }
        yeni = {
            "arac_adi": "Tulpar",
            "zafiyet_sayisi": 1,
            "bulgular": [{"zafiyet_adi": "Devam Eden", "kritiklik_seviyesi": "Yuksek", "risk_skoru": 7.0}]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g1:
            json.dump(onceki, g1)
            self.onceki_yol = g1.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g2:
            json.dump(yeni, g2)
            self.yeni_yol = g2.name
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8') as g3:
            self.karsilastirma_yol = g3.name
        try:
            fark = rapor_karsilastir(self.onceki_yol, self.yeni_yol, self.karsilastirma_yol)
            self.assertIsNotNone(fark)
            self.assertEqual(fark['ozet']['yeni_eklenen_zafiyet_sayisi'], 0)
            self.assertEqual(fark['ozet']['kapanan_zafiyet_sayisi'], 1)
        finally:
            for yol in [self.onceki_yol, self.yeni_yol, self.karsilastirma_yol]:
                if yol and os.path.exists(yol):
                    os.unlink(yol)

    def test_rapor_karsilastir_dosya_yok(self):
        from tulpar.yardimcilar import rapor_karsilastir
        sonuc = rapor_karsilastir('/var/yok/dosya1.json', '/var/yok/dosya2.json', '/var/yok/cikti.json')
        self.assertIsNone(sonuc)


class TestCokluBolgeKaynakTarama(unittest.TestCase):
    @patch('boto3.Session')
    def test_coklu_bolge_tarama_basarili(self, mock_session_sinifi):
        mock_ec2_global = MagicMock()
        mock_ec2_global.describe_regions.return_value = {
            'Regions': [
                {'RegionName': 'us-east-1'},
                {'RegionName': 'us-east-2'},
                {'RegionName': 'eu-west-1'}
            ]
        }
        mock_ec2_bolgesel = MagicMock()
        mock_ec2_bolgesel.describe_instances.return_value = {
            'Reservations': [
                {'Instances': [{'InstanceId': 'i-test123'}, {'InstanceId': 'i-test456'}]}
            ]
        }
        mock_lambda_bolgesel = MagicMock()
        mock_lambda_bolgesel.list_functions.return_value = {
            'Functions': [{'FunctionName': 'test-func-1'}, {'FunctionName': 'test-func-2'}, {'FunctionName': 'test-func-3'}]
        }
        mock_sts = MagicMock()
        mock_iam = MagicMock()

        def client_secici(servis, **kwargs):
            if servis == 'ec2':
                if kwargs.get('region_name') == 'us-east-1' and not hasattr(mock_ec2_global, '_called'):
                    mock_ec2_global._called = True
                    return mock_ec2_global
                return mock_ec2_bolgesel
            elif servis == 'lambda':
                return mock_lambda_bolgesel
            elif servis == 'sts':
                return mock_sts
            elif servis == 'iam':
                return mock_iam
            return MagicMock()

        mock_oturum = MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner

        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        tarayici.sts_istemicisi = mock_sts
        tarayici.iam_istemicisi = mock_iam
        tarayici.aktif_bolgeler = ['us-east-1', 'us-east-2', 'eu-west-1']

        sonuc = tarayici.coklu_bolge_kaynak_tarama()

        self.assertIsInstance(sonuc, list)
        self.assertGreater(len(sonuc), 0)

        kaynak_turleri = [b['kaynak_turu'] for b in sonuc]
        self.assertIn('EC2', kaynak_turleri)
        self.assertIn('Lambda', kaynak_turleri)

    @patch('boto3.Session')
    def test_paralel_bolge_tarama_tum_hatalar(self, mock_session_sinifi):
        hata_yaniti = {'Error': {'Code': 'AccessDenied', 'Message': 'Denied'}}
        mock_ec2_global = MagicMock()
        mock_ec2_global.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}, {'RegionName': 'eu-west-1'}]
        }
        mock_ec2_bolgesel = MagicMock()
        mock_ec2_bolgesel.describe_instances.side_effect = ClientError(hata_yaniti, 'DescribeInstances')
        mock_lambda_bolgesel = MagicMock()
        mock_lambda_bolgesel.list_functions.side_effect = ClientError(hata_yaniti, 'ListFunctions')
        mock_oturum = MagicMock()
        def client_secici(servis, **kwargs):
            if servis == 'ec2':
                if kwargs.get('region_name') == 'us-east-1' and not hasattr(mock_ec2_global, '_c'):
                    mock_ec2_global._c = True
                    return mock_ec2_global
                return mock_ec2_bolgesel
            if servis == 'lambda':
                return mock_lambda_bolgesel
            return MagicMock()
        mock_oturum.client.side_effect = client_secici
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')
        tarayici.aktif_bolgeler = ['us-east-1', 'eu-west-1']
        sonuc = tarayici.coklu_bolge_kaynak_tarama()
        self.assertEqual(len(sonuc), 0)


class TestAwsHataYonetimi(unittest.TestCase):
    def setUp(self):
        logging.disable(logging.NOTSET)
        self.tarayici = None

    @patch('boto3.Session')
    def test_access_denied_hatasi(self, mock_session_sinifi):
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        hata_yaniti = {
            'Error': {'Code': 'AccessDenied', 'Message': 'Access denied for this resource'}
        }
        hata = ClientError(hata_yaniti, 'TestOperation')

        with self.assertLogs('Tulpar', level='WARNING') as log_baglanti:
            self.tarayici._aws_hatasi_yonet(hata, 'Test Islem')
            self.assertTrue(any('Erisim Reddedildi' in kayit for kayit in log_baglanti.output))

    @patch('boto3.Session')
    def test_token_expired_hatasi(self, mock_session_sinifi):
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        hata_yaniti = {
            'Error': {'Code': 'TokenExpired', 'Message': 'The token has expired'}
        }
        hata = ClientError(hata_yaniti, 'TestOperation')

        with self.assertLogs('Tulpar', level='ERROR') as log_baglanti:
            self.tarayici._aws_hatasi_yonet(hata, 'Test Islem')
            self.assertTrue(any('Oturum Belirteci Suresi Doldu' in kayit for kayit in log_baglanti.output))

    @patch('boto3.Session')
    def test_invalid_client_token_id_hatasi(self, mock_session_sinifi):
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        hata_yaniti = {
            'Error': {'Code': 'InvalidClientTokenId', 'Message': 'The security token is invalid'}
        }
        hata = ClientError(hata_yaniti, 'TestOperation')

        with self.assertLogs('Tulpar', level='ERROR') as log_baglanti:
            self.tarayici._aws_hatasi_yonet(hata, 'Test Islem')
            self.assertTrue(any('Gecersiz Erisim Anahtari' in kayit for kayit in log_baglanti.output))

    @patch('boto3.Session')
    def test_bilinmeyen_hata_kodu(self, mock_session_sinifi):
        mock_oturum = MagicMock()
        mock_session_sinifi.return_value = mock_oturum

        from tulpar.tarayici import GekSizmaScanner
        self.tarayici = GekSizmaScanner(erisim_anahtari='AKIATESTTEST', gizli_anahtar='testtesttest')

        hata_yaniti = {
            'Error': {'Code': 'InternalFailure', 'Message': 'An internal error has occurred'}
        }
        hata = ClientError(hata_yaniti, 'TestOperation')

        with self.assertLogs('Tulpar', level='ERROR') as log_baglanti:
            self.tarayici._aws_hatasi_yonet(hata, 'Test Islem')
            self.assertTrue(any('Beklenmeyen Hata' in kayit for kayit in log_baglanti.output))


if __name__ == '__main__':
    unittest.main()
