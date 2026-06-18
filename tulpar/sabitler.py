SURUM = "2.1.0"

VARSAYILAN_BOLGELER = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1', 'eu-north-1',
    'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2',
    'ap-south-1', 'sa-east-1', 'ca-central-1', 'me-south-1', 'af-south-1'
]

KONTROL_EDILECEK_EYLEMLER = [
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

CDN_BOOTSTRAP_URL = 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css'
CDN_VIS_NETWORK_URL = 'https://cdn.jsdelivr.net/npm/vis-network@10.1.0/standalone/umd/vis-network.min.js'

SRI_BOOTSTRAP_HASH = 'sha384-T3c6CoIi6uLrA9TneNEoa7RxnatzjcDSCmG1MXxSR1GAsXEV/Dwwykc2MPK8M2HN'
SRI_VIS_NETWORK_HASH = 'sha384-Kp7cMaDnHOrgpE8FT6l7tUuGIo7kBcBVcttockpXN/whrsQBcy9ZcpKmr/1a/nMo'

YEREL_BOOTSTRAP_ADI = 'bootstrap.min.css'
YEREL_VIS_NETWORK_ADI = 'vis-network.min.js'

DUGUM_ZAFIYET_ESLEME_TABLOSU = [
    ("CreateNewPolicyVersion", "Politika Surumu Manipulasyonu"),
    ("AttachUserPolicy", "Dogrudan Hak Enjeksiyonu"),
    ("PutUserPolicy", "Dogrudan Hak Enjeksiyonu"),
    ("PassRole_EC2", "Metadata IMDSv2 Uzerinden Rol Calma"),
    ("PassRole_Lambda", "Lambda Fonksiyonu Ile Admin Tetikleme"),
    ("UpdateAssumeRolePolicy", "Guven Iliskisi Suistimali"),
    ("Glue_Endpoint_RolCalma", "AWS Glue Endpoint Uzerinden Rol Calma"),
    ("CloudFormation_Stack_Yukseltme", "CloudFormation Stack Yoluyla Yetki Yukseltme"),
    ("DataPipeline_Manipulasyonu", "DataPipeline Manipulasyonu Ile Yetki Yukseltme"),
    ("SageMaker_Konsol_Sizma", "SageMaker Notebook Uzerinden Yetki Yukseltme"),
    ("CreateAccessKey_Yukseltme", "Baska Kullanici Adina Erisim Anahtari Uretme"),
    ("CreateLoginProfile_Yukseltme", "Konsol Parolasi Atama Ile Yetki Yukseltme"),
    ("EC2_ModifyInstanceAttribute_RolAtama", "Var Olan EC2'ya Rol Atama Yoluyla Yetki Yukseltme"),
    ("AssumeRole_Zincirleme", "Zincirleme Rol Ustlenme Yoluyla Yetki Yukseltme"),
    ("SecretsManager_VeriSizdirma", "Secrets Manager Uzerinden Hassas Kimlik Bilgisi Okuma"),
    ("S3_Lambda_Tetikleme", "S3 Bucket Uzerinden Kod Calistirma ve Yetki Yukseltme"),
]

RISK_SKORU_TABLOSU = {
    "Politika Surumu Manipulasyonu": 9.0,
    "Dogrudan Hak Enjeksiyonu": 9.5,
    "Metadata IMDSv2 Uzerinden Rol Calma": 9.8,
    "Lambda Fonksiyonu Ile Admin Tetikleme": 9.5,
    "Guven Iliskisi Suistimali": 8.0,
    "AWS Glue Endpoint Uzerinden Rol Calma": 9.3,
    "CloudFormation Stack Yoluyla Yetki Yukseltme": 9.6,
    "DataPipeline Manipulasyonu Ile Yetki Yukseltme": 9.4,
    "SageMaker Notebook Uzerinden Yetki Yukseltme": 7.5,
    "Baska Kullanici Adina Erisim Anahtari Uretme": 9.2,
    "Konsol Parolasi Atama Ile Yetki Yukseltme": 9.0,
    "Var Olan EC2'ya Rol Atama Yoluyla Yetki Yukseltme": 9.7,
    "Zincirleme Rol Ustlenme Yoluyla Yetki Yukseltme": 7.5,
    "Secrets Manager Uzerinden Hassas Kimlik Bilgisi Okuma": 7.0,
    "S3 Bucket Uzerinden Kod Calistirma ve Yetki Yukseltme": 6.5,
    "Bilinmeyen Yetki Durumu": 5.0,
}

CIKTI_FORMATLARI = ['json', 'html', 'csv', 'markdown']
