# Tulpar — Multi-Cloud & Kubernetes IAM/RBAC Privilege Escalation Scanner (v3.0.0)

> 🛡️ **AltaySec** bünyesinde geliştirilmiştir.
Tulpar, AWS, GCP, Azure ve Kubernetes ortamlarında yetki yükseltme (privilege escalation) ve güvenlik zafiyet vektörlerini tarayan gelişmiş bir güvenlik aracıdır. Projenizdeki IAM politikalarını ve Kubernetes RBAC tanımlarını analiz ederek olası yetki yükseltme yollarını modeller ve sonuçları JSON, CSV, Markdown, SARIF, BloodHound formatları ile etkileşimli HTML grafiği ve modern Web Dashboard üzerinden sunar.

## Proje Hakkında: Sık Sorulan Sorular

**1. Tool'un Amacı ve Rengi Nedir? (Hangi Problemi Çözüyor, Hangi Dikeyde?)**
Tulpar, Cloud (AWS, GCP, Azure) ve Kubernetes ortamlarında gözden kaçan hatalı yapılandırılmış izinleri ve ayrıcalık yükseltme yollarını otomatik olarak tespit eder. Bu araç tam olarak **Purple Team (Mor Takım)** dikeyinde yer alır. Red Team (Kırmızı Takım) için "Zafiyet nasıl sömürülür?" (Exploit komutları, saldırı yolları) sorusunu cevaplarken, Blue Team (Mavi Takım) için "Nasıl savunulur?" (CloudTrail izleri, Terraform/CLI düzeltme kodları, daraltma önerileri) sorusunu yanıtlar. Her iki tarafın iletişimini ve iyileştirme süreçlerini otomatikleştirir.

**2. Hangi Teknoloji Stack'ini Kullanacaksın?**
Proje performansı ve yaygın ekosistemi sebebiyle **Python 3.11** ile geliştirilmiştir. Temel altyapı ve kütüphaneler şunlardır:
- **Bulut İletişimi:** AWS için `boto3`, Kubernetes için `kubernetes` istemcisi.
- **Arayüz ve Raporlama:** Modern CLI/TUI için `rich`, interaktif Web paneli için `streamlit`, saldırı grafiği görselleştirmesi için `vis.js`.
- **DevSecOps ve Test:** İzolasyon için `Docker` (sıfır zafiyet garantili Alpine Linux tabanı), API simülasyonu için `moto`, birim testleri için `pytest`, statik kod analizi ve güvenlik kontrolü için `flake8` ve `bandit`.

**3. Test Ve Doğrulama Planın Nedir?**
Tulpar, `moto` kütüphanesi kullanılarak mocklanmış sahte (dummy) AWS ortamlarında tamamen izole bir biçimde (sandbox) test edilir. `pytest` ile yazılmış 50'den fazla otomatik test senaryosu; IAM hak simülasyonlarını, hatalı kimlik girişlerini, sayfalama ve limit (throttling) senaryolarını test eder. GitHub Actions üzerinde kurulu 5 aşamalı CI/CD (DevSecOps) hattında; kodlar her commit'te otomatik teste girer, oluşturulan Docker imajları Trivy ile zafiyet taramasından geçirilir ve testleri geçmeyen hiçbir kod `main` dalına dahil edilmez.

**4. Sektördeki Muadillerinden Farkı/Özgünlüğü Ne?**
Sektördeki diğer araçların (örneğin Pacu, PMapper, Cloudsplaining) aksine Tulpar'ın en büyük gücü **Dinamik JSON Kural Veritabanı** mimarisidir. Kaynak koda dokunmadan sadece yeni bir JSON bloğu yazarak araca yepyeni bir zafiyet vektörü öğretilebilir. Ayrıca entegre Web Dashboard'u, AI/LLM destekli yönetici özeti oluşturabilmesi ve bulduğu zafiyetlerin CloudTrail loglarında aktif olarak sömürülüp sömürülmediğini (geriye dönük analiz) kontrol edebilmesi Tulpar'ı rakiplerinden açık ara daha eşsiz ve modern kılar.

## Yeni Özellikler (v3.0.0)

### 🌐 Modern Web Dashboard
- `--web` bayrağı ile Streamlit tabanlı, karanlık temalı interaktif bir web paneli başlatılır.
- Bulgular, risk dağılımı, canlı ilerleme çubuğu, etkileşimli saldırı grafiği ve düzeltme betikleri indirme olanağı sunar.
- **[YENİ]** API Anahtarları (Access/Secret Key) artık doğrudan web arayüzünden şifreli kutucuklar ile güvenli şekilde girilebilir (Kimlik bilgileri diske kaydedilmez, anlık işlenir).

### 🤖 AI/LLM Destekli Yönetici Özeti
- `--ai-analiz` bayrağı ile OpenAI (GPT-4o), Claude (Sonnet) ve AWS Bedrock aracılığıyla CISO/CTO seviyesinde üst düzey yönetici özeti çıkarılır.
- API erişimi olmaması veya bağlantı sorunlarında çalışan yerel (fallback) özetleyici.

### ☸️ Kubernetes RBAC Tarayıcı Entegrasyonu
- `--k8s-tarama` bayrağı ile Kubernetes (EKS vb.) kümelerindeki RBAC (Role-Based Access Control) konfigürasyonunu tarar.
- Riskli ClusterRole, RoleBinding ve yetki yükseltme yollarını raporlar.

### 🐳 Konteyner ve DevSecOps Altyapısı
- Projeyi anında ayağa kaldırmak için `Dockerfile` ve `docker-compose.yml` eklendi.
- `.github/workflows/tulpar_devsecops.yml` ile Bandit, Flake8 ve Pytest içeren tam DevSecOps kontrol hattı entegre edildi.

### 📦 PyPI/Pip Paket Yapısı (`pyproject.toml`)
- Modern setuptools standartlarına uygun olarak `pyproject.toml` tanımlandı. Proje doğrudan bir Python modülü olarak paketlenebilir.

### 🛡️ CloudTrail Analizi (v2.2.0)
- `--cloudtrail-analiz` bayrağı ile tespit edilen zafiyetlerin son 7 günlük CloudTrail loglarında kullanılıp kullanılmadığı kontrol edilir.
- Her zafiyet için `cloudtrail_istismar_durumu` alanı eklenir (olay sayısı, istismar olasılığı, örnek olaylar).
- `--cloudtrail-gun` ile geriye dönük gün sayısı ayarlanabilir.

### 🤖 Düzeltme (Remediation) Çıktıları (v2.2.0)
- `--duzelt` bayrağı ile bulunan zafiyetler için AWS CLI ve Terraform düzeltme kod blokları üretilir.
- `--duzeltme-cikti` ile çıktı dosyası yolu özelleştirilebilir.

### 🕸️ BloodHound / Neo4j Dışa Aktarımı (v2.2.0)
- `--bloodhound-cikti` ile saldırı yolları BloodHound 4.x / Neo4j uyumlu JSON formatında dışa aktarılır.
- Düğümler AZPrincipal, AZHighValue, AZUser tipleriyle etiketlenir.
- Kenarlar AZPrivilegeEscalation ve AZAdminAccess ilişkileriyle işaretlenir.

### 🧠 IAM Access Analyzer Entegrasyonu (v2.2.0)
- `--access-analyzer` bayrağı ile cross-account ve public rol bulguları taranır.
- Access Analyzer bulguları Tulpar raporuna dahil edilir.

### 🖥️ Terminal Arayüzü (TUI) (v2.2.0)
- `--tui` bayrağı ile Rich kütüphanesi tabanlı terminal arayüzü sağlanır.


### 🌩️ Multi-Cloud Desteği (GCP ve Azure) (v2.2.0)
- `--bulut gcp` veya `--bulut azure` ile GCP ve Azure IAM vektörleri taranabilir.
- `vektorler_gcp.json` (8 GCP vektörü) ve `vektorler_azure.json` (8 Azure vektörü).

### 🚀 AWS Lambda Entegrasyonu (v2.2.0)
- `lambda_handler.py` ile Tulpar AWS Lambda fonksiyonu olarak çalışabilir.

## 📸 Ekran Görüntüleri

### İnteraktif HTML Saldırı Grafiği (Vis.js)
![Saldırı Grafiği](ekran_goruntuleri/1.png)

### Modern Web Dashboard (Zafiyetler)
![Web Dashboard Zafiyetler](ekran_goruntuleri/2.png)

### Modern Web Dashboard (Saldırı Yolları)
![Web Dashboard Saldırı Yolları](ekran_goruntuleri/3.png)

### Terminal Arayüzü (TUI)
![TUI Arayüzü](ekran_goruntuleri/cli_arayuz.png)

### Otomatik Düzeltme Çıktısı (Remediation)
![Düzeltme Scripti](ekran_goruntuleri/web_duzeltme_cikti.png)

## Özellikler

### Kimlik ve Yetki Keşfi
- `sts:GetCallerIdentity` ile mevcut kimliğin ARN, Hesap ID ve Kullanıcı ID bilgilerini çeker
- `iam:SimulatePrincipalPolicy` API'si üzerinden **73 IAM eylemi** için yetki simülasyonu yapar
- Eylem sayısı 200'ü aştığında sayfalama (200'erli gruplar) ile API limit aşımı engellenir
- Simülasyon API'sine erişim engellendiğinde fallback mekanizması ile çalışmaya devam eder
- `botocore.config.Config` ile (5 yeniden deneme, exponential backoff) sayesinde throttling koruması

### Dinamik JSON Kural Veritabanı
- Aracın tespit ettiği tüm yetki yükseltme vektörleri, risk skorları, gerekli IAM izinleri ve mavi takım tavsiyeleri statik kod yerine harici bir `vektorler.json` dosyasında saklanır
- Koda müdahale etmeye gerek kalmadan, JSON dosyasına basit bir kural bloğu ekleyerek araca yeni zafiyet vektörleri öğretilebilir
- Her vektör için `gerekli_izinler` alanı iç içe liste yapısıyla tanımlanır: dış liste VEYA (OR), iç liste VE (AND) mantığıyla değerlendirilir
- **JSON Schema doğrulaması**: Yükleme anında 12 zorunlu alan, tip kontrolü ve geçerli risk seviyesi denetimi yapılır
- **JSONDecodeError** halinde hata satırı ve kolonu loglanarak bozuk JSON'un tam konumu gösterilir
- Risk skorları, düğüm-zafiyet eşleme tablosu ve kontrol edilecek IAM eylem listesi çalışma zamanında JSON'dan otomatik türetilir

### 65 Yetki Yükseltme Vektörü Kontrolü

#### IAM Tabanlı Vektörler (1–18)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 1 | Politika Sürümü Manipülasyonu | `iam:CreatePolicyVersion` | Kritik | 9.0 |
| 2 | Doğrudan Hak Enjeksiyonu | `iam:AttachUserPolicy` / `iam:PutUserPolicy` | Kritik | 9.5 |
| 3 | Güven İlişkisi Suistimali | `iam:UpdateAssumeRolePolicy` | Yüksek | 8.0 |
| 4 | Erişim Anahtarı Üretme | `iam:CreateAccessKey` | Kritik | 9.2 |
| 5 | Konsol Parolası Atama | `iam:CreateLoginProfile` | Kritik | 9.0 |
| 6 | Konsol Şifresi Güncelleme | `iam:UpdateLoginProfile` | Yüksek | 8.5 |
| 7 | Grup Yönetimi Manipülasyonu | `iam:AddUserToGroup` | Kritik | 9.2 |
| 8 | Eski Politika Sürümüne Dönüş | `iam:SetDefaultPolicyVersion` | Kritik | 8.8 |
| 9 | Rol Politikası Manipülasyonu | `iam:PutRolePolicy` / `iam:AttachRolePolicy` | Kritik | 9.3 |
| 10 | Yeni Yönetici Politikası Oluşturma | `iam:CreatePolicy` | Kritik | 9.0 |
| 11 | Yeni Rol Oluşturarak Yönetici Yetkisi Kazanma | `iam:CreateRole` + `iam:AttachRolePolicy` | Kritik | 9.8 |
| 12 | Rol Üzerindeki Kısıtlayıcı Politikayı Kaldırma | `iam:DeleteRolePolicy` | Kritik | 9.0 |
| 13 | SAML Kimlik Sağlayıcı Manipülasyonu | `iam:UpdateSAMLProvider` | Kritik | 9.1 |
| 14 | SAML Kimlik Sağlayıcı Oluşturarak Federasyon | `iam:CreateSAMLProvider` | Kritik | 9.2 |
| 15 | OIDC Parmak İzi Güncellemesi | `iam:UpdateOpenIDConnectProviderThumbprint` | Yüksek | 8.5 |
| 16 | İmzalama Sertifikası Yükleyerek API Erişimi | `iam:UploadSigningCertificate` | Yüksek | 8.5 |
| 17 | EC2 Örnek Profili Oluşturarak Rol Atama | `iam:CreateInstanceProfile` + `iam:AddRoleToInstanceProfile` | Kritik | 9.3 |
| 18 | Federasyon Belirteci Ele Geçirme | `sts:GetFederationToken` | Yüksek | 8.5 |

#### EC2 Tabanlı Vektörler (19–23)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 19 | Metadata IMDSv2 Üzerinden Rol Çalma | `iam:PassRole` + `ec2:RunInstances` | Kritik | 9.8 |
| 20 | EC2'ya Sonradan Rol Atama | `iam:PassRole` + `ec2:ModifyInstanceAttribute` | Kritik | 9.7 |
| 21 | EC2 Örnek Profili İlişkilendirme | `iam:PassRole` + `ec2:AssociateIamInstanceProfile` | Kritik | 9.5 |
| 22 | EC2 Yönetici Parolasını Ele Geçirme | `ec2:GetPasswordData` | Yüksek | 7.0 |
| 23 | Zincirleme Rol Üstlenme | `sts:AssumeRole` | Yüksek | 7.5 |

#### Lambda ve Sunucusuz Vektörler (24–31)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 24 | Lambda Fonksiyonu ile Admin Tetikleme | `iam:PassRole` + `lambda:CreateFunction` | Kritik | 9.5 |
| 25 | Mevcut Lambda Koduna Enjeksiyon | `lambda:UpdateFunctionCode` | Yüksek | 8.0 |
| 26 | Lambda Konfigürasyon Güncelleme | `lambda:UpdateFunctionConfiguration` | Yüksek | 8.5 |
| 27 | Lambda İzni Ekleme | `lambda:AddPermission` | Yüksek | 8.5 |
| 28 | Lambda Olay Kaynağı Eşleştirme | `lambda:CreateEventSourceMapping` | Yüksek | 8.0 |
| 29 | DynamoDB Akışı Üzerinden Lambda Tetikleme | `dynamodb:PutItem` | Yüksek | 7.5 |
| 30 | SNS Konusu Üzerinden Kod Çalıştırma | `sns:Publish` | Yüksek | 7.0 |
| 31 | SQS Kuyruğu Üzerinden Lambda Tetikleme | `sqs:SendMessage` | Yüksek | 7.0 |

#### Servis Spesifik PassRole Vektörleri (32–43)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 32 | Glue Endpoint Üzerinden Rol Çalma | `iam:PassRole` + `glue:CreateDevEndpoint` | Kritik | 9.3 |
| 33 | CloudFormation Stack ile Yetki Yükseltme | `iam:PassRole` + `cloudformation:CreateStack` | Kritik | 9.6 |
| 34 | CloudFormation Değişiklik Kümesi Yürütme | `cloudformation:CreateChangeSet` + `ExecuteChangeSet` | Yüksek | 8.5 |
| 35 | DataPipeline Manipülasyonu | `iam:PassRole` + `datapipeline:CreatePipeline` | Kritik | 9.4 |
| 36 | CodeBuild Projesi ile Rol Çalma | `iam:PassRole` + `codebuild:CreateProject` / `StartBuild` | Kritik | 9.5 |
| 37 | ECS Görev Tanımı Üzerinden Rol Çalma | `iam:PassRole` + `ecs:RegisterTaskDefinition` | Kritik | 9.0 |
| 38 | ECS Görev Çalıştırma Üzerinden Rol Çalma | `iam:PassRole` + `ecs:RunTask` | Kritik | 9.1 |
| 39 | EKS Kümesi Üzerinden Rol Çalma | `iam:PassRole` + `eks:CreateCluster` | Kritik | 9.0 |
| 40 | API Gateway Üzerinden Rol Çalma | `iam:PassRole` + `apigateway:POST` | Yüksek | 8.0 |
| 41 | MediaConvert İşi Üzerinden Rol Çalma | `iam:PassRole` + `mediaconvert:CreateJob` | Yüksek | 8.0 |
| 42 | CodeStar Projesi Üzerinden Rol Çalma | `iam:PassRole` + `codestar:CreateProject` | Yüksek | 8.5 |
| 43 | Redshift Kümesi Üzerinden Rol Çalma | `iam:PassRole` + `redshift:CreateCluster` | Yüksek | 8.5 |

#### Veri Erişimi ve Diğer Vektörler (44–50)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 44 | SageMaker Notebook Konsoluna Sızma | `sagemaker:CreatePresignedNotebookInstanceUrl` | Yüksek | 7.5 |
| 45 | Secrets Manager'dan Veri Okuma | `secretsmanager:GetSecretValue` | Yüksek | 7.0 |
| 46 | S3 Üzerinden Kod Çalıştırma | `s3:GetObject` / `s3:PutObject` | Yüksek | 6.5 |
| 47 | S3 Kova Olay Bildirimi Yapılandırması | `s3:PutBucketNotification` | Yüksek | 7.5 |
| 48 | S3 Kova Politikası Manipülasyonu | `s3:PutBucketPolicy` | Yüksek | 8.0 |
| 49 | SSM Komut Enjeksiyonu | `ssm:SendCommand` / `ssm:StartSession` | Yüksek | 8.5 |
| 50 | KMS Yetki Devri Oluşturma | `kms:CreateGrant` | Yüksek | 8.0 |

#### Keşif ve Bilgi Toplama Vektörleri (51–65)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 51 | Aşırı Geniş Kullanıcı Listeleme Yetkisi | `iam:ListUsers` | Orta | 4.0 |
| 52 | S3 Kova Listeleme Yetkisi ile Veri Keşfi | `s3:ListBucket` | Orta | 4.0 |
| 53 | RDS Veritabanı Listeleme Yetkisi | `rds:DescribeDBInstances` | Orta | 4.5 |
| 54 | EC2 Bulutu Listeleme Yetkisi | `ec2:DescribeInstances` | Düşük | 3.0 |
| 55 | CloudTrail İzlerini Listeleme Yetkisi | `cloudtrail:DescribeTrails` | Düşük | 3.0 |
| 56 | Güvenlik Grubu Listeleme Yetkisi | `ec2:DescribeSecurityGroups` | Orta | 4.5 |
| 57 | Erişim Anahtarı Listeleme Yetkisi | `iam:ListAccessKeys` | Orta | 4.5 |
| 58 | Parola Politikası Görüntüleme Yetkisi | `iam:GetAccountPasswordPolicy` | Düşük | 2.5 |
| 59 | Lambda Fonksiyon Listeleme Yetkisi | `lambda:ListFunctions` | Düşük | 2.5 |
| 60 | KMS Anahtar Listeleme Yetkisi | `kms:ListKeys` | Orta | 3.5 |
| 61 | SNS Konu Listeleme Yetkisi | `sns:ListTopics` | Düşük | 3.0 |
| 62 | CloudWatch Alarm Listeleme Yetkisi | `cloudwatch:DescribeAlarms` | Düşük | 2.5 |
| 63 | Rol Detayı Görüntüleme Yetkisi | `iam:GetRole` | Orta | 4.0 |
| 64 | SQS Kuyruk Listeleme Yetkisi | `sqs:ListQueues` | Düşük | 3.0 |
| 65 | AWS Config Kaydedici Listeleme Yetkisi | `config:DescribeConfigurationRecorders` | Düşük | 2.0 |

> **Risk Dağılımı:** 24 Kritik, 26 Yüksek, 7 Orta, 8 Düşük. Her vektör; açıklama, sömürü komutu, CloudTrail izi, sıkılaştırma önerisi ve mavi takım savunma önerisi ile birlikte `vektorler.json` içinde tanımlanmıştır.

### CVSS Benzeri Risk Skorlaması
- Her zafiyet için **0-10 arası sayısal risk skoru** otomatik hesaplanır
- HTML dashboard'da renkli risk çubuğu ile görselleştirilir (Kırmızı ≥9.0, Turuncu ≥7.0, Sarı ≥5.0, Yeşil <5.0)
- Risk skoru JSON, CSV, SARIF ve Markdown çıktılarına dahil edilir

### AWS Organizations ve SCP Kontrolü
- `organizations:DescribeOrganization` ile Organizations yapısını tespit eder
- `organizations:ListPoliciesForTarget` ile hesaba atanmış SCP'leri (Service Control Policy) listeler
- SCP varlığı tüm rapor formatlarında `scp_kisitlamasi_var` alanı ile belirtilir
- SCP varsa kullanıcıya IAM politikalarının SCP tarafından kısıtlanabileceği uyarısı verilir

### Çoklu Bölge (Multi-Region) Paralel Tarama
- `ec2:DescribeRegions` ile tüm aktif AWS bölgelerini dinamik olarak listeler
- `ThreadPoolExecutor` ile bölgeler **paralel taranır** (varsayılan 5 iş parçacığı, `--thread-sayisi` ile ayarlanabilir)
- API erişimi kısıtlıysa 17 varsayılan bölge üzerinden taramaya devam eder
- Her bölgede EC2 ve Lambda kaynaklarını tarayarak envanter çıkarır

### Tarama Önbelleği (Caching)
- `--onbellek` parametresi ile tarama sonuçlarını JSON dosyasına kaydeder
- `--onbellek-suresi` ile önbellek geçerlilik süresi ayarlanabilir (varsayılan: 24 saat)
- Geçerli önbellek varsa AWS API çağrıları atlanır, sonuçlar doğrudan yüklenir
- API limit koruması ve büyük hesaplarda hız avantajı sağlar

### Çoklu Çıktı Formatı
- `--format csv` ile CSV raporu (Jira/Excel entegrasyonu)
- `--format markdown` ile Markdown raporu (Confluence/Belgelendirme)
- `--format sarif` veya `--sarif-cikti` ile SARIF raporu (GitHub Security sekmesi entegrasyonu)
- JSON ve HTML formatlarına ek olarak desteklenir

### Tarama Profilleri
- **`--hizli`** — En kritik 15 vektörü tarar (hızlı triage modu)
- **`--sessiz`** — Sadece meta-bilgili JSON'u stdout'a basar, loglama kapalı (CI/CD entegrasyonu)
- **`--sadece-kontrol`** — AWS bağlantısını ve kimlik bilgisini doğrular, tarama yapmaz

### Diff Rapor (Karşılaştırma)
- **`--karsilastir onceki_rapor.json`** — İki tarama arasındaki farkı analiz eder
- Yeni eklenen, kapanan ve devam eden zafiyetleri ayrı ayrı listeler
- Yeni kritik zafiyet varsa `exit code 1` döndürür

### Konfigürasyon Dosyası Desteği
- `--konfig ayarlar.json` ile JSON/YAML konfigürasyon dosyasından varsayılan değerler okunur
- Tüm CLI parametreleri konfigürasyon dosyasından override edilebilir
- CI/CD pipeline'larına ve otomasyon sistemlerine kolay entegrasyon

### Çevrimdışı (Air-Gapped) Raporlama
- `--cevrimdisi` ile CDN asset'leri yerel `tulpar_assets/` klasörüne indirilir
- İndirme sonrası **SRI hash doğrulaması** yapılır; bozuk/manipüle dosyalar tespit edilip silinir
- HTML raporu internet bağlantısı olmadan çalışır
- İndirme başarısız olursa CDN bağlantılarına otomatik geri dönüş (fallback)

### Güvenlik Önlemleri
- **XSS Koruması:** HTML raporundaki tüm kullanıcı kaynaklı veriler `htmlKacis()` ile escape edilir
- **SRI Koruması:** Tüm CDN kaynakları `sha384` hash doğrulaması ile MITM saldırılarına karşı korunur
- **CDN Sürüm Damgası:** Asset URL'lerine `?v=SURUM` parametresi eklenerek tarayıcı önbellek tutarsızlıkları önlenir
- **Ölü Kod Tasfiyesi:** `aws_hatasi_yonet()` tek mantık-tek yer (DRY) prensibiyle `yardimcilar.py`'de toplanmıştır

### Gelişmiş Hata Yönetimi
- 8 farklı AWS hata kodu için spesifik Türkçe geri bildirim
- `AccessDenied`, `TokenExpired`, `InvalidClientTokenId`, `UnauthorizedOperation`, `Throttling`, `ExpiredToken`, `SignatureDoesNotMatch`, `RequestExpired`
- `aws_hatasi_yonet()` fonksiyonu hem `tarayici.py`'den delege edilerek hem de standalone olarak kullanılabilir

### Profesyonel Loglama
- Python `logging` modülü ile yapılandırılmış log çıktıları
- `hasHandlers()` kontrolü ile test ortamında mükerrer handler oluşumu engellenir
- Zaman damgalı, seviye etiketli: `2026-06-18 14:30:00 - INFO - mesaj`

### İnteraktif HTML Saldırı Grafiği
- **Sol Panel (%65):** vis.js 10.1.0 ağ grafiği ile saldırı yollarının görselleştirilmesi
- **Sağ Panel (%35):** Bootstrap 5.3.2 karanlık tema sidebar — tıklanan düğümün detayları
- Her zafiyet düğümü için: açıklama, kritiklik rozeti, risk skoru çubuğu, SCP durumu, CloudTrail izi, sömürü komutu, mavi takım önerisi, sıkılaştırma önerisi
- Düğümlere hover ve tıklama etkileşimleri, fizik simülasyonu, responsive tasarım
- Tüm kullanıcı verileri `htmlKacis()` ile XSS'ye karşı korunur

### CI/CD Entegrasyonu
- `.github/workflows/tulpar_tarama.yml` — iki job'lu pipeline: önce **test** (pytest), başarılı olursa **tarama**
- `workflow_dispatch` ile manuel tetikleme, `push` ile `tulpar/**` değişikliklerinde otomatik test
- `actions/cache@v4` ile **pip önbelleği** sayesinde workflow süresi kısalır
- AWS OIDC ile güvenli kimlik doğrulama (`configure-aws-credentials`)
- `upload-sarif@v3` ile SARIF sonuçları GitHub Security sekmesine akar
- Tarama sonuçlarını GitHub Artifacts olarak saklama
- Adım özetinde (Job Summary) zafiyet listesini gösterme

## Gereksinimler

- Python 3.8 veya üzeri
- boto3 >= 1.28.0 (AWS SDK for Python)
- tqdm >= 4.64.0 (opsiyonel — progress bar)
- moto >= 5.0.0 ve pytest >= 7.0.0 (geliştirme/test için)

## Kurulum

```bash
git clone https://github.com/mecik-arda/Tulpar-Framework.git
cd Tulpar-Framework
pip install -r requirements.txt
```

## Kullanım

### Temel Kullanım

```bash
python -m tulpar
```
Kimlik bilgisi verilmezse sırasıyla ortam değişkenleri, `~/.aws/credentials` ve EC2 instance profile kontrol edilir.

### Erişim Anahtarı ile

```bash
python -m tulpar \
  --erisim-anahtari AKIAIOSFODNN7EXAMPLE \
  --gizli-anahtar wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### AWS Profili ile

```bash
python -m tulpar --aws-profil uretim-hesabi
```

### Hızlı Triage

```bash
python -m tulpar --hizli
```

### Sessiz CI/CD Modu

```bash
python -m tulpar --sessiz
```

### Bağlantı Testi

```bash
python -m tulpar --sadece-kontrol
```

### SARIF Çıktısı (GitHub Security)

```bash
python -m tulpar --format sarif --format-cikti tulpar_rapor.sarif
```

### Diff Rapor (İki Tarama Karşılaştırma)

```bash
python -m tulpar --karsilastir onceki_tulpar_rapor.json --json-cikti yeni_tulpar_rapor.json
```

### CloudTrail İstismar Analizi

```bash
python -m tulpar --cloudtrail-analiz --cloudtrail-gun 14
```

### Otomatik Düzeltme Scripti

```bash
python -m tulpar --duzelt --duzeltme-cikti raporlar/tulpar_remediation.md
```

### BloodHound Dışa Aktarımı

```bash
python -m tulpar --bloodhound-cikti raporlar/tulpar_bloodhound.json
```

### IAM Access Analyzer Taraması

```bash
python -m tulpar --access-analyzer
```

### Modern TUI Arayüzü

```bash
pip install rich
python -m tulpar --tui
```

### Multi-Cloud Tarama (GCP/Azure)

```bash
python -m tulpar --bulut gcp
python -m tulpar --bulut azure
```

### Tüm Parametreler

```bash
python -m tulpar \
  --aws-profil guvenlik-denetim \
  --json-cikti raporlar/tulpar_rapor.json \
  --html-cikti raporlar/tulpar_grafik.html \
  --cevrimdisi \
  --onbellek tulpar_onbellek.json \
  --onbellek-suresi 48 \
  --format csv \
  --format-cikti raporlar/tulpar_bulgular.csv \
  --sarif-cikti raporlar/tulpar_rapor.sarif \
  --thread-sayisi 10 \
  --konfig tulpar_config.json \
  --cloudtrail-analiz \
  --access-analyzer \
  --duzelt \
  --bloodhound-cikti raporlar/tulpar_bloodhound.json \
  --web \
  --ai-analiz \
  --ai-provider openai \
  --k8s-tarama \
  --k8s-cikti raporlar/tulpar_k8s_rapor.json
```

### Parametreler

| Parametre | Zorunlu | Varsayılan | Açıklama |
|-----------|---------|------------|----------|
| `--erisim-anahtari` | Hayır | — | AWS Erişim Anahtarı Kimliği |
| `--gizli-anahtar` | Hayır | — | AWS Gizli Erişim Anahtarı |
| `--oturum-belirteci` | Hayır | `None` | AWS STS Oturum Belirteci |
| `--aws-profil` | Hayır | `None` | `~/.aws/credentials` profil adı |
| `--json-cikti` | Hayır | `raporlar/tulpar_rapor.json` | JSON rapor dosya yolu |
| `--html-cikti` | Hayır | `raporlar/tulpar_grafik.html` | HTML grafik dosya yolu |
| `--cevrimdisi` | Hayır | `False` | CDN asset'lerini yerel indir (SRI doğrulamalı) |
| `--onbellek` | Hayır | `None` | Önbellek JSON dosya yolu |
| `--onbellek-suresi` | Hayır | `24` | Önbellek geçerlilik süresi (saat) |
| `--format` | Hayır | `json` | Ek çıktı formatı: `csv`, `markdown`, `sarif` |
| `--format-cikti` | Hayır | `None` | Formatlı çıktı dosya yolu |
| `--sarif-cikti` | Hayır | `None` | SARIF formatında çıktı dosyası |
| `--konfig` | Hayır | `None` | JSON/YAML konfigürasyon dosyası |
| `--hizli` | Hayır | `False` | Sadece en kritik 15 vektörü tara |
| `--sessiz` | Hayır | `False` | Meta-bilgili JSON'u stdout'a bas, logları kapat |
| `--sadece-kontrol` | Hayır | `False` | AWS bağlantısını doğrula, tarama yapma |
| `--karsilastir` | Hayır | `None` | Önceki JSON raporu ile karşılaştır |
| `--karsilastirma-cikti` | Hayır | `raporlar/tulpar_karsilastirma.json` | Diff rapor çıktı yolu |
| `--thread-sayisi` | Hayır | `5` | Paralel bölge tarama iş parçacığı sayısı (1–20) |
| `--cloudtrail-analiz` | Hayır | `False` | CloudTrail loglarında istismar izi ara |
| `--cloudtrail-gun` | Hayır | `7` | CloudTrail geriye dönük gün sayısı |
| `--access-analyzer` | Hayır | `False` | IAM Access Analyzer taraması yap |
| `--duzelt` | Hayır | `False` | Otomatik Terraform/AWS CLI düzeltme kodu üret |
| `--duzeltme-cikti` | Hayır | `raporlar/tulpar_remediation.md` | Düzeltme script çıktı yolu |
| `--bloodhound-cikti` | Hayır | `None` | BloodHound/Neo4j JSON çıktı dosyası |
| `--tui` | Hayır | `False` | Rich tabanlı modern TUI arayüzü |
| `--bulut` | Hayır | `aws` | Bulut sağlayıcı: `aws`, `gcp`, `azure` |
| `--web` | Hayır | `False` | Streamlit tabanlı web dashboard'u başlatır |
| `--ai-analiz` | Hayır | `False` | AI/LLM destekli yönetici özeti üretir |
| `--ai-provider` | Hayır | `openai` | AI sağlayıcısı seçimi (`openai`, `claude`, `bedrock`) |
| `--ai-api-key` | Hayır | `None` | AI API anahtarı (ortam değişkeninden de okunabilir) |
| `--k8s-tarama` | Hayır | `False` | Kubernetes (EKS vb.) RBAC yetki yükseltme taraması yapar |
| `--kubeconfig` | Hayır | `None` | Kubernetes kubeconfig dosya yolu (varsayılan: `~/.kube/config`) |
| `--k8s-cikti` | Hayır | `raporlar/tulpar_k8s_rapor.json` | Kubernetes tarama raporu çıktı dosyası |

## Çıktı Dosyaları

### JSON Rapor

```json
{
  "arac_adi": "Tulpar",
  "rapor_tarihi": "Otomatik Uretildi",
  "zafiyet_sayisi": 5,
  "bulgular": [
    {
      "zafiyet_adi": "Politika Surumu Manipulasyonu",
      "kritiklik_seviyesi": "Kritik",
      "risk_skoru": 9.0,
      "scp_kisitlamasi_var": false,
      "aciklama": "Saldirgan, mevcut politikalara...",
      "cloudtrail_izi": "CreatePolicyVersion",
      "sikiastirma_onerisi": "iam:CreatePolicyVersion...",
      "somuru_komutu": "aws iam create-policy-version...",
      "mavi_takim_onerisi": "CloudTrail'de CreatePolicyVersion..."
    }
  ]
}
```

### Sessiz Mod JSON Çıktısı

```json
{
  "tarama_tarihi": "2026-06-18T14:30:00",
  "arac_surumu": "3.0.0",
  "zafiyet_sayisi": 5,
  "scp_kisitlamasi_var": false,
  "kritik_zafiyet_sayisi": 3,
  "yuksek_zafiyet_sayisi": 2,
  "zafiyetler": ["Politika Surumu Manipulasyonu", "Dogrudan Hak Enjeksiyonu", ...]
}
```

### SARIF Rapor — GitHub Security sekmesi entegrasyonu
### CSV Rapor — Jira/Excel entegrasyonu için
### Markdown Rapor — Confluence/Dokümantasyon için
### HTML Grafiği — İnteraktif görselleştirme (tarayıcıda açılır)
### Diff Rapor — İki tarama arası fark analizi

## Mimari

```
tulpar/
├── __init__.py              Paket başlatıcı, sürüm bilgisi (v3.0.0)
├── __main__.py              python -m tulpar giriş noktası
├── sabitler.py              Sürüm, bölge listesi, CDN URL'leri, SRI hash'leri, çıktı formatları
├── vektorler.json           Dinamik kural veritabanı - AWS (65 vektör, 58 benzersiz IAM eylemi)
├── vektorler_gcp.json       GCP IAM vektör tanımları (8 vektör)
├── vektorler_azure.json     Azure IAM vektör tanımları (8 vektör)
├── dogrulayici.py           JSON şema doğrulama, asset bütünlük kontrolü ve güvenlik
├── onbellek.py              Güvenli tarama önbelleği (chmod 0o600) okuma/yazma
├── raporlayici.py           CSV, SARIF, Markdown rapor formatları ve BloodHound export
├── entegrasyon.py           TUI, Web Dashboard ve AI analiz modülleri entegrasyonları
├── templates/grafik.html    Saldırı grafiği için statik HTML ve Vis.js şablonu
├── tarayici.py              GekSizmaScanner — Kimlik, SCP, CloudTrail, Access Analyzer,
│                            paralel çoklu bölge, retry, sayfalama
├── analiz.py                ExploitationMappingEngine — JSON'dan dinamik vektör işleme motoru,
│                            CloudTrail istismar analizi, Access Analyzer entegrasyonu
├── rapor.py                 AttackGraphGenerator (XSS korumalı) + ReportWriter + CokluFormatRaporlayici
├── lambda_handler.py        AWS Lambda handler — SNS/Slack bildirimli sürekli güvenlik taraması
├── ai_analiz.py             AI/LLM yönetici özeti motoru (OpenAI, Claude, Bedrock)
├── web_dashboard.py         Streamlit tabanlı web arayüzü ve görselleştirme paneli
├── k8s_tarayici.py          Kubernetes RBAC yetki yükseltme tarayıcısı ve analizörü
└── main.py                  CLI (argparse), tarama profilleri, exit code, kimlik çözümleme
Dockerfile                   DevSecOps ortamı için Docker imajı
docker-compose.yml           Docker Compose yapılandırması
pyproject.toml               PyPI paketleme ve bağımlılık yönetimi dosyası
.flake8                      Kod kalitesi kuralları
test_tulpar.py               51 birim testi (unittest.mock)
```

### Veri Akışı

1. `yardimcilar.vektorleri_yukle()` → `vektorler.json` (veya `vektorler_gcp.json`/`vektorler_azure.json`) okunur, 12 alanlı şema doğrulaması yapılır
2. `yardimcilar.kontrol_edilecek_eylemleri_derle()` → Vektörlerden benzersiz IAM eylemleri çıkarılır
3. `tarayici.hak_simulasyonu_yap()` → 200'erli sayfalama ile IAM simülasyonu yapılır
4. `analiz.ExploitationMappingEngine` → Her vektörün `gerekli_izinler` (OR/AND) koşulu değerlendirilir
5. **CloudTrail Entegrasyonu:** `tarayici.cloudtrail_istismar_analizi()` → Son N günlük CloudTrail olayları taranır
6. **Access Analyzer:** `tarayici.access_analyzer_tara()` → Cross-account ve public rol bulguları toplanır
7. `yardimcilar.dugum_zafiyet_esleme_olustur()` → JSON'dan düğüm-zafiyet eşleme tablosu türetilir
8. `rapor` modülü → JSON, HTML (XSS korumalı), CSV, Markdown, SARIF, BloodHound formatlarında rapor
9. **Düzeltme:** `yardimcilar.duzeltme_scripti_uret()` → Terraform + AWS CLI düzeltme blokları
10. Kritik zafiyet varsa `sys.exit(1)`, yoksa `sys.exit(0)` — CI/CD pipeline'ları için

### Yeni Vektör Ekleme

`vektorler.json` dosyasına aşağıdaki yapıda yeni bir JSON nesnesi eklemek yeterlidir — hiçbir kod değişikliği gerekmez:

```json
{
  "vektor_adi": "YeniVektor_TeknikAdi",
  "turkce_baslik": "Vektörün Türkçe Başlığı",
  "gerekli_izinler": [["izin:1", "izin:2"], ["izin:3"]],
  "risk_seviyesi": "Kritik",
  "risk_skoru": 9.0,
  "aciklama": "Zafiyetin detaylı açıklaması...",
  "iyilestirme": "Sıkılaştırma önerisi...",
  "cloudtrail_izi": "IlgiliAPILar",
  "somuru_komutu": "aws ... sömürü komutu ...",
  "mavi_takim_onerisi": "Mavi takım savunma önerisi...",
  "saldiri_grafi_dugumu": "GrafikDugumAdi",
  "saldiri_grafi_hedefi": "AdministratorAccess"
}
```

`gerekli_izinler` alanındaki dış liste VEYA (OR), iç listeler VE (AND) mantığıyla değerlendirilir:
- `[["izin:A"]]` → yalnızca `izin:A` allowed ise tetiklenir
- `[["izin:A", "izin:B"]]` → `izin:A` VE `izin:B` allowed ise tetiklenir
- `[["izin:A"], ["izin:B"]]` → `izin:A` VEYA `izin:B` allowed ise tetiklenir

## 🔒 5 Aşamalı DevSecOps Pipeline (GitHub Actions)

Depoda her kod değişikliğinde (push/PR) otomatik tetiklenen, **5 aşamalı ve sıfır-güven (zero-trust)** prensibine dayalı tam teşekküllü bir DevSecOps kontrol hattı bulunur (`.github/workflows/`):

1. 🧪 **Kod Kalitesi ve Birim Testleri:** `pytest` ile tüm fonksiyonlar test edilir, `flake8` ve `bandit` ile statik kod & güvenlik analizi yapılır.
2. 🐳 **Docker İmaj Tarama:** Güncel kod ile oluşturulan konteyner imajı `trivy` kullanılarak CVE zafiyetlerine karşı taranır.
3. ☁️ **OIDC Kimlik Doğrulama:** Uzun ömürlü ve statik AWS anahtarları kullanmak yerine, GitHub Actions OIDC (OpenID Connect) ile geçici, güvenli ve daraltılmış ayrıcalıklara sahip bir IAM rolüne bürünür (AssumeRole).
4. 🚀 **AWS IAM Yetki Yükseltme Taraması:** Tulpar, AWS ortamındaki güncel IAM politikalarını analiz eder ve olası ayrıcalık yükseltme (privilege escalation) risklerini tespit eder. Gece 03:07 UTC'de otomatik zamanlanmış tarama da yapılır.
5. 📊 **GitHub Advanced Security (SARIF):** Bulunan güvenlik açıkları ve zafiyet raporları SARIF formatında GitHub Security sekmesine (Code Scanning Alerts) ve Artifacts alanına otomatik olarak yüklenir.

**Kurulum & Kullanım:**

1. GitHub Secrets'a OIDC trust ilişkili IAM rolünüzün ARN değerini `AWS_TULPAR_TARAMA_ROLU_ARN` olarak ekleyin.
2. AWS hesabınızda GitHub Actions'ın `sts:AssumeRoleWithWebIdentity` yapabilmesi için [OIDC provider yapılandırın](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services).
3. Sonrasında yapacağınız her push işleminde, 5 güvenlik kapısından geçen temiz bir CI/CD süreci deneyimleyeceksiniz!

Manuel tetikleme: GitHub Actions sekmesinden → "Tulpar AWS IAM Guvenlik Taramasi" veya "Tulpar DevSecOps Guvenlik Kapisi" → "Run workflow"

## AWS Lambda Olarak Çalıştırma

Tulpar, her gece otomatik tarama yapacak bir AWS Lambda fonksiyonu olarak da çalışabilir:

### Lambda Deployment

```bash
# 1. Deployment paketini oluştur
pip install boto3 -t ./lambda_paket/
cp -r tulpar/ ./lambda_paket/tulpar/
cd lambda_paket && zip -r ../tulpar_lambda.zip . && cd ..

# 2. Lambda fonksiyonunu oluştur
aws lambda create-function \
  --function-name TulparGeceTaramasi \
  --runtime python3.9 \
  --handler tulpar.lambda_handler.lambda_handler \
  --role arn:aws:iam::HESAP_ID:role/LambdaExecutionRole \
  --zip-file fileb://tulpar_lambda.zip \
  --timeout 300 \
  --memory-size 512 \
  --environment "Variables={TULPAR_SNS_TOPIC_ARN=arn:aws:sns:BOLGE:HESAP_ID:TulparBildirimleri,TULPAR_HIZLI_MOD=false,TULPAR_CLOUDTRAIL_ANALIZ=true}"

# 3. EventBridge kuralı ile gece 03:00'da tetikle
aws events put-rule \
  --name TulparGeceTaramasiKurali \
  --schedule-expression "cron(0 3 * * ? *)"

aws events put-targets \
  --rule TulparGeceTaramasiKurali \
  --targets "Id"="1","Arn"="arn:aws:lambda:BOLGE:HESAP_ID:function:TulparGeceTaramasi"
```

### Slack Bildirimi

```bash
# Lambda ortam değişkenine Slack Webhook URL'i ekleyin
TULPAR_SLACK_WEBHOOK=https://hooks.slack.com/services/TXXXX/BXXXX/XXXXXXXX
```

### Lambda Ortam Değişkenleri

| Değişken | Zorunlu | Açıklama |
|----------|---------|----------|
| `TULPAR_SNS_TOPIC_ARN` | Hayır | SNS bildirim konusu ARN'i |
| `TULPAR_SLACK_WEBHOOK` | Hayır | Slack webhook URL'i |
| `TULPAR_HIZLI_MOD` | Hayır | `true` ise sadece 15 vektör taranır |
| `TULPAR_CLOUDTRAIL_ANALIZ` | Hayır | `true` ise CloudTrail analizi aktif |

## Test

```bash
pip install moto pytest
python -m pytest test_tulpar.py -v
```

**50+ test**, tüm modülleri kapsar:

| Test Sınıfı | Test Sayısı | Kapsam |
|-------------|:-----------:|--------|
| `TestGekSizmaScannerKimlik` | 3 | Kimlik doğrulama ve sadece-kontrol modu |
| `TestGekSizmaScannerHakSimulasyonu` | 3 | IAM simülasyonu, hata durumları |
| `TestGekSizmaScannerSCPKontrolu` | 2 | SCP tespiti ve Organizations API hataları |
| `TestGekSizmaScannerBolgeListeleme` | 2 | Bölge listeleme, AccessDenied fallback |
| `TestExploitationMappingEngine` | 4 | Zafiyet tespiti, risk skoru, fallback, hızlı mod |
| `TestYardimcilarVektorYukleme` | 8 | JSON yükleme, doğrulama (4 edge case), önbellek, eylem derleme, düğüm eşleme |
| `TestReportWriter` | 2 | JSON rapor, dizin otomatik oluşturma |
| `TestAttackGraphGenerator` | 1 | HTML grafik çıktısı |
| `TestCokluFormatRaporlayici` | 4 | CSV, Markdown, SARIF, geçersiz format |
| `TestSarifRaporu` | 2 | SARIF kritik ve orta risk seviyeleri |
| `TestRaporKarsilastir` | 3 | Diff: yeni eklenen, kapanan, dosya yok |
| `TestCokluBolgeKaynakTarama` | 2 | Paralel tarama, tüm bölgelerde hata |
| `TestAwsHataYonetimi` | 4 | 4 farklı AWS hata kodu |

## Güvenlik ve Sorumluluk Reddi

**Bu araç yalnızca yetkili güvenlik testleri, sızma testleri ve savunma amaçlı mavi takım çalışmaları için geliştirilmiştir.**

- Tulpar'ı yalnızca sahibi olduğunuz veya yazılı test izni aldığınız AWS hesaplarında kullanın
- Aracın kötüye kullanımından doğacak hukuki sonuçlardan kullanıcı sorumludur
- Araç salt okunur API çağrıları yapar; hiçbir kaynak oluşturmaz, değiştirmez veya silmez
- Uygulama girdiğiniz hiçbir API anahtarını veya erişim bilgisini diske kaydetmez, loglamaz veya dışarı sızdırmaz
- Tespit edilen zafiyetleri derhal ilgili AWS hesap yöneticilerine bildirin

## Lisans

MIT License. Detaylar için [LICENSE](LICENSE) dosyasına bakın.
