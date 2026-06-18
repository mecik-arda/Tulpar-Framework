# Tulpar — AWS IAM Privilege Escalation Scanner

Tulpar, AWS Identity and Access Management (IAM) ortamlarında yetki yükseltme (privilege escalation) vektörlerini otomatik olarak tarayan, analiz eden ve görselleştiren gelişmiş bir ofansif güvenlik aracıdır. Araç, bir AWS hesabına ait erişim anahtarları ile çalışarak mevcut yetkileri simüle eder, istismar edilebilir yolları tespit eder ve sonuçları JSON, CSV, Markdown raporları ile interaktif HTML saldırı grafiği olarak sunar.

## Özellikler

### Kimlik ve Yetki Keşfi
- `sts:GetCallerIdentity` ile mevcut kimliğin ARN, Hesap ID ve Kullanıcı ID bilgilerini çeker
- `iam:SimulatePrincipalPolicy` API'si üzerinden **58 kritik IAM eylemi** için yetki simülasyonu yapar
- Simülasyon API'sine erişim engellendiğinde fallback mekanizması ile çalışmaya devam eder

### Dinamik JSON Kural Veritabanı
- Aracın tespit ettiği tüm yetki yükseltme vektörleri, risk skorları, gerekli IAM izinleri ve mavi takım tavsiyeleri statik kod yerine harici bir `vektorler.json` dosyasında saklanır.
- Koda müdahale etmeye gerek kalmadan, JSON dosyasına basit bir kural bloğu ekleyerek araca yeni zafiyet vektörleri öğretilebilir.
- Her vektör için `gerekli_izinler` alanı iç içe liste yapısıyla tanımlanır: dış liste VEYA (OR), iç liste VE (AND) mantığıyla değerlendirilir. Bu sayede `PassRole + (CreateProject VEYA StartBuild)` gibi karmaşık izin koşulları kod yazmadan ifade edilebilir.
- Risk skorları, düğüm-zafiyet eşleme tablosu ve kontrol edilecek IAM eylem listesi çalışma zamanında JSON'dan otomatik türetilir.

### 50 Yetki Yükseltme Vektörü Kontrolü

#### IAM Tabanlı Vektörler (1–18)

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 1 | Politika Sürümü Manipülasyonu | `iam:CreateNewPolicyVersion` | Kritik | 9.0 |
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

> **Risk Dağılımı:** 24 Kritik (≥8.8), 26 Yüksek (6.5–8.5). Her vektör; açıklama, sömürü komutu, CloudTrail izi, sıkılaştırma önerisi ve mavi takım savunma önerisi ile birlikte `vektorler.json` içinde tanımlanmıştır.

### CVSS Benzeri Risk Skorlaması
- Her zafiyet için **0-10 arası sayısal risk skoru** otomatik hesaplanır
- HTML dashboard'da renkli risk çubuğu ile görselleştirilir (Kırmızı ≥9.0, Turuncu ≥7.0, Sarı ≥5.0, Yeşil <5.0)
- Risk skoru JSON, CSV ve Markdown çıktılarına dahil edilir

### AWS Organizations ve SCP Kontrolü
- `organizations:DescribeOrganization` ile Organizations yapısını tespit eder
- `organizations:ListPoliciesForTarget` ile hesaba atanmış SCP'leri (Service Control Policy) listeler
- SCP varlığı tüm rapor formatlarında `scp_kisitlamasi_var` alanı ile belirtilir
- SCP varsa kullanıcıya IAM politikalarının SCP tarafından kısıtlanabileceği uyarısı verilir

### Çoklu Bölge (Multi-Region) Desteği
- `ec2:DescribeRegions` ile tüm aktif AWS bölgelerini dinamik olarak listeler
- tqdm progress bar ile `[7/17] eu-west-1 taranıyor...` formatında anlık ilerleme gösterimi
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
- JSON ve HTML formatlarına ek olarak desteklenir

### Konfigürasyon Dosyası Desteği
- `--konfig ayarlar.json` ile JSON/YAML konfigürasyon dosyasından varsayılan değerler okunur
- CI/CD pipeline'larına ve otomasyon sistemlerine kolay entegrasyon

### Çevrimdışı (Air-Gapped) Raporlama
- `--cevrimdisi` ile CDN asset'leri yerel `tulpar_assets/` klasörüne indirilir
- HTML raporu internet bağlantısı olmadan çalışır
- İndirme başarısız olursa CDN bağlantılarına otomatik geri dönüş (fallback)

### Gelişmiş Hata Yönetimi
- 8 farklı AWS hata kodu için spesifik Türkçe geri bildirim
- `AccessDenied`, `TokenExpired`, `InvalidClientTokenId`, `UnauthorizedOperation`, `Throttling`, `ExpiredToken`, `SignatureDoesNotMatch`, `RequestExpired`

### Profesyonel Loglama
- Python `logging` modülü ile yapılandırılmış log çıktıları
- Zaman damgalı, seviye etiketli: `2026-06-18 14:30:00 - INFO - mesaj`

### İnteraktif HTML Saldırı Grafiği
- **Sol Panel (%65):** vis.js 10.1.0 ağ grafiği ile saldırı yollarının görselleştirilmesi
- **Sağ Panel (%35):** Bootstrap 5.3.2 karanlık tema sidebar — tıklanan düğümün detayları
- Her zafiyet düğümü için: açıklama, kritiklik rozeti, risk skoru çubuğu, SCP durumu, CloudTrail izi, sömürü komutu, mavi takım önerisi, sıkılaştırma önerisi
- Düğümlere hover ve tıklama etkileşimleri, fizik simülasyonu, responsive tasarım
- **SRI (Subresource Integrity) koruması:** Tüm CDN kaynakları `sha384` hash doğrulaması ile MITM saldırılarına karşı korunur

### CI/CD Entegrasyonu
- `.github/workflows/tulpar_tarama.yml` ile her gece 03:00'te otomatik tarama
- `workflow_dispatch` ile manuel tetikleme desteği
- AWS OIDC ile güvenli kimlik doğrulama (`configure-aws-credentials`)
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
  --konfig tulpar_config.json
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
| `--cevrimdisi` | Hayır | `False` | CDN asset'lerini yerel indir |
| `--onbellek` | Hayır | `None` | Önbellek JSON dosya yolu |
| `--onbellek-suresi` | Hayır | `24` | Önbellek geçerlilik süresi (saat) |
| `--format` | Hayır | `json` | Ek çıktı formatı: `csv`, `markdown` |
| `--format-cikti` | Hayır | `None` | Formatlı çıktı dosya yolu |
| `--konfig` | Hayır | `None` | JSON/YAML konfigürasyon dosyası |

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
      "cloudtrail_izi": "CreateNewPolicyVersion",
      "sikiastirma_onerisi": "iam:CreateNewPolicyVersion...",
      "somuru_komutu": "aws iam create-policy-version...",
      "mavi_takim_onerisi": "CloudTrail'de CreateNewPolicyVersion..."
    }
  ]
}
```

### CSV Rapor — Jira/Excel entegrasyonu için
### Markdown Rapor — Confluence/Dokümantasyon için
### HTML Grafiği — İnteraktif görselleştirme (tarayıcıda açılır)

## Mimari

```
tulpar/
├── __init__.py           Paket başlatıcı, sürüm bilgisi (v2.1.0)
├── __main__.py           python -m tulpar giriş noktası
├── sabitler.py           Sürüm, bölge listesi, CDN URL'leri, SRI hash'leri
├── vektorler.json        Dinamik kural veritabanı (50 vektör, izinler ve skorlar)
├── yardimcilar.py        Loglama, SRI hash, önbellek, konfigürasyon, vektör JSON okuyucu
├── tarayici.py           GekSizmaScanner — Kimlik, bölge, SCP, progress tracking
├── analiz.py             ExploitationMappingEngine — JSON'dan dinamik olarak kuralları işleyen motor
├── rapor.py              AttackGraphGenerator + ReportWriter + CokluFormatRaporlayici
└── main.py               CLI (argparse), kimlik çözümleme, akış kontrolü
test_tulpar.py            Birim testleri (unittest.mock)
```

### Veri Akışı

1. `yardimcilar.vektorleri_yukle()` → `vektorler.json` okunur, önbelleğe alınır
2. `yardimcilar.kontrol_edilecek_eylemleri_derle()` → Tüm vektörlerden benzersiz 58 IAM eylemi çıkarılır
3. `tarayici.hak_simulasyonu_yap()` → 58 eylem için IAM simülasyonu yapılır
4. `analiz.ExploitationMappingEngine` → Her vektörün `gerekli_izinler` koşulu simülasyon sonucuna karşı değerlendirilir, eşleşenler bulguya dönüştürülür
5. `yardimcilar.dugum_zafiyet_esleme_olustur()` → JSON'dan düğüm-zafiyet eşleme tablosu türetilir
6. `rapor` modülü → JSON, HTML, CSV, Markdown formatlarında rapor üretilir

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

## GitHub Actions CI/CD

Depoda `.github/workflows/tulpar_tarama.yml` dosyası mevcuttur. Her gece 03:00 UTC'de otomatik tarama çalıştırır. Kullanmak için:

1. GitHub Secrets'a `AWS_TULPAR_TARAMA_ROLU_ARN` ekleyin (OIDC trust ilişkili IAM rolü)
2. AWS hesabınızda GitHub Actions'ın assume-role yapabilmesi için OIDC provider yapılandırın
3. Workflow otomatik olarak çalışacak ve sonuçları Artifacts olarak saklayacaktır

Manuel tetikleme: GitHub Actions sekmesinden → "Tulpar AWS IAM Guvenlik Taramasi" → "Run workflow"

## Test

```bash
pip install moto pytest
python -m pytest test_tulpar.py -v
```

15 test, tüm temel sınıfları ve hata yönetimini kapsar.

## Güvenlik ve Sorumluluk Reddi

**Bu araç yalnızca yetkili güvenlik testleri, sızma testleri ve savunma amaçlı mavi takım çalışmaları için geliştirilmiştir.**

- Tulpar'ı yalnızca sahibi olduğunuz veya yazılı test izni aldığınız AWS hesaplarında kullanın
- Aracın kötüye kullanımından doğacak hukuki sonuçlardan kullanıcı sorumludur
- Araç salt okunur API çağrıları yapar; hiçbir kaynak oluşturmaz, değiştirmez veya silmez
- Tespit edilen zafiyetleri derhal ilgili AWS hesap yöneticilerine bildirin

## Lisans

MIT License. Detaylar için [LICENSE](LICENSE) dosyasına bakın.
