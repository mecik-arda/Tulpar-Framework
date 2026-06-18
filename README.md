# Tulpar — AWS IAM Privilege Escalation Scanner

Tulpar, AWS Identity and Access Management (IAM) ortamlarında yetki yükseltme (privilege escalation) vektörlerini otomatik olarak tarayan, analiz eden ve görselleştiren gelişmiş bir ofansif güvenlik aracıdır. Araç, bir AWS hesabına ait erişim anahtarları ile çalışarak mevcut yetkileri simüle eder, istismar edilebilir yolları tespit eder ve sonuçları JSON, CSV, Markdown raporları ile interaktif HTML saldırı grafiği olarak sunar.

## Özellikler

### Kimlik ve Yetki Keşfi
- `sts:GetCallerIdentity` ile mevcut kimliğin ARN, Hesap ID ve Kullanıcı ID bilgilerini çeker
- `iam:SimulatePrincipalPolicy` API'si üzerinden **29 kritik IAM eylemi** için yetki simülasyonu yapar
- Simülasyon API'sine erişim engellendiğinde fallback mekanizması ile çalışmaya devam eder

### 23 Yetki Yükseltme Vektörü Kontrolü

| # | Vektör | Gereken İzinler | Kritiklik | Risk |
|---|--------|-----------------|-----------|------|
| 1 | Politika Sürümü Manipülasyonu | `iam:CreateNewPolicyVersion` | Kritik | 9.0 |
| 2 | Doğrudan Hak Enjeksiyonu | `iam:AttachUserPolicy` / `iam:PutUserPolicy` | Kritik | 9.5 |
| 3 | Metadata IMDSv2 Üzerinden Rol Çalma | `iam:PassRole` + `ec2:RunInstances` | Kritik | 9.8 |
| 4 | Lambda Fonksiyonu ile Admin Tetikleme | `iam:PassRole` + `lambda:CreateFunction` | Kritik | 9.5 |
| 5 | Güven İlişkisi Suistimali | `iam:UpdateAssumeRolePolicy` | Yüksek | 8.0 |
| 6 | Glue Endpoint Üzerinden Rol Çalma | `iam:PassRole` + `glue:CreateDevEndpoint` | Kritik | 9.3 |
| 7 | CloudFormation Stack ile Yetki Yükseltme | `iam:PassRole` + `cloudformation:CreateStack` | Kritik | 9.6 |
| 8 | DataPipeline Manipülasyonu | `iam:PassRole` + `datapipeline:CreatePipeline` | Kritik | 9.4 |
| 9 | SageMaker Notebook Konsoluna Sızma | `sagemaker:CreatePresignedNotebookInstanceUrl` | Yüksek | 7.5 |
| 10 | Erişim Anahtarı Üretme | `iam:CreateAccessKey` | Kritik | 9.2 |
| 11 | Konsol Parolası Atama | `iam:CreateLoginProfile` | Kritik | 9.0 |
| 12 | EC2'ya Sonradan Rol Atama | `iam:PassRole` + `ec2:ModifyInstanceAttribute` | Kritik | 9.7 |
| 13 | Zincirleme Rol Üstlenme | `sts:AssumeRole` | Yüksek | 7.5 |
| 14 | Secrets Manager'dan Veri Okuma | `secretsmanager:GetSecretValue` | Yüksek | 7.0 |
| 15 | S3 Üzerinden Kod Çalıştırma | `s3:GetObject` / `s3:PutObject` | Yüksek | 6.5 |
| 16 | Konsol Şifresi Güncelleme | `iam:UpdateLoginProfile` | Yüksek | 8.5 |
| 17 | Grup Yönetimi Manipülasyonu | `iam:AddUserToGroup` | Kritik | 9.2 |
| 18 | Eski Politika Sürümüne Dönüş | `iam:SetDefaultPolicyVersion` | Kritik | 8.8 |
| 19 | Mevcut Lambda Koduna Enjeksiyon | `lambda:UpdateFunctionCode` | Yüksek | 8.0 |
| 20 | CodeBuild Projesi ile Rol Çalma | `iam:PassRole` + `codebuild:CreateProject` / `StartBuild` | Kritik | 9.5 |
| 21 | SSM Komut Enjeksiyonu | `ssm:SendCommand` / `ssm:StartSession` | Yüksek | 8.5 |
| 22 | Rol Politikası Manipülasyonu | `iam:PutRolePolicy` / `iam:AttachRolePolicy` | Kritik | 9.3 |
| 23 | Lambda Konfigürasyon Güncelleme | `lambda:UpdateFunctionConfiguration` | Yüksek | 8.5 |

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
├── sabitler.py           Tüm sabitler, risk skoru tablosu, CDN URL'leri
├── yardimcilar.py        Loglama, SRI hash, CSV/Markdown yazıcı, önbellek, konfigürasyon
├── tarayici.py           GekSizmaScanner — Kimlik, bölge, SCP, progress tracking
├── analiz.py             ExploitationMappingEngine — 23 vektör kontrolü, risk skorlama
├── rapor.py              AttackGraphGenerator + ReportWriter + CokluFormatRaporlayici
└── main.py               CLI (argparse), kimlik çözümleme, akış kontrolü
test_tulpar.py            Birim testleri (moto + unittest.mock)
```

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

16 test, tüm temel sınıfları ve hata yönetimini kapsar.

## Güvenlik ve Sorumluluk Reddi

**Bu araç yalnızca yetkili güvenlik testleri, sızma testleri ve savunma amaçlı mavi takım çalışmaları için geliştirilmiştir.**

- Tulpar'ı yalnızca sahibi olduğunuz veya yazılı test izni aldığınız AWS hesaplarında kullanın
- Aracın kötüye kullanımından doğacak hukuki sonuçlardan kullanıcı sorumludur
- Araç salt okunur API çağrıları yapar; hiçbir kaynak oluşturmaz, değiştirmez veya silmez
- Tespit edilen zafiyetleri derhal ilgili AWS hesap yöneticilerine bildirin

## Lisans

MIT License. Detaylar için [LICENSE](LICENSE) dosyasına bakın.
