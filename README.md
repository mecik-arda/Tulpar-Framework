# Tulpar — AWS IAM Privilege Escalation Scanner

Tulpar, AWS Identity and Access Management (IAM) ortamlarında yetki yükseltme (privilege escalation) vektörlerini otomatik olarak tarayan, analiz eden ve görselleştiren gelişmiş bir ofansif güvenlik aracıdır. Araç, bir AWS hesabına ait erişim anahtarları ile çalışarak mevcut yetkileri simüle eder, istismar edilebilir yolları tespit eder ve sonuçları hem yapılandırılmış JSON raporu hem de interaktif HTML saldırı grafiği olarak sunar.

## Özellikler

### Kimlik ve Yetki Keşfi
- `sts:GetCallerIdentity` ile mevcut kimliğin ARN, Hesap ID ve Kullanıcı ID bilgilerini çeker
- `iam:SimulatePrincipalPolicy` API'si üzerinden 12 kritik IAM eylemi için yetki simülasyonu yapar
- Simülasyon API'sine erişim engellendiğinde fallback mekanizması ile çalışmaya devam eder

### 11 Yetki Yükseltme Vektörü Kontrolü

| # | Vektör | Gereken İzinler | Kritiklik |
|---|--------|-----------------|-----------|
| 1 | Politika Sürümü Manipülasyonu | `iam:CreateNewPolicyVersion` | Kritik |
| 2 | Doğrudan Hak Enjeksiyonu | `iam:AttachUserPolicy` veya `iam:PutUserPolicy` | Kritik |
| 3 | Metadata IMDSv2 Üzerinden Rol Çalma | `iam:PassRole` + `ec2:RunInstances` | Kritik |
| 4 | Lambda Fonksiyonu ile Admin Tetikleme | `iam:PassRole` + `lambda:CreateFunction` | Kritik |
| 5 | Güven İlişkisi Suistimali | `iam:UpdateAssumeRolePolicy` | Yüksek |
| 6 | Glue Endpoint Üzerinden Rol Çalma | `iam:PassRole` + `glue:CreateDevEndpoint` | Kritik |
| 7 | CloudFormation Stack ile Yetki Yükseltme | `iam:PassRole` + `cloudformation:CreateStack` | Kritik |
| 8 | DataPipeline Manipülasyonu | `iam:PassRole` + `datapipeline:CreatePipeline` | Kritik |
| 9 | SageMaker Notebook Konsoluna Sızma | `sagemaker:CreatePresignedNotebookInstanceUrl` | Yüksek |
| 10 | Başka Kullanıcı Adına Erişim Anahtarı Üretme | `iam:CreateAccessKey` | Kritik |
| 11 | Bilinmeyen Yetki Durumu | Simülasyon API'si engellendiğinde | Belirsiz |

### Çoklu Bölge (Multi-Region) Desteği
- `ec2:DescribeRegions` ile tüm aktif AWS bölgelerini dinamik olarak listeler
- API erişimi kısıtlıysa 17 varsayılan bölge üzerinden taramaya devam eder
- Her bölgede EC2 bulutularını ve Lambda fonksiyonlarını tarayarak kaynak envanteri çıkarır
- Bulunan kaynakları potansiyel hedef olarak rapora ekler

### Gelişmiş Hata Yönetimi
- 8 farklı AWS hata kodu için spesifik Türkçe geri bildirim:
  - `AccessDenied` — Erişim Reddedildi
  - `TokenExpired` — Oturum Belirteci Süresi Doldu
  - `InvalidClientTokenId` — Geçersiz Erişim Anahtarı
  - `UnauthorizedOperation` — Yetkisiz İşlem
  - `Throttling` — İstek Kısıtlaması
  - `ExpiredToken` — Belirteç Geçersiz
  - `SignatureDoesNotMatch` — İmza Uyuşmazlığı
  - `RequestExpired` — İstek Zamanı Geçti

### Profesyonel Loglama
- Python `logging` modülü ile yapılandırılmış log çıktıları
- Zaman damgalı, seviye etiketli, temiz format: `2026-06-18 14:30:00 - INFO - mesaj`

### İnteraktif HTML Saldırı Grafiği
- **Sol Panel (%65):** vis.js ağ grafiği ile saldırı yollarının görselleştirilmesi
- **Sağ Panel (%35):** Tıklanan düğümün detaylarını gösteren modern karanlık tema sidebar
- Her zafiyet düğümü için dinamik olarak gösterilen bilgiler:
  - Zafiyet açıklaması
  - Kritiklik seviyesi (renk kodlu rozet)
  - CloudTrail izi (hangi API çağrılarının izleneceği)
  - Sömürü komutu örneği (kopyalanabilir kod kutusu)
  - Mavi Takım savunma önerisi
  - Sıkılaştırma önerisi
- Düğümlere hover ve tıklama etkileşimleri
- Fizik simülasyonu tamamlandıktan sonra otomatik dondurma
- Mobil uyumlu responsive tasarım
- **SRI (Subresource Integrity) koruması:** CDN kaynakları `sha384` hash doğrulaması ile MITM saldırılarına karşı korunur

### JSON Rapor Çıktısı
- Yapılandırılmış, makine tarafından işlenebilir JSON formatı
- Her bulgu için zengin metaveri alanları

## Gereksinimler

- Python 3.8 veya üzeri
- [boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html) — AWS SDK for Python
- İnternet bağlantısı (HTML raporundaki CDN kütüphaneleri için)

## Kurulum

```bash
pip install boto3
```

Ardından `tulpar.py` dosyasını çalıştırılabilir bir dizine kopyalayın.

```bash
git clone https://github.com/kullanici/tulpar.git
cd tulpar
pip install -r requirements.txt
```

`requirements.txt`:
```
boto3>=1.28.0
```

## Kullanım

### Temel Kullanım

```bash
python tulpar.py \
  --erisim-anahtari AKIAIOSFODNN7EXAMPLE \
  --gizli-anahtar wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### Oturum Belirteci (STS Token) ile

```bash
python tulpar.py \
  --erisim-anahtari AKIAIOSFODNN7EXAMPLE \
  --gizli-anahtar wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --oturum-belirteci IQoJb3JpZ2luX2VjE...
```

### Özel Çıktı Dosyaları

```bash
python tulpar.py \
  --erisim-anahtari AKIAIOSFODNN7EXAMPLE \
  --gizli-anahtar wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --json-cikti rapor.json \
  --html-cikti saldiri_grafi.html
```

### Parametreler

| Parametre | Zorunlu | Varsayılan | Açıklama |
|-----------|---------|------------|----------|
| `--erisim-anahtari` | Evet | — | AWS Erişim Anahtarı Kimliği (Access Key ID) |
| `--gizli-anahtar` | Evet | — | AWS Gizli Erişim Anahtarı (Secret Access Key) |
| `--oturum-belirteci` | Hayır | `None` | AWS Oturum Belirteci (STS Session Token) |
| `--json-cikti` | Hayır | `tulpar_rapor.json` | JSON raporunun kaydedileceği dosya yolu |
| `--html-cikti` | Hayır | `tulpar_grafik.html` | HTML grafiğinin kaydedileceği dosya yolu |

## Çıktı Dosyaları

### JSON Rapor (`tulpar_rapor.json`)

```json
{
  "arac_adi": "Tulpar",
  "rapor_tarihi": "Otomatik Uretildi",
  "zafiyet_sayisi": 3,
  "bulgular": [
    {
      "zafiyet_adi": "Politika Surumu Manipulasyonu",
      "kritiklik_seviyesi": "Kritik",
      "aciklama": "Saldirgan, mevcut politikalara yeni surumler ekleyerek...",
      "cloudtrail_izi": "CreateNewPolicyVersion",
      "sikiastirma_onerisi": "iam:CreateNewPolicyVersion yetkisini kaldirin...",
      "somuru_komutu": "aws iam create-policy-version --policy-arn ...",
      "mavi_takim_onerisi": "CloudTrail'de CreateNewPolicyVersion olaylarini izleyin..."
    }
  ]
}
```

### HTML Grafiği (`tulpar_grafik.html`)

Tamamen bağımsız (standalone) bir HTML dosyasıdır. Herhangi bir web tarayıcısında çift tıklayarak açılabilir. İnternet bağlantısı gerektirir (CDN kütüphaneleri için).

## Mimari

Araç dört ana sınıftan oluşur:

### `GekSizmaScanner`
Kimlik doğrulama, yetki simülasyonu ve çoklu bölge kaynak taramasından sorumlu temel sınıftır.
- `kimlik_bilgilerini_getir()` — STS'den mevcut kimlik bilgilerini alır
- `hak_simulasyonu_yap()` — IAM simülasyonu ile yetkileri kontrol eder
- `bolgeleri_listele()` — Aktif AWS bölgelerini dinamik olarak listeler
- `coklu_bolge_kaynak_tarama()` — Tüm bölgelerde EC2 ve Lambda kaynaklarını tarar
- `_aws_hatasi_yonet()` — AWS hata kodlarını işler ve anlamlı geri bildirim üretir

### `ExploitationMappingEngine`
Yetki yükseltme vektörlerini analiz eden motor sınıfıdır. 11 farklı kontrol metodu içerir.
- `analiz_baslat()` — Tüm kontrolleri sırayla çalıştıran ana metot
- Her vektör için `_*_kontrol_et()` şeklinde özel kontrol metotları

### `AttackGraphGenerator`
Saldırı yollarını interaktif HTML grafiğine dönüştüren görselleştirme sınıfıdır.
- `html_olustur()` — vis.js tabanlı, iki panelli, karanlık temalı HTML üretir
- Düğüm-zafiyet eşleme tablosu ile tıklama etkileşimlerini yönetir

### `ReportWriter`
Tespit edilen zafiyetleri yapılandırılmış JSON formatında diske yazar.

## Güvenlik ve Sorumluluk Reddi

**Bu araç yalnızca yetkili güvenlik testleri, sızma testleri ve savunma amaçlı mavi takım çalışmaları için geliştirilmiştir.**

- Tulpar'ı yalnızca sahibi olduğunuz veya yazılı test izni aldığınız AWS hesaplarında kullanın
- Aracın kötüye kullanımından doğacak hukuki sonuçlardan kullanıcı sorumludur
- Araç salt okunur API çağrıları yapar; hiçbir kaynak oluşturmaz, değiştirmez veya silmez
- Tespit edilen zafiyetleri derhal ilgili AWS hesap yöneticilerine bildirin

## AWS Politikaları ile Uyum

Tulpar'ın yaptığı API çağrıları:
- `sts:GetCallerIdentity` — Kimlik doğrulama (salt okunur)
- `iam:SimulatePrincipalPolicy` — Yetki simülasyonu (salt okunur)
- `ec2:DescribeRegions` — Bölge listeleme (salt okunur)
- `ec2:DescribeInstances` — EC2 envanteri (salt okunur)
- `lambda:ListFunctions` — Lambda envanteri (salt okunur)

Tüm çağrılar salt okunur nitelikte olup AWS ortamında herhangi bir değişiklik yapmaz.

## Lisans

MIT License. Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## Katkıda Bulunma

1. Bu depoyu fork'layın
2. Özellik dalınızı oluşturun (`git checkout -b yeni-vektor`)
3. Değişikliklerinizi commit'leyin (`git commit -am 'Yeni yetki yükseltme vektörü eklendi'`)
4. Dalınıza push'layın (`git push origin yeni-vektor`)
5. Bir Pull Request oluşturun

## İletişim

Hata raporları ve özellik istekleri için GitHub Issues sayfasını kullanın.
