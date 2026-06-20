"""Tulpar AI Analiz Motoru - LLM destekli yonetici ozeti ureticisi.

Desteklenen saglayicilar:
- OpenAI (GPT-4, GPT-4o, GPT-3.5)
- Claude (Anthropic API)
- AWS Bedrock (Claude, Llama, Titan)

Kullanim:
    python -m tulpar --ai-analiz --ai-provider openai --ai-api-key API_ANAHTARI
"""

import json
import logging
import os

logger = logging.getLogger("TulparAI")


def ai_yonetici_ozeti_uret(bulunan_zafiyetler, provider="openai", api_key=None, model=None):
    """Bulunan zafiyetlere dayali yonetici ozeti uretir.

    Args:
        bulunan_zafiyetler: Tarama sonucu bulunan zafiyet listesi
        provider: AI saglayici - 'openai', 'claude', 'bedrock'
        api_key: API anahtari (None ise ortam degiskeninden alinir)
        model: Kullanilacak model (None ise varsayilan)

    Returns:
        dict: {'baslik': ..., 'ozet': ..., 'risk_analizi': ..., 'aksiyon_plani': ...}
    """
    if not bulunan_zafiyetler:
        return {
            "baslik": "Tulpar Yönetici Özeti",
            "ozet": "Taramada herhangi bir zafiyet tespit edilmedi. Sistem güvenli görünüyor.",
            "risk_analizi": "Risk seviyesi: Düşük",
            "aksiyon_plani": "Mevcut güvenlik politikalarını sürdürmeye devam edin.",
        }

    zafiyet_ozeti = _zafiyet_ozeti_hazirla(bulunan_zafiyetler)
    prompt = _ai_prompt_olustur(zafiyet_ozeti)

    try:
        if provider == "openai":
            sonuc = _openai_analiz(prompt, api_key, model)
        elif provider == "claude":
            sonuc = _claude_analiz(prompt, api_key, model)
        elif provider == "bedrock":
            sonuc = _bedrock_analiz(prompt, api_key, model)
        else:
            sonuc = _yerel_ozet_uret(zafiyet_ozeti)

        logger.info("AI yonetici ozeti basariyla uretildi (%s)", provider)
        return sonuc
    except Exception as hata:
        logger.warning("AI analizi basarisiz (%s): %s. Yerel ozet kullaniliyor.", provider, hata)
        return _yerel_ozet_uret(zafiyet_ozeti)


def _zafiyet_ozeti_hazirla(bulunan_zafiyetler):
    """Zafiyet listesini AI promptu icin ozetler."""
    kritik_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Kritik")
    yuksek_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Yuksek")
    orta_sayisi = sum(1 for b in bulunan_zafiyetler if b.get("kritiklik_seviyesi") == "Orta")

    kritik_zafiyetler = [
        {
            "adi": b.get("zafiyet_adi", ""),
            "risk": b.get("risk_skoru", "-"),
            "aciklama": b.get("aciklama", "")[:300],
            "cloudtrail": b.get("cloudtrail_izi", ""),
            "etki": _etki_hesapla(b),
        }
        for b in bulunan_zafiyetler
        if b.get("kritiklik_seviyesi") in ("Kritik", "Yuksek")
    ]

    return {
        "toplam": len(bulunan_zafiyetler),
        "kritik": kritik_sayisi,
        "yuksek": yuksek_sayisi,
        "orta": orta_sayisi,
        "kritik_zafiyetler": kritik_zafiyetler[:10],
        "hesap_kodu": bulunan_zafiyetler[0].get("scp_kisitlamasi_var", None) if bulunan_zafiyetler else None,
    }


def _etki_hesapla(zafiyet):
    """Zafiyetin potansiyel etkisini hesaplar."""
    risk = zafiyet.get("risk_skoru", 5)
    if risk >= 9:
        return (
            "Hesap üzerinde tam kontrol sağlanabilir. "
            "Veri sızıntısı, kaynak manipülasyonu ve mali kayıp riski çok yüksektir."
        )
    elif risk >= 7:
        return (
            "Yüksek yetkili erişim elde edilebilir. "
            "Hassas verilere erişim ve kaynak değişikliği riski vardır."
        )
    elif risk >= 5:
        return (
            "Sınırlı kaynaklara yetkisiz erişim sağlanabilir. "
            "Keşif ve bilgi toplama riski mevcuttur."
        )
    return "Düşük seviyeli bilgi ifşası veya keşif riski bulunmaktadır."


def _ai_prompt_olustur(zafiyet_ozeti):
    """AI analizi icin prompt olusturur."""
    from tulpar.sabitler import SURUM

    prompt = f"""Sen bir kurumsal siber guvenlik uzmanisin. Asagida Tulpar aracinin (v{SURUM}) bir AWS/GCP/Azure taramasi sonucu buldugu IAM yetki yukseltme zafiyetlerinin ozeti bulunmaktadir.

Tarama Sonucu:
- Toplam Zafiyet: {zafiyet_ozeti['toplam']}
- Kritik: {zafiyet_ozeti['kritik']}
- Yuksek: {zafiyet_ozeti['yuksek']}
- Orta: {zafiyet_ozeti['orta']}

Kritik/Yuksek Zafiyet Detaylari:
{json.dumps(zafiyet_ozeti['kritik_zafiyetler'], ensure_ascii=False, indent=2)}

Lutfen asagidaki formatta bir YONETICI OZETI (Executive Summary) hazirla. Cevabini yalnizca JSON formatinda ver, baska bir sey yazma:

{{
  "baslik": "Tulpar Guvenlik Taramasi Yonetici Ozeti - [TARIH]",
  "ozet": "Yonetim kuruluna sunulmak uzere 2-3 paragraflik ozet. Bulgularin is etkisini, olasi maliyetini ve itibar riskini vurgula.",
  "risk_analizi": "Risklerin detayli analizi. En kritik bulgulari ve bunlarin is sureclerine etkisini acikla.",
  "aksiyon_plani": "Onceliklendirilmis 3-5 maddelik aksiyon plani. Her madde icin yaklasik zaman ve kaynak tahmini belirt.",
  "genel_risk_seviyesi": "Dusuk/Orta/Yuksek/Kritik"
}}

Turkce yaz. Profesyonel ama anlasilir bir dil kullan. CISO ve CTO seviyesinde yoneticiler icin uygun olsun."""
    return prompt


def _openai_analiz(prompt, api_key=None, model=None):
    """OpenAI API ile analiz yapar."""
    anahtar = api_key or os.environ.get("OPENAI_API_KEY")
    if not anahtar:
        raise ValueError(
            "OpenAI API anahtari gerekli. --ai-api-key ile belirtin veya OPENAI_API_KEY ortam degiskeni tanimlayin."
        )

    import urllib.request

    secili_model = model or "gpt-4o"
    govde = json.dumps(
        {
            "model": secili_model,
            "messages": [
                {"role": "system", "content": "Sen bir siber guvenlik uzmanisin. Yalnizca JSON formatinda yanit ver."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.3,
            "max_tokens": 2000,
        }
    ).encode("utf-8")

    istek = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=govde,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {anahtar}",
        },
    )

    with urllib.request.urlopen(istek, timeout=60) as yanit:  # nosec B310
        veri = json.load(yanit)
        icerik = veri["choices"][0]["message"]["content"]
        return json.loads(_json_ayikla(icerik))


def _claude_analiz(prompt, api_key=None, model=None):
    """Anthropic Claude API ile analiz yapar."""
    anahtar = api_key or os.environ.get("ANTHROPIC_API_KEY")
    if not anahtar:
        raise ValueError(
            "Anthropic API anahtari gerekli. --ai-api-key ile belirtin veya ANTHROPIC_API_KEY ortam degiskeni tanimlayin."
        )

    import urllib.request

    secili_model = model or "claude-sonnet-4-6"
    govde = json.dumps(
        {
            "model": secili_model,
            "max_tokens": 2000,
            "messages": [
                {"role": "user", "content": prompt},
            ],
        }
    ).encode("utf-8")

    istek = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=govde,
        headers={
            "Content-Type": "application/json",
            "x-api-key": anahtar,
            "anthropic-version": "2023-06-01",
        },
    )

    with urllib.request.urlopen(istek, timeout=60) as yanit:  # nosec B310
        veri = json.load(yanit)
        icerik = veri["content"][0]["text"]
        return json.loads(_json_ayikla(icerik))


def _bedrock_analiz(prompt, api_key=None, model=None):
    """AWS Bedrock API ile analiz yapar."""
    try:
        import boto3

        secili_model = model or "anthropic.claude-3-sonnet-20240229-v1:0"
        govde = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "messages": [{"role": "user", "content": prompt}],
        }

        bedrock = boto3.client("bedrock-runtime", region_name=os.environ.get("AWS_REGION", "us-east-1"))
        yanit = bedrock.invoke_model(
            modelId=secili_model,
            body=json.dumps(govde),
        )
        icerik = json.loads(yanit["body"].read())
        metin = icerik["content"][0]["text"]
        return json.loads(_json_ayikla(metin))
    except ImportError:
        raise ValueError("AWS Bedrock analizi icin boto3 gerekli: pip install boto3")
    except Exception as hata:
        raise ValueError(f"Bedrock analizi basarisiz: {hata}")


def _json_ayikla(metin):
    """AI yanitindan JSON blogunu ayiklar."""
    metin = metin.strip()
    if metin.startswith("```json"):
        metin = metin.split("```json", 1)[1]
        if "```" in metin:
            metin = metin.split("```", 1)[0]
    elif metin.startswith("```"):
        metin = metin.split("```", 1)[1]
        if "```" in metin:
            metin = metin.split("```", 1)[0]
    return metin.strip()


def _yerel_ozet_uret(zafiyet_ozeti):
    """AI kullanilamadiginda yerel (offline) yonetici ozeti uretir."""
    from datetime import datetime

    kritik = zafiyet_ozeti["kritik"]
    yuksek = zafiyet_ozeti["yuksek"]
    toplam = zafiyet_ozeti["toplam"]

    if kritik > 0:
        genel_risk = "Kritik"
        ozet = (
            f"Yapılan güvenlik taramasında {toplam} adet yetki yükseltme zafiyeti tespit edilmiştir. "
            f"Bunlardan {kritik} tanesi KRİTİK seviyede olup, hesap üzerinde tam kontrol sağlanmasına "
            f"imkan tanıyabilecek niteliktedir. Bu durum, yetkisiz erişim, veri sızıntısı, kaynak "
            f"manipülasyonu ve buna bağlı mali kayıplar riskini doğurmaktadır. "
            f"Regülasyon uyumluluğu (GDPR, KVKK, PCI-DSS) açısından da risk teşkil etmektedir. "
            f"En kısa sürede aksiyon alınması önerilmektedir."
        )
        aksiyon = [
            "ACİL: Kritik zafiyetlerin 24 saat içinde kapatılması — Tahmini süre: 2-4 saat",
            "IAM politikalarının 'least privilege' prensibine göre gözden geçirilmesi — Tahmini süre: 1 hafta",
            "CloudTrail alarmları ve AWS Config kurallarının aktif edilmesi — Tahmini süre: 2 gün",
            "MFA zorunluluğunun tüm IAM kullanıcılarına uygulanması — Tahmini süre: 1 gün",
            "Güvenlik ekibine Privilege Escalation farkındalık eğitimi verilmesi — Tahmini süre: 1 hafta",
        ]
    elif yuksek > 0:
        genel_risk = "Yüksek"
        ozet = (
            f"Yapılan güvenlik taramasında {toplam} adet yetki yükseltme zafiyeti tespit edilmiştir. "
            f"Bunlardan {yuksek} tanesi YÜKSEK seviyede olup, hassas kaynaklara yetkisiz erişim riski "
            f"barındırmaktadır. Kritik seviyede bir bulgu olmamakla birlikte, mevcut yüksek riskli "
            f"zafiyetler zincirleme saldırılarla kritik seviyeye ulaşabilir."
        )
        aksiyon = [
            "Yüksek riskli zafiyetlerin 1 hafta içinde kapatılması — Tahmini süre: 4-8 saat",
            "IAM rollerinin düzenli denetim takviminin oluşturulması — Tahmini süre: 1 hafta",
            "Güvenlik izleme araçlarının (SIEM) entegrasyonu — Tahmini süre: 2 hafta",
            "Otomatik düzeltme (auto-remediation) playbook'larının hazırlanması",
        ]
    else:
        genel_risk = "Düşük"
        ozet = (
            f"Yapılan güvenlik taramasında {toplam} adet düşük/orta seviyeli bulgu tespit edilmiştir. "
            f"Kritik veya yüksek seviyede bir zafiyet bulunmamaktadır. Mevcut güvenlik duruşu "
            f"kabul edilebilir seviyededir. Yine de sürekli izleme ve düzenli tarama önerilir."
        )
        aksiyon = [
            "Aylık güvenlik taramalarının takvime bağlanması",
            "Güvenlik politikalarının belgelendirilmesi ve güncel tutulması",
            "Ekibin siber güvenlik eğitimlerinin sürdürülmesi",
        ]

    return {
        "baslik": f"Tulpar Güvenlik Taraması Yönetici Özeti - {datetime.now().strftime('%d.%m.%Y')}",
        "ozet": ozet,
        "risk_analizi": _risk_detay_analizi_uret(zafiyet_ozeti),
        "aksiyon_plani": "\n".join(f"{i+1}. {madde}" for i, madde in enumerate(aksiyon)),
        "genel_risk_seviyesi": genel_risk,
    }


def _risk_detay_analizi_uret(zafiyet_ozeti):
    """Detayli risk analizi metni uretir."""
    satirlar = []
    satirlar.append("## Risk Analizi Detayları\n")
    for z in zafiyet_ozeti.get("kritik_zafiyetler", []):
        satirlar.append(f"### {z['adi']} (Risk: {z['risk']}/10)")
        satirlar.append(f"Potansiyel Etki: {z['etki']}")
        satirlar.append(f"CloudTrail İzi: {z['cloudtrail']}")
        satirlar.append("")
    return "\n".join(satirlar)
