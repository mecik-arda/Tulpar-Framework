import os
import json
import csv
import logging
from datetime import datetime
from tulpar.sabitler import SURUM

logger = logging.getLogger("Tulpar")

def csv_raporu_yaz(bulgular, cikti_dosyasi):
    alan_isimleri = [
        "zafiyet_adi",
        "kritiklik_seviyesi",
        "risk_skoru",
        "aciklama",
        "cloudtrail_izi",
        "sikiastirma_onerisi",
        "somuru_komutu",
        "mavi_takim_onerisi",
        "scp_kisitlamasi_var",
    ]
    try:
        with open(cikti_dosyasi, "w", newline="", encoding="utf-8") as dosya:
            yazici = csv.DictWriter(dosya, fieldnames=alan_isimleri, extrasaction="ignore")
            yazici.writeheader()
            for bulgu in bulgular:
                yazici.writerow({k: bulgu.get(k, "") for k in alan_isimleri})
        logger.info("CSV raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("CSV raporu olusturulamadi: %s", hata)
        return False

def markdown_raporu_yaz(bulgular, cikti_dosyasi, scp_durumu=None):
    try:
        satirlar = []
        satirlar.append("# Tulpar AWS IAM Yetki Yukseltme Raporu")
        satirlar.append("")
        satirlar.append("**Rapor Tarihi:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        satirlar.append("")
        satirlar.append("**Tespit Edilen Zafiyet Sayisi:** " + str(len(bulgular)))
        satirlar.append("")
        if scp_durumu is not None:
            satirlar.append(
                "**SCP Kisitlamasi:** "
                + (
                    "Var (SCP uygulanmis, yetkiler kisitlanmis olabilir)"
                    if scp_durumu
                    else "Yok (SCP uygulanmamis, IAM politikalari tam gecerli)"
                )
            )
            satirlar.append("")
        satirlar.append("---")
        satirlar.append("")
        for idx, bulgu in enumerate(bulgular, 1):
            satirlar.append("## " + str(idx) + ". " + bulgu.get("zafiyet_adi", "Bilinmeyen"))
            satirlar.append("")
            kritiklik = bulgu.get("kritiklik_seviyesi", "Belirsiz")
            risk = bulgu.get("risk_skoru", "-")
            satirlar.append("| Oznitelik | Deger |")
            satirlar.append("|-----------|-------|")
            satirlar.append("| Kritiklik Seviyesi | **" + kritiklik + "** |")
            satirlar.append("| Risk Skoru | **" + str(risk) + " / 10** |")
            satirlar.append("| CloudTrail Izi | `" + bulgu.get("cloudtrail_izi", "-") + "` |")
            if bulgu.get("scp_kisitlamasi_var") is not None:
                satirlar.append(
                    "| SCP Kisitlamasi | " + ("Evet" if bulgu.get("scp_kisitlamasi_var") else "Hayir") + " |"
                )
            satirlar.append("")
            satirlar.append("### Aciklama")
            satirlar.append("")
            satirlar.append(bulgu.get("aciklama", "-"))
            satirlar.append("")
            if bulgu.get("somuru_komutu"):
                satirlar.append("### Somuru Komutu")
                satirlar.append("")
                satirlar.append("```bash")
                satirlar.append(bulgu.get("somuru_komutu", ""))
                satirlar.append("```")
                satirlar.append("")
            satirlar.append("### Sikilastirma Onerisi")
            satirlar.append("")
            satirlar.append(bulgu.get("sikiastirma_onerisi", "-"))
            satirlar.append("")
            if bulgu.get("mavi_takim_onerisi"):
                satirlar.append("### Mavi Takim Savunma Onerisi")
                satirlar.append("")
                satirlar.append(bulgu.get("mavi_takim_onerisi", "-"))
                satirlar.append("")
            satirlar.append("---")
            satirlar.append("")
        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            dosya.write("\n".join(satirlar))
        logger.info("Markdown raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("Markdown raporu olusturulamadi: %s", hata)
        return False

def sarif_raporu_yaz(bulgular, cikti_dosyasi, arac_adi="Tulpar"):
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        sonuclar = []
        for idx, bulgu in enumerate(bulgular):
            risk = bulgu.get("risk_skoru", 5.0)
            if isinstance(risk, (int, float)):
                if risk >= 9.0:
                    seviye = "error"
                elif risk >= 7.0:
                    seviye = "warning"
                else:
                    seviye = "note"
            else:
                seviye = "warning"
            konum = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": "tulpar_rapor.json"
                    },
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
            sonuc = {
                "ruleId": bulgu.get("zafiyet_adi", "Bilinmeyen").replace(" ", "_")[:80],
                "ruleIndex": idx,
                "level": seviye,
                "message": {
                    "text": "{} [Risk: {}/10] - {}".format(
                        bulgu.get("zafiyet_adi", "Bilinmeyen"), bulgu.get("risk_skoru", "-"), bulgu.get("aciklama", "")
                    )
                },
                "locations": [konum],
                "properties": {
                    "kritiklik_seviyesi": bulgu.get("kritiklik_seviyesi", "Belirsiz"),
                    "risk_skoru": str(bulgu.get("risk_skoru", "-")),
                    "cloudtrail_izi": bulgu.get("cloudtrail_izi", ""),
                    "sikiastirma_onerisi": bulgu.get("sikiastirma_onerisi", ""),
                    "somuru_komutu": bulgu.get("somuru_komutu", ""),
                    "mavi_takim_onerisi": bulgu.get("mavi_takim_onerisi", ""),
                },
            }
            sonuclar.append(sonuc)
        arac = {
            "driver": {
                "name": arac_adi,
                "organization": "Tulpar Framework",
                "semanticVersion": SURUM,
                "rules": [
                    {
                        "id": b.get("zafiyet_adi", "Bilinmeyen").replace(" ", "_")[:80],
                        "name": b.get("zafiyet_adi", "Bilinmeyen"),
                        "shortDescription": {"text": b.get("aciklama", "")[:500]},
                        "helpUri": "https://github.com/mecik-arda/Tulpar-Framework",
                    }
                    for b in bulgular
                ],
            }
        }
        sarif_verisi = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": arac, "results": sonuclar}],
        }
        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            json.dump(sarif_verisi, dosya, ensure_ascii=False, indent=2)
        logger.info("SARIF raporu olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("SARIF raporu olusturulamadi: %s", hata)
        return False

def duzeltme_scripti_uret(bulgular, cikti_dosyasi):
    """Tespit edilen zafiyetler için otomatik Terraform ve AWS CLI düzeltme kodları üretir."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        satirlar = []
        satirlar.append("# Tulpar Otomatik Duzeltme Scripti")
        satirlar.append("")
        satirlar.append("**Uretim Tarihi:** " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        satirlar.append("")
        satirlar.append(
            "> **UYARI:** Bu script otomatik uretilmistir. "
            "Uygulamadan once gozden gecirin ve test ortaminda deneyin."
        )
        satirlar.append("")
        satirlar.append("---")
        satirlar.append("")

        duzeltme_eylemleri = {
            "iam:CreatePolicyVersion": {
                "aws_cli": (
                    "aws iam delete-policy-version --policy-arn HEDEF_POLITIKA_ARN --version-id v2"
                ),
                "terraform": (
                    'resource "aws_iam_policy" "guvenli_politika" {\n'
                    '  name        = "guvenli-politika"\n'
                    '  description = "Siki politika"\n'
                    '  policy      = data.aws_iam_policy_document.guvenli.json\n'
                    '}'
                ),
                "oneri": (
                    "Politika surumu olusturma yetkisini kaldirin "
                    "veya sadece belirli politikalara kisitlayin."
                ),
            },
            "iam:AttachUserPolicy": {
                "aws_cli": (
                    "aws iam detach-user-policy --user-name HEDEF_KULLANICI "
                    "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
                ),
                "terraform": (
                    'resource "aws_iam_user_policy_attachment" "guvenli" {\n'
                    '  user       = aws_iam_user.kullanici.name\n'
                    '  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"\n'
                    '}'
                ),
                "oneri": (
                    "Kullaniciya dogrudan AdministratorAccess gibi yuksek yetkili "
                    "politikalar eklenmesini engelleyin."
                ),
            },
            "iam:PassRole": {
                "aws_cli": (
                    "# IAM Policy Condition ile PassRole kisitlamasi:\n"
                    "aws iam put-role-policy --role-name HEDEF_ROL "
                    "--policy-name passrole-kisitlamasi "
                    "--policy-document '{\"Version\":\"2012-10-17\","
                    "\"Statement\":[{\"Effect\":\"Deny\","
                    "\"Action\":\"iam:PassRole\",\"Resource\":\"*\","
                    "\"Condition\":{\"StringNotEquals\":"
                    "{\"iam:PassedToService\":\"ec2.amazonaws.com\"}}}]}'"
                ),
                "terraform": (
                    'resource "aws_iam_role_policy" "passrole_kisitlamasi" {\n'
                    '  name = "passrole-kisitlamasi"\n'
                    '  role = aws_iam_role.hedef_rol.id\n'
                    '  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n'
                    '    Statement = [{\n'
                    '      Effect = "Deny"\n'
                    '      Action = "iam:PassRole"\n'
                    '      Resource = "*"\n'
                    '    }]\n'
                    '  })\n'
                    '}'
                ),
                "oneri": (
                    "PassRole yetkisini sadece guvenilir servisler "
                    "ve belirli rollerle sinirlandirin."
                ),
            },
            "ssm:SendCommand": {
                "aws_cli": (
                    "# SSM SendCommand yetkisini kaldirin:\n"
                    "aws iam delete-role-policy --role-name HEDEF_ROL "
                    "--policy-name ssm-send-command"
                ),
                "terraform": (
                    'resource "aws_iam_policy" "ssm_kisitlamasi" {\n'
                    '  name = "ssm-kisitlamasi"\n'
                    '  policy = jsonencode({\n'
                    '    Version = "2012-10-17"\n'
                    '    Statement = [{\n'
                    '      Effect = "Deny"\n'
                    '      Action = "ssm:SendCommand"\n'
                    '      Resource = "*"\n'
                    '    }]\n'
                    '  })\n'
                    '}'
                ),
                "oneri": (
                    "SSM SendCommand yetkisini kaldirin veya "
                    "sadece belirli EC2 kaynaklarina kisitlayin."
                ),
            },
        }

        genel_terraform_bloklari = []
        genel_aws_cli_komutlari = []

        for idx, bulgu in enumerate(bulgular, 1):
            zafiyet_adi = bulgu.get("zafiyet_adi", "Bilinmeyen")
            cloudtrail_izi = bulgu.get("cloudtrail_izi", "")
            satirlar.append("## {}. {}".format(idx, zafiyet_adi))
            satirlar.append("")
            satirlar.append("| Oznitelik | Deger |")
            satirlar.append("|-----------|-------|")
            satirlar.append("| Kritiklik | **{}** |".format(bulgu.get("kritiklik_seviyesi", "-")))
            satirlar.append("| Risk Skoru | **{}/10** |".format(bulgu.get("risk_skoru", "-")))
            satirlar.append("")
            satirlar.append("### Sikiastirma Onerisi")
            satirlar.append("")
            satirlar.append(bulgu.get("sikiastirma_onerisi", "Manuel inceleme gerekli."))
            satirlar.append("")

            birincil_iz = cloudtrail_izi.split(",")[0].strip() if cloudtrail_izi else ""
            duzeltme = duzeltme_eylemleri.get(birincil_iz)
            if duzeltme:
                satirlar.append("### AWS CLI Duzeltme Komutu")
                satirlar.append("")
                satirlar.append("```bash")
                satirlar.append(duzeltme["aws_cli"])
                satirlar.append("```")
                satirlar.append("")
                satirlar.append("### Terraform Duzeltme Blogu")
                satirlar.append("")
                satirlar.append("```hcl")
                satirlar.append(duzeltme["terraform"])
                satirlar.append("```")
                satirlar.append("")
                genel_aws_cli_komutlari.append(duzeltme["aws_cli"])
                genel_terraform_bloklari.append(duzeltme["terraform"])
            else:
                satirlar.append("### Genel Duzeltme Yaklasimi")
                satirlar.append("")
                satirlar.append("Bu zafiyet tipi icin en az yetki (least privilege) prensibini uygulayin:")
                satirlar.append("- Ilgili IAM yetkisini kaldirin veya dar kapsamli kaynaklara kisitlayin")
                satirlar.append("- CloudTrail alarmlari kurarak bu API cagrilarini izleyin")
                satirlar.append("- AWS Config kurallari ile uyumlulugu otomatik denetleyin")
                satirlar.append("")
            satirlar.append("---")
            satirlar.append("")

        if genel_aws_cli_komutlari:
            # BUG FIX: Use slice assignment to insert multiple items without messing up index
            toplu_satirlar = [
                "## Toplu AWS CLI Duzeltme Betigi",
                "",
                "```bash",
                "#!/bin/bash",
                "# Tulpar Otomatik Duzeltme Betigi - Tum Zafiyetler",
                ""
            ]
            for idx, komut in enumerate(genel_aws_cli_komutlari):
                toplu_satirlar.append("# Zafiyet " + str(idx + 1))
                toplu_satirlar.append(komut)
                toplu_satirlar.append("")
            toplu_satirlar.append("```")
            toplu_satirlar.append("")
            
            satirlar[3:3] = toplu_satirlar

        if genel_terraform_bloklari:
            satirlar.append("## Toplu Terraform Duzeltme Betigi")
            satirlar.append("")
            satirlar.append("```hcl")
            satirlar.append("# Tulpar Otomatik Terraform Duzeltme Betigi")
            satirlar.append("")
            for idx, blok in enumerate(genel_terraform_bloklari):
                satirlar.append("# Zafiyet " + str(idx + 1))
                satirlar.append(blok)
                satirlar.append("")
            satirlar.append("```")
            satirlar.append("")

        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            dosya.write("\n".join(satirlar))
        logger.info("Duzeltme scripti olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("Duzeltme scripti olusturulamadi: %s", hata)
        return False

def rapor_karsilastir(onceki_dosya, yeni_dosya, karsilastirma_ciktisi):
    try:
        with open(onceki_dosya, "r", encoding="utf-8") as dosya:
            onceki_veri = json.load(dosya)
        with open(yeni_dosya, "r", encoding="utf-8") as dosya:
            yeni_veri = json.load(dosya)
    except FileNotFoundError as hata:
        logger.error("Karsilastirma dosyasi bulunamadi: %s", hata)
        return None
    except json.JSONDecodeError as hata:
        logger.error("Karsilastirma dosyasi gecersiz JSON: %s", hata)
        return None
    onceki_adlar = {b.get("zafiyet_adi", "") for b in onceki_veri.get("bulgular", [])}
    yeni_adlar = {b.get("zafiyet_adi", "") for b in yeni_veri.get("bulgular", [])}
    yeni_eklenenler = yeni_adlar - onceki_adlar
    kapananlar = onceki_adlar - yeni_adlar
    devam_edenler = onceki_adlar & yeni_adlar
    onceki_yeni_bulgu_listesi = [
        b for b in yeni_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in yeni_eklenenler
    ]
    onceki_kapanan_bulgu_listesi = [
        b for b in onceki_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in kapananlar
    ]
    onceki_devam_bulgu_listesi = [b for b in yeni_veri.get("bulgular", []) if b.get("zafiyet_adi", "") in devam_edenler]
    fark_raporu = {
        "arac_adi": "Tulpar Diff Raporu",
        "rapor_tarihi": datetime.now().isoformat(),
        "onceki_dosya": onceki_dosya,
        "yeni_dosya": yeni_dosya,
        "ozet": {
            "onceki_zafiyet_sayisi": onceki_veri.get("zafiyet_sayisi", 0),
            "yeni_zafiyet_sayisi": yeni_veri.get("zafiyet_sayisi", 0),
            "yeni_eklenen_zafiyet_sayisi": len(yeni_eklenenler),
            "kapanan_zafiyet_sayisi": len(kapananlar),
            "devam_eden_zafiyet_sayisi": len(devam_edenler),
        },
        "yeni_eklenen_zafiyetler": onceki_yeni_bulgu_listesi,
        "kapanan_zafiyetler": onceki_kapanan_bulgu_listesi,
        "devam_eden_zafiyetler": onceki_devam_bulgu_listesi,
    }
    try:
        os.makedirs(os.path.dirname(os.path.abspath(karsilastirma_ciktisi)) or ".", exist_ok=True)
        with open(karsilastirma_ciktisi, "w", encoding="utf-8") as dosya:
            json.dump(fark_raporu, dosya, ensure_ascii=False, indent=4)
        logger.info(
            "Karsilastirma raporu olusturuldu: %s (Yeni: %d, Kapanan: %d, Devam: %d)",
            karsilastirma_ciktisi,
            len(yeni_eklenenler),
            len(kapananlar),
            len(devam_edenler),
        )
        return fark_raporu
    except Exception as hata:
        logger.error("Karsilastirma raporu yazilamadi: %s", hata)
        return None
