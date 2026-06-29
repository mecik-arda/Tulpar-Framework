import os
import json
import logging
from datetime import datetime
from tulpar.sabitler import SURUM

logger = logging.getLogger("Tulpar")

def bloodhound_disa_aktar(saldiri_yollari, bulunan_zafiyetler, cikti_dosyasi, kimlik_bilgileri=None):
    """Saldiri yollarini BloodHound/Neo4j uyumlu JSON formatinda disa aktarir."""
    try:
        os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
        dugumler = []
        kenarlar = []
        eklenen_dugumler = set()
        dugum_id_sayaci = 1
        dugum_sozlugu = {}

        for kaynak, hedef_ara, son_hedef in saldiri_yollari:
            for isim in [kaynak, hedef_ara, son_hedef]:
                if isim not in eklenen_dugumler:
                    dugum_tipi = "AZPrincipal"
                    if isim == "AdministratorAccess" or isim == "YoneticiRolu_Ustlenme":
                        dugum_tipi = "AZHighValue"
                    elif isim == "Baslangic":
                        dugum_tipi = "AZUser"
                    elif ":" in isim:
                        dugum_tipi = "AZPermissionSet"

                    dugum_sozlugu[isim] = dugum_id_sayaci
                    dugum = {
                        "id": dugum_id_sayaci,
                        "label": isim,
                        "type": dugum_tipi,
                        "properties": {
                            "name": isim,
                            "description": "Tulpar taramasi ile tespit edildi",
                            "highvalue": dugum_tipi == "AZHighValue",
                        },
                    }
                    dugumler.append(dugum)
                    eklenen_dugumler.add(isim)
                    dugum_id_sayaci += 1

            kenarlar.append(
                {
                    "from": dugum_sozlugu[kaynak],
                    "to": dugum_sozlugu[hedef_ara],
                    "type": "AZPrivilegeEscalation",
                    "properties": {"description": "Olası yetki yukseltme yolu", "risk": "Yuksek"},
                }
            )
            kenarlar.append(
                {
                    "from": dugum_sozlugu[hedef_ara],
                    "to": dugum_sozlugu[son_hedef],
                    "type": "AZAdminAccess",
                    "properties": {"description": "Yonetici erisimi elde etme yolu", "risk": "Kritik"},
                }
            )

        zafiyet_detaylari = {}
        for zafiyet in bulunan_zafiyetler:
            zafiyet_adi = zafiyet.get("zafiyet_adi", "")
            zafiyet_detaylari[zafiyet_adi] = {
                "risk_skoru": zafiyet.get("risk_skoru", "-"),
                "kritiklik": zafiyet.get("kritiklik_seviyesi", "Belirsiz"),
                "aciklama": zafiyet.get("aciklama", ""),
                "cloudtrail_izi": zafiyet.get("cloudtrail_izi", ""),
                "somuru_komutu": zafiyet.get("somuru_komutu", ""),
                "sikiastirma_onerisi": zafiyet.get("sikiastirma_onerisi", ""),
            }

        kanit_bilgisi = {}
        if kimlik_bilgileri:
            kanit_bilgisi = {
                "scan_arn": kimlik_bilgileri.get("arn", ""),
                "account_id": kimlik_bilgileri.get("hesap_id", ""),
                "user_id": kimlik_bilgileri.get("kullanici_id", ""),
            }

        bloodhound_verisi = {
            "format": "BloodHound 4.x / Neo4j Compatible",
            "source": f"Tulpar AWS IAM Scanner v{SURUM}",
            "export_date": datetime.now().isoformat(),
            "metadata": {
                "total_nodes": len(dugumler),
                "total_edges": len(kenarlar),
                "privilege_escalation_paths": len(saldiri_yollari),
                "scan_evidence": kanit_bilgisi,
            },
            "nodes": dugumler,
            "edges": kenarlar,
            "vulnerability_details": zafiyet_detaylari,
        }

        with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
            json.dump(bloodhound_verisi, dosya, ensure_ascii=False, indent=2)
        logger.info("BloodHound disa aktarimi olusturuldu: %s", cikti_dosyasi)
        return True
    except Exception as hata:
        logger.error("BloodHound disa aktarimi basarisiz: %s", hata)
        return False

def tui_dashboard_goster(argumanlar):
    """Rich kutuphanesi ile modern terminal arayuzu saglar."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
        from rich.table import Table
        from rich.text import Text
        from rich import box
        import time
    except ImportError:
        logger.warning("Rich kutuphanesi kurulu degil. 'pip install rich' ile kurabilirsiniz.")
        logger.info("TUI modu devre disi, standart modda devam ediliyor...")
        return

    konsol = Console()
    konsol.clear()

    baslik_paneli = Panel(
        Text("Tulpar AWS IAM Yetki Yukseltme Tarayicisi v" + SURUM, style="bold cyan"),
        subtitle="[yellow]Ofansif Guvenlik Araci[/yellow]",
        border_style="cyan",
    )
    konsol.print(baslik_paneli)

    konsol.print("\n[bold]TUI modu aktif. DEMO (Kuru calistirma) baslatiliyor...[/bold]\n")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=konsol,
    ) as ilerleme:

        kimlik_gorevi = ilerleme.add_task("[cyan]Kimlik dogrulama...", total=100)
        ilerleme.update(kimlik_gorevi, advance=30)

        scp_gorevi = ilerleme.add_task("[yellow]SCP kontrolu...", total=100)
        ilerleme.update(scp_gorevi, advance=50)

        bolge_gorevi = ilerleme.add_task("[green]Coklu bolge kaynak taramasi...", total=100)

        for i in range(5):
            time.sleep(0.1)
            ilerleme.update(bolge_gorevi, advance=20)

        ilerleme.update(kimlik_gorevi, advance=70)
        ilerleme.update(scp_gorevi, advance=50)

        simulasyon_gorevi = ilerleme.add_task("[magenta]IAM hak simulasyonu...", total=100)
        for i in range(10):
            time.sleep(0.05)
            ilerleme.update(simulasyon_gorevi, advance=10)

        vektor_gorevi = ilerleme.add_task("[blue]Vektor taramasi...", total=65)
        for i in range(65):
            time.sleep(0.02)
            ilerleme.update(vektor_gorevi, advance=1)

        rapor_gorevi = ilerleme.add_task("[green]Rapor olusturma...", total=100)
        for i in range(5):
            time.sleep(0.1)
            ilerleme.update(rapor_gorevi, advance=20)

    konsol.print("")
    ozet_tablosu = Table(title="Tulpar Tarama Ozeti", box=box.ROUNDED, border_style="cyan")
    ozet_tablosu.add_column("Oznitelik", style="cyan", no_wrap=True)
    ozet_tablosu.add_column("Deger", style="green")
    ozet_tablosu.add_row("Arac Surumu", SURUM)
    ozet_tablosu.add_row("Bulut Saglayici", getattr(argumanlar, "bulut", "Bilinmiyor").upper())
    ozet_tablosu.add_row("Hizli Mod", "Evet" if getattr(argumanlar, "hizli", False) else "Hayir")
    ozet_tablosu.add_row("CloudTrail Analizi", "Evet" if getattr(argumanlar, "cloudtrail_analiz", False) else "Hayir")
    ozet_tablosu.add_row("Access Analyzer", "Evet" if getattr(argumanlar, "access_analyzer", False) else "Hayir")
    ozet_tablosu.add_row("Otomatik Duzeltme", "Evet" if getattr(argumanlar, "duzelt", False) else "Hayir")
    konsol.print(ozet_tablosu)

    konsol.print("\n[bold green]TUI taramasi tamamlandi![/bold green]")
    konsol.print("[dim]Detayli raporlar raporlar/ dizininde olusturuldu.[/dim]")
    konsol.print("[yellow]Not: TUI sadece bir demo (dry run) modudur. Gercek tarama yapmaz. Gercek tarama icin --tui bayragi olmadan calistirin.[/yellow]")


def web_dashboard_baslat(argumanlar):
    """Streamlit web dashboard baslatir (lazy import)."""
    from tulpar.web_dashboard import web_dashboard_baslat as _web_baslat
    return _web_baslat(argumanlar)


def ai_yonetici_ozeti_uret(bulunan_zafiyetler, provider="openai", api_key=None, model=None):
    """AI yonetici ozeti uretir (lazy import)."""
    from tulpar.ai_analiz import ai_yonetici_ozeti_uret as _ai_uret
    return _ai_uret(bulunan_zafiyetler, provider=provider, api_key=api_key, model=model)
