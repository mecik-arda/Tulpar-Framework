"""Tulpar Web Dashboard - Streamlit tabanli interaktif guvenlik paneli.

Kullanim:
    streamlit run tulpar/web_dashboard.py -- --args
    python -m tulpar --web
"""

import logging

logger = logging.getLogger("TulparWeb")


def web_dashboard_baslat(argumanlar):
    """Streamlit web dashboard'unu baslatir."""
    try:
        import streamlit as st
    except ImportError:
        logger.error("Streamlit kutuphanesi kurulu degil. Kurmak icin: pip install streamlit")
        print("\nStreamlit kutuphanesi kurulu degil.")
        print("Kurmak icin: pip install streamlit")
        print("Sonra tekrar: python -m tulpar --web")
        return

    st.set_page_config(
        page_title="Tulpar - Güvenlik Paneli",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(
        """
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(135deg, #38bdf8 0%, #8b5cf6 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2rem;
        font-weight: 800;
        color: #f8fafc;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 4px;
    }
    .kritik-badge { background: #7f1d1d; color: #fca5a5; padding: 4px 12px; border-radius: 12px; font-weight: 700; font-size: 0.8rem; }
    .yuksek-badge { background: #78350f; color: #fcd34d; padding: 4px 12px; border-radius: 12px; font-weight: 700; font-size: 0.8rem; }
    .bilgi-badge { background: #1e3a5f; color: #93c5fd; padding: 4px 12px; border-radius: 12px; font-weight: 700; font-size: 0.8rem; }
    </style>
    """,
        unsafe_allow_html=True,
    )

    st.markdown(
        '<h1 class="main-header">🛡️ Tulpar Güvenlik Paneli</h1>',
        unsafe_allow_html=True,
    )
    st.caption(
        "AWS IAM Yetki Yükseltme Tarayıcısı — v{}".format(__import__("tulpar.sabitler", fromlist=["SURUM"]).SURUM)
    )

    st.sidebar.markdown("## ⚙️ Tarama Ayarları")

    aws_access_key = st.sidebar.text_input("AWS Access Key", type="password", help="İsteğe bağlı. Boş bırakılırsa sistemdeki (AWS CLI/Env) anahtarlar kullanılır. Güvenlik için asla kaydedilmez.")
    aws_secret_key = st.sidebar.text_input("AWS Secret Key", type="password", help="İsteğe bağlı. Boş bırakılırsa sistemdeki (AWS CLI/Env) anahtarlar kullanılır. Güvenlik için asla kaydedilmez.")

    bulut = st.sidebar.selectbox("Bulut Sağlayıcı", ["aws", "gcp", "azure"], index=0)
    hizli = st.sidebar.checkbox("Hızlı Mod (15 vektör)", value=False)
    cloudtrail = st.sidebar.checkbox("CloudTrail Analizi", value=True)
    access_analyzer = st.sidebar.checkbox("Access Analyzer", value=False)
    duzelt = st.sidebar.checkbox("Düzeltme Scripti Üret", value=False)
    thread_sayisi = st.sidebar.slider("Thread Sayısı", 1, 20, 5)

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📊 Tarama Profili")
    st.sidebar.info(
        f"""
        **Bulut:** {bulut.upper()}
        **Mod:** {'Hızlı' if hizli else 'Tam'}
        **CloudTrail:** {'Aktif' if cloudtrail else 'Pasif'}
        """
    )

    if st.sidebar.button("🚀 Taramayı Başlat", type="primary", use_container_width=True):
        with st.spinner("Tulpar taraması başlatılıyor... Lütfen bekleyin."):
            from tulpar.tarayici import GekSizmaScanner
            from tulpar.analiz import ExploitationMappingEngine
            from tulpar.yardimcilar import loglama_yapilandir
            from tulpar.dogrulayici import vektorleri_yukle
            
            progress_bar = st.progress(0, text="Kimlik doğrulanıyor...")
            ak = aws_access_key.strip() if aws_access_key.strip() else None
            sk = aws_secret_key.strip() if aws_secret_key.strip() else None
            tarayici = GekSizmaScanner(thread_sayisi=thread_sayisi, erisim_anahtari=ak, gizli_anahtar=sk)

            progress_bar.progress(15, text="Vektörler yükleniyor...")
            analiz_motoru = ExploitationMappingEngine(tarayici)

            if bulut != "aws":
                vektor_verisi = vektorleri_yukle(bulut=bulut)
                analiz_motoru.vektor_verisi = vektor_verisi
                analiz_motoru.vektorler = vektor_verisi.get("vektorler", [])

            if hizli:
                kritik_vektorler = sorted(analiz_motoru.vektorler, key=lambda v: v.get("risk_skoru", 0), reverse=True)[
                    :15
                ]
                analiz_motoru.vektorler = kritik_vektorler

            progress_bar.progress(30, text="Tarama yapılıyor...")
            analiz_motoru.analiz_baslat(cloudtrail_analizi=cloudtrail, access_analyzer=access_analyzer)

            progress_bar.progress(80, text="Rapor hazırlanıyor...")
            bulunan = analiz_motoru.bulunan_zafiyetler
            saldiri_yollari = analiz_motoru.saldiri_yollari

            progress_bar.progress(100, text="Tamamlandı!")
            st.success(f"✅ Tarama tamamlandı! {len(bulunan)} zafiyet tespit edildi.")

            kritik_sayisi = sum(1 for b in bulunan if b.get("kritiklik_seviyesi") == "Kritik")
            yuksek_sayisi = sum(1 for b in bulunan if b.get("kritiklik_seviyesi") == "Yuksek")
            orta_sayisi = sum(1 for b in bulunan if b.get("kritiklik_seviyesi") == "Orta")
            dusuk_sayisi = sum(1 for b in bulunan if b.get("kritiklik_seviyesi") == "Dusuk")

            col1, col2, col3, col4, col5 = st.columns(5)
            with col1:
                st.metric("Toplam Zafiyet", len(bulunan))
            with col2:
                st.metric("🔴 Kritik", kritik_sayisi, delta=f"{kritik_sayisi}" if kritik_sayisi > 0 else "0")
            with col3:
                st.metric("🟠 Yüksek", yuksek_sayisi)
            with col4:
                st.metric("🟡 Orta", orta_sayisi)
            with col5:
                st.metric("🟢 Düşük", dusuk_sayisi)

            if bulunan:
                st.markdown("---")
                st.markdown("### 📋 Tespit Edilen Zafiyetler")

                for idx, zafiyet in enumerate(bulunan):
                    kritiklik = zafiyet.get("kritiklik_seviyesi", "Belirsiz")
                    risk = zafiyet.get("risk_skoru", "-")

                    badge_class = "bilgi-badge"
                    if "Kritik" in kritiklik:
                        badge_class = "kritik-badge"
                    elif "Yuksek" in kritiklik:
                        badge_class = "yuksek-badge"

                    with st.expander(f"#{idx+1} {zafiyet.get('zafiyet_adi', 'Bilinmeyen')} — Risk: {risk}/10"):
                        col_a, col_b = st.columns([3, 1])
                        with col_a:
                            st.markdown(f"**Açıklama:** {zafiyet.get('aciklama', '-')}")
                            st.markdown(f"**CloudTrail İzi:** `{zafiyet.get('cloudtrail_izi', '-')}`")
                            st.markdown(f"**Sıkılaştırma Önerisi:** {zafiyet.get('sikiastirma_onerisi', '-')}")
                        with col_b:
                            import html
                            guvenli_kritiklik = html.escape(kritiklik)
                            st.markdown(f'<span class="{badge_class}">{guvenli_kritiklik}</span>', unsafe_allow_html=True)
                            st.metric("Risk Skoru", f"{risk}/10")

                        if zafiyet.get("somuru_komutu"):
                            st.code(zafiyet["somuru_komutu"], language="bash")

                        if zafiyet.get("cloudtrail_istismar_durumu"):
                            istismar = zafiyet["cloudtrail_istismar_durumu"]
                            if istismar.get("olay_sayisi", 0) > 0:
                                st.warning(f"⚠️ {istismar.get('uyari', '')}")

            if saldiri_yollari:
                st.markdown("---")
                st.markdown("### 🕸️ Saldırı Yolları")
                for idx, (kaynak, hedef, son) in enumerate(saldiri_yollari):
                    st.markdown(f"**Yol {idx+1}:** `{kaynak}` → `{hedef}` → `{son}`")

            if duzelt and bulunan:
                st.markdown("---")
                st.markdown("### 🔧 Düzeltme Önerileri")
                from tulpar.raporlayici import duzeltme_scripti_uret
                import tempfile

                with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as tmp:
                    duzeltme_scripti_uret(bulunan, tmp.name)

                with open(tmp.name, "r", encoding="utf-8") as f:
                    script_icerik = f.read()

                import os
                try:
                    os.unlink(tmp.name)
                except OSError:
                    pass

                st.download_button(
                    "📥 Düzeltme Scriptini İndir",
                    script_icerik,
                    "tulpar_remediation.md",
                    "text/markdown",
                )

    else:
        st.info("👈 Soldaki panelden ayarları yapıp **Taramayı Başlat** butonuna tıklayın.")

    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🔗 Bağlantılar")
    st.sidebar.markdown("[GitHub](https://github.com/mecik-arda/Tulpar-Framework)")
    st.sidebar.markdown("[PyPI](https://pypi.org/project/tulpar-scanner/)")
    st.sidebar.caption("© Tulpar Framework — MIT License")


if __name__ == "__main__":
    web_dashboard_baslat(None)
