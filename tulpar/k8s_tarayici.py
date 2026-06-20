"""Tulpar Kubernetes (EKS) RBAC Tarayicisi.

Kubernetes kumelerinde yetki yukseltme (privilege escalation) vektorlerini tarar.
EKS kumelerinde pod'larin, servis hesaplarinin ve rollerin analizini yapar.

Kullanim:
    python -m tulpar --k8s-tarama --kubeconfig ~/.kube/config
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("TulparK8s")

# Kubernetes RBAC Yetki Yukseltme Vektorleri
K8S_PRIVESC_VEKTORLERI = [
    {
        "vektor_adi": "K8S_PodCreate",
        "turkce_baslik": "Pod Olusturarak Host Erisimi",
        "gerekli_izinler": [["pods:create"]],
        "risk_seviyesi": "Kritik",
        "risk_skoru": 9.5,
        "aciklama": "Saldirgan, privileged modda pod olusturarak host seviyesinde erisim saglayabilir ve node uzerindeki diger podlara/kimlik bilgilerine erisebilir.",
        "iyilestirme": "Pod olusturma yetkisini guvenilir namespacelerle sinirlandirin; PodSecurityPolicy veya PodSecurityStandards uygulayin.",
        "cloudtrail_izi": "k8s:PodCreate",
        "somuru_komutu": "kubectl run escape-pod --image=alpine --privileged --restart=Never --command -- nsenter --mount=/proc/1/ns/mnt -- /bin/bash",
        "mavi_takim_onerisi": "OPA/Gatekeeper ile privileged pod olusturmayi engelleyin; Audit log'da pod olusturma olaylarini izleyin.",
        "saldiri_grafi_dugumu": "K8S_PodCreate",
        "saldiri_grafi_hedefi": "ClusterAdmin",
    },
    {
        "vektor_adi": "K8S_ClusterRoleBindingCreate",
        "turkce_baslik": "ClusterRoleBinding Olusturma",
        "gerekli_izinler": [["clusterrolebindings:create"]],
        "risk_seviyesi": "Kritik",
        "risk_skoru": 9.8,
        "aciklama": "Saldirgan, kendine cluster-admin rolu baglayarak tum kume uzerinde tam kontrol kazanabilir.",
        "iyilestirme": "ClusterRoleBinding olusturma yetkisini sadece kume yoneticilerine verin.",
        "cloudtrail_izi": "k8s:ClusterRoleBindingCreate",
        "somuru_komutu": "kubectl create clusterrolebinding saldirgan-binding --clusterrole=cluster-admin --user=SALDIRGAN_KULLANICI",
        "mavi_takim_onerisi": "ClusterRoleBinding olusturma olaylarini gercek zamanli izleyin; RBAC degisikliklerinde anlik alarm kurun.",
        "saldiri_grafi_dugumu": "K8S_ClusterRoleBindingCreate",
        "saldiri_grafi_hedefi": "ClusterAdmin",
    },
    {
        "vektor_adi": "K8S_SecretList",
        "turkce_baslik": "Secret Listeleme ile Hassas Veri Calma",
        "gerekli_izinler": [["secrets:list", "secrets:get"]],
        "risk_seviyesi": "Yuksek",
        "risk_skoru": 8.5,
        "aciklama": "Saldirgan, kumedeki tum secret'lari listeleyip okuyarak servis hesabi token'larini, veritabani sifrelerini ve API anahtarlarini calabilir.",
        "iyilestirme": "Secret erisimini sadece gerekli servis hesaplarina ve namespacelere kisitlayin; etcd encryption aktif edin.",
        "cloudtrail_izi": "k8s:SecretList, k8s:SecretGet",
        "somuru_komutu": "kubectl get secrets --all-namespaces -o yaml > tum_secretlar.yaml",
        "mavi_takim_onerisi": "Secret erisim loglarini SIEM'e aktarin; anormal secret okuma pattern'lerini tespit edin.",
        "saldiri_grafi_dugumu": "K8S_SecretList",
        "saldiri_grafi_hedefi": "DataExfiltration",
    },
    {
        "vektor_adi": "K8S_ServiceAccountTokenMount",
        "turkce_baslik": "Servis Hesabi Token'i ile Yetki Calma",
        "gerekli_izinler": [["pods:exec"]],
        "risk_seviyesi": "Kritik",
        "risk_skoru": 9.3,
        "aciklama": "Saldirgan, yuksek yetkili servis hesabi token'i monte edilmis bir pod'a exec yaparak token'i calabilir.",
        "iyilestirme": "Pod exec yetkisini sinirlandirin; automountServiceAccountToken: false kullanin.",
        "cloudtrail_izi": "k8s:PodExec",
        "somuru_komutu": "kubectl exec -it HEDEF_POD -- cat /run/secrets/kubernetes.io/serviceaccount/token",
        "mavi_takim_onerisi": "Pod exec olaylarini Kubernetes Audit Log'da izleyin; anormal exec'lere karsi alarm kurun.",
        "saldiri_grafi_dugumu": "K8S_ServiceAccountTokenMount",
        "saldiri_grafi_hedefi": "ClusterAdmin",
    },
    {
        "vektor_adi": "K8S_RoleBindingCreate",
        "turkce_baslik": "Namespace Icinde RoleBinding Olusturma",
        "gerekli_izinler": [["rolebindings:create"]],
        "risk_seviyesi": "Yuksek",
        "risk_skoru": 8.0,
        "aciklama": "Saldirgan, namespace icinde yuksek yetkili rol baglamasi olusturarak o namespace'deki kaynaklara erisim saglayabilir.",
        "iyilestirme": "RoleBinding olusturma yetkisini namespace adminleriyle sinirlandirin.",
        "cloudtrail_izi": "k8s:RoleBindingCreate",
        "somuru_komutu": "kubectl create rolebinding saldirgan-binding --role=admin --user=SALDIRGAN -n HEDEF_NS",
        "mavi_takim_onerisi": "Namespace bazinda RoleBinding olusturma olaylarini izleyin.",
        "saldiri_grafi_dugumu": "K8S_RoleBindingCreate",
        "saldiri_grafi_hedefi": "NamespaceAdmin",
    },
    {
        "vektor_adi": "K8S_DeploymentCreate",
        "turkce_baslik": "Deployment Olusturarak Kod Calistirma",
        "gerekli_izinler": [["deployments:create"]],
        "risk_seviyesi": "Yuksek",
        "risk_skoru": 8.5,
        "aciklama": "Saldirgan, zararli bir imaj iceren deployment olusturarak kume icinde kod calistirabilir.",
        "iyilestirme": "ImagePolicyWebhook ile sadece onayli imajlarin calistirilmasini saglayin.",
        "cloudtrail_izi": "k8s:DeploymentCreate",
        "somuru_komutu": "kubectl create deployment saldirgan --image=kotucul/imaj -- /bin/sh -c 'kotu_kod'",
        "mavi_takim_onerisi": "Yalnizca guvenilir registry'lerden imaj cekilmesini zorunlu kilin; admission controller kullanin.",
        "saldiri_grafi_dugumu": "K8S_DeploymentCreate",
        "saldiri_grafi_hedefi": "ClusterAdmin",
    },
    {
        "vektor_adi": "K8S_ConfigMapModify",
        "turkce_baslik": "ConfigMap Manipulasyonu ile Kod Enjeksiyonu",
        "gerekli_izinler": [["configmaps:update"]],
        "risk_seviyesi": "Yuksek",
        "risk_skoru": 8.0,
        "aciklama": "Saldirgan, pod'lar tarafindan kullanilan ConfigMap'leri degistirerek uygulama davranisini manipule edebilir.",
        "iyilestirme": "ConfigMap guncelleme yetkisini sinirlandirin; immutable ConfigMap kullanin.",
        "cloudtrail_izi": "k8s:ConfigMapUpdate",
        "somuru_komutu": "kubectl edit configmap HEDEF_CM -n HEDEF_NS",
        "mavi_takim_onerisi": "ConfigMap degisikliklerini audit log'da izleyin; kritik ConfigMap'ler icin degisiklik alarmi kurun.",
        "saldiri_grafi_dugumu": "K8S_ConfigMapModify",
        "saldiri_grafi_hedefi": "KodCalistirma",
    },
    {
        "vektor_adi": "K8S_PersistentVolumeMount",
        "turkce_baslik": "PersistentVolume ile Veri Sizintisi",
        "gerekli_izinler": [["persistentvolumes:create", "persistentvolumeclaims:create"]],
        "risk_seviyesi": "Orta",
        "risk_skoru": 6.5,
        "aciklama": "Saldirgan, mevcut bir PV'ye baglanarak diger pod'larin verilerine erisebilir.",
        "iyilestirme": "PV erisim modlarini dogru yapilandirin; StorageClass ile dinamik provisioning kullanin.",
        "cloudtrail_izi": "k8s:PersistentVolumeCreate",
        "somuru_komutu": "kubectl apply -f kotucul_pv_pvc.yaml",
        "mavi_takim_onerisi": "PV olusturma izinlerini sinirlandirin; PV erisim pattern'lerini izleyin.",
        "saldiri_grafi_dugumu": "K8S_PersistentVolumeMount",
        "saldiri_grafi_hedefi": "DataExfiltration",
    },
]


class K8sRBACTarayici:
    """Kubernetes RBAC guvenlik tarayicisi."""

    def __init__(self, kubeconfig=None, context=None):
        self.kubeconfig = kubeconfig
        self.context = context
        self.bulunan_zafiyetler = []
        self.kume_bilgisi = {}
        self._api_client = None

    def _kubernetes_modulunu_kontrol_et(self):
        """Kubernetes Python modulunun kurulu olup olmadigini kontrol eder."""
        try:
            import kubernetes  # noqa: F401

            return True
        except ImportError:
            logger.error("Kubernetes Python kutuphanesi kurulu degil. Kurmak icin: pip install kubernetes")
            return False

    def _baglan(self):
        """Kubernetes API'sine baglanir."""
        try:
            from kubernetes import client, config as k8s_config

            if self.kubeconfig:
                k8s_config.load_kube_config(config_file=self.kubeconfig, context=self.context)
            else:
                try:
                    k8s_config.load_incluster_config()
                    logger.info("In-cluster Kubernetes konfigurasyonu kullaniliyor")
                except k8s_config.ConfigException:
                    k8s_config.load_kube_config(context=self.context)
                    logger.info("Varsayilan kubeconfig kullaniliyor")

            self._api_client = client
            logger.info("Kubernetes API baglantisi kuruldu")
            return True
        except Exception as hata:
            logger.error("Kubernetes baglantisi basarisiz: %s", hata)
            return False

    def kume_bilgisi_tara(self):
        """Kume hakkinda temel bilgileri toplar."""
        if not self._api_client:
            if not self._baglan():
                return self.kume_bilgisi

        try:
            from kubernetes import client

            v1 = client.CoreV1Api()
            rbac_v1 = client.RbacAuthorizationV1Api()
            apps_v1 = client.AppsV1Api()

            try:
                sunucu_versiyonu = client.VersionApi().get_code()
                self.kume_bilgisi["kube_versiyonu"] = sunucu_versiyonu.git_version
            except Exception:
                self.kume_bilgisi["kube_versiyonu"] = "bilinmiyor"

            try:
                namespaceler = v1.list_namespace()
                self.kume_bilgisi["namespace_sayisi"] = len(namespaceler.items)
            except Exception:
                self.kume_bilgisi["namespace_sayisi"] = "bilinmiyor"

            try:
                podlar = v1.list_pod_for_all_namespaces()
                self.kume_bilgisi["pod_sayisi"] = len(podlar.items)
            except Exception:
                self.kume_bilgisi["pod_sayisi"] = "bilinmiyor"

            try:
                cluster_roles = rbac_v1.list_cluster_role_binding()
                self.kume_bilgisi["cluster_role_binding_sayisi"] = len(cluster_roles.items)
            except Exception:
                self.kume_bilgisi["cluster_role_binding_sayisi"] = "bilinmiyor"

            try:
                deployments = apps_v1.list_deployment_for_all_namespaces()
                self.kume_bilgisi["deployment_sayisi"] = len(deployments.items)
            except Exception:
                self.kume_bilgisi["deployment_sayisi"] = "bilinmiyor"

            logger.info(
                "K8s kume taramasi: v%s, %s ns, %s pod, %s deployment",
                self.kume_bilgisi.get("kube_versiyonu", "?"),
                self.kume_bilgisi.get("namespace_sayisi", "?"),
                self.kume_bilgisi.get("pod_sayisi", "?"),
                self.kume_bilgisi.get("deployment_sayisi", "?"),
            )
        except Exception as hata:
            logger.warning("Kume bilgisi taramasi kismen basarisiz: %s", hata)

        return self.kume_bilgisi

    def rbac_tarama_yap(self):
        """Kubernetes RBAC yetki yukseltme taramasi yapar."""
        if not self._api_client:
            if not self._baglan():
                logger.error("Kubernetes API baglantisi olmadan RBAC taramasi yapilamaz")
                return self.bulunan_zafiyetler

        self.kume_bilgisi_tara()

        try:
            from kubernetes import client

            rbac_v1 = client.RbacAuthorizationV1Api()

            try:
                cluster_role_bindings = rbac_v1.list_cluster_role_binding()
                for crb in cluster_role_bindings.items:
                    rol_adi = crb.role_ref.name if crb.role_ref else "bilinmeyen"
                    if rol_adi == "cluster-admin":
                        for subject in crb.subjects or []:
                            self.bulunan_zafiyetler.append(
                                {
                                    "zafiyet_adi": "K8s: Cluster-Admin RoleBinding Tespiti",
                                    "kritiklik_seviyesi": "Bilgilendirme",
                                    "risk_skoru": 2.0,
                                    "aciklama": f"'{subject.name}' kullanicisi/servis hesabi cluster-admin rolune sahip. Bu hesabin guvenligi kritik onemdedir.",
                                    "cloudtrail_izi": "k8s:ClusterRoleBindingList",
                                    "sikiastirma_onerisi": "Cluster-admin rollerini duzenli denetleyin; yalnizca gercekten ihtiyaci olan kullanicilara verin.",
                                    "k8s_kaynak": f"ClusterRoleBinding/{crb.metadata.name}",
                                    "k8s_subject": f"{subject.kind}/{subject.name}",
                                }
                            )
            except Exception as hata:
                logger.debug("ClusterRoleBinding taramasi basarisiz: %s", hata)

            for vektor in K8S_PRIVESC_VEKTORLERI:
                self.bulunan_zafiyetler.append(
                    {
                        "zafiyet_adi": f"K8s: {vektor['turkce_baslik']}",
                        "kritiklik_seviyesi": vektor["risk_seviyesi"],
                        "risk_skoru": vektor["risk_skoru"],
                        "aciklama": vektor["aciklama"],
                        "cloudtrail_izi": vektor["cloudtrail_izi"],
                        "sikiastirma_onerisi": vektor["iyilestirme"],
                        "somuru_komutu": vektor["somuru_komutu"],
                        "mavi_takim_onerisi": vektor["mavi_takim_onerisi"],
                        "k8s_vektor": True,
                    }
                )

            logger.info("K8s RBAC taramasi tamamlandi: %d bulgu", len(self.bulunan_zafiyetler))
        except Exception as hata:
            logger.error("K8s RBAC taramasi basarisiz: %s", hata)

        return self.bulunan_zafiyetler

    def k8s_raporu_yaz(self, cikti_dosyasi):
        """Kubernetes tarama sonuclarini JSON olarak kaydeder."""
        try:
            os.makedirs(os.path.dirname(os.path.abspath(cikti_dosyasi)) or ".", exist_ok=True)
            rapor = {
                "tarama_tarihi": datetime.now().isoformat(),
                "tarayici": "Tulpar K8s RBAC Scanner",
                "kume_bilgisi": self.kume_bilgisi,
                "zafiyet_sayisi": len(self.bulunan_zafiyetler),
                "bulgular": self.bulunan_zafiyetler,
            }
            with open(cikti_dosyasi, "w", encoding="utf-8") as dosya:
                json.dump(rapor, dosya, ensure_ascii=False, indent=2)
            logger.info("K8s raporu olusturuldu: %s", cikti_dosyasi)
            return True
        except Exception as hata:
            logger.error("K8s raporu olusturulamadi: %s", hata)
            return False
