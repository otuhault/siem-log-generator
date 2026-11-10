
|Concept OTel/K8s|Équivalent / analogie Splunk|
|---|---|
|**Splunk OTel Collector** (le chart)|Un Universal Forwarder "nouvelle génération", mais multi-signaux (logs **+** métriques **+** traces)|
|**DaemonSet**|Mécanisme K8s qui garantit **1 pod du collector par node**. Comme installer un UF sur chaque serveur physique|
|**HEC exporter**|La façon dont le collector envoie les données → exactement le **HTTP Event Collector** que tu connais|
|**values.yaml**|Le fichier de config (équivalent moral de tes `inputs.conf`/`outputs.conf`, mais en YAML)|
|**Helm**|Le "gestionnaire de paquets" K8s — il déploie le chart (= le package) dans le cluster|

`[Containers] → [OTel Collector (DaemonSet, 1/node)] → HEC → [Heavy Forwarder] → [Indexers]`
### Pré-requis avant de toucher au cluster
1. **Accès kubectl** au cluster (l'admin du cluster te fournit le _kubeconfig_).
2. **Helm 3.9+** installé sur ta machine.
3. Côté Splunk : **token HEC** + **endpoint** + **index(es)** prêts.
    - Un index pour les logs (ex. `k8s_logs`)
    - Un index métriques si tu veux les métriques (ex. `k8s_metrics`, de type `metric`)
### La démarche pas à pas
#### Étape A — Ajouter le repo Helm
```bash
helm repo add splunk-otel-collector-chart https://signalfx.github.io/splunk-otel-collector-chart
helm repo update
```

#### Étape B — Préparer un `values.yaml`
Plutôt que de tout mettre en `--set` (illisible), on utilise un fichier. Voici un exemple minimal **logs + traces vers Splunk Platform** :
```yaml
clusterName: mon-cluster-k8s

splunkPlatform:
  endpoint: "https://<HF>:8088/services/collector"
  token: "<TON_TOKEN_HEC>"
  index: "k8s_logs"          # index logs par défaut
  metricsIndex: "k8s_metrics" # si tu veux aussi les métriques
  insecureSkipVerify: true    # à éviter en prod — voir note TLS plus bas

logsEngine: otel  # moteur de collecte de logs

# Active/désactive les types de signaux
logsCollection:
  containers:
    enabled: true

# Traces : nécessite que tes apps émettent du OTLP (voir note plus bas)
tracesEnabled: true

# Métriques cluster (optionnel)
metricsEnabled: true
```

#### Étape C — Installer
```bash
helm -n otel install my-splunk-otel-collector \
  --values values.yaml \
  splunk-otel-collector-chart/splunk-otel-collector \
  --create-namespace
```
#### Étape D — Vérifier
```bash
kubectl -n otel get pods        # tu dois voir 1 pod par node (DaemonSet) en Running
kubectl -n otel logs <pod>      # check des erreurs d'export HEC
```

Puis côté Splunk, un bête `index=k8s_logs | head 100` doit montrer des events.

### Logs vs Traces — la grosse distinction à comprendre
C'est le point où débutants OTel se font piéger :
- **Logs** = collecte **automatique**. Le collector lit les fichiers de logs des containers sur chaque node (`/var/log/pods/...`, là où K8s écrit le `stdout`/`stderr` des containers). **Tu n'as rien à faire dans les applis.** ✅
- **Traces** = **PAS automatique** par défaut. Une "trace" décrit le cheminement d'une requête à travers tes services. Pour en avoir, il faut que **tes applications émettent des traces** au format OTLP, soit :
    - via instrumentation manuelle dans le code, soit
    - via **auto-instrumentation** (l'OTel Operator injecte des agents dans tes pods — section _Auto-instrumentation_ du README).
    Le collector ne _fabrique_ pas de traces ; il les _reçoit_ et les _transmet_. Si tes apps n'émettent rien, l'index traces restera vide.
**Donc** : pour ton besoin initial "collecter des logs des containers", l'étape B suffit. Les traces sont un chantier séparé qui dépend de tes applis.
### Points d'attention pratiques
- **TLS** : `insecureSkipVerify: true` est pratique en POC mais à proscrire en prod. Pousse plutôt le certificat CA de ton HF (paramètre `clientCert`/`caFile` dans la conf avancée).
- **Versioning** : le README insiste lourdement — **fige une version exacte** (`--version x.y.z`) car un bump "mineur" peut casser. Lis l'`UPGRADING.md` avant tout upgrade.
- **Sourcetypes** : par défaut les logs arrivent avec des sourcetypes type `kube:container:<nom>`. Tu peux remapper côté collector ou côté Splunk.
- **Volume / sizing** : K8s peut être très bavard. Regarde le doc _Sizing_ et prévois tes index en conséquence.
- **Métriques en index `metric`** : si tu actives les métriques, l'index Splunk cible doit être de type **metrics**, sinon rejets.

## RKE2 : les spécificités à connaître
**1. `distribution` n'a pas de valeur dédiée RKE2.** Le chart connaît `eks`, `gke`, `openshift`, etc., mais **pas** RKE2 explicitement. Donc :
- On laisse `distribution` **vide** (cas "vanilla / autre").
- Du coup `clusterName` devient **obligatoire** (pas de détection auto comme sur EKS/GKE).
**2. Chemins de logs containerd.** RKE2 utilise **containerd** (pas Docker). Les logs des containers sont dans `/var/log/pods/` — c'est le chemin standard que le chart lit par défaut. ✅ Donc en principe rien à customiser côté collecte de logs.
**3. SELinux (SUSE).** SUSE active souvent des politiques de sécurité strictes. Si les pods du collector n'arrivent **pas à lire** les logs (erreurs de permission dans les logs du pod), il faudra activer une option SELinux. On verra ça **seulement si** le symptôme apparaît — pas la peine de l'activer préventivement.

`values.yaml` pour ton cas (logs + traces, pas de métriques)
```yaml
clusterName: mon-cluster-rke2     # OBLIGATOIRE ici (pas de détection auto)
distribution: ""                # on laisse vide pour RKE2

splunkPlatform:
  endpoint: "https://<HF>:8088/services/collector"
  token: "<TON_TOKEN_HEC>"
  index: "k8s_logs"               # index logs
  insecureSkipVerify: true        # POC uniquement — TLS propre ensuite

logsEngine: otel

# ---- LOGS : activés ----
logsCollection:
  containers:
    enabled: true

# ---- TRACES : activées (réception OTLP) ----
splunkObservability:
  tracesEnabled: false            # on n'envoie PAS vers Observability Cloud

# Réception des traces et renvoi vers Splunk Platform via HEC
tracesEnabled: true

# ---- METRICS : désactivées ----
metricsEnabled: false
```


```
helm install splunk-otel-collector --set="splunkObservability.accessToken=RACCESS_TOKE,clusterName=myCluster,splunkObservability.realm=eu0,gateway.enabled=false,splunkPlatform.endpoint=MY HEC ENDPOINT,splunkPlatform.token=HEC_TOKEN,environment=myEnv" splunk-otel-collector-chart/splunk-otel-collector
```
