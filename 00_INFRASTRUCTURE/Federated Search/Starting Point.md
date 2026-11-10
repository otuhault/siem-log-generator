## 🔍 1. Comment ça fonctionne (en bref)

La **Federated Search** permet à un **Search Head "fédérateur"** (appelé **Federated Search Head / FSH**) d'envoyer des requêtes à des **providers distants** (d'autres Search Heads ou clusters SH), sans que les données soient centralisées.
### Architecture simplifiée
```none
[ Federated Search Head Cluster ]
        |
        |—— requête SPL avec "federated:" prefix
        |
        ├──► [ Remote SH Cluster A (ES) ]  ──► Indexers A
        ├──► [ Remote SH Cluster B (ES) ]  ──► Indexers B
        └──► [ Remote SH Cluster C (ES) ]  ──► Indexers C
```

### Flux d'une requête

1. L'utilisateur soumet une recherche sur le **FSH local**
2. Le FSH identifie les providers distants ciblés via le préfixe `federated:<provider_name>`
3. Le FSH transmet la requête aux **Search Heads distants**
4. Les SH distants exécutent la recherche sur **leurs propres indexers**
5. Les résultats sont **rapatriés et agrégés** sur le FSH local
6. L'utilisateur voit un résultat unifié

> ⚠️ **Important** : Les données ne bougent pas — seuls les **résultats** transitent vers le FSH.

---

## ⚙️ 2. Configurations nécessaires

### 2.1 Prérequis

|Composant|Exigence|
|---|---|
|Version Splunk|≥ 8.1 (recommandé 9.x)|
|Licence|Splunk Enterprise ou Cloud|
|ES sur remote SH|ES doit être installé et fonctionnel|
|Réseau|Connectivité HTTPS (port 8089 par défaut) entre FSH et remote SH|
|Auth|Compte de service avec rôles appropriés sur chaque remote SH|

---

### 2.2 Configuration côté Federated Search Head
#### Étape 1 — Déclarer un Federated Provider
Via UI : **Settings → Federated Search → Add Federated Provider**
Ou via `$SPLUNK_HOME/etc/system/local/federated.conf` :
```ini
[provider:mon_cluster_ES_A]
type = splunk
host = splunk-sh-cluster-A.domain.com
port = 8089
serviceAccount = svc_federated
password = <encrypted>
sslVerifyCert = true
```

#### Étape 2 — Déclarer un Federated Index
Via UI : **Settings → Federated Search → Add Federated Index**
Ou dans `federated.conf` :
```ini
[index:federated_es_a]
provider = mon_cluster_ES_A
remoteIndex = index_es_a
```

> Cela mappe un index **local virtuel** vers un index **réel sur le provider distant**.

#### Étape 3 — Syntaxe de recherche
```spl
| search index=federated:federated_es_a sourcetype=firewall
```

Ou en ciblant plusieurs providers :
```spl
index=federated:federated_es_a OR index=federated:federated_es_b
| stats count by src_ip
```

---
### 2.3 Configuration côté Remote Search Head (ES)

Sur chaque **remote SH ES**, il faut :
```ini
# server.conf
[shclustering]
# S'assurer que le cluster accepte les connexions distantes

# authorize.conf — Rôle dédié pour le compte de service
[role_federated_reader]
srchIndexesAllowed = index_es_a;index_es_b
srchJobsQuota = 50
rtSrchJobsQuota = 10
```

> ✅ Créer un **compte de service dédié** avec **droits minimaux** (principe du moindre privilège).

---
## ✅ 3. Best Practices essentielles
### 🔐 Sécurité
- Utiliser **TLS/SSL** sur toutes les communications (port 8089)
- **Compte de service dédié** par remote cluster (ne pas réutiliser des comptes admin)
- Restreindre les rôles au strict nécessaire : `srchIndexesAllowed` limité aux index ES pertinents
- Activer la **validation des certificats** (`sslVerifyCert = true`)
### ⚡ Performance
- **Limiter le volume de données retournées** : utiliser `stats`, `table`, `fields` pour réduire le payload
- Éviter les recherches `index=*` sur les providers fédérés
- Configurer des **timeouts adaptés** dans `federated.conf` (`connectTimeout`, `receiveTimeout`)
- Préférer des **searches asynchrones** pour les requêtes longues
### 🏗️ Architecture

- Dédier les **FSH à la fédération** (ne pas mélanger avec des SH classiques en production)
- En cluster FSH, configurer un **Search Head Cluster** standard + activer la federated search sur chaque membre
- Utiliser un **Deployer** pour propager `federated.conf` sur tous les membres du cluster FSH
- Documenter le **mapping index fédéré ↔ index réel** pour chaque provider

### 📊 Monitoring

- Surveiller les métriques via `_internal` :
```spl
index=_internal sourcetype=splunkd component=FederatedSearch
```
- Monitorer les **latences** entre FSH et remote SH
- Alerter sur les **échecs de connexion** aux providers

---
## 📋 Résumé des fichiers de configuration clés

| Fichier          | Rôle                                  | Emplacement                     |
| ---------------- | ------------------------------------- | ------------------------------- |
| `federated.conf` | Déclaration providers & index fédérés | FSH : `etc/system/local/`       |
| `authorize.conf` | Rôles & permissions                   | Remote SH : `etc/system/local/` |
| `server.conf`    | SSL, clustering                       | FSH + Remote SH                 |
| `web.conf`       | Activation UI federated search        | FSH                             |

---

## ❓ Prochaines étapes ?

Tu veux qu'on approfondisse un point spécifique ?

- 🔧 **Troubleshooting** des erreurs courantes de federated search ?
- 🏗️ **Architecture détaillée** pour un cluster FSH HA ?
- 🔐 **Configuration SSL/TLS** avancée ?
- 📦 **Intégration spécifique avec ES** (corrélations, Notable Events) ?



```ini
# ============================================================
# PROVIDERS
# ============================================================

[provider:provider_es_paris]
type = splunk
host = splunk-sh-paris.domain.com
port = 8089
serviceAccount = svc_federated
password = <encrypted>
sslVerifyCert = true

[provider:provider_es_lyon]
type = splunk
host = splunk-sh-lyon.domain.com
port = 8089
serviceAccount = svc_federated
password = <encrypted>
sslVerifyCert = true

[provider:provider_es_london]
type = splunk
host = splunk-sh-london.domain.com
port = 8089
serviceAccount = svc_federated
password = <encrypted>
sslVerifyCert = true

# ============================================================
# FEDERATED INDEXES
# ============================================================

[index:notable_es_paris]
provider = provider_es_paris
remoteIndex = notable

[index:notable_es_lyon]
provider = provider_es_lyon
remoteIndex = notable

[index:notable_es_london]
provider = provider_es_london
remoteIndex = notable
```


federated.conf
```
[provider:atea-m01-norway]
hostPort = https://no-vm-splash01.nix.mad.onenet.no:8089
serviceAccount = admsplunk
password = 
```

indexes.conf
```
[federated:remote_test]
federated.provider = atea-m01-norway
federated.dataset = _internal
```

```
[provider://ui_atea_m01_norway]
hostPort = no-vm-splash01.nix.mad.onenet.no:8089
mode = standard
password = $7$Gw6ii6tPLxw6OTUFXrwFIoysa6C6rYq3HQzHHH5WhJi6UbNR88u93VCDzpvtMmzRbYH9Bw==
serviceAccount = admsplunk
type = splunk
useFSHKnowledgeObjects = 0
```

```
[federated:atea-m01-norway_ep_edr]
federated.dataset = index:atea-m01-norway_ep_edr
federated.provider = ui_atea_m01_norway
```

atea_fsh_m01-norway_indexes/local
