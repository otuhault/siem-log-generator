/opt/splunk/var/run/ -> Bundle from Search Heads to the Indexers.

### 1. À quoi sert précisément ce dossier `snapshot/` ?
En Search Head Cluster, le Captain maintient deux mécanismes pour synchroniser les membres :
1. **Le journal des deltas (Replication Pull) :** Chaque modification (sauvegarde d'une recherche, création d'un tableau de bord, modification d'un lookup via l'UI) génère un commit incrémental que les autres membres appliquent.
2. **Le Snapshot complet (ce dossier de 9.2 Go) :**  
    Régulièrement (géré par le paramètre `conf_replication_summary.period`), le Captain crée une **photographie complète de l'ensemble des configurations réplicables de votre cluster** (pratiquement tout `$SPLUNK_HOME/etc/apps/` et `$SPLUNK_HOME/etc/users/`).
    
**Son rôle unique :**  
Permettre à un membre du SHC qui a trop de retard sur les deltas, qui redémarre après une longue panne, ou qui subit une resynchronisation forcée (_destructive resync_) de récupérer l'état complet du cluster en un seul bloc sans rejouer des milliers de petits commits un par un.


Dans l'architecture Splunk, le mot **« bundle »** est utilisé pour désigner des mécanismes différents. Entre les **Search Heads (SH)** et les **Indexeurs (IDX)**, il s'agit principalement du **Knowledge Bundle** (bundle de connaissances), mais il est souvent confondu avec d'autres types de bundles présents sur la plateforme.

Voici la cartographie exacte des différents bundles, leur rôle et où ils résident :

---

### 1. Le Knowledge Bundle (Entre Search Head et Indexers)

C'est le bundle central de la recherche distribuée (_Distributed Search_).

- **À quoi il sert** :  
    Pour exécuter une recherche, les indexeurs ont besoin de connaître les configurations de recherche du Search Head : les _field extractions_, macros, tags, eventtypes, fichiers de _lookups_ (`.csv`), `props.conf` et `transforms.conf`. Le Search Head archive ces éléments et les envoie aux indexeurs afin qu'ils appliquent les mêmes règles au moment de lire les données brutes.
    
- **Ce qu'il contient** :  
    Le contenu de `$SPLUNK_HOME/etc/apps/` et `$SPLUNK_HOME/etc/users/` (sauf ce qui est exclu par `replicationBlacklist` / `replicationDenylist` dans `distsearch.conf`).
    
- **Où il réside physiquement** :
    
    - **Sur le Search Head** :
        
        - **Le snapshot temporaire (non compressé)** :  
            `$SPLUNK_HOME/var/run/splunk/snapshot/<timestamp>/`  
            _(C'est ici que Splunk rassemble les fichiers avant compression. C'est le dossier lourd que vous avez pu observer)._
            
        - **L'archive compressée finale** :  
            `$SPLUNK_HOME/var/run/searchpeers/<bundle_id>.bundle` (ou dans `var/run/splunk/`).
            
    - **Sur les Indexeurs (Search Peers)** :
        
        - **Le répertoire de réception et décompression** :  
            `$SPLUNK_HOME/var/run/searchpeers/`
            
        - Dans ce dossier, chaque Search Head dispose de son propre répertoire nommé sous la forme :  
            `<GUID_du_SearchHead>-<timestamp>/`
            
        - À l'intérieur, les indexeurs ont l'arborescence complète décompressée (`etc/apps/`, `etc/users/`, lookups) pour pouvoir l'exécuter localement.
            

---

### 2. Le Delta Bundle (Variante incrémentale du Knowledge Bundle)

- **À quoi il sert** :  
    Pour éviter d'envoyer un fichier de plusieurs gigaoctets à chaque recherche, Splunk calcule les différences (_diff_) entre le dernier bundle connu sur l'indexeur et l'état actuel du SH. Si seulement un petit lookup ou un `.conf` a changé, seul un « delta » est transféré.
    
- **Où il réside** :
    
    - Appliqué directement dans le dossier `$SPLUNK_HOME/var/run/searchpeers/` sur les indexeurs pour mettre à jour la copie existante sans tout retransférer.
        

---

### 3. Les autres « Bundles » dans Splunk (À ne pas confondre)

Pour éviter toute ambiguïté lors de l'administration :

|   |   |   |   |   |
|---|---|---|---|---|
|Type de Bundle|Entre qui et qui ?|Emplacement source|Emplacement destination|À quoi ça sert ?|
|**Knowledge Bundle** _(celui dont on parle)_|**Search Head ➔ Indexers**|SH : `var/run/splunk/snapshot/`|IDX : `var/run/searchpeers/`|Distribuer les lookups, macros et règles de recherche search-time.|
|**Cluster Bundle** _(Indexer Cluster)_|**Cluster Manager ➔ Indexers**|CM : `etc/master-apps/`|IDX : `etc/slave-apps/` (ou `peer-apps/`)|Configurer les index, la rétention, les volumes et l'index-time.|
|**Deployer Bundle** _(SHC)_|**Deployer ➔ Search Heads**|Deployer : `etc/shcluster/apps/`|SH : `etc/apps/`|Déployer les applications et dashboards sur le cluster de SH.|

---

### Résumé visuel du cycle de vie du Knowledge Bundle :

1. **Génération sur le SH** : Lecture de `etc/apps` et `etc/users` (filtré par la denylist) ➔ copié dans `var/run/splunk/snapshot/` ➔ compressé en `.bundle`.
    
2. **Transfert réseau** : Envoyé via HTTPS (port de gestion 8089) aux indexeurs.
    
3. **Extraction sur l'IDX** : Décompressé dans `var/run/searchpeers/<SH-GUID>/` pour être interrogé par les processus de recherche `splunkd`.
    
4. **Nettoyage automatique** : Les anciens bundles expirés dans `searchpeers/` sont automatiquement supprimés par Splunk (`bundleCleaningOptions` dans `distsearch.conf`).