# Kubernetes
Imagine que **Kubernetes** soit une immense ville construite en **LEGO**, avec un **Maire robotique** chargé de veiller à ce que tout fonctionne tout seul 24h/24.

**1. C'est quoi le problème de base avec Kubernetes ?**
De base, le Maire robotique de Kubernetes ne connaît que des concepts très basiques (les briques standards) :
**•** Une **boîte** pour faire tourner un programme (_un Pod_).
**•** Un **câble réseau** pour brancher des boîtes ensemble (_un Service_).
**•** Un **tiroir** pour stocker des fichiers (_un Volume_).

Le problème ? Le Maire de Kubernetes **ne sait absolument pas ce qu'est Splunk, ni ce qu'est un Indexer, ni ce qu'est un LLM (Cerveau d'IA)**.

Si tu devais tout construire à la main avec les briques de base, tu devrais lui donner 500 instructions compliquées : _"Mets 3 boîtes, configure les disques NVMe, connecte le port 9997, surveille la mémoire GPU, gère les clés secrètes..."_. Si une boîte plante, le Maire ne saurait pas comment réparer la logique Splunk.

**2. Qu'est-ce qu'une CRD (****_Custom Resource Definition_****) ?**
Une **CRD**, c'est tout simplement **ajouter un nouveau mot dans le dictionnaire de Kubernetes**.
C'est comme si tu disais au Maire :
>_« À partir d'aujourd'hui, j'invente un nouveau mot dans notre ville : un_ **_IndexerCluster_** _(ou un_ **_ModelClaim_** _pour l'IA). Voici la fiche de définition qui explique à quoi ressemble ce mot. »_

Grâce à la CRD, au lieu d'écrire 50 pages de détails techniques, tu peux simplement poser une commande de 5 lignes sur le bureau du Maire :
```
MonSouhait:
  JeVeux: IndexerCluster
  NombreDIndexers: 3
  TailleDisque: 500Go
```

**3. Et SOK (Splunk Operator for Kubernetes) dans tout ça ?**
Avoir un nouveau mot dans le dictionnaire, c'est bien, mais le Maire ne sait toujours pas comment fabriquer concrètement un cluster Splunk.
C'est là qu'intervient **l'Operator (SOK)** :
**• SOK, c'est un ingénieur expert Splunk sous forme de robot**, que tu installes dans la ville Kubernetes.
**•** Ce robot a une seule mission dans sa vie : **regarder ta feuille de souhaits (la CRD)** et faire en sorte que la réalité corresponde **exactement** à ce que tu as demandé.
  
C'est ce qu'on appelle la **boucle de réconciliation (l'autopilote)** :
```
    +-------------------------------------------------------------+
    | 1. Tu écris ton souhait : "Je veux 3 Indexers"             |
    +-------------------------------------------------------------+
                                  |
                                  v
    +-------------------------------------------------------------+
    | 2. SOK lit ton souhait et crée les 3 Indexers en vrai       |
    +-------------------------------------------------------------+
                                  |
                                  v
    +-------------------------------------------------------------+
    | 3. Un serveur brûle la nuit : il ne reste que 2 Indexers   |
    +-------------------------------------------------------------+
                                  |
                                  v
    +-------------------------------------------------------------+
    | 4. SOK remarque l'écart (3 voulus vs 2 réels)               |
    |    -> Il recrée immédiatement le 3ème Indexer tout seul !   |
    +-------------------------------------------------------------+
```

**4. Et pour l'IA et les LLMs (AI Tier), comment ça marche ?**
C'est exactement le même principe ! Au lieu de devoir installer des pilotes de cartes graphiques NVIDIA à la main, configurer vLLM, et brancher des câbles virtuels :
1. Tu crées une CRD pour l'IA : par exemple un **ModelClaim** (une demande de modèle).
2. Tu écris ton souhait : _"J'ai besoin du modèle LLM Llama-3 sur une carte graphique GPU avec une réponse rapide pour mon assistant Splunk"_.
3. L'opérateur d'IA prend ta feuille, alloue la mémoire sur les cartes GPU, télécharge le modèle localement et te renvoie un « ticket secret » (_le Secret Kubernetes_) pour que ton application (SAIA ou ES 8.8) puisse parler au LLM directement.

# ETCD
**etcd**, c'est **le cerveau et la mémoire centrale unique de Kubernetes**.
Si Kubernetes est une ville robotique, **etcd est le grand registre notarié infalsifiable** où est consigné absolument tout ce qui existe et tout ce qui doit exister dans le cluster.

**1.** 🧠 **Quel est le rôle d'etcd dans Kubernetes ?**
Techniquement, **etcd** est une base de données distribuée de type **Clé-Valeur** (_Key-Value store_), ultra-rapide et hautement cohérente (_Strong Consistency_) utilisant l'algorithme de consensus **Raft**.

Dans Kubernetes, **rien n'existe en dehors d'etcd** :
**•** Tous les fichiers de souhaits (les **CRDs** comme ModelClaim, IndexerCluster).
**•** La liste de tous les serveurs, Pods, adresses IP, Services.
**•** Les mots de passe et certificats (les **Secrets**).
**•** L'état en temps réel du cluster.

>💡 **Règle d'or :** L'API Server de Kubernetes (kube-apiserver) est le seul composant qui a le droit de parler directement à etcd. Tous les autres (les Operators, SOK, les noeuds, etc.) passent par l'API Server pour lire ou écrire dans etcd.

**2.** 🔄 **Comment SOK et l'AI Tier utilisent-ils etcd ? (Le mécanisme de** **_Watch_****)**
L'opérateur **SOK** ne passe pas son temps à scanner tout le réseau en permanence. Il utilise une fonctionnalité clé d'etcd appelée le **« Watch »** :

1. **SOK pose une alerte sur etcd :** _« Préviens-moi dès que quelqu'un crée ou modifie une fiche_ _ModelClaim_ _ou_ _IndexerCluster__. »_
2. **Vous appliquez votre fichier :** kubectl apply -f modelclaim.yaml.
3. L'API Server enregistre votre souhait dans **etcd**.
4. **etcd réveille immédiatement SOK :** _« Quelqu'un vient de demander un modèle LLM avec 4 GPU dans le namespace_ _splunk-core_ _! »_
5. SOK exécute sa boucle de réconciliation pour allouer les ressources.

**3.** ⚠️ **Les 2 règles d'or d'etcd à connaître absolument en tant que Consultant**
Comprendre etcd vous évite deux pièges classiques en mission client :

**A. La limite stricte de 1 Mo par objet (****_Request Limit_****)**
**•** etcd refuse catégoriquement d'enregistrer tout objet dont la taille dépasse **1 Mo**.
**•** _Impact pratique :_ C'est exactement pour cela que les **CRDs de SOK** (qui contiennent des centaines de règles de validation) ne peuvent pas être embarquées directement dans un Chart Helm classique et doivent être appliquées manuellement au préalable (kubectl apply -f crds.yaml).

**B. etcd n'est PAS une base de données de logs ou de métriques**
**•** La base etcd d'un cluster a un quota de stockage par défaut limité (souvent bridé entre **2 Go et 8 Go**).
**•** _Impact pratique :_ C'est pourquoi l'architecture **AI Tier / Agentic SOC** stocke les déclarations stables (AgentRegistration) dans etcd via les CRDs, mais envoie les logs, les métriques d'inférence et les historiques d'alertes vers **PostgreSQL, OpenTelemetry ou une base vectorielle dédiée**, et **jamais dans Kubernetes/etcd**.