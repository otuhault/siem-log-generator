### 1️⃣ Mode Standard (Standard Mode)

|Caractéristique|Détail|
|---|---|
|**Fonctionnement**|Le Search Head local envoie une requête au Search Head distant (Remote Search Head)|
|**Exécution**|La recherche est exécutée **entièrement côté distant**, seuls les résultats sont renvoyés|
|**Connaissance du schéma**|L'utilisateur doit **connaître la structure** des données distantes (index, sourcetypes, fields)|
|**Langage**|SPL standard, mais certaines commandes peuvent être **limitées**|
|**Lookups / Knowledge Objects**|Les Knowledge Objects locaux **ne sont pas projetés** vers la cible distante|
|**Cas d'usage typique**|Interroger un autre déploiement Splunk isolé, une autre BU, un autre datacenter|

### 2️⃣ Mode Transparent (Transparent Mode)

| Caractéristique            | Détail                                                                                               |
| -------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Fonctionnement**         | Le Search Head local agit comme si les données distantes étaient **locales**                         |
| **Exécution**              | La requête est **décomposée automatiquement** : une partie s'exécute en distant, une partie en local |
| **Connaissance du schéma** | **Transparence totale** pour l'utilisateur — pas besoin de connaître la topologie distante           |
| **Knowledge Objects**      | Les **lookups, field aliases, tags** locaux peuvent être appliqués aux résultats distants            |
| **Cas d'usage typique**    | Environnements **multi-sites / multi-cloud** où l'expérience utilisateur doit rester homogène        |
| **Workload Balancing**     | Permet une meilleure **distribution de la charge** de recherche                                      |
## ⚡ Différences Clés en Résumé
```none
Standard Mode          →  Vous savez où vous cherchez
Transparent Mode       →  Vous ne vous souciez pas d'où vous cherchez
```

|Critère|Standard|Transparent|
|---|---|---|
|Complexité de configuration|Faible|Plus élevée|
|Expérience utilisateur|Manuelle|Fluide / abstraite|
|Application des KO locaux|❌ Non|✅ Oui (partielle)|
|SPL identique|✅ Oui|✅ Oui|
|Visibilité topologie requise|✅ Oui|❌ Non|
|Requêtes temps réel|⚠️ Limité|⚠️ Limité|