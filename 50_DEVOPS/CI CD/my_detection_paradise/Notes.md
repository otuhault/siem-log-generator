```
mkdir mon-depot-de-detections
cd mon-depot-de-detections
contentctl init
```
Cela va créer plusieurs dossiers, dont :
- `detections/` : Où vous placerez vos fichiers YAML de détection.
- `tests/` : Pour les données de test (fichiers YAML qui pointent vers des données brutes).
- `lookups/` et `macros/` : Pour les dépendances de vos recherches.

### Créer une nouvelle règle (YAML)
Vous pouvez maintenant créer un fichier YAML dans le dossier `detections/`. Voici à quoi ressemble une structure type (simplifiée) :
```
name: Detection de Force Brute Personnalisee
id: 123e4567-e89b-12d3-a456-426614174000
version: 1
date: '2026-04-15'
author: Votre Nom
type: TTP
datamodel: [Authentication]
description: Détecte les tentatives de connexion échouées répétées.
search: '| tstats count from datamodel=Authentication where Authentication.action="failure" by Authentication.user | where count > 10'
how_to_implement: Assurez-vous que le modèle de données Authentication est peuplé.
known_false_positives: Tests de charge, scripts d'automatisation.
tags:
  analytic_story: [Suspicious Authentication]
  asset_type: Endpoint
  mitre_attack_id: [T1110]
```
### Valider votre règle
Une fois votre fichier YAML écrit, utilisez `contentctl` pour vérifier qu'il n'y a pas d'erreurs de syntaxe ou de champs manquants :
```bash
contentctl validate
```
### Tester la détection (Optionnel mais recommandé)
Si vous avez des fichiers de données de test (fichiers JSON avec des logs), vous pouvez simuler l'attaque pour voir si votre règle déclenche bien une alerte :
```bash
contentctl test --start_splunk
```
_Note : Cela nécessite Docker car `contentctl` va monter une instance Splunk temporaire pour exécuter le test._
### Générer le package pour Splunk
Une fois que vos règles sont prêtes et validées, vous devez les transformer en une application Splunk (ou un fichier de configuration exploitable) :
```bash
contentctl build
```
Le résultat se trouvera dans un dossier `dist/`. Vous y trouverez une application Splunk (`.tar.gz`) que vous pourrez installer directement sur votre serveur Splunk ou votre Search Head.
### Pourquoi procéder ainsi ?
1. **Versionnage :** Vous pouvez mettre votre dossier sous Git et suivre chaque modification de vos règles.
2. **Standardisation :** Toutes vos règles ont le même format, ce qui facilite le transfert de connaissances.
3. **Automatisation (CI/CD) :** Vous pouvez intégrer `contentctl validate` dans un pipeline GitLab CI ou GitHub Actions pour que chaque règle soit vérifiée automatiquement avant d'être déployée en production.
**Conseil :** Pour vos premières règles, n'hésitez pas à copier un fichier YAML existant du dépôt [splunk/security_content](https://github.com/splunk/security_content/tree/develop/detections) et à le modifier pour l'adapter à vos besoins.

Types available:
- TTP
- Anomaly
- Hunting
- Correlation

|Si votre règle détecte...|Choisissez...|
|:--|:--|
|Une attaque précise et confirmée|`TTP`|
|Un comportement bizarre mais peut-être légitime|`Anomaly`|
|Une recherche large pour "fouiller" les logs|`Hunting`|
|Un enchaînement d'alertes|`Correlation`|
