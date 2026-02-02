# Log Generator - Outil de Test SIEM

Un puissant générateur de logs pour tester les systèmes SIEM. Génère des logs réalistes provenant de diverses sources incluant des serveurs web Apache et des journaux de sécurité Windows.

## Fonctionnalités

- 🎯 **Multiple Types de Logs**: Logs d'accès Apache, Logs de sécurité Windows (avec 12 Event IDs communs)
- 🎛️ **Gestion Facile**: Interface web pour créer, activer/désactiver, cloner et supprimer les senders
- ⚡ **Fréquence Configurable**: Contrôlez combien de logs par seconde chaque sender génère
- 📊 **Monitoring en Temps Réel**: Voyez le nombre de logs générés en temps réel
- 🔄 **Multi-thread**: Exécutez plusieurs senders simultanément sans blocage
- 📝 **Sortie Réaliste**: Les logs sont identiques à ceux produits par de vrais serveurs/endpoints

## Installation

1. Installer les dépendances Python:
```bash
pip install -r requirements.txt
```

2. Lancer l'application:
```bash
python3 app.py
```

3. Ouvrir le navigateur à: `http://localhost:5000`

## Utilisation

### Créer un Sender

1. Ouvrir l'interface web
2. Remplir le formulaire:
   - **Nom du Sender**: Un nom descriptif (ex: "Logs Serveur Web")
   - **Type de Log**: Choisir Apache Access Log ou Windows Security Event Log
   - **Destination**: Chemin complet où les logs seront écrits (ex: `/tmp/logs/apache.log`)
   - **Fréquence**: Logs par seconde (1-1000)
   - **Démarrer Immédiatement**: Cocher pour activer tout de suite

3. Cliquer sur "Create Sender"

### Gérer les Senders

Chaque carte de sender affiche:
- Statut actuel (Running/Stopped)
- Fichier de destination
- Fréquence
- Total de logs générés
- Date de création

Actions disponibles:
- **⏸️/▶️ Toggle**: Démarrer/arrêter la génération de logs
- **📋 Clone**: Dupliquer le sender avec les mêmes paramètres
- **🗑️ Delete**: Supprimer définitivement le sender

## Types de Logs

### Apache Access Log
Génère des logs au format Combined Log Format identiques aux vrais serveurs Apache/Nginx:
```
192.168.1.100 - - [02/Feb/2026:18:52:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://www.google.com/" "Mozilla/5.0..."
```

Caractéristiques:
- Adresses IP réalistes
- Méthodes HTTP variées (GET, POST)
- Mix de codes de statut (200, 404, 403, 500)
- User agents authentiques (Chrome, Firefox, Safari, Mobile)
- Distribution de requêtes pondérée

### Windows Security Event Log
Génère des logs Windows authentiques au format XML avec 12 Event IDs communs:

- **4624**: Connexion Réussie
- **4625**: Échec de Connexion
- **4634**: Déconnexion
- **4672**: Privilèges Spéciaux Assignés
- **4688**: Processus Créé
- **4689**: Processus Terminé
- **4698**: Tâche Planifiée Créée
- **4699**: Tâche Planifiée Supprimée
- **4720**: Compte Utilisateur Créé
- **4726**: Compte Utilisateur Supprimé
- **4732**: Membre Ajouté au Groupe de Sécurité
- **4756**: Membre Ajouté au Groupe de Sécurité Universel

Chaque événement inclut:
- Structure XML appropriée correspondant à Windows Event Viewer
- Noms d'utilisateurs, domaines, postes de travail réalistes
- Chemins de processus précis
- SIDs et Logon IDs valides

## Structure du Projet

```
log-generator/
├── app.py                    # Application web Flask
├── log_senders.py           # Gestion des senders et threading
├── log_generators/
│   ├── __init__.py
│   ├── apache.py            # Générateur de logs Apache
│   └── windows.py           # Générateur de logs Windows
├── templates/
│   └── index.html           # Interface web
├── static/
│   ├── css/
│   │   └── style.css        # Styles
│   └── js/
│       └── app.js           # JavaScript frontend
└── requirements.txt
```

## Améliorations Futures

Fonctionnalités prévues:
- Plus de types de logs (Palo Alto, Cisco, AWS CloudTrail, etc.)
- Sortie HTTP Event Collector (HEC) pour Splunk
- Support de sortie Syslog
- Mode benchmark pour tests de performance
- Options de filtrage/personnalisation des logs
- Tableau de bord de statistiques et métriques

## Détails Techniques

- **Backend**: Python 3 avec Flask
- **Threading**: Génération de logs multi-thread utilisant le module threading de Python
- **Stockage**: Configuration basée sur JSON (senders_config.json)
- **Frontend**: JavaScript vanilla avec CSS responsive

## Ajouter un Nouveau Type de Log

1. Créer une nouvelle classe de générateur dans `log_generators/`
2. Implémenter une méthode `generate()` qui retourne une seule ligne de log
3. L'enregistrer dans `SenderManager.log_generators` (log_senders.py)
4. L'ajouter au dropdown dans le frontend

Exemple:
```python
class MyLogGenerator:
    def generate(self):
        # Votre logique de génération de logs
        return "votre ligne de log ici"
```

## Démarrage Rapide

1. **Installer les dépendances:**
   ```bash
   cd log-generator
   pip3 install -r requirements.txt
   ```

2. **Lancer l'application:**
   ```bash
   python3 app.py
   ```

3. **Ouvrir dans le navigateur:**
   ```
   http://localhost:5000
   ```

## Licence

MIT License - libre d'utilisation et de modification!
