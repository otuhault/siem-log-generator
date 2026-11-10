```bash
# Démarrer tous les composants 
/opt/soar/bin/start_phantom.sh 
# Arrêter tous les composants 
/opt/soar/bin/stop_phantom.sh 
# Redémarrage propre 
/opt/soar/bin/stop_phantom.sh && /opt/soar/bin/start_phantom.sh
```
#### Gestion du démarrage automatique (Boot-Start / Systemd)
Contrairement à Splunk Enterprise (`splunk enable boot-start`), en mode non-privilégié (`unprivileged`), Splunk SOAR utilise **systemd en mode utilisateur** et la fonctionnalité `linger` :

```bash
# En tant que root : s'assurer que le user SOAR reste actif au boot 
sudo loginctl enable-linger soar_user 
# En tant que soar_user : piloter les services via systemd user si configuré
systemctl --user status phantom 
systemctl --user restart phantom
```

### Gestion granulaire avec `phsvc`
Le script `phsvc` permet de vérifier le statut, démarrer, arrêter ou redémarrer chaque démon individuellement.
#### Syntaxe:
```bash
/opt/soar/bin/phsvc <action> <servicename>
```
#### Exemples d'utilisation courante :
- **Vérifier le statut d'un service :**
    `/opt/soar/bin/phsvc status postgresql /opt/soar/bin/phsvc status uwsgi /opt/soar/bin/phsvc status nginx /opt/soar/bin/phsvc status phantom_decided`
- **Redémarrer uniquement l'interface Web / API (**`uwsgi` ou `nginx`) sans couper l'ingestion :
    `/opt/soar/bin/phsvc restart uwsgi /opt/soar/bin/phsvc restart nginx`
- **Redémarrer le moteur de playbooks & décisions :**
    `/opt/soar/bin/phsvc restart phantom_decided /opt/soar/bin/phsvc restart phantom_workflowd`
- **Vérifier le statut de tous les services en une boucle bash :**
    `for s in postgresql pgbouncer phantom_internal_broker nginx uwsgi phantom_decided phantom_ingestd phantom_workflowd phantom_watchdogd; do echo -n "$s: " /opt/soar/bin/phsvc status $s done`
---
### Liste des services et leurs rôles

|   |   |
|---|---|
|Nom du service (`phsvc`)|Rôle dans SOAR|
|`postgresql`|Base de données relationnelle principale (stocke containers, artefacts, configurations, audit)|
|`pgbouncer`|Pooler de connexions léger pour PostgreSQL|
|`phantom_internal_broker`|Broker de messages RabbitMQ / communication inter-processus|
|`nginx`|Serveur Web frontal (Reverse Proxy HTTPS)|
|`uwsgi`|Serveur d'application Django / API REST / Interface utilisateur|
|`phantom_decided`|Moteur central de prise de décision et d'exécution des playbooks|
|`phantom_workflowd`|Gestionnaire d'états et de workflows|
|`phantom_ingestd`|Démon responsable des apps de polling et de la collecte d'événements|
|`phantom_watchdogd`|Surveillance interne et redémarrage automatique des démons en échec|
|`phantom_clusterd`|Gestion du quorum et du clustering (actif uniquement si cluster activé)|
|`splunk_forwarder`|Universal Forwarder intégré (pour exporter les logs SOAR vers Splunk)|

---
### Autres scripts utiles dans votre dossier `/opt/soar/bin/`
- `phenv` : Indispensable pour exécuter n'importe quelle commande Python dans l'environnement SOAR :
    `/opt/soar/bin/phenv python3`
    
- `backup.pyc` / `restore.pyc` : Outils intégrés de sauvegarde et restauration :
    `/opt/soar/bin/phenv python3 /opt/soar/bin/backup.pyc --help`
    
- `import_cert.py` : Importation de certificats CA ou de serveurs personnalisés :
    `/opt/soar/bin/phenv python3 /opt/soar/bin/import_cert.py -f /chemin/vers/certificat.crt`

- `clean_restart_scheduled.sh` : Script standard utilisé pour le redémarrage périodique programmé (cron) évitant les fuites mémoire résiduelles.