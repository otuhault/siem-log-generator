**Contexte** : Edge Processor (EP) on-prem n'est pas un simple ajout à splunkd — c'est un binaire standalone qui communique avec le control plane Splunk Cloud (Data Manager). Il faut le traiter comme un service indépendant.
## 1. Placement / Sizing
- Dédier des hosts spécifiques EP, **ne pas colocaliser** avec indexer/SH/HF en prod
- Minimum recommandé : 4 vCPU / 8GB RAM par instance (à ajuster selon débit EPS)
- Prévoir 3 nœuds pour HA (load balancing devant, pas de clustering natif EP)
- Disque : volume séparé pour la persistent queue (buffer local), SSD recommandé, sizing selon débit x durée de rétention souhaitée en cas de coupure réseau
## 2. Utilisateur système
- Créer un user dédié non-root (ex: `splunkep`), pas de run en root
- Ownership complet sur le dossier d'install et la persistent queue
- Pas de sudo nécessaire pour le fonctionnement runtime, seulement à l'install
## 3. Systemd
- Unit file dédié (`edge-processor.service`), pas de script maison
- Points clés à vérifier/configurer :
    - `Restart=on-failure` + `RestartSec`
    - `LimitNOFILE` élevé (file descriptors, débit réseau élevé)
    - `User=`/`Group=` pointant vers le user dédié
    - `WorkingDirectory` explicite
    - Logs redirigés vers journald **et** vers fichier local pour rétention longue
- `systemctl enable` dès l'install pour survie au reboot

```
[Service]
User=splunkedge
Group=splunk-edge-grp
KillMode=mixed
```

```bash
sudo chown -R splunkedge: <install_directory>
sudo cp <install_directory>/etc/splunk-edge.service /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl enable splunk-edge
sudo systemctl start splunk-edge
sudo systemctl status splunk-edge.service
```
## 4. Réseau
- Flux **sortant uniquement** requis vers le control plane Splunk Cloud (HTTPS/443) — pas de flux entrant depuis Splunk Cloud
- Domaines à whitelister : endpoints `*.splunkcloud.com` / `*.splunk.com` liés au tenant Data Manager (à confirmer exactement dans ta doc d'admin console)
- Proxy : si proxy d'entreprise, **le proxy doit être utilisé** pour ces appels control-plane (ne pas les mettre dans no_proxy par erreur — piège fréquent, à l'inverse de ce qu'on ferait pour du trafic interne)
- Flux entrants côté sources (HEC, syslog, S2S 9997) à ouvrir selon les inputs configurés
## 5. Sécurité / Secrets
- Le client ID/secret du Data Manager doit être stocké de façon restreinte (permissions fichier 600, user dédié uniquement)
- TLS : valider la CA trust store si certs internes utilisés pour les inputs
## 6. Monitoring
- Vérifier logs locaux du binaire EP en plus de `_internal`
- Mettre en place un health check systemd (`ExecStartPre` ou monitoring externe) sur le port de health de l'EP
## 7. Upgrade
- Versionner explicitement le binaire (pas de "latest" en prod)
- Process : drain trafic → stop → upgrade binaire → start → vérifier health avant reprise trafic