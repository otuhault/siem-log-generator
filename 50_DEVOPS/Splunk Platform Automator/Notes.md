## 1. Les Workflows
**Workflow**: séquence ordonnée de tâches Ansible appliquées à une partie de l'infra Splunk définie dans le YAML de l'inventaire.

Exemples typiques de workflows livrés :
- `install_splunk` — déploie le binaire Splunk sur les hôtes ciblés
- `configure_splunk` — applique la config (apps, indexes, conf files)
- `start_splunk` / `stop_splunk` / `restart_splunk`
- `cluster_bootstrap` — initialise un cluster indexer
- `shc_bootstrap` — initialise un Search Head Cluster
- `upgrade_splunk` — upgrade contrôlé
- `apply_splunk_config` — push de configs sans redémarrage complet
- `show_splunk` — inventaire/diagnostic

Comment on les configure ?
- Définition de l'infra via le fichier YAML principal
- Lancement du workflow:
	```bash
	./splunk_platform_automator.sh -w install_splunk
	./splunk_platform_automator.sh -w configure_splunk -l idxc1
	./splunk_platform_automator.sh -w show_splunk
	```
Le `-l` (limit) restreint aux hôtes/groupes ciblés. Tu peux aussi passer `-t` pour les tags

## 2. Les Tags
Les tags sont **des étiquettes Ansible** posées sur les tâches à l'intérieur des rôles. Ils te permettent de **n'exécuter qu'une partie** d'un workflow sans tout rejouer.

Exemples de tags courants dans SPA :
- `splunk_install` — uniquement les tâches d'installation binaire
- `splunk_config` — uniquement la génération/push des `.conf`
- `splunk_apps` — uniquement le déploiement d'apps
- `splunk_systemd` — uniquement la gestion du service
- `splunk_license`
- `splunk_certs` / `splunk_tls`
- `splunk_users`
- `splunk_indexes`
- `splunk_outputs` / `splunk_inputs`
```bash
# Ne refaire que la partie indexes sans redémarrer ni réinstaller
./splunk_platform_automator.sh -w configure_splunk -t splunk_indexes

# Combiner
./splunk_platform_automator.sh -w configure_splunk -t splunk_apps,splunk_outputs

# Exclure
./splunk_platform_automator.sh -w configure_splunk --skip-tags splunk_certs
```

## 3. Le Runner
**Le runner est l'hôte qui exécute Ansible**.
Configuration typique :
- Une **VM/instance on-prem** (souvent Linux, RHEL/Ubuntu)
- Python + Ansible installés (versions compatibles avec SPA — vérifier le `requirements.txt` du repo)
- Le repo SPA cloné depuis Git (souvent en CI/CD ou simplement `git pull` manuel)
- Ton repo de **configs Splunk** (le fameux `splunk-configs` qui contient les apps, baseconfigs, certs chiffrés via ansible-vault)
- **SSH clé privée** vers tous les hôtes Splunk cibles (l'utilisateur `splunk` ou un utilisateur avec sudo)
- Accès réseau sortant vers les cibles (port 22) et entrant depuis qui pilote (toi, Jenkins, GitLab Runner, AAP/AWX…)

Variantes possibles :
- **Runner manuel** : tu te connectes en SSH et tu lances `./splunk_platform_automator.sh`
- **Runner CI** : GitLab Runner / Jenkins / GitHub Actions self-hosted qui déclenche les workflows sur push ou MR mergée
- **Ansible Automation Platform (AAP/AWX)** : le runner devient un _execution environment_, avec inventaire et credentials gérés dans AAP

Bonnes pratiques :
- Le runner doit être **stateless autant que possible** : tout vient de Git
- Les **secrets** (admin password, certs) chiffrés avec `ansible-vault`, la passphrase injectée par le CI ou un coffre (Vault/CyberArk)
- Loguer les runs (artefacts CI ou `ansible.log`)
- Idempotence : tu dois pouvoir rejouer un workflow plusieurs fois sans casser

