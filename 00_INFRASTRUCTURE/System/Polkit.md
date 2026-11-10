### 1. Validate systemd name 

`systemctl list-unit-files | grep -i splunk`
### 2. Create polkit rule

Sur RHEL 7/8/9, Polkit utilise des règles au format JavaScript dans `/etc/polkit-1/rules.d/`.

Créez un fichier de règles (par exemple `/etc/polkit-1/rules.d/10-splunk.rules`) :

`sudo vi /etc/polkit-1/rules.d/10-splunk.rules`

Insérez la règle suivante (qui gère à la fois `splunk.service` et `Splunkd.service`) :

```
polkit.addRule(function(action, subject) { if (action.id == "org.freedesktop.systemd1.manage-units" && (action.lookup("unit") == "splunk.service" || action.lookup("unit") == "Splunkd.service") && subject.user == "splunk") { return polkit.Result.YES; } });
```

> **Ce que fait cette règle :**
> 
> - Intercepte l'action D-Bus `org.freedesktop.systemd1.manage-units` (qui contrôle `start`, `stop`, `restart`, `reload`).  
>     
> - Vérifie que l'unité ciblée est bien `splunk.service` ou `Splunkd.service`.  
>     
> - Vérifie que l'utilisateur exécutant la commande est `splunk`.  
>     
> - Renvoie `polkit.Result.YES` (accès autorisé sans demander de mot de passe).  
>     
### 3. Permissions
Le service `polkitd` s'exécute sous son propre compte de service et nécessite des permissions strictes sur `/etc/polkit-1/rules.d/` :

```
sudo chown root:root /etc/polkit-1/rules.d/10-splunk.rules 
sudo chmod 0644 /etc/polkit-1/rules.d/10-splunk.rules
```
_(Sur certaines versions durcies de RHEL où le répertoire appartient à_ `polkitd`, assurez-vous que `polkitd` peut lire le fichier).
### Étape 4 : Reload Polkit and validate syntax
Polkit surveille automatiquement le répertoire via _inotify_, mais il est recommandé de redémarrer le service pour valider qu'il n'y a aucune erreur de syntaxe JS :
```
sudo systemctl restart polkit
```

Vérifiez les logs pour vous assurer que la règle a été chargée sans erreur :

`sudo journalctl -u polkit -n 20 --no-pager`

_(S'il y a une erreur dans le code JavaScript,_ `polkitd` la signalera explicitement ici).
### 5. Tests
With the splunk user:
`systemctl stop Splunkd.service`

La commande s'exécute immédiatement sans invite de mot de passe.

---

### En cas de blocage ou d'échec

1. **Vérifier l'action exacte bloquée en direct :**  
    Lancez dans un terminal séparé :
    
    `journalctl -f -u polkit`
    
    Puis relancez la commande `systemctl restart splunk` en tant que `splunk`. Vous verrez si Polkit refuse l'action ou s'il s'agit d'un nom d'unité différent (ex. `splunk@...` si instancié).
    
2. **Gestion des fichiers d'unité (**`enable` / `disable`) :  
    Si vous souhaitez aussi autoriser `enable` ou `disable`, ajoutez l'action `org.freedesktop.systemd1.manage-unit-files` dans la condition du script Polkit.