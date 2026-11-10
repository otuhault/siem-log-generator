https://github.com/doksu/selinux_policy_for_splunk
### State Check
```bash
# Afficher le statut actuel
sestatus

# Afficher le mode en cours
getenforce
```
### Change temporarily the mode
```bash
# Passer en mode permissive (les règles sont loggées mais non bloquantes)
sudo setenforce 0

# Repasser en mode enforcing
sudo setenforce 1
```
### Fix issue with Splunk
```
restorecon -Rv /opt/splunk
restorecon -Rv /opt/splunkforwarder
```

### Disable SELinux permanently
```bash
# Éditer le fichier de configuration
sudo vi /etc/selinux/config

# Modifier la ligne :
# SELINUX=enforcing 
SELINUX=disabled  
SELINUX=permissive

# Redémarrage nécessaire
sudo reboot
```
### Surveiller activement les logs AVC
En mode permissive, **SELinux logge toutes les violations** sans les bloquer. Il est essentiel de les surveiller.
```bash
# Installer les outils d'audit si absents
sudo yum install -y setroubleshoot-server audit policycoreutils-python-utils

# Vérifier que auditd tourne
sudo systemctl status auditd
sudo systemctl enable --now auditd

# Consulter les violations récentes liées à Splunk
sudo ausearch -m AVC,USER_AVC -ts today | grep -i splunk

# Analyse plus lisible
sudo sealert -a /var/log/audit/audit.log > /tmp/selinux_report.txt
```
### Manage specific ports
```bash
# Installer les outils nécessaires
sudo yum install -y policycoreutils-python-utils   # RHEL/CentOS 8+
sudo yum install -y policycoreutils-python          # RHEL/CentOS 7

# Lister les ports autorisés
sudo semanage port -l | grep http

# Autoriser les ports Splunk courants
sudo semanage port -a -t http_port_t -p tcp 8000    # Splunk Web
sudo semanage port -a -t http_port_t -p tcp 8089    # Splunkd management
sudo semanage port -a -t http_port_t -p tcp 9997    # Forwarder
sudo semanage port -a -t http_port_t -p tcp 8088    # HEC (HTTP Event Collector)

# Modifier un port existant
sudo semanage port -m -t http_port_t -p tcp 8000

# Supprimer un port
sudo semanage port -d -t http_port_t -p tcp 8000
```

