Focus on warm standby implementation as this is the most common one on-prem.

User is usually **phantom** or **soar**.

Firewalld (required)
```bash
sudo systemctl status firewalld

# If not installed: 
sudo dnf install -y firewalld
sudo systemctl enable --now firewalld
```

```bash
sudo yum install -y wget tar nfs-utils chrony net-tools bind-utils
```

```bash
sudo mkdir -p /opt/soar 
sudo tar -zxf splunk_soar-unpriv-<version>.tgz -C /opt 
sudo mv /opt/splunk-soar/* /opt/soar/ 
sudo chown -R soar_user:soar_user /opt/soar
```

For a lab with OS!=Redhat:
```bash
sudo dnf install -y epel-release 
sudo dnf config-manager --set-enabled crb
# Sauvegarder le fichier d'origine 
sudo cp /etc/os-release /etc/os-release.bak 
# Remplacer ID="rocky" par ID="rhel" 
sudo sed -i 's/^ID="rocky"/ID="rhel"/' /etc/os-release
```

Pour une installation **Standalone / Lab**, n'incluez pas `--gluster-fs` (inutile hors cluster multi-nœuds). Vous pouvez inclure les services recommandés :
```bash
sudo ./soar-prepare-system \ 
--splunk-soar-home /opt/soar \ 
--splunk-soar-user soar_user \ 
--chronyd-service \ 
--sysstat-service \ 
--enable-linger \ 
--firewall \ 
--port-forward
```
