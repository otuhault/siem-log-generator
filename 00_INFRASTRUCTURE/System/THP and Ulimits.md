### Transparent Huge Page
#### Temporary
```
sudo echo never > /sys/kernel/mm/transparent_hugepage/enabled 
sudo echo never > /sys/kernel/mm/transparent_hugepage/defrag
```
#### Persistant
##### Tuned
1. Install tuned
```
sudo apt install tuned # Ubuntu/Debian 
sudo yum install tuned # RHEL/CentOS
```
2. sudo vim /etc/tuned/splunk-profile/tuned.conf
```
[main]
summary=Profile optimised for Splunk performance
include=throughput-performance

[vm]
transparent_hugepages=never
```
3. Activate the profile
```
sudo tuned-adm profile splunk-profile
```
4. Start and Enable tuned
```
sudo systemctl enable tuned 
sudo systemctl start tuned
```
5. Validate THP is disabled
```
cat /sys/kernel/mm/transparent_hugepage/enabled 
cat /sys/kernel/mm/transparent_hugepage/defrag
```
##### systemctl
- Edit: */etc/systemd/system/disable-thp.service*
```
[Unit]
Description=Disable Transparent Huge Pages (THP)
Before=splunk.service mongodb.service redis.service
[Service]
Type=oneshot
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
```
- `systemctl daemon-reload`
- `systemctl enable disable-thp.service`
- Reboot pour confirmer
> Si tu utilises **RHEL/CentOS**, les chemins peuvent être /sys/kernel/mm/redhat_transparent_hugepage/ au lieu de /sys/kernel/mm/transparent_hugepage/. Adapte le ExecStart en conséquence

- Vérifie que des outils comme tuned ou ktune ne réactivent pas les THP. Désactive-les si nécessaire :
##### rc.local
- Edit: */etc/rc.local*
```
#!/bin/bash
if test -f /sys/kernel/mm/transparent_hugepage/enabled; then
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
fi
if test -f /sys/kernel/mm/transparent_hugepage/defrag; then
    echo never > /sys/kernel/mm/transparent_hugepage/defrag
fi
# Redémarrer les services sensibles aux THP (optionnel)
systemctl restart splunk
systemctl restart redis
systemctl restart mongod
exit 0
```

- Make the file executable:
`chmod +x /etc/rc.d/rc.local`
- Reboot to validate
##### Grub
- Edit: */etc/default/grub*
- Add/Modify the following:
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash transparent_hugepage=never"
```

```
sudo update-grub # Ubuntu 
sudo grub2-mkconfig -o /boot/grub2/grub.cfg # CentOS/RHEL
```
- Reboot to validate
### Ulimits
```
ulimits -a
```
Éditez le fichier des limites :
`vim /etc/security/limits.conf`

```
splunk soft nofile 65536 
splunk hard nofile 65536 
splunk soft nproc 4096 
splunk hard nproc 4096 
splunk soft memlock unlimited 
splunk hard memlock unlimited 
splunk soft as unlimited
splunk hard as unlimited
```
Reboot the OS and confirm with splunkd.log that Splunk process is under the correct settings
```
cat /opt/splunk/var/log/splunk/splunkd.log | grep ulimit
```

