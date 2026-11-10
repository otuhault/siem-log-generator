```
alias splunk="/opt/splunk/bin/splunk"
echo 'alias splunk="/opt/splunk/bin/splunk"' >> ~/.bashrc
```
### Cluster Administration
#### Deployment Server Reload
```
./splunk reload deploy-server
./splunk reload deploy-server -class my_serverclass
./splunk reload deploy-server -class my_serverclass -validate-only true
./splunk reload deploy-server -ignore-conflict true
```
- **class**: serverclass to be reloaded.
- **validate-only**: Do not reload the serverclass; log possible validation errors in splunkd.log
- **ignore-conflict**: Ignore current changes on the shared drive and enforce the reload
- **timeout**: Time CLI waits for operation to complete before exiting.
#### Deploy SHCluster Bundle
```
./splunk apply shcluster-bundle -target :<management_port>
```
#### Deploy Indexer Bundle
```
./splunk apply cluster-bundle
```


### Reset admin password
- Backup /opt/splunk/etc/passwd
- Create the file: /opt/splunk/etc/system/local/user-seed.conf with:
```
[user_info]
USERNAME = admin
PASSWORD = password
```
- Remove etc/password file and restart splunk
### Remove SAML Users
```
curl -k -u test_user:<PWD> --request DELETE https://splunkurl/services/admin/SAML-user-role-map/<username>
```
Think to encode the url .
### Enable boot start with systemd
```
./splunk enable boot-start -user splunk -systemd-managed 1 -create-polkit-rules 1
# Install policykit
apt install policykit-1
```

### Debug configurations
```
# In memory
`./splunk show config serverclass`
# In files
`./splunk btool serverclass list --debug | grep -v system/default`
# Check bad stanzas
./splunk btool check
```

### Granting an additional user read access with **setfacl**
```
setfacl -m u:splunk:r /var/log/access.log
```

### Forgot a single file from the **fishbucket**
```
./splunk cmd btprobe -d $SPLUNK_HOME/var/lib/splunk/fishbucket/splunk_private_db --file $FILE --reset
```

### Transparent Huge Page
```
sudo echo never > /sys/kernel/mm/transparent_hugepage/enabled sudo echo never > /sys/kernel/mm/transparent_hugepage/defrag
```
**Persistant**
`vim /etc/default/grub`
```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash transparent_hugepage=never"
```
### ulimits
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

### Generate HEC CLI
```
splunk http-event-collector create <token-name> \
  -uri https://<host>:8089 \
  -description "My HEC token" \
  -index <index_name> \
  -sourcetype <sourcetype>
```
