

|                                                                        |               |            |       |            |          |
| ---------------------------------------------------------------------- | ------------- | ---------- | ----- | ---------- | -------- |
| ci1_01091-EDU-31295-emplo000000000072547-cm1.students.splunk.education | 3.15.4.125    | 10.0.0.37  | admin | sccStudent | 3es3b4se |
| ci1_01091-EDU-31295-emplo000000000072547-mc1.students.splunk.education | 3.135.188.213 | 10.0.2.253 | admin | sccStudent | 3es3b4se |


SearchHead-1 :  
ci1-emplo000000000072547-sh1

ci1_01091-EDU-31295-emplo000000000072547-sh1.students.splunk.education
ci1_01091-EDU-31295-emplo000000000072547-sh1.students.splunk.education
Indexers: 
- ci1-emplo000000000072547-idx1
- ci1-emplo000000000072547-idx2

3es3b4se

# Lab 1
CM1: Splunk 9.0.6 (build 050c9bca8588)
```
[clustering]
/opt/splunk/etc/apps/org_cluster_manager_base/local/server.conf        pass4SymmKey = $7$xQfI3R0uEZ0+nZN7ilaP3G0vowfscWQrq8d0O69j1gyUXf5ER1oh5Q==

q327htk9

[general]
/opt/splunk/etc/system/local/server.conf                               pass4SymmKey = $7$/EqYzBYwIk+z8PbxW+z7fdPHNIaXxi/8f5nvWfKzfWnf8zUXSrpk3Q==
changeme

```

![[Pasted image 20241202162156.png]]

![[Pasted image 20241202163144.png]]
![[Pasted image 20241202163208.png]]
![[Pasted image 20241202163257.png]]
![[Pasted image 20241202163327.png]]

# Lab 2
![[Pasted image 20241203102725.png]]
![[Pasted image 20241203104548.png]]
![[Pasted image 20241203112546.png]]
![[Pasted image 20241203112609.png]]

8sebz379


/var/log/maillog
sourcetype = maillog

/var/log/cloud-init.log
sourcetype = cloud-init

/var/data/appserver
sourcetype = appserver

```
[maillog]
TIME_PREFIX=^
TIME_FORMAT=%b %d %H:%M:%S
MAX_TIMESTAMP_LOOKAHEAD=15
LINE_BREAKER=([\r\n]+)
SHOULD_LINEMERGE=false
TRUNCATE=10000

[cloud-init]
TIME_PREFIX=^
TIME_FORMAT=%Y-%m-%d %H:%M:%S,%Q
MAX_TIMESTAMP_LOOKAHEAD=23
LINE_BREAKER=([\r\n]+)
SHOULD_LINEMERGE=false
TRUNCATE=10000

[appserver]
TIME_PREFIX=^\[
TIME_FORMAT=%d-%m-%y %H:%M:%S:%Q %Z
MAX_TIMESTAMP_LOOKAHEAD=25
LINE_BREAKER=([\r\n]+)
SHOULD_LINEMERGE=false
TRUNCATE=12000
```


```
pt/splunkforwarder/etc/apps/scc2_linux_appserver_inputs/local/inputs.conf [monitor:///var/data/appserver]
/opt/splunkforwarder/etc/apps/scc2_linux_appserver_inputs/local/inputs.conf disabled = false
/opt/splunkforwarder/etc/apps/scc2_linux_appserver_inputs/local/inputs.conf index = linux
/opt/splunkforwarder/etc/apps/scc2_linux_appserver_inputs/local/inputs.conf sourcetype = appserver
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    [monitor:///var/data/syslog]
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    disabled = 1
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    index = linux
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    sourcetype = syslog
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    [monitor:///var/log]
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    disabled = false
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    index = linux
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    recursive = false
/opt/splunkforwarder/etc/apps/scc2_linux_syslog_inputs/local/inputs.conf    sourcetype = syslog
```


uf -> hf -> indexers

`setfacl -m u:user1:r fichier.txt`

# Lab 3
`scp -r user@192.168.1.10:/home/user/documents /local/path`
![[Pasted image 20241203162351.png]]

c3jpmgnv

``` authentication
[ProdLDAP]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = cn=admin,dc=splunk,dc=training
bindDNpassword = c3jpmgnv
bindDNpassword = $7$slNDtwgSH0oL5G2+Eg/NiuMelUT/KZLxSj+S3S/n83R/M7KHcG17mA==
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = ou=Groups,dc=splunk,dc=training
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = 10.0.1.175
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = ou=people,dc=splunk,dc=training
userNameAttribute = uid

[authentication]
authSettings = ProdLDAP
authType = LDAP

[roleMap_ProdLDAP]
student = Students
```

```authorize
[role_student]
grantableRoles = student
importRoles = admin
srchMaxTime = 8640000
srchTimeEarliest = -1
srchTimeWin = -1
```

# Lab 4
![[Pasted image 20241204105729.png]]
![[Pasted image 20241204120123.png]]
![[Pasted image 20241204120135.png]]
![[Pasted image 20241204120155.png]]

ym0lq09e
https://docs.splunk.com/Documentation/Splunk/latest/Data/Aboutindexedfieldextraction
https://docs.splunk.com/Documentation/Splunk/latest/Data/Configureindex-timefieldextraction

default syslog behavior to set host from the events
device combo --> UF, sample log

add indexed field: splunk_orig_fwd

UF:
```
[monitor:///var/data/appserver]
disabled = false
index = linux
sourcetype = appserver

[monitor:///var/data/syslog]
disabled = 1
index = linux
sourcetype = syslog

[monitor:///var/log]
disabled = false
index = linux
recursive = false
sourcetype = syslog
```
HF:
```
[monitor:///var/data/syslog]
disabled = 1
index = Linux
sourcetype = syslog

[monitor:///var/log]
disabled = false
index = linux
recursive = false
sourcetype = syslog
```
TRANSFORMS = syslog-host
TRANSFORMS-save_orig_host = save_orig_host

IDX:
```
props.conf
[syslog]
TRANSFORMS-save_orig_host = save_orig_host

transforms.conf
[save_orig_host]
REGEX = host::(.*)
SOURCE_KEY = MetaData:Host
WRITE_META = true
FORMAT = splunk_orig_fwd::$1
```

fields.conf > Search Head
```
[save_orig_host]
INDEXED=true
```

extract host from syslog
```
props.conf
[syslog]
TRANSFORMS-extract_syslog_host = extract_syslog_host

transforms.conf
[extract_syslog_host]
REGEX = ^\w{3}\s\d{1,2}\s\d{2}:\d{2}:\d{2}\s(\S+)\s
DEST_KEY = MetaData:Host
FORMAT = host::$1
```


TRANSFORMS = syslog-host
TRANSFORMS-extract_syslog_host = extract_syslog_host
TRANSFORMS-save_orig_host = save_orig_host

# Lab 5
Upgrade splunk

# Lab6
![[Pasted image 20241205133236.png]]
![[Pasted image 20241205133209.png]]

# Lab 7
DS Failover

# Lab 8
![[Pasted image 20241206141758.png]]
![[Pasted image 20241206141814.png]]
https://docs.splunk.com/Documentation/Splunk/latest/DistSearch/SHCdeploymentoverview
https://splunkbase.splunk.com/app/1581
https://splunkbase.splunk.com/app/1564

Instructor role in splunk can access fire brigade and search app

LDAP Instructors group -> Splunk Instructor role

replication port: 9887
Deployer
```
[shclustering]
pass4SymmKey = shclusterp4ss
shcluster_label = shcluster1
```

```
splunk init shcluster-config -mgmt_uri https://10.0.2.52:8089 -replication_port 9887 -replication_factor 3 -conf_deploy_fetch_url https://10.0.0.101:8089 -secret shclusterp4ss -shcluster_label shcluster1

splunk init shcluster-config -mgmt_uri https://10.0.7.212:8089 -replication_port 9887 -replication_factor 3 -conf_deploy_fetch_url https://10.0.0.101:8089 -secret shclusterp4ss -shcluster_label shcluster1

splunk init shcluster-config -mgmt_uri https://10.0.4.69:8089 -replication_port 9887 -replication_factor 3 -conf_deploy_fetch_url https://10.0.0.101:8089 -secret shclusterp4ss -shcluster_label shcluster1

splunk restart
```

bootstrap captain
```
splunk bootstrap shcluster-captain -servers_list "https://10.0.2.52:8089,https://10.0.7.212:8089,https://10.0.4.69:8089"
```
