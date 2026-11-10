### To search into a Cluster of Indexers
``` server.conf
[clustering]
manager_uri = https://10.152.31.202:8089
mode = searchhead
pass4SymmKey = whatever
```
### Replication Policy can be modified in distsearch.conf
```distsearch.conf
[replicationSettings]
replicationPolicy = classic | cascading
```
### Cascading Replication settings in server.conf
https://docs.splunk.com/Documentation/Splunk/9.3.1/Admin/Serverconf
``` server.conf 
[cascading_replication]
pass4SymmKey = <string>
pass4SymmKey_minLength = <integer>

# To be adjusted depending on needs
max_replication_threads = <integer>

max_replication_jobs = <integer>

cascade_replication_plan_reap_interval = <interval>

cascade_replication_plan_age = <interval>

cascade_replication_plan_fanout = auto|<positive integer>

cascade_replication_plan_topology = size_balanced

cascade_replication_plan_select_policy = random
```