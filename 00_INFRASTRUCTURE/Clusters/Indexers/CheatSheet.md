### Push bundle to peer
```
./splunk apply cluster-bundle
```
### Configure the Manager
#### via server.conf
```ini
[clustering]
mode = manager
replication_factor = 2
search_factor = 2
pass4SymmKey = whatever
cluster_label = cluster1

# [indexer_discovery]
# pass4SymmKey = <SOMETHING_OTHER_THAN_THE_EXISTING_PASS4SYMMKEY>
```
#### via cli
```cpp
./splunk edit cluster-config -mode manager -replication_factor 2 -search_factor 2 -secret your_key -cluster_label cluster1

./splunk restart
```

### Configure the peer-nodes
#### via server.conf
```ini
[replication_port://9887]

[clustering]
manager_uri = https://10.152.31.202:8089
mode = peer
pass4SymmKey = whatever
```
#### via cli
```cpp
splunk edit cluster-config -mode peer -manager_uri https://10.160.31.200:8089 -replication_port 9887 -secret your_key

splunk restart
```
### Managed by DS
``` ini
[deployment-client]
serverRepositoryLocationPolicy = rejectAlways
repositoryLocation = SPLUNK_HOME/etc/master-apps
```

