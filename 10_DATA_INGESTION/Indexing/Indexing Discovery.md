*server.conf* on CM
```
[indexer_discovery]
# For obvious security reason, DO NOT USE the same one that for indexer cluster above
# comment here if not used
pass4SymmKey = {{ pass4symmkeyidxdiscovery }}
# Security key shared between master node and forwarders.
# If specified here, the same value must also be specified on all forwarders
#  connecting to this master.
# see corresponding stanza in output apps
```


*outputs.conf*
```
[tcpout]
# Change here to specify the indexer group 
defaultGroup = org_myindexers

# increased queue
maxQueueSize = 70MB
useACK = false

forceTimebasedAutoLB = true
compressed = true

[tcpout:org_myindexers]
indexerDiscovery = idxdiscovery
server = indexer1:9997,indexer2:9997

[indexer_discovery:idxdiscovery]
pass4SymmKey = {{ pass4symmkeyidxdiscovery }}
manager_uri = https://{{ manager_name }}:8089
```

