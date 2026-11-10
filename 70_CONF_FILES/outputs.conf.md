- org_all_forwarder_outputs
https://docs.splunk.com/Documentation/Splunk/9.3.1/Forwarding/Setuploadbalancingd
```outputs.conf
autoLBFrequency=40 (default is 30 secondes)
autoLBVolume= ... (not active by default)
# If both enabled, take the first value to be hit.
```

**Asynchronous forwarding**
https://www.linkedin.com/pulse/splunk-asynchronous-forwarding-lightning-fast-data-ingestor-rawat/


```ini
[tcpout]
# Change here to specify the indexer group 
defaultGroup = org_myindexers

# increased queue
maxQueueSize = 70MB
useACK = false

# When indexing a large continuous file that grows very large, a universal
# or light forwarder may become "stuck" on one indexer, trying to reach
# EOF before being able to switch to another indexer. The symptoms of this
# are congestion on *one* indexer in the pool while others seem idle, and
# possibly uneven loading of the disk usage for the target index.
# In this instance, forceTimebasedAutoLB can help!
forceTimebasedAutoLB = true

# ATTENTION, consider using autoLBbyvolume and forcetimebased as last resort only

# make it fallback to compression so it still compress if ever tls1.3 enabled
compressed = true
# this is true by default
# useClientSSLCompression = true

[tcpout:org_myindexers]
server = indexer1:9997,indexer2:9997
#indexerDiscovery = idxdiscovery 

#[indexer_discovery:idxdiscovery]
#pass4SymmKey = {{ pass4symmkeyidxdiscovery }}
#pass4SymmKey = pass4symmkeyidxdiscovery
#manager_uri = https://{{ manager_name }}:8089
```
