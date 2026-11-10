# Steps Order
CHECK VERSIONS ALSO
1. Install new Indexers
2. Bootstrap indexers to join the cluster as peers
3. Ensure new indexers receive common configuration
	- Distribute files and apps with the configuration bundle
	- Common Files: indexes.conf, props.conf, transforms.conf
4. Prepare to decommission old indexers
	- Point forwarders (SH,MC,etc.) to new indexers
	- Put old indexers into detention: `./splunk edit cluster-config -manual_detention on -auth admin:passwd`
5. Decommission old indexers (one at a time)
	- Run command `./splunk offline --enforce-counts` (remove permanently a peer), wait until: ready for shutdown and next
	- Wait for indexer status to show as GracefulShutdown in CM UI
	- Repeat for remaining indexers
	- CM will fix / migrate buckets to new hardware
6. Remove the old peer from the master's list
	- `splunk remove cluster-peers -peers <guid>,<guid>,<guid>`


```
/opt/splunk/etc/apps/ci7_cluster_indexer_base/local/indexes.conf
/opt/splunk/etc/peer-apps/_cluster/default/indexes.conf
/opt/splunk/etc/peer-apps/ci7_all_indexes/local/indexes.conf
/opt/splunk/etc/peer-apps/ci7_indexer_volume_indexes/local/indexes.conf
/opt/splunk/etc/peer-apps/scc2_datagen_indexes/local/indexes.conf
```


pass4SymmKey = 


splunk remove cluster-peers -peers FC8CD2B1-3077-4531-A3A0-051EBD1A0526,98142A43-C8A5-4D18-BAA8-4BFCCD06E5FA