https://docs.splunk.com/Documentation/Splunk/9.3.2/Indexer/indexerdiscovery
# Configure the manager node to enable indexer discovery
```ini
[indexer_discovery]
pass4SymmKey = <string>
polling_rate = <integer>
indexerWeightByDiskCapacity = <bool>
```
polling_rate doc: https://docs.splunk.com/Documentation/Splunk/9.3.2/Indexer/indexerdiscovery#Adjust_the_frequency_of_polling
weight_lb doc: https://docs.splunk.com/Documentation/Splunk/9.3.2/Indexer/indexerdiscovery#Use_weighted_load_balancing
# Configure the Forwarders
``` ini
[indexer_discovery:<name>]
pass4SymmKey = <string>
manager_uri = <uri>

[tcpout:<target_group>]
indexerDiscovery = <name>
# Add the following if you want to ensure end-to-end data fidelity
# useACK=true

[tcpout]
defaultGroup = <target_group>
```
# Multi-site Discovery
https://docs.splunk.com/Documentation/Splunk/9.3.2/Indexer/indexerdiscovery#Use_indexer_discovery_in_a_multisite_cluster