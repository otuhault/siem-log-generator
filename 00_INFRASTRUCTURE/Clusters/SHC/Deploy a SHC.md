https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.0/deploy-search-head-clustering/deploy-a-search-head-cluster

1. Set up the deployer
```ini
[shclustering]
pass4SymmKey = yoursecuritykey
shcluster_label = shlabel
```
1. Install SE instances
2. Initialise cluster members
	```ini
splunk init shcluster-config -auth <username>:<password> -mgmt_uri <URI>:<management_port> -replication_port <replication_port> -replication_factor <n> -conf_deploy_fetch_url <URL>:<management_port> -secret <security_key> -shcluster_label <label>	

splunk restart
	```
3. bring up the cluster captain
```ini
splunk bootstrap shcluster-captain -servers_list "<URI>:<management_port>,<URI>:<management_port>,..." -auth <username>:<password>
```

# VIP - LoadBalancer
Before the Search Heads we want a Load Balancer with GTM + LTM, and sticky sessions
https://docs.splunk.com/Documentation/Splunk/latest/DistSearch/UseSHCwithloadbalancers