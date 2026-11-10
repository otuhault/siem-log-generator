### Push configuration bundle to the Search Heads
```
./splunk apply shcluster-bundle -target :<management_port>
```
### Initialise cluster members
```
./splunk init shcluster-config -auth : -mgmt_uri :<management_port> -replication_port <replication_port> -replication_factor -conf_deploy_fetch_url :<management_port> -secret <security_key> -shcluster_label
./splunk restart
```
### Bring up the Cluster Captain
```
splunk bootstrap shcluster-captain -servers_list ":<management_port>,:<management_port>,..." -auth <username>:<password>
```
### Add instance to the Cluster 
#### from a new member
```
./splunk add shcluster-member -current_member_uri <URI:port>
```
#### from a current member
```
./splunk add shcluster-member -new_member_uri <URI:port>
```
### Remove a Cluster member
Make sure the instance is not the Captain (transfer or restart to force an election)
- Remove the instance from the cluster
	`./splunk remove shcluster-member`
- Wait 2min for configurations to update across the cluster, then stop the instance
- Allows the KV Store to adjust/remove the member from the hosts
	`./splunk show kvstore-status`
### Control captaincy
#### Designating Members as "preferred" in server.conf
`preferred_captain = true
#### Transfer captaincy from one member to another
`./splunk transfer shcluster-captain -mgmt_uri <URI:port> -auth <username:password>`
#### Identify the Captain in a SHC
`./splunk show cluster-status -auth username:password`

