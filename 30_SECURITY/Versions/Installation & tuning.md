
# Clustering Steps
https://docs.splunk.com/Documentation/ES/7.3.2/Install/InstallEnterpriseSecuritySHC#Installing_Enterprise_Security_in_a_search_head_cluster_environment

## Install ES on the Deployer
### GUI
- `$SPLUNK_HOME/etc/system/local/web.conf` with the following stanza.  
	```
	[settings]
	max_upload_size = 1024
	splunkdConnectionTimeout = 3000
	```
- Apps > Manage Apps > Install from file
- Click **Enable SSL** to turn on SSL and start using `https://` for encrypted data transfer.
- Click **Do Not Enable SSL** to keep SSL turned off and continue using `http://` for data transfer.
### CLI
If using CLI, use the **–-ssl_enablement ignore** parameter.
- ./splunk install, REST or splunk search
	```
	./splunk install app <filename> '--deployment_type', default='search_head',choices=['search_head', 'shc_deployer'], help='select deployment type'
	
	curl -k -u admin:password [https://localhost:8089/services/apps/local](https://localhost:8089/services/apps/local) -d filename="true" -d name="<file name and directory>" -d update="true" -v

	splunk search '| essinstall --deployment_type shc_deployer' -auth admin:password
	```
	- [!] 
>	On the command line, the installer doesn't auto detect if it is being launched from a deployer. Therefore, it is necessary to add a command line option: `'--deployment_type', default='search_head', choices=['search_head', 'shc_deployer'], help='select deployment type'`

*--> The value of the `deployment_type` setting in the `searchbnf.conf` configuration file is `shc_deployer`*

- The preferred setting for `ssl_enablement` is `strict`
- Restart with ./splunk restart only if SSL is changed from disabled to enabled or vice versa.
- Use the deployer to deploy Enterprise Security to the cluster members. From the deployer, run this command:  
    ```
    splunk apply shcluster-bundle --answer-yes -target <URI>:<management_port> -auth <username>:<password>
	```

## Define ES Required Indexes
### indexes.conf
```
## DA-ESS-AccessProtection ######
[gia_summary]
coldPath = volume:cold/gia_summarydb/colddb
homePath = volume:hotwarm/gia_summarydb/db
thawedPath = $SPLUNK_DB/gia_summarydb/thawedd
##### DA-ESS-ThreatIntelligence ######
[ioc]
coldPath = volume:cold/iocdb/colddb
homePath = volume:hotwarm/iocdb/db
thawedPath = $SPLUNK_DB/iocdb/thaweddb
[threat_activity]
coldPath = volume:cold/threat_activitydb/colddb
homePath = volume:hotwarm/threat_activitydb/db
thawedPath = $SPLUNK_DB/threat_activitydb/thaweddb
###### SA-AuditAndDataProtection ######
[audit_summary]
coldPath = volume:cold/audit_summarydb/colddb
homePath = volume:hotwarm/audit_summarydb/db
thawedPath = $SPLUNK_DB/audit_summarydb/thaweddb
###### SA-EndpointProtection ######
[endpoint_summary]
coldPath = volume:cold/endpoint_summarydb/colddb
homePath = volume:hotwarm/endpoint_summarydb/db
thawedPath = $SPLUNK_DB/endpoint_summarydb/thaweddb
###### SA-NetworkProtection ######
[whois]
coldPath = volume:cold/whoisdb/colddb
homePath = volume:hotwarm/whoisdb/db
thawedPath = $SPLUNK_DB/whoisdb/thaweddb
###### SA-ThreatIntelligence ######
[notable]
coldPath = volume:cold/notabledb/colddb
homePath = volume:hotwarm/notabledb/db
thawedPath = $SPLUNK_DB/notabledb/thaweddb
[notable_summary]
coldPath = volume:cold/notable_summarydb/colddb
homePath = volume:hotwarm/notable_summarydb/db
thawedPath = $SPLUNK_DB/notable_summarydb/thaweddb
[risk]
coldPath = volume:cold/riskdb/colddb
homePath = volume:hotwarm/riskdb/db
thawedPath = $SPLUNK_DB/riskdb/thaweddb
###### SplunkEnterpriseSecuritySuite ######
[sequenced_events]
coldPath = volume:cold/sequenced_eventsdb/colddb
homePath = volume:hotwarm/sequenced_eventsdb/db
thawedPath = $SPLUNK_DB/sequenced_eventsdb/thaweddb
###### Splunk_SA_CIM ######
[cim_modactions]
coldPath = volume:cold/cim_modactionsdb/colddb
homePath = volume:hotwarm/cim_modactionsdb/db
thawedPath = $SPLUNK_DB/cim_modactionsdb/thaweddb
###### Splunk_TA_ueba ######
[ubaroute]
coldPath = volume:cold/ubaroute/colddb
homePath = volume:hotwarm/ubaroute/db
thawedPath = $SPLUNK_DB/ubaroute/thaweddb
[ueba]
coldPath = volume:cold/uebadb/colddb
homePath = volume:hotwarm/uebadb/db
thawedPath = $SPLUNK_DB/uebadb/thaweddb
###### scsproxy ######
[missioncontrol]
coldPath = volume:cold/missioncontrol/colddb
homePath = volume:hotwarm/missioncontrol/db
thawedPath = $SPLUNK_DB/missioncontrol/thaweddb
```
### Note
- [!] Don't forget to modify the adequate volumes into the file.

- Prepare the Deployer with the prerequisites:
	- One deployer
	- The same version of Splunk Enterprise on the deployer and search head cluster nodes
	- The same app versions of any other apps on the deployer and search head cluster nodes (not yet including Enterprise Security)
	- The backup of `etc/shcluster/apps` on the deployer before installing Enterprise Security
	- The backup of `etc/apps` from one of search head cluster nodes
	- The backup of the KVstore from one of search head cluster nodes
## CIM Tuning
How to get correct indexes for a datamodel?
`| tstats count from datamodel=<datamodelname> by index`
Configure > CIM Setup
## Assign ES Roles to Users
You **MUST NOT** use the _ess_admin_ role directly,
instead use the **admin** role

| Role        | Type of User                                                                                                                                      |
| :---------- | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| ess_user    | Executive management or auditor who will not manage ES incidents or modify                                                                        |
| ess_analyst | Security Analyst or Engineer who will be a daily user of ES, will manage<br>incidents, and use all dashboards in ES, but not modify any settings. |
| admin       | Splunk and ES administrator who will have the ability to make any change, including modify rules, saved searches, dashboards, and incidents.      |

## Assets and Identities
...

# Check - Configuration
## Deployer
```server.conf
[shclustering]
pass4SymmKey = yoursecuritykey
shcluster_label = shcluster1
mgmt_uri = [ mgmt-URI ] # cluster member's own address to itself.
```
## SHC Members
```server.conf
[shclustering]
conf_deploy_fetch_url = <URL>:<management_port> # Deployer URL
shcluster_label = shcluster1

[shclustering]
disabled = false
replication_factor = <REP_FACTOR>
# ensure pass4SymmKey matches target IDX Cluster
pass4SymmKey = <COMMON_SECURITY_KEY_ACROSS_IDXC_AND_DEPLOYER_AND_SHC_MEMBERS>
shcluster_label = <SEARCH_HEAD_CLUSTER_LABEL>
conf_deploy_fetch_url = https://<FDQN_OF_THE_SHC_DEPLOYER>:8089

[replication_port://<port>]

# at its respective $SPLUNK_HOME/etc/system/local/server.conf - e.g.
# [shclustering]
# mgmt_uri = https://<FQDN_OF_THE_SHC_MEMBER>:8089
```

### Initialize a Cluster Member
```
splunk init shcluster-config -auth <username>:<password> -mgmt_uri <URI>:<management_port> -replication_port <replication_port> -replication_factor <n> -conf_deploy_fetch_url <URL>:<management_port> -secret <security_key> -shcluster_label <label>

splunk restart
```
### Bring up the Cluster Captain
On the selected instance, run the following command:
```
splunk bootstrap shcluster-captain -servers_list "<URI>:<management_port>,<URI>:<management_port>,..." -auth <username>:<password>
```

### web.conf
```web.conf
[settings]
max_upload_size = 1024
splunkdConnectionTimeout = 3000
```
