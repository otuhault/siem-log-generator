# Pre-Checks
- RF/SF OK and Green on Cluster Manager, no "bucket fixups" or rebalancing
- No smart store maintenance
- Admin account access OK
- SHC Quorum OK, stable captain and no KV Store migration running
- Enough Disk Space for binaries
- Apps compatibility, Python scripts, tierce libraries
- Freeze DS/Deployer deployments during the upgrade
- Notify the collaborator teams about the upgrade
- Have a restore plan validated and tested
- Backup server authentication indexes inputs outputs server.pem/licenses  on all the nodes, etc/shcluster on Deployer, kvstore on all SH `splunk backup kvstore` ,etc/deployment-apps/ and serverclass.conf on deployement server, etc/ on CM and HFs

- • Splunk is run on root user: it is not recommended running Splunk with root as it is a security risk and also a best practice to not do.  
- /tmp directory has enough free space for ES upgrade; at least 3GB are required.  
- The Splunk instance meet minimum resource requirements in terms of CPU and RAM.  
- Transparent Huge Pages is disabled on all Splunk instances  
- No issues in data ingestion pipeline have been identified, there were no blocked queues  
- No scheduler oversubscription has been identified

# Open Support Ticket 
It is recommended to create a proactive support ticket with Splunk prior to running the upgrade. This ticket should state  
- That it is being opened proactively to create awareness of upgrade timing 
- It should list the planned date and time of the upgrade and any associated change freeze window duration 
- It should state the current and target planned versions of the upgrade 
- It should state that the ticket is being created at the advice of Splunk Professional Services 
- It should have a low priority level (P3 or P4). Do not use a P1 or P0 ticket.
# Steps Order
1. Cluster Manager
2. Search Heads Tiers
3. Deployer
4. Indexer Tiers
5. Deployment Server
6. Heavy Forwarders
- universal forwarders
### 1. Cluster Manager
- Back up etc/apps; etc/manager-apps; etc/system/local; splunk.secret; certificates
- Stop the Cluster Master: `splunk stop`
- Upgrade it normally: `tar -xvzf splunk.tgz -C /opt/`
- Start the Cluster Master: `splunk start`
### 2. Search Heads Tiers
- Back up kvstore on each member
- Stop all Search Heads
- Upgrade using normal procedure
	- **If the Indexer Cluster is integrated with the SHC**
		- Upgrade one member and make it the captain
		- Upgrade other members, one by one
		- Upgrade the Deployer
- Start the Search Heads
### 3. Deployer
- Backup etc/
- `splunk stop`
- `tar -xvzf splunk.tgz -C /opt`
- `splunk start` 
### 4. Indexer Tiers
- Put Cluster Manager in Maintenance Mode: `./splunk enable maintenance-mode`
- Stop all indexers - `./splunk offline` to stop the indexer properly
- Upgrade peers normally with: `tar xvzf splunk -C /opt/`
- Start the indexers
- Disable Maintenance Mode on CM: `./splunk disable maintenance-mode`
### 5. Deployment Server
- Backup etc/
- `splunk stop`
- `tar -xvzf splunk.tgz -C /opt`
- `splunk start` 
### 6. Heavy Forwarders
- Backup etc/
- `splunk stop`
- `tar -xvzf splunk.tgz -C /opt`
- `splunk start` 
# Post-Checks
- SHC `shcluster-status` `kvstore-status`
- CM Green, RF/SF replication ok
- Monitoring Console Health 
#  Matrix Compatibility
https://docs.splunk.com/Documentation/Splunk/8.0.2/Installation/HowtoupgradeSplunk
https://docs.splunk.com/Documentation/Splunk/9.0.1/Installation/HowtoupgradeSplunk
https://docs.splunk.com/Documentation/Splunk/9.3.2/Installation/HowtoupgradeSplunk
https://help.splunk.com/en/splunk-enterprise/get-started/install-and-upgrade/9.4/upgrade-or-migrate-splunk-enterprise/how-to-upgrade-splunk-enterprise
![[Pasted image 20241127153346.png]]
![[Pasted image 20241127153426.png]]
![[Pasted image 20241127153501.png]]
![[Pasted image 20241127153313.png]]
![[Pasted image 20251001222255.png]]


# Atlassian Doc
https://splservices.atlassian.net/wiki/spaces/PS/pages/2825685177/Task+-+Upgrade+Advisory+-+Readiness+Check
- Upgrade: Advisory - Readiness Check
	- Objective: Perform an audit of the currently installed Splunk environment in preparation for an upgrade
    - Scope: This task may include:
        - Identify core Splunk Enterprise system components and roles
        - Identify instance types used to host Splunk
        - Review of server resources (CPU, disk, and memory) allocated        
        - Review of current installed Splunk environment, including app key value store
        - Review configuration settings relevant to the host operating system
            - ulimits/THP
            - init.d vs. systemd
        - Review Customer-specific automation requirements
        - Identify versions and compatibility of Splunkbase and Customer-specific apps installed in the environment for the targeted version of the Splunk platform        
    - Out of Scope:
        - Modifications to any Splunk configurations    
        - Upgrade of premium apps    
    - Task-Specific Assumption:
        - Provide access to and/or documentation of the existing Splunk environment   
        - Subject matter experts will be provided by Customer for vendor technology  
        - Customer has pre-provisioned instances in adherence to Splunk’s documented system requirements for use of the Splunk platform
    - Professional Services Materials: Upgrade assessment document

# Documentation
How to upgrade Splunk Enterprise:  https://docs.splunk.com/Documentation/Splunk/latest/Installation/HowtoupgradeSplunk
## Search Heads Cluster
https://docs.splunk.com/Documentation/Splunk/9.3.2/DistSearch/UpgradeaSHC
## Indexer Cluster
![[Pasted image 20241115145030.png]]
- Searchable Rolling Upgrade: https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Searchablerollingupgrade
- Process flow chart to upgrade and checks: https://docs.splunk.com/images/d/d3/Splunk_upgrade_order_of_ops.pdf
- Splunk Indexer Upgrade: https://docs.splunk.com/Documentation/Splunk/latest/Indexer/Upgradeacluster
