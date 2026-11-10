# Tools, Resources, and Data Gathering
**Important logs file**

| LogName                                             | Description                                    |
| --------------------------------------------------- | ---------------------------------------------- |
| **splunkd.log**                                     | Splunk’s primary log                           |
| **essinstaller2.log**                               | ES app setup activity and errors               |
| **threatlist.log  <br>**                            | Shows intel downloads and status               |
| **threat_intelligence_manager.log  <br>**           | Parsing of data and dispatching of Lookup Gens |
| **threat_intel_file_upload_rest_handler.log  <br>** | Logs file uploading activity and errors        |
| **python_modular_input.log  <br>**                  | Are module inputs are running as expected      |
# Assets and Identities
- Check all expected lookups are present
- Check if the correct lookup .csv file is associated to the lookup
- Check if the lookup is enabled (disabled by default)
## Test missing information
- Test identity for username “dmsys”  
    **| makeresults | eval user="dmsys" | `get_identity4events(user)`**
## Resetting Collections
Rebuild the collections if they get into an undesirable state
- Click Reset Collection (available on all tabs in the interface A&I Management)
- Select which collections to reset and click Delete
- When the identity manager runs again (every 5min), collections are rebuilt based on the source files
## Matching Issues
- Maybe issues with the way the lookup tables are formatted, or fields are configured.
- The a&i matching algorithms match on specific column names. If these columns are renamed or removed from .csv files, the fields will not match.
## Confirm Column Headers
From the search preview tab, verify the column names between the Gen Searches and the lookups
## Merging Example
- Investing data in the lookup files to see why it's not merging correctly
	- Add an ignore value of "unknown" if needed (not that clear here...)
- Ensure fields with more than one value are configured as MultiValue
- If all values are not displaying for a Multivalued field, the MultiValue Limit may be too low and truncating the results. Increase the MultiValue Limit.
## Merge Logging Erros
- Use **index=\_internal source=\*entity\*.log** to look for merging errors
## Issues with Categories
- Categories not updating and displaying properly
    - Categories are rebuilt by default every 5 minutes
    - To ensure the categories are correct, use the following search  
        | `assets` | mvexpand category | dedup category | sort category | table category
        - The **`assets`** macro displays the merged assets from the asset lookups defined under the **Asset Lookup Configuration** **tab** / **inputs.conf**
        - The MultiValue (MV) field **category** is then expanded, deduplicated, sorted, and tabled
## Issues with Global Settings
- Has merging been disabled?
- Have key fields been configured as "ignore"values?
- Have enforcements been disabled?
- Has the time in which the Identity Manager runs been changed from the default of 5min?
## LDAP Data Onboarding Issues
- Issues with using current LDAP data?
    - Is the **SA-ldapsearch** add-on is installed?
    - Is the correct domain configured?
    - Lookup defines the name of the lookup file that ES creates
        - Splunk gives the file a **.csv** name
# Threat Intelligence
## Threat Activity Events Missing
- Events missing from **index=threat_activity**
    - Threat Gen searches not matching and placing events in index
        - Ensure **DA-ESS-ThreatIntelligence** Threat Gen searches are enabled  
              
            **Settings > Searches, Reports, and Alerts**  
            OR  
            **$SPLUNK_HOME/apps/DA-ESS-ThreatIntelligence/default/savedsearches.conf**
    - **Threat Activity Detection** correlation search not matching events?
        - Ensure the correlation search is enabled  
              
            **Configure > Content > Content Management**  
            OR  
            **$SPLUNK_HOME/apps/DA-ESS-ThreatIntelligence/default|local/savedsearches.conf**
- Rule out issues with threat intelligence
    - How is the data being produced?
        - Via a scheduled download  
            OR
        - Via a manually created and uploaded file (.csv)
- View configured downloads
    - CLI: **curl -k -u admin:s3cur3m3 https://34.222.37.147/services/data/inputs/threatlist?output_mode=json | python -m json.tool**  
        OR
    - SPL: **| rest services/data/inputs/threatlist**
## Intel Download Settings
For a TAXII feed, the Type must be taxii

Download will fail with incorrect parsing settings
## Proxy Options
Proxy User must be created in the Splunk Credential Manager first. If there are proxy issues, confirm the user is configured correctly in the Splunk Credential Manager.
## Threat Intel Audit
Search for threat intel errors
**index=\_internal eventtype=threatintel_internal_logs error**

- View downloaded content and the status of the download via the **threatlist** modular input
- If there is only a **_status** file, the intel has not been downloaded
- Check the URL, fields, delimiter, etc.

- Intel downloads are logged in **threatlist.log**
- Parsing of data and dispatching of Lookup Gens are logged in  
    **threat_intelligence_manager.log**
- File uploading errors/activity are logged in **threat_intel_file_upload_rest_handler.log**

- Verify the module inputs are running as expected
    - **$SPLUNK_HOME/var/log/splunk/python_modular_input.log**
- To force a re-download or watch execution “live”, use CLI execution:  
    - ./splunk cmd splunkd print-modinput-config threatlist threatlist://iblocklist_spyware  
    - ./python /opt/splunk/etc/apps/SA-ThreatIntelligence/bin/threatlist.py --username=admin --password=s3cur3m3**
## Using Retention Settings
Remove stale or old data
1. Decrease the retention period (max_age) for the threat intel source in the KV Store
2. Enable the corresponding saved search from **Settings > Searches, reports, and alerts**, and filter on "retention”
# Data Models
Data models reside in the **CIM app** as well as **ES apps**
- Data models in the ES app include:
	- Assets and Identities
	- Domain Analysis
	- Incident Management
	- Risk Analysis
	- Threat Intelligence
	- User and Entity Behavior Analytics (UEBA)
## Accelerated Data Models
- When accelerated, Splunk builds the initial set of .tsidx file summaries for the data model and then runs scheduled searches in the background every 5 minutes to keep those summaries up to date
    - Configured in **datamodels.conf**  
        [<datamodel_name>]  
        acceleration.cron_schedule = \*/5 * * * *
- The Summary Director runs every 30 minutes from the time Splunk starts to remove old, outdated .tsidx summary files
    - Configured in **limits.conf**  
        [auto_summarizer]  
        maintenance_period = 1800
## Data Model Audit
Audit > Data Model Audit
## Possible Issues
- Dashboard missing data?
- Notable events missing from Incident Review?
- Things to check:
    - Is the data model accelerated?
    - Does your data have the correct event type and tags for the DM?
    - Are the data model attributes (fields/extractions) correct?
## Dashboard not loading
-  If a dashboard takes a long time to load, inspect **(i)** the panel search
- If a large amount of time is spent in sort / stats / merge operations, increase **max_mem_usage_mb** from 200 MB (default)
## Rebuilding a Data Model
- If you suspect a data loss issue, rebuild the summary data for an accelerated data model
    - Splunk deletes the entire summary and rebuilds it
    - Depending on the size of the summaries, this can take a long time!
    - Disabling and re-enabling acceleration for a data model also rebuilds the summaries
## Troubleshooting Commands
- The Risk datamodel is constantly stuck in a state of building
    - Use btool to view **datamodels.conf** configuration  
        ./splunk btool datamodels list Risk --debug
    - Search **scheduler.log** events for “risk” generating searches  
        index=_internal sourcetype=scheduler savedsearch_name=*Risk*
- Run the accelerated search ES uses to build the data model on the current knowledge objects  
    | datamodel Risk acceleration_search

## Data Model Acceleration Loss Scenarios
- **Things to remember:**
    - To make changes to an accelerated data model, you must first disable acceleration
    - The summary director runs every 30 minutes from the time Splunk starts
- **Data Loss Scenario 1**
    - If you disable acceleration, and make changes to a data model, and the summary director runs during this time, all your data would be lost because the summary director dumps all the data for the de-accelerated data model
    - If you make changes within the 30-minute window of the summary director and re-enable acceleration, data is not lost
- **Data Loss Scenario 2**
    - If an app is disabled and the summary directory runs, it will rebuild the data model for that app
    - For example, if during the upgrade of the CIM app, the app is disabled and the summary manager runs, you will lose the accelerated data for all the data models in the CIM app
- Solutions for both scenarios:
    - Ensure **Manual Rebuilds** is enabled/checked for all data models so that the summary director runs only when you manually rebuild the data model
    - Increase the timing of the Summary Director in **limits.conf**  
        **[auto_summarizer]  
        maintenance_period = 1800**
## Slow or Skipped Searches
- Compare the time the acceleration search takes from the **Data Model Audit** dashboard to the cron schedule
    - Is the search is completing fast enough?
    - Adjust the cron schedule to give it more time to complete
- Enable all required DA-ESS*, TA-*, and SA-*
    - For example, ensure DA-ESS-IdentityManagement and DA-ESS-ThreatIntelligence have not been disabled
- Disable unused TA-* and SA-\*, they will slow down the DM searches
- Specify necessary indexes in the DM constraints/macro
    - A searching against **_all_** indexes will use up RAM quickly and slow it down   
## Data Model Storage
- The storage volumes allocated for acceleration should be tuned for best performance and replicated if in a cluster
- Keep up to date on ES hardware and storage requirements
- By default, acceleration storage is allocated in the same location as the index containing the raw events being accelerated
- DMs can be large depending on the number of fields in the model and the size of the bucket
- Specify an alternate location in **indexes.conf** using  
     **tstatsHomePath = volume:**
    - Default location:  
        **volume:\_splunk_summaries/<index_name>/datamodel_summary**
- [!] In a SHC, the volume for a data model on all members in the cluster must be in the same location in the app
# Installation and Upgrades
## Resources
- Release notes 
    - New features and add-ons
    - Deprecated or removed features and add-ons
    - End of support schedule  
        [https://docs.splunk.com/Documentation/ES/latest/RN/Enhancements](https://docs.splunk.com/Documentation/ES/latest/Install/Overview)
- Install and upgrade guide
    - Deployment planning
    - Version compatibility
    - Hardware requirements  
        [https://docs.splunk.com/Documentation/ES/latest/Install/Overview](https://docs.splunk.com/Documentation/ES/latest/Install/Overview)
## Prerequisites
- Is ES installed on its own search head with the correct requirements?
    - 64 bit OS
    - Minimum 32 GB RAM
    - 16 processor cores[](https://docs.splunk.com/Documentation/ES/latest/Install/Overview)
        - Additional memory and CPU capacity may be needed depending on number of concurrent users, searches, etc.
- Install and upgrade guide
- Are the required TAs installed on the search head?
- Disable any unused apps or add-ons
- Users must have the **admin** role and the **edit_local_apps** capability to install or upgrade ES
- The **/tmp/** directory must have at least 1 GB of free space to complete the ES install or upgrade
- If a deployment server manages any of the apps or add-ons included with ES, remove the **deploymentclient.conf** file that contains references to the deployment server and restart Splunk
    - If you do not do this, the installation will not complete
## Possible Upgrade Issues
- ES app upload error
- Installation log shows incomplete setup
- ES setup timeout
- App version mismatch 
- Unable to start Splunk Web
- Unable to access Splunk Web
## CLI Install
- Installing ES via CLI is helpful with fixing an installation that failed using the UI
- ES installation is a two-step process, upload and setup
1. Upload the ES app to Splunk  
    **./splunk install app \<filename\>**  
    OR  
    **curl -k -u admin:\<password\> https://localhost:8089/services/apps/local -d filename="true” -d name="\<file name and directory>\" -d update="true" -v**
2. Use the **'| essinstall'** command to enter ES setup  
    **./splunk search '| essinstall' -auth <admin_username>:\<password\>**
### Dry-Run
- Use the **--dry-run** option to see the outcome of an installation and setup of a new version of ES
    - The example also skips the installation of the Splunk_TA_windows and Splunk_TA_nix add-ons  
        **$SPLUNK_HOME/bin/splunk search '| essinstall --skip-ta**   
        **Splunk_TA_windows Splunk_TA_nix --dry-run' -auth admin:s3cur3m3**
## Uninstall ES
- It may be necessary to uninstall ES when troubleshooting a new ES installation
    - Recursively move the **SplunkEnterpriseSecuritySuite** app from **$SPLUNK_HOME/etc/apps to $SPLUNK_HOME/etc/disabled-apps**
        - Gives you the ability to test and move it back        
            OR
    - Recursively remove the **SplunkEnterpriseSecuritySuite** app from **$SPLUNK_HOME/etc/apps**
- [!] Both Methods require a restart of Splunk
## Upload Error
Receiving an installation/upgrade error regarding content-length or app upload?
- Increase the Splunk Web upload size limit in **web.conf**
    - The 6.0.0+ installer is larger than the default upload limit
- Revise **$SPLUNK_HOME/etc/system/local/web.conf** and restart
![[Pasted image 20241016171921.png]]
## Setup Timeout
Receiving a timeout error when starting the ES setup process?
- Increase the **splunkd** connection timeout value in **web.conf**  
    (default 30 seconds)
- Revise **$SPLUNK_HOME/etc/system/local/web.conf** and restart
![[Pasted image 20241016172036.png]]
## essinstaller2.log
- Check **splunkd.log** for errors with the file upload process
- Use **essinstaller2.log** view the ES setup process and errors
    - Confirm “STAGE STARTING” and “STAGE COMPLETE” for each stage of the  
         setup process
    - Stages: initial, refresh, deprecate_apps, disable_apps, install_apps, reenable_apps,  
        postinstall, finalize
## Version Mismatch
- ES app file is uploaded to Splunk, but ES setup fails due to a mismatch between Splunk Enterprise and ES version
- Check for compatibility matrix for Splunk and ES versions      [https://docs.splunk.com/Documentation/ES/latest/Install/DeploymentPlanning#Splunk_Enterprise_system_requirements](http://docs.splunk.com/Documentation/ES/latest/Install/DeploymentPlanning#Splunk_Enterprise_system_requirements)
- Confirm Splunk version:
	- /opt/splunk/etc/system/default/app.conf
	- SplunkEnterpriseSecuritySuite/local/ess_setup.conf
## UI Errors
- Is a custom dashboard in conflict with the upgrade version?
    - Is there a custom .xml file in    
        **$SPLUNK_HOME/etc/apps/<app_name>/local/data/ui/views**
    - Move the .**xml** file out of the **views** folder to see if it fixes the UI issues
    - Customize the dashboard for the latest version under default, and copy it to **$SPLUNK_HOME/etc/apps/<app_name>/local/data/ui/views**
## Configuration Checker
![[Pasted image 20241016172358.png]]
- Configuration scripts are located in  
    **$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/bin/configuration_checks**
- Configuration Checker messages are logged in  
    **$SPLUNK_HOME/var/log/splunk/configuration_check.log**
- If ERROR messages are not being logged for a specific configuration checker, change  
    the **Default Severity** to ERROR
# ES Search Head Cluster
## Overview
- Deployer distributes configurations to search head cluster (SHC) members
- Members of SHC elect a captain
- The Captain:
    - replicates configuration changes to all cluster members
    - schedules and manages searches
    - handles bundle replication for the entire SHC
## Deploying ES
- ES must first be installed on the Deployer
    - There can only be one Deployer
    - Confirm that the deployer is configured  
        **/services/configs/conf-server/shclustering | table disabled, pass4symmkey**
        - If **disabled = 1** and there is a **pass4SymmKey** this is a deployer
    - Deployer and cluster members must be running the same version of Splunk
    - Cluster members must be running the same version of all other apps
    - Ensure the max upload size is increased on the Deployer for the ES install  
        **$SPLUNK_HOME/etc/system/local/web.conf  
        [settings]  
        max_upload_size = 1024**
    - CLI install of ES to cluster members from the Deployer:  
    splunk apply shcluster-bundle -target \<URI>:<mgmt_port> -auth \<username>:\<password>
	- Each SH must have at least 1GB fee space in the /tmp/ directory for installation or upgrade
	- App is installed into **$SPLUNK_HOME/etc/system/shcluster/apps**
	- Confirm ES is installed on the cluster members
	    - Are ES and the supporting apps installed in **/etc/apps?**  
	        **SplunkEnterpriseSecuritySuite, Splunk_SA_CIM, DA-ESS-AccessProtection, DA-ESS-EndpointProtection, etc.**
	- Confirm the data models are accelerated  
    **$SPLUNK_HOME/etc/apps/SplunkEnterpriseSecuritySuite/local/inputs.conf  
    [datemodel_name]  
    Acceleration = true**
	- Remember, all cluster members must have the same configuration!
## Confirm KV Store Status
From the Deployer, confirm the KV Store status and captain using  
**splunk show kvstore-status**
## Deployer essinstaller2.log
- When viewing essinstaller2.log on the Deployer, the following are not logged: **deprecate_apps, disable_apps, reenable_apps**, and post-install stages
## SHC Configuration for ES
- Confirm the SHC configuration in **server.conf**  
    [shclustering]  
    **disabled = false  
    pass4SymmKey = \<password>** - must be the same on all members!
- For larger deployments, increase timeouts under the  
    **[clustering]** stanza
    - **rcv_timeout** (default 60s): timeout for receiving data between cluster nodes
    - **send_timeout** (default 60s): timeout for sending data between cluster nodes
    - **election_timeout_ms** (default 60000ms/1m): the amount of time that a member waits before trying to become captain
        - Increase this number to make members wait longer
## Bundle Overview
- A “bundle” of knowledge objects that each member in a SHC needs to perform searches (investigations, sequence templates, inputs, etc.)
- Bundles reside under **$SPLUNK_HOME/var/run**
- Distributed to **$SPLUNK_HOME/var/run/searchpeers** on each member of the SHC
- Issues that may occur:
    - Too large a bundle file
    - Bundle replication times out 
    - SHC members get out of synchronization
## Bundle Deployment
![[Pasted image 20241017082749.png]]
## Bundle Status
- From a search head member:  
    **index=_internal component=ConfDeployment data.task=*Apps  
    | table host data.source data.target_label data.task data.status**
- Check the Monitoring Control > Search Head Clustering App Deployment dashboard
MC > Search > Search Head Clustering: App Deployment
- Other bundle status CLI commands include:
    - **splunk show bundle-replication-status**
    - **splunk show bundle-replication-config**
## Blacklisting Files
- Define which files to include in bundle replication in **distsearch.conf** under the **[replicationBlacklist]** stanza
- Prevent unwanted bundle replication due to:
    - Very large files – there may be part of an app that may not need to be replicated. Especially true if they are not needed on search nodes
    - Frequently updated files - for example, some lookups will trigger retransmission of all search head data
    - Scripted input or old apps that frequently  
        update table data
## Replication Settings - Deployer
- Fine-tune bundle replication for the Deployer:
    - In **distsearch.conf** under **[replicationSettings]**
    - **maxBundleSize** (default 2048MB/2GB): maximum size of the bundle
        - If a bundle exceeds this value, the SH will not push the bundle to the indexers. Indexers will use the previously pushed bundle
    - **replicationThreads** (default 5): number of concurrent indexers to replicate the bundles to
        - If set to **auto**, the peer autotunes the number of threads based on the number of CPUs it has
- Fine-tune other bundle replication settings for the Deployer:
    - In **limits.conf** under **[lookup]**
        - **max_memtable_bytes** (default 10000000B/10MB): file larger than this value will be indexed (for each file size, not entire bundle size)
        - **replication_period_sec** (default 60s): time between two successive bundle replications
    - In **server.conf** under **[httpServer]**
        - **max_content_length** (default 2147483648B/2GB): the upper size limit of an http request