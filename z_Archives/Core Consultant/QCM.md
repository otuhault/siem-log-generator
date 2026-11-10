1. How does the MC initially identify the server role(s) of a new Splunk Instance?
	- The MC uses a REST endpoint to query the server
2. A customer has asked for a five-node SHC, but does not have the storage budget to use a replication factor greater than 2. They would like to understand what might happen in terms of the user's ability to view historic scheduled search results if they log onto a search head which doesn't contain one of the 2 copies of a given search artifact.
	- The SH that the user has logged onto will proxy the required artifact over to itself from a SH that currently holds a copy. A copy will also be replicated from that SH permanently, so it is available for future use.
3. MC health check configuration items are stored in which configuration file?
	- checklist.conf
4. What should be considered when running the following CLI commands with a goal of accelerating an index cluster migration to new hardware?    ./splunk edit cluster-config -max_peer_build_load 3 AND ./splunk edit cluster-config -max_peer_rep_load 6
	   - Network latency and storage IOPS
5. Which statement is true about subsearches?
	 - Subsearches work best for small result sets
6. A customer has been using Splunk for one year, utilizing a single/all-in-one instance. This single Splunk server is now struggling to cope with the daily ingest rate.  Also, Splunk has become a vital system in day-to-day operations making high availability a consideration for the Splunk service. The customer is unsure how to design the new environment topology in order to provide this. Which resource would help the customer gather the requirements for their new architecture?
	- Refer the customer to the Splunk Validated Architectures document in order to guide them through which approved architectures could meet their requirements
7. The customer has an indexer cluster supporting a wide variety of search needs, including scheduled search, data model acceleration, and summary indexing. ![[Pasted image 20241223141359.png]]Which strategy represents the minimum and least disruptive change necessary to protect the searchability of the indexer cluster in case of indexer failure?
	- Leave replication_factor=2, increase search_factor=2 and enable summary_replication.
8. What is the primary driver behind implementing indexer clustering in a customer's environment?
	- To provide higher availability for buckets of data.
9. In a single indexer cluster, where should the MC be installed?
	- Cluster Master node...
10. A customer has downloaded the Splunk App for AWS from Splunkbase and installed it in a search head cluster following the instructions using the deployer. A power user modifies a dashboard in the app on one of the search head cluster members. The app containing an updated dashboard is upgraded to the latest version by following the instructions via the deployer.  What happens?
	- The updated dashboard will not be available to the power user, they will see their modified version.
11. A customer's deployment server is overwhelmed with forwarder connections after adding an additional 1000 clients. The default phone home interval is set to 60 seconds. To reduce the number of connection failures to the DS what is recommended?
	- Increase the phone home interval to 600 seconds
12. Which of the following server.conf stanza indicates the Indexer Discovery feature has not been fullly configured (restart pending) on the Master Node?
	- the one with the clear text password.
13. What is the Splunk PS recommendation when using the deployment server and building deployment apps?
	- Carefully design smaller apps with specific configurations that can be reused
14. Which of the following processor occur in the indexing pipeline?
	- tcp out, syslog out
15. Which configuration item should be set to false to significantly improve data ingestion performance?
	- SHOULD_LINEMERGE
16. A customer has a new set of hardware to replace their aging indexers. What method would reduce the amount of bucket replication operations during the migration process?
	- Put the old indexers into manual detention
17. When a bucket rolls from cold to frozen on a clustered indexer, which of the following scenarios occurs?
	- Replicated copies of the bucket will remain on all other indexers and the Cluster Master (CM) assigns a new primary bucket.
18. A site from a multi-site indexer cluster needs to be decommissioned. Which of the following actions must be taken?
	- Remove the site from the list of available sites and create an alias for where the new data should be sent.
19. A customer wants to implement LDAP because managing local Splunk users is becoming too much of an overhead. What configuration details are needed from the customer to implement LDAP authentication?
	- LDAP server: port, bind user credentials, base DN for groups, base DN for users.
20. A customer has a search cluster (SHC) of six members split evenly between two data centers (DC). The customer is concerned with network connectivity between the two DCs due to frequent outages. Which of the following is true as it relates to SHC resiliency when a network outage occurs between the two DCs?
	- The SHC will stop all scheduled search activity within the SHC.
21. A `[script://]` input sends data to a Splunk forwarder using which method?
	- STDOUT/STDERR
22. A customer wants to understand how Splunk bucket types (hot, warm, cold) impact search performance within their environment. Their indexers have a single storage device for all data. What is the proper message to communicate to the customer?
	- The bucket types (hot, warm, or cold) have the same search performance characteristics within the customer's environment.
23. An index receives approximately 50GB of data per day per indexer at an even and consistent rate. The customer would like to keep this data searchable for a minimum of 30 days. In addition, they have hourly scheduled searches that process a week's worth of data and are quite sensitive to search performance. Given ideal conditions (no restarts, nor drops/bursts in data volume), and following PS best practices, which of the following sets of indexes.conf settings can be leveraged to meet the requirements?
	- frozenTimePeriodInSecs, maxDataSize, maxVolumeDataSizeMB, maxHotBuckets
24. A customer has a Universal Forwarder (UF) with an inputs.conf monitoring its splunkd.log. The data is sent through a heavy forwarder to an indexer.  Where does the Index time parsing occur?
	- Heavy Forwarder
25. The customer wants to migrate their current Splunk Index cluster to new hardware to improve indexing and search performance. What is the correct process and procedure for this task?
	- 1. Install new indexers. 2. Configure indexers into the cluster as peers; ensure they receive the cluster bundle and the same configuration as original peers. 3. Update forwarders to forward to the new peers. 4. Decommission old peers one at a time. 5. Remove old peers from the CM's list.
26. Consider the scenario where the /var/log directory contains the files secure, messages, cron, audit. A customer has created the following inputs.conf stanzas in the same Splunk app in order to attempt to monitor the files secure and messages:![[Pasted image 20241226093542.png]]
	- /var/log/secure
27.  A customer has written the following search: ...
	- index > lookup > search > stats > table
28. How could a role in which all users must specify an index=clause in all searches be configured?
	- Set the authorize.conf setting: srchIndexesDefault to no value.
29. In which of the following scenarios should base configurations be used to provide consistent, repeatable, and supportable configurations?
	- To provide settings that can be customized to meet customer requirements.
30. Data can be onboarded using apps, Splunk Web, or the CLI. Which is the PS preferred method?
	- inputs.conf file
31. ??
32. The data in Splunk is now subject to auditing and compliance controls. A customer would like to ensure that at least one year of logs are retained for both Windows and Firewall events. What data retention controls must be configured?
	- maxTotalDataSizeMB and frozenTimePeriodInSecs
33. What happens when an index cluster peer freezes a bucket?
	- The cluster master will no longer perform fix-up activities for the bucket.
34. A customer has the following Splunk instances within their environment: An indexer cluster consisting of a cluster master/master node and five clustered indexers, two search heads (no search head clustering), a deployment server, and a license master. The deployment server and license master are running on their own single-purpose instances. The customer would like to start using the Monitoring Console (MC) to monitor the whole environment. On the MC instance, which instances will need to be configured as distributed search peers by specifying them via the UI using the settings menu?
	- Search heads, deployment server, license master, cluster master/master node
35. What does Splunk do when it indexes events?
	- Extracts metadata fields such as host, source, sourcetype.
36. What is the default push mode for a search head cluster deployer app configuration bundle?
	- merge_to_default
37. In which of the following scenarios is a subsearch the most appropriate?
	- When dynamically filtering hosts.
38. A customer has implemented their own Role Based Access Control (RBAC) model to attempt to give the Security team different data access than the Operations team by creating two new Splunk roles "" security and operations. In the srchIndexesAllowed setting of authorize.conf, they specified the network index under the security role and the operations index under the operations role. The new roles are set up to inherit the default user role. If a new user is created and assigned to the operations role only, which indexes will the user have access to search?
	- operations, network
39. A customer would like Splunk to delete files after they've been ingested. The Universal Forwarder has read/write access to the directory structure. Which input type would be most appropriate to use in order to ensure files are ingested and then deleted afterwards?
	- Batch
40. In which directory should base config app(s) be placed to initialize an indexer?
	- $SPLUNK_HOME/etc/apps/
41. As a best practice which of the following should be used to ingest data on clustered indexers?
	- A. Monitoring (via a process), collecting data (modular inputs) from remote systems/applications
	- B. Modular inputs, HTTP Event Collector (HEC), inputs.conf monitor stanza
	- C. Actively listening on ports, monitoring (via a process), collecting data from remote systems/applications
	- **D. splunktcp, splunktcp-ssl, HTTP Event Collector (HEC) - Most Voted**
42. When adding a new search head to a search head cluster (SHC), which of the following scenarios occurs?
	- The new search head connects to the deployer and pulls the most recently deployed bundle. It then connects to the captain and replays any recent configuration changes to bring it up to date.
43. A customer wants to migrate from using Splunk local accounts to use Active Directory with LDAP for their Splunk user accounts instead. Which configuration files must be modified to connect to an Active Directory LDAP provider?
	- authentication.conf
44. A customer has a number of inefficient regex replacement transforms being applied. When under heavy load the indexers are struggling to maintain the expected indexing rate. In a worst case scenario, which queue(s) would be expected to fill up?
	- **Typing, merging, parsing, input**
	- **Parsing**
	- Typing
	- Indexing, typing, merging, parsing, input
45. A new single-site three indexer cluster is being stood up with replication_factor:2, search_factor:2. At which step would the Indexer Cluster be classed as "˜Indexing Ready' and be able to ingest new data?  **Step 1:** Install and configure Cluster Master (CM)/Master Node with base clustering stanza settings, restarting CM.  **Step 2**: Configure a base app in etc/master-apps on the CM to enable a splunktcp input on port 9997 and deploy index creation configurations.  **Step 3**: Install and configure Indexer 1 so that once restarted, it contacts the CM, download the latest config bundle.  **Step 4:** Indexer 1 restarts and has successfully joined the cluster.  **Step 5:** Install and configure Indexer 2 so that once restarted, it contacts the CM, downloads the latest config bundle  **Step 6**: Indexer 2 restarts and has successfully joined the cluster.  **Step 7**: Install and configure Indexer 3 so that once restarted, it contacts the CM, downloads the latest config bundle.  **Step 8**: Indexer 3 restarts and has successfully joined the cluster.
	- Step 6.
46. A new search head cluster is being implemented. Which is the correct command to initialize the deployer node without restarting the search head cluster peers?
	- $SPLUNK_HOME/bin/splunk apply shcluster-bundle ""action stage
47. What is required to setup the HTTP Event Collector (HEC)?
	- Each HEC input entry must contain a valid token.
48. In the diagrammed environment shown below, the customer would like the data read by the universal forwarders to set an indexed field containing the UF's host name. Where would the parsing configurations need to be installed for this to work?
	- On all parsing Splunk instances.
49. Report acceleration has been enabled for a specific use case. In which bucket location is the corresponding CSV file located?
	- summaryHomePath
6. Which command is most efficient in finding the pass4SymmKey of an index cluster?
	- $SPLUNK_HOME/bin/splunk btool server list clustering | grep pass4SymmKey
7. Where does the bloomfilter reside?
	- $SPLUNK_HOME/var/lib/splunk/indexfoo/db/db_1553504858_1553504507_8
8. A customer is having issues with truncated events greater than 64K. What configuration should be deployed to a universal forwarder (UF) to fix the issue?
	- EVENT_BREAKER_ENABLE and EVENT_BREAKER regular expression settings per sourcetype
9. A customer has a network device that transmits logs directly with UDP or TCP over SSL. Using PS best practices, which ingestion method should be used?
	- Use a syslog server to aggregate the data to files and use a universal forwarder to read and transmit the data to the indexing tier.
10. As data enters the indexer, it proceeds through a pipeline where event processing occurs. In which pipeline does line breaking occur?
	- Parsing
11. A customer has a multisite cluster (two sites, each site in its own data center) and users experiencing a slow response when searches are run on search heads located in either site. The Search Job Inspector shows the delay is being caused by search heads on either site waiting for results to be returned by indexers on the opposing site. The network team has confirmed that there is limited bandwidth available between the two data centers, which are in different geographic locations.  Which of the following would be the least expensive and easiest way to improve search performance?
	- Configure site_search_factor to ensure a searchable copy exists in the local site for each search head.
12. A customer is using regex to whitelist access logs and secure logs from a web server, but only the access logs are being ingested. Which troubleshooting resource would provide insight into why the secure logs are not being ingested?
	- tailingprocessor
13. A customer with a large distributed environment has blacklisted a large lookup from the search bundle to decrease the bundle size using distsearch.conf.  After this change, when running searches utilizing the lookup that was blacklisted they see error messages in the Splunk Search UI stating the lookup file does not exist. What can the customer do to resolve the issue?
	- The search needs to be modified to ensure the lookup command specifies parameter local=true.
14. In preparation for the deployment of a new environment for a customer, which of the following mappings are correct per PS best practices?
	- ![[Pasted image 20241226105633.png]]
15. Which of the following statements is true, as it pertains to search head clustering (SHC)?
	- SHC is supported on AIX, Linux, and Windows operating systems. ??
	- SHC members must run on the same hardware specifications. ??
16. Where are Splunk Data Model Acceleration (DMA) summaries stored?
	- In tstatsHomePath
17. When can the Search Job Inspector be used to debug searches?
	- If the search has not expired.
18. A Splunk Index cluster is being installed and the indexers need to be configured with a license master. After the customer provides the name of the license master, what is the next step?
	- Update the Splunk PS base config license app and deploy via the cluster master.
19. A customer has three users and is planning to ingest 250GB of data per day. They are concerned with search uptime, can tolerate up to a two-hour downtime for the search tier, and want advice on single search head versus a search head cluster. (SHC). Which recommendation is the most appropriate?
	- The customer should deploy a SHC with a single member for HA; more members can be added later.
	- The customer should deploy a single search head with a warm standby search head and an rsync process to synchronize configurations.
20. Which of the following is the most efficient search?
	- (index=www status=200 uri=/cart/checkout) OR (index=sales) | stats count, sum(revenue) as total_revenue by session_id | table total_revenue session_id
21. ![[Pasted image 20241226143247.png]]
	What is this search's intended function?
	- To return all the web_log events from the web index that occur two hours before and after the most recent high severity, denied event found in the firewall index.
66. When setting up a multisite search head and indexer cluster, which nodes are required to declare site membership?
	- Search head cluster members, indexers, cluster master
67. A customer is using both internal Splunk authentication and LDAP for user management.  If a username exists in both $SPLUNK_HOME/etc/passwd and LDAP, which of the following statements is accurate?
	- The internal Splunk authentication will take precedence.
68. When utilizing a subsearch within a Splunk SPL search query, which of the following statements is accurate?
	- Subsearches have a default result output limit of 10000.
69. A customer is migrating their existing Splunk Indexer from an old set of hardware to a new set of indexers. What is the earliest method to migrate the system?
	- 1. Add new indexers to the cluster as peers, in the same site (if needed). 2. Ensure new indexers receive common configuration. 3. Decommission old indexers (one at a time) to allow time for CM to fix/migrate buckets to new hardware. 4. Remove all the old indexers from the CM's list.
70. When using SAML, where does user authentication occur?
	- The Identity Provider (IDP) decodes the SAML request and authenticates the user.
71. Which of the following server roles should be configured for a host which indexes its internal logs locally?
	- Indexer
72. The Splunk Validated Architectures (SVAs) document provides a series of approved Splunk topologies. Which statement accurately describes how it should be used by a customer?
	- Customers should identify their requirements, provisionally choose an approved design that meets them, then consider design principles and best practices to come to an informed design decision.
73. In a large cloud customer environment with many (>100) dynamically created endpoint systems, each with a UF already deployed, what is the best approach for associating these systems with an appropriate serverclass on the deployment server?
	- Work with the cloud orchestration team to create a common host-naming convention for these systems so a simple pattern can be used in the serverclass.conf whitelist attribute.
74. Which of the following is the most efficient search?
	- index > fields > lookup > where > stats
75. A customer has 30 indexers in an indexer cluster configuration and two search heads. They are working on writing SPL search for a particular use-case, but are concerned that it takes too long to run for short time durations.  How can the Search Job Inspector capabilities be used to help validate and understand the customer concerns?
	- Search Job Inspector provides statistics to show how much time and the number of events each indexer has processed.
76. A customer would like to remove the output_file capability from users with the default user role to stop them from filling up the disk on the search head with lookup files. What is the best way to remove this capability from users?
	- Clone the default user role, remove the output_file capability, and assign it to the users.
77. A working search head cluster has been set up and used for 6 months with just the native/local Splunk user authentication method. In order to integrate the search heads with an external Active Directory server using LDAP, which of the following statements represents the most appropriate method to deploy the configuration to the servers?
	- Configure the integration in a base configuration app located in shcluster-apps directory on the search head deployer, then deploy the configuration to the search heads using the splunk apply shcluster-bundle command.
78. In an environment that has Indexer Clustering, the Monitoring Console (MC) provides dashboards to monitor environment health. As the environment grows over time and new indexers are added, which steps would ensure the MC is aware of the additional indexers?
	- Using the MC setup UI, review and apply the changes.
79. In addition to the normal responsibilities of a search head cluster captain, which of the following is a default behavior?
	- The captain is a cluster member who performs normal search activities.
80. What happens to the indexer cluster when the indexer Cluster Master (CM) runs out of disk space?
	- The indexer cluster will continue to operate as long as no indexers fail.
81. Which event processing pipeline contains the regex replacement processor that would be called upon to run event masking routines on events as they are ingested?
	- Typing pipeline
82. In general, which statement is correct?
	- In general, search commands that can be distributed to the search peers should occur as early as possible in a well-tuned search.
83. A non-ES customer has a concern about data availability during a disaster recovery event. Which of the following Splunk Validated Architectures (SVAs) would be recommended for that use case?
	- Topology Category Code: M4
84. The universal forwarder (UF) should be used whenever possible, as it is smaller and more efficient. In which of the following scenarios would a heavy forwarder (HF) be a more appropriate choice?
	- When a predictable version of Python is required
85. When monitoring and forwarding events collected from a file containing unstructured textual events, what is the difference in the Splunk2Splunk payload traffic sent between a universal forwarder (UF) and indexer compared to the Splunk2Splunk payload sent between a heavy forwarder (HF) and the indexer layer?  (Assume that the file is being monitored locally on the forwarder.)
	- The UF sends a stream of data containing one set of medata fields to represent the entire stream, whereas the HF sends individual events, each with their own metadata fields attached, resulting in a lager payload.
