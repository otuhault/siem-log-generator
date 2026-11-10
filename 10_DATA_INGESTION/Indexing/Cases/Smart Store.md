**[Configure Smart Store Documentation](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/9.1/manage-smartstore/configure-smartstore)** 

[Base Apps indexes.conf](https://github.com/araman-m/base-apps-jinja/blob/main/base-apps-jinja/org_indexer_s2_indexes/local/indexes.conf)

## Current Restrictions on SmartStore Use
SmartStore support requires that the indexing tier conforms to certain restrictions:
- Each index's home path and cold path must be pointed to the same partition.
- _indexes.conf_ settings are restricted with SmartStore.
- SmartStore-enabled index cannot be converted to non-SmartStore.
- For multisite clusters, if any SmartStore indexes use report acceleration or data model acceleration, you must disable search affinity by setting all search heads to the site.
	- in *server.conf*
``` disable_search_affinity
	[general] 
	site = site0
	
	[clustering] 
	multisite = true
```

To ensure that there is remote storage access across the indexer cluster, you can run this command from one of the peer nodes:
`splunk cmd splunkd rfs -- ls --starts-with volume:remote_store`



# Intro - Recap
## SmartStore Deployment
### Consider enabling SmartStore under these circumstances:
- The amount of data in local storage grows. While local storage may be manageable for small deployments, it’s wise to reconsider its use as your deployment grows.
- Using indexer clusters, you find that considerable amounts of your time and your computing resources are devoted to managing the cluster.
- When most searches are over recent data.
### There are a few situations where local storage might be a better choice:
- If you have a small deployment with limited amounts of stored data
- If you have a frequent need to run rare searches. Rare searches require the indexer to copy large amounts of data, which can cause performance issues on SmartStore
- If you run frequent long lookback searches, you should increase your cache size or continue to rely on local storage.
## Current Restrictions on SmartStore Use
SmartStore support requires that the indexing tier conforms to certain restrictions:
- Each index's home path and cold path must be pointed to the same partition.
- _indexes.conf_ settings are restricted with SmartStore.
- SmartStore-enabled index cannot be converted to non-SmartStore.
- For multisite clusters, if any SmartStore indexes use report acceleration or data model acceleration, you must disable search affinity by setting all search heads to the site.
	- in *server.conf*
``` disable_search_affinity
	[general] 
	site = site0
	
	[clustering] 
	multisite = true
```
## Benefits and Limitations
### Benefits
SmartStore was created to provide a solution for decoupling computing and storage, enabling a more elastic deployment of the indexing tier.
Elasticity allows for added compute as needed. It also helps increase the amount of storage to extend your data retention intervals without causing additional infrastructure costs. SmartStore has a different architecture compared to Classic
- Reduction in storage costs in a cloud computing environment
- AWS S3 Storage is more economical than Elastic Block Storage.
- In a classic environment, non-SmartStore architecture on AWS, EBS comprises the infrastructure's cost.
- SmartStore reduces overall infrastructure costs.
### Limitations
While SmartStore is a great fit for most common Splunk usage patterns, there are situations where it might not be appropriate. A full list of restrictions is available in the SmartStore documentation.
- Significant All Time Searches
- Stringent Hardware Requirements
- Data Integrity Control
- Restoring Frozen Buckets
## Indexing in SmartStore
- Indexers maintain buckets for SmartStore indexes in only two states:
    - **Hot Buckets**
    - **Warm Buckets**
- Cold buckets are no longer needed, as SmartStore indexes only need to distinguish between warm and hot. Data storage can reside in warm buckets as it ages because it is inexpensive.
- Indexes that are configured to use SmartStore should have the maxDataSize for those indexes to auto instead of auto_high_volume - add this to the indexer cluster course
- it's important to understand that while indexers are limited to searching hot buckets and those currently in the cache, not all buckets reside in the cache at any given time. However, the indexer maintains metadata for all the buckets it needs to be aware of in the S3 storage
## Searching in SmartStore
The fundamentals of search are the same for SmartStore and non-SmartStore indexes. The indexer searches buckets in response to a request from a search head. The process of searching buckets always occurs in local storage.
**Hot Buckets**
These always reside in local storage whether or not it is a part of SmartStore index or non-SmartStore index. Searches of Hot buckets works the same for both environments..
**Warm Buckets**
Reside in the remote object store such as AWS after being uploaded from the indexer cache. Non-primary copies of warm buckets are evicted from indexers first, leaving searchable warm primary in the cache until space is needed.

In a SmartStore setup, each bucket is managed by a designated primary indexer. This indexer maintains metadata and, if a bucket isn't cached, only it will download the bucket from remote storage when needed. This strategy optimizes data retrieval and system performance by preventing redundant downloads.

> **Warm buckets do not reside in the local cache. If a warm bucket is not in a local cache, the cache manager must first fetch a copy from the remote storage and place it in the local cache. Then, the indexer can search the bucket as usual.**
## System Requirements
The requirements for SmartStore-enabled indexers are the same as those for non-SmartStore-enabled indexers. The main differences are the local storage requirements and the need to connect to remote storage.

- Indexer Requirements:
    - Hardware requirements: Same as any Splunk Indexer
    - 64-bit Linux Operating system.
    - Splunk Enterprise Version 7.2 or Later
    - Local Storage Requirements
    - SSD is preferred and highly recommended
    - Remote Storage
    - S3
    - Splunk Indexer is a client of S3
    - Able to use standard HTTP Protocols.

The amount of local storage available on each indexer for cached data must be proportional to the expected working set. For best results, enough local storage should be provided to accommodate at least 30 days' and at least 90 days worth of indexed data.
> **For use with Splunk Enterprise Security, provision enough local storage to accommodate 90 days' worth of indexed data rather than the otherwise recommended 30 days.**
## SmartStore Topology and Deployment options
### Cloud Service Provider (CSP), Customer Managed, Single Site
This is the by far best platform for SmartStore. It is relatively easy to implement and scale successfully. The three main Cloud Hosting Providers satisfy the networking and object store throughput requirements by default. The only key consideration is choosing the right instance types and sizing for the deployment and ensuring that it is cached properly for a given workload.
### Cloud Service Provider (CSP), Customer Managed, Multi-Site
Multi-site clusters using SmartStore on AWS are only supported across different availability zones within the same region, and clusters that span across multiple regions are not supported.
### On-Premises, Single-Site
Deploying SmartStore On-premises is challenging compared to a cloud hosting provider. Due to the performance requirements for throughput, it is rarely possible to use existing hardware. This topology consists of a local object store from a Splunk-validated vendor and a cluster of indexers with local SSD drives. It is not supported to use on-premise indexers with an object store hosted in the cloud, such as AWS-S3
### On-Premises, Multi-Site
This deployment choice will require an object store at each site. The object store will be responsible for near-synchronous, bi-directional replication between the sites.
# Deploying SmartStore on Indexer Clusters
## SmartStore Architecture Comparisons
Non-clustered and indexer cluster peers have distinct roles and configurations within the data management system.
- **Non-Clustered Peers:** Each peer operates independently without a cluster manager, making them easier to configure and manage. They handle their own data lifecycle, including hot, warm, and cold buckets. However, they lack built-in redundancy, risking data loss if a peer fails, unless external backup solutions are used.
- **Indexer Cluster Peers:** Peers are coordinated by a cluster manager, which manages data replication and redundancy, providing resilience against data loss. While more complex to configure due to required synchronization and communication, it offers greater scalability through distributed indexing and search, efficiently handling large data volumes.

## Why use SmartStore with Splunk Clusters
- All the existing benefits of Splunk clusters still apply
- SmartStore can rediscover and recover data
    - Fully recoverable if surviving peers are equal or greater than the replication factor
    - The cluster can still recover even if all peers go down
        - Only warm buckets can be recovered
    - Re-using data from one cluster on another is possible with SmartStore cluster
- Cluster recovery (fixup) is super fast
    - There is no need for replicate the entire bucket's contents
    - Only one peer needs to download bucket contents if required  
- Storage usage and bucket retention are centrally managed
## SmartStore Cluster Deployment Requirements
- Same requirements and restrictions apply as in non-clustered peer
    - 64-bit Linux 3.x+
    - SSD is preferred and highly recommended
    - S3 or S3-compliant storage service
    - Splunk peer nodes are clients to S3
- SmartStore configurations apply on the indexer cluster peers only
    - The cluster must be in a valid and complete state
        - Confirm that there are no pending fixup tasks
    - All cluster nodes must be on the same version
    - The peer node configurations must be identical
    - The replication factor and search factor must be equal
        - Only hot buckets follow the traditional replication process
## Deploy SmartStore on a new indexer Cluster
### Pre-requisites:
- Ensure that you have a working Splunk Enterprise environment.
- Prepare your object storage (e.g., AWS S3, Google Cloud Storage) and obtain the necessary access credentials.
### Setting up Security Strategies
Understand the SmartStore security strategies that will be used for the specific deployment type. Prepare to implement these security strategies during the deployment process.
- [**SmartStore on S3 security strategies**(opens in a new tab)](http://docs.splunk.com/Documentation/Splunk/9.4.1/Indexer/SmartStoresecuritystrategies)
- [**SmartStore on GCS security strategies**(opens in a new tab)](http://docs.splunk.com/Documentation/Splunk/9.4.1/Indexer/SmartStoreGCPsecuritystrategies)
- [**SmartStore on Azure Blob security strategies**](http://docs.splunk.com/Documentation/Splunk/9.4.1/Indexer/SmartStoreAzuresecuritystrategies)
### New Splunk Enterprise Instance
Install a new Splunk Enterprise instance and enable it as the manager node for a new indexer.
### Indexer Cluster Replication
Set the indexer cluster’s replication factor and search factor to equal values, for example, 3/3.
### Manager Node and SmartStore Deployment
1. On the manager Node, create or edit the following command:
    1. _$SPLUNK_HOME/etc/manager-apps/_cluster/local/indexes.conf_
    2. Specifiy the Smartstore settings as show in this example according to the S3 configurations. ( depending on your deployment, you may use AWS, Azure or GCP)
    3. When the peer nodes start-up, the manager node automatically distributes these settings, along with the rest of the configuration bundle

This is an example of a configuration
```
[default]
remotePath = volume:remote_store/$_index_name
repFactor = auto

# Configure the remote volume.
[volume:remote_store]
storageType = remote
path = s3://mybucket/some/path
remote.s3.access_key = <S3 access key>
remote.s3.secret_key = <S3 secret key>
remote.s3.endpoint = https:|http://<S3 host>

# This example stanza configures a custom index, "cs_index".
[cs_index]
homePath = $SPLUNK_DB/cs_index/db

# SmartStore-enabled indexes do not use thawedPath or coldPath, but you must still specify them here.
coldPath = $SPLUNK_DB/cs_index/colddb
thawedPath = $SPLUNK_DB/cs_index/thaweddb
```
### Manager Node configuration
- On the manager node, run this command:
    - `splunk apply cluster-bundle --answer-yes`
### Install and enable peer nodes
Install and enable the peer nodes and search as you would for any new indexer cluster. It may take a bit of time for the peer nodes to download the configuration bundle with the SmartStore settings.
To view the status of the configuration you can run the `splunk show cluster-bundle-status` command
### Testing the deployment
- There are ways to test the deployment to ensure it is functional and proper.
    - **Monitoring the status using this command:**
        - `splunk show cluster-status -auth <admin>:<password>`
            
    - **Confirming remote storage access across the indexer:**
        - Place a sample text file in the remote store and run this command:
            - `splunk cmd splunkd rfs -- ls --starts-with volume:remote_store`
            - This will provide a  list of files that are present in the remote store
                
    - **Validate data transfer to the remote store:**
        - Send some data to the remote store and run this command
            - `splunk internal call /data/indexes/<indexname>/roll-hot-buckets -auth <admin>:<password>`
            - Look for warm buckets.
                
    - **Validating data transfer from the remote store:**
        - On one of the peer nodes, evict a bucket from the cache with a POST to this REST endpoint:
            - services/admin/cacheman/**cid**/evict
            - where **cid** is bid|**bucketId**|.
                - For example: `"bid|cs_index~0~7D76564B-AA17-488A-BAF2-5353EA0E9CE5|"``
                    
        - Run a search locally on the peer node. The search must require data from the evicted bucket.
        - The peer node must now transfer the bucket from remote storage to run the search. After running the search, you can check that the bucket has reappeared in the cache.
## Deploy Multisite indexer clusters with SmartStore
- Deploying a multisite indexer cluster deployment with SmartStore helps with disaster recovery. Clusters and their Object stores can be hosted by a public cloud provider or in an on-premise data center.
- There are two deployment types available:
    - Active-active multisite hosted in a public cloud provider (AWS, GCP, or Azure), within a single region across multiple zones
    - Active-active multisite hosted across data centers, using S3 API-compliant on-premises object stores
### Public cloud provider-hosted, within a single region
This deployment supports AWS, GCP, and Azure, using S3, GCS, and Azure Blob Storage respectively. Indexer clusters are in separate zones within a region, sharing a remote store endpoint. The cloud provider manages object store failover, and each zone hosts a cluster manager node, with one active and others as standby.
### On-premises hosted, across data centers
This deployment type is available only for S3-API-compliant object stores, which is limited to two sites hosted in an on-premises datacenter. These sites host active replicated object stores.  One site is on an active cluster manager, and the other hosts a standby cluster manager.

> **Multisite deployments must be hosted on a single public cloud provider or on-prem datacenter. They cannot span multiple cloud providers or include both a cloud provider and a datacenter.**
### Requirements for all multisite clusters with SmartStore
In addition to the standard requirements, multisite clusters with SmartStore have specific deployment and configuration needs to function properly. This includes setting up a standby manager. For further information, please refer to the Splunk documentation.
# Configure and Optimize the SmartStore for your environment
## Configure the S3 remote store for SmartStore
### Pre-Requisites
You must have access to an AWS account with permission to create and manage S3 buckets. If applicable, you must obtain access to the existing S3 buckets. This step must be followed in order to move on to the next configuration step.
### Create an S3 Bucket
- Log into the AWS management console
- Navigate to the S3 Service
- Create a new bucket, ensuring the name is unique globally
### Set Up Access Permissions
- Configure bucket policies to allow access from the Splunk Indexers
- Depending on the setup, IAM policy and roles will have to be created for the Splunk instance. Ensure that the necessary S3 permissions are provided.
### Configure the SmartStore in Splunk
- Access the Splunk instance and navigate to the indexer cluster configuration
- Edit the _indexes.conf_ file to define the remote store details
### Modify the indexes.conf file
Specify the S3 bucket as the remote store
Example Configuration:
```
[index_name]
remotePath = s3://your-bucket-name/optional-path
```
### Configure the server.conf file:
Ensure your server.conf file includes necessary details for SmartStore.
Example
```
[smartstore]
enable = true

[volume:remote_store]
storageType = remote
path = s3://your-bucket-name/optional-path
```
### Test the Configuration
- Restart the Splunk Service to apply the changes
- Verify that data is being uploaded to the S3 Bucket.
## Migrating Indexer Cluster to Use SmartStore
In the following section, we will provide an overview of the migration process for SmartStore. This will encompass the migration of existing data, a detailed explanation of the procedures involved, and the methods for monitoring the migration process.
## Migrate existing data on an indexer cluster to SmartStore
You can migrate the existing data on your indexer cluster from local storage to the remote store. You can modify the migration process if you only want to migrate some indexes. Indexers support a mixed environment of SmartStore and non-SmartStore indexers.
Because this process requires the cluster to upload large amounts of data, it can take a long time to complete and can significantly impact concurrent indexing and searching.
## Migrate Data
The migration data process is performed in two phases.
1. Test the SmartStore configurations and remote connectivity on a standalone test instance.
2. Run the migration by applying the configurations to your production indexer cluster. In this section, we will review this phase in more detail below.
### Prerequisites
- Review Smartstore requirements to ensure that you are meeting the system requirements needed.
- Ensure that the appropriate configurations are followed and reviewed for the particular deployment.
### Security strategies prepared
- Understand and prepare to implement security strategies during the deployment process.
- Ensure you follow the appropriate security strategies for your deployment.
### Upgrading cluster nodes
Prior to the migration, upgrade all cluster nodes. This includes the manager node, peer nodes and search heads to the latest version of Splunk Enterprise.
### Confirm cluster state
Confirm that the cluster is in a valid and complete state. This will also include the cluster having both replication and search factors met.
This can be confirmed using the Manager Node Dashboard.
### Confirm status of buckets
- Confirm that there are no bucket fix up tasks in progress or pending.
- This can be determine by accessing the Manager Node Dashboard and clicking on indexes tab then the Bucket status button.
### Splunk maintenance mode
- Run `splunk enable maintenance-mode` on the manager node.
- To confirm that the manager is in maintenance mode, run `splunk show maintenance-mode.`
### Stop peer nodes
- Make sure to stop all peer nodes.
- When bringing down the peer nodes ensure to use _splunk stop_ command and not the _splunk offline_ command
### Editing manager node
On the manager node, edit the existing _$SPLUNK_HOME/etc/manager-apps/_cluster/local/indexes.conf_ file to make the following additions.
1. Specify the SmartStore index global and volume settings. Assuming that you have already tested these settings on your standalone instance, you can copy the settings over from your standalone instance, remembering to add a line for _repFactor=auto_
2. Configure the data retention settings, as necessary, to ensure that the cluster will follow your desired freezing behaviour, post-migration
This step is extremely important to avoid unwanted bucket freezing and possible data loss.
### Master node changes if necessary
On the manager node, edit _$SPLUNK_HOME/etc/manager-apps/_cluster/local/server.conf_ for any necessary changes to the SmartStore-related _server.conf_ settings on the peer nodes.
In particular, configure the cache size to fit the needs of your deployment.
### Rolling restart setting
If the setting rolling_restart in _$SPLUNK_HOME/etc/system/local/server.conf_ on the manager node has some value other than "restart," such as "searchable_force," you must change the value to "restart" before applying the bundle
- On the manager node, run:
    - `splunk edit cluster-config -rolling_restart restart`
### Applying the cluster bundle
To apply the cluster bundle on the manager node, you want to apply the command:
- `splunk apply cluster-bundle --answer-yes`
### If the value of rolling_restart was changed
If the value of rolling_restart was changed prior to applying the bundle, you have to revert the settings to their original value.
To do this, you need to run the following command on the manager node:
- `splunk edit cluster-config -rolling_restart <original_restart_type>`
### Starting up all peer nodes
Start all the peer nodes. Wait briefly for the peer nodes to download the configuration bundle with the SmartStore settings.
To view the status of the configuration bundle process, you can run the `splunk show cluster-bundle-status command`
### Disabling maintenance mode
Run _splunk disable maintenance-mode_ on the manager.
To confirm that the manager is not in maintenance mode, run _splunk show maintenance-mode_.
### Peer nodes starting up again
- After the peer nodes have started again they will need some time for them to begin uploading their warm and cold buckets to the remote store.
- Cold buckets use the cold path as their cache location, post migration
### Confirm remote storage access
To ensure that there is remote storage access across the indexer cluster, you can run this command from one of the peer nodes:
`splunk cmd splunkd rfs -- ls --starts-with volume:remote_store`
This command lists any files that are present in the remote store. It should also show that. the cluster is starting to upload warm buckets to the remote store.
### To determine that migration is complete
- Confirm that the cluster is in a valid and complete state, with both replication and search factors met.
- Confirm that the search `|rest splunk_server=idx1 ... /services/admin/cacheman |search cm:bucket.stable=0 |stats count` returns 0.
### Testing SmartStore functionality.
To validate data fetching from remote storage, do the following:
- On one of the peer nodes, look for a fully populated bucket that contains both tsidz files and rawdata files.
- Evict the bucket from the cache, using this REST endpoint:
    - `services/admin/cacheman/<cid>/evict`
    - where `<cid> is bid|<bucketId>|.` For example: `"bid|cs_index~0~7D76564B-AA17-488A-BAF2-5353EA0E9CE5|"`
- Run a search locally on the peer node. The search must be one that requires data from the evicted bucket.
The peer must now transfer the bucket from remote storage to run the search. After running the search, you can check that the bucket has reappeared in the cache.
## Monitoring the Data Migration
Using the monitoring console, you can monitor the migration progress.
Using an endpoint from the manager node, you can also determine the migration status.
```
$ splunk search "|rest /services/admin/cacheman/_metrics |fields splunk_server migration.*" -auth <admin>:<password>
```
The endpoint will return data on the migration. This will help you determine where each of the peers is.
In the example below, peer1 is on its 8th job out of 35, so the peer's migration is about 20-25% complete. The _start_epoch_ field tells you when the migration began, allowing you to estimate an approximate completion time.
## What is SmartStore Cache Manager
The cache manager manages the SmartStore data in local storage. It attempts to maintain any data likely to participate in future searches.  This helps minimize the potential of search delays resulting from data being downloaded from the remote store.
- The cache manager does the following:
    - Copies buckets from local to remote storage when the buckets roll from hot to warm
    - Fetches bucket files from remote storage into the local storage cache when a search needs the files
    - Evicts files from the local storage cache when they are no longer likely to be needed for future searches
## Configure data retention for SmartStore Indexes
Cache manager settings reside in the `[cachemanager]` stanza in _server.conf_.
- Initiate eviction based on occupancy of the cache's disk partition
    - The _max_cache_size_ setting specifies the maximum occupied space in megabytes for the disk partition containing the cache.
    - The minFreeSpace setting specifies a partition's minimum free space in megabytes.
    - The _eviction_padding_ setting controls the amount of additional space, in megabytes, that the cache manager protects beyond the _minFreeSpace_ value.
        
- Set cache retention periods based on data recency.
    - By setting cache retention periods, it can protect data from eviction. Setting the cache retention capability can be done in two ways:
        - On a global level (across all indexes), to favor recently indexed data over recently used data.
        - On a per-index level, the cache retention data in critical indexes will be favored over data in non-critical indexes.
        - Retention periods can be set using the _hotlist_recency_secs_ setting and the _hotlist_bloom_filter_recency_hours_ setting.
            
- Set the maximum download and upload rates.
    - The _max_concurrent_downloads_ setting in the _server.conf_ specifies the maximum number of buckets that can be downloaded simultaneously from remote storage. Its default is 8.
    - The _max_concurrent_uploads_ setting in the _server.conf_ specifies the maximum number of buckets that can be uploaded simultaneously to remote storage. Its default is 8.

On indexer clusters, data retention for SmartStore indexes is managed cluster-wide. Once a bucket in the index meets the criteria for freezing, the cluster removes the bucket entirely from the system, both from remote storage and from any local caches where copies of it exist.
Because SmartStore indexes do not support the cold bucket state, except for migrated buckets, buckets roll from warm directly to frozen. Bucket freezing occurs whenever any of these limits is reached. If the settings are improperly configured, this can result in unexpected data loss.
## Bootstrapping SmartStore Cluster
Bootstrapping refers to the initial setup and configuration process that enables the indexers within a cluster to use SmartStore efficiently for data storage.  When you Bootstrap new cluster or indexer inherits the SmartStore buckets from the old cluster or indexer.
### Bootstrap SmartStore indexes onto a new indexer cluster
1. After ensuring that all local data, including data from any hot buckets, is available on the remote store, bring down the old cluster or standalone indexer.
2. Bring up the new cluster and configure its indexes for SmartStore. Follow the procedure in Deploy SmartStore on an indexer cluster.
3. Note the following:
    - When configuring indexes.conf, add stanzas for all SmartStore indexes that you want to bootstrap.
    - Confirm that you have set repFactor=auto globally to apply to all indexes in the cluster, including the ones that you intend to bootstrap.
    - Configure the path attribute to point to the same remote storage location as on the old cluster or standalone indexer.
    - Maintain the remote store encryption and access settings used by the old cluster or standalone indexer.
    - All indexes that you bootstrap must be SmartStore-enabled on the new cluster. You cannot use bootstrapping to revert an index to non-SmartStore.
### The Bootstrap Process
1. The manager node obtains a list of all SmartStore indexes from the peer nodes.
2. Bootstrapping proceeds on a per-index basis:
    1. The manager node assigns one peer to obtain a list of all buckets for the index from the remote store.
    2. The peer returns the bucket list to the manager in batches.
    3. Batch size is controlled by the _recreate_index_fetch_bucket_batch_size_ attribute in the manager node's _server.conf_ file.
    4. The manager node uses the list to assign buckets, randomly but evenly, across all available peer nodes.
    5. The manager node provides each peer node with a set of target peer nodes of a number equal to the replication factor.
    6. Each peer node downloads, from the remote store, the metadata for its assigned buckets.
    7. The peer node uses the downloaded metadata to update the index's .bucketManifest file and to create empty directories for its assigned buckets. The primary marker for each bucket resides on the peer that downloaded that bucket's metadata from the remote store.
    8. The peer node replicates copies of its primary buckets' metadata to target peer nodes to meet the replication factor.
# Troubleshooting SmartStore Deployment
## Troubleshooting SmartStore
### Monitoring Console
- The monitoring console can be used to monitor most aspects of your deployment. This section discusses the console dashboards, which provide insight into SmartStore activity and performance.
- Several dashboards monitor SmartStore status. The dashboards are scoped to a single instance or the entire deployment. Find the dashboards under the Indexing menu and the SmartStore submenu:
    - Smartstore Activity Dashboards review information on activity related to the remote storage, such as:
        - Remote storage connectivity
        - Bucket upload/download activity
        - Bucket upload/download failure count
    - Smartstore Cache Performance Dashboards review information on the local caches, such as:
        - The values for the server.conf settings that affect cache eviction
        - The bucket eviction rate
        - Portion of search time spent downloading buckets from remote storage
        - Cache hits and misses
        - Repeat bucket downloads
### Log Files
- Several log files can provide insight into the state of SmartStore operations.
    - _splunkd.log._ Examine these log channels:
    - _S3Client._ Communication with S3.
    - _GCSClient._ Communication with GCS.
    - _AzureStorageClient._ Communication with Azure Blob storage.
    - StorageInterface. External storage activity (at a higher level than S3Client, GCSClient, or AzureStorageClient).
    - _CacheManager_. The activity of the cache manager component.
    - _CacheManagerHandler._ Cache manager REST endpoint activity (both server and client-side).
    - _KeyProviderManager._ Errors related to key provider setup and configuration. The key provider is used when the system has encrypted data on the remote store.
- _search.log._
    - Examine these log channels:
        - CacheManagerHandler. Bucket operations with cache manager REST endpoint activity.
        - S2BucketCache. Search-time bucket management (open, close, and so on).
        - BatchSearch, CursoredSearch, IndexScopedSearch, ISearchOperator. Search activity related to buckets.
- _Audit.log_
    - Contains information on bucket operations, such as upload, download, evict, and so on.
- _Metrics.log_
    - Contains metrics concerning operations on external storage.
- _Splunkd_access.log_
    - Contains a trail of the search process activity against the cache manager REST endpoint.
### CLI Commands
- Using the _dbinspect_ command, information about the SmartStore buckets can be obtained. It is important to understand the effect of the cached argument on SmartStore bucket searches.
    - The “t” in the cached argument obtains statistics from the buckets manifest
        - _cached=t_
    - The “f”in the cached examines the bucket that resides in the remote store.
        - _cached=f_
- _sizeOnDiskMB_ is one of the fields that dbinspect returns. If the Smartstore bucket is no longer in the indexers’s local cache, the bucket directory is empty and thus has a size of 0. Therefore if _cached=f dbsinspect_ inspects the local bucket to determine the value of sizeOnDiskMB
- _cached=t_, the indexer pulls the bucket's manifest from the copy in the remote store and dbinspect then uses the statistics in that manifest, thus returning the true size of the bucket.
### REST Searches
- Use the following search to get a list of buckets that are actively being searched:
    - `| rest /services/admin/cacheman search=cm:bucket.ref_count>0`
        
- The ref_count value increments by 1 when the search opens the bucket and decrements by 1 when the search closes the bucket.
- Use the following search to get a list of buckets that have not been uploaded to the remote store (that is, are not "stable" on the remote store):
    - `| rest /services/admin/cacheman search=cm:bucket.stable=0`
## Troubleshooting Connectivity
One common problem is connectivity with the remote storage. Connectivity problems can result from network or permissions issues. Use the _splunkd cmd rfs_ command to test connectivity with remote storage.
- List the contents of the "foobar" index on remote storage:
`splunk cmd splunkd rfs ls index:foobar``
- List the contents of a given bucket on remote storage:
`splunk cmd splunkd rfs ls bucket:foo~737~B1CE2AB0-CE4A-4697-83F2-1C5DBFB6485A`
- Test getting a file from remote storage:
`splunk cmd splunkd rfs getF bucket:foo~737~B1CE2AB0-CE4A-4697-83F2-1C5DBFB6485A/guidSplunk-B1CE2AB0-CE4A-4697-83F2-1C5DBFB6485A/Hosts.data  /tmp/foo/`
- Test getting an unencrypted file from remote storage that uses SSE-C:
`splunk cmd splunkd rfs getR bucket:foo~737~B1CE2AB0-CE4A-4697-83F2-1C5DBFB6485A/receipt.json  /tmp/foo/`
## Cluster Recovery Scenarios
### Nb of failed node
- The cluster is still valid
    - Can recover using the local copies
    - The master Initiates a normal fixup
- Peers copy the bucket metadata until recovered to a complete state
    - Hot buckets roll and upload
        - Primary has the full content in cache
    - Cached buckets are only needed to push their metadata
- Peers fetch contents as-needed basis from the remote storage
### Nb of failed node >= RF
- The cluster may not have all buckets
    - Only buckets that have been stored in the remote can be recovered
    - Some data in hot buckets are lost
- The master considers the current bucket list invalid
    - Asks a peer to re-generate the list
    - Re-assigns peers to download the missing buckets
    - The peers only download the bucket metadata and replicate to meet replication factor

When a peer node fails, the master handles fix-ups essentially the same way as for non-SmartStore indexes, except. The replication factor on warm has no effect on how the remote storage service achieves the complete state. The replication factor still controls the metadata replication. Metadata replication is done with a REST endpoint POST to the target peers

## Overall common Issues
When troubleshooting SmartStore, common issues may occur. Below are three common issues we see when it comes to deploying SmartsStore.
### Searches are running slowly or appear stuck
- Slow or stuck searches are often due to these issues:
    - Performance issues with remote storage.
    - The cache manager is evicting buckets too aggressively.
    - Cold cache issues. A cold cache occurs when an indexer cluster peer node participating in a search does not have a local copy of some needed buckets and, therefore, must download the buckets from remote storage. The manager assigning primary bucket copies to different peers can cause a cold cache.
### Searches erroring out
The search-related error message "_Failed to localize fileSet='....' for bid='...'._ Results will be incomplete." indicates an error condition while downloading the specified bucket.
For more details, examine _splunkd.log_ on the indexer issuing the error.
### Disk full issues
A disk full-related message indicates that the cache manager cannot evict sufficient buckets.
- These are some possible causes:
    - Search load overwhelming local storage. For example, buckets opened by at least one search process might consume the entire cache. When the search ends, this problem should go away.
    - Cache manager issues. If the problem persists beyond a search, the cause could be related to the cache manager.  Examine _splunkd.log_ on the indexer issuing the error.

# Documentation Resources
**Module 1**
- [Deploying SmartStore on indexer clusters(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/MultisiteSmartStore)
- [Requirements for SmartStore on Multisite Indexer(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/MultisiteSmartStore#:~:text=enabled%20indexer%20clusters.-,Requirements%20for%20all%20multisite%20clusters%20with%20SmartStore,-Multisite%20clusters%20with)
- [Migrate existing data on an indexer cluster to SmartStore(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/MigratetoSmartStore)
    
**Module 2**
- [Bootstrap SmartStore indexes(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/9.3.2/Indexer/BootstrapaSmartStoreindexercluster)
- [Configure the S3 remote store for SmartStore(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/ConfigureremotestoreforSmartStore)
- [Configure Data Retention(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/SmartStoredataretention)
    
**Module 3**
- [Troubleshooting SmartStore(opens in a new tab)](https://docs.splunk.com/Documentation/Splunk/latest/Indexer/TroubleshootSmartStore)

# SmartStore Lab - Implementing SS on a Indexer Cluster
## Lab 1 - Migrate existing data on an indexer Cluster to SmartStore
1. On CM: `./splunk enable maintenance-mode`
2. Stop indexers 1 and 2
3. On CM, add into system/local/indexes.conf:
```
[volume:remote_store}
storageType = remote
path = s3://smartstore-858617-splunk-smartstore
remote.s3.endpoint = https://s3.us-east-2.amazonaws.com
```
4. Create an app into manager-apps/ and push with: `./splunk apply cluster-bundle`
5. Start indexers 1 and 2
6. From the CM:
```
echo "hello" > /tmp/test.txt
aws s3 cp test.txt s3://smartstore-858617-splunk-smartstore
```
7. From an indexer:
`./splunk cmd splunkd rfs -- ls --starts-with s3://smartstore-858617-splunk-smartstore`

If the migration returns a count of zero, this means the migration is complete
```
| rest splunk_server=idx1 /services/admin/cacheman 
| search cm:bucket.stable=0 
| stats count
```

```
| rest splunk_server=idx1 /services/admin/cacheman
| eval stable_size = if('cm:bucket.stable'=1,
'cm:bucket.estimated_size', 0)
| stats sum(stable_size) as stable_bytes,
sum(cm:bucket.estimated_size) as all_bytes
| eval migration_progress=if(all_bytes > 0,
round((stable_bytes / all_bytes) * 100), 0)."% complete"
| fields migration_progress
```
## Lab 2 - Bootstraping Indexer Cluster
1. Add server.conf and inputs.conf in manager-apps/
2. push the bundle to the indexers
3. Get the pass4symmkey for the cluster stanza
4. Execute the following command on idx3:
`/opt/splunk/bin/splunk edit cluster-config -mode peer -manager_uri https://smartstore-858617-emplo000000000072547-cm1.students.splunk.education:8089 -secret ou025ub4d062 -replication_port 9100`

./splunk cmd splunkd rfs -- ls --starts-with s3://smartstore-858617-splunk-smartstore