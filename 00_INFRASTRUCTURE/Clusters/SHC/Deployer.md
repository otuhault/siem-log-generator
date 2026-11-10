# Managed by a Deployment-Server
```ini
[deployment-client]
serverRepositoryLocationPolicy = rejectAlways
repositoryLocation = SPLUNK_HOME/etc/shcluster/apps
```
# Deployer Configuration
```ini
[shclustering]
pass4SymmKey = yoursecuritykey
shcluster_label = shcluster1
mgmt_uri = [ mgmt-URI ] # cluster member's own address to itself.
# deployer_push_mode = full | local_only
```
The Deployer is responsible for distributing "baseline" content to the cluster members. This typically includes:
	– Distributed search information (indexing cluster)
	– Authentication information
	– Third-party applications (Splunkbase)
	– Any configuration files that are manually edited
The Deployer does not distribute search-related runtime configuration changes
	– Cluster automatically replicates such changes to all cluster members
If the `deployer_push_mode` is not explicitly set in `app.conf` for a given app, then that app follows the global `deployer_push_mode` setting.
## Push configuration Bundle
``` ini
splunk apply shcluster-bundle -target <URI>:<management_port>

# To control the rolling-restart:
splunk apply shcluster-bundle -target <URI>:<management_port> -action stage
splunk apply shcluster-bundle -target <URI>:<management_port> -action send
splunk rolling-restart shcluster-members
```
-> By default, triggers a rolling-restart as necessary
## Types of push
https://docs.splunk.com/Documentation/Splunk/9.3.1/DistSearch/PropagateSHCconfigurationchanges
**Mode:**
	- full
	- local_only               *(default for built-in apps)*
	- default_only            
	- merge_to_default  *(default)*
One tarball per app and one "users" tarball sent to the Captain only

How the cluster applies the configuration bundle
1. Deployer stages bundle, pushes new/updated apps to cluster members
2. Deployer pushes the "users" tarball to the Captain (if necessary)
3. Captain replicates any changed user configurations to cluster members
4. Each cluster member applies the tarball(s) locally

The staged bundle lives in $SPLUNK_HOME/var/run/splunk/deploy

Captain coordinates replication of artifacts, maintains registry
- artifacts stored in: $SPLUNK_HOME/var/run/splunk/dispatch