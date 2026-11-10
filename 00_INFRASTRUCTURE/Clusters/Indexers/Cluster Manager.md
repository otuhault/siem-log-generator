### CM as client into managers-apps/
*deploymentclient.conf*
```ini
# CLUSTER MASTER VERSION
# This file would have to be hand-copied to the $SPLUNK_HOME/etc/apps
# directory of the cluster manager. Note that the cluster manager itself
# will no longer be manageable by the deployment server, as the configs
# which are received go to the etc/manager-apps directory, rather than the
# etc/apps directory.
  
[deployment-client]
# Set the phoneHome at the end of the PS engagement
# 10 minutes
# phoneHomeIntervalInSecs = 600

# NOTE: Because of a bug in the way the client works when installing apps
# outside of $SPLUNK_HOME/etc/apps, these apps aren't listed as "installed"
# by the deployment client, meaning that taking an app away from the cluster
# manager's serverclass won't remove it from the manager-apps directory. This
# would have to be done by hand. Updates to existing apps will transfer
# from the deployment server just fine, however.
repositoryLocation = $SPLUNK_HOME/etc/manager-apps
serverRepositoryLocationPolicy = rejectAlways

[target-broker:deploymentServer]
# Change the targetUri
targetUri= ds-hostname-ip:8089

# These two options together make the cluster manager a client of the
# deployment server, stashing the received apps directly in the manager-apps
# directory. In this way, it becomes a proxy for the indexer config. This
# still requires positive action by the administrator to push the bundle
# from the cluster manager, but it requires the least amount of interactive
# steps by the admin.
```
This allows a Cluster Master to pull Apps from a Deployment Server directly into the directory indicated in `repositoryLocation`.
From the *serverclass.conf* file of your DS, you need to add: `stateOnClient = noop` for each app entry, for apps to be in the CM manager-apps directory.