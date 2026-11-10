https://docs.splunk.com/Documentation/Splunk/9.3.1/admin/Distsearchconf
# Knowledge Bundle
On Search Heads, they resides under *$SPLUNK_HOME/var/run* with extension of .bundle for full bundles, or .delta for delta bundles. They are tar files, you can run *tar tvf* to see the contents.
During replication, it gets distributed to *$SPLUNK_HOME/var/run/searchpeers* directory on each search peer.
## Bundle Size Limit
### On Search Heads
``` distsearch
# When increasing bundle size, need to increase max_content_length on the indexers, by at least the same amount.
[replicationSettings]
maxBundleSize = 4096  # in MB
```
### On Indexers
``` server.conf
[httpServer]
max_content_length = 4294967296  # in Bytes

```
## Replication: Classic vs Cascading vs Mounted
### Classic
``` distsearch.conf
# Appropriate for small deployments
[replicationSettings]
replicationPolicy = classic
```
### Cascading
``` distsearch.conf
# Consider using cascading when nb of search peers exceeds 15
[replicationSettings]
replicationPolicy = cascading
```

```server.conf
[cascading_replication]
pass4SymmKey = <password>
```
### Mounted
Is not recommended for general use.

## Customize the bundle for an App
https://docs.splunk.com/Documentation/Splunk/9.3.1/DistSearch/Limittheknowledgebundlesize
``` distsearch.conf
[replicationAllowList]
<name> = <allowlist_regex>

[replicationSettings:refineConf]
replicate.lookups.conf = true
...

[replicationDenyList]
```