```ini
[general]
parallelIngestionPipeline = 2 # default
```
https://docs.splunk.com/Documentation/Splunk/9.3.1/Indexer/Pipelinesets
Required PS intervention to go beyond 2
Another way is to use asynchronous forwarding: https://www.linkedin.com/pulse/splunk-asynchronous-forwarding-lightning-fast-data-ingestor-rawat/


Associated with deploymentclient.conf file.
```ini
[sslConfig]
useSslClientSessionCache=true


# use this if you enabled same setting on DS
[deployment]
# Forwarders in the 6.x can connect with this, but for some reason
# their bundle (app) downloads have different checksums, and fail to
# validate. Not an option for those versions.
#pass4Symmkey = new_shared_secret
```
