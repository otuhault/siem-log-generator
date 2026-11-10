- Decouple the ingest and index by putting a smart bus in between.
- Advantages: building elastic ingestion plane, enhanced data safety and greater ingestion rate, less queue blockage etc.
- Any BYOL admin with Splunk 10.2 onwards (and ready to use Amazon SQS+S3 and Azure Storage Queue+Blobs)
- Customer needs to set up the cloud based message queue and then needs to enable the remote input and remote output queues in splunk indexers.
### Current Architecture Problem
- Indexer nodes handle ingest, indexing, and search simultaneously.![[Pasted image 20260217103735.png]]
### New Architecture Cuts
- The pipeline is cut between typing and indexing![[Pasted image 20260217104654.png]]

### Configuration
default-mode.conf 
outputs.conf
inputs.conf

### Configuration Best Practices
- For multisite indexer cluster, it’s recommended to have separate SQS queue and S3 bucket for smartbus  
blobs per site  
	- This would ensure the indexers from each site share the ingestion load with fellow indexers from the same site,  
	and would not compete with remote site indexers  
	- If sites are geographically far, having single SQS queue and S3 bucket may add ingestion latency for the  
	indexers from the far site  
	- This also means that the SQS and smartbus S3 bucket settings are asymmetric for different sites, and hence  
may need to be pushed through REST APIs to each indexer (instead of cluster bundle push) as an one time  
provisioning  
- It is recommended that S2S encoding format is used for blobs because S2S has been found to be faster than  
protobuf in Splunk Cloud over the years.  
-  It is highly recommended that SSE-C encryption scheme is used for best security measures to protect the  
ingest blobs  
- It is highly recommended that forwarders and HEC inputs use useACK, because default send interval is 4 sec  
and ingestors can crash in between and can lead to data loss. With useACK now back pressure is not created  
anymore and performance penalty is not much because the ACK is sent as soon as the message is on smartbus  
- For single site indexer cluster, smartbus configuration can be pushed through cluster bundle push