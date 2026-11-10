# Based Configs
![[Pasted image 20240826142305.png]]
- cluster:
https://drive.google.com/drive/folders/10aVQXjbgQC99b9InTvncrLFWUrXci3gz
- non-cluster:
https://drive.google.com/drive/folders/107qWrfsv17j5bLxc21ymTagjtHG0AobF
- props
https://docs.splunk.com/Documentation/Splunk/latest/Admin/propsconf

## Name Convention
CustomerName_LocationOfConfiguraitons_SplunkInstance_ConfigurationType
## Deployment Server
- org_all_deploymentclient/local/
	- app.conf
	- deploymentclient.conf
- org_all_forwarder_outputs
	- app.conf
	- limits.conf
	- outputs.conf
## Deployers
- org_all_deploymentclient/local/
	- app.conf
	- deploymentclient.conf
- org_all_forwarder_outputs
	- app.conf
	- limits.conf
	- outputs.conf
- org_all_indexes/local/
	- indexes.conf
- org_search_volume_indexes/local
- org_all_app_props/local/
	- props.conf
	- transforms.conf
	- app.conf
## Search Head
- org_all_search_base/local/
	- app.conf
	- authentication.conf
	- authorize.conf
	- web.conf
## Indexers
- org_all_indexer_base/local/
	- app.conf
	- inputs.conf
	- web.conf
- org_all_indexes/local/
	- indexes.conf
- org_indexer_volume_indexes/local/
	- indexes.conf
- org_all_app_props/local/
	- props.conf
	- transforms.conf
	- app.conf
## Forwarders
- org_dept_app_inputs
	- app.conf
	- inputs.conf
- org_all_deploymentclient/local/
	- app.conf
	- deploymentclient.conf
- org_all_forwarder_outputs
	- app.conf
	- limits.conf
	- outputs.conf
## All Components
- org_full_license_server/local
	- app.conf
	- server.conf

# Magic 8
- At file read / Intermediate Forwarder handoff (on UF)
	- EVENT_BREAKER
	- EVENT_BREAKER_ENABLE
- At aggregator Processor during Merging Pipeline
	- SHOULD_LINEMERGE (false if possible)
	- LINE_BREAKER
	- TRUNCATE
	- TIME_PREFIX
	- TIME_FORMAT
	- MAX_TIMESTAMP_LOOKAHEAD
strftime:
- https://docs.splunk.com/Documentation/Splunk/latest/Data/Configuretimestamprecognition

![[Pasted image 20240826181149.png]]


● Best Practices Recap
● Deploying Splunk
● Monitoring Console
● Configuration Management
● Access & Roles
● Data collection and Troubleshooting Inputs
● Indexing
● Installation and Upgrading
● Internals of search
● Index and Search Clustering

*Lab Instructions*: The lab instructions are intended to be vague in places to simulate information received from your external and internal Splunk customers when delivering. You are expected to treat this as you would with customers and perform due diligence to understand the real-requirement

*Understand the ask*: Before performing any configuration, read and understand the job specification. There isn’t time to complete the lab twice so make sure you understand what is required so as to do it right the first time.

*Perform Discovery*: Be sure to perform the necessary discovery for each lab environment. You must understand what is already configured to understand the changes required and cater for any ‘curve balls’.

*Establish a Plan*: It’s easy to lose your way or forget configuration steps under pressure. If you have to deviate from that plan, record what you did for your own auditing purposes later.

*Ask Splunk!*: If something is not working use all the tools at your disposal to help you work out what’s going on. Splunk logs so much about itself, if in doubt ASK SPLUNK! E.g. btool, splunkd.log, REST API ... the list goes on...




