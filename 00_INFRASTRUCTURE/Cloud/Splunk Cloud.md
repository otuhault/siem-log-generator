# Classic Experience
- Supports QZS and GCP environments
- Uses Inputs Data Manager (IDM) for data collection
- Supports Hybrid Search
- Existing non-Noah stack
## Search Heads
Single SH or SHC, no SHC for ES
## Data Ingestion
Configured on IDM
# Victoria Experience
- Enhanced capabilities and service limits than Classic
- Currently available only on AWS Cloud Platform
- Data collection is configured directly in the Search Head tier
- Search Head Clusters available for ES
- Supports Federated search
- Stack enabled with Noah service
## Search Heads
SHC with load balancer, SH for ES and ITSI
## Data Ingestion
Configured directly in SH tier

# SCMA - Splunk Cloud Migration Assessment App for Splunk
- Assess Readiness
- Streamline Process
- Guidance
- Optimization

# Enterprise Security
- **KV Store migration at the time of cutover:** can be performed twice, once before and once after the cutover. Migrating before is beneficial for the UAT phase, but post-cutover migration is mandatory
- **On-prem SOAR integration with ES SH:** ensure that ES can connect to SOAR. Ticket needed to enable connectivity from SplunkCloud to on-premises SOAR. Splunk App for SOAR and Splunk App for SOAR Export is installed in Splunk Cloud. Ensure dependencies such as JS and CSS files are also migrated.
# ITSI
- **Backup and Restore ITSI KV Store data:** perform a backup of ITSI using the native Backup/Restore ITSI UI on the CMP environment and restore it in SC ITSI SH

# Data Migration Options
## S2DC Migration (Preferred)
Migrate to Splunk Managed Cloud using S2DC method.
**Use Cases**
- Non-clustered or Clustered environment
- Linux systems with Splunk 7.2.9+
- Windows OS
- SmartStore enabled environments
**Benefits**
- Data Copy vs Move: in this method, buckets are copied rather than moved, as done in the SmartStore method
- This process can be run on both indexers with or without SmartStore
- Data remains on CMP
**Considerations**
S2DC dependencies has to be downloaded manually in an air-gapped environment

