Migrate from On Prem Splunk to Splunk Cloud:
- Configuration Transfer
- User and Role Migration
- Application Migration
- Historical Data Migration

What is not Cloud Migration?
- Migrating from customer managed Azure to customer managed AWS
- Migrating from ELK to Splunk
- Re-architecting Applications

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

![[Pasted image 20241118145606.png]]

# Co-Delivery
## PS
Mainly involved in technical configurations, validations, and ensuring the correctness and completeness of migrations across different components (data, user content, apps, and KV Store)
### Data Migration
- requesting migration credentials (S3 Credentials Keys) from Splunk TechOps
- validating configurations (public IPs, indexer access to S3, retention policies)
- applying data migration configurations and monitoring the upload process
- performing bootstrap in SplunkCloud to make data visible
- running validation searches and ensuring successful data migration
### User Content Migration
- rebranding user names to SSO user names (if applicable)
- migrating private user configurations across various search heads (Ad-hoc SH, ES SH, ITSI SH)
- validating role-based access control (RBAC) configurations
### Local content of all Apps Migration
- validating the installation and configurations of apps on various search heads (adhoc, ES, ITSI)
- performing app vetting and remediation
- migrating and configuring specific premium app content (ES, ITSI)
- enabling data model acceleration and configuring asset/identity feeds
### KVStore Migration
- performing kvstore backups and restores for various environments (ES, ITSI Adhoc)
- validating kvstore migrations
- recreating kvstore in Splunk Cloud if required
- coordinating with Splunk TechOps for KVStore operations (backup and restore)
## Partner
Primarily responsible for preparatory tasks, providing necessary information and credentials, assisting with configurations, and ensuring coordination and communication with users and other stakeholders
### Data Migration
- provisioning time windows for indexer restarts
- communicating data migration and change freeze windows to users
- providing a list of indexes not to be migrated (if applicable)
### User Content Migration
- providing a list of user apps for vetting
- assisting in setting up user groups in IDP for different search heads
- providing the groups names to Splunk PS for configuring SAML Groups
### Local content of all Apps Migration
- assisting in identifying and providing app-related information
- collaborating on any remediation tasks listed in the Statement of Work (SoW)
### KVStore Migration
- confirming KVstore use on Adhoc search heads
- assisting in collecting and populating data needed for custom KVStore configurations (if opting not to migrate directly)