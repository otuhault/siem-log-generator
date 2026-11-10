https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/asset-and-identity-management/extract-asset-and-identity-data-in-splunk-enterprise-security

**Fields documentation**
https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.1/asset-and-identity-management/extract-asset-and-identity-data-in-splunk-enterprise-security
1. Add new lookup file (+ permissions)
2. Add new lookup definition (+ permissions) in SA-IdentityManagement App

>**Note**: In a distributed environment, these lookup table files are not replicated from the search heads to the indexers. Only the expanded lookup is replicated to the indexers. However, these lookup files are still replicated between search heads. If an asset or identity lookup table file grows in excess of 1GB+, it should be broken down into smaller files (for example, by location or by type or by easily identifiable category). When making changes to lookup files, only the updated files are replicated across search heads, reducing bundle sizes.