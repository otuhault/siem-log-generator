https://splservices.atlassian.net/wiki/spaces/DA/pages/4778131465/Advisory+UEBA+Cloud+vs+UEBA+CMP+vs+UBA+Legacy+-+Key+Differences
CMP: Customer Manager Platform.
There are key differences between UEBA Cloud and CMP that will affect scoping, implementation, and tuning phases being delivered in the filed.
# UEBA Cloud
- In addition to leveraging Splunk runtime with AI toolkit (formerly MLTK) for detections, UEBA Cloud has an additional runtime engine that operates as a cloud-native service on Splunk Cloud Services (SCS) to offload workloads for scale, cost efficiency and advanced capabilities. Applicable data is sent to this service automatically through native indexAndForward Splunk capabilities, and results are sent back to customer stack once detections are run.
- The UEBA backend services mentioned above perform field extraction, normalization, and transformation of received data based on the Open Cybersecurity Schema Framework (OCSF) vocabulary and attribute semantics by a series of Cloud microservices
- Content is automatically updated by Splunk's managed pipeline
- Cloud ingest focuses on raw log sources and normalizes them in the backend
# UEBA CMP
- All detections are contained and run on customer Enterprise Security search head, and standard sizing/performance guidelines apply (largely based on number of expected concurrent searches)
- All data normalization occurs on read, on customer Enterprise Security search head
- Content updates arrive as a Splunk App that needs to be imported into the Enterprise Security environment manually
- Primary data inputs are CIM compliant datasets that align to standard OOTB datamodels
# UEBA Installation
Since Enterprise Security can be downloaded from Splunkbase with both Essentials and Premier license entitlements, UEBA content is not packaged with Enterprise Security by default for CMP deployments.  The UEBA PX app will be packaged by default, which contains UEBA related dashboards, but detection and populated dashboard content would not be available without the Premier entitlement.  It requires those with the Premier entitlement to download the UEBA content app separately from Splunkbase and install it manually on the Enterprise Security search head, using the standard app installation process.  Details here:  [https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/installing-ueba-for-splunk-enterprise-security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/installing-ueba-for-splunk-enterprise-security "https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/installing-ueba-for-splunk-enterprise-security")
