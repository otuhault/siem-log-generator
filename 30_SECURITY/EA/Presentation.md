https://www.splunk.com/en_us/blog/security/introducing-exposure-analytics-in-splunk-enterprise-security.html
#### **![](https://www.splunk.com/icons/key-takeaways.svg)Key takeaways**
1. **Many security teams rely on outdated data and manual processes,** making it harder to spot risks, investigate alerts, and focus on the threats that matter most.
2. **Splunk Exposure Analytics creates a real-time, self-updating view** of users, devices, and assets so teams can better understand and secure their environment.
3. **With faster investigations, fewer false alarms, and stronger visibility,** organizations can move from reacting to problems toward preventing them.

**[Exposure Analytics](https://www.splunk.com/en_us/products/exposure-analytics.html "Exposure Analytics")** is available as a new capability within [Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html "Splunk Enterprise Security") (ES Essentials and ES Premier).

To continuously discover, enrich, and analyze entities—including assets and users—that comprise the attack surface.

### Key Features & Signature Capabilities
- **Continuous Entity Discovery:** Automatically builds and maintains accurate inventories of workstations, servers, cloud assets, and IoT devices by analyzing existing security events.
- **Entity Attribution:** Allows analysts to accurately attribute user and assets to findings and detections, identify unusual activity and gain visibility into how an entity’s state has evolved.
- **Attack Surface Explorer:** A visual tool to discover evolving entity-driven connections and relationships, helping you see how users and devices interact across your environment.


### Setup Guide
https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-set-up-guide-for-admins-in-splunk-enterprise-security

|Step number|Setup task|Description|Documentation|
|---|---|---|---|
|1|(Recommended) Set up company subnet directory|Populate a company subnet directory to help locate assets on enrichment lookups.|[Populate the company subnet directory](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-inventory-enrichment/populate-the-company-subnet-directory)|
|2|(Required) Configure entity discovery sources|Automatically detect data sources for discovery and pull data from specific events. You can select from predefined, compatible data sources, or add your own additional sources.|[Configuring entity discovery sources for Exposure Analytics](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/configuring-entity-discovery-sources-for-exposure-analytics)|
|3|(Optional) Add additional inventory fields|Manage your inventories by adding your own additional inventory fields.|[Adding an additional field](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-inventory-management/adding-an-additional-field-in-exposure-analytics)|
|4|(Optional) Add or modify enrichment rules|Use default enrichment rules to improve asset information such as missing field values. You can also create new enrichment rules.|[Create an enrichment rule](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/exposure-analytics/exposure-analytics-inventory-enrichment/enrichment-rules-in-exposure-analytics/create-an-additional-enrichment-rule)|
When you set up a source in Exposure Analytics, the source becomes assigned to an inventory. Exposure Analytics can only assign a source to an inventory if the source contains the key field for that inventory. As a result, when you identify a suitable source, you might want to choose a source that contains at least 2 of the key fields. The key fields for each inventory are as follows:

|Key field|Inventory|
|---|---|
|nt_host|Asset|
|ip|IP|
|user_id|User|
|mac|MAC|
### Types of sources
|Type of source|Description|
|---|---|
|streaming|A streaming source updates in Exposure Analytics within seconds of the source generating the events.<br><br>These sources contain asset-relevant events that you can search for without using search pipes in your SPL.|
|scheduled|A scheduled source can include any of the following:<br><br>- Events that update in real-time but have asset-related field values spread out over multiple events.<br>- Events that don't update in real-time. Exposure Analytics indexes them on a schedule, such as once per day, instead.<br>- Events with delayed indexing.<br><br>These sources contain asset-relevant events that require an advanced search.|
|static|Static sources are typically asset lists from databases, CMDBs, or uploads of Microsoft Excel or CSV files. For these sources, there might not be any indication of when each asset in the list was last detected on the network. You can label these sources as Passive in Exposure Analytics.|

