
### Exposure Analytics Overview
1. **Purpose:** Exposure Analytics addresses a critical gap in security operations by continuously discovering assets and user identities, creating a "living inventory" that is updated and enriched in real time.
2. **Key Functions:**
    - Continuous asset and user discovery across multiple data sources including endpoints, network, cloud data, CMDBs, vulnerability assessment tools, Active Directory, etc.
    - Automated building and maintenance of an assets and identities framework inside Splunk Enterprise Security (ES).
    - Providing full context during investigations to speed up alerts, detections, and investigations.
3. **Challenges it Solves:** Traditional CMDBs (Configuration Management Databases) are often outdated, manual, and not trusted by security teams. Exposure Analytics overcomes this by maintaining a near real-time inventory that reduces time wasted chasing down information about hosts, assets, or users.
4. **Integration and Architecture:**
    - Exposure Analytics works across Splunk search heads and indexers.
    - It stores historical data in indexes and uses KV stores to handle high-volume data processing with load spreading over time to reduce performance impact.
    - Integration with existing features like UEBA (User and Entity Behavior Analytics) entity analysis, showing detailed tabs such as attack surface and attribution when entities are discovered.
5. **Benefits:**
    - Faster, smarter detections and investigations.
    - Reduced investigation costs and risk.
    - Enriched and prioritized asset and identity data improves accuracy in risk scoring.
6. **User Experience:**
    - Users access exposure analytics through entity analysis views where discovered entities show detailed contextual information.
    - Caching and efficient data retrieval ensure a responsive experience.
7. **Troubleshooting Tips:**
    - If exposure analytics panels do not appear, clearing browser session storage or opening in a new tab can resolve UI visibility issues.
    - Lack of extra tabs like attack surface or attributions indicates the entity is not discovered.

### Summary
Exposure Analytics is a powerful, continuously updating system within Splunk ES that helps security teams maintain accurate awareness of their assets and users, enabling more effective and efficient security operations.
Short version is its 5 days consultant. However there's a conversation on what is the right tool.


