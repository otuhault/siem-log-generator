# 🛡️ Splunk ES 8.5: Findings Management

> [!abstract] Overview In Splunk ES 8.5, **Findings** represent the evolution of "Notable Events." They are the core unit for monitoring security operations, allowing you to group detected events, analyze them, and manage their entire lifecycle.

## 1. Monitoring the SOC with Findings
The Findings management interface serves as the analyst's command center.
- **Centralized Visibility**: Provides a real-time view of the threat landscape and SOC workload.
- **Key Performance Indicators (KPIs)**: Track Finding volume by severity, owner, and status.
- **Advanced Filtering**: Ability to filter by security domains, urgency levels, or framework tags (e.g., MITRE ATT&CK).
## 2. Configuration and Customization
### Manual Field Configuration
To track specific data points, you can configure Findings to capture and display precise fields:
- **Field Extraction**: Customize which fields appear in the interface to meet business requirements.
- **Specific Tracking**: Ensures analysts have immediate access to critical data (e.g., `user`, `dest`, `file_hash`) without searching through raw logs.
### Token Expansion
Findings support **token expansion** to make titles and descriptions dynamic:
- **Syntax**: Uses `$fieldname$` (e.g., `Suspicious access detected for user $user$`).
- **Benefit**: Provides immediate context, allowing analysts to understand the nature of the alert at a glance.
## 3. Urgency Management
Urgency is calculated dynamically to assist with prioritization.
- **Urgency Matrix**: It is the product of the event **Severity** (defined in the correlation rule) and the **Priority** of the asset or identity (Asset/Identity).
- **Adjustment**: You can configure priority levels so that alerts involving critical assets (e.g., Domain Controllers) are automatically escalated to "Critical."
## 4. Lifecycle and Status
The workflow is managed through status changes:
- **Standard States**: New, In Progress, Pending, Resolved, Closed.
- **Link to Investigations**: A Finding can be promoted to or included in an **Investigation** for deeper, collaborative analysis.
- **Audit Trail**: Every status change is logged to ensure full traceability of analyst actions.
## 5. Annotations and Frameworks
Enriching Findings facilitates faster incident response:
- **Security Frameworks**: Native integration of **MITRE ATT&CK**, **NIST**, or **CIS** annotations.
- **Visualization**: Tactics and techniques are displayed directly on the Finding, helping analysts quickly understand the adversary's intent.
## 6. Finding Groups
To combat **alert fatigue**, Splunk ES 8.5 allows for the creation of Finding Groups:
- **Grouping Logic**: Based on common criteria (e.g., same source host, same attack type).
- **Noise Reduction**: Allows analysts to treat a single entity (the group) rather than dozens of redundant individual Findings.
---

### 💡 Obsidian Tips

- **Suggested Tags**: `#splunk` `#cybersecurity` `#SOC` `#SIEM` `#SplunkES_8.5`
- **Internal Links**: If you have related notes, consider linking to `[[Splunk Investigations]]` or `[[MITRE ATT&CK]]`.