### Threat Collections Data Optimisation
Enables data retention policies for Threat Intel Collections - ES Administrators are able to set up data retention policies (max age/ max size) for threat intelligence as per the Data Retention Policy Framework added to ES 8.1
Can access through: Settings | Data Inputs | MC KV Store Collection Retention
- Onboards threat intel collections to be managed via the Data Retention Policy framework
- This helps limit the size of all \*\_intel collections, and the corresponding threatintel_by_* collections, which are replicated in the knowledge bundle
- This is not a new feature -We are onboarding collections that were not involved before
- This is available to all ES 8.3 customers.
Changes are localised in:
- DA-ESS-ThreatIntelligence/package/default/collections.conf
### Allow Skew/Detections Scheduling & Time Improvements (revert from 8.3)
- Allows customers to enable/disable allow_skew=100% property for selected apps and helps with converting non skewable cron schedules to skewable ones.
- ES > Configure > All Configurations > Allow Skew
- Changes can be made only to apps that support versioning.
### Pinned fields in Analyst Queue
- Allows security analysts to "pin" (favorite) their most frequently used fields to the top of Analyst Queue Sidepanel and Investigation overview.
- It's by user, that can only access/modify their own pinned fields.
### AQ Nested Navigation & Drill Down View
- Allows users to view all the nested findings in the AQ table. This new view is called a drilldown view of the nested findings. The sidepanel shows included findings with links to see these drilldown views. Breadcrumbs in AQ table header and sidepanel header allow navigation between the nested finding groups/findings and the parent.
### Legacy Investigation
- Allows ES 7.x customers to continue working with their complete investigations after the upgrade of ES 8.3.
There are 2 known issues:
- New creation of ES 7.x investigation is not supported
- Slide View for Timeline Notes is removed due to security reasons.
### Options for Immutable Notes
- There is now the option to enable/disable note editing
- Configure > All Configurations > Analyst queue settings
### Migrate Detection Versioning Datastore to KVstore
- Migration of the detection versioning datastore from an index system to a KV Store.
### Select all findings in AQ and bulk action capability
Can be long if more than 1000 findings at the same time.
### CIM 6.3.0 Release
 CIM-1388: Endpoint Data Model
● Updated prescribed values for field process_integrity_level
CIM-1168: Change Data Model
● Removed prescribed values for field object_category
### OCSF-CIM TA
Map OCSF events to CIM datamodels.