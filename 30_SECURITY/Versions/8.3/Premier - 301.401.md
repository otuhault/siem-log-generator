### UEBA - User and Entity Behavior Analytics
On-prem UEBA Content App:
- (DA-ESS-UEBAContent) for: Summarizing, learning baselines, anomaly detection, risk event generation.
UEBA Cloud Services (SCS):
- Parsing & enrichment
- Streaming detections
- Learning behavior baselines
- Detecting deviations from baselines
- Computing evidence/explanations
- Computing detection reports
- Ingesting risks events

UEBA offering will supersede Splunk UBA at ES Premier GA

### Installing UEBA PX via ES installer
- UEBA PX 1.4 shipped only inside ES
- ES Editions provides different capabilities:
	- Esentials: ERS Model (ES/MC Analyst Queue)
	- Premier: ERS Modal and access to the Overview, Analysis, Configuration pages
- Customers not upgrading to ES 8.3 can only stay on UEBA 1.3.1
### Performance
- UEBA PX Scheduled Searches add overhead to the ES SH
	- They run every 20-30min
	- ERS, Normalised Assets/Users, Normalsie IPv6
### UEBA Content App Overview
- UEBA Content App is a Splunk app for delivering premium ML and static detections to ES Premier Edition customers (similar to ESCU).
#### Architecture
![[Pasted image 20251215142955.png]]
1. Raw logs
2. Raw log index
3. CIM Data Model
	1. not all detections will leverage a CIM Data Model.
4. Hourly Summary Search
	1. runs hourly, now called "Summarisation"
5. Daily Summary Search
	1. runs daily, now called "Consolidation"
6. Feature Value Summary Search (not required in some detections)
7. Feature Value Lookup Search (not required in some detections)
8. Scoring Search (not required in some detections)
9. Detection Search
10. Risk Index
	1. UEBA PX App will read from the risk index
#### Deployment
- Separate and restricted Splunk app that is not bundled with ES
- Only available from splunkbase for ES Premier Edition customers, as a fresh install on Search Head(s)
- Require ES 8.3
#### Configuration
- Customers might need to adjust the following data map macros depending on their log formats
	- Network Traffic
	- Printer
	- USB
- Customers can also disable/enable detections in Searches, Reports, and Alerts depending on their use cases.
#### UEBA CMP Service Limits
- Highest ingestion was 50-60TB per day
	- ~50% of ingested data is applicable to the UEBA use cases
- Max observed number of monitored users and devices
	- 7M users, 35M devices
- References will be shared internally
#### UEBA CMP Performance Impact
- UEBA runs a set of scheduled searches and maintains additional index (ueba_summaries) and kv lookups.
- Users should expect increased:
	- number of scheduled searches
	- CPU and memory usage on test stacks
		- indexers: 6% point CPU usage increase, 3GB memory usage increase
		- search heads: 3% point CPU usage increase, 3GB memory usage increase
	- Disk usage (from ueba_summary index, 25% of ingest volume processed by UEBA)
- Sizing guide: https://splunk.atlassian.net/wiki/spaces/MG/pages/1079016554840/UEBA+CMP+1.0+Sizing+Guide
### Troubleshoot
Some helpful SPL queries if risk events aren’t generated:
1. Verify summary searches are running:
```
index=_internal sourcetype=scheduler app=DA-ESS-UEBAContent | search savedsearch_name="*Summarization*"
| stats latest(_time) as last_run by savedsearch_name, status
```

2. Check if summary data exists:
```
index=ueba_summaries
| stats count by source
```

3. Verify data model acceleration (adjust as needed for different data models)
```
| rest /services/admin/summarization by_tstats=1
| search eai:acl.app="Splunk_SA_CIM" summary.id="*Authentication*"
| table summary.id, summary.complete, summary.latest_time
```
Troubleshooting runbook: https://splunk.atlassian.net/wiki/spaces/MG/pages/1078845608820/UEBA+Content+1.0.0+-+Troubleshooting+and+Validation

### UEBA CMP Detections
- Powered by Splunk MLTK
- +90 ML Detections
	- ML Detections with description: https://docs.google.com/spreadsheets/d/1Gv_FSnMPcKghP3gimm2-M-hORQlqxQMZ_3YOHF-R778/edit?usp=sharing
- Supported CIM data sources
	- Authentication
	- Endpoint
	- Network Traffic
	- UEBA Printer
#### Types of CMP ML Detections
- Behavior based
	- An entities behavior is compared it to past behavior
- Peer-grouping based behavior normalisation
	- An entity is ranked against its peers
- Company wide normalisation
	- An entity is ranked in the whole organisation

- All models are written in SPL and MLTK
- Allows deep customisation based on their environment
	- Allow custom model tuning per customer basis
	- Allows customer to filter data sources in SPL
	- Allows whitelist/blacklist of users/devices
- Peer-grouping is based on BU-Unit
	- This BU-Unit is pre-populated through CIM enrichment with A&I
### Static Content
#### Detections by focus
UEBA Insider Threat: monitor for activities and techniques associated with insider threats and specifically focusing on malicious insiders operating within a corporate environment.
#### UEBA Cloud
AWS Compromised Account
Risk data model and Cloudtrail sourcetype required.
#### UEBA Web
Web datamodel and surricata or proxy sourcetypes required.
#### UEBA Endpoint
Authentication, Change, Risk datamodels and XmlWinEventLog:Security and Auditd sourcetypes are required.
#### UEBA Email
Email datamodel and gws:email sourcetypes are required.
### UEBA Cloud Detections
Behavior-based detections that supports Insider Threat use-cases for UEBA.
![[Pasted image 20251215145850.png]]

### UEBA Features
#### Entity Risk Scoring (ERS) in ES
ERS 2.0:
- Replaces the simplistic, unbounded scoring of ERS 1.0 with a weighted, explainable and normalised to a 0-100 scale model the reflects real-world analyst reasoning.
- It factors in detection diversity, MITRE tactic coverage, event severity, and event rates to produce more meaningful, context-aware scores. Analysts can now see a transparent score breakdown directly in the UEBA Entity Risk Calculation model for clearer, more actionable insights.
Current "Risk score" is now labelled "Finding score" and continues to be available alongside the new ERS.
- Clicking on the ERS score/entity name would open ERS Model.

ERS 2.0 is the saved search "Risk - EWA Entity Risk Score calculation" which runs every 20 minutes over a 7 day window of risk events. Resides with UEBA App and populates ers_index and ers_klookup KV Store collection.
ES access this colletions using normalized_risk_object and risk_object_type as lookup keys to enrich risk data with the calculated ERS value (rounded to whole number and capped at 100).
#### ERS Feature Availability Across Essential and Premier
![[Pasted image 20251215153404.png]]
### UEBA Detection Editor
- This feature introduces Model Cards directly into Splunk UI, within the Detection Editor and Content Management workflows. It allows users to view key model details - such as purpose, inputs, validation metrics, and drift status - without leaving the product.
### Investigation annotations on the risk score timeline
- Only for Premier.
### IPv6 Support
- Normalisation of IPv6 address values to a common format.