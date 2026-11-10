# ES Premier
- ES
- SOAR
- UEBA
--> Threat Detection (Static, **Dynamic (ML)**, Pre-built, Custom, Authoring)
--> Investigation (RBA, Threat Hunting, Integrated Analytics)
--> Response (Enrichment, **Automation**, **Orchestration**, **Playbooks**)
# ES Essentials
- ES
--> Threat Detection (Static, Pre-built, Custom, Authoring)
--> Investigation (RBA, Threat Hunting, Integrated Analytics)
--> Response (Enrichment)

# Features
### Essentials
#### Allow Skew / Detection Scheduling & Time Range Improvements
Allow Skew allows the search scheduler to intelligently offset scheduled search start time to spread search load.
- Only version controlled detections can be configured in the ES UI to take advantage of allow_skew.
- Only some cron schedules are "skewable" but the UI enhancement helps customers adjust schedules to conform to allow_skew requirements.
- Can be configured on an App basis.
#### Migrate Detection Versioning Datastore to KVStore
- Detection Versioning information was stored in a Splunk index in versions before 8.3 and are being moved to KVStore collections during upgrade to 8.3.
Why?
- Improved performance during UI workflows
- Customer upgrade or migration support cases and outages (missing indexes)
- Potential data loss in rare circumstances
Things to know:
- Change will be mostly invisible to customers, this is a backend change
- Custom dashboards/reports to search on index=cms_main will need to adjust technique to query the KVStore instead
- Initial performance tests show a significant decrease in read operation duration (2-5sec to ˜250ms)
- No action required on upgrade.
#### Optional Immutable Notes
- Customers can now toggle a setting to globally disable the editing of notes after they have been created.
Why?
- Some customers want notes to be immutable for a number of reasons; Chain of custody, Audit, Compliance, Workflow Integration, etc.
Things to know:
- By default, note editing will be enabled.
- When enabled, behave as they currently do in ES8.X
- When disabled, users cannot edit or delete notes after creation
- Any SOAR actions/playbooks that edit/delete notes will fail if note editing is disabled.
- No action required on upgrade.
#### Pinned Fields in AQ side panel / Investigations
- Fields can now be pinned in the Analyst Queue sidebar and Investigations
Why?
- Findings can contain lots of data and pinning enables users to make sure the data they care about is available at a glance.
Things to know
- Pinned fields are per-user and stored in the KV Store
- The same fields are pinned in the AQ sidebar and Investigations
- Fields can be re-ordered with drag and drop
- Fields are pinned directly from the sidebar/Investigation
#### Entity Risk Scoring
- New scoring aggregation that binds score between 0-100 and weights risk events by score, uniqueness, and distinct counts.
Why?
- Traditional risk score is a flat, additive aggregation that doesn't automatically account for noise.
Things to know:
- "Finding Risk Score" refers to the additive score
- "Entity Risk Score" refers to the weighted score, bound between 0-100
- ERS created from year of detection frequency, past week of entity activity
- Available in Risk Analysis dashboard and next to entity name for Essentials
- Replaces score glyph next to entity names, can be clicked on for drilldown
#### Select/Edit All Findings in AQ
- Users of ES8 can now bulk select and edit Findings in the AQ even beyond the current page.
- A deselect button has been added as well.
Why?
- Allow bulk editing of Findings
- Restore functionality that existed in ES7.
Things to know:
- Users can "Edit"or "Assign to Me"
	- Edit: Change owner, set status, change urgency, change disposition, add notes.
- "Add to Investigation" and "Run Playbook"are greyed out.
- Can select all items on a page or all items available in the queue up to a cap
	- eventAvailableCount
- AQ searches now show the total amount returned AND the total number of matches.
- Editing large amount of records can take "up to a minute"
- No action required on upgrade.
#### Analyst Queue Performance Improvements
- Significant improvements were made to both actual load times and the user experience around how pages handle loading.
Things to know:
- Finding are dynamically loaded and unloaded from the database (KV) which means the AQ gets faster as you interact with it more.
- Duplicate API calls when loading the side panel have been reduced/eliminated, decreasing load times by over 30%.
- The AQ now leverages "skeleton loading" which is a common design tool to display page elements as data loads and make loads feel faster.
- Fixed instances where charts were re-rendering unnecessarily.
- No action required on upgrade.
#### Nested Finding Navigation
- Rather than being limited to seeing 10 rows of "nested" findings, all nested findings can now be broken out into a table.
- Navigation breadcrumbs are included in the sidepanel when viewing nested findings.
Why?
- Hierarchical detections are a big part of ES8 and we need to make them easier for users to leverage.
Things to know:
- Links will appear when there are more than 10 findings in an object
- Links will appear in the AQ, side panel, and Investigation

#### Legacy Investigation Access
- A temporary way to access already-started legacy (>=7.x) ES investigations has been added.
Why?
- Customers may have had in-flight investigations that needed to be completed.
- Customers wanted a chance to go back and export legacy investigations post-upgrade
- Remove a common upgrade blocker.
Things to know:
- This feature is temporary with PM aiming to keep it around ~1year.
	- There is a customer-visible warning banner
- Users will see "Legacy Investigations" in the Configuration menu if they had at least one legacy investigation.
	- Under "Findings and Investigations"
- Old investigations can be updated/exported but the "Create New Investigation" button is removed.
- Full migration was investigated and deemed not feasible
#### CMP Support for ES Editions
- ES has a license now
	- Premier needs a license which will be applied on ES and propagated to SOAR
	- A system with ES installed but no license defaults to Essentials
- Premier cannot currently be sold as Hybrid.

#### TIM - Threat Collections Data Optimisation
- Optimise how Threat Intelligence collections are stored and managed
- Allows customer configured retention of threat intel data
Why?
- ES customers hit the 3GB bundle size limit,. causing searches to stop
- Optimising TIM data ensures reliability and scalability without limiting intel use.
Things to know:
- Default threat intel retention set to 60 days - can be configured from the UI.
- No impact to correlation search logic, dashboards, or threat intel configurations.
### Premier
#### Show Investigation in UEBA
- Interactive markers on the risk score timeline showing when investigations were created
Why?
- Gives analysts immediate context when reviewing entity risk patterns
- Enhances the existing risk score timeline by visually connecting investigations to score fluctuations.
Things to know:
- Available to ES Premier users in both Asset and User Explorer interfaces
- Toggled on/off via the "Show Activity" control
- No impact to existing risk score timeline behavior.
#### UEBA CMP Detections / Content App
- New separate and restricted UEBA CMP content app (similar to ESCU)
- ML and static detections
Why?
- Provide behavior-based detection capabilities for CMP customers
ML Detections:
- Powered by Splunk MLTK
- Supports 90+ ML models
- Supports CIM/custom data sources
	- Authentication
	- Network Traffic
	- Endpoint
	- UEBA Printer
- Behavior-based detections
- Peer-grouping based detection
- Company wide normalisation
Static Content:
- Detections by focus
	- Cloud (AWS)
	- Web
	- Email
	- Endpoint
Things to know:
- The download of the app is restricted and NOT bundled with new ES Premier Edition customers on a fresh install.
- Adjustments to data map macros may be required
- Usage increase on SH and Indexers has been seen to be a few %
	- Actual impact depends on which detections are enabled and how much ingested data is used by the data models powering the detections.
#### UEBA Cloud Detections
- Behavior-based detections to support insider threat use cases
	- Batch (ML): 51
	- Batch (Anomaly Rules): 8
	- Streaming: 83
Why?
- To provide the latest detections to uncover negligent or malicious insiders.
UEBA Behavior-based Detection Types:
- Machine Learning Models
- Anomaly rule-based on historical baselines
- Near real-time streaming rules
Things to know:
- No action required on upgrade as detections are continuously deployed
- 12 sourcetypes supported: box:events, cisco:asa, o365:...
#### UEBA Behavior-Based Detection Editor
- New BDD editor allows user to:
	- open model card with data requirements
	- view risk mapping and framework mapping
	- pivot to finding exclusion rules
Why?
- To simplify configuration and demystify UEBA detections.
Things to know:
- Read-only for ES8.3 release
- No action required on upgrade to ES8.3 and UEBA 1.4
- No performance impact noted in testing
- Works in on-prem or cloud ES with no tie to specific Edition.
#### Entity Risk Scoring + UEBA Dashboard
- Investigation process for Entity Risk Score (ERS) enabled by UEBA in Premier
Why?
- Provide process for ERS-driven risky entities and explanations behind score.
Things to know:
- No longer separate app, located within ES under Analystics -> UEBA
- Entity risk score explanation workbench is in both Essentials and Premier
	- Just like Essentials can click on a entity score; from there "Open in UEBA" only in Premier
- UEBA Dashboards (Premier only) presents riskiest asset/user overview with:
	- entity list functionality
	- timeline annotations on investigations for this entity
	- connected users-to-assets and assets-to-users panel
	- MITRE ATT&CK breakdown + heatmap
	- detection frequency heatmap
	- finding exclusion functionality to tune weight of detections
#### UEBA Service Limits
- Defined service limits for the UEBA offering
Why?
- To provide customers guidance on the limits of what UEBA can support.
Things to know:
- UEBA Cloud Service Limits
	- EPS: 45,000-60,000
	- Users and Devices 3,000,000 for each
- UEBA PX
	- Entity Lists: 500 across A&I for all types (source, category, pattern match)
	- Finding Exclusions: 2,000 across all types (field match, lookup)
#### UEBA Health Monitoring
- Diagnostics dashboard with ERS related metrics
Why?
- Users can monitoring and analyse ERS score contributions
Things to know:
- Different capabilities by ES Edition:
	- Essentials: No metrics related to Premier features
	- Premier: All metrics and panels
- Troubleshooting simple issues
	- presence of ERS index
	- charts to display ERS score vs. Entity counts
	- Identifies which detections are overwhelming the risk score

