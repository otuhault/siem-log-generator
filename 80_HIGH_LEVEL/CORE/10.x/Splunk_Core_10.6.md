---
title: "Splunk Enterprise 10.6"
version: 10.6
type: minor-release-note
product: splunk-core
family: 10.x
date: 2026-10-01
status: stable
tags:
  - splunk/core
  - splunk/10.6
  - release-notes
  - architecture
  - administration
---
# Splunk Enterprise 10.6

> [!summary] Executive Summary
> **Splunk Enterprise 10.6** aligns On-Premises capabilities with modern Splunk Cloud architecture. Key highlights include the **Unified 4-Segment Versioning Scheme**, public **Data Management Service REST APIs** for Edge/Ingest Processors automation, on-premises **Configuration Change Tracking**, significant **App restart reductions** (`[reload_on_delete]`), and the final optional phase of the **Co-Hosted KV Store** architecture transition.

---
### 1. ⚡ Major Features & Architecture
* **Standardized 4-Segment Versioning:** Release numbering transition to `Major.Minor.Maintenance.Patch` (e.g., `10.6.4.1`) to clearly distinguish maintenance bundles from urgent security patches.
* **Data Management Service APIs:** Official REST endpoints allowing platform engineering teams to automate Edge Processor & Ingest Processor pipeline provisioning, deployment, and monitoring via enterprise CI/CD.
* **Cloud-Aligned Configuration Change Tracking (On-Premises):** Native auditing across Web UI and REST API that logs actor identities, execution timestamps, modified `.conf` files, and success/failure statuses.
* **Optimized App Lifecycle (Zero/Low Downtime):** ~50% reduction in platform restart requirements when deleting or uninstalling apps.
* **Federated Search Handshake:** Automatic exchange and validation of SPL capabilities between federated Search Heads and remote search nodes.
* **Splunk AI Assistant "Agent Mode":** Autonomous reasoning, multi-step search execution, and tool selection with Human-In-The-Loop approval gates.

---
### 2. ⚙️ Configuration File (`.conf`) Changes
* **`limits.conf` — App Reload on Delete:**
  * Eliminates mandatory restarts when deleting or uninstalling applications:
  ```ini
  [reload_on_delete]
  disabled = false
  ```
	- **`disabled = true` (Default Setting):** Splunk **skips** attempts to dynamically reload configuration files after an app is deleted. This means an automatic or manual **restart of the Splunk platform is strictly required** to complete the deletion process.
	- **`disabled = false`:** Splunk will actively try to reload its components in real-time. If **every single configuration file** inside the deleted app natively supports standard Splunk reloading mechanisms (e.g., lookups, simple search scripts, simple UI elements), **Splunk reloads seamlessly without a restart.**
	    - _Note:_ If the app contains even one configuration file type that cannot be reloaded live (such as index-time `props.conf` changes or custom binary endpoints), Splunk will gracefully fall back and flag a restart as required.
	
* **`server.conf` — Configuration Change Tracking & Audit:**
  * Granular logging controls for configuration modifications:
  ```ini
  [config_change_tracking]
  enable = true
  audit_retention_days = 90
  ```

---

### 3. 🗄️ KV Store Engine & Migration (Critical Trajectory)

> [!warning] Co-Hosted KV Store Engine (Final Deferrable Phase)
> * **10.6 Status:** The migration to the modern co-hosted KV Store architecture remains **optional / deferrable** in 10.6.x releases.
> * **Upcoming Requirement:** This architecture will be **strictly mandatory starting in version 10.7+ and 11.x**.
> * **Recommendation:** Complete the co-hosted KV Store migration during the 10.6 upgrade window to ensure seamless future platform upgrades.

---

### 4. 🐍 Python Runtime & Module Compatibility

* **Python 3.13 Standard:** Fully standard runtime across search heads, indexers, and forwarders.
* **Legacy Script Conversion:** Any legacy custom search command script still invoking deprecated Python 2/3.7 syntax must be refactored to standard Python 3.13.

---

### 5. ⚠️ Breaking Changes & Versioning Impact

* **Version Parsing in Custom Tooling:** Deployment scripts, CI/CD pipelines, and health-check tools parsing the 3-digit `major.minor.patch` string must be updated to support the 4-segment scheme (`10.6.4.0`).
* **Federated Endpoints:** Deprecated point-to-point federation REST calls replaced by the capability handshake engine.

---

### 6. 🔄 Maintenance Releases & Patches Log

* **10.6.4** (01/10/2026) : Official release with Data Management Service APIs and `[reload_on_delete]` optimization.
* **10.6.0** : Initial branch release.

---

### 7. 🔗 Cross References
* `[[80_HIGH_LEVEL/CORE/10.x/Splunk_Core_10.x_Overview|Splunk Core 10.x Master Overview]]`
* `[[80_HIGH_LEVEL/CORE/10.x/Splunk_Core_10.5|Splunk Enterprise 10.5]]`
* `[[80_HIGH_LEVEL/Edge_Processor/Edge_Processor_Architecture|Edge Processor Architecture Guide]]`
