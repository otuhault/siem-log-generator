---
title: "Splunk Enterprise 10.5"
version: 10.5
type: minor-release-note
product: splunk-core
family: 10.x
date: 2026-07-20
status: stable
tags:
  - splunk/core
  - splunk/10.5
  - release-notes
  - architecture
  - administration
---
# Splunk Enterprise 10.5

> [!summary] Executive Summary
> **Splunk Enterprise 10.5** introduces the **Machine Data Lake** tier and the enterprise **Data Catalog**, expanding Splunk's hybrid data federation footprint. This release enables organizations to retain massive volumes of full-fidelity machine data economically while extending **Federated Search** natively to Microsoft Azure Data Lake Storage (ADLS), Snowflake, and Dynamic Data Self-Storage (DDSS).

---
### 1. ⚡ Major Features & Architecture
* **Machine Data Lake Architecture:** A cost-optimized, full-fidelity storage tier designed for secondary and compliance-driven long-term log retention, searchable directly without re-indexing.
* **Unified Data Catalog:** Central repository to discover, classify, and activate hybrid datasets across on-premises clusters, cloud stores, and external data lakes.
* **Extended Federated Search Providers:** Native query federation connectors for:
  * **Microsoft Azure Data Lake Storage (ADLS Gen2)**
  * **Snowflake Data Cloud**
  * **Dynamic Data Self-Storage (DDSS)**
---
### 2. ⚙️ Configuration File (`.conf`) Changes
* **`indexes.conf` — Machine Data Lake Storage Tiering:**
  * Defines cold-to-lake rollover policies and storage provider bindings:
  ```ini
  [volume:datalake_tier]
  path = s3://splunk-datalake-archive/hot_warm
  maxVolumeDataSizeMB = 50000000

  [index_security_archive]
  homePath = $SPLUNK_DB/index_security_archive/db
  coldPath = volume:datalake_tier/index_security_archive/colddb
  thawedPath = $SPLUNK_DB/index_security_archive/thaweddb
  ```
* **`server.conf` — Cloud Federated Providers:**
  * Enhanced authentication and rate-limiting profiles for Snowflake and Azure ADLS endpoints.

---
### 3. 🗄️ KV Store Engine & Migration
> [!info] KV Store Co-Hosted Architecture Preparation
> * **Engine Stability:** Continues on MongoDB 7.0/8.0.
> * **Preparation:** Internal codebase refactoring preparing for the transition to the co-hosted KV Store architecture in 10.6+.

---
### 4. 🐍 Python Runtime & Deprecations

* **Python 3.13 Enforcement:** Python 3.13 is strictly enforced across all standard search commands and background tasks.
* **Module Audit:** Complete elimination of dependencies on Python 3.9 core libraries.
---
### 5. ⚠️ Breaking Changes & Deprecations
* **Legacy Storage Connectors:** Direct S3/Blob connectors using deprecated v1 SDKs must be upgraded to the unified storage framework.
* **Legacy Search Export Endpoints:** Unauthenticated streaming CSV export endpoints are restricted.
---
### 6. 🔄 Maintenance Releases & Patches Log
* **10.5.3** : Snowflake query federation performance tuning and catalog sync fixes.
* **10.5.1** : Azure ADLS token refresh enhancements.
* **10.5.0** : Initial GA release (July 2026).
---
### 7. 🔗 Cross References
* [[80_HIGH_LEVEL/CORE/10.x/Splunk_Core_10.4|Splunk Enterprise 10.4]]
* [[80_HIGH_LEVEL/CORE/10.x/Splunk_Core_10.6|Splunk Enterprise 10.6]]
