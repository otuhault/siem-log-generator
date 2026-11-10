**1. What CDF is**
- CDF is **not a purchasable product** — it's a set of capabilities/solutions, the next evolution of the Splunk Platform ("Cisco Data Fabric, powered by the Splunk Platform").
- 3 pillars: **Data** (AI-powered Data Management, MDL=Machine Data Lake, Federated Search) / **Context** (Splunk Catalog, Search & Correlate) / **Action** (AI Canvas, MCP, Agent Launchpad, AI Toolkit, Cisco Time Series Model).
- MDL + Catalog are the **last components to GA — July 30, 2026**. Agent Launchpad and Cisco Time Series Model already GA.

**2. GA capabilities (clarified by transcript)**
- **Ingest**: AI-guided onboarding; auto field extraction + auto-schematization in **Controlled Availability** (not full GA).
- **Land & Retain**: MDL raw on low-cost object storage; all existing paths (IP/EP, HEC, UF/HF); 4 metadata fields.
- **Discover**: Catalog = end of `index=*` to find out what's in Splunk; covers MDL, Federated, Splunk indexes; RBAC incl. promotion permissions; **Delta/open sharing API** to access MDL externally.
- **Promote** (= flexible data tiering on demand):
- Targets: **Splunk Index** (streaming/"hot" or static/ad-hoc) and **Analytics Table** (ad-hoc only at GA)
- Criteria: time window + filter on the 4 key fields; job management (track/pause/cancel/delete); **scheduled promotions are possible**
- **Analytics**: FS on S3, Azure Blob, Databricks, Snowflake, **DDSS**, plus direct search on MDL states; SAIA (Beta 10.5) NL→SPL2 on MDL & federated datasets; MCP SPL2 on MDL/FS; Agent Launchpad + TimeSeriesFM (fit/apply) on indexes and MDL-promoted indexes only.

**3. Not GA — FY27 roadmap**
- **Streaming promotion to Analytics Table** → fast-follow; blocks **OCSF real-time detections**
- **Native ES on MDL / FS** → ES searches written against indexes work if data is promoted; Analytics Table & raw = manual/user-driven for now
- **MELT (metrics/traces/spans)** → work with the Observability Cloud team so O11y can tap MDL (unified platform)
- **SAIA/MCP on MDL + federation** → GA targeted **10.6**
- **FedRAMP (GovEast/GovWest)**: **not in Phase 3** — AWS Commercial only; FedRAMP targeted FY27 H2

**4. Starter Pack (internal name only — do NOT use with customers; final naming pending marketing)**
- **Not a trial: free forever** while on a Splunk Cloud subscription (SVC, ABP, or Ingest SKU); real product, not reduced functionality
- Fixed capacity, deliberately **one-size-fits-all** for simplicity (t-shirt sizing was explored and rejected): **100 GB/day MDL ingest + 3-month retention**, **10 GB/day promotion to Analytics Table**, **100 search units/day FS**, **500 GB/day Ingest Processor** (already available; premium IP is an add-on)
- Search units are **weighted**: small searches = 1 unit, larger data volumes map to X units
- Solves 4 barriers: entitlement friction, workflow uncertainty, packaging ambiguity, weak sales signals
- Paid capacity is **additive** (layers on top) — no trial→prod migration
- GTM sensor: any usage → 90% (CMC + admin email + in-product) → 150% overage → expansion sale
- Existing pricing uplifts (PCI/HIPAA etc.) still apply; **SKUs exist in SFDC but are restricted until GA** (open a ticket if urgent)
- Rollout: Canary US East → Phase 1 (US East, Frankfurt, Tokyo — one region/theater) → Phase 2 (Oregon, Sydney, Ireland) → Phase 3 (remaining eligible AWS regions). Oregon is late simply due to per-theater prioritization.

**5. Monitoring (CMC)**
- Starter Pack panel on **Federated Search, Ingest Processor, MDL** dashboards; sits alongside paid license view
- Daily allocation + last-24h usage, then usage-over-time chart
- **Iterative release**: summary numbers first (canary), chart later (~Phase 1)
- Also visible in **CMC Mirror / SkyNet** for internal teams

**6. Field asks raised in Q&A (open items)**
- Need **"rules of the road"**: data classification → which tier/target per use case (heavily searched / ES / premium apps → index; unknown use case → cheap landing)
- **Use-case & transition deck** in progress with Michael Sondak's team (incl. DDAA/DDSS migration paths)
- Overarching CDF GTM messaging on Sales Connect Hub (Carla Patterson), also in VECs/QEP
- **Demo/test environments**: currently limited to select GTM folks; broad demo stacks + hands-on labs after GA; click-through demos & videos in build. Strong field push for Cloud Architects, SAs, Support, PS, CS to get access early.
- **Concurrency limits for MCP/AI searches**: likely counted (same underlying search APIs/quotas), but 2 layers (Splunk + MDL stores) — to be confirmed, needs a dedicated deep dive
- Guided onboarding: docs/guides + click-throughs at launch; **full in-product guided experience not complete**

**7. Key message to carry to customers** Paradigm shift: stop deciding upfront what to index. **Land everything cheaply, activate on demand** — fewer upfront decisions, more transparency, better economics.


## Consultant cheat-sheet: what to master

|Area|Must know|
|---|---|
|Guided Onboarding|Constraint-based questioning (deployment, infra, latency, volume, PII); arbitration logic; IP vs. infra-based paths|
|Auto-schematization|Sample upload → CIM mapping → generated props.conf/TA; OCSF on roadmap|
|Self-healing pipelines|Alert types: CIM non-compliance, volume spike, volume drop; schema-diff remediation + TA regeneration|
|MDL|Land raw cheap → discover in Catalog → **promote a narrow slice** (target + time + filter) → analyze; raw search performance warning|
|Delta Sharing|Open access for external tools / customer model training|
|Federated Search|Connections + datasets; routed-and-inferred **vs.** BYO store (Iceberg REST / Nessie); consistent SPL; search at rest|
|SAIA Agent Mode|Plan → execute → refine (z-score) → guide; approval gates; Markdown context files|
