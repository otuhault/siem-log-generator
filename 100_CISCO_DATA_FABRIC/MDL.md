Machine Data Lake
## 1. Customer challenges (the "why")

| Barrier                           | Reality                                                                                                   | Quote                                                                                                                 |
| --------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **No affordable landing zone**    | Choose expensive indexing or external lake; drop the rest                                                 | _"We have to choose our most critical data for Splunk. The rest goes to AWS S3."_ — Marriott                          |
| **High management overhead**      | External lake = customer-managed schema, ETL, regex, partitioning, Glue catalogs, compaction, perf tuning | _"We haven't baked in a partitioning schema yet… unsure how to tag fields and manage cardinality."_ — Royal Caribbean |
| **Unstructured data unreachable** | >90% of operational data unusable, esp. for AI/ML; only ~10% properly managed                             | _"Dumping most of our cloud data into S3 without any ETL or structure."_ — Cisco                                      |

## 2. Value proposition
- **Land**: zero ingest cost, ~**$0.05 / compressed GB / month**, ~80% compression (1 TB raw ≈ 200 GB billed). Competitive with Cribl Lake.
- **Fully managed**: partitioning, compaction, tuning, governance handled by Splunk.
- **Discover**: Catalog = datasets, metadata, fields, statistics, retention, access.
- **Activate on demand**: promote to **TSIDX** or **Analytics Table** (Iceberg; formerly "Lakehouse" — **use "Analytics Table" publicly**).
- **AI/ML ready**: raw + Analytics Table via **Open Sharing** (ex-Delta Sharing: Spark, PyTorch, Pandas, Power BI) + **MCP server** / search APIs.
## 3. Customer journey
**Land → Discover → Promote/Activate → Search / AI**
- Land via forwarders, HEC, S2S, EP/IP; Splunk extracts `_time`, `source`, `host`, `sourcetype` and registers the dataset.
- Discover: filter Catalog by source/sourcetype/host/time across indexes, Analytics Tables, raw tables.
- Promote: 3-step wizard (~3–4 clicks); static run ≈ 15–20 min.
- Search: promoted index = normal Splunk index; Analytics Table via Federated Search; raw searchable but slow (UI warns).

**Dataset creation options**: per-table retention (3 yrs financial / 7 yrs pharma), governance caps (max retention for static promos, max rolling window for streaming), **per-dataset RBAC** (who can query, who can promote static vs. streaming — promotions cost money), landing config (redirect e.g. `sourcetype=aws:cloudtrail`).

### GA promotion matrix

|Target|Static|Streaming|
|---|---|---|
|Splunk Index (TSIDX)|✅|✅|
|Analytics Table|✅|❌ → **10.6**|

---
## 4. Historical promote to TSIDX — Promotion Planner _(Part 2 focus)_
**Role**: takes Parquet files and converts them to Splunk's proprietary **TSIDX** format.
**Flow**: Catalog UI → **DMS** creates the promotion job → Planner requests files from **UCF** → UCF returns files **in batches** → Planner does **planning** (X files / Y volume) → spins up **worker pods** → workers download Parquet from MDL S3, merge/split, convert via `importtool` → upload TSIDX to **SmartStore S3** → **metadata registration** (Noah) → searchable.
- Planner internals: job lifecycle + state in **Aurora DB**, work batches, phases **Discovering → Promoting → Metering**, PostgreSQL advisory leases (multi-replica), notifies Noah on completion.
- Deep dive available: _"MDL Promotion Planner Inner Workings"_ (optional reading).

**Critical: parsing / props & transforms**
- **No SmartBus involved** — this is a completely different path from today's Ingest Processor flow.
- Transformation happens in **two places**: (1) rules applied **before landing**, (2) rules defined **during promotion**.
- Both are executed by the **Cloud Processor (IP layer)** — the CP does the P&T work, _then_ hands the job to the Planner.
- Path starts from the landing zone (an S3 prefix): read Iceberg table → apply rules → transform → write buckets to S3.

**Common issues**: can't start a promotion · job times out / fails · **stuck in Discovering or Promoting** · **cancel doesn't take effect** (usually a race condition, not always definitive given multi-service hops).
**Retry behavior**: ❌ **no retry on a failed promotion.** The UI shows the failure; you must **create a new promotion job** with the same or refined predicates.
**Scheduled static promotions**: **not** a Planner feature. The Planner is a pure downstream executor — it doesn't care whether the request came from a schedule or on-demand. Scheduling would sit in DMS / UI.
**Troubleshooting**
```none
index=k8s_prod k8s_namespace="mdl-promotion-planner-*" hostname="*mdl-promotion-planner*" tenant=<tenant> promotionId=<id>   → orchestration / data in-flow
index=k8s_prod k8s_namespace="mdl-promotion-planner-*" hostname="*mdl-promotion-worker*"  tenant=<tenant> promotionId=<id>   → actual promotion work
```

- Use `*` in the namespace (suffix is a generated hash). Staging/dev → `k8s_test` / `k8s_dev` (documented in the runbook).
- Check: active **5xx** + health alerts (deployment struggling / bad setup) · **Vault / AWS credential** failures (tenant onboarding step missed, DB write path, credential setup) · single-tenant vs. widespread.
- **Skynet dashboards** (staging + prod): promotion duration, data received vs. promoted, time spent per phase.
- Collect: **promotion ID, time range, tenants affected** — ~12 fields, template linked in the runbook.

**⭐ The promotion ID is the master key**: a GUID with prefixes, propagated across **all** services. Search it in Skynet to isolate the failing subsystem — e.g. if it failed in DMS/DO you'll see **nothing** in the Planner (terminated upstream). Documented in every individual service runbook + the main MDL Troubleshooting Guide.

---

## 5. Retention — two completely disjoint mechanisms _(clarified in Part 2)_

|Artifact|Where|Retention mechanism|
|---|---|---|
|**Iceberg tables** (MDL raw / Analytics Table)|Landing zone (S3)|Own Iceberg-level retention; **counted from the promotion/landing date, not event time**|
|**Splunk buckets** (TSIDX promoted)|SmartStore|Each promotion job **creates a brand-new Splunk index**; you pick a **TTL** at promotion time → **DMS triggers a delete index**|

- This is **not** the Victoria mechanism (Noah freezing buckets on `frozenTimePeriodInSecs`) — entirely different.
- **DMS owns the retention policy for both** raw/landing datasets and promoted datasets, but it's a behind-the-scenes service — customers don't interact with it.
- Field takeaway: you'll now manage retention in **two** places (Splunk _and_ MDL). Detailed MDL/Iceberg retention behavior → ask in `#mdl-field-questions`.

## 6. Other Part 2 clarifications

- **Search performance best practices for Analytics Table promotions**: **no guidance yet** — still under test by PM + PSR; documentation targeted **before GA** in the field docs.
- **Release cadence**: MDL surfaces through Catalog UI, which is part of the **EC release**, so significant updates will follow the **EC release cadence**.
- **One MDL per stack — strictly 1:1**: each stack = one tenant ID; tenant data is not shared across stacks. **Multiple stacks (e.g. dev + prod) cannot share a single MDL** — the "umbrella across a customer's stacks" scenario (land once, promote to dev _and_ prod) is **not covered today**; noted as future consideration.
- **Weekly office hours**: 1 hour every Tuesday, starting the week after the sessions.

---

## 7. GA limitations & gotchas (consolidated)

- **Dual routing not native**: to send data to both an index _and_ MDL raw, build an IP pipeline. Checkbox coming post-GA.
- **Max promotion volume limit** (admin approval threshold): post-GA.
- **Preview slow** at GA; read-only and **sampled**.
- Promotion filter statements are **OR**, not AND.
- **Landing latency ~10 min** before searchable.
- **Federated search on landing = metadata fields only**; other fields only after promotion.
- **Historical TSIDX promotion has a 20-min completion buffer** (discovery/processing → Planner execution) to absorb late-arriving intermediate data.
- **No retry** on failed promotions; **no scheduling** from the Planner.
- Streaming: no backfill before activation; rolling window = **retention, not backfill**; **no GA field extraction** (index-time only); extraction-heavy streaming is post-GA.
- **Open Sharing**: raw + Analytics Table only (**not TSIDX**); no time travel, no Change Data Feed, no Delta table versions/commit history.

## 8. Provisioning & eligibility

**Requires all 3**: S3 bucket on the stack + **Splunk Cloud 10.5.2605.5+** + required SCS service plans (MDL Essentials / MDL Premier).

- **Eligibility**: Splunk Cloud **Victoria Experience on AWS** only.
- **Net-new stacks** (post July 30): MDL provisioned by default via CDA; on first login the admin sees the **CDF Starter Pack** screen — that's the entry point to MDL.
- **Existing AWS VE stacks**: must be upgraded to **.5** first, then the **CDF Starter Pack (incl. MDL)** rolls out **shortly afterwards** — not immediately on upgrade.
- **Net-new purchases** after GA: provisioned separately, still require the .5 patch.
- **Account teams are responsible** for confirming VE + version before provisioning.
- ~10+ SCS services orchestrate the 4 pillars.

## 9. Troubleshooting by workflow (Part 1 recap)

- **Data Landing (IP/Router)**: queues created from tenant config? plan = Essentials/Premier? IP+MDL flags in CO2 spec? event `index` = `~.federated.<dataset_name>` or matching predicate? Missing fields → TAs installed + `props.conf` index-time extraction. Skynet: `sourcetype=cloud-processor OR cp-router`, correlate `pipeline_id`/`requestId`.
- **Catalog UI**: **always open DevTools first** — inspect `/servicesNS/<user>/<app>/mdc/v1alpha2/catalog-objects/<id>?extended=true` to confirm whether the backend actually returned the data (demo: apparent "UI bug" was MDC returning no fields). Collect screenshots/video, user role, dataset ID, HAR.
- **Dataset lifecycle (DMS)**: `sourcetype=data-mgmt-service`, `status>=400` → **4xx** fix the request (don't retry unchanged) · **5xx/503** trace the dependency · **2xx + stale UI** → GET the dataset, route to Catalog UI. Raw dataset ↔ landing pipeline is **1:1**; DMS cancels then best-effort rollback — if rollback fails the dataset lingers → manual cleanup. **Default MDL Raw dataset cannot be deleted**; `409` = live dependency.
- **Static promote to Analytics Table**: dependencies Iceberg Catalog Service → promoted dataset → generated pipeline → IP via DO. Watch: missing `_time` (deselectable in UI but **required**), unsupported metadata key, invalid `process_data` module. Preview ≠ promotion → compare same window/filters/fields/module.
- **Streaming promote to TSIDX**: landing always writes MDL Raw; each promotion is a predicate **branch** to a separate pipeline → TSIDX; **promotion failure must not stop landing**. Triage the **first broken handoff**: no new raw events after activation → **Landing** · generated pipeline ≠ authored SPL → **DMS/DMX UI** · no processing → **Ingest Processor** · output emitted but destination empty → **Router/TSIDX**.
- **Search on promoted datasets**: TSIDX → capture SID + standard Splunk search troubleshooting; Analytics Table → **FA2 runbook**.
- **External Sharing**: only owner/admin can share; token auth enabled in `authorize.conf`; raw + Analytics Table only. 500 → retry/Delta Sharing team · 400 → request shape · 401/403 → profile & token state. Depends on **FAS, Splunk Data Catalog Service, DO**. **Never log bearer tokens, profile secrets or presigned URLs.**

## 10. MDC (Metadata Catalog)

**Sidecar** (search head, **10.5.2605.4+ required**) + **SCS MDC service** → **GraphDB/Neo4j** (catalog objects, relationships, schema) + **Aurora Postgres** (high-cardinality MDL field values). Plans: `graph-service.database`, `mdc.sidecar-principal`, `mdc.provisioning`.

|Pipeline|Default 10.5|Cadence|Powers|
|---|---|---|---|
|`pipeline_index_discovery`|✅|30 min (bounded by `distributed-indexes` cache, default 1 h)|Local indexes in Catalog|
|`pipeline_mdl_metadata_field_value`|✅|30 min (needs IP `federated.field_summary`)|source/sourcetype/host filters, size estimates|
|`pipeline_mdl_size_time`|❌ opt-in|30 min, bounded batches|Dataset size / earliest / latest / event count|
|`pipeline_schema`|❌ opt-in|**00:00 UTC daily, fixed**|Field-name search & schema display|
|`pipeline_schema_hourly`|❌ opt-in|hourly, bounded, new promoted datasets|Faster first schema availability|

- Flags in `server.conf` `[metadata_catalog]` / `[federated_analytics]`; hot-reloadable but opt-in requires CO2 + Puppet reload.
- **Why opt-in**: these run SPL/SPL2 and **consume customer search concurrency slots** (perf impact / skipped searches).
- **Billing**: MDC federated SPL2 excluded from DSU/ABP metering and CDF Starter Pack entitlement; **SVC from local SPL cannot be filtered out**.
- Cadences are **fixed**, not user-configurable.

## 11. Reference use cases

|Persona|Scenario|Path|
|---|---|---|
|**Jason** — SOC analyst|DNS logs never indexed; needs exfiltration confirmation|Land all DNS → filter → promote 2-week window to **TSIDX** → SPL correlation|
|**Ana** — ML engineer|Months of Nexus/SD-WAN telemetry for node-degradation model|Land full fidelity → explore → promote 6 months to **Parquet/Analytics Table** → Catalog API into SageMaker|
|**Michael** — Compliance lead|HIPAA report over 12 months of admin access logs|HEC → lake → filter 12 months → promote to **Parquet** → SPL audit report via Federation|

## 12. Resources — remember two pages

1. **MDL Troubleshooting Guide** (Confluence) — 1:1 match with the deck, **kept up to date** (the deck will go stale); links every service runbook incl. MDL Promotion Planner, plus all Skynet dashboards
2. **Cloud Escalation Policy** — VictorOps paging + Slack channels per team