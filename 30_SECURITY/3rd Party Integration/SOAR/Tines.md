# Configuring Tines SOAR with Splunk for Notable Events
Integrating Tines with Splunk Enterprise Security (ES) to retrieve and act on Notable Events is a common SOAR use case. Here's a breakdown of how to approach it.
## High-Level Architecture
There are two main integration patterns:
1. **Pull model** – Tines periodically queries Splunk's REST API for new Notable Events.
2. **Push model** – Splunk sends Notable Events to Tines via a webhook (using Splunk Alert Actions or Adaptive Response).
## Prerequisites
### On the Splunk Side
- **Splunk Enterprise Security (ES)** – Notable Events are an ES concept (stored in the `notable` index).
- **A Splunk service account** with roles granting:
    - `search` capability
    - Access to the `notable` index
    - Access to ES-specific endpoints (`/services/notable_update` if you want to close/update notables)
- **Authentication token** – A Splunk bearer token (preferred) or username/password.
- **Splunk REST API reachable** from Tines (typically port `8089`).
- Optional: The **Tines app for Splunk** (if using the push model) or a webhook alert action.
### On the Tines Side
- A Tines tenant (Cloud or Self-hosted).
- A **Credential** stored in Tines for the Splunk token.
- A **Story** containing the automation logic.
- If Splunk is on-prem/private, a **Tines Tunnel** may be required for connectivity.
## Configuration Steps
### 1. Create Splunk Credentials in Tines
- Go to **Credentials → New Credential → Text (or HTTP Request Header)**.
- Store the Splunk bearer token (e.g., `Bearer eyJ...`).
### 2. Build the Pull Workflow (most common)
In a Tines Story:
**Step A – HTTP Request Action** to run a Splunk search:
- **URL:** `https://<splunk-host>:8089/services/search/jobs`
- **Method:** `POST`
- **Headers:** `Authorization: {{.CREDENTIAL.splunk_token}}`
- **Payload:**
    - `search`: `search index=notable earliest=-5m | table event_id, rule_name, src, dest, urgency, status`
    - `output_mode`: `json`
    - `exec_mode`: `oneshot` (returns results immediately)

**Step B – Explode / Event Transformation Action** to iterate through each notable.
**Step C – Enrichment Actions** – e.g., query VirusTotal, CrowdStrike, AD, etc.
**Step D – Decision/Trigger Actions** – route based on severity or rule name.
**Step E – Callback to Splunk** – Update the notable status:
- `POST https://<splunk-host>:8089/services/notable_update`
- Parameters: `ruleUIDs`, `status=2` (In Progress) / `5` (Closed), `comment`, `urgency`.
### 3. (Alternative) Push Model via Splunk Alert Action
- In Splunk ES, edit the correlation search.
- Under **Adaptive Response Actions**, add a **Webhook** action pointing to a Tines **Webhook Action** URL.
- Tines receives the notable event JSON in real time—no polling needed.
### 4. Schedule the Story
- For the pull model, use a **Tines Scheduler / Send to Story** trigger running every 1–5 minutes.
- Use deduplication logic (e.g., store processed `event_id`s in a Tines Resource) to avoid reprocessing.
## Official Documentation
Yes—Tines maintains official documentation. The most relevant resources:
- **Tines Hub / Story Library** – Pre-built Splunk templates:  
    `https://www.tines.com/library/` (search for "Splunk")
- **Tines Docs – Splunk integration & HTTP Request action:**  
    `https://www.tines.com/docs/`
- **Splunkbase – Tines App for Splunk** (if available in your version):  
    `https://splunkbase.splunk.com/`
- **Splunk REST API Reference** – for search jobs and notable updates:  
    `https://docs.splunk.com/Documentation/Splunk/latest/RESTREF/RESTsearch`
- **Splunk ES Notable Event API:**  
    `https://docs.splunk.com/Documentation/ES/latest/API/NotableAPIReference`
## Recommended Best Practices

- Use **bearer tokens** rather than basic auth.
- Restrict the Splunk service account to least privilege.
- Store all secrets in **Tines Credentials**, never inline.
- Implement **deduplication** and **error handling** branches.
- Log actions back to Splunk (via HEC) for auditability.
- Test in a **Sandbox / Draft Story** before promoting to production.