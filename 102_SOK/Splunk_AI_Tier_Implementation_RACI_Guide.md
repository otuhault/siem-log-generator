---
title: "Splunk AI Tier & SOK On-Premises Implementation Roadmap & RACI Guide"
type: consulting-delivery-guide
product: splunk-ai-tier
family: professional-services
date: 2026-11-03
status: stable
tags:
  - splunk/ai-tier
  - splunk/sok
  - professional-services
  - raci
  - delivery-roadmap
  - agentic-soc
---

# Splunk AI Tier & SOK On-Premises Implementation Roadmap & RACI Guide

> [!summary] Consultant Scope & Purpose
> This guide outlines the official multi-phase implementation methodology for deploying the **Splunk AI Tier on Kubernetes (SOK/CMP-K)** and connecting it with **SAIA (Splunk AI Assistant)** and **Enterprise Security (ES 8.8+) Agentic SOC**. It provides a clear **RACI matrix** to delineate infrastructure/hardware boundaries from high-value **Professional Services (PS) consulting and delivery workflows**.

---
### 1. 👥 RACI Matrix by Project Phase

| Phase | Milestone | Client Infra / DC Team | Client K8s Admin | Splunk PS Consultant (YOU) | Splunk / SOC Admin |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Phase 1** | **Hardware & Physical Rack Readiness** | **Accountable / Responsible** | Consulted | **Informed** *(Intake validation only)* | Informed |
| **Phase 2** | **Kubernetes Substrate & GPU Drivers** | Consulted | **Accountable / Responsible** | **Consulted / Validator** | Informed |
| **Phase 3** | **AI-Tier Platform Operator & Local Models** | Informed | Consulted | **Responsible / Accountable** | Consulted |
| **Phase 4** | **Service Binding & SAIA App Integration** | Informed | Informed | **Responsible / Accountable** | **Accountable / User** |
| **Phase 5** | **ES 8.8 Agentic SOC Onboarding & Validation** | Informed | Informed | **Responsible** | **Accountable / Approver** |

---

### 2. 🚦 Phase-by-Phase Delivery Workflow

```
+-------------------------------------------------------------------------------------------------+
| [PHASE 1] Hardware & DC Readiness (Client Infra)                                                |
| Racking, Cabling, Power (Cisco UCS / GPUs: 4x-8x L40S/H100), TOR Switching (Nexus), IP/VLANs  |
+-------------------------------------------------------------------------------------------------+
                                                |
                                                v
+-------------------------------------------------------------------------------------------------+
| [PHASE 2] Kubernetes & GPU Substrate (Client K8s Team / SKI)                                    |
| k0s/OpenShift deploy, CSI Storage Classes (NVMe + S3), NVIDIA GPU Operator & Container Toolkit |
+-------------------------------------------------------------------------------------------------+
                                                |
                                                v
+-------------------------------------------------------------------------------------------------+
| [PHASE 3] AI-Tier Platform & Model Serving (SPLUNK PS CONSULTANT CORE SCOPE)                   |
| 1. Create 'ai-tier' namespace & configure private registry image mirror                         |
| 2. Deploy AI-Tier Operator (vLLM/Triton, Qdrant Vector DB, Shared Memory) via Helm             |
| 3. Stage local LLM weights (Mistral, Nemotron, Llama 3) & configure 'AIPlatformAccessGrant'    |
+-------------------------------------------------------------------------------------------------+
                                                |
                                                v
+-------------------------------------------------------------------------------------------------+
| [PHASE 4] SAIA App & Service Binding (SPLUNK PS CONSULTANT CORE SCOPE)                          |
| 1. Apply 'ModelClaim' CRD in 'splunk-core' namespace (specifying 'interactive' profile)         |
| 2. Reconcile Secret binding (.status.binding.name) containing internal gRPC/HTTPS endpoint      |
| 3. Configure SAIA App on Search Head & test natural language <-> SPL translation (<1.5s SLA)    |
+-------------------------------------------------------------------------------------------------+
                                                |
                                                v
+-------------------------------------------------------------------------------------------------+
| [PHASE 5] ES 8.8 Agentic SOC Enablement (SPLUNK PS CONSULTANT CORE SCOPE)                       |
| 1. Apply 'AgentRegistration' CRDs in 'splunk-es' (Triage, Detection, and Connector Agents)     |
| 2. Wire MCP (Model Context Protocol) and A2A interfaces to Vector Store & Finding context       |
| 3. Validate HITL containment guardrails, audit logging (View Change History), and GPU metrics   |
+-------------------------------------------------------------------------------------------------+
```

---
### 3. 🔍 Detailed Breakdown of Your PS Consultant Deliverables
#### Step A: Pre-Flight Intake & Validation (Phase 1 & 2 Check)
* Review the **Customer Intake Form**:
  * Confirm GPU allocation: at least **4x NVIDIA L40S** or **2x H100 (80GB)**.
  * Verify GPU driver readiness: Run `kubectl describe nodes` and confirm `nvidia.com/gpu: 4` is allocatable.
  * Verify persistent NVMe storage class and S3-compatible bucket (SeaweedFS / MinIO) for model weight caching.

#### Step B: AI-Tier Platform Deployment (Phase 3)
* Create isolated platform namespace:
  `kubectl create namespace ai-tier`
* In an air-gapped setup, verify local container images are staged in Harbor/Artifactory.
* Deploy the AI-Tier Helm chart with custom `values.yaml`:
  ```yaml
  modelServing:
    engine: vLLM
    defaultModel: "splunk/spl-reasoning-model-v2"
    gpuCount: 4
  vectorDB:
    enabled: true
    engine: qdrant
  ```
* Apply the cross-namespace authorization grant (`AIPlatformAccessGrant`):
  ```yaml
  apiVersion: ai.splunk.com/v1alpha1
  kind: AIPlatformAccessGrant
  metadata:
    name: allow-splunk-consumers
    namespace: ai-tier
  spec:
    from:
      - group: "ai.splunk.com"
        kind: "ModelClaim"
        namespace: "splunk-core"
      - group: "ai.splunk.com"
        kind: "ModelClaim"
        namespace: "splunk-es"
  ```

#### Step C: Service Binding & SAIA App Configuration (Phase 4)
* Declare the consumer `ModelClaim` in `splunk-core`:
  ```yaml
  apiVersion: ai.splunk.com/v1alpha1
  kind: ModelClaim
  metadata:
    name: saia-spl-claim
    namespace: splunk-core
  spec:
    modelId: "splunk/spl-reasoning-model-v2"
    throughputProfile: "interactive"
    targetQoS: "guaranteed"
  ```
* Inspect the generated binding secret:
  `kubectl get modelclaim saia-spl-claim -n splunk-core -o jsonpath='{.status.binding.name}'`
* Bind the **Splunk AI Assistant (SAIA)** App in Splunk Web to use the local inference route.
* **Testing & Verification:** Run prompt in Search & Reporting: *"Find failed SSH logins grouped by source IP over the last 24h"* → verify SPL generated and latency is <1.5 seconds.

#### Step D: ES 8.8 Agentic SOC Onboarding (Phase 5)
* Apply `AgentRegistration` for the **AI SOC Analyst / Triage Agent**:
  ```yaml
  apiVersion: ai.splunk.com/v1alpha1
  kind: AgentRegistration
  metadata:
    name: es-triage-agent
    namespace: splunk-es
  spec:
    displayName: "Enterprise Security Triage Agent"
    version: "8.8.0"
    supportedProtocols: ["MCP", "A2A"]
    modelClaimRef:
      name: "es-soc-reasoning"
  ```
* Conduct acceptance testing: Trigger test notable event in ES, verify autonomous finding triage, entity risk scoring, and Human-In-The-Loop approval gates.

