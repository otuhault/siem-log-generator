---
title: "Splunk AI Tier on Kubernetes (SOK) — Architecture & Enablement Guide for SAIA & ES 8.8 Agentic SOC"
type: architecture-guide
product: splunk-ai-tier
family: kubernetes
date: 2026-11-03
status: stable
tags:
  - splunk/ai-tier
  - splunk/sok
  - splunk/es-8.8
  - agentic-soc
  - saia
  - llm-inference
  - architecture
  - professional-services
---

# Splunk AI Tier on Kubernetes (SOK) — Architecture & Enablement Guide

> [!summary] Executive Summary & Consulting Rationale
> The **Splunk AI Tier for Kubernetes (CMP-K - Customer Managed Platform on Kubernetes)** delivers a fully self-hosted, air-gapped AI runtime layer running on customer-managed GPU infrastructure. Rather than deploying traditional Splunk search heads or indexers, SOK orchestrates **local LLM serving (e.g. Llama 3/3.1, Mistral, Nemotron, Antares 3B)**, vector databases, and agent memory services. This provides the execution backbone for the **Splunk AI Assistant (SAIA)** and future-proofs on-premises environments for **Enterprise Security (ES 8.8+) Agentic SOC** workflows (Detection Builder, Connector Builder, AI SOC Analyst, and Automation Builder).

---

### 1. 🏗️ Logical Architecture: The Provider/Consumer Operator Pattern

The AI Tier decouples the shared AI infrastructure lifecycle from consumer security products (like ES and Core) through an **Operator-first Provider/Consumer model**:

```
+----------------------------------------------------------------------------------------------------+
|                                    CUSTOMER KUBERNETES CLUSTER (CMP-K)                             |
|                                                                                                    |
|  [ Namespace: ai-tier ] (Shared Platform Provider)                                                 |
|  +----------------------------------------------------------------------------------------------+  |
|  |  +---------------------------+    +-----------------------------+    +--------------------+  |  |
|  |  | Model Serving (vLLM/Triton|    | Vector Store / Embedding DB |    | Shared Memory      |  |  |
|  |  | (NVIDIA L40S / A100 GPUs) |    | (Milvus / Qdrant / Pgvector)|    | Service            |  |  |
|  |  +---------------------------+    +-----------------------------+    +--------------------+  |  |
|  |                                  ^                                  ^                        |  |
|  |                                  |                                  |                        |  |
|  |  +----------------------------------------------------------------------------------------+  |  |
|  |  | Platform Operator (AI-Tier Controller) & AI Gateway / Agent Registry (MCP / A2A)      |  |  |
|  |  +----------------------------------------------------------------------------------------+  |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                             ^                                                      |
|                      Declarative CRDs via   | Reconciles & writes Binding                          |
|                      Public Kubernetes API  | Secrets per Consumer Namespace                       |
|                                             v                                                      |
|  [ Namespace: splunk-es ] (Consumer: Enterprise Security 8.8+)                                     |
|  +----------------------------------------------------------------------------------------------+  |
|  |  +----------------------------------------------------------------------------------------+  |  |
|  |  | ES Operator & Agentic SOC Workloads:                                                   |  |  |
|  |  | - Detection Builder Agent   - Connector Builder Agent                                  |  |  |
|  |  | - AI SOC Analyst            - Automation Builder Agent                                 |  |  |
|  |  +----------------------------------------------------------------------------------------+  |  |
|  |  | ModelClaim: 'es-soc-reasoning' | VectorClaim: 'es-finding-rag' | AgentRegistration       |  |  |
|  +----------------------------------------------------------------------------------------------+  |
|                                                                                                    |
|  [ Namespace: splunk-core ] (Consumer: Splunk Core Search Head)                                    |
|  +----------------------------------------------------------------------------------------------+  |
|  |  +----------------------------------------------------------------------------------------+  |  |
|  |  | SAIA App (Splunk AI Assistant for SPL): Translates Natural Language <-> SPL            |  |  |
|  |  | ModelClaim: 'spl-translation-3b' (Binding Secret -> local vLLM endpoint)                |  |  |
|  +----------------------------------------------------------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

### 2. 📜 The Declarative CRD Public Contract

Consumer product teams and platform consultants do **not** write raw deployments or configure pod-level model parameters directly. All integrations happen via declarative Kubernetes Custom Resources:

#### A. `ModelClaim` / `InferenceClaim` (Consumer Namespace)
Requests LLM inference capacity with explicit QoS, model IDs, token quotas, and concurrency profiles:
```yaml
apiVersion: ai.splunk.com/v1alpha1
kind: ModelClaim
metadata:
  name: saia-spl-model
  namespace: splunk-core
spec:
  modelId: "splunk/spl-reasoning-model-v2"
  throughputProfile: "interactive"  # low latency SLA (<1.5s)
  maxContextTokens: 8192
  targetQoS: "guaranteed"
```

#### B. `AIPlatformAccessGrant` (Platform Namespace: `ai-tier`)
Authorizes specific consumer namespaces and kinds to access shared AI services (modeled after Kubernetes Gateway API `ReferenceGrant`):
```yaml
apiVersion: ai.splunk.com/v1alpha1
kind: AIPlatformAccessGrant
metadata:
  name: allow-splunk-es
  namespace: ai-tier
spec:
  from:
    - group: "enterprise.splunk.com"
      kind: "IndexerCluster"
      namespace: "splunk-es"
    - group: "ai.splunk.com"
      kind: "ModelClaim"
      namespace: "splunk-es"
```

#### C. `AgentRegistration` (For ES 8.8 Agentic SOC)
Registers specialized security agents into the platform's central Agent Registry:
```yaml
apiVersion: ai.splunk.com/v1alpha1
kind: AgentRegistration
metadata:
  name: es-ai-soc-analyst
  namespace: splunk-es
spec:
  displayName: "Splunk ES AI SOC Analyst"
  version: "8.8.0"
  supportedProtocols:
    - "MCP"   # Model Context Protocol
    - "A2A"   # Agent-to-Agent communication
    - "AGUI"  # Agent-to-GUI streaming
  modelClaimRef:
    name: "es-soc-reasoning"
  vectorCollectionRef:
    name: "es-finding-rag"
```

---

### 3. 🔐 Service Binding Model

1. **Consumer Declarations:** Consumer Operator applies `ModelClaim` in `splunk-core` or `splunk-es`.
2. **Platform Reconciliation:** AI-Tier Operator checks `AIPlatformAccessGrant`, provisions/routes the model, and creates a Kubernetes `Secret` inside the consumer's namespace.
3. **Dynamic Consumption:** The Secret name is returned in `.status.binding.name`. The SAIA App / ES Agent reads this Secret to obtain the internal gRPC/HTTPS endpoint, token, and certificate without hardcoded IPs.

---

### 4. ⚡ Hardware & GPU Sizing Guardrails (Air-Gapped Deployment)

> [!tip] Recommended GPU Hardware Baseline
> * **Minimum Air-Gapped Sizing (SAIA for SPL):**
>   * **4x NVIDIA L40S** (48GB VRAM each) or **2x NVIDIA A100/H100 (80GB)** across 1-2 compute nodes (e.g. Cisco UCS C240 M7 with PCIe GPUs or AWS `g6e.12xlarge`).
>   * Supports interactive SPL translation, syntax explanation, and summarization with sub-2s latency.
> * **Full Agentic SOC & ES 8.8 Production Sizing:**
>   * **8x NVIDIA L40S** (or 4x H100 NVLink).
>   * Supports parallel execution of **Detection Builder**, **Connector Builder**, **AI SOC Analyst**, and local embedding models (BGE / E5) with multi-turn session memory.

---

### 5. 🚀 Consultant Readiness Checklist for ES 8.8

* [ ] **GPU Operator Deployment:** Validate NVIDIA GPU Operator and NVIDIA Container Toolkit drivers are running cleanly on K8s.
* [ ] **Private Model Staging:** Download HuggingFace / Splunk private model weights on staging bastion and mirror into internal Object Storage (SmartStore/SeaweedFS S3 bucket) or local NVMe Persistent Volumes.
* [ ] **Namespace Separation:** Establish `ai-tier` (Platform) and `splunk-es` (Workload) namespaces with RBAC isolation.
* [ ] **MCP Protocol Validation:** Verify that Mission Control Platform (MCP) agent endpoints can communicate over low-latency cluster-local DNS (`http://ai-gateway.ai-tier.svc.cluster.local:8080`).

---

### 6. 🔗 Related Vault References
* Internal Documentation: [AI Tier Architecture on SharePoint](https://cisco.sharepoint.com/sites/spk_splunkaiorg/Splunk%20AI%20Products/AI%20Tier/AI%20Tier%20Architecture.docx)
