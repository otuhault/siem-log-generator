---
title: "Splunk Operator for Kubernetes (SOK) - Air-Gapped On-Premises Implementation Guide"
type: architecture-guide
product: splunk-sok
family: kubernetes
date: 2026-11-03
status: stable
tags:
  - splunk/sok
  - splunk/kubernetes
  - air-gapped
  - cisco-ucs
  - architecture
  - professional-services
---

# Splunk Operator for Kubernetes (SOK) — Air-Gapped Implementation Guide

> [!summary] Executive Summary & Consultant Overview
> The **Splunk Operator for Kubernetes (SOK)** enables declarative, automated lifecycle management of Splunk Enterprise deployments on Kubernetes (Standalone, Distributed Clustered Indexers, Search Head Clusters, and SmartStore). In **on-premises air-gapped environments**, SOK requires specific architecture patterns: private container registries, offline CRD pre-provisioning, S3-compatible on-prem object storage (SmartStore), and decoupled secret management for enterprise licensing and TLS.

---
### 1. 🏗️ Air-Gapped Architectural Blueprint

```
+-----------------------------------------------------------------------------------+
|                        AIR-GAPPED KUBERNETES CLUSTER                             |
|                                                                                   |
|  +------------------------+      +---------------------------------------------+  |
|  | Private Registry       | ---> | Splunk Operator Pod                         |  |
|  | (Harbor / Artifactory) |      | (Reconciliation loop & CRD Controller)      |  |
|  +------------------------+      +---------------------------------------------+  |
|                                           |                                       |
|                  +------------------------+-----------------------+               |
|                  |                                                |               |
|  +--------------------------------+            +-------------------------------+  |
|  | Search Head Cluster (SHC)      |            | Indexer Cluster (Clustered)   |  |
|  | (SearchHead CR)                |            | (ClusterManager + Indexer CR) |  |
|  +--------------------------------+            +-------------------------------+  |
|                  |                                                |               |
|  +--------------------------------+            +-------------------------------+  |
|  | Fast Local Storage (NVMe CSI)  |            | SmartStore Cache (NVMe CSI)   |  |
|  +--------------------------------+            +-------------------------------+  |
|                                                                   |               |
|  +-----------------------------------------------------------------------------+  |
|  | On-Prem S3 Object Storage (SeaweedFS / MinIO / Ceph / Dell ECS / UCS POD)   |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

### 2. 🚀 Step-by-Step Air-Gapped Deployment Methodology

#### Step 1: Container Image Mirroring
In an isolated environment, pull public images in a connected staging bastion, export to tarballs, transfer via approved air-gap data diode/media, and push to the internal private registry:
```bash
# Core SOK and Splunk images to mirror:
- docker.io/splunk/splunk-operator:<version>
- docker.io/splunk/splunk:<version> (e.g. 10.6.4, 10.4.x)
- quay.io/k8scsi/csi-resizer:... (if bundling local CSI)
```

#### Step 2: Manual CRD Pre-Installation
> [!danger] CRD Size Limit in Helm
> Helm does not bundle SOK CRDs by default because they exceed Kubernetes etcd's 1MB metadata limit.
> **Mandatory Action:** Download and manually apply CRD manifests before running Helm:
```bash
kubectl apply -f https://github.com/splunk/splunk-operator/releases/download/<version>/crds.yaml
# Or offline:
kubectl apply -f ./manifests/crds.yaml
```

#### Step 3: Secret Management (License & TLS)
Create isolated Kubernetes Secrets for the Enterprise license and certificates:
```bash
# Enterprise License Secret
kubectl create secret generic splunk-enterprise-license \
  --from-file=enterprise.lic=/opt/splunk/licenses/enterprise.lic \
  -n splunk

# TLS CA and Key Secret
kubectl create secret tls splunk-tls-certificates \
  --cert=/path/to/tls.crt \
  --key=/path/to/tls.key \
  -n splunk
```

#### Step 4: SOK Helm Chart Deployment with Private Values
Deploy SOK using customized `values.yaml` pointing to the private registry:
```yaml
image:
  repository: internal-registry.corp.local/splunk/splunk-operator
  tag: 3.1.0
  imagePullPolicy: IfNotPresent

imagePullSecrets:
  - name: internal-registry-secret

env:
  - name: RELATED_IMAGE_SPLUNK_ENTERPRISE
    value: "internal-registry.corp.local/splunk/splunk:10.6.4"
```
```bash
helm install splunk-operator ./splunk-operator-chart -f values.yaml -n splunk
```

---

### 3. 💾 Storage Architecture & SmartStore on Cisco UCS

> [!tip] Recommended Storage Tiering
> * **Hot/Warm Local Cache (CSI) :** High-performance NVMe/SSD via Rook-Ceph, Portworx, or OpenEBS for local bucket cache and search operations.
> * **SmartStore Remote Storage (S3-Compatible) :** Mandatory for scaling indexers without petabyte-scale local SAN disks. Cisco UCS Splunk POD natively leverages **SeaweedFS** or enterprise S3 (MinIO, Dell ECS).

```yaml
# Example SmartStore Spec in IndexerCluster CR
apiVersion: enterprise.splunk.com/v4
kind: IndexerCluster
metadata:
  name: idxc
  namespace: splunk
spec:
  replicas: 3
  smartStore:
    volList:
      - name: default
        endpoint: http://seaweedfs-s3.storage.svc:8333
        bucket: splunk-smartstore
        secretRef: seaweedfs-s3-secret
  licenseMasterRef:
    name: license-master
```

---

### 4. 📚 Consultant Enablement Resources & CVD Links

* **Cisco Validated Design (CVD) :**
  * [Splunk POD on Cisco UCS Deployment Guide](https://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/UCS_CVDs/cisco_ucs_splunk_pod.html)
* **Sales Connect Collateral & Decks :**
  * `Splunk on Kubernetes (SOK) First - FAQ FY27` (Sales Connect)
  * `Splunk POD Frequently Asked Questions` (Sales Connect)
  * `Splunk Platform + AI - BDM Deck FY27` (Sales Connect)
* **Internal Training (School of Splunk) :**
  * *Splunk Operator for Kubernetes Overview*
  * *Deep Dive Training for Support & PS*
  * *Triage and Troubleshoot SOK*
* **Official Docs & Lantern :**
  * [Splunk Operator for Kubernetes Official Documentation](https://help.splunk.com/en/splunk-enterprise/splunk-operator-for-kubernetes-guide/3.1/splunk-operator-for-kubernetes-overview)
  * [Splunk Lantern: SOK Advanced Operational Learnings](https://lantern.splunk.com/Platform_Data_Management/Transform_Pipelines/Splunk_Operator_for_Kubernetes:_Advanced_operational_learnings)
