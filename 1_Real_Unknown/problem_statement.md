# 🎯 Problem Statement

> **Stage 1: Real Unknown** — Clearly define the pain point, gap, or opportunity before starting.

---

## 🔍 Core Problem / Pain Point
When critical production incidents hit PostgreSQL/EDB database clusters, enterprise DBAs generate EDB Lasso diagnostic bundles (`.tar.gz`) to dispatch to vendor support. However, these bundles capture plaintext database passwords, replication credentials (`primary_conninfo`), SCRAM/MD5 hashes, API keys, and internal RFC 1918 network topologies verbatim.

- **Current State:** Sharing raw Lasso bundles violates zero-trust security postures and compliance mandates (SOC 2, HIPAA, PCI-DSS), causing transmission delays or catastrophic secret leakage.
- **Ideal State:** An automated, zero-pip, deterministic reduction engine that strips credentials, pseudonymizes node IPs consistently across cluster logs, handles recursive nested archives (`.tar.bz2`), preserves binary crash dumps, and generates dual audit manifests.
- **The Gap:** Standard diagnostic tooling lacks built-in deterministic redaction and dual-manifest segregation for support vs. SecOps.

## 👥 Target Audience & Stakeholders
- **Primary User:** Enterprise PostgreSQL DBAs and Platform Site Reliability Engineers (SREs).
- **Secondary Stakeholders:** Enterprise Infosec / Compliance Officers (CISO teams) and EnterpriseDB (EDB) Support Engineers.

## 💡 Proposed Value Proposition
- Instant compliance sign-off: Eliminates secret leakage before diagnostics leave the customer perimeter.
- Deterministic correlation: Support engineers can reconstruct replication topologies and timeline flows without learning real internal network addressing.
- Dual-manifest separation: Internal SecOps retains forensic audit proofs (`security_donotshare`), while vendor support receives clean evidence without credentials.

## 🚀 Constraints & Scope Boundaries
- Zero external package dependencies (standard library only) to ensure execution in air-gapped database servers.
- Preserves raw unreadable/binary artifacts (`shutil.copy2`) without file corruption.
