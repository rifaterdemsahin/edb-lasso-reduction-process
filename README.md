# EDB Lasso Diagnostic Reduction Process (PoC)

[![PostgreSQL Safe](https://img.shields.io/badge/PostgreSQL-Safe-336791?logo=postgresql&logoColor=white)](https://www.enterprisedb.com)
[![PoC Status](https://img.shields.io/badge/Status-Complete-success)]()
[![GitHub Pages](https://img.shields.io/badge/Demo-GitHub%20Pages-blue)](https://rifaterdemsahin.github.io/edb-lasso-reduction-process/)

A proof-of-concept project demonstrating how to sanitize, reduce, and pseudonymize **EDB Lasso** diagnostic reports and bundles before sharing them with EnterpriseDB support or community issue trackers, ensuring zero secret leakage.

---

## 🔍 What is EDB Lasso?

**EDB Lasso** is a multi-platform diagnostic tool developed by **EnterpriseDB (EDB)**, one of the leading providers of PostgreSQL products, enterprise tooling, and mission-critical support.

When troubleshooting or debugging complex database environments, getting a complete picture of the system's state is often the most difficult step. Lasso acts as an automated collector that safely gathers configuration details, performance metrics, and system statistics from both the PostgreSQL database and the underlying operating system.

### Why EDB Lasso is Critical When Debugging PostgreSQL Environments:

1. **Standardizes the Troubleshooting Process**  
   In traditional database debugging, support engineers and DBAs waste hours playing ping-pong with requests: *"Can you send me this log file?"* followed by *"Now can you show me the output of this query?"*  
   Lasso eliminates this by instantly bundling a comprehensive, standardized report of the entire system state. Support engineers receive exactly what they need in a format they already know how to read, drastically accelerating root-cause analysis.

2. **It is Production-Safe**  
   One of the biggest risks of debugging a live database is accidentally exposing sensitive data or slowing down the server. Lasso is specifically designed for production environments:
   * **Zero Data Extraction:** It only collects system statistics, configuration files, and diagnostics. It **never** pulls actual user data or rows from your database tables.
   * **Low Overhead:** It is built to run with an imperceptible impact on your active database workload.

3. **Holistic Ecosystem Visibility**  
   Database problems are rarely confined to just the database. A slow query might be caused by CPU throttling on the OS, or a replication failure might stem from a misconfigured backup tool. Lasso gathers data from:
   * **The Operating System:** Even if Postgres isn't installed on the machine, you can run Lasso to gather OS-level context (memory, CPU, disk configurations).
   * **The EDB/Postgres Ecosystem:** It natively collects data from surrounding architecture like **Barman** (backup/recovery), **repmgr** (replication/failover), and **EFM** (EnterpriseDB Failover Manager).

4. **Direct Support Integration**  
   Lasso is explicitly built to interface with EDB’s support portal. You configure it with your company's EDB customer token, and it can automatically upload the bundled diagnostic report securely to EDB's support engineers.

> **Summary:** If you are debugging a Postgres environment, EDB Lasso acts as your primary "black box" flight recorder. It grabs all the necessary context cleanly and securely so that you (or EDB's support team) can identify and fix the issue without guessing.

---

## 🛡️ Why the Reduction / Redaction Process is Necessary

While EDB Lasso guarantees zero user data extraction from tables, configuration artifacts (`postgresql.conf`, `pg_hba.conf`, `barman.conf`) and environment dumps frequently contain:
- **Connection Strings & Passwords**: `primary_conninfo = 'host=... password=SecretPass'`
- **Backup Authentication Tokens**: Barman streaming credentials and SSH private key references
- **Authentication Hashes**: `md5...` and `SCRAM-SHA-256$...` passwords
- **Customer Support Tokens**: `EDB_CUSTOMER_TOKEN`
- **Cloud Credentials**: Environment variables like `AWS_SECRET_ACCESS_KEY`
- **Internal Topology & Network IPs**: Private subnets and node addresses

The **EDB Lasso Reduction Process** provides an automated, deterministic sanitization pipeline before uploading or sharing diagnostic bundles.

## 🧠 Architecture & Enterprise Debugging Lifecycle

Explore the full interactive architecture page and diagram at **[Architecture & Debugging Flow](architecture.html)**.
Download the raw diagram: **[`architecture-mindmap.excalidraw`](architecture-mindmap.excalidraw)** (openable on [Excalidraw](https://excalidraw.com)).

### What Happens During an Enterprise Debugging Session with EDB:
1. **Production Incident Trigger**: Monitoring alerts on replication lag, failover flapping in EFM, or query throttling. Severity 1 triage declared.
2. **Diagnostic Capture via EDB Lasso**: DBA runs `sudo -u postgres lasso --no-upload` to extract lock-free metrics from PostgreSQL, OS sysctl, and Barman without touching table rows.
3. **Lasso Reduction Process**: Passwords in `primary_conninfo`, MD5/SCRAM hashes, and customer tokens are stripped. Internal IPs are deterministically mapped to `PSEUDO_IP_NODE_xx` aliases.
4. **SecOps & Infosec Clearance**: The cryptographic `lasso_reduction_manifest.json` is reviewed, verifying zero credential or topology leakage.
5. **EDB Support Portal Intake**: The sanitized `.tar.gz` bundle is uploaded to the EDB Support case ticket, starting the SLA response clock.
6. **Collaborative Root Cause Analysis (RCA)**: EDB engineers analyze standardized telemetry without iterative log ping-pong, correlating OS I/O spikes with WAL generation.
7. **Remediation & Patching**: Production parameter adjustments applied, verified, and post-mortem documented.

---

## ⚙️ Architecture & Features

```
+--------------------------+       +-----------------------------------+       +-------------------------------+
| Raw EDB Lasso Artifacts  | ----> |   Lasso Reduction Engine          | ----> | Sanitized Diagnostic Bundle   |
| (Configs, Tarball, Logs) |       |   - Credential Stripping          |       | - Clean Configs & Logs        |
+--------------------------+       |   - Deterministic IP Masking      |       | - Cryptographic Manifest      |
                                   |   - Audit Logging & Verification  |       |   (lasso_reduction_manifest)  |
                                   +-----------------------------------+       +-------------------------------+
```

1. **Deterministic Pseudonymization**: Maps IP addresses consistently (e.g. `10.0.12.45` -> `PSEUDO_IP_NODE_01`) across all files in the bundle, preserving cluster topology and replication relationships without revealing internal network addressing.
2. **Multi-layer Secret Masking**: Strips plaintext passwords, SCRAM secrets, MD5 hashes, URI credentials, API tokens, and EDB customer keys.
3. **Audit Manifest Generation**: Creates a structured `lasso_reduction_manifest.json` detailing exact counts, categories, and proof of sanitization for compliance audits.
4. **Tarball Support**: Direct unpack, sanitization, and repacking of `.tar.gz` Lasso bundles.
5. **Interactive Web Sandbox**: Built-in browser-based simulator (`index.html`) to preview and test reduction rules instantly.

---

## 📑 Diagnostic Reduction Pipeline Stages

| Stage | Name | Description | Page |
| :--- | :--- | :--- | :--- |
| **01** | **Ingestion & Unpack** | Extracts the EDB Lasso tarball (`.tar.gz`) or output directory without altering raw file permissions or leaking intermediate state. | [Stage 01](stage-01-ingestion-unpack.html) |
| **02** | **Credential Stripping** | Identifies and masks passwords in conninfo, MD5 hashes, SCRAM-SHA-256 tokens, API keys, and customer tokens. | [Stage 02](stage-02-credential-stripping.html) |
| **03** | **Deterministic IP Mapping** | Maps internal IP addresses (e.g. `10.0.12.45`) to consistent aliases (`PSEUDO_IP_NODE_01`) preserving cluster topology. | [Stage 03](stage-03-deterministic-ip-mapping.html) |
| **04** | **Audit Manifest & Repack** | Generates `lasso_reduction_manifest.json` detailing redaction tallies and produces a sanitized archive. | [Stage 04](stage-04-audit-manifest-repack.html) |

### 🔍 Side-by-Side Comparison Tool
Visit the dedicated [Side-by-Side Comparison Page](comparison.html) to view side-by-side split diffs of raw Lasso configs vs. sanitized outputs with highlighted secrets.

---

## 📦 Creating the EDB Lasso Tarball (`.tar.gz`)

For complete details, visit the interactive guide at [Create EDB Lasso Tarball](create-lasso-tarball.html).

### 1. From the CLI
```bash
# Recommended: Run offline so bundle can be reduced before sharing
sudo -u postgres lasso \
  -U postgres \
  -d postgres \
  --no-upload \
  -o /var/tmp/edb_lasso_$(hostname)_$(date +%Y%m%d).tar.gz

# Targeted scope (avoid log bloat)
sudo -u postgres lasso -U postgres -d postgres --days 2 -o /tmp/edb_lasso_recent.tar.gz

# Pack mock bundle using the PoC engine
python3 lasso_redact.py --create-mock-tarball mock_lasso_bundle.tar.gz
```

### 2. What to Expect
* **Archive Format**: Standard `.tar.gz` with subdirectories `system/`, `postgresql/`, `barman/`, and `metadata.json`.
* **Runtime Duration**: 30 seconds to 3 minutes depending on I/O.
* **File Size**: Typically 5 MB to 35 MB compressed.
* **Workload Impact**: Near-zero overhead. Lock-free queries, zero customer table rows extracted.

### 3. What to Care About & Watch Out For (Gotchas)
* ⚠️ **Raw Secret Exposure**: Lasso copies `postgresql.conf` and `barman.conf` verbatim. Plaintext replication passwords (`primary_conninfo`) and backup keys **are stored in the raw archive**!
* ⚠️ **Log File Bloat**: Unrotated log directories can expand the bundle to tens of gigabytes; always specify `--days 2`.
* ⚠️ **Sudo & Catalog Permissions**: Running as a normal user will cause blank metrics; run with `sudo -u postgres`.
* ⚠️ **Network Egress**: Port 443 firewall restrictions will cause `--upload` to hang; collect offline and sanitize locally first.

---

## 🚀 Quick Start

### 1. Run Unit & Integration Tests
```bash
python3 test_lasso_redact.py
```

### 2. Sanitize a Diagnostic Directory
```bash
python3 lasso_redact.py -i mock_lasso_bundle -o sanitized_bundle
```

### 3. Sanitize a Compressed Tarball
```bash
python3 lasso_redact.py -i lasso_archive.tar.gz -o lasso_archive_sanitized.tar.gz
```

### 4. Run the Local Interactive Web UI
```bash
python3 -m http.server 30088
open -a "Google Chrome" http://localhost:30088
```

---

## 🌐 Live GitHub Pages Demo
Visit the live interactive page:
👉 **[https://rifaterdemsahin.github.io/edb-lasso-reduction-process/](https://rifaterdemsahin.github.io/edb-lasso-reduction-process/)**
