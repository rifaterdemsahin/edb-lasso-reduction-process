---
marp: true
theme: gaia
_class: lead
paginate: true
backgroundColor: #090d16
color: #e2e8f0
style: |
  section {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    padding: 40px 60px;
    font-size: 24px;
    line-height: 1.5;
  }
  h1 {
    color: #38bdf8;
    font-size: 40px;
    margin-bottom: 12px;
  }
  h2 {
    color: #0284c7;
    font-size: 32px;
    border-bottom: 2px solid #1e293b;
    padding-bottom: 8px;
    margin-top: 0;
  }
  h3 {
    color: #94a3b8;
    font-size: 24px;
    margin-bottom: 8px;
  }
  a {
    color: #38bdf8;
    text-decoration: none;
  }
  code {
    background-color: #1e293b;
    color: #38bdf8;
    border-radius: 4px;
    padding: 2px 6px;
    font-size: 0.88em;
  }
  pre {
    background-color: #0f172a !important;
    border: 1px solid #334155;
    border-radius: 8px;
    font-size: 17px;
    line-height: 1.35;
  }
  pre code {
    background: transparent !important;
    color: #cbd5e1 !important;
    padding: 0;
  }
  blockquote {
    border-left: 4px solid #0284c7;
    background: #0f172a;
    padding: 12px 20px;
    border-radius: 0 8px 8px 0;
    font-size: 20px;
    color: #94a3b8;
  }
  table {
    font-size: 19px;
    border-collapse: collapse;
    width: 100%;
    margin-top: 10px;
  }
  th {
    background-color: #1e293b;
    color: #38bdf8;
    text-align: left;
    padding: 10px 14px;
    border-bottom: 2px solid #334155;
  }
  td {
    padding: 8px 14px;
    border-bottom: 1px solid #1e293b;
    color: #cbd5e1;
  }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 9999px;
    font-size: 14px;
    font-weight: 700;
    text-transform: uppercase;
  }
  .badge-why { background: #dc2626; color: #fff; }
  .badge-what { background: #0284c7; color: #fff; }
  .badge-how { background: #16a34a; color: #fff; }
  .badge-code { background: #7c3aed; color: #fff; }
  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 24px;
  }
  .card {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 10px;
    padding: 16px 20px;
  }
  footer {
    font-size: 14px;
    color: #64748b;
  }
  header {
    font-size: 14px;
    color: #475569;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
---

<!-- _class: lead -->
# EDB Lasso Diagnostic Reduction Process
### Operational Standard Operating Procedure (SOP)
**WHY, WHAT, and HOW of Secure Diagnostic Sanitization**

<span class="badge badge-why">WHY</span> <span class="badge badge-what">WHAT</span> <span class="badge badge-how">HOW</span> <span class="badge badge-code">CODE EVOLUTION</span>

**Author:** Enterprise DBA & Platform Operations  
**Tool:** `lasso_redact.py` Engine (PoC)

---

<header>Operational Context | Executive Summary</header>

## The Enterprise Dilemma

When high-severity incidents strike an **EDB Postgres** cluster (failovers, replication lag, memory exhaustion), vendor support asks for an **EDB Lasso bundle**.

<div class="grid-2">
  <div class="card">
    <h3 style="color: #ef4444;">🚨 Infosec Mandate</h3>
    <ul>
      <li>Plaintext passwords in <code>postgresql.conf</code></li>
      <li>MD5 / SCRAM-SHA-256 hashes in <code>pg_hba.conf</code></li>
      <li>Private IP topologies expose internal subnets</li>
      <li>Sharing breaches SOC 2, HIPAA, PCI-DSS</li>
    </ul>
  </div>
  <div class="card">
    <h3 style="color: #22c55e;">🛠️ Support Mandate</h3>
    <ul>
      <li>Need cluster node relationship topology</li>
      <li>Need Barman & Repmgr configurations</li>
      <li>Need exact error logs & OS metrics</li>
      <li>Cannot debug without realistic context</li>
    </ul>
  </div>
</div>

> **Resolution:** An automated, verifiable, deterministic redaction pipeline before external transfer.

---

<header>Operational Procedure | The WHY</header>

## <span class="badge badge-why">WHY</span> Why Is This Procedure Mandatory?

Every Lasso report captures complete system configuration states:

1. **Authentication Secrets**:
   `primary_conninfo = 'host=10.0.12.45 user=repuser password=SuperSecret!'`
2. **Database URI Schemes**:
   `postgres://admin:P@ssword123@192.168.1.50:5432/mydb`
3. **Portal & API Tokens**:
   `EDB_CUSTOMER_TOKEN = edb_prod_cust_tok_...`
4. **Internal Network Maps**:
   RFC 1918 addresses (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`) that reveal internal VPC architectures.

**The Risk:** Sending raw bundles exposes live database credentials and corporate network topology to external ticket portals and ticketing archives.

---

<header>Operational Procedure | The WHAT</header>

## <span class="badge badge-what">WHAT</span> What Is the Lasso Reduction Process?

A modular 4-stage pipeline that sanitizes bundles while retaining 100% diagnostic integrity:

```
[Raw Lasso Archive (.tar.gz / .tar.bz2)]
               │
               ▼
┌────────────────────────────────────────────────────────┐
│ Stage 01: Ingestion & Archive Unpacking                │
├────────────────────────────────────────────────────────┤
│ Stage 02: Pattern Masking & Credential Redaction       │
├────────────────────────────────────────────────────────┤
│ Stage 03: Deterministic IP Pseudonymization            │
├────────────────────────────────────────────────────────┤
│ Stage 04: Audit Manifest Generation & Re-packing       │
└────────────────────────────────────────────────────────┘
               │
               ▼
[Sanitized Bundle + lasso_reduction_manifest.json]
```

---

<header>Code Evolution | The Problem</header>

## <span class="badge badge-code">CODE</span> The Real-World Bug Uncovered

When running early versions against production-like Lasso reports:

```bash
$ python3 lasso_redact.py -i lassoreport.tar.gz -o lassoreport_redacted.tar.gz
...
[+] Reduction Completed: Total Redacted Secrets: 0
```

### Why did it report 0 redactions?

1. **Nested Archive Architecture**:
   EDB Lasso creates an outer `.tar.gz`, but inside it packages individual node diagnostics as **nested `.tar.bz2` archives** (`node-01.tar.bz2`, `node-02.tar.bz2`).
   *The script was simply copying the inner `.tar.bz2` files without looking inside!*

2. **Binary File Drops**:
   When decoding non-UTF8 files (binaries, core dumps, SSL certs), `open()` with `errors="replace"` or unhandled read exceptions skipped or mangled raw binary assets.

---

<header>Code Deep Dive | Solution 1: Nested Archives</header>

## <span class="badge badge-code">CODE</span> Handling Nested `.tar.bz2` Archives

The engine now recursively detects and unpacks inner bzip2 archives:

```python
def redact_nested_tar_bz2(self, archive_path: Path, output_path: Path):
    """Extract, redact and rebuild nested .tar.bz2 archives."""
    with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
        with tarfile.open(archive_path, "r:bz2") as tar:
            tar.extractall(tmp_in)

        # Recursively redact the extracted directory tree
        self.redact_directory(Path(tmp_in), Path(tmp_out))

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output_path, "w:bz2") as tar:
            tar.add(tmp_out, arcname="")
```

*Inside `redact_directory()`:*
```python
if file_name.endswith(".tar.bz2"):
    print(f"[*] Processing nested archive: {src_file}")
    self.redact_nested_tar_bz2(src_file, dest_file)
    total_files += 1
    continue
```

---

<header>Code Deep Dive | Solution 2: Binary Preservation</header>

## <span class="badge badge-code">CODE</span> Preserving Binaries via `shutil.copy2`

In `redact_file()`, text processing is encapsulated in a safe `try-except` block:

```python
def redact_file(self, file_path: Path, output_path: Path) -> int:
    """Redacts a single file and writes to destination."""
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        redacted_content, matches = self.redact_text(
            content, source_identifier=file_path.name
        )
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(redacted_content)
        return len(matches)

    except Exception:
        # Fallback: preserve binary dumps, certificates, or unparsed files byte-for-byte
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_path, output_path)
        return 0
```

---

<header>Operational Procedure | The HOW (Step-by-Step SOP)</header>

## <span class="badge badge-how">HOW</span> Standard Operating Procedure (SOP)

### Phase 1: Bundle Capture (DBA Host)
```bash
# Generate the official EDB Lasso bundle
sudo lasso --barman --system --postgresql --tarball
# Creates: /tmp/edb-lasso-report-<cluster>-<date>.tar.gz
```

### Phase 2: Reduction Execution (Secure Staging)
```bash
python3 lasso_redact.py \
  -i /tmp/edb-lasso-report.tar.gz \
  -o /tmp/edb-lasso-report-sanitized.tar.gz
```

You will see:
`[*] Processing nested archive: .../node1.tar.bz2`  
`[+] Reduction Completed Successfully! Total Redacted Secrets: 21`

---

<header>Operational Procedure | Verification</header>

## <span class="badge badge-how">HOW</span> Validating the Sanitized Output

### Phase 3: Inspect Audit Manifest
```bash
cat sanitized_bundle/lasso_reduction_manifest.json | jq .category_breakdown
```

Sample audit output:
```json
{
  "title": "EDB Lasso Reduction Manifest",
  "total_redactions": 21,
  "category_breakdown": {
    "network": 13,
    "credentials": 6,
    "api_tokens": 2
  },
  "pseudonymized_ip_count": 6
}
```

> **Infosec Rule:** If `"total_redactions": 0` on an archive containing secrets, abort transmission and investigate new pattern rules.

---

<header>Deep Dive | Deterministic IP Mapping</header>

## Deterministic IP Pseudonymization

Why not simply replace all IPs with `XXX.XXX.XXX.XXX`?

- PostgreSQL replication topologies require knowing which replica talks to which primary.
- Random hashing breaks replication correlation across configuration files.

### Deterministic Solution:
```
10.0.12.45 (Primary)  ──▶  PSEUDO_IP_NODE_01  (Consistently throughout all logs)
10.0.12.46 (Replica)  ──▶  PSEUDO_IP_NODE_02  (Consistently throughout all logs)
192.168.1.50 (Barman) ──▶  PSEUDO_IP_NODE_03  (Consistently throughout all logs)
```

**Result:** Support can reconstruct the failover timeline and network flow without ever learning the customer's actual private IP space.

---

<header>Operational Procedure | Operational Checklist</header>

## Pre-Transmission Checklist for DBAs

| Phase | Step | Command / Check |
|---|---|---|
| **1. Verification** | Run Unit Test Suite | `python3 test_lasso_redact.py` (Must pass 8/8) |
| **2. Reduction** | Run Engine on Tarball | `python3 lasso_redact.py -i <in> -o <out>` |
| **3. Nested Check** | Observe Node Logs | Ensure `[*] Processing nested archive:` appeared |
| **4. Manifest** | Inspect Counts | Confirm `total_redactions > 0` |
| **5. Evidence** | Attach Manifest | Upload `lasso_reduction_manifest.json` with ticket |
| **6. Cleanup** | Secure Staging Cleanup | Remove raw bundles from temporary directory |

---

<!-- _class: lead -->
# Summary & Key Takeaways

1. **Compliance by Design:** Eliminates password leaks and network exposure before files leave your perimeter.
2. **Recursive Archive Support:** Handles both outer `.tar.gz` and nested `.tar.bz2` node bundles.
3. **Data Integrity Guarantee:** `shutil.copy2` fallback protects binary dumps and certificates from corruption.
4. **Transparent Audit Trail:** Cryptographic and categorical manifest satisfies SOC 2 / ISO 27001 evidence requirements.

---

<header>Resources & Documentation</header>

## Links & References

- **Web Dashboard:** [http://localhost:30088/index.html](http://localhost:30088/index.html)
- **Interactive Presentation:** [http://localhost:30088/presentation.html](http://localhost:30088/presentation.html)
- **Source Code:** [`lasso_redact.py`](file:///Users/rifaterdemsahin/projects/edb-lasso-reduction-process/lasso_redact.py)
- **Test Suite:** [`test_lasso_redact.py`](file:///Users/rifaterdemsahin/projects/edb-lasso-reduction-process/test_lasso_redact.py)
- **GitHub Repository:** [https://github.com/rifaterdemsahin/edb-lasso-reduction-process](https://github.com/rifaterdemsahin/edb-lasso-reduction-process)
