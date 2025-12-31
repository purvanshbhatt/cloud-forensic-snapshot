# Cloud Forensic Snapshot (CFS)

> **In traditional forensics, you seize the disk. In cloud forensics, the disk is already gone. Logs are the evidence.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10+-green.svg)](https://python.org)

**Cloud Forensic Snapshot** is a vendor-neutral, incident-ready forensic acquisition tool designed to collect, preserve, and validate log-based evidence across **AWS**, **Azure**, and **GCP**—even when infrastructure no longer exists.

---

## Why Cloud Forensics is Different

| Traditional Forensics | Cloud Forensics |
|-----------------------|-----------------|
| Seize physical disk | Infrastructure is ephemeral |
| Bit-for-bit image | Logs are the primary evidence |
| Chain of custody via physical control | Chain of custody via cryptographic hashing |
| Evidence is static | Evidence may be automatically rotated/deleted |

**The reality**: By the time you respond to an incident, the compromised VM may already be terminated, the container destroyed, the Lambda function updated. What remains? **Logs.**

---

## Key Principles

1. **Logs = Evidence** — We treat cloud logs with the same rigor as disk images
2. **Assume Infrastructure is Gone** — Collect what survives, not what exists
3. **Read-Only Operations** — Zero writes to source environments
4. **Immutable by Design** — SHA-256 hashing, manifest generation, chain of custody
5. **Legally Defensible** — Designed to survive courtroom scrutiny

---

## Features

- **Multi-Cloud Support**: AWS, Azure, GCP with provider-isolated collectors
- **Evidence Preservation**: SHA-256 hashing, `manifest.json`, `chain_of_custody.txt`
- **Immutability Detection**: Warns if target bucket lacks Object Lock
- **Permission Preflight**: Validates access before collection begins
- **Dry-Run Mode**: Simulate acquisition without touching anything
- **YAML Configuration**: Reproducible, auditable collection parameters
- **Execution Audit Log**: Complete record of tool operations

---

## Installation

```bash
pip install cloud-forensic-snapshot
```

Or from source:

```bash
git clone https://github.com/YOUR_USERNAME/cloud-forensic-snapshot.git
cd cloud-forensic-snapshot
pip install -e .
```

---

## Quick Start

```bash
# Collect last 24 hours of AWS evidence
cfs snapshot \
  --provider aws \
  --account-id 123456789012 \
  --time-window 24h \
  --incident-id IR-2025-001 \
  --output ./forensic_snapshot

# Dry-run first (recommended)
cfs snapshot --provider aws --dry-run --config config.yaml
```

---

## Authentication

CFS delegates authentication to your existing cloud CLI tools. This is intentional:

| Why Delegation? | Benefit |
|-----------------|---------|
| **Least Privilege** | Use your existing IAM roles with minimal permissions |
| **No Credential Storage** | CFS never stores or manages secrets |
| **Audit Trail** | All access logged via native cloud audit mechanisms |
| **Enterprise Ready** | Works with SSO, MFA, assumed roles |

### Supported Authentication Modes

**AWS**
- AWS CLI configured profiles (`~/.aws/credentials`)
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
- IAM instance profiles (EC2)
- Assumed roles via STS

**Azure**
- Azure CLI (`az login`)
- Service Principal with environment variables
- Managed Identity

**GCP**
- gcloud CLI (`gcloud auth login`)
- Application Default Credentials
- Service Account key files

---

## What Gets Collected

### AWS
| Source | Description |
|--------|-------------|
| CloudTrail | Management and Data events |
| VPC Flow Logs | Network traffic metadata |
| GuardDuty | Threat findings |
| IAM | Credential reports, policies |
| EC2 | Instance metadata (if available) |
| S3 | Access logs |
| Lambda | CloudWatch execution logs |

### Azure
| Source | Description |
|--------|-------------|
| Activity Logs | Control plane operations |
| Azure AD | Audit and Sign-in logs |
| NSG Flow Logs | Network traffic |
| Azure Monitor | Diagnostic logs |
| Storage | Analytics logs |

### GCP
| Source | Description |
|--------|-------------|
| Cloud Audit Logs | Admin and Data access |
| VPC Flow Logs | Network metadata |
| IAM | Policy bindings |
| Compute | Instance metadata |
| Cloud Functions | Execution logs |

---

## Output Structure

```
forensic_snapshot/
├── provider/
│   ├── aws/
│   │   ├── cloudtrail/
│   │   ├── vpc_flow_logs/
│   │   ├── guardduty/
│   │   └── iam/
│   ├── azure/
│   └── gcp/
├── logs/
│   └── execution_audit.log
├── metadata/
│   └── collection_context.json
├── hashes/
│   └── sha256sums.txt
├── manifest.json
└── chain_of_custody.txt
```

---

## Evidence Integrity

Every acquisition produces:

| File | Purpose |
|------|---------|
| `manifest.json` | Complete inventory with SHA-256 per artifact |
| `chain_of_custody.txt` | Acquisition metadata, timestamps, investigator info |
| `sha256sums.txt` | Hashcat/forensic-tool compatible hash list |

### Immutability Warning

CFS detects whether your output bucket has immutability enabled:

```
⚠️  WARNING: Target bucket 's3://evidence-bucket' does NOT have Object Lock enabled.
    Evidence integrity cannot be guaranteed without immutability.
    See: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
```

---

## Configuration

```yaml
# config.yaml
provider: aws
account_id: "123456789012"
time_window: 24h
incident_id: IR-2025-001

output:
  type: local  # or 's3', 'azure-blob', 'gcs'
  path: ./forensic_snapshot

collectors:
  cloudtrail:
    enabled: true
    include_data_events: true
  vpc_flow_logs:
    enabled: true
  guardduty:
    enabled: true
  iam:
    enabled: true
```

---

## Required Permissions

CFS requires **read-only** access. Example AWS policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrail",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "ec2:DescribeInstances",
        "ec2:DescribeFlowLogs",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## Why No AI?

This tool deliberately excludes AI/LLM integration. Why?

1. **Forensic Purity** — Evidence collection must be deterministic and reproducible
2. **Legal Defensibility** — "The AI interpreted..." is not a valid chain of custody
3. **Operational Security** — No API keys, no external calls, no data exfiltration risk
4. **Separation of Concerns** — Collection ≠ Analysis

> **For AI-assisted analysis**, consider building a private MCP server that reads collected evidence. Keep acquisition and analysis separate.

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Roadmap

- [ ] v0.1: AWS collector + CLI + evidence preservation
- [ ] v0.2: Azure collector
- [ ] v0.3: GCP collector
- [ ] v0.4: Multi-cloud correlation support
- [ ] v1.0: Production hardening

---

<p align="center">
  <i>Built for incident responders who understand that in the cloud, logs are the only truth that survives.</i>
</p>
