# Changelog

All notable changes to the **Cloud Forensic Snapshot** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-12-31

### Production Readiness
- **Production Hardened**: Full resilience, concurrency, and audit logging for enterprise-scale deployments.
- **Strict Separation**: Verified architectural isolation between preservation (CFS) and analysis (Private MCP), ensuring forensic purity.
- **Forensic Integrity**: Validated manifest generation, SHA-256 hashing, and Chain of Custody compliance.

### Added
- **Resilience**: Implemented `@with_retry` decorator with exponential backoff for all cloud API calls (AWS, Azure, GCP).
- **Concurrency**: Parallelized evidence collection using `ThreadPoolExecutor` for high-throughput acquisition.
- **Audit Logging**: Added full-fidelity `execution.log` capturing every CLI action and API result.
- **Packaging**: Standardized distribution with `MANIFEST.in` and strict dependency management.
- **Testing**: Comprehensive `pytest` suite with `moto` mocks and live smoke test verification.

### Changed
- **CLI**: Improved authentication guidance and error reporting for missing credentials.
- **Dependencies**: Added `google-cloud-functions` and production-grade version pinning.

## [0.2.0] - 2025-12-30

### Added
- **Multi-Cloud Parity**: Full collector implementations for Azure (Activity Logs, Network, Compute) and GCP (Audit Logs, IAM, Network, Cloud Functions).
- **Export Command**: New `cfs export` command supporting local disk, S3, and GCS destinations with `check_immutability` warnings.
- **Manifest v1.0**: Standardized JSON schema for `manifest.json` with explicit `errors` array and `status` field.
- **Improved Failure Handling**: Collectors now report partial failures (exit code 1) instead of crashing (exit code 0) or aborting completely.
- **Immutability Awareness**: CLI now warns if target export buckets do not have Object Lock (S3) or Retention Policy (GCS) enabled.

### Changed
- **CLI Exit Codes**:
    - `0`: Success
    - `1`: Partial success (some collectors failed)
    - `2`: Preflight failure or configuration error
- **Timestamp Precision**: Enforced UTC normalization across all AWS/Azure/GCP collectors.

### Security
- Added explicit Threat Model and "What CFS Does NOT Do" section to README.
- Clarified "Least Privilege" permission matrix for all three clouds.

## [0.1.0] - 2025-12-30

### Added
- Initial release of Cloud Forensic Snapshot.
- AWS Collector (CloudTrail, GuardDuty, IAM, VPC Flow Metadata, EC2).
- Core preservation layer (SHA-256 hashing, Manifest, Chain of Custody).
- Basic CLI structure with `init`, `snapshot`, `verify`.
