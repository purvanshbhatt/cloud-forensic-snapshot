# Contributing to Cloud Forensic Snapshot

Thank you for your interest in contributing to Cloud Forensic Snapshot (CFS)!

## Core Principles

Before contributing, understand our non-negotiable design principles:

1. **Logs = Evidence** — Every feature must treat cloud logs as forensic artifacts
2. **Read-Only Operations** — We NEVER write to source cloud environments
3. **No AI/LLM Integration** — This is intentional; see README for rationale
4. **Evidence Integrity** — All outputs must be hashable and verifiable

## How to Contribute

### Reporting Issues

- Search existing issues first
- Include: CFS version, Python version, cloud provider, error logs
- For security vulnerabilities, email maintainers directly (do not open public issues)

### Code Contributions

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Write tests for new functionality
4. Ensure all tests pass: `pytest`
5. Run linting: `ruff check .`
6. Submit a pull request

### Pull Request Guidelines

- One feature/fix per PR
- Update documentation if needed
- Add tests for new collectors or preservation logic
- Follow existing code style

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/cloud-forensic-snapshot.git
cd cloud-forensic-snapshot
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -e ".[dev]"
```

## Code of Conduct

Be respectful. Be professional. We're building tools for serious incident response work.

## Questions?

Open a discussion or issue. We're here to help.
