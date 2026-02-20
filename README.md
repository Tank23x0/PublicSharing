# PublicSharing — Cyber Operations Arsenal

**Author:** Joe Romaine | [JoeRomaine.com](https://JoeRomaine.com)
**Classification:** UNCLASSIFIED // PUBLIC RELEASE
**Mission Type:** Blue Team Defense, Offensive Security Research, Enterprise Hardening

A curated arsenal of **700+ production-grade scripts, audit frameworks, and security tooling** built for **SOC analysts, threat hunters, incident responders, and penetration testers**. Every tool follows a standardized methodology -- clear headers, structured logging, safe defaults, and operational discipline.

---

## OPORD: Mission Statement

This repository is a **Cyber Operations Toolkit** -- a living armory of automation, detection, and response capabilities organized by operational domain. Built from years of real-world enterprise security operations, every script is designed for **immediate deployment** in defended environments.

**Core Tenets:**
- **Standardized methodology** across all languages (PowerShell, Bash, Python)
- **Defensive-first design** -- safe defaults, confirmation gates, clean audit trails
- **Operational readiness** -- every tool tested against production-class environments
- **Knowledge sharing** -- open-source to elevate the community's defensive posture

---

## ORBAT: Order of Battle (Repository Structure)

### SECTOR 1: Cloud Theater Operations

| Unit | AOR (Area of Responsibility) | Strength |
|------|------------------------------|----------|
| [`/AWS/`](AWS/) | Amazon Web Services -- IAM, GuardDuty, CloudTrail, S3, EC2, KMS, VPC security | 50+ scripts |
| [`/Microsoft-Azure/`](Microsoft-Azure/) | Azure -- RBAC, Security Center, Key Vault, NSGs, resource governance | 50+ scripts |
| [`/Microsoft-365/`](Microsoft-365/) | M365 tenant -- Secure Score, compliance, service health, DLP | 50+ scripts |

### SECTOR 2: Identity & Access Operations

| Unit | AOR | Strength |
|------|-----|----------|
| [`/ActiveDirectory/`](ActiveDirectory/) | On-prem AD -- GPO, Kerberos, replication, privileged groups, stale accounts | 50+ scripts |
| [`/Microsoft-Entra/`](Microsoft-Entra/) | Entra ID (Azure AD) -- conditional access, risk signals, identity protection | 50+ scripts |
| [`/Microsoft-Exchange/`](Microsoft-Exchange/) | Exchange Online & on-prem -- mail flow, permissions, DLP, forensic traces | 50+ scripts |

### SECTOR 3: Endpoint Defense & Fleet Operations

| Unit | AOR | Strength |
|------|-----|----------|
| [`/CrowdStrike/`](CrowdStrike/) | Falcon EDR -- detections, containment, IOCs, RTR, sensor health, ZTA | 50+ scripts |
| [`/Jamf/`](Jamf/) | Apple fleet -- compliance, inventory, profiles, MDM, security posture | 50+ scripts |
| [`/Linux/`](Linux/) | Linux hardening -- security audit, firewall, rootkit, SUID, SSH, kernel | 50+ scripts |
| [`/Zscaler/`](Zscaler/) | Zero Trust network -- DLP, policies, traffic, threat analytics, ZPA | 50+ scripts |

### SECTOR 4: Governance, Risk & Compliance (GRC)

| Unit | AOR | Strength |
|------|-----|----------|
| [`/Microsoft-Purview/`](Microsoft-Purview/) | Data governance -- DLP, retention, eDiscovery, sensitivity labels, compliance | 50+ scripts |
| [`/Microsoft-Teams/`](Microsoft-Teams/) | Teams governance -- policies, guest access, channel audit, lifecycle | 50+ scripts |
| [`/Auditing/`](Auditing/) | Cross-platform audit frameworks -- 18 platform full-audit suites | 36+ files |

### SECTOR 5: Support Operations & Sustainment

| Unit | AOR | Strength |
|------|-----|----------|
| [`/PowerShell-Bandaid/`](PowerShell-Bandaid/) | PS environment repair -- module conflicts, gallery fixes, WinRM, profiles | 48+ scripts |
| [`/Custom-Scripts/`](Custom-Scripts/) | Specialized tooling -- M365 deep-dive scripts, XDR monitor, utilities | 300+ scripts |
| [`/Training-Awareness/`](Training-Awareness/) | Security awareness -- phishing, ransomware, social engineering, IR training | 40+ files |

### SECTOR 6: Cyber Weapons Development (Web Applications)

| Unit | AOR | Strength |
|------|-----|----------|
| [`/WebApps/`](WebApps/) | Security web tools -- log analyzer, header scanner, hash lookup, subnet calculator | Active development |

### COMMAND: Planning & Operations

| Unit | Purpose |
|------|---------|
| [`/_NextSteps/`](_NextSteps/) | Future capability roadmap -- planned tools, research areas, expansion targets |
| [`/CONVENTIONS.md`](CONVENTIONS.md) | Coding standards -- standardized headers and patterns for all languages |

---

## TTPs: Technical Standards

### Script Quality Doctrine

Every script in this arsenal follows **standardized conventions** (see [`CONVENTIONS.md`](CONVENTIONS.md)):

- **Standardized header block** -- name, synopsis, description, author, version, date, requirements
- **Structured logging** -- timestamped, leveled (INFO/WARNING/ERROR/SUCCESS), persistent to disk
- **Module dependency management** -- auto-check, auto-install where safe
- **Safe execution** -- confirmation prompts before destructive operations
- **Professional output** -- banner display, progress indicators, summary reports
- **Cross-platform paths** -- Windows (`C:\Scripts\`) and Linux/Mac (`~/Documents/Scripts/`)

### Supported Languages

| Language | Domain | Convention |
|----------|--------|------------|
| **PowerShell** | Windows/M365/Azure/AD administration | `Verb-Noun.ps1` with `CmdletBinding`, comment-based help |
| **Bash** | Linux systems, hardening, network ops | `kebab-case.sh` with `set -euo pipefail`, function-based |
| **Python** | Web apps, API integrations, data tools | `snake_case.py` with docstrings, type hints, `argparse` |

---

## SIGINT: Threat Hunting & IR Capabilities

This arsenal supports **real-world SOC and IR workflows**:

- **Multi-source correlation** -- Sentinel + CrowdStrike + Purview telemetry fusion
- **Identity attack investigation** -- Kerberoasting, password spray, MFA bypass detection
- **Email forensics** -- message trace, forwarding rules, delegate audit, mail flow analysis
- **Endpoint containment** -- CrowdStrike RTR, host isolation, IOC deployment
- **Data exfiltration detection** -- DLP alerts, sharing audit, sensitivity label tracking
- **Compliance response** -- eDiscovery, legal hold, retention, subject rights requests

---

## COMMS: Getting Started

```bash
# Clone the operations repository
git clone https://github.com/Tank23x0/PublicSharing.git
cd PublicSharing

# PowerShell operations (Windows)
.\AWS\Get-AWSCredentialReport.ps1

# Bash operations (Linux/Mac)
chmod +x Linux/security-audit.sh
./Linux/security-audit.sh

# Python web applications
cd WebApps
pip install -r requirements.txt
python app.py
```

### Requirements

- **PowerShell 5.1+** or **PowerShell 7+** (cross-platform)
- **Bash 4.0+** (Linux/macOS)
- **Python 3.9+** with pip (web applications)
- Appropriate administrative/elevated permissions
- Required modules auto-install or prompt on first run

---

## OPSEC: Security Notice

These tools are provided for **authorized security operations only**. Always:

- Review scripts before deploying to production environments
- Test in isolated/non-production environments first
- Ensure proper authorization and change control approval
- Follow your organization's ROE (Rules of Engagement)
- Maintain chain of custody for forensic outputs

---

## PERSEC: Author

**Joe Romaine** -- [JoeRomaine.com](https://JoeRomaine.com)
Security Engineer | Threat Hunter | Blue Team Operator | Pentester

- **20+ years** enterprise systems and security operations
- **Multi-domain expertise** -- SOC, identity, endpoint, cloud, M365, infrastructure
- **AI-augmented security** -- LLM-driven detection, triage acceleration, knowledge synthesis
- **Automation-first** -- PowerShell, Bash, Python across hybrid environments

---

## Contributing

Contributions welcome. Follow the conventions in [`CONVENTIONS.md`](CONVENTIONS.md):

1. Fork the repository
2. Create a feature branch
3. Follow the standardized script format for the target language
4. Submit a pull request with clear description of the capability added

---

## LICENSE

MIT License -- see [LICENSE](LICENSE) for details.

---

*Built for defenders. Shared with the community. Operational at all times.*
