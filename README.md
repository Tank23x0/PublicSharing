# PublicSharing — Security-First Automation & Threat-Hunting Toolkit

A curated, security-first library of **650+ production-ready scripts** and playbooks for **sysadmins, security engineers, and incident responders**. This repo is built for **knowledge-sharing**: clear, auditable automation that helps peers **detect faster, respond smarter, and operate safer** across enterprise environments.

## 🧭 Mission

PublicSharing exists to **share battle-tested automation and threat-hunting building blocks** with the broader IT and security community. Every script is created with a **security-first mindset**, emphasizing least privilege, safe defaults, clear logging, and operational hygiene.

## 🧠 Professional Profile (Quick Highlights)

- **AI Security Threat Hunter** with a strong focus on **telemetry-driven detection, triage efficiency, and operational resilience**.
- **Multi-disciplinary engineer** spanning **security operations, identity, endpoint, cloud, M365, and infrastructure**.
- **20+ years** of Windows Server & enterprise systems management.
- **Automation-first mindset** with deep experience in **PowerShell, Bash, and scheduled task orchestration**.
- Passionate about **LLMs and AI-assisted security workflows**, from **lightweight models on Raspberry Pi** to **frontier models like Opus 4.5**, plus **ClawDBot/MoltBot** and widely adopted open-weight and proprietary model stacks.

## 🔐 Security-First Engineering Philosophy

I build automation that **respects security boundaries and operational reality**:

- **Safe-by-default** operations with confirmations before destructive actions
- **Clean logging** for auditability and incident traceability
- **Module dependency checks** to reduce runtime surprises
- **Compatibility across hybrid environments** (on-prem + cloud)

## 🤖 AI & LLM Passion

I actively integrate **LLMs into security workflows**—from lightweight **local models** to enterprise-grade systems:

- **Model range**: Raspberry Pi–scale local models → frontier-grade platforms (including **Opus 4.5**) 
- **Agents & tooling**: **ClawDBot / MoltBot**, prompt-driven triage accelerators, and knowledge synthesis automation
- **Focus**: **security-first AI**, minimizing hallucination risk through grounding, validation, and deterministic checks

## ⚙️ Automation Before AI (Because Operations Matter)

Long before AI, I built automation that **keeps environments stable and compliant**:

- **PowerShell + Bash** for infra hygiene, fleet compliance, and audit readiness
- **Windows scheduled tasks + Linux cron** for reliable, repeatable ops
- **Environment-aware execution** (dev/test/prod parity, change control, staged rollouts)

## 🧩 Repository Structure (Project Map)

| Folder | Focus Area | Notable Themes |
|--------|------------|----------------|
| `/Microsoft-Exchange/` | Exchange Online & on-prem management | Exchange backend health, mailbox hygiene, transport rules |
| `/Microsoft-Azure/` | Azure security & resource management | RBAC, subscriptions, compliance, cost-aware governance |
| `/Microsoft-Entra/` | Identity & access (Azure AD) | Identity lifecycle, risk signals, conditional access |
| `/Microsoft-Purview/` | Data governance & compliance | DLP, retention, audit, eDiscovery workflows |
| `/Microsoft-Teams/` | Teams administration & auditing | Governance, audits, lifecycle management |
| `/Microsoft-365/` | M365 tenant management | Secure Score, tenant posture, service hardening |
| `/CrowdStrike/` | EDR management & threat hunting | Falcon ops, detection tuning, response ops |
| `/AWS/` | AWS security & administration | IAM, security services, guardrails |
| `/Linux/` | System administration & hardening | Baselines, patching, hardening checks |
| `/ActiveDirectory/` | On-prem AD management | GPO hardening, identity cleanup, auditing |
| `/Zscaler/` | Zero trust network security | Policy management, reporting, hygiene |
| `/Jamf/` | Apple device management | Compliance, inventory, security posture |
| `/PowerShell-Bandaid/` | Module mgmt & troubleshooting | Reliability tooling, diagnostic helpers |
| `/Custom-Scripts/` | Legacy & miscellaneous | Specialized utilities and edge cases |

## 🧪 Threat Hunting & Incident Response Focus

This repo supports **real-world IR and SOC workflows**, including:

- **Sentinel + CrowdStrike cohesion** for multi-source correlation and containment
- **Incident response building blocks** (host triage, log capture, containment prep)
- **Exchange & identity investigations** with fast scoping and audit-ready outputs
- **Purview + compliance automation** for legal and data governance workflows

## ✨ Script Quality Standards

Every script in this library includes:

- **Professional headers** with name, description, author, version, and date
- **Detailed comments** explaining each section
- **User confirmation prompts** before destructive operations
- **Progress indicators** for long-running tasks
- **Comprehensive logging** (Windows: `C:\Scripts\`, Mac/Linux: `~/Documents/Scripts/`)
- **Module dependency checks** with automatic installation
- **Clean, professional output** formatting

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Anessen/PublicSharing.git
   ```

2. Navigate to the desired category folder

3. Review the script header and requirements

4. Run with appropriate permissions:
   ```powershell
   # PowerShell (Windows)
   .\ScriptName.ps1
   
   # Bash (Linux/Mac)
   chmod +x script-name.sh
   ./script-name.sh
   ```

## 📋 Requirements

- **PowerShell 5.1+** or **PowerShell 7+** for Windows scripts
- **Bash 4.0+** for Linux/Mac scripts
- **Python 3.8+** for Python scripts
- Appropriate admin/elevated permissions
- Required modules (installed automatically or prompted)

## 🔒 Security Note

These scripts are provided for **legitimate administrative purposes only**. Always:

- Review scripts before running in production
- Test in a non-production environment first
- Ensure you have proper authorization
- Follow your organization's change management process

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Anessen** — Security Engineer, Threat Hunter, and Systems Automation Practitioner

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the existing script format
4. Submit a pull request

---

*Built with ❤️ for the IT community*
