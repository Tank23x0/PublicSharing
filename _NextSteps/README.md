# _NextSteps — Future Capability Roadmap

**Author:** Joe Romaine | [JoeRomaine.com](https://JoeRomaine.com)
**Status:** Planning Phase — Items below require manual review and full design before implementation

---

## Purpose

This directory tracks planned additions to the Cyber Operations Arsenal. Each topic folder below represents a capability that should be fully thought through before being built. When ready, create the folder at the appropriate location in the repo and move the planning notes there.

---

## Planned Capability Expansions

### Red Team / Offensive Operations

| Topic | Description | Priority |
|-------|-------------|----------|
| `OSINT-Recon/` | Open-source intelligence gathering tools — domain enumeration, email harvesting, social media footprinting, DNS recon | High |
| `Network-Scanning/` | Automated network discovery and vulnerability scanning wrappers — nmap, masscan, Nessus API integration | High |
| `Password-Auditing/` | Credential strength testing tools — hash cracking orchestration, password policy compliance checking | Medium |
| `Exploit-Frameworks/` | Wrapper scripts for Metasploit, Cobalt Strike, Sliver — engagement automation and reporting | Medium |
| `Wireless-Assessment/` | WiFi security auditing tools — WPA testing, rogue AP detection, Bluetooth scanning | Low |
| `Physical-Security-Tools/` | Badge cloning detection, USB drop monitoring, physical access audit scripts | Low |

### Blue Team / Defensive Enhancements

| Topic | Description | Priority |
|-------|-------------|----------|
| `SIEM-Integrations/` | Sentinel KQL query library, Splunk SPL queries, ElasticSearch detection rules | High |
| `Threat-Intel-Feeds/` | IOC aggregation, STIX/TAXII feed processors, VirusTotal/AbuseIPDB API tools | High |
| `Forensics-Toolkit/` | Memory acquisition, disk imaging, timeline generation, evidence preservation scripts | High |
| `Malware-Analysis/` | Sandbox orchestration, static analysis helpers, YARA rule management | Medium |
| `Deception-Technology/` | Honeypot deployment scripts, canary token generators, decoy credential management | Medium |
| `Network-Defense/` | IDS/IPS rule management, packet capture automation, NetFlow analysis | Medium |

### Web Application Security

| Topic | Description | Priority |
|-------|-------------|----------|
| `WebApp-Scanner/` | Automated web vulnerability scanner — OWASP Top 10 checks, XSS/SQLi detection | High |
| `API-Security-Tester/` | REST/GraphQL API fuzzing, authentication bypass testing, rate limit testing | High |
| `SSL-TLS-Auditor/` | Certificate chain validation, cipher suite analysis, HSTS/CSP header checking | Medium |
| `WAF-Testing/` | Web Application Firewall bypass testing and rule validation tools | Medium |

### Cloud Security Expansion

| Topic | Description | Priority |
|-------|-------------|----------|
| `GCP-Security/` | Google Cloud Platform security scripts — IAM, VPC, GKE, Cloud Armor | Medium |
| `Kubernetes-Security/` | K8s cluster hardening, pod security policies, RBAC audit, image scanning | High |
| `Terraform-Security/` | IaC security scanning, drift detection, compliance-as-code templates | Medium |
| `Container-Security/` | Docker image scanning, runtime monitoring, registry security | Medium |

### Automation & Orchestration

| Topic | Description | Priority |
|-------|-------------|----------|
| `SOAR-Playbooks/` | Security orchestration playbooks — automated IR workflows, enrichment chains | High |
| `CI-CD-Security/` | Pipeline security scanning, secret detection, dependency auditing | Medium |
| `ChatOps-Integration/` | Slack/Teams bot for security alerts, incident commands, SOC notifications | Medium |
| `Reporting-Dashboard/` | Centralized security metrics dashboard — aggregated posture scoring | Medium |

### Training & Simulation

| Topic | Description | Priority |
|-------|-------------|----------|
| `CTF-Challenges/` | Custom Capture The Flag challenges for team training | Medium |
| `Attack-Simulations/` | Atomic Red Team wrappers, MITRE ATT&CK exercise scripts | High |
| `Tabletop-Exercises/` | IR tabletop exercise generators and scoring tools | Low |
| `Lab-Environments/` | Automated lab deployment — vulnerable VMs, AD forests, cloud sandboxes | Medium |

---

## How to Promote a Topic

1. Review the topic description and validate the requirement
2. Design the tool architecture and identify dependencies
3. Create the directory at the appropriate repo location
4. Build following the conventions in [`/CONVENTIONS.md`](/CONVENTIONS.md)
5. Remove the entry from this roadmap once the capability is live

---

## Notes

- Items marked **High** priority align with immediate operational needs
- All tools must follow the standardized coding conventions
- Offensive tools require clear authorization context documentation
- Each new capability should include its own README with usage instructions
