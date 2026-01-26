# Security Auditing Toolkit

Comprehensive security audit scripts and documentation for 18 major platforms.

## Platforms Covered

| Platform | Script | Guide |
|----------|--------|-------|
| AWS | `AWS/AWS-Full-Audit.ps1` | `AWS/AWS-Audit-Guide.md` |
| Active Directory | `ActiveDirectory/AD-Full-Audit.ps1` | `ActiveDirectory/AD-Audit-Guide.md` |
| Azure | `Azure/Azure-Full-Audit.ps1` | `Azure/Azure-Audit-Guide.md` |
| CrowdStrike | `CrowdStrike/CrowdStrike-Full-Audit.ps1` | `CrowdStrike/CrowdStrike-Audit-Guide.md` |
| Entra ID (Azure AD) | `EntraID/EntraID-Full-Audit.ps1` | `EntraID/EntraID-Audit-Guide.md` |
| GitHub Enterprise | `GitHubEnterprise/GitHub-Full-Audit.ps1` | `GitHubEnterprise/GitHub-Audit-Guide.md` |
| Jamf | `Jamf/Jamf-Full-Audit.ps1` | `Jamf/Jamf-Audit-Guide.md` |
| Linux | `Linux/Linux-Full-Audit.sh` | `Linux/Linux-Audit-Guide.md` |
| Microsoft 365 | `Microsoft365/M365-Full-Audit.ps1` | `Microsoft365/M365-Audit-Guide.md` |
| Microsoft Exchange | `MicrosoftExchange/Exchange-Full-Audit.ps1` | `MicrosoftExchange/Exchange-Audit-Guide.md` |
| Microsoft Purview | `MicrosoftPurview/Purview-Full-Audit.ps1` | `MicrosoftPurview/Purview-Audit-Guide.md` |
| Microsoft Sentinel | `MicrosoftSentinel/Sentinel-Full-Audit.ps1` | `MicrosoftSentinel/Sentinel-Audit-Guide.md` |
| Microsoft SharePoint | `MicrosoftSharePoint/SharePoint-Full-Audit.ps1` | `MicrosoftSharePoint/SharePoint-Audit-Guide.md` |
| Microsoft Teams | `MicrosoftTeams/Teams-Full-Audit.ps1` | `MicrosoftTeams/Teams-Audit-Guide.md` |
| Oracle Cloud (OCI) | `OracleCloudInfrastructure/OCI-Full-Audit.sh` | `OracleCloudInfrastructure/OCI-Audit-Guide.md` |
| Salesforce | `Salesforce/Salesforce-Full-Audit.ps1` | `Salesforce/Salesforce-Audit-Guide.md` |
| Snowflake | `Snowflake/Snowflake-Full-Audit.sql` | `Snowflake/Snowflake-Audit-Guide.md` |
| Zscaler | `Zscaler/Zscaler-Full-Audit.ps1` | `Zscaler/Zscaler-Audit-Guide.md` |

## Features

### Scripts Include:
- 🔍 User/account last activity (90-day stale check)
- 🔑 Password age & last set date
- 🗝️ API keys / service principals audit
- 👑 Privileged access / admin role audits
- 🔐 MFA status & gaps
- ⚠️ Login anomalies & failed attempts
- 📋 Resource permissions & access reviews
- ✅ Compliance gaps & policy violations

### Documentation Includes:
- Manual retrieval steps
- Official platform documentation links
- API endpoints and methods
- Common audit queries
- Compliance framework mapping (SOC2, ISO27001, NIST, CIS)

## Usage

### PowerShell Scripts
```powershell
# Example: AWS Audit
.\AWS\AWS-Full-Audit.ps1 -ProfileName "production" -AuditEntireOrganization

# Example: Active Directory Audit
.\ActiveDirectory\AD-Full-Audit.ps1 -StaleThresholdDays 90 -ExportToCSV

# Example: Azure Audit
.\Azure\Azure-Full-Audit.ps1 -AllSubscriptions
```

### Bash Scripts
```bash
# Linux Audit
chmod +x Linux/Linux-Full-Audit.sh
sudo ./Linux/Linux-Full-Audit.sh -d 90

# OCI Audit
chmod +x OracleCloudInfrastructure/OCI-Full-Audit.sh
./OracleCloudInfrastructure/OCI-Full-Audit.sh
```

### SQL Scripts
```sql
-- Snowflake Audit
-- Run queries from Snowflake/Snowflake-Full-Audit.sql using ACCOUNTADMIN role
```

## Output

All scripts generate:
- **HTML Report** - Visual summary with findings
- **Log File** - Detailed execution log
- **CSV Export** (optional) - Raw findings data

Default output locations:
- Windows: `%USERPROFILE%\Documents\Scripts\<Platform>-Audit\`
- macOS/Linux: `~/Documents/Scripts/<Platform>-Audit/`

## Compliance Coverage

Scripts map to major compliance frameworks:
- SOC 2 Type II
- ISO 27001
- NIST Cybersecurity Framework
- NIST 800-53
- CIS Benchmarks
- HIPAA
- PCI DSS

## Requirements

### General
- PowerShell 5.1+ (PowerShell 7 recommended)
- Platform-specific CLI tools or modules

### Platform-Specific
See individual guide files for detailed prerequisites.

## Contributing

1. Scripts follow consistent patterns for logging and reporting
2. All findings include severity, description, and recommendation
3. Documentation includes manual steps for validation

## Disclaimer

These scripts are provided for security auditing purposes. Always:
- Test in non-production environments first
- Review scripts before execution
- Ensure appropriate permissions
- Follow your organization's change management process

---

**Version:** 2.0.0  
**Last Updated:** 2025-01-26
