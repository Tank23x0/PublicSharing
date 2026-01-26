# Microsoft 365 Security Audit Guide

## Overview
Guide for auditing Microsoft 365 tenant security including Exchange Online, SharePoint, Teams, and security policies.

## Prerequisites

```powershell
# Install modules
Install-Module ExchangeOnlineManagement -Force
Install-Module Microsoft.Online.SharePoint.PowerShell -Force
Install-Module MicrosoftTeams -Force
Install-Module Microsoft.Graph -Force

# Connect
Connect-ExchangeOnline
Connect-MgGraph -Scopes "Directory.Read.All","SecurityEvents.Read.All"
```

## Key Audit Areas

### 1. Admin Role Audit
```powershell
# List Global Admins
Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'" | 
    Get-MgDirectoryRoleMember

# All admin role assignments
Get-MgDirectoryRole | ForEach-Object {
    $role = $_
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $_.Id
    [PSCustomObject]@{Role=$role.DisplayName; Members=$members.Count}
}
```

### 2. Anti-Phishing Policies
```powershell
Get-AntiPhishPolicy | Select-Object Name, Enabled, EnableMailboxIntelligenceProtection, 
    EnableSpoofIntelligence, PhishThresholdLevel
```

### 3. Anti-Malware Policies
```powershell
Get-MalwareFilterPolicy | Select-Object Name, EnableFileFilter, 
    ZapEnabled, FileTypes
```

### 4. Audit Log Status
```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

### 5. External Sharing
```powershell
# Check mail forwarding rules
Get-TransportRule | Where-Object {$_.RedirectMessageTo -or $_.BlindCopyTo}

# Check user forwarding
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingSmtpAddress}
```

### 6. Secure Score
Access via Microsoft 365 Defender portal: https://security.microsoft.com/securescore

## Compliance Mapping
- SOC 2: CC6.1 (Access Control), CC6.6 (Endpoint Security)
- NIST: AC-2 (Account Management), SI-4 (Monitoring)

## Resources
- [Microsoft 365 Security Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/)
- [Microsoft Secure Score](https://docs.microsoft.com/en-us/microsoft-365/security/defender/microsoft-secure-score)

---
*Version: 2.0.0 | Updated: 2025-01-26*
