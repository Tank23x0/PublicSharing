# Microsoft Purview Security Audit Guide

## Connection
```powershell
Install-Module ExchangeOnlineManagement -Force
Connect-IPPSSession  # Security & Compliance PowerShell
```

## Key Audit Commands

### DLP Policies
```powershell
Get-DlpCompliancePolicy | Select-Object Name, Mode, Workload
Get-DlpComplianceRule | Select-Object Name, ParentPolicyName, Disabled
```

### Sensitivity Labels
```powershell
Get-Label | Select-Object Name, Priority, ContentType
Get-LabelPolicy | Select-Object Name, Labels, Enabled
```

### Retention Policies
```powershell
Get-RetentionCompliancePolicy | Select-Object Name, Enabled, Workload
Get-RetentionComplianceRule | Select-Object Name, RetentionDuration
```

### eDiscovery Cases
```powershell
Get-ComplianceCase | Select-Object Name, Status, CaseType
```

### Alert Policies
```powershell
Get-ProtectionAlert | Select-Object Name, Category, Severity, Disabled
```

### Audit Log
```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
Search-UnifiedAuditLog -StartDate (Get-Date).AddDays(-7) -EndDate (Get-Date) -RecordType ExchangeAdmin
```

## Security Checklist
- [ ] DLP policies for PII, financial data, health info
- [ ] Sensitivity labels published
- [ ] Retention policies configured
- [ ] Unified audit logging enabled
- [ ] Alert policies active

## Resources
- [Microsoft Purview Documentation](https://docs.microsoft.com/en-us/microsoft-365/compliance/)
- [DLP Policy Templates](https://docs.microsoft.com/en-us/microsoft-365/compliance/dlp-policy-reference)

---
*Version: 2.0.0 | Updated: 2025-01-26*
