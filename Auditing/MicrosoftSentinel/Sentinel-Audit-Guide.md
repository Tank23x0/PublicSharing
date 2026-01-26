# Microsoft Sentinel Security Audit Guide

## Connection
```powershell
Install-Module Az.SecurityInsights -Force
Connect-AzAccount
Set-AzContext -SubscriptionId "your-subscription-id"
```

## Key Audit Commands

### Analytics Rules
```powershell
Get-AzSentinelAlertRule -ResourceGroupName "RG" -WorkspaceName "WS" | 
    Select-Object DisplayName, Enabled, Severity, QueryFrequency
```

### Data Connectors
```powershell
Get-AzSentinelDataConnector -ResourceGroupName "RG" -WorkspaceName "WS" |
    Select-Object Name, Kind
```

### Incidents
```powershell
Get-AzSentinelIncident -ResourceGroupName "RG" -WorkspaceName "WS" |
    Where-Object {$_.Status -ne "Closed"} |
    Select-Object Title, Severity, Status, CreatedTimeUtc
```

### Watchlists
```powershell
Get-AzSentinelWatchlist -ResourceGroupName "RG" -WorkspaceName "WS"
```

### Automation Rules
```powershell
Get-AzSentinelAutomationRule -ResourceGroupName "RG" -WorkspaceName "WS"
```

## Security Checklist
- [ ] Critical data connectors enabled (Azure AD, M365, Defender)
- [ ] Analytics rules enabled (50+ recommended)
- [ ] Automation rules for auto-assignment
- [ ] Open incidents being triaged
- [ ] Workbooks configured for visibility

## Resources
- [Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [Sentinel Content Hub](https://docs.microsoft.com/en-us/azure/sentinel/sentinel-solutions-catalog)

---
*Version: 2.0.0 | Updated: 2025-01-26*
