# SharePoint Online Security Audit Guide

## Connection
```powershell
Install-Module Microsoft.Online.SharePoint.PowerShell -Force
Connect-SPOService -Url https://tenant-admin.sharepoint.com
```

## Key Audit Commands

### Tenant Settings
```powershell
Get-SPOTenant | Select-Object SharingCapability, LegacyAuthProtocolsEnabled, 
    PreventExternalUsersFromResharing, DefaultSharingLinkType
```

### Site Collections
```powershell
Get-SPOSite -Limit All | Select-Object Url, SharingCapability, Owner, StorageQuota
```

### External Sharing
```powershell
# Check external users
Get-SPOExternalUser -PageSize 50

# Check sharing links
Get-SPOSite | ForEach-Object { Get-SPOSiteSharingPolicy -Identity $_.Url }
```

### Site Permissions
```powershell
# Using PnP PowerShell (Install-Module PnP.PowerShell)
Connect-PnPOnline -Url "https://tenant.sharepoint.com/sites/sitename" -Interactive
Get-PnPSiteCollectionAdmin
Get-PnPGroup | Get-PnPGroupMembers
```

## Security Checklist
- [ ] External sharing restricted appropriately
- [ ] Legacy auth disabled
- [ ] Anonymous links disabled or time-limited
- [ ] Site owners trained on sharing
- [ ] Regular external user access review

## Resources
- [SharePoint Security](https://docs.microsoft.com/en-us/sharepoint/security-for-sharepoint-online)
- [Sharing Settings](https://docs.microsoft.com/en-us/sharepoint/turn-external-sharing-on-or-off)

---
*Version: 2.0.0 | Updated: 2025-01-26*
