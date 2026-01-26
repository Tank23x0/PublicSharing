# Microsoft Teams Security Audit Guide

## Connection
```powershell
Install-Module MicrosoftTeams -Force
Connect-MicrosoftTeams
```

## Key Audit Commands

### Guest & External Access
```powershell
Get-CsTeamsClientConfiguration | Select-Object AllowGuestUser
Get-CsTenantFederationConfiguration | Select-Object AllowFederatedUsers, AllowedDomains
```

### Meeting Policies
```powershell
Get-CsTeamsMeetingPolicy | Select-Object Identity, AllowAnonymousUsersToJoinMeeting, 
    AutoAdmittedUsers, AllowExternalParticipantGiveRequestControl
```

### Messaging Policies
```powershell
Get-CsTeamsMessagingPolicy | Select-Object Identity, AllowUrlPreviews, 
    AllowUserEditMessage, AllowUserDeleteMessage
```

### Teams & Channels
```powershell
Get-Team | Select-Object DisplayName, Visibility, MailNickName
Get-Team | ForEach-Object { Get-TeamChannel -GroupId $_.GroupId }
```

### App Policies
```powershell
Get-CsTeamsAppPermissionPolicy | Select-Object Identity, DefaultCatalogApps, 
    GlobalCatalogApps, PrivateCatalogApps
```

## Security Checklist
- [ ] Guest access configured appropriately
- [ ] External federation restricted
- [ ] Anonymous meeting join disabled
- [ ] Lobby settings enforced
- [ ] App permissions reviewed

## Resources
- [Teams Security](https://docs.microsoft.com/en-us/microsoftteams/security-compliance-overview)
- [Teams Policies](https://docs.microsoft.com/en-us/microsoftteams/assign-policies)

---
*Version: 2.0.0 | Updated: 2025-01-26*
