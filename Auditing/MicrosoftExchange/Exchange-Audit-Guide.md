# Microsoft Exchange Online Security Audit Guide

## Quick Reference

### Connection
```powershell
Install-Module ExchangeOnlineManagement -Force
Connect-ExchangeOnline
```

### Key Audit Commands

#### Mail Forwarding
```powershell
# Mailbox forwarding
Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingSmtpAddress} | 
    Select-Object DisplayName, ForwardingSmtpAddress

# Inbox rules with forwarding
Get-Mailbox | ForEach-Object {
    Get-InboxRule -Mailbox $_.UserPrincipalName | 
        Where-Object {$_.ForwardTo -or $_.RedirectTo}
}
```

#### Transport Rules
```powershell
Get-TransportRule | Select-Object Name, State, Priority
```

#### Anti-Spam/Phishing
```powershell
Get-HostedContentFilterPolicy | Select-Object Name, BulkThreshold, SpamAction
Get-AntiPhishPolicy | Select-Object Name, Enabled, PhishThresholdLevel
Get-MalwareFilterPolicy | Select-Object Name, EnableFileFilter
```

#### Email Authentication
```powershell
# DKIM
Get-DkimSigningConfig | Select-Object Domain, Enabled

# DMARC (check DNS)
Resolve-DnsName -Name "_dmarc.yourdomain.com" -Type TXT
```

#### Audit Logging
```powershell
Get-AdminAuditLogConfig | Select-Object UnifiedAuditLogIngestionEnabled
```

#### Permissions
```powershell
# Mailbox permissions
Get-MailboxPermission -Identity user@domain.com | Where-Object {$_.User -ne "NT AUTHORITY\SELF"}

# Calendar permissions
Get-MailboxFolderPermission -Identity user@domain.com:\Calendar
```

## Security Checklist
- [ ] Unified audit logging enabled
- [ ] DKIM enabled for all domains
- [ ] DMARC policy configured
- [ ] No unauthorized forwarding rules
- [ ] Anti-phishing policies configured
- [ ] Safe Links/Attachments enabled

## Resources
- [Exchange Online Protection](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/)
- [Email Authentication](https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/email-validation-and-authentication)

---
*Version: 2.0.0 | Updated: 2025-01-26*
