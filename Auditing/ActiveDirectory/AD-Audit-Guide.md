# Active Directory Security Audit Guide

## Overview

This guide covers comprehensive security auditing for Active Directory environments, including user accounts, privileged access, password policies, Kerberos security, and Group Policy.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [User Account Audit](#user-account-audit)
3. [Privileged Group Audit](#privileged-group-audit)
4. [Password Policy Audit](#password-policy-audit)
5. [Service Account Audit](#service-account-audit)
6. [Computer Account Audit](#computer-account-audit)
7. [Kerberos Security Audit](#kerberos-security-audit)
8. [Group Policy Audit](#group-policy-audit)
9. [Trust Relationship Audit](#trust-relationship-audit)
10. [Domain Controller Audit](#domain-controller-audit)
11. [Common Attack Detection](#common-attack-detection)
12. [PowerShell Commands Reference](#powershell-commands-reference)
13. [API and LDAP Reference](#api-and-ldap-reference)
14. [Compliance Mapping](#compliance-mapping)
15. [Resources](#resources)

---

## Prerequisites

### Required Tools

```powershell
# Install RSAT (Remote Server Administration Tools) on Windows 10/11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0

# Or install all RSAT tools
Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online

# Verify module installation
Get-Module -ListAvailable ActiveDirectory
Import-Module ActiveDirectory
```

### Required Permissions

Minimum permissions for comprehensive auditing:
- **Read-only Domain Admin** or
- **Account Operators** + **Read access to Configuration partition**
- For GPO audit: **Group Policy Read** permissions

Recommended: Use a dedicated audit service account with read-only permissions.

---

## User Account Audit

### Manual Steps (ADUC)

1. **Open**: Active Directory Users and Computers
2. **View**: Enable Advanced Features (View → Advanced Features)
3. **Filter**: Create custom query for stale accounts
4. **Export**: Right-click domain → Export List

### PowerShell Commands

```powershell
# Get all users with key properties
Get-ADUser -Filter * -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, 
    PasswordNotRequired, Enabled, LockedOut, WhenCreated, Description, MemberOf |
    Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet, 
    PasswordNeverExpires, WhenCreated

# Find users who haven't logged in for 90+ days
$threshold = (Get-Date).AddDays(-90)
Get-ADUser -Filter {LastLogonDate -lt $threshold -and Enabled -eq $true} -Properties LastLogonDate |
    Select-Object SamAccountName, LastLogonDate |
    Sort-Object LastLogonDate

# Find users who have NEVER logged in
Get-ADUser -Filter {LastLogonDate -notlike "*" -and Enabled -eq $true} -Properties WhenCreated |
    Select-Object SamAccountName, WhenCreated

# Find disabled accounts
Get-ADUser -Filter {Enabled -eq $false} | Select-Object SamAccountName

# Find locked out accounts
Search-ADAccount -LockedOut | Select-Object SamAccountName, LockedOut, LastLogonDate

# Find accounts with password never expires
Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} |
    Select-Object SamAccountName

# Find accounts with password not required (CRITICAL)
Get-ADUser -Filter {PasswordNotRequired -eq $true -and Enabled -eq $true} |
    Select-Object SamAccountName

# Find accounts expiring soon
Search-ADAccount -AccountExpiring -TimeSpan "30.00:00:00" |
    Select-Object SamAccountName, AccountExpirationDate

# Find recently created accounts (last 30 days)
$created = (Get-Date).AddDays(-30)
Get-ADUser -Filter {WhenCreated -gt $created} -Properties WhenCreated |
    Select-Object SamAccountName, WhenCreated
```

### LDAP Queries

```ldap
# Users not logged in for 90 days (convert date to LDAP timestamp)
(&(objectCategory=person)(objectClass=user)(lastLogonTimestamp<=132123456789012345)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))

# Disabled accounts
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))

# Password never expires
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))

# Password not required
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
```

---

## Privileged Group Audit

### Critical Groups to Monitor

| Group | Risk Level | Notes |
|-------|------------|-------|
| Domain Admins | Critical | Full domain control |
| Enterprise Admins | Critical | Forest-wide control |
| Schema Admins | Critical | Can modify AD schema |
| Administrators | Critical | Built-in admin group |
| Account Operators | High | Can modify most accounts |
| Backup Operators | High | Can backup/restore files |
| Server Operators | High | DC administration |
| DnsAdmins | High | Can execute code as SYSTEM |
| Group Policy Creator Owners | High | Can create GPOs |
| Print Operators | Medium | Legacy privileged group |

### PowerShell Commands

```powershell
# List members of Domain Admins
Get-ADGroupMember -Identity "Domain Admins" -Recursive | 
    Get-ADUser -Properties LastLogonDate, PasswordLastSet, Enabled |
    Select-Object SamAccountName, Enabled, LastLogonDate, PasswordLastSet

# List ALL privileged group memberships
$groups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", 
            "Account Operators", "Backup Operators", "Server Operators")
foreach ($group in $groups) {
    Write-Host "`n=== $group ===" -ForegroundColor Cyan
    Get-ADGroupMember -Identity $group -Recursive -ErrorAction SilentlyContinue |
        Select-Object Name, SamAccountName, ObjectClass
}

# Find nested group memberships
Get-ADGroupMember -Identity "Domain Admins" | 
    Where-Object {$_.objectClass -eq "group"} |
    ForEach-Object { 
        Write-Host "Nested Group: $($_.Name)"
        Get-ADGroupMember -Identity $_.DistinguishedName -Recursive
    }

# Find users with AdminCount=1 (was/is protected)
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf |
    Select-Object SamAccountName, AdminCount

# Count members in each privileged group
$groups | ForEach-Object {
    $count = (Get-ADGroupMember -Identity $_ -Recursive -ErrorAction SilentlyContinue | Measure-Object).Count
    [PSCustomObject]@{Group=$_; Members=$count}
} | Format-Table
```

### Manual Verification (ADUC)

1. Navigate to **Users** container or **Builtin** container
2. Right-click each privileged group → **Properties** → **Members**
3. Document all members including nested groups
4. Check **Member Of** tab for group nesting

---

## Password Policy Audit

### PowerShell Commands

```powershell
# Get Default Domain Password Policy
Get-ADDefaultDomainPasswordPolicy

# Get detailed password policy
Get-ADDefaultDomainPasswordPolicy | Select-Object *

# Get Fine-Grained Password Policies
Get-ADFineGrainedPasswordPolicy -Filter *

# Get FGPP with applied targets
Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
    $policy = $_
    $applied = Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name
    [PSCustomObject]@{
        Name = $policy.Name
        Precedence = $policy.Precedence
        MinLength = $policy.MinPasswordLength
        MaxAge = $policy.MaxPasswordAge
        AppliedTo = ($applied.Name -join ", ")
    }
}

# Check specific user's effective password policy
Get-ADUserResultantPasswordPolicy -Identity "username"
```

### Recommended Settings

| Setting | Minimum Recommendation | Best Practice |
|---------|------------------------|---------------|
| Min Password Length | 12 characters | 14+ characters |
| Password History | 12 passwords | 24 passwords |
| Max Password Age | 90 days | 60-90 days |
| Min Password Age | 1 day | 1 day |
| Complexity | Enabled | Enabled |
| Lockout Threshold | 5-10 attempts | 5 attempts |
| Lockout Duration | 15-30 minutes | 30 minutes |
| Lockout Counter Reset | 15-30 minutes | 30 minutes |

### Manual Steps (GPMC)

1. Open **Group Policy Management Console**
2. Navigate to: Forest → Domains → [Domain] → Default Domain Policy
3. Right-click → **Edit**
4. Navigate: Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies
5. Review **Password Policy** and **Account Lockout Policy**

---

## Service Account Audit

### Identifying Service Accounts

```powershell
# Find accounts with Service Principal Names (SPNs) - service accounts
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, 
    PasswordLastSet, PasswordNeverExpires, TrustedForDelegation |
    Select-Object SamAccountName, ServicePrincipalName, PasswordLastSet, 
    PasswordNeverExpires, TrustedForDelegation

# List all SPNs in domain
Get-ADObject -Filter {servicePrincipalName -like "*"} -Properties servicePrincipalName |
    Select-Object Name, @{N='SPNs';E={$_.servicePrincipalName -join "; "}}

# Find Managed Service Accounts (MSAs)
Get-ADServiceAccount -Filter * -Properties PasswordLastSet, PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object Name, PasswordLastSet, PrincipalsAllowedToRetrieveManagedPassword

# Find Group Managed Service Accounts (gMSAs)
Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} |
    Select-Object Name, DNSHostName
```

### Service Account Security Checks

```powershell
# Kerberoastable accounts (accounts with SPNs)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName |
    Select-Object SamAccountName, ServicePrincipalName

# Service accounts with old passwords (>365 days)
$threshold = (Get-Date).AddDays(-365)
Get-ADUser -Filter {ServicePrincipalName -like "*" -and PasswordLastSet -lt $threshold} `
    -Properties PasswordLastSet, ServicePrincipalName |
    Select-Object SamAccountName, PasswordLastSet

# Service accounts with unconstrained delegation (CRITICAL)
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object SamAccountName, TrustedForDelegation

# Service accounts in admin groups
$adminGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
foreach ($group in $adminGroups) {
    $members = Get-ADGroupMember -Identity $group -Recursive | 
        Where-Object {$_.objectClass -eq "user"}
    foreach ($member in $members) {
        $user = Get-ADUser -Identity $member -Properties ServicePrincipalName
        if ($user.ServicePrincipalName) {
            Write-Host "WARNING: Service account $($user.SamAccountName) is in $group"
        }
    }
}
```

---

## Computer Account Audit

### PowerShell Commands

```powershell
# Get all computers
Get-ADComputer -Filter * -Properties LastLogonDate, OperatingSystem, PasswordLastSet |
    Select-Object Name, OperatingSystem, LastLogonDate, PasswordLastSet

# Find stale computers (no login in 90 days)
$threshold = (Get-Date).AddDays(-90)
Get-ADComputer -Filter {LastLogonDate -lt $threshold} -Properties LastLogonDate, OperatingSystem |
    Select-Object Name, OperatingSystem, LastLogonDate

# Find computers running old OS
Get-ADComputer -Filter {OperatingSystem -like "*2008*" -or OperatingSystem -like "*2003*" -or 
    OperatingSystem -like "*XP*" -or OperatingSystem -like "*Windows 7*"} `
    -Properties OperatingSystem |
    Select-Object Name, OperatingSystem

# Computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation |
    Select-Object Name, TrustedForDelegation

# Domain Controllers
Get-ADDomainController -Filter * | 
    Select-Object Name, IPv4Address, OperatingSystem, IsGlobalCatalog
```

---

## Kerberos Security Audit

### Key Areas

1. **krbtgt Account** - Key to golden ticket attacks
2. **Delegation Settings** - Unconstrained, constrained, resource-based
3. **Encryption Types** - AES vs RC4/DES
4. **SPN Configuration** - Kerberoasting targets

### PowerShell Commands

```powershell
# Check krbtgt password age (should rotate every 180 days)
$krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet
$age = (Get-Date) - $krbtgt.PasswordLastSet
Write-Host "krbtgt password age: $($age.Days) days"

# Accounts with Kerberos pre-auth disabled (AS-REP roastable)
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, DoesNotRequirePreAuth

# Accounts using DES encryption (weak)
Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly |
    Select-Object SamAccountName, UseDESKeyOnly

# Accounts with constrained delegation
Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} `
    -Properties msDS-AllowedToDelegateTo, TrustedToAuthForDelegation |
    Select-Object SamAccountName, @{N='DelegateTo';E={$_.'msDS-AllowedToDelegateTo' -join "; "}}, 
    TrustedToAuthForDelegation

# Accounts with protocol transition (S4U2Self)
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} |
    Select-Object SamAccountName

# All SPNs (Kerberoasting targets)
Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
    Select-Object SamAccountName, @{N='SPNs';E={$_.ServicePrincipalName -join "; "}}
```

### krbtgt Password Rotation

```powershell
# WARNING: This will impact Kerberos authentication
# Rotate krbtgt password (do this TWICE with replication time between)

# First rotation
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "ComplexPassword123!" -Force)

# Wait for replication (check replication status)
repadmin /replsummary

# Second rotation (after full replication)
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "AnotherComplexPassword456!" -Force)
```

---

## Group Policy Audit

### PowerShell Commands

```powershell
# Import GroupPolicy module
Import-Module GroupPolicy

# List all GPOs
Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime

# Get GPO details including links
Get-GPO -All | ForEach-Object {
    $report = [xml](Get-GPOReport -Guid $_.Id -ReportType Xml)
    [PSCustomObject]@{
        Name = $_.DisplayName
        Created = $_.CreationTime
        Modified = $_.ModificationTime
        LinksTo = ($report.GPO.LinksTo.SOMPath -join "; ")
        Status = $_.GpoStatus
    }
}

# Find unlinked GPOs
Get-GPO -All | ForEach-Object {
    $report = [xml](Get-GPOReport -Guid $_.Id -ReportType Xml)
    if (-not $report.GPO.LinksTo) {
        Write-Host "Unlinked: $($_.DisplayName)"
    }
}

# Check for GPP Passwords (MS14-025 - CRITICAL)
$gpos = Get-GPO -All
foreach ($gpo in $gpos) {
    $report = Get-GPOReport -Guid $gpo.Id -ReportType Xml
    if ($report -match "cpassword") {
        Write-Host "WARNING: GPO '$($gpo.DisplayName)' contains GPP password!" -ForegroundColor Red
    }
}

# Get GPO settings as HTML report
Get-GPO -All | ForEach-Object {
    Get-GPOReport -Guid $_.Id -ReportType Html -Path "C:\GPOReports\$($_.DisplayName).html"
}
```

### Manual Steps (GPMC)

1. Open **Group Policy Management Console**
2. Navigate domain structure to see all GPOs
3. Right-click each GPO → **Settings** to view configuration
4. Check **Delegation** tab for permissions
5. Run **Group Policy Results** for specific users/computers

---

## Trust Relationship Audit

### PowerShell Commands

```powershell
# List all trusts
Get-ADTrust -Filter * | Select-Object Name, Direction, TrustType, 
    SelectiveAuthentication, SIDFilteringQuarantined

# Get detailed trust info
Get-ADTrust -Filter * | ForEach-Object {
    [PSCustomObject]@{
        Name = $_.Name
        Direction = $_.Direction
        TrustType = $_.TrustType
        SelectiveAuth = $_.SelectiveAuthentication
        SIDFiltering = $_.SIDFilteringQuarantined
        ForestTransitive = $_.ForestTransitive
        IntraForest = $_.IntraForest
    }
}

# Verify trust (requires both domains accessible)
Test-ComputerSecureChannel -Server "TrustedDomain.com"

# Using netdom
netdom trust <TrustingDomain> /d:<TrustedDomain> /verify
```

### Trust Security Checklist

- [ ] External trusts have SID filtering enabled
- [ ] Selective authentication used where possible
- [ ] Forest trusts properly scoped
- [ ] Trust direction is appropriate (one-way vs two-way)
- [ ] Regular trust review documented

---

## Domain Controller Audit

### PowerShell Commands

```powershell
# List all DCs
Get-ADDomainController -Filter * | 
    Select-Object Name, IPv4Address, Site, OperatingSystem, IsGlobalCatalog, IsReadOnly

# Check DC health
Get-ADDomainController -Filter * | ForEach-Object {
    $dc = $_
    $repl = Get-ADReplicationFailure -Target $dc.HostName -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Name = $dc.Name
        OS = $dc.OperatingSystem
        Site = $dc.Site
        GC = $dc.IsGlobalCatalog
        ReplFailures = ($repl | Measure-Object).Count
    }
}

# Check replication status
repadmin /replsummary

# Check SYSVOL replication
Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" | Measure-Object

# Check DC time sync
w32tm /monitor /domain:$env:USERDNSDOMAIN
```

---

## Common Attack Detection

### Kerberoasting Indicators

```powershell
# Accounts vulnerable to Kerberoasting
Get-ADUser -Filter {ServicePrincipalName -like "*" -and Enabled -eq $true} `
    -Properties ServicePrincipalName, PasswordLastSet |
    Where-Object {$_.PasswordLastSet -lt (Get-Date).AddYears(-1)} |
    Select-Object SamAccountName, PasswordLastSet, ServicePrincipalName
```

### AS-REP Roasting Indicators

```powershell
# Accounts with pre-auth disabled
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true -and Enabled -eq $true} |
    Select-Object SamAccountName
```

### Golden Ticket Indicators

```powershell
# Check krbtgt password age
$krbtgt = Get-ADUser -Identity krbtgt -Properties PasswordLastSet
"krbtgt Password Last Set: $($krbtgt.PasswordLastSet)"
"Days Since Reset: $([int]((Get-Date) - $krbtgt.PasswordLastSet).TotalDays)"
```

### DCSync Attack Surface

```powershell
# Users with replication rights
$domain = Get-ADDomain
$domainDN = $domain.DistinguishedName
$acl = Get-Acl "AD:\$domainDN"
$acl.Access | Where-Object {
    $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or  # DS-Replication-Get-Changes
    $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"     # DS-Replication-Get-Changes-All
} | Select-Object IdentityReference, ActiveDirectoryRights
```

---

## PowerShell Commands Reference

### Quick Reference Table

| Task | Command |
|------|---------|
| All users | `Get-ADUser -Filter *` |
| Enabled users | `Get-ADUser -Filter {Enabled -eq $true}` |
| Disabled users | `Get-ADUser -Filter {Enabled -eq $false}` |
| Locked accounts | `Search-ADAccount -LockedOut` |
| Password expired | `Search-ADAccount -PasswordExpired` |
| Password never expires | `Get-ADUser -Filter {PasswordNeverExpires -eq $true}` |
| Domain Admins | `Get-ADGroupMember "Domain Admins" -Recursive` |
| All computers | `Get-ADComputer -Filter *` |
| All DCs | `Get-ADDomainController -Filter *` |
| Password policy | `Get-ADDefaultDomainPasswordPolicy` |
| All GPOs | `Get-GPO -All` |
| All trusts | `Get-ADTrust -Filter *` |
| krbtgt info | `Get-ADUser krbtgt -Properties *` |

---

## API and LDAP Reference

### LDAP Attribute Reference

| Attribute | Description |
|-----------|-------------|
| `lastLogonTimestamp` | Last logon (replicated) |
| `lastLogon` | Last logon (per-DC, not replicated) |
| `pwdLastSet` | Password last changed |
| `userAccountControl` | Account flags (bitmap) |
| `adminCount` | Protected by AdminSDHolder |
| `servicePrincipalName` | Kerberos SPNs |
| `msDS-AllowedToDelegateTo` | Constrained delegation targets |
| `memberOf` | Group memberships |
| `whenCreated` | Account creation date |
| `whenChanged` | Last modification date |

### UserAccountControl Flags

| Flag | Value | Description |
|------|-------|-------------|
| ACCOUNTDISABLE | 0x0002 | Account is disabled |
| PASSWD_NOTREQD | 0x0020 | Password not required |
| PASSWD_CANT_CHANGE | 0x0040 | User cannot change password |
| ENCRYPTED_TEXT_PWD_ALLOWED | 0x0080 | Reversible encryption |
| DONT_EXPIRE_PASSWORD | 0x10000 | Password never expires |
| TRUSTED_FOR_DELEGATION | 0x80000 | Unconstrained delegation |
| NOT_DELEGATED | 0x100000 | Sensitive, cannot be delegated |
| USE_DES_KEY_ONLY | 0x200000 | DES encryption only |
| DONT_REQ_PREAUTH | 0x400000 | No Kerberos pre-auth |
| TRUSTED_TO_AUTH_FOR_DELEGATION | 0x1000000 | Protocol transition |

---

## Compliance Mapping

### SOC 2

| Control | AD Feature |
|---------|------------|
| CC6.1 - Logical Access | Account policies, group membership |
| CC6.2 - Access Authorization | Privileged groups, delegation |
| CC6.3 - Access Removal | Disabled accounts, stale accounts |
| CC6.6 - Credential Management | Password policy, MFA |
| CC7.2 - Security Monitoring | Event logs, audit policy |

### ISO 27001

| Control | AD Feature |
|---------|------------|
| A.9.2.1 - User Registration | Account provisioning |
| A.9.2.2 - Access Provisioning | Group membership |
| A.9.2.3 - Privileged Access | Admin groups, delegation |
| A.9.2.5 - Review of Access | Stale account review |
| A.9.2.6 - Removal of Access | Account disabling |
| A.9.4.3 - Password Management | Password policy |

### NIST 800-53

| Control | AD Feature |
|---------|------------|
| AC-2 - Account Management | User/computer accounts |
| AC-3 - Access Enforcement | Group Policy, permissions |
| AC-6 - Least Privilege | Group membership review |
| IA-5 - Authenticator Management | Password policy |
| AU-2 - Audit Events | Security event logging |

---

## Resources

### Official Documentation

- [Active Directory Security Best Practices](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)
- [Securing Privileged Access](https://docs.microsoft.com/en-us/security/compass/overview)
- [Password Policy Recommendations](https://docs.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations)
- [Kerberos Authentication Overview](https://docs.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)

### Microsoft Security Blog

- [Detecting Kerberoasting](https://techcommunity.microsoft.com/t5/microsoft-security-and/detecting-kerberoasting-activity/ba-p/972972)
- [Protecting Privileged Accounts](https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/protecting-privileged-domain-accounts-safeguarding-krbtgt/ba-p/259399)
- [AdminSDHolder and Protected Groups](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

### Community Tools

- [PingCastle](https://www.pingcastle.com/) - AD Security Assessment
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD Attack Path Analysis
- [Purple Knight](https://www.purple-knight.com/) - AD Security Assessment
- [ADRecon](https://github.com/adrecon/ADRecon) - AD Data Collection

### Books

- "Active Directory Administration Cookbook" - Sander Berkouwer
- "Mastering Active Directory" - Dishan Francis
- "Active Directory: Designing, Deploying, and Running Active Directory" - O'Reilly

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
