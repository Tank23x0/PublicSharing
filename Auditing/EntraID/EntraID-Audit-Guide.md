# Microsoft Entra ID (Azure AD) Security Audit Guide

## Overview

Comprehensive guide for auditing Microsoft Entra ID (formerly Azure AD) tenants including identity security, MFA, privileged access, applications, and Conditional Access.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [User Account Audit](#user-account-audit)
3. [MFA and Authentication Methods](#mfa-and-authentication-methods)
4. [Privileged Role Audit](#privileged-role-audit)
5. [Conditional Access Audit](#conditional-access-audit)
6. [Application and Service Principal Audit](#application-and-service-principal-audit)
7. [Guest Access Audit](#guest-access-audit)
8. [Sign-in and Audit Logs](#sign-in-and-audit-logs)
9. [Risk Detection](#risk-detection)
10. [Security Defaults](#security-defaults)
11. [Microsoft Graph API Reference](#microsoft-graph-api-reference)
12. [Compliance Mapping](#compliance-mapping)
13. [Resources](#resources)

---

## Prerequisites

### Microsoft Graph PowerShell SDK

```powershell
# Install Microsoft Graph modules
Install-Module Microsoft.Graph -Scope CurrentUser

# Or install specific modules
Install-Module Microsoft.Graph.Authentication
Install-Module Microsoft.Graph.Users
Install-Module Microsoft.Graph.Groups
Install-Module Microsoft.Graph.Identity.DirectoryManagement
Install-Module Microsoft.Graph.Identity.SignIns
Install-Module Microsoft.Graph.Applications

# Connect
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All"
```

### Azure CLI

```bash
# Install
brew install azure-cli  # macOS
# or
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash  # Linux

# Login
az login

# Use Microsoft Graph
az rest --method GET --url "https://graph.microsoft.com/v1.0/users"
```

### Required Permissions

| Permission | Type | Use Case |
|------------|------|----------|
| User.Read.All | Delegated/Application | List users |
| Directory.Read.All | Delegated/Application | Read directory data |
| AuditLog.Read.All | Delegated/Application | Sign-in logs |
| Policy.Read.All | Delegated/Application | Conditional Access |
| IdentityRiskyUser.Read.All | Delegated/Application | Risky users |
| RoleManagement.Read.Directory | Delegated/Application | Directory roles |

---

## User Account Audit

### PowerShell Commands

```powershell
# List all users
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, AccountEnabled, UserType

# Find stale users (no sign-in in 90 days)
$threshold = (Get-Date).AddDays(-90)
Get-MgUser -All -Property SignInActivity, DisplayName, UserPrincipalName | Where-Object {
    $_.SignInActivity.LastSignInDateTime -and 
    [DateTime]$_.SignInActivity.LastSignInDateTime -lt $threshold
} | Select-Object DisplayName, UserPrincipalName, @{N='LastSignIn';E={$_.SignInActivity.LastSignInDateTime}}

# Find users who never signed in
Get-MgUser -All -Property SignInActivity, DisplayName, UserPrincipalName, CreatedDateTime |
    Where-Object { -not $_.SignInActivity.LastSignInDateTime } |
    Select-Object DisplayName, UserPrincipalName, CreatedDateTime

# Find disabled users
Get-MgUser -Filter "accountEnabled eq false" -All

# Find guest users
Get-MgUser -Filter "userType eq 'Guest'" -All | 
    Select-Object DisplayName, UserPrincipalName, CreatedDateTime

# Get user authentication methods
Get-MgUserAuthenticationMethod -UserId "user@domain.com"

# Find users without assigned licenses
Get-MgUser -All -Property AssignedLicenses, DisplayName | 
    Where-Object { $_.AssignedLicenses.Count -eq 0 }
```

### Azure CLI

```bash
# List all users
az ad user list --output table

# Find users by filter
az ad user list --filter "accountEnabled eq false" --output table

# Show user details
az ad user show --id "user@domain.com"
```

### Manual Steps (Entra Admin Center)

1. Navigate to **Entra Admin Center** → **Users** → **All users**
2. Click **Columns** to add: Last sign-in, Account enabled, User type
3. Click **Add filter** to filter by criteria
4. Export using **Download users**

---

## MFA and Authentication Methods

### PowerShell Commands

```powershell
# Get user authentication methods
Get-MgUserAuthenticationMethod -UserId "user@domain.com" | 
    Select-Object @{N='Type';E={$_.'@odata.type'}}, Id

# List all phone methods (SMS/Voice)
Get-MgUserAuthenticationPhoneMethod -UserId "user@domain.com"

# List Microsoft Authenticator registrations
Get-MgUserAuthenticationMicrosoftAuthenticatorMethod -UserId "user@domain.com"

# List FIDO2 security keys
Get-MgUserAuthenticationFido2Method -UserId "user@domain.com"

# Check MFA registration for all users (simplified)
Get-MgUser -All -Property Id, DisplayName, UserPrincipalName | ForEach-Object {
    $methods = Get-MgUserAuthenticationMethod -UserId $_.Id -ErrorAction SilentlyContinue
    $hasMFA = $methods | Where-Object { 
        $_.'@odata.type' -ne "#microsoft.graph.passwordAuthenticationMethod"
    }
    [PSCustomObject]@{
        User = $_.UserPrincipalName
        HasMFA = [bool]$hasMFA
    }
}

# Get authentication methods policy
Get-MgPolicyAuthenticationMethodPolicy
```

### MFA Reports (Admin Center)

1. Navigate to **Entra Admin Center** → **Protection** → **Authentication methods**
2. View **Registration campaign** for MFA adoption
3. Check **Activity** for authentication method usage
4. Review **Manage** for enabled methods

### Per-User MFA (Legacy)

```powershell
# Install MSOnline module (legacy)
Install-Module MSOnline
Connect-MsolService

# Get MFA status (legacy method)
Get-MsolUser -All | Select-Object DisplayName, UserPrincipalName, 
    @{N='MFAStatus';E={$_.StrongAuthenticationRequirements.State}}
```

---

## Privileged Role Audit

### PowerShell Commands

```powershell
# List all directory roles
Get-MgDirectoryRole -All | Select-Object DisplayName, Id

# Get members of a specific role
$role = Get-MgDirectoryRole -Filter "displayName eq 'Global Administrator'"
Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id | ForEach-Object {
    Get-MgUser -UserId $_.Id -ErrorAction SilentlyContinue | 
        Select-Object DisplayName, UserPrincipalName
}

# Get all role assignments
$roles = Get-MgDirectoryRole -All
foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    if ($members.Count -gt 0) {
        Write-Host "`n$($role.DisplayName): $($members.Count) members"
        foreach ($member in $members) {
            $user = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
            if ($user) { Write-Host "  - $($user.UserPrincipalName)" }
        }
    }
}

# Check PIM eligible assignments (requires PIM)
Get-MgRoleManagementDirectoryRoleEligibilitySchedule -All | 
    Select-Object PrincipalId, RoleDefinitionId, StartDateTime, EndDateTime
```

### Critical Roles to Monitor

| Role | Risk Level | Recommended Max |
|------|------------|-----------------|
| Global Administrator | Critical | 2-5 |
| Privileged Role Administrator | Critical | 2-3 |
| Privileged Authentication Administrator | Critical | 2-3 |
| Security Administrator | High | 3-5 |
| Conditional Access Administrator | High | 3-5 |
| Application Administrator | High | 3-5 |
| User Administrator | Medium | 5-10 |
| Exchange Administrator | High | 3-5 |

### Manual Steps (Admin Center)

1. **Entra Admin Center** → **Roles and administrators**
2. Select role → View **Assignments**
3. Check for guests, stale accounts, excessive members
4. For PIM: **Entra Admin Center** → **Privileged Identity Management**

---

## Conditional Access Audit

### PowerShell Commands

```powershell
# List all CA policies
Get-MgIdentityConditionalAccessPolicy -All | 
    Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime

# Get policy details
$policies = Get-MgIdentityConditionalAccessPolicy -All
foreach ($policy in $policies) {
    Write-Host "`n=== $($policy.DisplayName) ===" -ForegroundColor Cyan
    Write-Host "State: $($policy.State)"
    Write-Host "Users Include: $($policy.Conditions.Users.IncludeUsers -join ', ')"
    Write-Host "Users Exclude: $($policy.Conditions.Users.ExcludeUsers -join ', ')"
    Write-Host "Grant Controls: $($policy.GrantControls.BuiltInControls -join ', ')"
}

# Export CA policies
Get-MgIdentityConditionalAccessPolicy -All | 
    ConvertTo-Json -Depth 10 | Out-File "CA-Policies-Export.json"
```

### Essential CA Policies Checklist

- [ ] **Block legacy authentication** - Block Exchange ActiveSync, other legacy clients
- [ ] **Require MFA for admins** - All privileged roles
- [ ] **Require MFA for all users** - At minimum for risky sign-ins
- [ ] **Block high-risk sign-ins** - Require password change or block
- [ ] **Require compliant devices** - For corporate apps
- [ ] **Block access from risky locations** - Countries you don't operate in

### Manual Steps (Admin Center)

1. **Entra Admin Center** → **Protection** → **Conditional Access**
2. Review each policy's status (On/Off/Report-only)
3. Check policy coverage gaps
4. Review Named Locations

---

## Application and Service Principal Audit

### PowerShell Commands

```powershell
# List app registrations
Get-MgApplication -All | Select-Object DisplayName, AppId, CreatedDateTime

# Check app credential expiration
Get-MgApplication -All | ForEach-Object {
    $app = $_
    foreach ($cred in $_.PasswordCredentials) {
        if ($cred.EndDateTime -lt (Get-Date).AddDays(30)) {
            [PSCustomObject]@{
                App = $app.DisplayName
                CredentialType = "Secret"
                Expiry = $cred.EndDateTime
            }
        }
    }
    foreach ($cert in $_.KeyCredentials) {
        if ($cert.EndDateTime -lt (Get-Date).AddDays(30)) {
            [PSCustomObject]@{
                App = $app.DisplayName
                CredentialType = "Certificate"
                Expiry = $cert.EndDateTime
            }
        }
    }
}

# List enterprise apps (service principals)
Get-MgServicePrincipal -All | Select-Object DisplayName, AppId, ServicePrincipalType

# Check consent grants
Get-MgServicePrincipal -All | ForEach-Object {
    $sp = $_
    $grants = Get-MgServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
    if ($grants) {
        [PSCustomObject]@{
            App = $sp.DisplayName
            ConsentType = $grants.ConsentType
            Scope = $grants.Scope
        }
    }
}

# Find apps with high-privilege permissions
Get-MgApplication -All | ForEach-Object {
    $app = $_
    $highPriv = @("Directory.ReadWrite.All", "User.ReadWrite.All", "Mail.ReadWrite", "Sites.ReadWrite.All")
    # Check required permissions (simplified)
    if ($app.RequiredResourceAccess.ResourceAccess.Type -contains "Role") {
        [PSCustomObject]@{
            App = $app.DisplayName
            HasAppPermissions = $true
        }
    }
}
```

### Security Concerns

1. **Expiring credentials** - Apps may break when secrets/certs expire
2. **Admin consent grants** - Review tenant-wide consents
3. **Application permissions** - More dangerous than delegated
4. **Overly permissive scopes** - Directory.ReadWrite.All, Mail.ReadWrite
5. **Unverified publishers** - Third-party apps from unknown sources

---

## Guest Access Audit

### PowerShell Commands

```powershell
# List all guest users
Get-MgUser -Filter "userType eq 'Guest'" -All | 
    Select-Object DisplayName, UserPrincipalName, CreatedDateTime, 
    @{N='LastSignIn';E={$_.SignInActivity.LastSignInDateTime}}

# Find stale guests
$threshold = (Get-Date).AddDays(-90)
Get-MgUser -Filter "userType eq 'Guest'" -All -Property SignInActivity | 
    Where-Object {
        -not $_.SignInActivity.LastSignInDateTime -or
        [DateTime]$_.SignInActivity.LastSignInDateTime -lt $threshold
    }

# Check guest access settings
Get-MgPolicyAuthorizationPolicy | Select-Object GuestUserRoleId, AllowInvitesFrom

# Guest role descriptions
# 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest users have the same access as members (most permissive)
# 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest users have limited access (default)
# a0b1b346-4d3e-4e8b-98f8-753987be4970 = Guest user access is restricted (most restrictive)
```

### Manual Steps

1. **Entra Admin Center** → **Users** → Filter by "Guest"
2. **External Identities** → **External collaboration settings**
3. Review: Guest invite settings, Guest user access restrictions

---

## Sign-in and Audit Logs

### PowerShell Commands (Requires Azure AD Premium)

```powershell
# Get recent sign-ins
Get-MgAuditLogSignIn -Top 100 | 
    Select-Object UserDisplayName, UserPrincipalName, Status, 
    ClientAppUsed, DeviceDetail, Location

# Failed sign-ins
Get-MgAuditLogSignIn -Filter "status/errorCode ne 0" -Top 100 |
    Select-Object UserDisplayName, Status, CreatedDateTime

# Sign-ins from specific user
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'user@domain.com'" -Top 50

# Get audit logs
Get-MgAuditLogDirectoryAudit -Top 100 | 
    Select-Object ActivityDisplayName, Category, Result, InitiatedBy

# Risky sign-ins
Get-MgAuditLogSignIn -Filter "riskLevelDuringSignIn ne 'none'" -Top 100
```

### Key Events to Monitor

| Event | Category | Importance |
|-------|----------|------------|
| User account created | UserManagement | Medium |
| User account deleted | UserManagement | Medium |
| Add member to role | RoleManagement | High |
| Remove member from role | RoleManagement | High |
| Consent to application | ApplicationManagement | High |
| Policy modified | Policy | High |
| MFA registered | AuthenticationMethods | Medium |

---

## Risk Detection

### PowerShell Commands (Requires Azure AD P2)

```powershell
# Get risky users
Get-MgRiskyUser -All | Select-Object UserDisplayName, RiskLevel, RiskState, RiskLastUpdatedDateTime

# Get high-risk users
Get-MgRiskyUser -Filter "riskLevel eq 'high'" -All

# Get risk detections
Get-MgRiskDetection -Top 100 | 
    Select-Object UserDisplayName, RiskType, RiskLevel, DetectedDateTime

# Dismiss risky user
# Confirm-MgRiskyUserCompromised -RiskyUserIds @("user-id")
```

### Manual Steps

1. **Entra Admin Center** → **Protection** → **Risky users**
2. Review users flagged as high/medium risk
3. Investigate and remediate (confirm compromised, dismiss, etc.)
4. **Protection** → **Risky sign-ins** for sign-in investigations

---

## Security Defaults

### PowerShell Commands

```powershell
# Check Security Defaults status
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | 
    Select-Object IsEnabled

# Security Defaults includes:
# - MFA registration for all users
# - MFA for admins
# - MFA when risky
# - Block legacy authentication
```

### Manual Steps

1. **Entra Admin Center** → **Properties** → **Manage security defaults**
2. View current status (enabled/disabled)

### Note on Security Defaults vs. Conditional Access

- **Security Defaults**: Free, basic protection, all-or-nothing
- **Conditional Access**: Requires P1/P2, granular control, recommended for enterprises

---

## Microsoft Graph API Reference

### Key Endpoints

| Resource | Endpoint |
|----------|----------|
| Users | GET /users |
| Sign-in logs | GET /auditLogs/signIns |
| Audit logs | GET /auditLogs/directoryAudits |
| Directory roles | GET /directoryRoles |
| CA policies | GET /identity/conditionalAccess/policies |
| Applications | GET /applications |
| Service principals | GET /servicePrincipals |
| Risky users | GET /identityProtection/riskyUsers |
| Risk detections | GET /identityProtection/riskDetections |
| Auth methods | GET /users/{id}/authentication/methods |

### API Examples

```bash
# Get users
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/users"

# Get sign-in logs (beta for some properties)
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/beta/auditLogs/signIns?\$top=10"

# Get risky users
curl -H "Authorization: Bearer $TOKEN" \
    "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
```

---

## Compliance Mapping

### SOC 2

| Control | Entra ID Feature |
|---------|------------------|
| CC6.1 - Logical Access | User management, authentication |
| CC6.2 - Access Authorization | Directory roles, RBAC |
| CC6.3 - Access Removal | User lifecycle, access reviews |
| CC6.6 - Credential Management | Password policies, MFA |
| CC7.2 - Security Monitoring | Sign-in logs, risk detection |

### ISO 27001

| Control | Entra ID Feature |
|---------|------------------|
| A.9.2.1 - User Registration | User provisioning |
| A.9.2.3 - Privileged Access | PIM, directory roles |
| A.9.4.2 - Secure Log-on | MFA, Conditional Access |
| A.12.4.1 - Event Logging | Audit and sign-in logs |

### NIST 800-53

| Control | Entra ID Feature |
|---------|------------------|
| AC-2 - Account Management | User management |
| AC-6 - Least Privilege | Role assignments, CA |
| IA-2 - Identification | Authentication methods |
| AU-2 - Audit Events | Sign-in/audit logs |

---

## Resources

### Official Documentation

- [Microsoft Entra ID Documentation](https://docs.microsoft.com/en-us/entra/identity/)
- [Conditional Access Documentation](https://docs.microsoft.com/en-us/entra/identity/conditional-access/)
- [Privileged Identity Management](https://docs.microsoft.com/en-us/entra/id-governance/privileged-identity-management/)
- [Microsoft Graph API Reference](https://docs.microsoft.com/en-us/graph/api/overview)

### Microsoft Security Blog

- [Microsoft Entra Blog](https://techcommunity.microsoft.com/t5/microsoft-entra-blog/bg-p/Identity)
- [Identity Security Best Practices](https://docs.microsoft.com/en-us/entra/identity/users/best-practices)

### Tools

- [Microsoft Entra Admin Center](https://entra.microsoft.com)
- [Azure AD Connect Health](https://docs.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-operations)
- [Microsoft Secure Score](https://security.microsoft.com/securescore)

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
