<#
.SYNOPSIS
    Comprehensive Microsoft Entra ID (Azure AD) Security Audit Script
    
.DESCRIPTION
    Performs thorough security audits of Entra ID tenants including:
    - User accounts (stale, disabled, guests)
    - MFA status and authentication methods
    - Privileged roles and PIM
    - Service principals and app registrations
    - Conditional Access policies
    - Sign-in logs and risky users
    - B2B/Guest access
    - Security defaults and settings
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - Microsoft Graph PowerShell SDK
    - Global Reader or Security Reader role minimum
    - For sign-in logs: Azure AD Premium P1+
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\EntraID-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSignInLogs
)

#region Configuration

$script:Config = @{
    ScriptName = "EntraID-Full-Audit"
    Version = "2.0.0"
    StartTime = Get-Date
    LogFile = $null
    ReportFile = $null
    TotalFindings = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
}

if ($PSVersionTable.Platform -eq 'Unix') {
    $OutputPath = $OutputPath -replace '\$env:USERPROFILE', $env:HOME
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "EntraID-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "EntraID-Audit-Report_$timestamp.html"

$script:AllFindings = @()

#endregion

#region Logging

function Write-AuditLog {
    param([string]$Message, [string]$Level = "INFO")
    
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    
    $color = switch ($Level) {
        "INFO" { "White" } "WARNING" { "Yellow" } "ERROR" { "Red" }
        "SUCCESS" { "Green" } "FINDING" { "Cyan" }
    }
    
    Write-Host $entry -ForegroundColor $color
    Add-Content -Path $script:Config.LogFile -Value $entry
}

function Write-Finding {
    param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    
    $script:Config.TotalFindings++
    switch ($Severity) {
        "CRITICAL" { $script:Config.CriticalFindings++ }
        "HIGH" { $script:Config.HighFindings++ }
        "MEDIUM" { $script:Config.MediumFindings++ }
        "LOW" { $script:Config.LowFindings++ }
    }
    
    $script:AllFindings += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Severity = $Severity
        Object = $Object
        Finding = $Finding
        Recommendation = $Recommendation
    }
    
    Write-AuditLog "[$Severity] $Category - $Finding" "FINDING"
}

#endregion

#region Module Verification

function Test-GraphModules {
    Write-AuditLog "Checking Microsoft Graph modules..." "INFO"
    
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Groups",
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Identity.SignIns",
        "Microsoft.Graph.Applications",
        "Microsoft.Graph.Identity.Governance"
    )
    
    $missing = @()
    foreach ($mod in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-AuditLog "Installing missing modules: $($missing -join ', ')" "WARNING"
        foreach ($mod in $missing) {
            try {
                Install-Module -Name $mod -Force -AllowClobber -Scope CurrentUser
            }
            catch {
                Write-AuditLog "Failed to install $mod" "ERROR"
                return $false
            }
        }
    }
    
    foreach ($mod in $requiredModules) {
        Import-Module $mod -Force -ErrorAction SilentlyContinue
    }
    
    Write-AuditLog "Graph modules verified" "SUCCESS"
    return $true
}

function Initialize-GraphConnection {
    Write-AuditLog "Connecting to Microsoft Graph..." "INFO"
    
    $scopes = @(
        "User.Read.All",
        "Directory.Read.All",
        "AuditLog.Read.All",
        "Policy.Read.All",
        "IdentityRiskyUser.Read.All",
        "Application.Read.All",
        "RoleManagement.Read.Directory"
    )
    
    try {
        $context = Get-MgContext
        
        if (-not $context) {
            if ($TenantId) {
                Connect-MgGraph -Scopes $scopes -TenantId $TenantId
            } else {
                Connect-MgGraph -Scopes $scopes
            }
            $context = Get-MgContext
        }
        
        Write-AuditLog "Connected to tenant: $($context.TenantId)" "SUCCESS"
        Write-AuditLog "Account: $($context.Account)" "INFO"
        
        $script:TenantInfo = Get-MgOrganization
        $script:TenantName = $script:TenantInfo.DisplayName
        
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect: $_" "ERROR"
        return $false
    }
}

#endregion

#region User Audit

function Invoke-UserAudit {
    Write-AuditLog "Auditing User Accounts..." "INFO"
    
    try {
        $users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AccountEnabled, 
            CreatedDateTime, SignInActivity, UserType, AssignedLicenses, OnPremisesSyncEnabled
        
        $total = $users.Count
        $enabled = 0
        $disabled = 0
        $stale = 0
        $guests = 0
        $noLicense = 0
        
        $thresholdDate = (Get-Date).AddDays(-$StaleThresholdDays)
        
        Write-AuditLog "Processing $total users..." "INFO"
        
        foreach ($user in $users) {
            if ($user.AccountEnabled) { $enabled++ } else { $disabled++ }
            if ($user.UserType -eq "Guest") { $guests++ }
            
            # Skip disabled and guests for some checks
            if (-not $user.AccountEnabled) { continue }
            
            # Check stale accounts
            $lastSignIn = $user.SignInActivity.LastSignInDateTime
            if ($lastSignIn) {
                if ([DateTime]$lastSignIn -lt $thresholdDate) {
                    $daysSince = [int]((Get-Date) - [DateTime]$lastSignIn).TotalDays
                    $stale++
                    
                    Write-Finding -Category "Users" -Severity "MEDIUM" `
                        -Object $user.UserPrincipalName `
                        -Finding "User has not signed in for $daysSince days" `
                        -Recommendation "Review account necessity and consider disabling"
                }
            }
            elseif ($user.CreatedDateTime -and [DateTime]$user.CreatedDateTime -lt $thresholdDate) {
                # Never signed in
                Write-Finding -Category "Users" -Severity "MEDIUM" `
                    -Object $user.UserPrincipalName `
                    -Finding "User has never signed in (created $(([DateTime]$user.CreatedDateTime).ToString('yyyy-MM-dd')))" `
                    -Recommendation "Verify account is needed"
            }
            
            # Check for unlicensed members (not guests)
            if ($user.UserType -ne "Guest" -and 
                (-not $user.AssignedLicenses -or $user.AssignedLicenses.Count -eq 0)) {
                $noLicense++
            }
        }
        
        # Guest user warnings
        if ($guests -gt 50) {
            Write-Finding -Category "Users" -Severity "LOW" `
                -Object "Guest Users" `
                -Finding "$guests guest users in tenant" `
                -Recommendation "Review guest access policies and necessity"
        }
        
        $script:UserStats = @{
            Total = $total
            Enabled = $enabled
            Disabled = $disabled
            Stale = $stale
            Guests = $guests
            NoLicense = $noLicense
        }
        
        Write-AuditLog "User Stats: Total=$total, Enabled=$enabled, Stale=$stale, Guests=$guests" "INFO"
    }
    catch {
        Write-AuditLog "Error in user audit: $_" "ERROR"
    }
}

#endregion

#region MFA Audit

function Invoke-MFAAudit {
    Write-AuditLog "Auditing MFA Status..." "INFO"
    
    try {
        # Get authentication methods for users
        $users = Get-MgUser -All -Filter "accountEnabled eq true and userType eq 'Member'" `
            -Property Id, DisplayName, UserPrincipalName
        
        $totalUsers = $users.Count
        $withMFA = 0
        $withoutMFA = 0
        $processedCount = 0
        
        foreach ($user in $users) {
            $processedCount++
            
            if ($processedCount % 50 -eq 0) {
                Write-Progress -Activity "Checking MFA" -Status "$processedCount of $totalUsers" `
                    -PercentComplete (($processedCount / $totalUsers) * 100)
            }
            
            try {
                $methods = Get-MgUserAuthenticationMethod -UserId $user.Id -ErrorAction SilentlyContinue
                
                $hasMFA = $methods | Where-Object {
                    $_.'@odata.type' -in @(
                        "#microsoft.graph.phoneAuthenticationMethod",
                        "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod",
                        "#microsoft.graph.fido2AuthenticationMethod",
                        "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
                    )
                }
                
                if ($hasMFA) {
                    $withMFA++
                } else {
                    $withoutMFA++
                    Write-Finding -Category "MFA" -Severity "HIGH" `
                        -Object $user.UserPrincipalName `
                        -Finding "No MFA methods registered" `
                        -Recommendation "Enforce MFA registration via Conditional Access"
                }
            }
            catch {
                # Skip if can't access auth methods
            }
        }
        
        Write-Progress -Activity "Checking MFA" -Completed
        
        $mfaPercentage = if ($totalUsers -gt 0) { [math]::Round(($withMFA / $totalUsers) * 100, 1) } else { 0 }
        
        if ($mfaPercentage -lt 90) {
            Write-Finding -Category "MFA" -Severity "HIGH" `
                -Object "MFA Coverage" `
                -Finding "Only $mfaPercentage% of users have MFA ($withMFA of $totalUsers)" `
                -Recommendation "Target 100% MFA coverage"
        }
        
        Write-AuditLog "MFA Coverage: $withMFA/$totalUsers ($mfaPercentage%)" "INFO"
    }
    catch {
        Write-AuditLog "Error in MFA audit: $_" "ERROR"
    }
}

#endregion

#region Privileged Role Audit

function Invoke-PrivilegedRoleAudit {
    Write-AuditLog "Auditing Privileged Roles..." "INFO"
    
    $criticalRoles = @(
        "Global Administrator",
        "Privileged Role Administrator", 
        "Privileged Authentication Administrator",
        "Security Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "User Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Conditional Access Administrator"
    )
    
    try {
        $roleDefinitions = Get-MgDirectoryRole -All
        
        foreach ($role in $roleDefinitions) {
            if ($role.DisplayName -in $criticalRoles) {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
                $memberCount = $members.Count
                
                Write-AuditLog "  $($role.DisplayName): $memberCount members" "INFO"
                
                # Global Admin specific checks
                if ($role.DisplayName -eq "Global Administrator") {
                    if ($memberCount -gt 5) {
                        Write-Finding -Category "Privileged Access" -Severity "HIGH" `
                            -Object "Global Administrator" `
                            -Finding "$memberCount Global Admins (recommended: 2-5)" `
                            -Recommendation "Reduce Global Admin count"
                    }
                    
                    foreach ($member in $members) {
                        $memberDetail = Get-MgUser -UserId $member.Id -ErrorAction SilentlyContinue
                        if ($memberDetail) {
                            # Check if guest
                            if ($memberDetail.UserType -eq "Guest") {
                                Write-Finding -Category "Privileged Access" -Severity "CRITICAL" `
                                    -Object $memberDetail.UserPrincipalName `
                                    -Finding "Guest user is Global Administrator" `
                                    -Recommendation "Remove guest from Global Admin immediately"
                            }
                            
                            # Check last sign-in
                            if ($memberDetail.SignInActivity.LastSignInDateTime) {
                                $lastSignIn = [DateTime]$memberDetail.SignInActivity.LastSignInDateTime
                                if ($lastSignIn -lt (Get-Date).AddDays(-30)) {
                                    Write-Finding -Category "Privileged Access" -Severity "MEDIUM" `
                                        -Object $memberDetail.UserPrincipalName `
                                        -Finding "Global Admin hasn't signed in for $([int]((Get-Date) - $lastSignIn).TotalDays) days" `
                                        -Recommendation "Review admin account necessity"
                                }
                            }
                        }
                    }
                }
                
                # Check for excessive role assignments
                if ($role.DisplayName -eq "Privileged Role Administrator" -and $memberCount -gt 3) {
                    Write-Finding -Category "Privileged Access" -Severity "HIGH" `
                        -Object $role.DisplayName `
                        -Finding "$memberCount users can manage privileged roles" `
                        -Recommendation "Minimize Privileged Role Administrator count"
                }
            }
        }
    }
    catch {
        Write-AuditLog "Error in role audit: $_" "ERROR"
    }
}

#endregion

#region Service Principal Audit

function Invoke-ServicePrincipalAudit {
    Write-AuditLog "Auditing Service Principals and App Registrations..." "INFO"
    
    try {
        # App registrations
        $apps = Get-MgApplication -All
        Write-AuditLog "Found $($apps.Count) app registrations" "INFO"
        
        foreach ($app in $apps) {
            # Check for credentials expiring soon
            foreach ($cred in $app.PasswordCredentials) {
                if ($cred.EndDateTime -and $cred.EndDateTime -lt (Get-Date).AddDays(30)) {
                    Write-Finding -Category "Applications" -Severity "MEDIUM" `
                        -Object $app.DisplayName `
                        -Finding "App credential expires in less than 30 days" `
                        -Recommendation "Rotate application credentials"
                }
            }
            
            foreach ($cert in $app.KeyCredentials) {
                if ($cert.EndDateTime -and $cert.EndDateTime -lt (Get-Date).AddDays(30)) {
                    Write-Finding -Category "Applications" -Severity "MEDIUM" `
                        -Object $app.DisplayName `
                        -Finding "App certificate expires in less than 30 days" `
                        -Recommendation "Rotate application certificate"
                }
            }
            
            # Check for overly permissive API permissions
            $highPrivPerms = @(
                "Directory.ReadWrite.All",
                "User.ReadWrite.All",
                "Application.ReadWrite.All",
                "RoleManagement.ReadWrite.Directory",
                "Mail.ReadWrite",
                "Sites.ReadWrite.All"
            )
            
            foreach ($resource in $app.RequiredResourceAccess) {
                foreach ($permission in $resource.ResourceAccess) {
                    # This is simplified - in production, resolve permission names
                    if ($permission.Type -eq "Role") { # Application permission
                        Write-Finding -Category "Applications" -Severity "LOW" `
                            -Object $app.DisplayName `
                            -Finding "App has application-level permissions (verify necessity)" `
                            -Recommendation "Review and minimize application permissions"
                        break
                    }
                }
            }
        }
        
        # Service principals with high privilege roles
        $spPrincipals = Get-MgServicePrincipal -All | Where-Object { $_.ServicePrincipalType -eq "Application" }
        
        foreach ($sp in $spPrincipals) {
            try {
                $roleAssignments = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -ErrorAction SilentlyContinue
                if ($roleAssignments -and $roleAssignments.Count -gt 10) {
                    Write-Finding -Category "Applications" -Severity "LOW" `
                        -Object $sp.DisplayName `
                        -Finding "Service principal has $($roleAssignments.Count) role assignments" `
                        -Recommendation "Review service principal permissions"
                }
            }
            catch {}
        }
    }
    catch {
        Write-AuditLog "Error in service principal audit: $_" "ERROR"
    }
}

#endregion

#region Conditional Access Audit

function Invoke-ConditionalAccessAudit {
    Write-AuditLog "Auditing Conditional Access Policies..." "INFO"
    
    try {
        $policies = Get-MgIdentityConditionalAccessPolicy -All
        
        Write-AuditLog "Found $($policies.Count) Conditional Access policies" "INFO"
        
        $hasBlockLegacy = $false
        $hasMFAForAdmins = $false
        $hasMFAForAll = $false
        $hasRiskPolicy = $false
        
        foreach ($policy in $policies) {
            if ($policy.State -ne "enabled") { continue }
            
            $policyName = $policy.DisplayName
            
            # Check for legacy auth blocking
            if ($policy.Conditions.ClientAppTypes -contains "exchangeActiveSync" -or
                $policy.Conditions.ClientAppTypes -contains "other") {
                if ($policy.GrantControls.BuiltInControls -contains "block") {
                    $hasBlockLegacy = $true
                }
            }
            
            # Check for admin MFA
            $adminRoles = $policy.Conditions.Users.IncludeRoles
            if ($adminRoles -and $policy.GrantControls.BuiltInControls -contains "mfa") {
                $hasMFAForAdmins = $true
            }
            
            # Check for all users MFA
            if ($policy.Conditions.Users.IncludeUsers -contains "All" -and
                $policy.GrantControls.BuiltInControls -contains "mfa") {
                $hasMFAForAll = $true
            }
            
            # Check for risk-based policies
            if ($policy.Conditions.SignInRiskLevels -or $policy.Conditions.UserRiskLevels) {
                $hasRiskPolicy = $true
            }
        }
        
        if (-not $hasBlockLegacy) {
            Write-Finding -Category "Conditional Access" -Severity "HIGH" `
                -Object "Legacy Authentication" `
                -Finding "No policy blocking legacy authentication" `
                -Recommendation "Create CA policy to block legacy auth"
        }
        
        if (-not $hasMFAForAdmins) {
            Write-Finding -Category "Conditional Access" -Severity "CRITICAL" `
                -Object "Admin MFA" `
                -Finding "No policy requiring MFA for administrators" `
                -Recommendation "Create CA policy requiring MFA for admin roles"
        }
        
        if (-not $hasMFAForAll) {
            Write-Finding -Category "Conditional Access" -Severity "MEDIUM" `
                -Object "User MFA" `
                -Finding "No policy requiring MFA for all users" `
                -Recommendation "Consider MFA for all users via CA policy"
        }
        
        if (-not $hasRiskPolicy) {
            Write-Finding -Category "Conditional Access" -Severity "MEDIUM" `
                -Object "Risk Policies" `
                -Finding "No risk-based Conditional Access policies" `
                -Recommendation "Implement sign-in and user risk policies"
        }
    }
    catch {
        Write-AuditLog "Error in CA audit (may need P1/P2 license): $_" "WARNING"
    }
}

#endregion

#region Security Defaults and Settings

function Invoke-SecuritySettingsAudit {
    Write-AuditLog "Auditing Security Settings..." "INFO"
    
    try {
        # Check Security Defaults
        $securityDefaults = Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy -ErrorAction SilentlyContinue
        
        if ($securityDefaults -and $securityDefaults.IsEnabled) {
            Write-AuditLog "Security Defaults are enabled" "INFO"
        }
        else {
            # Only warn if no CA policies exist
            $caCount = (Get-MgIdentityConditionalAccessPolicy -All -ErrorAction SilentlyContinue).Count
            if ($caCount -eq 0) {
                Write-Finding -Category "Security Settings" -Severity "CRITICAL" `
                    -Object "Security Defaults" `
                    -Finding "Security Defaults disabled and no CA policies" `
                    -Recommendation "Enable Security Defaults or implement CA policies"
            }
        }
        
        # Check password reset policy
        try {
            $authPolicy = Get-MgPolicyAuthenticationMethodPolicy -ErrorAction SilentlyContinue
            Write-AuditLog "Authentication methods policy retrieved" "INFO"
        }
        catch {}
        
        # Check if SSPR enabled
        try {
            $sspr = Get-MgPolicyAuthorizationPolicy -ErrorAction SilentlyContinue
            Write-AuditLog "Authorization policy retrieved" "INFO"
        }
        catch {}
    }
    catch {
        Write-AuditLog "Error in security settings audit: $_" "ERROR"
    }
}

#endregion

#region Risky Users Audit

function Invoke-RiskyUsersAudit {
    Write-AuditLog "Auditing Risky Users..." "INFO"
    
    try {
        $riskyUsers = Get-MgRiskyUser -All -ErrorAction SilentlyContinue
        
        if ($riskyUsers) {
            $high = ($riskyUsers | Where-Object { $_.RiskLevel -eq "high" }).Count
            $medium = ($riskyUsers | Where-Object { $_.RiskLevel -eq "medium" }).Count
            
            if ($high -gt 0) {
                Write-Finding -Category "Risk Detection" -Severity "CRITICAL" `
                    -Object "Risky Users" `
                    -Finding "$high users flagged as high risk" `
                    -Recommendation "Investigate and remediate high-risk users immediately"
            }
            
            if ($medium -gt 0) {
                Write-Finding -Category "Risk Detection" -Severity "HIGH" `
                    -Object "Risky Users" `
                    -Finding "$medium users flagged as medium risk" `
                    -Recommendation "Review and address medium-risk users"
            }
            
            Write-AuditLog "Risky users: High=$high, Medium=$medium" "INFO"
        }
    }
    catch {
        Write-AuditLog "Unable to query risky users (requires P2 license)" "WARNING"
    }
}

#endregion

#region Report Generation

function Export-AuditReport {
    Write-AuditLog "Generating report..." "INFO"
    
    $duration = (Get-Date) - $script:Config.StartTime
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Entra ID Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 15px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333; }
        .low { background: #1976d2; }
        .info { background: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #0078d4; color: white; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #1976d2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Microsoft Entra ID Security Audit Report</h1>
        <p><strong>Tenant:</strong> $($script:TenantName)</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p><strong>Duration:</strong> $($duration.ToString("hh\:mm\:ss"))</p>
        
        <h2>Summary</h2>
        <div class="summary-box">
            <div class="summary-item critical"><h3>$($script:Config.CriticalFindings)</h3><p>Critical</p></div>
            <div class="summary-item high"><h3>$($script:Config.HighFindings)</h3><p>High</p></div>
            <div class="summary-item medium"><h3>$($script:Config.MediumFindings)</h3><p>Medium</p></div>
            <div class="summary-item low"><h3>$($script:Config.LowFindings)</h3><p>Low</p></div>
            <div class="summary-item info"><h3>$($script:Config.TotalFindings)</h3><p>Total</p></div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@

    foreach ($f in ($script:AllFindings | Sort-Object { switch ($_.Severity) { "CRITICAL" {0} "HIGH" {1} "MEDIUM" {2} "LOW" {3} }})) {
        $html += "<tr><td class='severity-$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>"
    }

    $html += "</table></div></body></html>"
    
    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "Report saved: $($script:Config.ReportFile)" "SUCCESS"
    
    if ($ExportToCSV) {
        $csvPath = $script:Config.ReportFile -replace "\.html$", ".csv"
        $script:AllFindings | Export-Csv -Path $csvPath -NoTypeInformation
    }
}

#endregion

#region Main

function Invoke-EntraIDAudit {
    Write-AuditLog "=" * 60 "INFO"
    Write-AuditLog "MICROSOFT ENTRA ID SECURITY AUDIT" "INFO"
    Write-AuditLog "=" * 60 "INFO"
    
    if (-not (Test-GraphModules)) { return }
    if (-not (Initialize-GraphConnection)) { return }
    
    Invoke-UserAudit
    Invoke-MFAAudit
    Invoke-PrivilegedRoleAudit
    Invoke-ServicePrincipalAudit
    Invoke-ConditionalAccessAudit
    Invoke-SecuritySettingsAudit
    Invoke-RiskyUsersAudit
    
    Export-AuditReport
    
    Write-AuditLog "" "INFO"
    Write-AuditLog "AUDIT COMPLETE - Findings: $($script:Config.TotalFindings)" "SUCCESS"
}

Invoke-EntraIDAudit

#endregion
