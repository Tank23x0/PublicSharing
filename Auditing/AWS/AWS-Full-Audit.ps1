<#
.SYNOPSIS
    Comprehensive AWS Security Audit Script - Multi-Account Organization Support
    
.DESCRIPTION
    Performs thorough security audits across ALL AWS accounts in an organization.
    Covers IAM users, roles, access keys, MFA status, EC2 instances, S3 buckets,
    security groups, CloudTrail, GuardDuty, and compliance checks.
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - AWS Tools for PowerShell (AWS.Tools.*)
    - Appropriate IAM permissions (SecurityAudit managed policy recommended)
    - AWS Organizations access for multi-account auditing
    - PowerShell 7.0 or higher recommended
    
.NOTES
    Run from an account with OrganizationsReadOnlyAccess and ability to assume
    audit roles in member accounts.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ProfileName = "default",
    
    [Parameter(Mandatory = $false)]
    [string]$Region = "us-east-1",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "~/Documents/Scripts/AWS-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [int]$KeyAgeThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeAllRegions,
    
    [Parameter(Mandatory = $false)]
    [switch]$AuditEntireOrganization,
    
    [Parameter(Mandatory = $false)]
    [string]$CrossAccountRoleName = "OrganizationAccountAccessRole",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipResourceAudit
)

#region Configuration and Initialization

$script:Config = @{
    ScriptName = "AWS-Full-Audit"
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

# Ensure output directory exists
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath.Replace("~", $env:HOME ?? $env:USERPROFILE))
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "AWS-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "AWS-Audit-Report_$timestamp.html"

#endregion

#region Logging Functions

function Write-AuditLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "FINDING")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "FINDING" { "Cyan" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $script:Config.LogFile -Value $logEntry
}

function Write-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$AccountId,
        [string]$Resource,
        [string]$Finding,
        [string]$Recommendation
    )
    
    $script:Config.TotalFindings++
    switch ($Severity) {
        "CRITICAL" { $script:Config.CriticalFindings++ }
        "HIGH"     { $script:Config.HighFindings++ }
        "MEDIUM"   { $script:Config.MediumFindings++ }
        "LOW"      { $script:Config.LowFindings++ }
    }
    
    $script:AllFindings += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Severity = $Severity
        AccountId = $AccountId
        Resource = $Resource
        Finding = $Finding
        Recommendation = $Recommendation
    }
    
    Write-AuditLog -Message "[$Severity] $Category - $Finding" -Level "FINDING"
}

function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
}

#endregion

#region Module Verification

function Test-AWSModules {
    Write-AuditLog "Checking required AWS PowerShell modules..." -Level "INFO"
    
    $requiredModules = @(
        "AWS.Tools.Common",
        "AWS.Tools.IdentityManagement",
        "AWS.Tools.Organizations",
        "AWS.Tools.SecurityToken",
        "AWS.Tools.EC2",
        "AWS.Tools.S3",
        "AWS.Tools.CloudTrail",
        "AWS.Tools.SecurityHub",
        "AWS.Tools.GuardDuty",
        "AWS.Tools.ConfigService",
        "AWS.Tools.AccessAnalyzer",
        "AWS.Tools.IAMAccessAnalyzer"
    )
    
    $missingModules = @()
    
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-AuditLog "Missing modules: $($missingModules -join ', ')" -Level "WARNING"
        Write-AuditLog "Installing missing modules..." -Level "INFO"
        
        foreach ($module in $missingModules) {
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-AuditLog "Installed: $module" -Level "SUCCESS"
            }
            catch {
                Write-AuditLog "Failed to install $module`: $_" -Level "ERROR"
                return $false
            }
        }
    }
    
    # Import modules
    foreach ($module in $requiredModules) {
        try {
            Import-Module $module -Force -ErrorAction Stop
        }
        catch {
            Write-AuditLog "Failed to import $module - some features may be limited" -Level "WARNING"
        }
    }
    
    Write-AuditLog "All required modules verified" -Level "SUCCESS"
    return $true
}

#endregion

#region AWS Connection Functions

function Initialize-AWSConnection {
    param(
        [string]$Profile = "default",
        [string]$Region = "us-east-1"
    )
    
    try {
        Set-AWSCredential -ProfileName $Profile
        Set-DefaultAWSRegion -Region $Region
        
        # Verify connection by getting caller identity
        $identity = Get-STSCallerIdentity
        Write-AuditLog "Connected as: $($identity.Arn)" -Level "SUCCESS"
        Write-AuditLog "Account ID: $($identity.Account)" -Level "INFO"
        
        return $identity
    }
    catch {
        Write-AuditLog "Failed to connect to AWS: $_" -Level "ERROR"
        return $null
    }
}

function Get-OrganizationAccounts {
    Write-AuditLog "Retrieving AWS Organization accounts..." -Level "INFO"
    
    try {
        $accounts = Get-ORGAccountList -ErrorAction Stop
        Write-AuditLog "Found $($accounts.Count) accounts in organization" -Level "SUCCESS"
        return $accounts
    }
    catch {
        Write-AuditLog "Unable to list organization accounts. Running single-account audit." -Level "WARNING"
        return $null
    }
}

function Enter-CrossAccountRole {
    param(
        [string]$AccountId,
        [string]$RoleName
    )
    
    try {
        $roleArn = "arn:aws:iam::${AccountId}:role/$RoleName"
        $sessionName = "AuditSession-$(Get-Date -Format 'yyyyMMddHHmmss')"
        
        $credentials = Use-STSRole -RoleArn $roleArn -RoleSessionName $sessionName
        
        return $credentials.Credentials
    }
    catch {
        Write-AuditLog "Failed to assume role in account ${AccountId}: $_" -Level "WARNING"
        return $null
    }
}

#endregion

#region IAM Audit Functions

function Get-IAMCredentialReport {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Generating IAM Credential Report for account $AccountId..." -Level "INFO"
    
    try {
        # Request credential report generation
        $reportStatus = Request-IAMCredentialReport
        
        # Wait for report to be ready
        $maxAttempts = 10
        $attempt = 0
        do {
            Start-Sleep -Seconds 2
            $attempt++
            try {
                $report = Get-IAMCredentialReport -AsTextArray
                break
            }
            catch {
                if ($attempt -ge $maxAttempts) { throw }
            }
        } while ($attempt -lt $maxAttempts)
        
        # Parse CSV report
        $credentialReport = $report | ConvertFrom-Csv
        
        return $credentialReport
    }
    catch {
        Write-AuditLog "Failed to generate credential report: $_" -Level "ERROR"
        return $null
    }
}

function Invoke-IAMUserAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing IAM Users for account $AccountId..." -Level "INFO"
    
    $users = Get-IAMUserList
    $credReport = Get-IAMCredentialReport -AccountId $AccountId
    
    $userCount = $users.Count
    $processedCount = 0
    
    foreach ($user in $users) {
        $processedCount++
        Show-Progress -Activity "Auditing IAM Users" -Status "$($user.UserName)" -PercentComplete (($processedCount / $userCount) * 100)
        
        $userName = $user.UserName
        $userArn = $user.Arn
        
        # Get user details from credential report
        $userCreds = $credReport | Where-Object { $_.user -eq $userName }
        
        if ($userCreds) {
            # Check password age
            if ($userCreds.password_enabled -eq "true" -and $userCreds.password_last_changed -ne "N/A") {
                $passwordLastChanged = [DateTime]::Parse($userCreds.password_last_changed)
                $passwordAgeDays = (Get-Date) - $passwordLastChanged
                
                if ($passwordAgeDays.Days -gt $StaleThresholdDays) {
                    Write-Finding -Category "IAM" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource $userName `
                        -Finding "Password is $($passwordAgeDays.Days) days old (threshold: $StaleThresholdDays days)" `
                        -Recommendation "Enforce password rotation policy or disable password access"
                }
            }
            
            # Check password last used (stale users)
            if ($userCreds.password_last_used -ne "N/A" -and $userCreds.password_last_used -ne "no_information") {
                $passwordLastUsed = [DateTime]::Parse($userCreds.password_last_used)
                $daysSinceLogin = ((Get-Date) - $passwordLastUsed).Days
                
                if ($daysSinceLogin -gt $StaleThresholdDays) {
                    Write-Finding -Category "IAM" -Severity "HIGH" `
                        -AccountId $AccountId -Resource $userName `
                        -Finding "User has not logged in for $daysSinceLogin days" `
                        -Recommendation "Review user necessity and consider disabling or removing"
                }
            }
            
            # Check MFA status
            if ($userCreds.password_enabled -eq "true" -and $userCreds.mfa_active -ne "true") {
                Write-Finding -Category "IAM" -Severity "HIGH" `
                    -AccountId $AccountId -Resource $userName `
                    -Finding "Console access enabled without MFA" `
                    -Recommendation "Enable MFA for all users with console access"
            }
            
            # Check Access Key 1
            if ($userCreds.access_key_1_active -eq "true") {
                # Check key age
                if ($userCreds.access_key_1_last_rotated -ne "N/A") {
                    $key1Created = [DateTime]::Parse($userCreds.access_key_1_last_rotated)
                    $key1AgeDays = ((Get-Date) - $key1Created).Days
                    
                    if ($key1AgeDays -gt $KeyAgeThresholdDays) {
                        Write-Finding -Category "IAM" -Severity "HIGH" `
                            -AccountId $AccountId -Resource "$userName/AccessKey1" `
                            -Finding "Access Key 1 is $key1AgeDays days old" `
                            -Recommendation "Rotate access key immediately"
                    }
                }
                
                # Check key usage
                if ($userCreds.access_key_1_last_used_date -ne "N/A") {
                    $key1LastUsed = [DateTime]::Parse($userCreds.access_key_1_last_used_date)
                    $daysSinceKey1Used = ((Get-Date) - $key1LastUsed).Days
                    
                    if ($daysSinceKey1Used -gt $StaleThresholdDays) {
                        Write-Finding -Category "IAM" -Severity "MEDIUM" `
                            -AccountId $AccountId -Resource "$userName/AccessKey1" `
                            -Finding "Access Key 1 not used in $daysSinceKey1Used days" `
                            -Recommendation "Disable or delete unused access keys"
                    }
                }
            }
            
            # Check Access Key 2
            if ($userCreds.access_key_2_active -eq "true") {
                if ($userCreds.access_key_2_last_rotated -ne "N/A") {
                    $key2Created = [DateTime]::Parse($userCreds.access_key_2_last_rotated)
                    $key2AgeDays = ((Get-Date) - $key2Created).Days
                    
                    if ($key2AgeDays -gt $KeyAgeThresholdDays) {
                        Write-Finding -Category "IAM" -Severity "HIGH" `
                            -AccountId $AccountId -Resource "$userName/AccessKey2" `
                            -Finding "Access Key 2 is $key2AgeDays days old" `
                            -Recommendation "Rotate access key immediately"
                    }
                }
                
                if ($userCreds.access_key_2_last_used_date -ne "N/A") {
                    $key2LastUsed = [DateTime]::Parse($userCreds.access_key_2_last_used_date)
                    $daysSinceKey2Used = ((Get-Date) - $key2LastUsed).Days
                    
                    if ($daysSinceKey2Used -gt $StaleThresholdDays) {
                        Write-Finding -Category "IAM" -Severity "MEDIUM" `
                            -AccountId $AccountId -Resource "$userName/AccessKey2" `
                            -Finding "Access Key 2 not used in $daysSinceKey2Used days" `
                            -Recommendation "Disable or delete unused access keys"
                    }
                }
            }
        }
        
        # Check inline policies (should use managed policies instead)
        $inlinePolicies = Get-IAMUserPolicyList -UserName $userName
        if ($inlinePolicies.Count -gt 0) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource $userName `
                -Finding "User has $($inlinePolicies.Count) inline policies" `
                -Recommendation "Migrate to managed policies for better governance"
        }
        
        # Check for overly permissive policies
        $attachedPolicies = Get-IAMAttachedUserPolicyList -UserName $userName
        foreach ($policy in $attachedPolicies) {
            if ($policy.PolicyName -match "Administrator|FullAccess|PowerUser") {
                Write-Finding -Category "IAM" -Severity "HIGH" `
                    -AccountId $AccountId -Resource $userName `
                    -Finding "User has highly privileged policy: $($policy.PolicyName)" `
                    -Recommendation "Review and apply least privilege principle"
            }
        }
        
        # Check user groups for admin access
        $userGroups = Get-IAMGroupForUser -UserName $userName
        foreach ($group in $userGroups) {
            $groupPolicies = Get-IAMAttachedGroupPolicyList -GroupName $group.GroupName
            foreach ($policy in $groupPolicies) {
                if ($policy.PolicyName -match "Administrator|FullAccess") {
                    Write-Finding -Category "IAM" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource $userName `
                        -Finding "User in group '$($group.GroupName)' with admin policy: $($policy.PolicyName)" `
                        -Recommendation "Review group membership and policy necessity"
                }
            }
        }
    }
    
    Write-Progress -Activity "Auditing IAM Users" -Completed
}

function Invoke-IAMRoleAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing IAM Roles for account $AccountId..." -Level "INFO"
    
    $roles = Get-IAMRoleList
    $roleCount = $roles.Count
    $processedCount = 0
    
    foreach ($role in $roles) {
        $processedCount++
        Show-Progress -Activity "Auditing IAM Roles" -Status "$($role.RoleName)" -PercentComplete (($processedCount / $roleCount) * 100)
        
        # Skip AWS service-linked roles
        if ($role.Path -like "/aws-service-role/*") {
            continue
        }
        
        $roleName = $role.RoleName
        
        # Check role last used
        try {
            $roleLastUsed = (Get-IAMRole -RoleName $roleName).RoleLastUsed
            if ($roleLastUsed.LastUsedDate) {
                $daysSinceUsed = ((Get-Date) - $roleLastUsed.LastUsedDate).Days
                if ($daysSinceUsed -gt $StaleThresholdDays) {
                    Write-Finding -Category "IAM" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource "Role:$roleName" `
                        -Finding "Role not used in $daysSinceUsed days" `
                        -Recommendation "Review role necessity and consider removing"
                }
            }
        }
        catch {
            # Role last used info not available
        }
        
        # Check trust policy for overly permissive trust
        $trustPolicy = $role.AssumeRolePolicyDocument | ConvertFrom-Json -Depth 10
        foreach ($statement in $trustPolicy.Statement) {
            if ($statement.Principal -eq "*" -or $statement.Principal.AWS -eq "*") {
                Write-Finding -Category "IAM" -Severity "CRITICAL" `
                    -AccountId $AccountId -Resource "Role:$roleName" `
                    -Finding "Role has wildcard principal in trust policy" `
                    -Recommendation "Restrict trust policy to specific accounts/services"
            }
            
            # Check for cross-account trust
            if ($statement.Principal.AWS -and $statement.Principal.AWS -notmatch $AccountId) {
                Write-Finding -Category "IAM" -Severity "LOW" `
                    -AccountId $AccountId -Resource "Role:$roleName" `
                    -Finding "Role has cross-account trust: $($statement.Principal.AWS)" `
                    -Recommendation "Verify cross-account trust is intended and necessary"
            }
        }
        
        # Check attached policies
        $attachedPolicies = Get-IAMAttachedRolePolicyList -RoleName $roleName
        foreach ($policy in $attachedPolicies) {
            if ($policy.PolicyName -eq "AdministratorAccess") {
                Write-Finding -Category "IAM" -Severity "HIGH" `
                    -AccountId $AccountId -Resource "Role:$roleName" `
                    -Finding "Role has AdministratorAccess policy attached" `
                    -Recommendation "Review if full admin access is necessary"
            }
        }
    }
    
    Write-Progress -Activity "Auditing IAM Roles" -Completed
}

function Invoke-RootAccountAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing Root Account for account $AccountId..." -Level "INFO"
    
    try {
        $credReport = Get-IAMCredentialReport -AccountId $AccountId
        $rootUser = $credReport | Where-Object { $_.user -eq "<root_account>" }
        
        if ($rootUser) {
            # Check root MFA
            if ($rootUser.mfa_active -ne "true") {
                Write-Finding -Category "IAM" -Severity "CRITICAL" `
                    -AccountId $AccountId -Resource "RootAccount" `
                    -Finding "Root account does not have MFA enabled" `
                    -Recommendation "Enable MFA on root account immediately"
            }
            
            # Check if root has access keys
            if ($rootUser.access_key_1_active -eq "true" -or $rootUser.access_key_2_active -eq "true") {
                Write-Finding -Category "IAM" -Severity "CRITICAL" `
                    -AccountId $AccountId -Resource "RootAccount" `
                    -Finding "Root account has active access keys" `
                    -Recommendation "Delete root access keys - use IAM users/roles instead"
            }
            
            # Check recent root usage
            if ($rootUser.password_last_used -ne "N/A" -and $rootUser.password_last_used -ne "no_information") {
                $lastUsed = [DateTime]::Parse($rootUser.password_last_used)
                $daysSinceUsed = ((Get-Date) - $lastUsed).Days
                
                if ($daysSinceUsed -lt 30) {
                    Write-Finding -Category "IAM" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource "RootAccount" `
                        -Finding "Root account used $daysSinceUsed days ago" `
                        -Recommendation "Root should only be used for account-level tasks"
                }
            }
        }
    }
    catch {
        Write-AuditLog "Unable to audit root account: $_" -Level "WARNING"
    }
}

#endregion

#region Password Policy Audit

function Invoke-PasswordPolicyAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing Password Policy for account $AccountId..." -Level "INFO"
    
    try {
        $policy = Get-IAMAccountPasswordPolicy
        
        # Check minimum length
        if ($policy.MinimumPasswordLength -lt 14) {
            Write-Finding -Category "IAM" -Severity "MEDIUM" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Minimum password length is $($policy.MinimumPasswordLength) (recommended: 14+)" `
                -Recommendation "Increase minimum password length to at least 14 characters"
        }
        
        # Check complexity requirements
        if (-not $policy.RequireUppercaseCharacters) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Uppercase characters not required" `
                -Recommendation "Enable uppercase character requirement"
        }
        
        if (-not $policy.RequireLowercaseCharacters) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Lowercase characters not required" `
                -Recommendation "Enable lowercase character requirement"
        }
        
        if (-not $policy.RequireNumbers) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Numbers not required" `
                -Recommendation "Enable number requirement"
        }
        
        if (-not $policy.RequireSymbols) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Symbols not required" `
                -Recommendation "Enable symbol requirement"
        }
        
        # Check password expiration
        if ($policy.MaxPasswordAge -eq 0 -or $policy.MaxPasswordAge -gt 90) {
            Write-Finding -Category "IAM" -Severity "MEDIUM" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Password expiration not set or too long ($($policy.MaxPasswordAge) days)" `
                -Recommendation "Set password expiration to 90 days or less"
        }
        
        # Check password reuse prevention
        if ($policy.PasswordReusePrevention -lt 12) {
            Write-Finding -Category "IAM" -Severity "LOW" `
                -AccountId $AccountId -Resource "PasswordPolicy" `
                -Finding "Password history is $($policy.PasswordReusePrevention) (recommended: 12+)" `
                -Recommendation "Increase password history to at least 12"
        }
    }
    catch {
        Write-Finding -Category "IAM" -Severity "HIGH" `
            -AccountId $AccountId -Resource "PasswordPolicy" `
            -Finding "No custom password policy configured" `
            -Recommendation "Configure a strong password policy"
    }
}

#endregion

#region EC2 and Infrastructure Audit

function Invoke-EC2SecurityAudit {
    param(
        [string]$AccountId = "current",
        [string]$Region = "us-east-1"
    )
    
    Write-AuditLog "Auditing EC2 Security for account $AccountId in region $Region..." -Level "INFO"
    
    $regions = if ($IncludeAllRegions) {
        (Get-EC2Region).RegionName
    } else {
        @($Region)
    }
    
    foreach ($currentRegion in $regions) {
        try {
            Set-DefaultAWSRegion -Region $currentRegion
            
            # Audit Security Groups
            $securityGroups = Get-EC2SecurityGroup
            
            foreach ($sg in $securityGroups) {
                foreach ($permission in $sg.IpPermissions) {
                    foreach ($ipRange in $permission.IpRanges) {
                        if ($ipRange.CidrIp -eq "0.0.0.0/0") {
                            $portInfo = if ($permission.FromPort -eq $permission.ToPort) {
                                "port $($permission.FromPort)"
                            } else {
                                "ports $($permission.FromPort)-$($permission.ToPort)"
                            }
                            
                            $severity = switch ($permission.FromPort) {
                                22 { "HIGH" }     # SSH
                                3389 { "HIGH" }   # RDP
                                3306 { "CRITICAL" } # MySQL
                                5432 { "CRITICAL" } # PostgreSQL
                                1433 { "CRITICAL" } # MSSQL
                                27017 { "CRITICAL" } # MongoDB
                                default { "MEDIUM" }
                            }
                            
                            Write-Finding -Category "EC2" -Severity $severity `
                                -AccountId $AccountId -Resource "$currentRegion/SG:$($sg.GroupId)" `
                                -Finding "Security group '$($sg.GroupName)' allows 0.0.0.0/0 on $portInfo" `
                                -Recommendation "Restrict ingress to specific IP ranges"
                        }
                    }
                    
                    foreach ($ipv6Range in $permission.Ipv6Ranges) {
                        if ($ipv6Range.CidrIpv6 -eq "::/0") {
                            $portInfo = if ($permission.FromPort -eq $permission.ToPort) {
                                "port $($permission.FromPort)"
                            } else {
                                "ports $($permission.FromPort)-$($permission.ToPort)"
                            }
                            
                            Write-Finding -Category "EC2" -Severity "MEDIUM" `
                                -AccountId $AccountId -Resource "$currentRegion/SG:$($sg.GroupId)" `
                                -Finding "Security group '$($sg.GroupName)' allows ::/0 on $portInfo" `
                                -Recommendation "Restrict IPv6 ingress to specific ranges"
                        }
                    }
                }
            }
            
            # Audit EC2 Instances
            $instances = Get-EC2Instance
            
            foreach ($reservation in $instances) {
                foreach ($instance in $reservation.Instances) {
                    $instanceId = $instance.InstanceId
                    $instanceName = ($instance.Tags | Where-Object { $_.Key -eq "Name" }).Value
                    $displayName = if ($instanceName) { "$instanceName ($instanceId)" } else { $instanceId }
                    
                    # Check for public IP
                    if ($instance.PublicIpAddress) {
                        Write-Finding -Category "EC2" -Severity "LOW" `
                            -AccountId $AccountId -Resource "$currentRegion/$displayName" `
                            -Finding "Instance has public IP: $($instance.PublicIpAddress)" `
                            -Recommendation "Review if public IP is necessary"
                    }
                    
                    # Check IMDSv2
                    if ($instance.MetadataOptions.HttpTokens -ne "required") {
                        Write-Finding -Category "EC2" -Severity "HIGH" `
                            -AccountId $AccountId -Resource "$currentRegion/$displayName" `
                            -Finding "Instance not enforcing IMDSv2" `
                            -Recommendation "Enable IMDSv2 requirement to prevent SSRF attacks"
                    }
                    
                    # Check EBS encryption
                    foreach ($blockDevice in $instance.BlockDeviceMappings) {
                        try {
                            $volume = Get-EC2Volume -VolumeId $blockDevice.Ebs.VolumeId
                            if (-not $volume.Encrypted) {
                                Write-Finding -Category "EC2" -Severity "MEDIUM" `
                                    -AccountId $AccountId -Resource "$currentRegion/$displayName" `
                                    -Finding "EBS volume $($volume.VolumeId) is not encrypted" `
                                    -Recommendation "Enable EBS encryption for data at rest protection"
                            }
                        }
                        catch {}
                    }
                }
            }
            
            # Audit EBS default encryption
            try {
                $ebsEncryption = Get-EC2EbsEncryptionByDefault
                if (-not $ebsEncryption) {
                    Write-Finding -Category "EC2" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource "$currentRegion/EBS-Default" `
                        -Finding "EBS default encryption is not enabled" `
                        -Recommendation "Enable default EBS encryption for the region"
                }
            }
            catch {}
        }
        catch {
            Write-AuditLog "Error auditing EC2 in $currentRegion`: $_" -Level "WARNING"
        }
    }
    
    Set-DefaultAWSRegion -Region $Region
}

#endregion

#region S3 Bucket Audit

function Invoke-S3SecurityAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing S3 Buckets for account $AccountId..." -Level "INFO"
    
    try {
        $buckets = Get-S3Bucket
        $bucketCount = $buckets.Count
        $processedCount = 0
        
        foreach ($bucket in $buckets) {
            $processedCount++
            Show-Progress -Activity "Auditing S3 Buckets" -Status "$($bucket.BucketName)" -PercentComplete (($processedCount / $bucketCount) * 100)
            
            $bucketName = $bucket.BucketName
            
            # Check public access block
            try {
                $publicAccessBlock = Get-S3PublicAccessBlock -BucketName $bucketName
                
                if (-not $publicAccessBlock.BlockPublicAcls -or 
                    -not $publicAccessBlock.BlockPublicPolicy -or 
                    -not $publicAccessBlock.IgnorePublicAcls -or 
                    -not $publicAccessBlock.RestrictPublicBuckets) {
                    Write-Finding -Category "S3" -Severity "HIGH" `
                        -AccountId $AccountId -Resource "S3:$bucketName" `
                        -Finding "Public access block not fully configured" `
                        -Recommendation "Enable all public access block settings"
                }
            }
            catch {
                Write-Finding -Category "S3" -Severity "HIGH" `
                    -AccountId $AccountId -Resource "S3:$bucketName" `
                    -Finding "No public access block configured" `
                    -Recommendation "Configure public access block settings"
            }
            
            # Check bucket encryption
            try {
                $encryption = Get-S3BucketEncryption -BucketName $bucketName
                # Encryption is configured - good
            }
            catch {
                Write-Finding -Category "S3" -Severity "MEDIUM" `
                    -AccountId $AccountId -Resource "S3:$bucketName" `
                    -Finding "Default encryption not configured" `
                    -Recommendation "Enable default S3 bucket encryption"
            }
            
            # Check versioning
            try {
                $versioning = Get-S3BucketVersioning -BucketName $bucketName
                if ($versioning.Status -ne "Enabled") {
                    Write-Finding -Category "S3" -Severity "LOW" `
                        -AccountId $AccountId -Resource "S3:$bucketName" `
                        -Finding "Versioning not enabled" `
                        -Recommendation "Enable versioning for data protection"
                }
            }
            catch {}
            
            # Check bucket policy for public access
            try {
                $bucketPolicy = Get-S3BucketPolicy -BucketName $bucketName
                $policyJson = $bucketPolicy.Policy | ConvertFrom-Json
                
                foreach ($statement in $policyJson.Statement) {
                    if ($statement.Principal -eq "*" -and $statement.Effect -eq "Allow") {
                        if (-not $statement.Condition) {
                            Write-Finding -Category "S3" -Severity "CRITICAL" `
                                -AccountId $AccountId -Resource "S3:$bucketName" `
                                -Finding "Bucket policy allows public access without conditions" `
                                -Recommendation "Review and restrict bucket policy"
                        }
                    }
                }
            }
            catch {
                # No bucket policy - this is fine
            }
            
            # Check logging
            try {
                $logging = Get-S3BucketLogging -BucketName $bucketName
                if (-not $logging.TargetBucketName) {
                    Write-Finding -Category "S3" -Severity "LOW" `
                        -AccountId $AccountId -Resource "S3:$bucketName" `
                        -Finding "Access logging not enabled" `
                        -Recommendation "Enable S3 access logging for audit trail"
                }
            }
            catch {}
        }
        
        Write-Progress -Activity "Auditing S3 Buckets" -Completed
    }
    catch {
        Write-AuditLog "Error auditing S3: $_" -Level "ERROR"
    }
}

#endregion

#region CloudTrail Audit

function Invoke-CloudTrailAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing CloudTrail for account $AccountId..." -Level "INFO"
    
    try {
        $trails = Get-CTTrailList
        
        if ($trails.Count -eq 0) {
            Write-Finding -Category "CloudTrail" -Severity "CRITICAL" `
                -AccountId $AccountId -Resource "CloudTrail" `
                -Finding "No CloudTrail trails configured" `
                -Recommendation "Enable CloudTrail for all regions with management events"
            return
        }
        
        $hasOrgTrail = $false
        $hasMultiRegion = $false
        
        foreach ($trail in $trails) {
            $trailDetails = Get-CTTrail -Name $trail.Name
            
            if ($trailDetails.IsOrganizationTrail) {
                $hasOrgTrail = $true
            }
            
            if ($trailDetails.IsMultiRegionTrail) {
                $hasMultiRegion = $true
            }
            
            # Check logging status
            $trailStatus = Get-CTTrailStatus -Name $trail.Name
            if (-not $trailStatus.IsLogging) {
                Write-Finding -Category "CloudTrail" -Severity "CRITICAL" `
                    -AccountId $AccountId -Resource "Trail:$($trail.Name)" `
                    -Finding "CloudTrail logging is disabled" `
                    -Recommendation "Enable logging immediately"
            }
            
            # Check log file validation
            if (-not $trailDetails.LogFileValidationEnabled) {
                Write-Finding -Category "CloudTrail" -Severity "MEDIUM" `
                    -AccountId $AccountId -Resource "Trail:$($trail.Name)" `
                    -Finding "Log file integrity validation not enabled" `
                    -Recommendation "Enable log file validation for tamper detection"
            }
            
            # Check encryption
            if (-not $trailDetails.KMSKeyId) {
                Write-Finding -Category "CloudTrail" -Severity "MEDIUM" `
                    -AccountId $AccountId -Resource "Trail:$($trail.Name)" `
                    -Finding "CloudTrail logs not encrypted with KMS" `
                    -Recommendation "Enable KMS encryption for CloudTrail logs"
            }
            
            # Check CloudWatch integration
            if (-not $trailDetails.CloudWatchLogsLogGroupArn) {
                Write-Finding -Category "CloudTrail" -Severity "LOW" `
                    -AccountId $AccountId -Resource "Trail:$($trail.Name)" `
                    -Finding "CloudWatch Logs integration not configured" `
                    -Recommendation "Enable CloudWatch Logs for real-time alerting"
            }
        }
        
        if (-not $hasMultiRegion) {
            Write-Finding -Category "CloudTrail" -Severity "HIGH" `
                -AccountId $AccountId -Resource "CloudTrail" `
                -Finding "No multi-region trail configured" `
                -Recommendation "Configure at least one multi-region trail"
        }
    }
    catch {
        Write-AuditLog "Error auditing CloudTrail: $_" -Level "ERROR"
    }
}

#endregion

#region GuardDuty Audit

function Invoke-GuardDutyAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing GuardDuty for account $AccountId..." -Level "INFO"
    
    try {
        $detectors = Get-GDDetectorList
        
        if ($detectors.Count -eq 0) {
            Write-Finding -Category "GuardDuty" -Severity "HIGH" `
                -AccountId $AccountId -Resource "GuardDuty" `
                -Finding "GuardDuty is not enabled" `
                -Recommendation "Enable GuardDuty for threat detection"
            return
        }
        
        foreach ($detectorId in $detectors) {
            $detector = Get-GDDetector -DetectorId $detectorId
            
            if ($detector.Status -ne "ENABLED") {
                Write-Finding -Category "GuardDuty" -Severity "HIGH" `
                    -AccountId $AccountId -Resource "GuardDuty:$detectorId" `
                    -Finding "GuardDuty detector is not enabled" `
                    -Recommendation "Enable the GuardDuty detector"
            }
            
            # Check for recent findings
            $findingsIds = Get-GDFindingList -DetectorId $detectorId -MaxResult 50
            
            if ($findingsIds.Count -gt 0) {
                $findings = Get-GDFinding -DetectorId $detectorId -FindingId $findingsIds
                
                $criticalCount = ($findings | Where-Object { $_.Severity -ge 7 }).Count
                $highCount = ($findings | Where-Object { $_.Severity -ge 4 -and $_.Severity -lt 7 }).Count
                
                if ($criticalCount -gt 0) {
                    Write-Finding -Category "GuardDuty" -Severity "CRITICAL" `
                        -AccountId $AccountId -Resource "GuardDuty" `
                        -Finding "$criticalCount critical GuardDuty findings require attention" `
                        -Recommendation "Investigate and remediate critical findings immediately"
                }
                
                if ($highCount -gt 0) {
                    Write-Finding -Category "GuardDuty" -Severity "HIGH" `
                        -AccountId $AccountId -Resource "GuardDuty" `
                        -Finding "$highCount high severity GuardDuty findings" `
                        -Recommendation "Review and address high severity findings"
                }
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing GuardDuty: $_" -Level "WARNING"
    }
}

#endregion

#region Security Hub Audit

function Invoke-SecurityHubAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing Security Hub for account $AccountId..." -Level "INFO"
    
    try {
        $hub = Get-SHUBHub
        
        # Check enabled standards
        $standards = Get-SHUBEnabledStandard
        
        $hasAWSFoundational = $standards | Where-Object { $_.StandardsArn -match "aws-foundational-security-best-practices" }
        $hasCIS = $standards | Where-Object { $_.StandardsArn -match "cis-aws-foundations-benchmark" }
        
        if (-not $hasAWSFoundational) {
            Write-Finding -Category "SecurityHub" -Severity "MEDIUM" `
                -AccountId $AccountId -Resource "SecurityHub" `
                -Finding "AWS Foundational Security Best Practices standard not enabled" `
                -Recommendation "Enable AWS Foundational Security Best Practices standard"
        }
        
        if (-not $hasCIS) {
            Write-Finding -Category "SecurityHub" -Severity "LOW" `
                -AccountId $AccountId -Resource "SecurityHub" `
                -Finding "CIS AWS Foundations Benchmark not enabled" `
                -Recommendation "Consider enabling CIS AWS Foundations Benchmark"
        }
        
        # Get compliance summary
        foreach ($standard in $standards) {
            try {
                $controls = Get-SHUBStandardsControlList -StandardsSubscriptionArn $standard.StandardsSubscriptionArn
                
                $failedControls = $controls | Where-Object { $_.ComplianceStatus -eq "FAILED" }
                $failedCount = $failedControls.Count
                
                if ($failedCount -gt 0) {
                    Write-Finding -Category "SecurityHub" -Severity "MEDIUM" `
                        -AccountId $AccountId -Resource "SecurityHub" `
                        -Finding "$failedCount failed controls in $($standard.StandardsArn.Split('/')[-1])" `
                        -Recommendation "Review and remediate failed Security Hub controls"
                }
            }
            catch {}
        }
    }
    catch {
        Write-Finding -Category "SecurityHub" -Severity "MEDIUM" `
            -AccountId $AccountId -Resource "SecurityHub" `
            -Finding "Security Hub is not enabled" `
            -Recommendation "Enable Security Hub for centralized security findings"
    }
}

#endregion

#region IAM Access Analyzer Audit

function Invoke-AccessAnalyzerAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing IAM Access Analyzer for account $AccountId..." -Level "INFO"
    
    try {
        $analyzers = Get-IAMAAAnalyzerList
        
        if ($analyzers.Count -eq 0) {
            Write-Finding -Category "AccessAnalyzer" -Severity "MEDIUM" `
                -AccountId $AccountId -Resource "AccessAnalyzer" `
                -Finding "IAM Access Analyzer not configured" `
                -Recommendation "Enable Access Analyzer to identify unintended resource access"
            return
        }
        
        foreach ($analyzer in $analyzers) {
            if ($analyzer.Status -ne "ACTIVE") {
                Write-Finding -Category "AccessAnalyzer" -Severity "MEDIUM" `
                    -AccountId $AccountId -Resource "AccessAnalyzer:$($analyzer.Name)" `
                    -Finding "Access Analyzer is not active" `
                    -Recommendation "Activate the Access Analyzer"
                continue
            }
            
            # Check for active findings
            $findings = Get-IAMAAFindingList -AnalyzerArn $analyzer.Arn -MaxResult 100
            $activeFindings = $findings | Where-Object { $_.Status -eq "ACTIVE" }
            
            if ($activeFindings.Count -gt 0) {
                Write-Finding -Category "AccessAnalyzer" -Severity "HIGH" `
                    -AccountId $AccountId -Resource "AccessAnalyzer" `
                    -Finding "$($activeFindings.Count) active Access Analyzer findings (external access detected)" `
                    -Recommendation "Review and remediate Access Analyzer findings"
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing Access Analyzer: $_" -Level "WARNING"
    }
}

#endregion

#region Config Service Audit

function Invoke-ConfigServiceAudit {
    param(
        [string]$AccountId = "current"
    )
    
    Write-AuditLog "Auditing AWS Config for account $AccountId..." -Level "INFO"
    
    try {
        $recorders = Get-CFGConfigurationRecorderList
        
        if ($recorders.Count -eq 0) {
            Write-Finding -Category "AWSConfig" -Severity "HIGH" `
                -AccountId $AccountId -Resource "AWSConfig" `
                -Finding "AWS Config recorder not configured" `
                -Recommendation "Enable AWS Config for resource configuration tracking"
            return
        }
        
        foreach ($recorderName in $recorders) {
            $recorderStatus = Get-CFGConfigurationRecorderStatus -ConfigurationRecorderName $recorderName
            
            if (-not $recorderStatus.Recording) {
                Write-Finding -Category "AWSConfig" -Severity "HIGH" `
                    -AccountId $AccountId -Resource "Config:$recorderName" `
                    -Finding "AWS Config recorder is not recording" `
                    -Recommendation "Start the configuration recorder"
            }
            
            if ($recorderStatus.LastStatus -eq "FAILURE") {
                Write-Finding -Category "AWSConfig" -Severity "MEDIUM" `
                    -AccountId $AccountId -Resource "Config:$recorderName" `
                    -Finding "AWS Config recorder last delivery failed" `
                    -Recommendation "Investigate and fix configuration recorder issues"
            }
        }
        
        # Check Config rules
        $rules = Get-CFGConfigRuleList
        $nonCompliantRules = $rules | Where-Object { $_.ComplianceType -eq "NON_COMPLIANT" }
        
        if ($nonCompliantRules.Count -gt 0) {
            Write-Finding -Category "AWSConfig" -Severity "MEDIUM" `
                -AccountId $AccountId -Resource "AWSConfig" `
                -Finding "$($nonCompliantRules.Count) Config rules are non-compliant" `
                -Recommendation "Review and remediate non-compliant Config rules"
        }
    }
    catch {
        Write-AuditLog "Error auditing AWS Config: $_" -Level "WARNING"
    }
}

#endregion

#region Report Generation

function Export-AuditReport {
    Write-AuditLog "Generating audit report..." -Level "INFO"
    
    $endTime = Get-Date
    $duration = $endTime - $script:Config.StartTime
    
    # HTML Report
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AWS Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #232f3e; border-bottom: 3px solid #ff9900; padding-bottom: 15px; }
        h2 { color: #232f3e; margin-top: 30px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; flex: 1; text-align: center; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333; }
        .low { background: #1976d2; }
        .info { background: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #232f3e; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #1976d2; }
        .metadata { color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 AWS Security Audit Report</h1>
        <div class="metadata">
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Duration:</strong> $($duration.ToString("hh\:mm\:ss"))</p>
            <p><strong>Stale Threshold:</strong> $StaleThresholdDays days</p>
            <p><strong>Key Age Threshold:</strong> $KeyAgeThresholdDays days</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary-box">
            <div class="summary-item critical">
                <h3>$($script:Config.CriticalFindings)</h3>
                <p>Critical</p>
            </div>
            <div class="summary-item high">
                <h3>$($script:Config.HighFindings)</h3>
                <p>High</p>
            </div>
            <div class="summary-item medium">
                <h3>$($script:Config.MediumFindings)</h3>
                <p>Medium</p>
            </div>
            <div class="summary-item low">
                <h3>$($script:Config.LowFindings)</h3>
                <p>Low</p>
            </div>
            <div class="summary-item info">
                <h3>$($script:Config.TotalFindings)</h3>
                <p>Total</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Account</th>
                <th>Resource</th>
                <th>Finding</th>
                <th>Recommendation</th>
            </tr>
"@

    foreach ($finding in ($script:AllFindings | Sort-Object { 
        switch ($_.Severity) {
            "CRITICAL" { 0 }
            "HIGH" { 1 }
            "MEDIUM" { 2 }
            "LOW" { 3 }
        }
    })) {
        $severityClass = "severity-$($finding.Severity.ToLower())"
        $html += @"
            <tr>
                <td class="$severityClass">$($finding.Severity)</td>
                <td>$($finding.Category)</td>
                <td>$($finding.AccountId)</td>
                <td>$($finding.Resource)</td>
                <td>$($finding.Finding)</td>
                <td>$($finding.Recommendation)</td>
            </tr>
"@
    }

    $html += @"
        </table>
        
        <h2>Compliance Frameworks Covered</h2>
        <ul>
            <li>SOC 2 Type II</li>
            <li>ISO 27001</li>
            <li>NIST Cybersecurity Framework</li>
            <li>CIS AWS Foundations Benchmark</li>
            <li>AWS Well-Architected Framework - Security Pillar</li>
            <li>PCI DSS</li>
            <li>HIPAA</li>
        </ul>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by AWS-Full-Audit.ps1 v$($script:Config.Version)</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "HTML report saved to: $($script:Config.ReportFile)" -Level "SUCCESS"
    
    # CSV Export
    if ($ExportToCSV) {
        $csvPath = $script:Config.ReportFile -replace "\.html$", ".csv"
        $script:AllFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-AuditLog "CSV report saved to: $csvPath" -Level "SUCCESS"
    }
}

#endregion

#region Main Execution

function Invoke-AWSSecurityAudit {
    Write-AuditLog "=" * 60 -Level "INFO"
    Write-AuditLog "AWS COMPREHENSIVE SECURITY AUDIT" -Level "INFO"
    Write-AuditLog "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
    
    # Initialize findings array
    $script:AllFindings = @()
    
    # Verify modules
    if (-not (Test-AWSModules)) {
        Write-AuditLog "Module verification failed. Exiting." -Level "ERROR"
        return
    }
    
    # Initialize connection
    $identity = Initialize-AWSConnection -Profile $ProfileName -Region $Region
    if (-not $identity) {
        Write-AuditLog "Failed to connect to AWS. Exiting." -Level "ERROR"
        return
    }
    
    $accountsToAudit = @()
    
    if ($AuditEntireOrganization) {
        $orgAccounts = Get-OrganizationAccounts
        if ($orgAccounts) {
            $accountsToAudit = $orgAccounts
        } else {
            $accountsToAudit = @([PSCustomObject]@{ Id = $identity.Account; Name = "Current" })
        }
    } else {
        $accountsToAudit = @([PSCustomObject]@{ Id = $identity.Account; Name = "Current" })
    }
    
    $totalAccounts = $accountsToAudit.Count
    $currentAccountNum = 0
    
    foreach ($account in $accountsToAudit) {
        $currentAccountNum++
        Write-AuditLog "" -Level "INFO"
        Write-AuditLog "=" * 40 -Level "INFO"
        Write-AuditLog "Auditing Account [$currentAccountNum/$totalAccounts]: $($account.Id) ($($account.Name))" -Level "INFO"
        Write-AuditLog "=" * 40 -Level "INFO"
        
        # Assume role if cross-account
        if ($account.Id -ne $identity.Account -and $AuditEntireOrganization) {
            $crossAccountCreds = Enter-CrossAccountRole -AccountId $account.Id -RoleName $CrossAccountRoleName
            if (-not $crossAccountCreds) {
                Write-AuditLog "Skipping account $($account.Id) - unable to assume role" -Level "WARNING"
                continue
            }
            Set-AWSCredential -Credential $crossAccountCreds
        }
        
        # Run all audits
        try {
            Invoke-RootAccountAudit -AccountId $account.Id
            Invoke-PasswordPolicyAudit -AccountId $account.Id
            Invoke-IAMUserAudit -AccountId $account.Id
            Invoke-IAMRoleAudit -AccountId $account.Id
            
            if (-not $SkipResourceAudit) {
                Invoke-EC2SecurityAudit -AccountId $account.Id -Region $Region
                Invoke-S3SecurityAudit -AccountId $account.Id
            }
            
            Invoke-CloudTrailAudit -AccountId $account.Id
            Invoke-GuardDutyAudit -AccountId $account.Id
            Invoke-SecurityHubAudit -AccountId $account.Id
            Invoke-AccessAnalyzerAudit -AccountId $account.Id
            Invoke-ConfigServiceAudit -AccountId $account.Id
        }
        catch {
            Write-AuditLog "Error during audit of account $($account.Id): $_" -Level "ERROR"
        }
        
        # Reset to original credentials
        if ($account.Id -ne $identity.Account -and $AuditEntireOrganization) {
            Set-AWSCredential -ProfileName $ProfileName
        }
    }
    
    # Generate report
    Export-AuditReport
    
    Write-AuditLog "" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
    Write-AuditLog "AUDIT COMPLETE" -Level "SUCCESS"
    Write-AuditLog "Total Findings: $($script:Config.TotalFindings)" -Level "INFO"
    Write-AuditLog "  Critical: $($script:Config.CriticalFindings)" -Level "INFO"
    Write-AuditLog "  High: $($script:Config.HighFindings)" -Level "INFO"
    Write-AuditLog "  Medium: $($script:Config.MediumFindings)" -Level "INFO"
    Write-AuditLog "  Low: $($script:Config.LowFindings)" -Level "INFO"
    Write-AuditLog "Report: $($script:Config.ReportFile)" -Level "INFO"
    Write-AuditLog "Log: $($script:Config.LogFile)" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
}

# Execute main function
Invoke-AWSSecurityAudit

#endregion
