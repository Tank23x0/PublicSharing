<#
.SYNOPSIS
    Comprehensive Active Directory Security Audit Script
    
.DESCRIPTION
    Performs thorough security audits of Active Directory environments including:
    - User account analysis (stale, disabled, locked)
    - Password policy compliance
    - Privileged group membership
    - Service accounts audit
    - Computer account analysis
    - Group Policy review
    - Trust relationship audit
    - Security configuration assessment
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - Active Directory PowerShell module (RSAT)
    - Domain Admin or equivalent read permissions
    - PowerShell 5.1 or higher
    
.NOTES
    Run from a domain-joined machine with appropriate permissions
#>

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainController,
    
    [Parameter(Mandatory = $false)]
    [string]$Domain,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\AD-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [int]$PasswordAgeThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDetailedGPO,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipLargeQueries
)

#region Configuration and Initialization

$script:Config = @{
    ScriptName = "AD-Full-Audit"
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
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "AD-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "AD-Audit-Report_$timestamp.html"

# Initialize findings array
$script:AllFindings = @()

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
        [string]$Object,
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
        Object = $Object
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

#region Module and Connection Verification

function Test-ADModule {
    Write-AuditLog "Checking Active Directory module..." -Level "INFO"
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-AuditLog "Active Directory module loaded successfully" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-AuditLog "Failed to load Active Directory module. Install RSAT tools." -Level "ERROR"
        return $false
    }
}

function Initialize-ADConnection {
    Write-AuditLog "Initializing Active Directory connection..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Test connection by getting domain info
        $domainInfo = Get-ADDomain @params
        $forestInfo = Get-ADForest @params
        
        $script:DomainDN = $domainInfo.DistinguishedName
        $script:DomainName = $domainInfo.DNSRoot
        $script:ForestName = $forestInfo.Name
        $script:PDCEmulator = $domainInfo.PDCEmulator
        
        Write-AuditLog "Connected to domain: $($script:DomainName)" -Level "SUCCESS"
        Write-AuditLog "Forest: $($script:ForestName)" -Level "INFO"
        Write-AuditLog "PDC Emulator: $($script:PDCEmulator)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect to Active Directory: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region Domain and Forest Audit

function Invoke-DomainInfoAudit {
    Write-AuditLog "Auditing Domain Information..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        $domain = Get-ADDomain @params
        $forest = Get-ADForest @params
        
        # Check domain functional level
        $domainLevel = $domain.DomainMode
        $forestLevel = $forest.ForestMode
        
        $currentVersions = @("Windows2016Domain", "Windows2019Domain", "Windows2022Domain")
        if ($domainLevel -notin $currentVersions) {
            Write-Finding -Category "Domain" -Severity "MEDIUM" `
                -Object "Domain Functional Level" `
                -Finding "Domain functional level is $domainLevel (older version)" `
                -Recommendation "Consider upgrading to Windows Server 2016 or higher functional level"
        }
        
        # Check for trusts
        $trusts = Get-ADTrust -Filter * @params -ErrorAction SilentlyContinue
        foreach ($trust in $trusts) {
            if ($trust.TrustDirection -eq "Bidirectional" -or $trust.TrustDirection -eq "Inbound") {
                Write-Finding -Category "Trusts" -Severity "LOW" `
                    -Object "Trust: $($trust.Name)" `
                    -Finding "Trust relationship exists: $($trust.Name) ($($trust.TrustDirection))" `
                    -Recommendation "Review trust necessity and ensure proper security controls"
            }
            
            if (-not $trust.SelectiveAuthentication) {
                Write-Finding -Category "Trusts" -Severity "MEDIUM" `
                    -Object "Trust: $($trust.Name)" `
                    -Finding "Trust does not use selective authentication" `
                    -Recommendation "Enable selective authentication to limit access"
            }
            
            if ($trust.TrustType -eq "External" -and -not $trust.SIDFilteringQuarantined) {
                Write-Finding -Category "Trusts" -Severity "HIGH" `
                    -Object "Trust: $($trust.Name)" `
                    -Finding "SID filtering is not enabled on external trust" `
                    -Recommendation "Enable SID filtering to prevent SID history attacks"
            }
        }
        
        Write-AuditLog "Domain information audit complete" -Level "SUCCESS"
    }
    catch {
        Write-AuditLog "Error during domain audit: $_" -Level "ERROR"
    }
}

#endregion

#region User Account Audit

function Invoke-UserAccountAudit {
    Write-AuditLog "Auditing User Accounts..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Get all users with relevant properties
        $users = Get-ADUser -Filter * -Properties `
            SamAccountName, DisplayName, Enabled, LastLogonDate, PasswordLastSet, `
            PasswordNeverExpires, PasswordNotRequired, PasswordExpired, `
            LockedOut, AccountExpirationDate, WhenCreated, Description, `
            MemberOf, ServicePrincipalName, AdminCount, UserAccountControl, `
            msDS-UserPasswordExpiryTimeComputed, LastBadPasswordAttempt, `
            BadPwdCount, LogonCount @params
        
        $totalUsers = $users.Count
        $processedUsers = 0
        
        # Statistics
        $enabledUsers = 0
        $disabledUsers = 0
        $staleUsers = 0
        $neverLoggedIn = 0
        $passwordNeverExpires = 0
        $passwordNotRequired = 0
        $lockedOut = 0
        
        $thresholdDate = (Get-Date).AddDays(-$StaleThresholdDays)
        $passwordThresholdDate = (Get-Date).AddDays(-$PasswordAgeThresholdDays)
        
        foreach ($user in $users) {
            $processedUsers++
            if ($processedUsers % 100 -eq 0) {
                Show-Progress -Activity "Auditing User Accounts" -Status "$processedUsers of $totalUsers" -PercentComplete (($processedUsers / $totalUsers) * 100)
            }
            
            $userName = $user.SamAccountName
            
            # Count statistics
            if ($user.Enabled) { $enabledUsers++ } else { $disabledUsers++ }
            if ($user.LockedOut) { $lockedOut++ }
            if ($user.PasswordNeverExpires) { $passwordNeverExpires++ }
            if ($user.PasswordNotRequired) { $passwordNotRequired++ }
            
            # Skip disabled accounts for some checks
            if (-not $user.Enabled) { continue }
            
            # Check for stale accounts (no login in X days)
            if ($user.LastLogonDate) {
                if ($user.LastLogonDate -lt $thresholdDate) {
                    $daysSinceLogin = ((Get-Date) - $user.LastLogonDate).Days
                    $staleUsers++
                    
                    Write-Finding -Category "Users" -Severity "MEDIUM" `
                        -Object $userName `
                        -Finding "User has not logged in for $daysSinceLogin days (last: $($user.LastLogonDate.ToString('yyyy-MM-dd')))" `
                        -Recommendation "Review account necessity and consider disabling"
                }
            }
            else {
                $neverLoggedIn++
                if ($user.WhenCreated -lt $thresholdDate) {
                    Write-Finding -Category "Users" -Severity "MEDIUM" `
                        -Object $userName `
                        -Finding "User has never logged in (created: $($user.WhenCreated.ToString('yyyy-MM-dd')))" `
                        -Recommendation "Verify account is needed and user has received credentials"
                }
            }
            
            # Check password age
            if ($user.PasswordLastSet -and $user.PasswordLastSet -lt $passwordThresholdDate) {
                $passwordAgeDays = ((Get-Date) - $user.PasswordLastSet).Days
                
                Write-Finding -Category "Users" -Severity "MEDIUM" `
                    -Object $userName `
                    -Finding "Password is $passwordAgeDays days old (last set: $($user.PasswordLastSet.ToString('yyyy-MM-dd')))" `
                    -Recommendation "Enforce password change or review account"
            }
            
            # Check for password never expires (non-service accounts)
            if ($user.PasswordNeverExpires -and -not $user.ServicePrincipalName) {
                Write-Finding -Category "Users" -Severity "HIGH" `
                    -Object $userName `
                    -Finding "Password set to never expire (non-service account)" `
                    -Recommendation "Remove 'Password never expires' flag or convert to service account"
            }
            
            # Check for password not required
            if ($user.PasswordNotRequired) {
                Write-Finding -Category "Users" -Severity "CRITICAL" `
                    -Object $userName `
                    -Finding "Password is not required for this account" `
                    -Recommendation "Remove 'Password not required' flag immediately"
            }
            
            # Check for locked out accounts
            if ($user.LockedOut) {
                Write-Finding -Category "Users" -Severity "LOW" `
                    -Object $userName `
                    -Finding "Account is currently locked out (bad attempts: $($user.BadPwdCount))" `
                    -Recommendation "Investigate lockout reason and unlock if legitimate"
            }
            
            # Check AdminCount (privileged)
            if ($user.AdminCount -eq 1 -and $user.Enabled) {
                # Will be checked in privileged group audit
            }
            
            # Check for accounts with Kerberos pre-auth disabled (AS-REP roastable)
            $uac = $user.UserAccountControl
            if ($uac -band 0x400000) { # DONT_REQ_PREAUTH
                Write-Finding -Category "Users" -Severity "HIGH" `
                    -Object $userName `
                    -Finding "Kerberos pre-authentication is disabled (AS-REP roastable)" `
                    -Recommendation "Enable Kerberos pre-authentication unless specifically required"
            }
            
            # Check for reversible encryption
            if ($uac -band 0x80) { # ENCRYPTED_TEXT_PWD_ALLOWED
                Write-Finding -Category "Users" -Severity "HIGH" `
                    -Object $userName `
                    -Finding "Reversible encryption is enabled" `
                    -Recommendation "Disable reversible encryption - passwords can be recovered"
            }
            
            # Check for DES encryption
            if ($uac -band 0x200000) { # USE_DES_KEY_ONLY
                Write-Finding -Category "Users" -Severity "MEDIUM" `
                    -Object $userName `
                    -Finding "DES encryption is enabled" `
                    -Recommendation "Disable DES encryption - use AES instead"
            }
        }
        
        Write-Progress -Activity "Auditing User Accounts" -Completed
        
        Write-AuditLog "User Account Statistics:" -Level "INFO"
        Write-AuditLog "  Total Users: $totalUsers" -Level "INFO"
        Write-AuditLog "  Enabled: $enabledUsers" -Level "INFO"
        Write-AuditLog "  Disabled: $disabledUsers" -Level "INFO"
        Write-AuditLog "  Stale ($StaleThresholdDays+ days): $staleUsers" -Level "INFO"
        Write-AuditLog "  Never Logged In: $neverLoggedIn" -Level "INFO"
        Write-AuditLog "  Password Never Expires: $passwordNeverExpires" -Level "INFO"
        Write-AuditLog "  Password Not Required: $passwordNotRequired" -Level "INFO"
        Write-AuditLog "  Locked Out: $lockedOut" -Level "INFO"
        
        # Store for report
        $script:UserStats = @{
            Total = $totalUsers
            Enabled = $enabledUsers
            Disabled = $disabledUsers
            Stale = $staleUsers
            NeverLoggedIn = $neverLoggedIn
            PasswordNeverExpires = $passwordNeverExpires
            PasswordNotRequired = $passwordNotRequired
            LockedOut = $lockedOut
        }
    }
    catch {
        Write-AuditLog "Error during user audit: $_" -Level "ERROR"
    }
}

#endregion

#region Privileged Group Audit

function Invoke-PrivilegedGroupAudit {
    Write-AuditLog "Auditing Privileged Groups..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    # High-privilege groups to audit
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Server Operators",
        "Print Operators",
        "DnsAdmins",
        "Group Policy Creator Owners",
        "Cert Publishers"
    )
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $group = Get-ADGroup -Identity $groupName @params -ErrorAction SilentlyContinue
            if (-not $group) { continue }
            
            $members = Get-ADGroupMember -Identity $groupName @params -Recursive -ErrorAction SilentlyContinue
            $memberCount = ($members | Measure-Object).Count
            
            Write-AuditLog "  $groupName`: $memberCount members" -Level "INFO"
            
            # Check each member
            foreach ($member in $members) {
                if ($member.objectClass -eq "user") {
                    $user = Get-ADUser -Identity $member.SamAccountName -Properties Enabled, LastLogonDate, PasswordLastSet, Description @params
                    
                    # Disabled admin account
                    if (-not $user.Enabled) {
                        Write-Finding -Category "Privileged Access" -Severity "LOW" `
                            -Object "$($user.SamAccountName) in $groupName" `
                            -Finding "Disabled user is member of privileged group" `
                            -Recommendation "Remove disabled users from privileged groups"
                        continue
                    }
                    
                    # Stale admin account
                    if ($user.LastLogonDate -and $user.LastLogonDate -lt (Get-Date).AddDays(-$StaleThresholdDays)) {
                        Write-Finding -Category "Privileged Access" -Severity "HIGH" `
                            -Object "$($user.SamAccountName) in $groupName" `
                            -Finding "Privileged user has not logged in for $([int]((Get-Date) - $user.LastLogonDate).Days) days" `
                            -Recommendation "Review privileged access necessity"
                    }
                    
                    # Old password on admin
                    if ($user.PasswordLastSet -and $user.PasswordLastSet -lt (Get-Date).AddDays(-$PasswordAgeThresholdDays)) {
                        Write-Finding -Category "Privileged Access" -Severity "MEDIUM" `
                            -Object "$($user.SamAccountName) in $groupName" `
                            -Finding "Privileged user password is $([int]((Get-Date) - $user.PasswordLastSet).Days) days old" `
                            -Recommendation "Enforce password change for privileged accounts"
                    }
                }
            }
            
            # Excessive membership warnings
            if ($groupName -eq "Domain Admins" -and $memberCount -gt 5) {
                Write-Finding -Category "Privileged Access" -Severity "MEDIUM" `
                    -Object "Domain Admins" `
                    -Finding "Domain Admins has $memberCount members (recommended: <5)" `
                    -Recommendation "Reduce Domain Admins membership to essential personnel only"
            }
            
            if ($groupName -eq "Enterprise Admins" -and $memberCount -gt 3) {
                Write-Finding -Category "Privileged Access" -Severity "MEDIUM" `
                    -Object "Enterprise Admins" `
                    -Finding "Enterprise Admins has $memberCount members (recommended: <3)" `
                    -Recommendation "Enterprise Admins should be minimal - use only when needed"
            }
            
            if ($groupName -eq "Schema Admins" -and $memberCount -gt 0) {
                Write-Finding -Category "Privileged Access" -Severity "MEDIUM" `
                    -Object "Schema Admins" `
                    -Finding "Schema Admins has $memberCount members (recommended: 0)" `
                    -Recommendation "Schema Admins should be empty unless making schema changes"
            }
        }
        catch {
            Write-AuditLog "Error auditing group $groupName`: $_" -Level "WARNING"
        }
    }
}

#endregion

#region Service Account Audit

function Invoke-ServiceAccountAudit {
    Write-AuditLog "Auditing Service Accounts..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Find accounts with SPNs (service accounts)
        $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties `
            SamAccountName, ServicePrincipalName, Enabled, PasswordLastSet, `
            PasswordNeverExpires, Description, MemberOf, LastLogonDate, `
            TrustedForDelegation, TrustedToAuthForDelegation, `
            msDS-AllowedToDelegateTo @params
        
        Write-AuditLog "Found $($serviceAccounts.Count) service accounts (accounts with SPNs)" -Level "INFO"
        
        foreach ($svc in $serviceAccounts) {
            $svcName = $svc.SamAccountName
            
            if (-not $svc.Enabled) { continue }
            
            # Kerberoastable accounts
            Write-Finding -Category "Service Accounts" -Severity "LOW" `
                -Object $svcName `
                -Finding "Service account is Kerberoastable (has SPN)" `
                -Recommendation "Use Group Managed Service Accounts (gMSA) where possible"
            
            # Old password
            if ($svc.PasswordLastSet -lt (Get-Date).AddDays(-365)) {
                $passwordAge = [int]((Get-Date) - $svc.PasswordLastSet).Days
                Write-Finding -Category "Service Accounts" -Severity "HIGH" `
                    -Object $svcName `
                    -Finding "Service account password is $passwordAge days old" `
                    -Recommendation "Rotate service account password or migrate to gMSA"
            }
            
            # Unconstrained delegation
            if ($svc.TrustedForDelegation) {
                Write-Finding -Category "Service Accounts" -Severity "CRITICAL" `
                    -Object $svcName `
                    -Finding "Service account has unconstrained delegation enabled" `
                    -Recommendation "Remove unconstrained delegation - use constrained or resource-based"
            }
            
            # Constrained delegation with protocol transition
            if ($svc.TrustedToAuthForDelegation) {
                Write-Finding -Category "Service Accounts" -Severity "HIGH" `
                    -Object $svcName `
                    -Finding "Service account can perform protocol transition" `
                    -Recommendation "Review if protocol transition is necessary"
            }
            
            # Check for admin group membership
            $adminGroups = @("Domain Admins", "Administrators", "Enterprise Admins")
            foreach ($adminGroup in $adminGroups) {
                if ($svc.MemberOf -match $adminGroup) {
                    Write-Finding -Category "Service Accounts" -Severity "CRITICAL" `
                        -Object $svcName `
                        -Finding "Service account is member of '$adminGroup'" `
                        -Recommendation "Remove admin privileges from service accounts"
                }
            }
        }
        
        # Check for gMSA accounts
        try {
            $gMSAs = Get-ADServiceAccount -Filter * @params -ErrorAction SilentlyContinue
            Write-AuditLog "Found $($gMSAs.Count) Group Managed Service Accounts" -Level "INFO"
        }
        catch {
            Write-AuditLog "Unable to query gMSA accounts" -Level "WARNING"
        }
    }
    catch {
        Write-AuditLog "Error during service account audit: $_" -Level "ERROR"
    }
}

#endregion

#region Computer Account Audit

function Invoke-ComputerAccountAudit {
    Write-AuditLog "Auditing Computer Accounts..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        $computers = Get-ADComputer -Filter * -Properties `
            Name, Enabled, LastLogonDate, OperatingSystem, OperatingSystemVersion, `
            PasswordLastSet, TrustedForDelegation, Description, WhenCreated @params
        
        $totalComputers = $computers.Count
        $enabledComputers = 0
        $staleComputers = 0
        $oldOSCount = 0
        
        $thresholdDate = (Get-Date).AddDays(-$StaleThresholdDays)
        
        foreach ($computer in $computers) {
            if ($computer.Enabled) { $enabledComputers++ }
            
            # Stale computers
            if ($computer.LastLogonDate -and $computer.LastLogonDate -lt $thresholdDate) {
                $staleComputers++
                if (-not $SkipLargeQueries) {
                    Write-Finding -Category "Computers" -Severity "LOW" `
                        -Object $computer.Name `
                        -Finding "Computer has not logged in for $([int]((Get-Date) - $computer.LastLogonDate).Days) days" `
                        -Recommendation "Review computer status and consider disabling/removing"
                }
            }
            
            # Old operating systems
            $oldOSPatterns = @("Windows Server 2008", "Windows Server 2003", "Windows XP", "Windows 7", "Windows Server 2012")
            foreach ($pattern in $oldOSPatterns) {
                if ($computer.OperatingSystem -like "*$pattern*") {
                    $oldOSCount++
                    Write-Finding -Category "Computers" -Severity "HIGH" `
                        -Object $computer.Name `
                        -Finding "Computer is running unsupported OS: $($computer.OperatingSystem)" `
                        -Recommendation "Upgrade or decommission unsupported operating systems"
                    break
                }
            }
            
            # Unconstrained delegation on computers
            if ($computer.TrustedForDelegation -and $computer.Name -notmatch "DC") {
                Write-Finding -Category "Computers" -Severity "HIGH" `
                    -Object $computer.Name `
                    -Finding "Computer has unconstrained delegation (non-DC)" `
                    -Recommendation "Remove unconstrained delegation from non-DC computers"
            }
        }
        
        Write-AuditLog "Computer Account Statistics:" -Level "INFO"
        Write-AuditLog "  Total Computers: $totalComputers" -Level "INFO"
        Write-AuditLog "  Enabled: $enabledComputers" -Level "INFO"
        Write-AuditLog "  Stale ($StaleThresholdDays+ days): $staleComputers" -Level "INFO"
        Write-AuditLog "  Unsupported OS: $oldOSCount" -Level "INFO"
        
        $script:ComputerStats = @{
            Total = $totalComputers
            Enabled = $enabledComputers
            Stale = $staleComputers
            UnsupportedOS = $oldOSCount
        }
    }
    catch {
        Write-AuditLog "Error during computer audit: $_" -Level "ERROR"
    }
}

#endregion

#region Password Policy Audit

function Invoke-PasswordPolicyAudit {
    Write-AuditLog "Auditing Password Policies..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Default Domain Password Policy
        $defaultPolicy = Get-ADDefaultDomainPasswordPolicy @params
        
        Write-AuditLog "Default Domain Password Policy:" -Level "INFO"
        Write-AuditLog "  Min Password Length: $($defaultPolicy.MinPasswordLength)" -Level "INFO"
        Write-AuditLog "  Password History: $($defaultPolicy.PasswordHistoryCount)" -Level "INFO"
        Write-AuditLog "  Max Password Age: $($defaultPolicy.MaxPasswordAge.Days) days" -Level "INFO"
        Write-AuditLog "  Complexity Enabled: $($defaultPolicy.ComplexityEnabled)" -Level "INFO"
        Write-AuditLog "  Lockout Threshold: $($defaultPolicy.LockoutThreshold)" -Level "INFO"
        
        # Check minimum length
        if ($defaultPolicy.MinPasswordLength -lt 12) {
            Write-Finding -Category "Password Policy" -Severity "MEDIUM" `
                -Object "Default Policy" `
                -Finding "Minimum password length is $($defaultPolicy.MinPasswordLength) (recommended: 12+)" `
                -Recommendation "Increase minimum password length to at least 12 characters"
        }
        
        # Check complexity
        if (-not $defaultPolicy.ComplexityEnabled) {
            Write-Finding -Category "Password Policy" -Severity "HIGH" `
                -Object "Default Policy" `
                -Finding "Password complexity is not enabled" `
                -Recommendation "Enable password complexity requirements"
        }
        
        # Check max age
        if ($defaultPolicy.MaxPasswordAge.Days -eq 0) {
            Write-Finding -Category "Password Policy" -Severity "MEDIUM" `
                -Object "Default Policy" `
                -Finding "Passwords do not expire" `
                -Recommendation "Consider enabling password expiration (90 days recommended)"
        }
        elseif ($defaultPolicy.MaxPasswordAge.Days -gt 90) {
            Write-Finding -Category "Password Policy" -Severity "LOW" `
                -Object "Default Policy" `
                -Finding "Password max age is $($defaultPolicy.MaxPasswordAge.Days) days" `
                -Recommendation "Consider reducing to 90 days or less"
        }
        
        # Check history
        if ($defaultPolicy.PasswordHistoryCount -lt 12) {
            Write-Finding -Category "Password Policy" -Severity "LOW" `
                -Object "Default Policy" `
                -Finding "Password history is $($defaultPolicy.PasswordHistoryCount) (recommended: 12+)" `
                -Recommendation "Increase password history to at least 12"
        }
        
        # Check lockout
        if ($defaultPolicy.LockoutThreshold -eq 0) {
            Write-Finding -Category "Password Policy" -Severity "MEDIUM" `
                -Object "Default Policy" `
                -Finding "Account lockout is not configured" `
                -Recommendation "Enable account lockout (5-10 attempts recommended)"
        }
        elseif ($defaultPolicy.LockoutThreshold -gt 10) {
            Write-Finding -Category "Password Policy" -Severity "LOW" `
                -Object "Default Policy" `
                -Finding "Lockout threshold is $($defaultPolicy.LockoutThreshold) (high)" `
                -Recommendation "Consider reducing lockout threshold to 5-10"
        }
        
        # Check Fine-Grained Password Policies
        try {
            $fgpp = Get-ADFineGrainedPasswordPolicy -Filter * @params
            Write-AuditLog "Found $($fgpp.Count) Fine-Grained Password Policies" -Level "INFO"
            
            foreach ($policy in $fgpp) {
                Write-AuditLog "  FGPP: $($policy.Name) - Min Length: $($policy.MinPasswordLength)" -Level "INFO"
            }
        }
        catch {
            Write-AuditLog "Unable to query Fine-Grained Password Policies" -Level "WARNING"
        }
    }
    catch {
        Write-AuditLog "Error during password policy audit: $_" -Level "ERROR"
    }
}

#endregion

#region Group Policy Audit

function Invoke-GPOAudit {
    Write-AuditLog "Auditing Group Policy Objects..." -Level "INFO"
    
    try {
        Import-Module GroupPolicy -ErrorAction Stop
        
        $gpos = Get-GPO -All
        Write-AuditLog "Found $($gpos.Count) Group Policy Objects" -Level "INFO"
        
        foreach ($gpo in $gpos) {
            $gpoName = $gpo.DisplayName
            
            # Check for GPOs not linked
            try {
                $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml
                if ($gpoReport -notmatch "LinksTo") {
                    Write-Finding -Category "Group Policy" -Severity "LOW" `
                        -Object $gpoName `
                        -Finding "GPO is not linked to any OU" `
                        -Recommendation "Link GPO or consider removing if unused"
                }
            }
            catch {}
            
            # Check modification date
            if ($gpo.ModificationTime -lt (Get-Date).AddYears(-1)) {
                Write-Finding -Category "Group Policy" -Severity "LOW" `
                    -Object $gpoName `
                    -Finding "GPO has not been modified in over a year" `
                    -Recommendation "Review GPO for relevance and update if needed"
            }
            
            if ($IncludeDetailedGPO) {
                # More detailed GPO analysis
                try {
                    $gpoReport = [xml](Get-GPOReport -Guid $gpo.Id -ReportType Xml)
                    
                    # Check for password settings in GPO (potential sensitive data)
                    if ($gpoReport.InnerXml -match "cpassword") {
                        Write-Finding -Category "Group Policy" -Severity "CRITICAL" `
                            -Object $gpoName `
                            -Finding "GPO contains cpassword (Group Policy Preferences password)" `
                            -Recommendation "Remove GPP passwords immediately - they are easily decrypted"
                    }
                }
                catch {}
            }
        }
    }
    catch {
        Write-AuditLog "GroupPolicy module not available. Skipping GPO audit." -Level "WARNING"
    }
}

#endregion

#region Domain Controller Audit

function Invoke-DomainControllerAudit {
    Write-AuditLog "Auditing Domain Controllers..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        $domainControllers = Get-ADDomainController -Filter * @params
        
        Write-AuditLog "Found $($domainControllers.Count) Domain Controllers" -Level "INFO"
        
        foreach ($dc in $domainControllers) {
            Write-AuditLog "  DC: $($dc.HostName) - OS: $($dc.OperatingSystem)" -Level "INFO"
            
            # Check for old DC OS
            $oldOSPatterns = @("Windows Server 2008", "Windows Server 2003", "Windows Server 2012")
            foreach ($pattern in $oldOSPatterns) {
                if ($dc.OperatingSystem -like "*$pattern*") {
                    Write-Finding -Category "Domain Controllers" -Severity "CRITICAL" `
                        -Object $dc.HostName `
                        -Finding "Domain Controller running unsupported OS: $($dc.OperatingSystem)" `
                        -Recommendation "Upgrade or decommission DC immediately"
                }
            }
            
            # Check if DC is Global Catalog
            if (-not $dc.IsGlobalCatalog) {
                Write-Finding -Category "Domain Controllers" -Severity "LOW" `
                    -Object $dc.HostName `
                    -Finding "Domain Controller is not a Global Catalog server" `
                    -Recommendation "Consider enabling GC for redundancy"
            }
        }
    }
    catch {
        Write-AuditLog "Error during DC audit: $_" -Level "ERROR"
    }
}

#endregion

#region Kerberos Configuration Audit

function Invoke-KerberosAudit {
    Write-AuditLog "Auditing Kerberos Configuration..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Check krbtgt password age
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet @params
        $krbtgtAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days
        
        Write-AuditLog "krbtgt password age: $krbtgtAge days" -Level "INFO"
        
        if ($krbtgtAge -gt 180) {
            Write-Finding -Category "Kerberos" -Severity "HIGH" `
                -Object "krbtgt" `
                -Finding "krbtgt password is $krbtgtAge days old (should be rotated every 180 days)" `
                -Recommendation "Rotate krbtgt password twice (with replication between)"
        }
        
        # Check for accounts with constrained delegation
        $constrainedDelegation = Get-ADUser -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties `
            msDS-AllowedToDelegateTo, TrustedToAuthForDelegation @params
        
        foreach ($account in $constrainedDelegation) {
            $delegateTo = $account.'msDS-AllowedToDelegateTo' -join ", "
            Write-Finding -Category "Kerberos" -Severity "LOW" `
                -Object $account.SamAccountName `
                -Finding "Account has constrained delegation to: $delegateTo" `
                -Recommendation "Review delegation configuration for necessity"
        }
    }
    catch {
        Write-AuditLog "Error during Kerberos audit: $_" -Level "ERROR"
    }
}

#endregion

#region AdminSDHolder Audit

function Invoke-AdminSDHolderAudit {
    Write-AuditLog "Auditing AdminSDHolder..." -Level "INFO"
    
    $params = @{}
    if ($DomainController) { $params['Server'] = $DomainController }
    
    try {
        # Check for orphaned AdminCount users
        $adminCountUsers = Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount, MemberOf @params
        
        $privilegedGroupDNs = @(
            "Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
            "Account Operators", "Backup Operators", "Server Operators"
        ) | ForEach-Object {
            try {
                (Get-ADGroup -Identity $_ @params).DistinguishedName
            }
            catch {}
        }
        
        foreach ($user in $adminCountUsers) {
            $isInPrivGroup = $false
            foreach ($groupDN in $privilegedGroupDNs) {
                if ($user.MemberOf -contains $groupDN) {
                    $isInPrivGroup = $true
                    break
                }
            }
            
            if (-not $isInPrivGroup) {
                Write-Finding -Category "AdminSDHolder" -Severity "LOW" `
                    -Object $user.SamAccountName `
                    -Finding "User has AdminCount=1 but is not in a protected group (orphaned)" `
                    -Recommendation "Clear AdminCount attribute and verify permissions"
            }
        }
    }
    catch {
        Write-AuditLog "Error during AdminSDHolder audit: $_" -Level "ERROR"
    }
}

#endregion

#region Report Generation

function Export-AuditReport {
    Write-AuditLog "Generating audit report..." -Level "INFO"
    
    $endTime = Get-Date
    $duration = $endTime - $script:Config.StartTime
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 15px; }
        h2 { color: #323130; margin-top: 30px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333; }
        .low { background: #1976d2; }
        .info { background: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078d4; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #1976d2; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: #f8f8f8; padding: 15px; border-radius: 8px; border-left: 4px solid #0078d4; }
        .metadata { color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Active Directory Security Audit Report</h1>
        <div class="metadata">
            <p><strong>Domain:</strong> $($script:DomainName)</p>
            <p><strong>Forest:</strong> $($script:ForestName)</p>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Duration:</strong> $($duration.ToString("hh\:mm\:ss"))</p>
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
        
        <h2>Statistics</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <h4>User Accounts</h4>
                <p>Total: $($script:UserStats.Total)</p>
                <p>Enabled: $($script:UserStats.Enabled)</p>
                <p>Stale: $($script:UserStats.Stale)</p>
                <p>Locked Out: $($script:UserStats.LockedOut)</p>
            </div>
            <div class="stat-card">
                <h4>Computer Accounts</h4>
                <p>Total: $($script:ComputerStats.Total)</p>
                <p>Stale: $($script:ComputerStats.Stale)</p>
                <p>Unsupported OS: $($script:ComputerStats.UnsupportedOS)</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Object</th>
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
                <td>$($finding.Object)</td>
                <td>$($finding.Finding)</td>
                <td>$($finding.Recommendation)</td>
            </tr>
"@
    }

    $html += @"
        </table>
        
        <h2>Compliance Frameworks</h2>
        <ul>
            <li>SOC 2 - Access Control</li>
            <li>ISO 27001 - A.9 Access Control</li>
            <li>NIST 800-53 - AC (Access Control)</li>
            <li>CIS Controls - Identity and Access Management</li>
            <li>HIPAA - Access Management</li>
        </ul>
        
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by AD-Full-Audit.ps1 v$($script:Config.Version)</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "HTML report saved to: $($script:Config.ReportFile)" -Level "SUCCESS"
    
    if ($ExportToCSV) {
        $csvPath = $script:Config.ReportFile -replace "\.html$", ".csv"
        $script:AllFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-AuditLog "CSV report saved to: $csvPath" -Level "SUCCESS"
    }
}

#endregion

#region Main Execution

function Invoke-ADSecurityAudit {
    Write-AuditLog "=" * 60 -Level "INFO"
    Write-AuditLog "ACTIVE DIRECTORY COMPREHENSIVE SECURITY AUDIT" -Level "INFO"
    Write-AuditLog "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
    
    # Verify module
    if (-not (Test-ADModule)) {
        return
    }
    
    # Initialize connection
    if (-not (Initialize-ADConnection)) {
        return
    }
    
    # Run audits
    Invoke-DomainInfoAudit
    Invoke-UserAccountAudit
    Invoke-PrivilegedGroupAudit
    Invoke-ServiceAccountAudit
    Invoke-ComputerAccountAudit
    Invoke-PasswordPolicyAudit
    Invoke-GPOAudit
    Invoke-DomainControllerAudit
    Invoke-KerberosAudit
    Invoke-AdminSDHolderAudit
    
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

# Execute
Invoke-ADSecurityAudit

#endregion
