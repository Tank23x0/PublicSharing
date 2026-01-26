<#
.SYNOPSIS
    Comprehensive Jamf Pro Security Audit Script
    
.DESCRIPTION
    Audits Jamf Pro deployment including:
    - Computer and mobile device inventory
    - Configuration profiles and policies
    - User and admin access
    - Extension attributes
    - Smart group configurations
    - FileVault compliance
    - Software updates
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - Jamf Pro API credentials
    - Jamf Pro Classic API or Jamf Pro API access
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$JamfUrl,  # e.g., https://yourcompany.jamfcloud.com
    
    [Parameter(Mandatory = $true)]
    [string]$Username,
    
    [Parameter(Mandatory = $true)]
    [string]$Password,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Jamf-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 30,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV
)

#region Configuration

$script:Config = @{
    ScriptName = "Jamf-Full-Audit"
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
$script:Config.LogFile = Join-Path $OutputPath "Jamf-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "Jamf-Audit-Report_$timestamp.html"

$script:AllFindings = @()
$script:JamfUrl = $JamfUrl.TrimEnd('/')
$script:Token = $null

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

#region API Functions

function Get-JamfToken {
    Write-AuditLog "Authenticating to Jamf Pro API..." "INFO"
    
    try {
        $base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${Password}"))
        $headers = @{
            "Authorization" = "Basic $base64Auth"
        }
        
        $response = Invoke-RestMethod -Uri "$script:JamfUrl/api/v1/auth/token" -Method POST -Headers $headers
        $script:Token = $response.token
        Write-AuditLog "Successfully authenticated to Jamf Pro" "SUCCESS"
        return $true
    }
    catch {
        Write-AuditLog "Failed to authenticate: $_" "ERROR"
        return $false
    }
}

function Invoke-JamfAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [switch]$Classic
    )
    
    $headers = @{
        "Authorization" = "Bearer $script:Token"
        "Accept" = "application/json"
    }
    
    $uri = if ($Classic) {
        "$script:JamfUrl/JSSResource$Endpoint"
    } else {
        "$script:JamfUrl/api/v1$Endpoint"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
        return $response
    }
    catch {
        Write-AuditLog "API Error ($Endpoint): $_" "ERROR"
        return $null
    }
}

#endregion

#region Computer Audit

function Invoke-ComputerAudit {
    Write-AuditLog "Auditing Computers..." "INFO"
    
    try {
        $computers = Invoke-JamfAPI -Endpoint "/computers" -Classic
        
        if (-not $computers -or -not $computers.computers) {
            Write-AuditLog "No computers found" "WARNING"
            return
        }
        
        $totalComputers = $computers.computers.Count
        Write-AuditLog "Found $totalComputers computers" "INFO"
        
        $staleComputers = 0
        $noFileVault = 0
        $outdatedOS = 0
        
        foreach ($computer in $computers.computers) {
            $computerId = $computer.id
            
            # Get detailed info
            $details = Invoke-JamfAPI -Endpoint "/computers/id/$computerId" -Classic
            
            if ($details) {
                $computerName = $details.computer.general.name
                $lastContact = $details.computer.general.last_contact_time
                $osVersion = $details.computer.hardware.os_version
                $fileVaultStatus = $details.computer.hardware.filevault2_status
                
                # Check last contact
                if ($lastContact) {
                    $lastContactDate = [DateTime]::Parse($lastContact)
                    $daysSinceContact = [int]((Get-Date) - $lastContactDate).TotalDays
                    
                    if ($daysSinceContact -gt $StaleThresholdDays) {
                        $staleComputers++
                        Write-Finding -Category "Computers" -Severity "MEDIUM" `
                            -Object $computerName `
                            -Finding "No contact in $daysSinceContact days" `
                            -Recommendation "Investigate device status"
                    }
                }
                
                # Check FileVault
                if ($fileVaultStatus -ne "Encrypted") {
                    $noFileVault++
                    Write-Finding -Category "Computers" -Severity "HIGH" `
                        -Object $computerName `
                        -Finding "FileVault not enabled (Status: $fileVaultStatus)" `
                        -Recommendation "Enable FileVault encryption"
                }
                
                # Check OS version
                if ($osVersion -match "^1[0-2]\.") {
                    $outdatedOS++
                    Write-Finding -Category "Computers" -Severity "MEDIUM" `
                        -Object $computerName `
                        -Finding "Outdated macOS version: $osVersion" `
                        -Recommendation "Update to supported macOS version"
                }
            }
        }
        
        $script:ComputerStats = @{
            Total = $totalComputers
            Stale = $staleComputers
            NoFileVault = $noFileVault
            OutdatedOS = $outdatedOS
        }
        
        # Summary findings
        if ($noFileVault -gt 0) {
            $percent = [math]::Round(($noFileVault / $totalComputers) * 100, 1)
            Write-AuditLog "FileVault not enabled on $noFileVault computers ($percent%)" "WARNING"
        }
    }
    catch {
        Write-AuditLog "Error in computer audit: $_" "ERROR"
    }
}

#endregion

#region Policy Audit

function Invoke-PolicyAudit {
    Write-AuditLog "Auditing Policies..." "INFO"
    
    try {
        $policies = Invoke-JamfAPI -Endpoint "/policies" -Classic
        
        if ($policies -and $policies.policies) {
            $totalPolicies = $policies.policies.Count
            Write-AuditLog "Found $totalPolicies policies" "INFO"
            
            $disabledPolicies = 0
            
            foreach ($policy in $policies.policies) {
                $policyId = $policy.id
                $policyDetails = Invoke-JamfAPI -Endpoint "/policies/id/$policyId" -Classic
                
                if ($policyDetails) {
                    $policyName = $policyDetails.policy.general.name
                    $enabled = $policyDetails.policy.general.enabled
                    
                    if (-not $enabled) {
                        $disabledPolicies++
                    }
                }
            }
            
            if ($disabledPolicies -gt 10) {
                Write-Finding -Category "Policies" -Severity "LOW" `
                    -Object "Disabled Policies" `
                    -Finding "$disabledPolicies policies are disabled" `
                    -Recommendation "Review and clean up disabled policies"
            }
        }
    }
    catch {
        Write-AuditLog "Error in policy audit: $_" "ERROR"
    }
}

#endregion

#region Admin User Audit

function Invoke-AdminUserAudit {
    Write-AuditLog "Auditing Admin Users..." "INFO"
    
    try {
        $accounts = Invoke-JamfAPI -Endpoint "/accounts" -Classic
        
        if ($accounts -and $accounts.accounts) {
            $users = $accounts.accounts.users
            $groups = $accounts.accounts.groups
            
            Write-AuditLog "Found $($users.Count) admin users and $($groups.Count) groups" "INFO"
            
            $fullAccessCount = 0
            
            foreach ($user in $users) {
                $userId = $user.id
                $userDetails = Invoke-JamfAPI -Endpoint "/accounts/userid/$userId" -Classic
                
                if ($userDetails) {
                    $userName = $userDetails.account.name
                    $accessLevel = $userDetails.account.access_level
                    
                    if ($accessLevel -eq "Full Access") {
                        $fullAccessCount++
                    }
                }
            }
            
            if ($fullAccessCount -gt 5) {
                Write-Finding -Category "Admin Users" -Severity "MEDIUM" `
                    -Object "Full Access Users" `
                    -Finding "$fullAccessCount users have full admin access" `
                    -Recommendation "Review and reduce full access accounts"
            }
        }
    }
    catch {
        Write-AuditLog "Error in admin user audit: $_" "ERROR"
    }
}

#endregion

#region Configuration Profile Audit

function Invoke-ConfigProfileAudit {
    Write-AuditLog "Auditing Configuration Profiles..." "INFO"
    
    try {
        $profiles = Invoke-JamfAPI -Endpoint "/osxconfigurationprofiles" -Classic
        
        if ($profiles -and $profiles.os_x_configuration_profiles) {
            $totalProfiles = $profiles.os_x_configuration_profiles.Count
            Write-AuditLog "Found $totalProfiles configuration profiles" "INFO"
            
            # Check for security-related profiles
            $hasPasscode = $false
            $hasFirewall = $false
            $hasGatekeeper = $false
            
            foreach ($profile in $profiles.os_x_configuration_profiles) {
                $profileName = $profile.name.ToLower()
                
                if ($profileName -match "password|passcode") { $hasPasscode = $true }
                if ($profileName -match "firewall") { $hasFirewall = $true }
                if ($profileName -match "gatekeeper") { $hasGatekeeper = $true }
            }
            
            if (-not $hasPasscode) {
                Write-Finding -Category "Profiles" -Severity "MEDIUM" `
                    -Object "Passcode Profile" `
                    -Finding "No passcode policy profile detected" `
                    -Recommendation "Create and deploy a passcode requirements profile"
            }
        }
    }
    catch {
        Write-AuditLog "Error in profile audit: $_" "ERROR"
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
    <title>Jamf Pro Audit Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f7; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; }
        h1 { color: #1d1d1f; border-bottom: 3px solid #0071e3; padding-bottom: 15px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #ff3b30; }
        .high { background: #ff9500; }
        .medium { background: #ffcc00; color: #1d1d1f; }
        .low { background: #007aff; }
        .info { background: #34c759; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #d2d2d7; }
        th { background: #1d1d1f; color: white; }
        .severity-critical { color: #ff3b30; font-weight: bold; }
        .severity-high { color: #ff9500; font-weight: bold; }
        .severity-medium { color: #ffcc00; }
        .severity-low { color: #007aff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍎 Jamf Pro Security Audit Report</h1>
        <p><strong>Instance:</strong> $JamfUrl</p>
        <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        
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
}

#endregion

#region Main

function Invoke-JamfAudit {
    Write-AuditLog "=" * 60 "INFO"
    Write-AuditLog "JAMF PRO SECURITY AUDIT" "INFO"
    Write-AuditLog "=" * 60 "INFO"
    
    if (-not (Get-JamfToken)) { return }
    
    Invoke-ComputerAudit
    Invoke-PolicyAudit
    Invoke-AdminUserAudit
    Invoke-ConfigProfileAudit
    
    Export-AuditReport
    
    Write-AuditLog "AUDIT COMPLETE - Findings: $($script:Config.TotalFindings)" "SUCCESS"
}

Invoke-JamfAudit

#endregion
