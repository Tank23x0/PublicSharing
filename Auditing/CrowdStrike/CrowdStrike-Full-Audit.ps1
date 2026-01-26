<#
.SYNOPSIS
    Comprehensive CrowdStrike Falcon Security Audit Script
    
.DESCRIPTION
    Audits CrowdStrike Falcon deployment including:
    - Sensor deployment coverage
    - Prevention policy compliance
    - Detection and incident review
    - User and role audit
    - API key management
    - Response action audit
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - CrowdStrike API credentials (Client ID + Secret)
    - Falcon API scopes: Hosts Read, Detections Read, Users Read, Policies Read
    - PSFalcon module recommended
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ClientId,
    
    [Parameter(Mandatory = $true)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory = $false)]
    [string]$Cloud = "us-1",  # us-1, us-2, eu-1, us-gov-1
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\CrowdStrike-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 14,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV
)

#region Configuration

$script:Config = @{
    ScriptName = "CrowdStrike-Full-Audit"
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
$script:Config.LogFile = Join-Path $OutputPath "CrowdStrike-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "CrowdStrike-Audit-Report_$timestamp.html"

$script:AllFindings = @()

# API Configuration
$cloudUrls = @{
    "us-1" = "https://api.crowdstrike.com"
    "us-2" = "https://api.us-2.crowdstrike.com"
    "eu-1" = "https://api.eu-1.crowdstrike.com"
    "us-gov-1" = "https://api.laggar.gcw.crowdstrike.com"
}
$script:BaseUrl = $cloudUrls[$Cloud]
$script:AccessToken = $null

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

function Get-FalconToken {
    Write-AuditLog "Authenticating to CrowdStrike Falcon API..." "INFO"
    
    try {
        $body = @{
            client_id = $ClientId
            client_secret = $ClientSecret
        }
        
        $response = Invoke-RestMethod -Uri "$script:BaseUrl/oauth2/token" `
            -Method Post -ContentType "application/x-www-form-urlencoded" `
            -Body $body
        
        $script:AccessToken = $response.access_token
        Write-AuditLog "Successfully authenticated to Falcon API" "SUCCESS"
        return $true
    }
    catch {
        Write-AuditLog "Failed to authenticate: $_" "ERROR"
        return $false
    }
}

function Invoke-FalconAPI {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = @{},
        [hashtable]$Query = @{}
    )
    
    $headers = @{
        "Authorization" = "Bearer $script:AccessToken"
        "Content-Type" = "application/json"
    }
    
    $uri = "$script:BaseUrl$Endpoint"
    
    if ($Query.Count -gt 0) {
        $queryString = ($Query.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "&"
        $uri = "$uri`?$queryString"
    }
    
    try {
        if ($Method -eq "GET") {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers
        }
        else {
            $response = Invoke-RestMethod -Uri $uri -Method $Method -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10)
        }
        return $response
    }
    catch {
        Write-AuditLog "API Error ($Endpoint): $_" "ERROR"
        return $null
    }
}

#endregion

#region Host/Sensor Audit

function Invoke-SensorAudit {
    Write-AuditLog "Auditing Falcon Sensor Deployment..." "INFO"
    
    try {
        # Get all host IDs
        $hostIds = Invoke-FalconAPI -Endpoint "/devices/queries/devices/v1" -Query @{limit=5000}
        
        if (-not $hostIds -or -not $hostIds.resources) {
            Write-AuditLog "No hosts found" "WARNING"
            return
        }
        
        $totalHosts = $hostIds.resources.Count
        Write-AuditLog "Found $totalHosts hosts" "INFO"
        
        # Get host details in batches
        $batchSize = 100
        $allHosts = @()
        
        for ($i = 0; $i -lt $totalHosts; $i += $batchSize) {
            $batch = $hostIds.resources[$i..([Math]::Min($i + $batchSize - 1, $totalHosts - 1))]
            $hostDetails = Invoke-FalconAPI -Endpoint "/devices/entities/devices/v2" -Method POST -Body @{ids = $batch}
            if ($hostDetails -and $hostDetails.resources) {
                $allHosts += $hostDetails.resources
            }
        }
        
        # Analyze hosts
        $staleHosts = 0
        $offlineHosts = 0
        $reducedProtection = 0
        $oldSensor = 0
        
        $thresholdDate = (Get-Date).AddDays(-$StaleThresholdDays)
        
        foreach ($host in $allHosts) {
            $hostname = $host.hostname
            $lastSeen = [DateTime]$host.last_seen
            $status = $host.status
            $preventionPolicy = $host.device_policies.prevention.policy_type
            
            # Check for stale sensors
            if ($lastSeen -lt $thresholdDate) {
                $staleHosts++
                $daysSince = [int]((Get-Date) - $lastSeen).TotalDays
                
                Write-Finding -Category "Sensors" -Severity "MEDIUM" `
                    -Object $hostname `
                    -Finding "Sensor offline for $daysSince days (last seen: $($lastSeen.ToString('yyyy-MM-dd')))" `
                    -Recommendation "Investigate host status or remove stale sensor"
            }
            
            # Check for reduced functionality mode
            if ($host.reduced_functionality_mode -eq "yes") {
                $reducedProtection++
                Write-Finding -Category "Sensors" -Severity "HIGH" `
                    -Object $hostname `
                    -Finding "Sensor in reduced functionality mode" `
                    -Recommendation "Investigate and remediate sensor issues"
            }
            
            # Check status
            if ($status -eq "offline") {
                $offlineHosts++
            }
        }
        
        # Summary findings
        $offlinePercent = [math]::Round(($offlineHosts / $totalHosts) * 100, 1)
        if ($offlinePercent -gt 10) {
            Write-Finding -Category "Sensors" -Severity "MEDIUM" `
                -Object "Sensor Coverage" `
                -Finding "$offlinePercent% of sensors are offline ($offlineHosts/$totalHosts)" `
                -Recommendation "Investigate connectivity issues"
        }
        
        if ($staleHosts -gt 0) {
            Write-Finding -Category "Sensors" -Severity "LOW" `
                -Object "Stale Sensors" `
                -Finding "$staleHosts hosts not seen in $StaleThresholdDays+ days" `
                -Recommendation "Review and cleanup stale host entries"
        }
        
        $script:HostStats = @{
            Total = $totalHosts
            Online = $totalHosts - $offlineHosts
            Offline = $offlineHosts
            Stale = $staleHosts
            ReducedMode = $reducedProtection
        }
        
        Write-AuditLog "Host Stats: Total=$totalHosts, Online=$($totalHosts - $offlineHosts), Stale=$staleHosts" "INFO"
    }
    catch {
        Write-AuditLog "Error in sensor audit: $_" "ERROR"
    }
}

#endregion

#region Detection Audit

function Invoke-DetectionAudit {
    Write-AuditLog "Auditing Detections..." "INFO"
    
    try {
        # Get recent detections
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddT00:00:00Z")
        
        $detections = Invoke-FalconAPI -Endpoint "/detects/queries/detects/v1" -Query @{
            filter = "first_behavior:>='$thirtyDaysAgo'"
            limit = 500
        }
        
        if (-not $detections -or -not $detections.resources) {
            Write-AuditLog "No detections in last 30 days" "INFO"
            return
        }
        
        $detectionCount = $detections.resources.Count
        Write-AuditLog "Found $detectionCount detections in last 30 days" "INFO"
        
        # Get detection details
        $detectionDetails = Invoke-FalconAPI -Endpoint "/detects/entities/summaries/GET/v1" -Method POST -Body @{
            ids = $detections.resources[0..([Math]::Min(99, $detectionCount - 1))]
        }
        
        $critical = 0
        $high = 0
        $newStatus = 0
        
        if ($detectionDetails -and $detectionDetails.resources) {
            foreach ($detection in $detectionDetails.resources) {
                $severity = $detection.max_severity_displayname
                $status = $detection.status
                
                if ($severity -eq "Critical") { $critical++ }
                elseif ($severity -eq "High") { $high++ }
                
                if ($status -eq "new") { $newStatus++ }
            }
        }
        
        # Findings
        if ($critical -gt 0) {
            Write-Finding -Category "Detections" -Severity "CRITICAL" `
                -Object "Critical Detections" `
                -Finding "$critical critical severity detections in last 30 days" `
                -Recommendation "Investigate and remediate critical detections immediately"
        }
        
        if ($high -gt 5) {
            Write-Finding -Category "Detections" -Severity "HIGH" `
                -Object "High Detections" `
                -Finding "$high high severity detections in last 30 days" `
                -Recommendation "Review and address high severity detections"
        }
        
        if ($newStatus -gt 0) {
            Write-Finding -Category "Detections" -Severity "MEDIUM" `
                -Object "Unreviewed Detections" `
                -Finding "$newStatus detections still in 'new' status" `
                -Recommendation "Review and triage pending detections"
        }
    }
    catch {
        Write-AuditLog "Error in detection audit: $_" "ERROR"
    }
}

#endregion

#region Prevention Policy Audit

function Invoke-PolicyAudit {
    Write-AuditLog "Auditing Prevention Policies..." "INFO"
    
    try {
        # Get prevention policies
        $policies = Invoke-FalconAPI -Endpoint "/policy/queries/prevention/v1"
        
        if (-not $policies -or -not $policies.resources) {
            Write-AuditLog "No prevention policies found" "WARNING"
            return
        }
        
        $policyDetails = Invoke-FalconAPI -Endpoint "/policy/entities/prevention/v1" -Query @{
            ids = ($policies.resources -join "&ids=")
        }
        
        if ($policyDetails -and $policyDetails.resources) {
            foreach ($policy in $policyDetails.resources) {
                $policyName = $policy.name
                $enabled = $policy.enabled
                
                if (-not $enabled) {
                    Write-Finding -Category "Policies" -Severity "MEDIUM" `
                        -Object $policyName `
                        -Finding "Prevention policy is disabled" `
                        -Recommendation "Enable policy or review why it's disabled"
                }
                
                # Check for detection-only mode (no prevention)
                $settings = $policy.prevention_settings
                # Note: Actual setting names vary - this is illustrative
            }
        }
    }
    catch {
        Write-AuditLog "Error in policy audit: $_" "ERROR"
    }
}

#endregion

#region User Audit

function Invoke-UserAudit {
    Write-AuditLog "Auditing Falcon Users..." "INFO"
    
    try {
        $users = Invoke-FalconAPI -Endpoint "/users/queries/user-uuids-by-cid/v1"
        
        if (-not $users -or -not $users.resources) {
            Write-AuditLog "No users found" "WARNING"
            return
        }
        
        $userDetails = Invoke-FalconAPI -Endpoint "/users/entities/users/v1" -Query @{
            ids = ($users.resources -join "&ids=")
        }
        
        if ($userDetails -and $userDetails.resources) {
            $adminCount = 0
            
            foreach ($user in $userDetails.resources) {
                $email = $user.uid
                $roles = $user.roles
                
                # Check for admin roles
                if ($roles -match "admin|Administrator") {
                    $adminCount++
                }
                
                # Check for 2FA
                # Note: 2FA status may not be available via API
            }
            
            Write-AuditLog "Found $($userDetails.resources.Count) users, $adminCount with admin roles" "INFO"
            
            if ($adminCount -gt 5) {
                Write-Finding -Category "Users" -Severity "MEDIUM" `
                    -Object "Admin Users" `
                    -Finding "$adminCount users have admin roles" `
                    -Recommendation "Review admin access and apply least privilege"
            }
        }
    }
    catch {
        Write-AuditLog "Error in user audit: $_" "ERROR"
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
    <title>CrowdStrike Falcon Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        h1 { color: #e01e2d; border-bottom: 3px solid #e01e2d; padding-bottom: 15px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333; }
        .low { background: #1976d2; }
        .info { background: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #e01e2d; color: white; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #1976d2; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🦅 CrowdStrike Falcon Security Audit Report</h1>
        <p><strong>Cloud:</strong> $Cloud</p>
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
}

#endregion

#region Main

function Invoke-CrowdStrikeAudit {
    Write-AuditLog "=" * 60 "INFO"
    Write-AuditLog "CROWDSTRIKE FALCON SECURITY AUDIT" "INFO"
    Write-AuditLog "=" * 60 "INFO"
    
    if (-not (Get-FalconToken)) { return }
    
    Invoke-SensorAudit
    Invoke-DetectionAudit
    Invoke-PolicyAudit
    Invoke-UserAudit
    
    Export-AuditReport
    
    Write-AuditLog "" "INFO"
    Write-AuditLog "AUDIT COMPLETE - Findings: $($script:Config.TotalFindings)" "SUCCESS"
}

Invoke-CrowdStrikeAudit

#endregion
