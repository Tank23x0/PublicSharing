<#
.SYNOPSIS
    Microsoft Purview (Compliance) Security Audit Script
.DESCRIPTION
    Audits DLP policies, sensitivity labels, retention policies, eDiscovery, and compliance settings.
.VERSION
    2.0.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Purview-Audit")

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $OutputPath "Purview-Audit-Report_$timestamp.html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++
    switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

Write-Host "=== MICROSOFT PURVIEW SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    # Connect to Security & Compliance PowerShell
    $session = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not $session) {
        Connect-IPPSSession -ShowBanner:$false
    }
    
    # DLP Policies
    Write-Host "Checking DLP Policies..." -ForegroundColor White
    $dlpPolicies = Get-DlpCompliancePolicy -ErrorAction SilentlyContinue
    if (-not $dlpPolicies -or $dlpPolicies.Count -eq 0) {
        Write-Finding -Category "DLP" -Severity "HIGH" -Object "DLP Policies" `
            -Finding "No DLP policies configured" `
            -Recommendation "Create DLP policies to protect sensitive data"
    } else {
        $disabledDLP = $dlpPolicies | Where-Object { $_.Mode -eq "Disable" }
        if ($disabledDLP) {
            Write-Finding -Category "DLP" -Severity "MEDIUM" -Object "DLP Policies" `
                -Finding "$($disabledDLP.Count) DLP policies are disabled" `
                -Recommendation "Review and enable DLP policies"
        }
    }
    
    # Sensitivity Labels
    Write-Host "Checking Sensitivity Labels..." -ForegroundColor White
    $labels = Get-Label -ErrorAction SilentlyContinue
    if (-not $labels -or $labels.Count -eq 0) {
        Write-Finding -Category "Information Protection" -Severity "MEDIUM" -Object "Sensitivity Labels" `
            -Finding "No sensitivity labels configured" `
            -Recommendation "Create and publish sensitivity labels"
    }
    
    # Retention Policies
    Write-Host "Checking Retention Policies..." -ForegroundColor White
    $retentionPolicies = Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue
    if (-not $retentionPolicies -or $retentionPolicies.Count -eq 0) {
        Write-Finding -Category "Data Governance" -Severity "MEDIUM" -Object "Retention" `
            -Finding "No retention policies configured" `
            -Recommendation "Create retention policies for data lifecycle management"
    }
    
    # Audit Log Search
    Write-Host "Checking Audit Configuration..." -ForegroundColor White
    $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
    if ($auditConfig -and -not $auditConfig.UnifiedAuditLogIngestionEnabled) {
        Write-Finding -Category "Audit" -Severity "CRITICAL" -Object "Unified Audit" `
            -Finding "Unified audit logging is disabled" `
            -Recommendation "Enable unified audit logging immediately"
    }
    
    # Alert Policies
    Write-Host "Checking Alert Policies..." -ForegroundColor White
    $alerts = Get-ProtectionAlert -ErrorAction SilentlyContinue
    $disabledAlerts = $alerts | Where-Object { $_.Disabled -eq $true }
    if ($disabledAlerts.Count -gt 5) {
        Write-Finding -Category "Monitoring" -Severity "LOW" -Object "Alerts" `
            -Finding "$($disabledAlerts.Count) alert policies are disabled" `
            -Recommendation "Review and enable security alerts"
    }
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Purview Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#742774}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#742774;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>🛡️ Microsoft Purview Security Audit</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<p>Findings: Critical=$($script:Config.CriticalFindings), High=$($script:Config.HighFindings), Medium=$($script:Config.MediumFindings), Low=$($script:Config.LowFindings)</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report saved: $ReportFile" -ForegroundColor Green
