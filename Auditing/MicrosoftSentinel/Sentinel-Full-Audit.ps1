<#
.SYNOPSIS
    Microsoft Sentinel Security Audit Script
.DESCRIPTION
    Audits Sentinel workspace configuration, analytics rules, data connectors, and incidents.
.VERSION
    2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$SubscriptionId,
    [Parameter(Mandatory=$true)][string]$ResourceGroupName,
    [Parameter(Mandatory=$true)][string]$WorkspaceName,
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Sentinel-Audit"
)

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $OutputPath "Sentinel-Audit-Report_$timestamp.html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++
    switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

Write-Host "=== MICROSOFT SENTINEL SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    Import-Module Az.SecurityInsights -ErrorAction Stop
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    
    # Analytics Rules
    Write-Host "Checking Analytics Rules..." -ForegroundColor White
    $rules = Get-AzSentinelAlertRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue
    
    $enabledRules = ($rules | Where-Object { $_.Enabled }).Count
    $disabledRules = ($rules | Where-Object { -not $_.Enabled }).Count
    
    if ($enabledRules -lt 10) {
        Write-Finding -Category "Detection" -Severity "HIGH" -Object "Analytics Rules" `
            -Finding "Only $enabledRules analytics rules are enabled" `
            -Recommendation "Enable more detection rules from Content Hub"
    }
    
    if ($disabledRules -gt $enabledRules) {
        Write-Finding -Category "Detection" -Severity "MEDIUM" -Object "Analytics Rules" `
            -Finding "$disabledRules rules disabled (more than enabled)" `
            -Recommendation "Review and enable appropriate detection rules"
    }
    
    # Data Connectors
    Write-Host "Checking Data Connectors..." -ForegroundColor White
    $connectors = Get-AzSentinelDataConnector -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue
    
    $criticalConnectors = @("AzureActiveDirectory", "Office365", "MicrosoftDefenderAdvancedThreatProtection")
    foreach ($conn in $criticalConnectors) {
        $found = $connectors | Where-Object { $_.Kind -like "*$conn*" }
        if (-not $found) {
            Write-Finding -Category "Data Connectors" -Severity "MEDIUM" -Object $conn `
                -Finding "Critical data connector not configured: $conn" `
                -Recommendation "Enable $conn data connector"
        }
    }
    
    # Incidents
    Write-Host "Checking Incidents..." -ForegroundColor White
    $incidents = Get-AzSentinelIncident -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue
    
    $highSeverity = ($incidents | Where-Object { $_.Severity -eq "High" -and $_.Status -ne "Closed" }).Count
    if ($highSeverity -gt 0) {
        Write-Finding -Category "Incidents" -Severity "HIGH" -Object "Open Incidents" `
            -Finding "$highSeverity high severity incidents not closed" `
            -Recommendation "Investigate and resolve high severity incidents"
    }
    
    # Automation Rules
    Write-Host "Checking Automation Rules..." -ForegroundColor White
    $automationRules = Get-AzSentinelAutomationRule -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -ErrorAction SilentlyContinue
    if (-not $automationRules -or $automationRules.Count -eq 0) {
        Write-Finding -Category "Automation" -Severity "LOW" -Object "Automation" `
            -Finding "No automation rules configured" `
            -Recommendation "Create automation rules for incident response"
    }
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Sentinel Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#0078d4}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#0078d4;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>🔍 Microsoft Sentinel Security Audit</h1>
<p>Workspace: $WorkspaceName</p><p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<p>Findings: Critical=$($script:Config.CriticalFindings), High=$($script:Config.HighFindings), Medium=$($script:Config.MediumFindings), Low=$($script:Config.LowFindings)</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report saved: $ReportFile" -ForegroundColor Green
