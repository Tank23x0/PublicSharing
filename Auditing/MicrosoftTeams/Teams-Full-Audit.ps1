<#
.SYNOPSIS
    Microsoft Teams Security Audit Script
.VERSION
    2.0.0
#>

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Teams-Audit")

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$ReportFile = Join-Path $OutputPath "Teams-Audit-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++; switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

Write-Host "=== MICROSOFT TEAMS SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    Import-Module MicrosoftTeams -ErrorAction Stop
    Connect-MicrosoftTeams
    
    # Guest Access
    Write-Host "Checking Guest Access Settings..." -ForegroundColor White
    $guestConfig = Get-CsTeamsClientConfiguration
    if ($guestConfig.AllowGuestUser) {
        Write-Finding -Category "Guest Access" -Severity "LOW" -Object "Tenant" `
            -Finding "Guest access is enabled" `
            -Recommendation "Review guest access policies"
    }
    
    # External Access
    $externalConfig = Get-CsTenantFederationConfiguration
    if ($externalConfig.AllowFederatedUsers) {
        Write-Finding -Category "External Access" -Severity "LOW" -Object "Federation" `
            -Finding "Federation with external organizations is enabled" `
            -Recommendation "Review allowed/blocked domains"
    }
    
    # Meeting Policies
    Write-Host "Checking Meeting Policies..." -ForegroundColor White
    $meetingPolicies = Get-CsTeamsMeetingPolicy
    $globalPolicy = $meetingPolicies | Where-Object { $_.Identity -eq "Global" }
    
    if ($globalPolicy.AllowAnonymousUsersToJoinMeeting) {
        Write-Finding -Category "Meetings" -Severity "MEDIUM" -Object "Global Policy" `
            -Finding "Anonymous users can join meetings" `
            -Recommendation "Consider disabling anonymous join"
    }
    
    if (-not $globalPolicy.AutoAdmittedUsers -or $globalPolicy.AutoAdmittedUsers -eq "Everyone") {
        Write-Finding -Category "Meetings" -Severity "MEDIUM" -Object "Global Policy" `
            -Finding "Everyone is auto-admitted to meetings" `
            -Recommendation "Restrict auto-admit to organization members"
    }
    
    # Messaging Policies
    Write-Host "Checking Messaging Policies..." -ForegroundColor White
    $messagingPolicies = Get-CsTeamsMessagingPolicy
    $globalMessaging = $messagingPolicies | Where-Object { $_.Identity -eq "Global" }
    
    if ($globalMessaging.AllowUrlPreviews) {
        Write-Finding -Category "Messaging" -Severity "LOW" -Object "Global Policy" `
            -Finding "URL previews are enabled (potential data leakage)" `
            -Recommendation "Consider disabling URL previews for sensitive environments"
    }
    
    # Teams Count
    Write-Host "Checking Teams..." -ForegroundColor White
    $teams = Get-Team
    Write-Host "Total Teams: $($teams.Count)" -ForegroundColor White
    
    $publicTeams = $teams | Where-Object { $_.Visibility -eq "Public" }
    if ($publicTeams.Count -gt 10) {
        Write-Finding -Category "Teams" -Severity "LOW" -Object "Public Teams" `
            -Finding "$($publicTeams.Count) public teams in organization" `
            -Recommendation "Review public team settings"
    }
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Teams Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#6264a7}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#6264a7;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>💬 Microsoft Teams Security Audit</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report: $ReportFile" -ForegroundColor Green
