<#
.SYNOPSIS
    Microsoft SharePoint Online Security Audit Script
.VERSION
    2.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AdminUrl,  # e.g., https://tenant-admin.sharepoint.com
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\SharePoint-Audit"
)

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$ReportFile = Join-Path $OutputPath "SharePoint-Audit-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++; switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

Write-Host "=== SHAREPOINT ONLINE SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
    Connect-SPOService -Url $AdminUrl
    
    # Tenant Settings
    Write-Host "Checking Tenant Settings..." -ForegroundColor White
    $tenant = Get-SPOTenant
    
    if ($tenant.SharingCapability -eq "ExternalUserAndGuestSharing") {
        Write-Finding -Category "External Sharing" -Severity "HIGH" -Object "Tenant" `
            -Finding "External sharing is fully enabled (including anonymous)" `
            -Recommendation "Restrict to authenticated guests or less"
    }
    
    if (-not $tenant.PreventExternalUsersFromResharing) {
        Write-Finding -Category "External Sharing" -Severity "MEDIUM" -Object "Tenant" `
            -Finding "External users can reshare content" `
            -Recommendation "Prevent external users from resharing"
    }
    
    if ($tenant.LegacyAuthProtocolsEnabled) {
        Write-Finding -Category "Authentication" -Severity "HIGH" -Object "Tenant" `
            -Finding "Legacy authentication protocols are enabled" `
            -Recommendation "Disable legacy auth protocols"
    }
    
    # Site Collections
    Write-Host "Checking Site Collections..." -ForegroundColor White
    $sites = Get-SPOSite -Limit All
    
    foreach ($site in $sites) {
        if ($site.SharingCapability -eq "ExternalUserAndGuestSharing" -and $site.Template -notlike "*BLOG*") {
            Write-Finding -Category "Site Sharing" -Severity "MEDIUM" -Object $site.Url `
                -Finding "Site allows anonymous sharing" `
                -Recommendation "Restrict sharing for this site"
        }
    }
    
    # External Users
    Write-Host "Checking External Users..." -ForegroundColor White
    $externalUsers = Get-SPOExternalUser -PageSize 50
    if ($externalUsers.Count -gt 100) {
        Write-Finding -Category "External Users" -Severity "LOW" -Object "Tenant" `
            -Finding "$($externalUsers.Count) external users have access" `
            -Recommendation "Review external user access periodically"
    }
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>SharePoint Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#038387}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#038387;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>📄 SharePoint Online Security Audit</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report: $ReportFile" -ForegroundColor Green
