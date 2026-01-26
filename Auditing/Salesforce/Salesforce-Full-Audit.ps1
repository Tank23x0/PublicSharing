<#
.SYNOPSIS
    Salesforce Security Audit Script
.DESCRIPTION
    Audits Salesforce org security including users, profiles, permissions, login history, and settings.
.VERSION
    2.0.0
.NOTES
    Requires Salesforce CLI (sf/sfdx) or connected app with API access
#>

[CmdletBinding()]
param(
    [string]$OrgAlias = "production",
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Salesforce-Audit"
)

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$ReportFile = Join-Path $OutputPath "Salesforce-Audit-Report_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++; switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

function Invoke-SFQuery {
    param([string]$Query)
    try {
        $result = sf data query --query $Query --target-org $OrgAlias --json 2>$null | ConvertFrom-Json
        return $result.result.records
    }
    catch { return $null }
}

Write-Host "=== SALESFORCE SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    # Check SF CLI
    if (-not (Get-Command sf -ErrorAction SilentlyContinue)) {
        Write-Host "Salesforce CLI (sf) not found. Install from https://developer.salesforce.com/tools/salesforcecli" -ForegroundColor Red
        exit
    }
    
    # Active Users
    Write-Host "Querying Active Users..." -ForegroundColor White
    $users = Invoke-SFQuery "SELECT Id, Username, Profile.Name, IsActive, LastLoginDate FROM User WHERE IsActive = true"
    
    if ($users) {
        # Users with System Admin profile
        $sysAdmins = $users | Where-Object { $_.Profile.Name -eq "System Administrator" }
        if ($sysAdmins.Count -gt 5) {
            Write-Finding -Category "Users" -Severity "MEDIUM" -Object "System Administrators" `
                -Finding "$($sysAdmins.Count) users have System Administrator profile" `
                -Recommendation "Reduce System Admin count; use custom profiles"
        }
        
        # Stale users (no login in 90 days)
        $threshold = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        $staleUsers = $users | Where-Object { $_.LastLoginDate -and $_.LastLoginDate -lt $threshold }
        if ($staleUsers.Count -gt 0) {
            Write-Finding -Category "Users" -Severity "MEDIUM" -Object "Stale Users" `
                -Finding "$($staleUsers.Count) active users haven't logged in for 90+ days" `
                -Recommendation "Deactivate or review stale user accounts"
        }
    }
    
    # Permission Sets with Modify All
    Write-Host "Checking Permission Sets..." -ForegroundColor White
    $permSets = Invoke-SFQuery "SELECT Id, Name, PermissionsModifyAllData FROM PermissionSet WHERE PermissionsModifyAllData = true"
    if ($permSets -and $permSets.Count -gt 0) {
        Write-Finding -Category "Permissions" -Severity "HIGH" -Object "Permission Sets" `
            -Finding "$($permSets.Count) permission sets have 'Modify All Data'" `
            -Recommendation "Review and limit Modify All Data permission"
    }
    
    # Login History - Failed Logins
    Write-Host "Checking Login History..." -ForegroundColor White
    $failedLogins = Invoke-SFQuery "SELECT COUNT(Id) cnt FROM LoginHistory WHERE Status != 'Success' AND LoginTime = LAST_N_DAYS:7"
    if ($failedLogins -and $failedLogins.cnt -gt 100) {
        Write-Finding -Category "Authentication" -Severity "MEDIUM" -Object "Failed Logins" `
            -Finding "$($failedLogins.cnt) failed login attempts in last 7 days" `
            -Recommendation "Investigate failed login patterns"
    }
    
    # Session Settings via SOQL on SecuritySettings is limited; recommend manual check
    Write-Finding -Category "Settings" -Severity "LOW" -Object "Session Settings" `
        -Finding "Manual review recommended for session timeout and security settings" `
        -Recommendation "Check Setup > Session Settings for timeout and lockout policies"
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Salesforce Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#00a1e0}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#00a1e0;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>☁️ Salesforce Security Audit</h1>
<p>Org Alias: $OrgAlias</p><p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report: $ReportFile" -ForegroundColor Green
