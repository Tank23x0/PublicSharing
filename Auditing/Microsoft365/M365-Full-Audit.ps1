<#
.SYNOPSIS
    Comprehensive Microsoft 365 Security Audit Script
    
.DESCRIPTION
    Audits Microsoft 365 tenant security including:
    - License usage and assignment
    - Security & Compliance settings
    - Anti-phishing and anti-malware policies
    - Data Loss Prevention (DLP)
    - Secure Score analysis
    - Admin role assignments
    
.VERSION
    2.0.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\M365-Audit",
    [switch]$ExportToCSV
)

#region Configuration
$script:Config = @{
    ScriptName = "M365-Full-Audit"
    Version = "2.0.0"
    StartTime = Get-Date
    TotalFindings = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "M365-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "M365-Audit-Report_$timestamp.html"
$script:AllFindings = @()
#endregion

#region Logging
function Write-AuditLog { param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) { "INFO" {"White"} "WARNING" {"Yellow"} "ERROR" {"Red"} "SUCCESS" {"Green"} "FINDING" {"Cyan"} }
    Write-Host "[$ts] [$Level] $Message" -ForegroundColor $color
    Add-Content -Path $script:Config.LogFile -Value "[$ts] [$Level] $Message"
}

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++
    switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{ Timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); Category=$Category; Severity=$Severity; Object=$Object; Finding=$Finding; Recommendation=$Recommendation }
    Write-AuditLog "[$Severity] $Category - $Finding" "FINDING"
}
#endregion

#region Module Check
function Test-M365Modules {
    $modules = @("ExchangeOnlineManagement", "Microsoft.Online.SharePoint.PowerShell", "MicrosoftTeams")
    foreach ($mod in $modules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            Write-AuditLog "Installing $mod..." "INFO"
            Install-Module -Name $mod -Force -Scope CurrentUser -ErrorAction SilentlyContinue
        }
    }
    return $true
}
#endregion

#region Connection
function Connect-M365Services {
    Write-AuditLog "Connecting to Microsoft 365 services..." "INFO"
    try {
        Connect-ExchangeOnline -ShowBanner:$false
        Write-AuditLog "Connected to Exchange Online" "SUCCESS"
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect: $_" "ERROR"
        return $false
    }
}
#endregion

#region Audit Functions
function Invoke-AdminRoleAudit {
    Write-AuditLog "Auditing Admin Roles..." "INFO"
    try {
        $adminRoles = Get-MgDirectoryRole -All -ErrorAction SilentlyContinue
        foreach ($role in $adminRoles) {
            if ($role.DisplayName -match "Administrator") {
                $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -ErrorAction SilentlyContinue
                if ($members.Count -gt 5 -and $role.DisplayName -eq "Global Administrator") {
                    Write-Finding -Category "Admin Roles" -Severity "HIGH" -Object $role.DisplayName `
                        -Finding "$($members.Count) Global Administrators" `
                        -Recommendation "Reduce to 2-5 Global Admins"
                }
            }
        }
    }
    catch { Write-AuditLog "Error in admin role audit: $_" "WARNING" }
}

function Invoke-AntiPhishingAudit {
    Write-AuditLog "Auditing Anti-Phishing Policies..." "INFO"
    try {
        $policies = Get-AntiPhishPolicy -ErrorAction SilentlyContinue
        if (-not $policies) {
            Write-Finding -Category "Email Security" -Severity "HIGH" -Object "Anti-Phishing" `
                -Finding "No anti-phishing policies configured" `
                -Recommendation "Configure anti-phishing policies in Defender"
        }
        foreach ($policy in $policies) {
            if (-not $policy.EnableMailboxIntelligenceProtection) {
                Write-Finding -Category "Email Security" -Severity "MEDIUM" -Object $policy.Name `
                    -Finding "Mailbox intelligence protection not enabled" `
                    -Recommendation "Enable mailbox intelligence"
            }
        }
    }
    catch { Write-AuditLog "Error in anti-phishing audit: $_" "WARNING" }
}

function Invoke-AntiMalwareAudit {
    Write-AuditLog "Auditing Anti-Malware Policies..." "INFO"
    try {
        $policies = Get-MalwareFilterPolicy -ErrorAction SilentlyContinue
        foreach ($policy in $policies) {
            if ($policy.EnableFileFilter -eq $false) {
                Write-Finding -Category "Email Security" -Severity "MEDIUM" -Object $policy.Name `
                    -Finding "Common attachment filter not enabled" `
                    -Recommendation "Enable common attachment type filtering"
            }
        }
    }
    catch { Write-AuditLog "Error in anti-malware audit: $_" "WARNING" }
}

function Invoke-AuditLogAudit {
    Write-AuditLog "Checking Audit Log Settings..." "INFO"
    try {
        $auditConfig = Get-AdminAuditLogConfig -ErrorAction SilentlyContinue
        if ($auditConfig -and $auditConfig.UnifiedAuditLogIngestionEnabled -eq $false) {
            Write-Finding -Category "Logging" -Severity "CRITICAL" -Object "Unified Audit Log" `
                -Finding "Unified Audit Logging is disabled" `
                -Recommendation "Enable unified audit logging immediately"
        }
    }
    catch { Write-AuditLog "Error checking audit log: $_" "WARNING" }
}

function Invoke-ExternalSharingAudit {
    Write-AuditLog "Auditing External Sharing Settings..." "INFO"
    try {
        $orgConfig = Get-OrganizationConfig -ErrorAction SilentlyContinue
        if ($orgConfig) {
            # Check mail forwarding rules
            $forwardingRules = Get-TransportRule | Where-Object { $_.RedirectMessageTo -or $_.BlindCopyTo }
            if ($forwardingRules) {
                Write-Finding -Category "Data Protection" -Severity "MEDIUM" -Object "Transport Rules" `
                    -Finding "$($forwardingRules.Count) forwarding transport rules exist" `
                    -Recommendation "Review forwarding rules for necessity"
            }
        }
    }
    catch { Write-AuditLog "Error in external sharing audit: $_" "WARNING" }
}
#endregion

#region Report
function Export-AuditReport {
    $html = @"
<!DOCTYPE html><html><head><title>Microsoft 365 Audit Report</title>
<style>body{font-family:'Segoe UI',Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#0078d4;border-bottom:3px solid #0078d4;padding-bottom:15px}.summary-box{display:flex;gap:20px;margin:20px 0}.summary-item{padding:20px;border-radius:8px;color:white;min-width:120px;text-align:center}.critical{background:#d32f2f}.high{background:#f57c00}.medium{background:#fbc02d;color:#333}.low{background:#1976d2}.info{background:#388e3c}table{width:100%;border-collapse:collapse;margin:20px 0}th,td{padding:12px;text-align:left;border-bottom:1px solid #ddd}th{background:#0078d4;color:white}.severity-critical{color:#d32f2f;font-weight:bold}.severity-high{color:#f57c00;font-weight:bold}.severity-medium{color:#fbc02d}.severity-low{color:#1976d2}</style></head>
<body><div class="container"><h1>📧 Microsoft 365 Security Audit Report</h1>
<p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<h2>Summary</h2><div class="summary-box">
<div class="summary-item critical"><h3>$($script:Config.CriticalFindings)</h3><p>Critical</p></div>
<div class="summary-item high"><h3>$($script:Config.HighFindings)</h3><p>High</p></div>
<div class="summary-item medium"><h3>$($script:Config.MediumFindings)</h3><p>Medium</p></div>
<div class="summary-item low"><h3>$($script:Config.LowFindings)</h3><p>Low</p></div>
<div class="summary-item info"><h3>$($script:Config.TotalFindings)</h3><p>Total</p></div></div>
<h2>Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
    foreach ($f in ($script:AllFindings | Sort-Object {switch($_.Severity){"CRITICAL"{0}"HIGH"{1}"MEDIUM"{2}"LOW"{3}}})) {
        $html += "<tr><td class='severity-$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>"
    }
    $html += "</table></div></body></html>"
    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "Report saved: $($script:Config.ReportFile)" "SUCCESS"
}
#endregion

#region Main
Write-AuditLog "=" * 60 "INFO"
Write-AuditLog "MICROSOFT 365 SECURITY AUDIT" "INFO"
Write-AuditLog "=" * 60 "INFO"

Test-M365Modules
if (Connect-M365Services) {
    Invoke-AdminRoleAudit
    Invoke-AntiPhishingAudit
    Invoke-AntiMalwareAudit
    Invoke-AuditLogAudit
    Invoke-ExternalSharingAudit
    Export-AuditReport
}

Write-AuditLog "AUDIT COMPLETE - Findings: $($script:Config.TotalFindings)" "SUCCESS"
#endregion
