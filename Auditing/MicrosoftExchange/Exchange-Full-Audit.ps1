<#
.SYNOPSIS
    Microsoft Exchange Online Security Audit Script
.VERSION
    2.0.0
#>

#Requires -Version 5.1

[CmdletBinding()]
param([string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Exchange-Audit")

$script:AllFindings = @()
$script:Config = @{TotalFindings=0;CriticalFindings=0;HighFindings=0;MediumFindings=0;LowFindings=0}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$ReportFile = Join-Path $OutputPath "Exchange-Audit-Report_$timestamp.html"

function Write-Finding { param([string]$Category, [string]$Severity, [string]$Object, [string]$Finding, [string]$Recommendation)
    $script:Config.TotalFindings++
    switch ($Severity) { "CRITICAL" { $script:Config.CriticalFindings++ } "HIGH" { $script:Config.HighFindings++ } "MEDIUM" { $script:Config.MediumFindings++ } "LOW" { $script:Config.LowFindings++ } }
    $script:AllFindings += [PSCustomObject]@{Category=$Category;Severity=$Severity;Object=$Object;Finding=$Finding;Recommendation=$Recommendation}
    Write-Host "[$Severity] $Finding" -ForegroundColor $(switch($Severity){"CRITICAL"{"Red"}"HIGH"{"DarkYellow"}"MEDIUM"{"Yellow"}"LOW"{"Cyan"}})
}

Write-Host "=== EXCHANGE ONLINE SECURITY AUDIT ===" -ForegroundColor Cyan

try {
    $context = Get-ConnectionInformation -ErrorAction SilentlyContinue
    if (-not $context) { Connect-ExchangeOnline -ShowBanner:$false }
    
    # Mailbox Forwarding Audit
    Write-Host "Checking mailbox forwarding..." -ForegroundColor White
    $forwarding = Get-Mailbox -ResultSize Unlimited | Where-Object {$_.ForwardingSmtpAddress -or $_.ForwardingAddress}
    if ($forwarding) {
        Write-Finding -Category "Mail Flow" -Severity "HIGH" -Object "Forwarding" `
            -Finding "$($forwarding.Count) mailboxes have forwarding enabled" `
            -Recommendation "Review and disable unnecessary forwarding"
    }
    
    # Inbox Rules with External Forwarding
    Write-Host "Checking inbox rules..." -ForegroundColor White
    $mailboxes = Get-Mailbox -ResultSize 100
    foreach ($mbx in $mailboxes) {
        $rules = Get-InboxRule -Mailbox $mbx.UserPrincipalName -ErrorAction SilentlyContinue | 
            Where-Object {$_.ForwardTo -or $_.RedirectTo -or $_.ForwardAsAttachmentTo}
        if ($rules) {
            Write-Finding -Category "Mail Flow" -Severity "MEDIUM" -Object $mbx.UserPrincipalName `
                -Finding "Inbox rules with forwarding detected" `
                -Recommendation "Review inbox forwarding rules"
        }
    }
    
    # Admin Audit Log
    Write-Host "Checking audit configuration..." -ForegroundColor White
    $auditConfig = Get-AdminAuditLogConfig
    if (-not $auditConfig.UnifiedAuditLogIngestionEnabled) {
        Write-Finding -Category "Logging" -Severity "CRITICAL" -Object "Audit Log" `
            -Finding "Unified audit logging is disabled" `
            -Recommendation "Enable unified audit logging"
    }
    
    # Anti-Spam Policies
    Write-Host "Checking anti-spam policies..." -ForegroundColor White
    $spamPolicies = Get-HostedContentFilterPolicy
    foreach ($policy in $spamPolicies) {
        if ($policy.BulkThreshold -gt 7) {
            Write-Finding -Category "Spam Protection" -Severity "LOW" -Object $policy.Name `
                -Finding "Bulk mail threshold is permissive ($($policy.BulkThreshold))" `
                -Recommendation "Consider lowering bulk threshold"
        }
    }
    
    # DKIM Status
    Write-Host "Checking DKIM..." -ForegroundColor White
    $domains = Get-AcceptedDomain
    foreach ($domain in $domains) {
        $dkim = Get-DkimSigningConfig -Identity $domain.DomainName -ErrorAction SilentlyContinue
        if (-not $dkim -or -not $dkim.Enabled) {
            Write-Finding -Category "Email Authentication" -Severity "MEDIUM" -Object $domain.DomainName `
                -Finding "DKIM not enabled for domain" `
                -Recommendation "Enable DKIM signing"
        }
    }
    
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}

# Generate Report
$html = @"
<!DOCTYPE html><html><head><title>Exchange Audit</title>
<style>body{font-family:Arial;margin:40px;background:#f5f5f5}.container{max-width:1200px;margin:0 auto;background:white;padding:30px;border-radius:8px}h1{color:#0078d4}table{width:100%;border-collapse:collapse}th,td{padding:10px;text-align:left;border-bottom:1px solid #ddd}th{background:#0078d4;color:white}.critical{color:#d32f2f}.high{color:#f57c00}.medium{color:#fbc02d}.low{color:#1976d2}</style></head>
<body><div class="container"><h1>📬 Exchange Online Security Audit</h1>
<p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
<p>Findings: Critical=$($script:Config.CriticalFindings), High=$($script:Config.HighFindings), Medium=$($script:Config.MediumFindings), Low=$($script:Config.LowFindings)</p>
<table><tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
"@
foreach ($f in $script:AllFindings) { $html += "<tr><td class='$($f.Severity.ToLower())'>$($f.Severity)</td><td>$($f.Category)</td><td>$($f.Object)</td><td>$($f.Finding)</td><td>$($f.Recommendation)</td></tr>" }
$html += "</table></div></body></html>"
$html | Out-File $ReportFile -Encoding UTF8
Write-Host "Report saved: $ReportFile" -ForegroundColor Green
