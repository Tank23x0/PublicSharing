<#
.SYNOPSIS
    Get-ExternalForwardingReport.ps1 - External Email Forwarding Audit

.DESCRIPTION
    Identifies all mailboxes forwarding to external addresses. Critical security audit.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-ExternalForwardingReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\ExternalForwardingReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-ExternalForwardingReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║           EXTERNAL FORWARDING SECURITY AUDIT                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Security Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$AcceptedDomains = (Get-AcceptedDomain).DomainName
$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets Delivery | Where-Object { $_.ForwardingSmtpAddress }

$Results = foreach ($MB in $Mailboxes) {
    $ForwardAddress = $MB.ForwardingSmtpAddress -replace "smtp:", ""
    $Domain = $ForwardAddress.Split("@")[1]
    $IsExternal = $Domain -notin $AcceptedDomains
    
    if ($IsExternal) {
        [PSCustomObject]@{
            DisplayName         = $MB.DisplayName
            UserPrincipalName   = $MB.UserPrincipalName
            ForwardingTo        = $ForwardAddress
            ForwardingDomain    = $Domain
            DeliverToMailbox    = $MB.DeliverToMailboxAndForward
            RiskLevel           = "HIGH"
        }
    }
}

Write-Log "Found $($Results.Count) external forwarding rules" -Level $(if ($Results.Count -gt 0) { "WARNING" } else { "SUCCESS" })

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "EXTERNAL FORWARDING DETECTED: $($Results.Count)" -ForegroundColor $(if ($Results.Count -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Audit Completed ==========" -Level "SUCCESS"
