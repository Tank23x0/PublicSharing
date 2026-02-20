<#
.SYNOPSIS
    Get-AntiSpamPolicyReport.ps1 - Anti-Spam Policy Configuration Report

.DESCRIPTION
    Documents all anti-spam policies in Exchange Online Protection.
    Identifies weak configurations and provides recommendations.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AntiSpamPolicyReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\AntiSpamPolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AntiSpamPolicyReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    $LogMessage = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    $Color = switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } }
    Write-Host $LogMessage -ForegroundColor $Color
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              ANTI-SPAM POLICY REPORT GENERATOR                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Anti-Spam Policy Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Retrieving anti-spam policies..." -Level "INFO"
$Policies = Get-HostedContentFilterPolicy

$Results = foreach ($Policy in $Policies) {
    $Issues = @()
    if ($Policy.SpamAction -eq "MoveToJmf") { $Issues += "Spam goes to Junk (consider Quarantine)" }
    if ($Policy.HighConfidenceSpamAction -eq "MoveToJmf") { $Issues += "High confidence spam goes to Junk" }
    if (-not $Policy.BulkSpamAction) { $Issues += "Bulk mail action not configured" }
    
    [PSCustomObject]@{
        Name                        = $Policy.Name
        IsDefault                   = $Policy.IsDefault
        SpamAction                  = $Policy.SpamAction
        HighConfidenceSpamAction    = $Policy.HighConfidenceSpamAction
        PhishSpamAction             = $Policy.PhishSpamAction
        HighConfidencePhishAction   = $Policy.HighConfidencePhishAction
        BulkSpamAction              = $Policy.BulkSpamAction
        BulkThreshold               = $Policy.BulkThreshold
        QuarantineRetentionPeriod   = $Policy.QuarantineRetentionPeriod
        EnableEndUserSpamNotifications = $Policy.EnableEndUserSpamNotifications
        AllowedSenders              = ($Policy.AllowedSenders -join "; ")
        AllowedSenderDomains        = ($Policy.AllowedSenderDomains -join "; ")
        BlockedSenders              = ($Policy.BlockedSenders -join "; ")
        BlockedSenderDomains        = ($Policy.BlockedSenderDomains -join "; ")
        Issues                      = ($Issues -join "; ")
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Policies: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
