<#
.SYNOPSIS
    Get-EDiscoveryHoldReport.ps1 - eDiscovery Hold Status Report

.DESCRIPTION
    Reports on mailboxes with eDiscovery holds applied.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-EDiscoveryHoldReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\EDiscoveryHoldReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-EDiscoveryHoldReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             EDISCOVERY HOLD STATUS REPORT                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets Hold | Where-Object { $_.InPlaceHolds -or $_.LitigationHoldEnabled }
Write-Log "Found $($Mailboxes.Count) mailboxes with holds" -Level "SUCCESS"

$Results = foreach ($MB in $Mailboxes) {
    [PSCustomObject]@{
        DisplayName         = $MB.DisplayName
        UserPrincipalName   = $MB.UserPrincipalName
        LitigationHoldEnabled = $MB.LitigationHoldEnabled
        LitigationHoldDuration = $MB.LitigationHoldDuration
        LitigationHoldOwner = $MB.LitigationHoldOwner
        InPlaceHolds        = ($MB.InPlaceHolds -join "; ")
        HoldCount           = $MB.InPlaceHolds.Count
        RetentionHoldEnabled = $MB.RetentionHoldEnabled
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$LitHold = ($Results | Where-Object { $_.LitigationHoldEnabled }).Count

Write-Host "`nMailboxes with Holds: $($Results.Count)" -ForegroundColor White
Write-Host "Litigation Hold:      $LitHold" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
