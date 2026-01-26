<#
.SYNOPSIS
    Get-SafeLinksReport.ps1 - Safe Links Policy Configuration Report

.DESCRIPTION
    Reports on Microsoft Defender for Office 365 Safe Links policies.
    Identifies gaps in URL protection coverage.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-SafeLinksReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\SafeLinksReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-SafeLinksReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    $Color = switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $Color
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              SAFE LINKS POLICY REPORT GENERATOR                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Safe Links Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Retrieving Safe Links policies..." -Level "INFO"

try {
    $Policies = Get-SafeLinksPolicy -ErrorAction Stop
    Write-Log "Found $($Policies.Count) Safe Links policies" -Level "SUCCESS"
}
catch {
    Write-Log "Safe Links not available (requires Defender for Office 365)" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$Results = foreach ($Policy in $Policies) {
    $Issues = @()
    if (-not $Policy.EnableSafeLinksForEmail) { $Issues += "Email scanning disabled" }
    if (-not $Policy.EnableSafeLinksForTeams) { $Issues += "Teams scanning disabled" }
    if (-not $Policy.EnableSafeLinksForOffice) { $Issues += "Office apps scanning disabled" }
    if (-not $Policy.TrackClicks) { $Issues += "Click tracking disabled" }
    if ($Policy.AllowClickThrough) { $Issues += "Click-through allowed" }
    
    [PSCustomObject]@{
        Name                        = $Policy.Name
        IsEnabled                   = $Policy.IsEnabled
        EnableSafeLinksForEmail     = $Policy.EnableSafeLinksForEmail
        EnableSafeLinksForTeams     = $Policy.EnableSafeLinksForTeams
        EnableSafeLinksForOffice    = $Policy.EnableSafeLinksForOffice
        TrackClicks                 = $Policy.TrackClicks
        AllowClickThrough           = $Policy.AllowClickThrough
        ScanUrls                    = $Policy.ScanUrls
        EnableForInternalSenders    = $Policy.EnableForInternalSenders
        DeliverMessageAfterScan     = $Policy.DeliverMessageAfterScan
        DisableUrlRewrite           = $Policy.DisableUrlRewrite
        DoNotRewriteUrls            = ($Policy.DoNotRewriteUrls -join "; ")
        Issues                      = ($Issues -join "; ")
        RiskLevel                   = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Policies: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:      $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
