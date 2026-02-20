<#
.SYNOPSIS
    Get-SafeAttachmentsReport.ps1 - Safe Attachments Policy Report

.DESCRIPTION
    Reports on Microsoft Defender for Office 365 Safe Attachments policies.
    Identifies gaps in attachment protection coverage.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-SafeAttachmentsReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\SafeAttachmentsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-SafeAttachmentsReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║           SAFE ATTACHMENTS POLICY REPORT GENERATOR               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Safe Attachments Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Retrieving Safe Attachments policies..." -Level "INFO"

try {
    $Policies = Get-SafeAttachmentPolicy -ErrorAction Stop
    Write-Log "Found $($Policies.Count) Safe Attachments policies" -Level "SUCCESS"
}
catch {
    Write-Log "Safe Attachments not available (requires Defender for Office 365)" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$Results = foreach ($Policy in $Policies) {
    $Issues = @()
    if (-not $Policy.Enable) { $Issues += "Policy disabled" }
    if ($Policy.Action -eq "Allow") { $Issues += "Action set to Allow (no protection)" }
    if (-not $Policy.QuarantineTag) { $Issues += "No quarantine tag configured" }
    
    [PSCustomObject]@{
        Name                    = $Policy.Name
        IsEnabled               = $Policy.Enable
        Action                  = $Policy.Action
        ActionOnError           = $Policy.ActionOnError
        Redirect                = $Policy.Redirect
        RedirectAddress         = $Policy.RedirectAddress
        QuarantineTag           = $Policy.QuarantineTag
        Issues                  = ($Issues -join "; ")
        RiskLevel               = if ($Issues.Count -ge 2 -or $Policy.Action -eq "Allow") { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Policies: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
