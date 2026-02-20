<#
.SYNOPSIS
    Get-EmailAddressPolicyReport.ps1 - Email Address Policy Configuration Report

.DESCRIPTION
    Reports on email address policies configured in Exchange Online.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-EmailAddressPolicyReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\EmailAddressPolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-EmailAddressPolicyReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            EMAIL ADDRESS POLICY REPORT GENERATOR                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Policies = Get-EmailAddressPolicy
$Results = foreach ($Policy in $Policies) {
    [PSCustomObject]@{
        Name                    = $Policy.Name
        Priority                = $Policy.Priority
        EnabledEmailAddressTemplates = ($Policy.EnabledEmailAddressTemplates -join "; ")
        EnabledPrimarySMTPAddressTemplate = $Policy.EnabledPrimarySMTPAddressTemplate
        RecipientFilter         = $Policy.RecipientFilter
        RecipientFilterApplied  = $Policy.RecipientFilterApplied
        WhenCreated             = $Policy.WhenCreated
        WhenChanged             = $Policy.WhenChanged
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nTotal Policies: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
