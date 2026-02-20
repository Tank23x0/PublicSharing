<#
.SYNOPSIS
    Get-DKIMReport.ps1 - DKIM Configuration Status Report

.DESCRIPTION
    Reports on DKIM signing configuration for all accepted domains.
    Identifies domains without DKIM configured.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-DKIMReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\DKIMReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-DKIMReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                DKIM CONFIGURATION REPORT                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== DKIM Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Retrieving DKIM configuration..." -Level "INFO"

$DKIMConfigs = Get-DkimSigningConfig
$AcceptedDomains = Get-AcceptedDomain

$Results = foreach ($Domain in $AcceptedDomains) {
    $DKIMConfig = $DKIMConfigs | Where-Object { $_.Domain -eq $Domain.DomainName }
    
    $Status = if ($DKIMConfig) {
        if ($DKIMConfig.Enabled) { "Enabled" } else { "Disabled" }
    }
    else { "Not Configured" }
    
    [PSCustomObject]@{
        Domain              = $Domain.DomainName
        DomainType          = $Domain.DomainType
        IsDefault           = $Domain.Default
        DKIMStatus          = $Status
        DKIMEnabled         = if ($DKIMConfig) { $DKIMConfig.Enabled } else { $false }
        Selector1CNAME      = if ($DKIMConfig) { $DKIMConfig.Selector1CNAME } else { "N/A" }
        Selector2CNAME      = if ($DKIMConfig) { $DKIMConfig.Selector2CNAME } else { "N/A" }
        KeyCreationTime     = if ($DKIMConfig) { $DKIMConfig.KeyCreationTime } else { "N/A" }
        LastChecked         = if ($DKIMConfig) { $DKIMConfig.LastChecked } else { "N/A" }
        RiskLevel           = if ($Status -eq "Enabled") { "Low" } elseif ($Status -eq "Disabled") { "Medium" } else { "High" }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$NotConfigured = ($Results | Where-Object { $_.DKIMStatus -eq "Not Configured" }).Count
$Disabled = ($Results | Where-Object { $_.DKIMStatus -eq "Disabled" }).Count

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Domains:    $($Results.Count)" -ForegroundColor White
Write-Host "DKIM Enabled:     $(($Results | Where-Object { $_.DKIMEnabled }).Count)" -ForegroundColor Green
Write-Host "DKIM Disabled:    $Disabled" -ForegroundColor $(if ($Disabled -gt 0) { "Yellow" } else { "Green" })
Write-Host "Not Configured:   $NotConfigured" -ForegroundColor $(if ($NotConfigured -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
