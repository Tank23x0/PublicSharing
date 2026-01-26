<#
.SYNOPSIS
    Get-ATPreport.ps1 - Advanced Threat Protection Status Report

.DESCRIPTION
    Reports on Microsoft Defender for Office 365 ATP policy configuration.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-ATPreport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\ATPReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-ATPreport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║        ADVANCED THREAT PROTECTION STATUS REPORT                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== ATP Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Results = @()

# Anti-Phishing Policies
try {
    $AntiPhish = Get-AntiPhishPolicy
    foreach ($Policy in $AntiPhish) {
        $Results += [PSCustomObject]@{
            PolicyType      = "Anti-Phishing"
            Name            = $Policy.Name
            Enabled         = $Policy.Enabled
            ImpersonationProtection = $Policy.EnableTargetedUserProtection
            MailboxIntelligence = $Policy.EnableMailboxIntelligence
            SpoofIntelligence = $Policy.EnableSpoofIntelligence
        }
    }
}
catch { Write-Log "Could not retrieve Anti-Phishing policies: $_" -Level "WARNING" }

# Anti-Malware Policies
try {
    $AntiMalware = Get-MalwareFilterPolicy
    foreach ($Policy in $AntiMalware) {
        $Results += [PSCustomObject]@{
            PolicyType      = "Anti-Malware"
            Name            = $Policy.Name
            Enabled         = $true
            ZAPEnabled      = $Policy.ZapEnabled
            FileTypeFilter  = $Policy.EnableFileFilter
            CommonAttachmentFilter = ($Policy.FileTypes -join ", ")
        }
    }
}
catch { Write-Log "Could not retrieve Anti-Malware policies: $_" -Level "WARNING" }

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nATP Policies Found: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
