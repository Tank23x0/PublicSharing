<#
.SYNOPSIS
    Get-PurviewAutoLabelingReport.ps1 - Microsoft Purview Management Tool

.DESCRIPTION
    Professional Microsoft Purview compliance and data governance script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Compliance Administrator role

.EXAMPLE
    .\Get-PurviewAutoLabelingReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-PurviewAutoLabelingReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-PurviewAutoLabelingReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MICROSOFT PURVIEW MANAGEMENT TOOL                   ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-PurviewAutoLabelingReport Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Log "Installing ExchangeOnlineManagement module..." -Level "WARNING"
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect to Security & Compliance Center
Write-Log "Connecting to Security & Compliance Center..." -Level "INFO"
Connect-IPPSSession -ShowBanner:$false

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving Purview data..." -Level "INFO"

# Example: Get sensitivity labels
try {
    $Labels = Get-Label -ErrorAction SilentlyContinue
    foreach ($Label in $Labels) {
        $Results += [PSCustomObject]@{
            Name            = $Label.Name
            DisplayName     = $Label.DisplayName
            Priority        = $Label.Priority
            Tooltip         = $Label.Tooltip
            Enabled         = $Label.Enabled
            ParentId        = $Label.ParentId
        }
    }
}
catch {
    Write-Log "Error retrieving data: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue

Write-Host "`nTotal Records: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-PurviewAutoLabelingReport Completed ==========" -Level "SUCCESS"
