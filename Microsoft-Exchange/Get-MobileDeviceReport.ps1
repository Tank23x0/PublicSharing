<#
.SYNOPSIS
    Get-MobileDeviceReport.ps1 - Mobile Device Inventory for Exchange

.DESCRIPTION
    Reports on all mobile devices connected to Exchange Online via ActiveSync.
    Identifies device types, OS versions, and potential security concerns.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-MobileDeviceReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MobileDeviceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-MobileDeviceReport"
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
║               MOBILE DEVICE REPORT GENERATOR                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Mobile Device Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Retrieving mobile devices..." -Level "INFO"
$Devices = Get-MobileDevice -ResultSize Unlimited
Write-Log "Found $($Devices.Count) mobile devices" -Level "SUCCESS"

$Results = foreach ($Device in $Devices) {
    [PSCustomObject]@{
        UserDisplayName     = $Device.UserDisplayName
        DeviceType          = $Device.DeviceType
        DeviceModel         = $Device.DeviceModel
        DeviceOS            = $Device.DeviceOS
        DeviceFriendlyName  = $Device.DeviceFriendlyName
        DeviceId            = $Device.DeviceId
        FirstSyncTime       = $Device.FirstSyncTime
        LastSuccessSync     = $Device.LastSuccessSync
        DeviceAccessState   = $Device.DeviceAccessState
        DevicePolicyApplied = $Device.DevicePolicyApplied
        IsManaged           = $Device.IsManaged
        IsCompliant         = $Device.IsCompliant
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Devices: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
