<#
.SYNOPSIS
    Get-RoomMailboxReport.ps1 - Room and Resource Mailbox Report

.DESCRIPTION
    Reports on all room and equipment mailboxes in Exchange Online.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-RoomMailboxReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\RoomMailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-RoomMailboxReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║           ROOM & RESOURCE MAILBOX REPORT GENERATOR               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Rooms = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails RoomMailbox, EquipmentMailbox
Write-Log "Found $($Rooms.Count) room/equipment mailboxes" -Level "SUCCESS"

$Results = foreach ($Room in $Rooms) {
    $CalProcessing = Get-CalendarProcessing -Identity $Room.Identity -ErrorAction SilentlyContinue
    
    [PSCustomObject]@{
        DisplayName         = $Room.DisplayName
        PrimarySmtpAddress  = $Room.PrimarySmtpAddress
        RecipientType       = $Room.RecipientTypeDetails
        ResourceCapacity    = $Room.ResourceCapacity
        Office              = $Room.Office
        AutomateProcessing  = if ($CalProcessing) { $CalProcessing.AutomateProcessing } else { "N/A" }
        AllBookInPolicy     = if ($CalProcessing) { $CalProcessing.AllBookInPolicy } else { "N/A" }
        BookInPolicy        = if ($CalProcessing) { ($CalProcessing.BookInPolicy -join "; ") } else { "N/A" }
        AllRequestInPolicy  = if ($CalProcessing) { $CalProcessing.AllRequestInPolicy } else { "N/A" }
        AllowConflicts      = if ($CalProcessing) { $CalProcessing.AllowConflicts } else { "N/A" }
        WhenCreated         = $Room.WhenCreated
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$RoomCount = ($Results | Where-Object { $_.RecipientType -eq "RoomMailbox" }).Count
$EquipCount = ($Results | Where-Object { $_.RecipientType -eq "EquipmentMailbox" }).Count

Write-Host "`nRoom Mailboxes:      $RoomCount" -ForegroundColor White
Write-Host "Equipment Mailboxes: $EquipCount" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
