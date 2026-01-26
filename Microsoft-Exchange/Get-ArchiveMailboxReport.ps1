<#
.SYNOPSIS
    Get-ArchiveMailboxReport.ps1 - Archive Mailbox Status Report

.DESCRIPTION
    Reports on all archive-enabled mailboxes with size and status information.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-ArchiveMailboxReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\ArchiveMailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-ArchiveMailboxReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              ARCHIVE MAILBOX STATUS REPORT                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -Archive
Write-Log "Found $($Mailboxes.Count) archive-enabled mailboxes" -Level "SUCCESS"

$Results = @()
$Counter = 0

foreach ($MB in $Mailboxes) {
    $Counter++
    if ($Counter % 50 -eq 0) {
        Write-Progress -Activity "Processing Archives" -Status "$Counter of $($Mailboxes.Count)" -PercentComplete (($Counter / $Mailboxes.Count) * 100)
    }
    
    $ArchiveStats = Get-EXOMailboxStatistics -Identity $MB.UserPrincipalName -Archive -ErrorAction SilentlyContinue
    
    $Results += [PSCustomObject]@{
        DisplayName     = $MB.DisplayName
        UserPrincipalName = $MB.UserPrincipalName
        ArchiveStatus   = $MB.ArchiveStatus
        ArchiveName     = $MB.ArchiveName
        ArchiveQuota    = $MB.ArchiveQuota
        ArchiveWarningQuota = $MB.ArchiveWarningQuota
        ArchiveSize     = if ($ArchiveStats) { $ArchiveStats.TotalItemSize } else { "N/A" }
        ArchiveItemCount = if ($ArchiveStats) { $ArchiveStats.ItemCount } else { "N/A" }
        AutoExpandingArchiveEnabled = $MB.AutoExpandingArchiveEnabled
    }
}

Write-Progress -Activity "Processing Archives" -Completed

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nArchive Mailboxes: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
