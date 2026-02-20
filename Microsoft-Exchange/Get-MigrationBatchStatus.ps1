<#
.SYNOPSIS
    Get-MigrationBatchStatus.ps1 - Migration Batch Status Report

.DESCRIPTION
    Reports on current and historical migration batches in Exchange Online.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-MigrationBatchStatus.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\MigrationBatchStatus_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-MigrationBatchStatus"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MIGRATION BATCH STATUS REPORT                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Batches = Get-MigrationBatch
Write-Log "Found $($Batches.Count) migration batches" -Level "INFO"

$Results = foreach ($Batch in $Batches) {
    [PSCustomObject]@{
        Identity        = $Batch.Identity
        Status          = $Batch.Status
        Type            = $Batch.MigrationType
        Direction       = $Batch.Direction
        TotalCount      = $Batch.TotalCount
        SyncedCount     = $Batch.SyncedCount
        FinalizedCount  = $Batch.FinalizedCount
        FailedCount     = $Batch.FailedCount
        CreatedDateTime = $Batch.CreatedDateTime
        StartDateTime   = $Batch.StartDateTime
        CompleteDateTime = $Batch.CompleteDateTime
        CreatedBy       = $Batch.CreatedBy
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$InProgress = ($Results | Where-Object { $_.Status -match "Sync|InProgress" }).Count

Write-Host "`nTotal Batches:  $($Results.Count)" -ForegroundColor White
Write-Host "In Progress:    $InProgress" -ForegroundColor $(if ($InProgress -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
