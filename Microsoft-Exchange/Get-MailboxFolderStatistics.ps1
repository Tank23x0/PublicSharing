<#
.SYNOPSIS
    Get-MailboxFolderStatistics.ps1 - Detailed Folder Size Analysis

.DESCRIPTION
    Analyzes folder sizes and item counts within a mailbox.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-MailboxFolderStatistics.ps1 -Mailbox user@domain.com
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Mailbox,
    
    [string]$OutputPath = "$env:USERPROFILE\Documents\FolderStats_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-MailboxFolderStatistics"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            MAILBOX FOLDER STATISTICS ANALYZER                    ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Analysis Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

Write-Log "Analyzing folders for: $Mailbox" -Level "INFO"

$FolderStats = Get-EXOMailboxFolderStatistics -Identity $Mailbox
$Results = foreach ($Folder in $FolderStats) {
    $SizeBytes = 0
    if ($Folder.FolderSize) {
        $SizeString = $Folder.FolderSize.ToString()
        if ($SizeString -match "\(([0-9,]+)\s*bytes\)") {
            $SizeBytes = [double]($Matches[1] -replace ",", "")
        }
    }
    
    [PSCustomObject]@{
        FolderPath      = $Folder.FolderPath
        FolderType      = $Folder.FolderType
        ItemsInFolder   = $Folder.ItemsInFolder
        FolderSize      = $Folder.FolderSize
        FolderSizeMB    = [math]::Round($SizeBytes / 1MB, 2)
        ItemsInFolderAndSubfolders = $Folder.ItemsInFolderAndSubfolders
        DeletedItemsInFolder = $Folder.DeletedItemsInFolder
        OldestItemReceivedDate = $Folder.OldestItemReceivedDate
        NewestItemReceivedDate = $Folder.NewestItemReceivedDate
    }
}

$Results | Sort-Object FolderSizeMB -Descending | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$TotalFolders = $Results.Count
$TotalItems = ($Results | Measure-Object -Property ItemsInFolder -Sum).Sum
$TotalSizeMB = ($Results | Measure-Object -Property FolderSizeMB -Sum).Sum

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nTotal Folders: $TotalFolders" -ForegroundColor White
Write-Host "Total Items:   $TotalItems" -ForegroundColor White
Write-Host "Total Size:    $([math]::Round($TotalSizeMB / 1024, 2)) GB" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Analysis Completed ==========" -Level "SUCCESS"
