<#
.SYNOPSIS
    Get-AzureDiskReport.ps1 - Azure Managed Disk Inventory

.DESCRIPTION
    Inventories all managed disks including orphaned disks and encryption status.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureDiskReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureDiskReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureDiskReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║               AZURE MANAGED DISK INVENTORY                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Disk Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Disks = Get-AzDisk
    
    foreach ($Disk in $Disks) {
        $IsOrphaned = [string]::IsNullOrEmpty($Disk.ManagedBy)
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $Disk.ResourceGroupName
            DiskName            = $Disk.Name
            Location            = $Disk.Location
            DiskSizeGB          = $Disk.DiskSizeGB
            DiskState           = $Disk.DiskState
            SkuName             = $Disk.Sku.Name
            SkuTier             = $Disk.Sku.Tier
            OsType              = $Disk.OsType
            EncryptionType      = $Disk.Encryption.Type
            AttachedTo          = if ($Disk.ManagedBy) { $Disk.ManagedBy.Split("/")[-1] } else { "Unattached" }
            IsOrphaned          = $IsOrphaned
            TimeCreated         = $Disk.TimeCreated
            Tags                = if ($Disk.Tags) { ($Disk.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; " } else { "" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$OrphanedCount = ($Results | Where-Object { $_.IsOrphaned }).Count
$TotalSizeGB = ($Results | Measure-Object -Property DiskSizeGB -Sum).Sum

Write-Host "`nTotal Disks:        $($Results.Count)" -ForegroundColor White
Write-Host "Total Storage:      $TotalSizeGB GB" -ForegroundColor White
Write-Host "Orphaned Disks:     $OrphanedCount" -ForegroundColor $(if ($OrphanedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Disk Inventory Completed ==========" -Level "SUCCESS"
