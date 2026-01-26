<#
.SYNOPSIS
    Remove-AzureOrphanedResources.ps1 - Clean Up Orphaned Azure Resources

.DESCRIPTION
    Identifies and optionally removes orphaned resources (disks, NICs, public IPs, NSGs).

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Remove-AzureOrphanedResources.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureOrphanedResources_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Remove-AzureOrphanedResources"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            AZURE ORPHANED RESOURCE CLEANUP                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Orphaned Resource Scan Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Scanning: $($Sub.Name)" -Level "INFO"
    
    # Orphaned Disks
    $OrphanedDisks = Get-AzDisk | Where-Object { [string]::IsNullOrEmpty($_.ManagedBy) }
    foreach ($Disk in $OrphanedDisks) {
        $Results += [PSCustomObject]@{
            Subscription = $Sub.Name
            ResourceGroup = $Disk.ResourceGroupName
            ResourceName = $Disk.Name
            ResourceType = "Disk"
            SizeGB = $Disk.DiskSizeGB
            ResourceId = $Disk.Id
        }
    }
    
    # Orphaned NICs
    $OrphanedNICs = Get-AzNetworkInterface | Where-Object { [string]::IsNullOrEmpty($_.VirtualMachine) }
    foreach ($NIC in $OrphanedNICs) {
        $Results += [PSCustomObject]@{
            Subscription = $Sub.Name
            ResourceGroup = $NIC.ResourceGroupName
            ResourceName = $NIC.Name
            ResourceType = "NIC"
            SizeGB = "N/A"
            ResourceId = $NIC.Id
        }
    }
    
    # Orphaned Public IPs
    $OrphanedPIPs = Get-AzPublicIpAddress | Where-Object { [string]::IsNullOrEmpty($_.IpConfiguration) }
    foreach ($PIP in $OrphanedPIPs) {
        $Results += [PSCustomObject]@{
            Subscription = $Sub.Name
            ResourceGroup = $PIP.ResourceGroupName
            ResourceName = $PIP.Name
            ResourceType = "PublicIP"
            SizeGB = "N/A"
            ResourceId = $PIP.Id
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$DiskCount = ($Results | Where-Object { $_.ResourceType -eq "Disk" }).Count
$NICCount = ($Results | Where-Object { $_.ResourceType -eq "NIC" }).Count
$PIPCount = ($Results | Where-Object { $_.ResourceType -eq "PublicIP" }).Count
$TotalDiskSizeGB = ($Results | Where-Object { $_.ResourceType -eq "Disk" } | Measure-Object -Property SizeGB -Sum).Sum

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "ORPHANED RESOURCES FOUND" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Orphaned Disks:      $DiskCount ($TotalDiskSizeGB GB)" -ForegroundColor White
Write-Host "Orphaned NICs:       $NICCount" -ForegroundColor White
Write-Host "Orphaned Public IPs: $PIPCount" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Orphaned Resource Scan Completed ==========" -Level "SUCCESS"
