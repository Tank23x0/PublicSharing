<#
.SYNOPSIS
    Get-AzureVMInventory.ps1 - Azure Virtual Machine Inventory

.DESCRIPTION
    Comprehensive inventory of all Azure VMs including size, OS, disk, and network details.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureVMInventory.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureVMInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureVMInventory"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE VIRTUAL MACHINE INVENTORY                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== VM Inventory Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Compute -ListAvailable)) {
    Install-Module -Name Az.Compute -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $VMs = Get-AzVM -Status
    
    foreach ($VM in $VMs) {
        $OSType = if ($VM.StorageProfile.OsDisk.OsType) { $VM.StorageProfile.OsDisk.OsType } else { "Unknown" }
        $OSPublisher = if ($VM.StorageProfile.ImageReference) { $VM.StorageProfile.ImageReference.Publisher } else { "" }
        $OSOffer = if ($VM.StorageProfile.ImageReference) { $VM.StorageProfile.ImageReference.Offer } else { "" }
        $OSSku = if ($VM.StorageProfile.ImageReference) { $VM.StorageProfile.ImageReference.Sku } else { "" }
        
        $DataDiskCount = if ($VM.StorageProfile.DataDisks) { $VM.StorageProfile.DataDisks.Count } else { 0 }
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $VM.ResourceGroupName
            VMName              = $VM.Name
            Location            = $VM.Location
            VMSize              = $VM.HardwareProfile.VmSize
            PowerState          = ($VM.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
            ProvisioningState   = $VM.ProvisioningState
            OSType              = $OSType
            OSPublisher         = $OSPublisher
            OSOffer             = $OSOffer
            OSSku               = $OSSku
            OSDiskSize          = $VM.StorageProfile.OsDisk.DiskSizeGB
            DataDiskCount       = $DataDiskCount
            AvailabilitySet     = if ($VM.AvailabilitySetReference) { $VM.AvailabilitySetReference.Id.Split("/")[-1] } else { "" }
            Tags                = if ($VM.Tags) { ($VM.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; " } else { "" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$RunningVMs = ($Results | Where-Object { $_.PowerState -eq "VM running" }).Count
$StoppedVMs = ($Results | Where-Object { $_.PowerState -ne "VM running" }).Count

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total VMs:     $($Results.Count)" -ForegroundColor White
Write-Host "Running:       $RunningVMs" -ForegroundColor Green
Write-Host "Stopped:       $StoppedVMs" -ForegroundColor Yellow
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== VM Inventory Completed ==========" -Level "SUCCESS"
