<#
.SYNOPSIS
    Get-AzureResourceLockReport.ps1 - Azure Resource Lock Inventory

.DESCRIPTION
    Inventories all resource locks to ensure critical resources are protected.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureResourceLockReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureResourceLockReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureResourceLockReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE RESOURCE LOCK INVENTORY                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Resource Lock Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Locks = Get-AzResourceLock
    
    foreach ($Lock in $Locks) {
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            LockName            = $Lock.Name
            LockLevel           = $Lock.Properties.level
            Notes               = $Lock.Properties.notes
            ResourceId          = $Lock.ResourceId
            Scope               = if ($Lock.ResourceId -match "/resourceGroups/([^/]+)") { $Matches[1] } else { "Subscription" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$DeleteLocks = ($Results | Where-Object { $_.LockLevel -eq "CanNotDelete" }).Count
$ReadOnlyLocks = ($Results | Where-Object { $_.LockLevel -eq "ReadOnly" }).Count

Write-Host "`nTotal Locks:      $($Results.Count)" -ForegroundColor White
Write-Host "CanNotDelete:     $DeleteLocks" -ForegroundColor White
Write-Host "ReadOnly:         $ReadOnlyLocks" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Resource Lock Inventory Completed ==========" -Level "SUCCESS"
