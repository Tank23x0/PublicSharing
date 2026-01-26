<#
.SYNOPSIS
    Get-AzureResourceGroupReport.ps1 - Azure Resource Group Inventory

.DESCRIPTION
    Inventories all resource groups with resource counts and tags.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureResourceGroupReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureResourceGroupReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureResourceGroupReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE RESOURCE GROUP INVENTORY                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Resource Group Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $ResourceGroups = Get-AzResourceGroup
    
    foreach ($RG in $ResourceGroups) {
        $Resources = Get-AzResource -ResourceGroupName $RG.ResourceGroupName
        $ResourceCount = $Resources.Count
        
        $Tags = if ($RG.Tags) { 
            ($RG.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; " 
        } else { "" }
        
        $Issues = @()
        if ($ResourceCount -eq 0) { $Issues += "Empty resource group" }
        if (-not $RG.Tags -or $RG.Tags.Count -eq 0) { $Issues += "No tags" }
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroupName   = $RG.ResourceGroupName
            Location            = $RG.Location
            ProvisioningState   = $RG.ProvisioningState
            ResourceCount       = $ResourceCount
            Tags                = $Tags
            TagCount            = if ($RG.Tags) { $RG.Tags.Count } else { 0 }
            Issues              = ($Issues -join "; ")
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$EmptyRGs = ($Results | Where-Object { $_.ResourceCount -eq 0 }).Count
$NoTagsRGs = ($Results | Where-Object { $_.TagCount -eq 0 }).Count

Write-Host "`nTotal Resource Groups: $($Results.Count)" -ForegroundColor White
Write-Host "Empty Groups:          $EmptyRGs" -ForegroundColor $(if ($EmptyRGs -gt 0) { "Yellow" } else { "Green" })
Write-Host "Without Tags:          $NoTagsRGs" -ForegroundColor $(if ($NoTagsRGs -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Resource Group Inventory Completed ==========" -Level "SUCCESS"
