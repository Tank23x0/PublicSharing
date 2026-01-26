<#
.SYNOPSIS
    Get-AzureVNetReport.ps1 - Azure Virtual Network Inventory

.DESCRIPTION
    Inventories all VNets with subnets, peering, and service endpoint information.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureVNetReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureVNetReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureVNetReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE VIRTUAL NETWORK INVENTORY                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== VNet Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $VNets = Get-AzVirtualNetwork
    
    foreach ($VNet in $VNets) {
        foreach ($Subnet in $VNet.Subnets) {
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                ResourceGroup       = $VNet.ResourceGroupName
                VNetName            = $VNet.Name
                VNetAddressSpace    = ($VNet.AddressSpace.AddressPrefixes -join ", ")
                Location            = $VNet.Location
                SubnetName          = $Subnet.Name
                SubnetAddressPrefix = ($Subnet.AddressPrefix -join ", ")
                NSG                 = if ($Subnet.NetworkSecurityGroup) { $Subnet.NetworkSecurityGroup.Id.Split("/")[-1] } else { "None" }
                ServiceEndpoints    = ($Subnet.ServiceEndpoints.Service -join ", ")
                PrivateEndpointNetworkPolicies = $Subnet.PrivateEndpointNetworkPolicies
                DnsServers          = ($VNet.DhcpOptions.DnsServers -join ", ")
                PeeringCount        = $VNet.VirtualNetworkPeerings.Count
                EnableDdosProtection = $VNet.EnableDdosProtection
            }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$VNetCount = ($Results | Select-Object -Property VNetName -Unique).Count

Write-Host "`nTotal VNets:    $VNetCount" -ForegroundColor White
Write-Host "Total Subnets:  $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== VNet Inventory Completed ==========" -Level "SUCCESS"
