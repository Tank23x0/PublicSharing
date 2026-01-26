<#
.SYNOPSIS
    Get-AzureLoadBalancerReport.ps1 - Azure Load Balancer Inventory

.DESCRIPTION
    Inventories all Azure Load Balancers with backend pools and health probes.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureLoadBalancerReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureLoadBalancerReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureLoadBalancerReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE LOAD BALANCER INVENTORY                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Load Balancer Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $LoadBalancers = Get-AzLoadBalancer
    
    foreach ($LB in $LoadBalancers) {
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $LB.ResourceGroupName
            Name                = $LB.Name
            Location            = $LB.Location
            Sku                 = $LB.Sku.Name
            FrontendIPCount     = $LB.FrontendIpConfigurations.Count
            BackendPoolCount    = $LB.BackendAddressPools.Count
            LoadBalancingRuleCount = $LB.LoadBalancingRules.Count
            ProbeCount          = $LB.Probes.Count
            NatRuleCount        = $LB.InboundNatRules.Count
            ProvisioningState   = $LB.ProvisioningState
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Load Balancers: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Load Balancer Inventory Completed ==========" -Level "SUCCESS"
