<#
.SYNOPSIS
    Get-AzureAKSReport.ps1 - Azure Kubernetes Service Inventory

.DESCRIPTION
    Inventories all AKS clusters with node pools and configurations.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureAKSReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureAKSReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureAKSReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE KUBERNETES SERVICE INVENTORY                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== AKS Inventory Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Aks -ListAvailable)) {
    Install-Module -Name Az.Aks -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Clusters = Get-AzAksCluster -ErrorAction SilentlyContinue
    
    foreach ($Cluster in $Clusters) {
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $Cluster.ResourceGroupName
            ClusterName         = $Cluster.Name
            Location            = $Cluster.Location
            KubernetesVersion   = $Cluster.KubernetesVersion
            NodeResourceGroup   = $Cluster.NodeResourceGroup
            DnsPrefix           = $Cluster.DnsPrefix
            Fqdn                = $Cluster.Fqdn
            NetworkPlugin       = $Cluster.NetworkProfile.NetworkPlugin
            NodePoolCount       = $Cluster.AgentPoolProfiles.Count
            TotalNodeCount      = ($Cluster.AgentPoolProfiles | Measure-Object -Property Count -Sum).Sum
            EnableRBAC          = $Cluster.EnableRBAC
            ProvisioningState   = $Cluster.ProvisioningState
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal AKS Clusters: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== AKS Inventory Completed ==========" -Level "SUCCESS"
