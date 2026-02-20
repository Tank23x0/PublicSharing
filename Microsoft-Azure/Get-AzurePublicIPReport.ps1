<#
.SYNOPSIS
    Get-AzurePublicIPReport.ps1 - Azure Public IP Inventory

.DESCRIPTION
    Inventories all public IP addresses including orphaned IPs.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzurePublicIPReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzurePublicIPReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzurePublicIPReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║               AZURE PUBLIC IP INVENTORY                          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Public IP Inventory Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $PublicIPs = Get-AzPublicIpAddress
    
    foreach ($PIP in $PublicIPs) {
        $IsOrphaned = [string]::IsNullOrEmpty($PIP.IpConfiguration)
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $PIP.ResourceGroupName
            Name                = $PIP.Name
            Location            = $PIP.Location
            IpAddress           = $PIP.IpAddress
            AllocationMethod    = $PIP.PublicIpAllocationMethod
            Sku                 = $PIP.Sku.Name
            AssociatedTo        = if ($PIP.IpConfiguration) { $PIP.IpConfiguration.Id.Split("/")[-3] } else { "Unassociated" }
            DnsLabel            = $PIP.DnsSettings.DomainNameLabel
            Fqdn                = $PIP.DnsSettings.Fqdn
            IsOrphaned          = $IsOrphaned
            Zones               = ($PIP.Zones -join ", ")
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$OrphanedCount = ($Results | Where-Object { $_.IsOrphaned }).Count

Write-Host "`nTotal Public IPs:   $($Results.Count)" -ForegroundColor White
Write-Host "Orphaned IPs:       $OrphanedCount" -ForegroundColor $(if ($OrphanedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Public IP Inventory Completed ==========" -Level "SUCCESS"
