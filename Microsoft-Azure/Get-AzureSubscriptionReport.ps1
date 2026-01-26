<#
.SYNOPSIS
    Get-AzureSubscriptionReport.ps1 - Azure SubscriptionReport Tool

.DESCRIPTION
    Professional Azure management script for SubscriptionReport operations.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureSubscriptionReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-AzureSubscriptionReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureSubscriptionReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE SubscriptionReport TOOL                                  ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== SubscriptionReport Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    # Add resource-specific logic here
    $Resources = Get-AzResource -ResourceGroupName "*" -ErrorAction SilentlyContinue | Select-Object -First 100
    
    foreach ($Resource in $Resources) {
        $Results += [PSCustomObject]@{
            Subscription = $Sub.Name
            ResourceGroup = $Resource.ResourceGroupName
            ResourceName = $Resource.Name
            ResourceType = $Resource.ResourceType
            Location = $Resource.Location
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Resources: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== SubscriptionReport Completed ==========" -Level "SUCCESS"
