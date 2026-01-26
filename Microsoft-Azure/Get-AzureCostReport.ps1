<#
.SYNOPSIS
    Get-AzureCostReport.ps1 - Azure Cost Analysis Report

.DESCRIPTION
    Analyzes Azure spending by subscription, resource group, and resource type.
    Identifies cost trends and expensive resources.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Az.Billing module
    - Cost Management Reader role

.EXAMPLE
    .\Get-AzureCostReport.ps1 -Days 30
#>

[CmdletBinding()]
param(
    [int]$Days = 30,
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureCostReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureCostReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                  AZURE COST ANALYSIS REPORT                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Cost Analysis Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Billing -ListAvailable)) {
    Install-Module -Name Az.Billing -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$StartDate = (Get-Date).AddDays(-$Days).ToString("yyyy-MM-dd")
$EndDate = (Get-Date).ToString("yyyy-MM-dd")

Write-Log "Analyzing costs from $StartDate to $EndDate" -Level "INFO"

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    try {
        $Usage = Get-AzConsumptionUsageDetail -StartDate $StartDate -EndDate $EndDate -ErrorAction SilentlyContinue
        
        if ($Usage) {
            $GroupedByResource = $Usage | Group-Object InstanceName
            
            foreach ($Group in $GroupedByResource) {
                $TotalCost = ($Group.Group | Measure-Object -Property PretaxCost -Sum).Sum
                $ResourceType = ($Group.Group | Select-Object -First 1).ConsumedService
                
                $Results += [PSCustomObject]@{
                    Subscription    = $Sub.Name
                    ResourceName    = $Group.Name
                    ResourceType    = $ResourceType
                    TotalCost       = [math]::Round($TotalCost, 2)
                    Currency        = ($Group.Group | Select-Object -First 1).Currency
                    UsageDays       = $Days
                    DailyAverage    = [math]::Round($TotalCost / $Days, 2)
                }
            }
        }
    }
    catch {
        Write-Log "Could not retrieve costs for $($Sub.Name): $_" -Level "WARNING"
    }
}

$Results = $Results | Sort-Object TotalCost -Descending
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$TotalSpend = ($Results | Measure-Object -Property TotalCost -Sum).Sum

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Period:          Last $Days days" -ForegroundColor White
Write-Host "Total Spend:     `$$([math]::Round($TotalSpend, 2))" -ForegroundColor White
Write-Host "Daily Average:   `$$([math]::Round($TotalSpend / $Days, 2))" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Cost Analysis Completed ==========" -Level "SUCCESS"
