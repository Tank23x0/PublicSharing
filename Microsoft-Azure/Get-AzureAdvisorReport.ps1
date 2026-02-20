<#
.SYNOPSIS
    Get-AzureAdvisorReport.ps1 - Azure Advisor Recommendations Report

.DESCRIPTION
    Retrieves Azure Advisor recommendations for cost, security, reliability, and performance.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureAdvisorReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureAdvisorReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureAdvisorReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE ADVISOR RECOMMENDATIONS REPORT                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Advisor Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Advisor -ListAvailable)) {
    Install-Module -Name Az.Advisor -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    try {
        $Recommendations = Get-AzAdvisorRecommendation
        
        foreach ($Rec in $Recommendations) {
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                Category            = $Rec.Category
                Impact              = $Rec.Impact
                ImpactedField       = $Rec.ImpactedField
                ImpactedValue       = $Rec.ImpactedValue
                Problem             = $Rec.ShortDescription.Problem
                Solution            = $Rec.ShortDescription.Solution
                ResourceId          = $Rec.ResourceId
                RecommendationType  = $Rec.RecommendationTypeId
                LastUpdated         = $Rec.LastUpdated
            }
        }
    }
    catch {
        Write-Log "Error on $($Sub.Name): $_" -Level "WARNING"
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Summary by category
$CategorySummary = $Results | Group-Object Category

Write-Host "`nTotal Recommendations: $($Results.Count)" -ForegroundColor White
Write-Host "`nBy Category:" -ForegroundColor Yellow
$CategorySummary | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White }
Write-Host "`nReport: $OutputPath" -ForegroundColor Green
Write-Log "========== Advisor Report Completed ==========" -Level "SUCCESS"
