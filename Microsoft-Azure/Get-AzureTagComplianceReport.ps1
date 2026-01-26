<#
.SYNOPSIS
    Get-AzureTagComplianceReport.ps1 - Azure Tag Compliance Audit

.DESCRIPTION
    Audits resources for tag compliance against required tags.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureTagComplianceReport.ps1 -RequiredTags "Environment","Owner","CostCenter"
#>

[CmdletBinding()]
param(
    [string[]]$RequiredTags = @("Environment", "Owner", "CostCenter"),
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureTagComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureTagComplianceReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE TAG COMPLIANCE AUDIT                           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Tag Compliance Audit Started ==========" -Level "INFO"
Write-Log "Required Tags: $($RequiredTags -join ', ')" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Resources = Get-AzResource
    
    foreach ($Resource in $Resources) {
        $MissingTags = @()
        $PresentTags = @()
        
        foreach ($Tag in $RequiredTags) {
            if ($Resource.Tags -and $Resource.Tags.ContainsKey($Tag)) {
                $PresentTags += $Tag
            }
            else {
                $MissingTags += $Tag
            }
        }
        
        $CompliancePercent = [math]::Round(($PresentTags.Count / $RequiredTags.Count) * 100, 2)
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $Resource.ResourceGroupName
            ResourceName        = $Resource.Name
            ResourceType        = $Resource.ResourceType
            MissingTags         = ($MissingTags -join ", ")
            PresentTags         = ($PresentTags -join ", ")
            CompliancePercent   = $CompliancePercent
            IsCompliant         = $MissingTags.Count -eq 0
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$CompliantCount = ($Results | Where-Object { $_.IsCompliant }).Count
$NonCompliantCount = ($Results | Where-Object { -not $_.IsCompliant }).Count
$ComplianceRate = if ($Results.Count -gt 0) { [math]::Round(($CompliantCount / $Results.Count) * 100, 2) } else { 0 }

Write-Host "`nTotal Resources:    $($Results.Count)" -ForegroundColor White
Write-Host "Compliant:          $CompliantCount ($ComplianceRate%)" -ForegroundColor Green
Write-Host "Non-Compliant:      $NonCompliantCount" -ForegroundColor $(if ($NonCompliantCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Tag Compliance Audit Completed ==========" -Level "SUCCESS"
