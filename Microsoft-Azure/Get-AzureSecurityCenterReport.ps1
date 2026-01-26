<#
.SYNOPSIS
    Get-AzureSecurityCenterReport.ps1 - Azure Security Center Assessment Report

.DESCRIPTION
    Retrieves Microsoft Defender for Cloud security assessments and recommendations.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureSecurityCenterReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureSecurityCenterReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureSecurityCenterReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║          AZURE SECURITY CENTER ASSESSMENT REPORT                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Security Center Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Security -ListAvailable)) {
    Install-Module -Name Az.Security -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    try {
        $Assessments = Get-AzSecurityAssessment -ErrorAction SilentlyContinue
        
        foreach ($Assessment in $Assessments) {
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                AssessmentName      = $Assessment.Name
                DisplayName         = $Assessment.DisplayName
                Status              = $Assessment.Status.Code
                ResourceDetails     = $Assessment.ResourceDetails.Id
                Category            = $Assessment.Metadata.Category
                Severity            = $Assessment.Metadata.Severity
                Description         = $Assessment.Metadata.Description
            }
        }
    }
    catch {
        Write-Log "Error on $($Sub.Name): $_" -Level "WARNING"
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$Unhealthy = ($Results | Where-Object { $_.Status -eq "Unhealthy" }).Count
$HighSeverity = ($Results | Where-Object { $_.Severity -eq "High" -and $_.Status -eq "Unhealthy" }).Count

Write-Host "`nTotal Assessments:    $($Results.Count)" -ForegroundColor White
Write-Host "Unhealthy:            $Unhealthy" -ForegroundColor $(if ($Unhealthy -gt 0) { "Yellow" } else { "Green" })
Write-Host "High Severity Issues: $HighSeverity" -ForegroundColor $(if ($HighSeverity -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Security Center Report Completed ==========" -Level "SUCCESS"
