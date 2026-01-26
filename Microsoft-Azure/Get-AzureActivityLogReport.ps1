<#
.SYNOPSIS
    Get-AzureActivityLogReport.ps1 - Azure Activity Log Analysis

.DESCRIPTION
    Analyzes Azure Activity Logs for security-relevant events and administrative actions.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureActivityLogReport.ps1 -Days 7
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureActivityLogReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureActivityLogReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE ACTIVITY LOG ANALYSIS                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Activity Log Analysis Started ==========" -Level "INFO"

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$StartTime = (Get-Date).AddDays(-$Days)
$EndTime = Get-Date

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Logs = Get-AzActivityLog -StartTime $StartTime -EndTime $EndTime -MaxRecord 5000
    
    foreach ($Log in $Logs) {
        $IsSecurityRelevant = $Log.OperationName.Value -match "write|delete|action|roleAssignment|password|secret|key"
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            Timestamp           = $Log.EventTimestamp
            Caller              = $Log.Caller
            OperationName       = $Log.OperationName.Value
            ResourceProvider    = $Log.ResourceProviderName.Value
            ResourceId          = $Log.ResourceId
            Status              = $Log.Status.Value
            SubStatus           = $Log.SubStatus.Value
            Level               = $Log.Level
            Category            = $Log.Category.Value
            IsSecurityRelevant  = $IsSecurityRelevant
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$SecurityEvents = ($Results | Where-Object { $_.IsSecurityRelevant }).Count
$FailedEvents = ($Results | Where-Object { $_.Status -ne "Succeeded" -and $_.Status -ne "Started" -and $_.Status }).Count

Write-Host "`nTotal Events:           $($Results.Count)" -ForegroundColor White
Write-Host "Security-Relevant:      $SecurityEvents" -ForegroundColor Yellow
Write-Host "Failed Operations:      $FailedEvents" -ForegroundColor $(if ($FailedEvents -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Activity Log Analysis Completed ==========" -Level "SUCCESS"
