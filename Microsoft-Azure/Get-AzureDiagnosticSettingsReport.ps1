<#
.SYNOPSIS
    Get-AzureDiagnosticSettingsReport.ps1 - Azure Diagnostic Settings Audit

.DESCRIPTION
    Audits diagnostic settings across resources to ensure logging is configured.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureDiagnosticSettingsReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureDiagnosticSettingsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureDiagnosticSettingsReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            AZURE DIAGNOSTIC SETTINGS AUDIT                       ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Diagnostic Settings Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Monitor -ListAvailable)) {
    Install-Module -Name Az.Monitor -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    # Check key resource types
    $KeyResources = Get-AzResource | Where-Object { 
        $_.ResourceType -match "Microsoft.KeyVault|Microsoft.Sql|Microsoft.Storage|Microsoft.Compute/virtualMachines" 
    }
    
    foreach ($Resource in $KeyResources) {
        $DiagSettings = Get-AzDiagnosticSetting -ResourceId $Resource.ResourceId -ErrorAction SilentlyContinue
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $Resource.ResourceGroupName
            ResourceName        = $Resource.Name
            ResourceType        = $Resource.ResourceType
            HasDiagnostics      = [bool]$DiagSettings
            DiagnosticSettingsCount = if ($DiagSettings) { $DiagSettings.Count } else { 0 }
            StorageAccount      = if ($DiagSettings) { ($DiagSettings.StorageAccountId | Select-Object -First 1) } else { "" }
            LogAnalytics        = if ($DiagSettings) { ($DiagSettings.WorkspaceId | Select-Object -First 1) } else { "" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$WithDiagnostics = ($Results | Where-Object { $_.HasDiagnostics }).Count
$WithoutDiagnostics = ($Results | Where-Object { -not $_.HasDiagnostics }).Count

Write-Host "`nTotal Resources Checked: $($Results.Count)" -ForegroundColor White
Write-Host "With Diagnostics:        $WithDiagnostics" -ForegroundColor Green
Write-Host "Without Diagnostics:     $WithoutDiagnostics" -ForegroundColor $(if ($WithoutDiagnostics -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Diagnostic Settings Audit Completed ==========" -Level "SUCCESS"
