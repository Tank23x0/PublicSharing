<#
.SYNOPSIS
    Get-RetentionPolicyReport.ps1 - Retention Policy Configuration Report

.DESCRIPTION
    Reports on MRM retention policies and tags configured in Exchange Online.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-RetentionPolicyReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\RetentionPolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-RetentionPolicyReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            RETENTION POLICY REPORT GENERATOR                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

# Get retention policies
$Policies = Get-RetentionPolicy
$Results = @()

foreach ($Policy in $Policies) {
    # Get tags for this policy
    $Tags = $Policy.RetentionPolicyTagLinks
    
    $Results += [PSCustomObject]@{
        PolicyName      = $Policy.Name
        RetentionTags   = ($Tags -join "; ")
        TagCount        = $Tags.Count
        IsDefault       = $Policy.IsDefault
        WhenCreated     = $Policy.WhenCreated
    }
}

# Also get retention tags
$TagResults = Get-RetentionPolicyTag | ForEach-Object {
    [PSCustomObject]@{
        TagName             = $_.Name
        Type                = $_.Type
        AgeLimitForRetention = $_.AgeLimitForRetention
        RetentionAction     = $_.RetentionAction
        RetentionEnabled    = $_.RetentionEnabled
        SystemTag           = $_.SystemTag
        Comment             = $_.Comment
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
$TagResults | Export-Csv -Path ($OutputPath -replace ".csv", "_Tags.csv") -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nRetention Policies: $($Results.Count)" -ForegroundColor White
Write-Host "Retention Tags: $($TagResults.Count)" -ForegroundColor White
Write-Host "Reports: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
