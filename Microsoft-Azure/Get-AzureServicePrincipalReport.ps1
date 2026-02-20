<#
.SYNOPSIS
    Get-AzureServicePrincipalReport.ps1 - Azure Service Principal Audit

.DESCRIPTION
    Audits all service principals and app registrations for security review.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureServicePrincipalReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureServicePrincipalReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureServicePrincipalReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║             AZURE SERVICE PRINCIPAL AUDIT                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Service Principal Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Resources -ListAvailable)) {
    Install-Module -Name Az.Resources -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

Write-Log "Retrieving service principals..." -Level "INFO"
$ServicePrincipals = Get-AzADServicePrincipal -First 1000

$Results = foreach ($SP in $ServicePrincipals) {
    [PSCustomObject]@{
        DisplayName         = $SP.DisplayName
        ApplicationId       = $SP.AppId
        ObjectId            = $SP.Id
        ServicePrincipalType = $SP.ServicePrincipalType
        AccountEnabled      = $SP.AccountEnabled
        AppOwnerOrganizationId = $SP.AppOwnerOrganizationId
        SignInAudience      = $SP.SignInAudience
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Service Principals: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Service Principal Audit Completed ==========" -Level "SUCCESS"
