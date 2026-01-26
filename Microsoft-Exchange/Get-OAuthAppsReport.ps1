<#
.SYNOPSIS
    Get-OAuthAppsReport.ps1 - OAuth/App Permissions Audit for Exchange

.DESCRIPTION
    Audits OAuth applications with Exchange Online permissions.
    Identifies high-risk app permissions and consent grants.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Microsoft.Graph module
    - Global Reader or Application Administrator role

.EXAMPLE
    .\Get-OAuthAppsReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\OAuthAppsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-OAuthAppsReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

# Exchange-related permissions to flag
$ExchangePermissions = @(
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "Mail.ReadBasic",
    "MailboxSettings.Read", "MailboxSettings.ReadWrite",
    "Calendars.Read", "Calendars.ReadWrite",
    "Contacts.Read", "Contacts.ReadWrite",
    "EWS.AccessAsUser.All", "full_access_as_app"
)

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    $Color = switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║              OAUTH APPS AUDIT FOR EXCHANGE                       ║
║                      Version $ScriptVersion                              ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Get-RiskLevel {
    param($Permissions)
    
    $HighRisk = @("Mail.ReadWrite", "Mail.Send", "full_access_as_app", "EWS.AccessAsUser.All")
    
    foreach ($Perm in $Permissions) {
        if ($Perm -in $HighRisk) { return "High" }
    }
    return "Medium"
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner
Write-Log "========== OAuth Apps Audit Started ==========" -Level "INFO"

# Module check
if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    Write-Log "Installing Microsoft.Graph module..." -Level "WARNING"
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}
Import-Module Microsoft.Graph.Applications -ErrorAction Stop

# Connect
Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
Connect-MgGraph -Scopes "Application.Read.All", "Directory.Read.All" -NoWelcome

# Get service principals (apps)
Write-Log "Retrieving application permissions..." -Level "INFO"

try {
    $ServicePrincipals = Get-MgServicePrincipal -All
    Write-Log "Found $($ServicePrincipals.Count) service principals" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve service principals: $_" -Level "ERROR"
    Disconnect-MgGraph
    exit 1
}

$Results = @()
$Counter = 0

foreach ($SP in $ServicePrincipals) {
    $Counter++
    if ($Counter % 50 -eq 0) {
        Write-Progress -Activity "Analyzing Apps" -Status "$Counter of $($ServicePrincipals.Count)" -PercentComplete (($Counter / $ServicePrincipals.Count) * 100)
    }
    
    # Get OAuth2 permission grants (delegated permissions)
    $Grants = Get-MgServicePrincipalOAuth2PermissionGrant -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue
    
    # Get app role assignments (application permissions)
    $AppRoles = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SP.Id -ErrorAction SilentlyContinue
    
    # Filter for Exchange-related permissions
    $ExchangeGrants = $Grants | Where-Object { 
        $Scopes = $_.Scope -split " "
        $Scopes | Where-Object { $_ -in $ExchangePermissions }
    }
    
    if ($ExchangeGrants -or ($AppRoles | Where-Object { $_.AppRoleId })) {
        $AllPermissions = @()
        foreach ($Grant in $ExchangeGrants) {
            $AllPermissions += ($Grant.Scope -split " ")
        }
        
        $ExchangeRelatedPerms = $AllPermissions | Where-Object { $_ -in $ExchangePermissions }
        
        if ($ExchangeRelatedPerms) {
            $RiskLevel = Get-RiskLevel -Permissions $ExchangeRelatedPerms
            
            $Results += [PSCustomObject]@{
                AppDisplayName      = $SP.DisplayName
                AppId               = $SP.AppId
                PublisherName       = $SP.PublisherName
                ServicePrincipalType = $SP.ServicePrincipalType
                ExchangePermissions = ($ExchangeRelatedPerms -join "; ")
                PermissionType      = "Delegated"
                RiskLevel           = $RiskLevel
                Enabled             = $SP.AccountEnabled
                CreatedDateTime     = $SP.CreatedDateTime
            }
        }
    }
}

Write-Progress -Activity "Analyzing Apps" -Completed

# Export
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$HighRiskCount = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Disconnect-MgGraph

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Apps with Exchange Permissions: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk Apps:                 $HighRiskCount" -ForegroundColor $(if ($HighRiskCount -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== OAuth Apps Audit Completed ==========" -Level "SUCCESS"

#endregion
