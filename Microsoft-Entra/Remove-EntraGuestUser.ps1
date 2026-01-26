<#
.SYNOPSIS
    Remove-EntraGuestUser.ps1 - Microsoft Entra ID Management Tool

.DESCRIPTION
    Professional Microsoft Entra ID (Azure AD) management and audit script.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Microsoft.Graph module
    - Appropriate Entra ID permissions

.EXAMPLE
    .\Remove-EntraGuestUser.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Remove-EntraGuestUser_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Remove-EntraGuestUser"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MICROSOFT ENTRA ID MANAGEMENT TOOL                  ║
║                      Version 1.0.0                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Remove-EntraGuestUser Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    Write-Log "Installing Microsoft.Graph module..." -Level "WARNING"
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}
Import-Module Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.SignIns -ErrorAction SilentlyContinue

# Connect to Microsoft Graph
Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
Connect-MgGraph -Scopes "User.Read.All", "Group.Read.All", "Directory.Read.All" -NoWelcome

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving data from Entra ID..." -Level "INFO"

$Users = Get-MgUser -All -Property DisplayName,UserPrincipalName,AccountEnabled,CreatedDateTime,SignInActivity -ErrorAction SilentlyContinue | Select-Object -First 1000

foreach ($User in $Users) {
    $Results += [PSCustomObject]@{
        DisplayName         = $User.DisplayName
        UserPrincipalName   = $User.UserPrincipalName
        AccountEnabled      = $User.AccountEnabled
        CreatedDateTime     = $User.CreatedDateTime
        LastSignIn          = $User.SignInActivity.LastSignInDateTime
    }
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "`nTotal Records: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Remove-EntraGuestUser Completed ==========" -Level "SUCCESS"
