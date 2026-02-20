<#
.SYNOPSIS
    Get-RoleGroupReport.ps1 - Exchange Role Groups Report

.DESCRIPTION
    Reports on Exchange Online role groups and their members.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-RoleGroupReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\RoleGroupReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-RoleGroupReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              EXCHANGE ROLE GROUPS REPORT                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$RoleGroups = Get-RoleGroup
Write-Log "Found $($RoleGroups.Count) role groups" -Level "SUCCESS"

$Results = foreach ($RG in $RoleGroups) {
    $Members = Get-RoleGroupMember -Identity $RG.Identity
    
    [PSCustomObject]@{
        Name            = $RG.Name
        Description     = $RG.Description
        RoleGroupType   = $RG.RoleGroupType
        Members         = ($Members.Name -join "; ")
        MemberCount     = $Members.Count
        Roles           = ($RG.Roles -join "; ")
        WhenCreated     = $RG.WhenCreated
        WhenChanged     = $RG.WhenChanged
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Identify highly privileged groups
$HighPrivileged = $Results | Where-Object { $_.Name -match "Admin|Organization Management|Security" }

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nTotal Role Groups:       $($Results.Count)" -ForegroundColor White
Write-Host "High Privilege Groups:   $($HighPrivileged.Count)" -ForegroundColor Yellow
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
