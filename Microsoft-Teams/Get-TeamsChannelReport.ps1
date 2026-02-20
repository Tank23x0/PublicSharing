<#
.SYNOPSIS
    Get-TeamsChannelReport.ps1 - Microsoft Teams Management Tool

.DESCRIPTION
    Professional Microsoft Teams administration and audit script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - MicrosoftTeams module
    - Teams Administrator role

.EXAMPLE
    .\Get-TeamsChannelReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-TeamsChannelReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-TeamsChannelReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MICROSOFT TEAMS MANAGEMENT TOOL                     ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-TeamsChannelReport Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name MicrosoftTeams -ListAvailable)) {
    Write-Log "Installing MicrosoftTeams module..." -Level "WARNING"
    Install-Module -Name MicrosoftTeams -Force -Scope CurrentUser
}
Import-Module MicrosoftTeams -ErrorAction Stop

# Connect to Teams
Write-Log "Connecting to Microsoft Teams..." -Level "INFO"
Connect-MicrosoftTeams

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving Teams data..." -Level "INFO"

$Teams = Get-Team -ErrorAction SilentlyContinue

foreach ($Team in $Teams) {
    $Owners = Get-TeamUser -GroupId $Team.GroupId -Role Owner -ErrorAction SilentlyContinue
    $Members = Get-TeamUser -GroupId $Team.GroupId -Role Member -ErrorAction SilentlyContinue
    $Channels = Get-TeamChannel -GroupId $Team.GroupId -ErrorAction SilentlyContinue
    
    $Results += [PSCustomObject]@{
        DisplayName     = $Team.DisplayName
        GroupId         = $Team.GroupId
        Description     = $Team.Description
        Visibility      = $Team.Visibility
        Archived        = $Team.Archived
        OwnerCount      = ($Owners | Measure-Object).Count
        MemberCount     = ($Members | Measure-Object).Count
        ChannelCount    = ($Channels | Measure-Object).Count
    }
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-MicrosoftTeams -ErrorAction SilentlyContinue

Write-Host "`nTotal Teams: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-TeamsChannelReport Completed ==========" -Level "SUCCESS"
