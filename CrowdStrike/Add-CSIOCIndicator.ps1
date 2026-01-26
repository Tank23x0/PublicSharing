<#
.SYNOPSIS
    Add-CSIOCIndicator.ps1 - CrowdStrike Falcon Management Tool

.DESCRIPTION
    Professional CrowdStrike Falcon EDR management and reporting script.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - PSFalcon module
    - CrowdStrike API credentials

.EXAMPLE
    .\Add-CSIOCIndicator.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Add-CSIOCIndicator_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$ClientId,
    [string]$ClientSecret,
    [string]$Cloud = "us-1"
)

$ScriptName = "Add-CSIOCIndicator"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              CROWDSTRIKE FALCON MANAGEMENT TOOL                  ║
║                      Version 1.0.0                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Add-CSIOCIndicator Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name PSFalcon -ListAvailable)) {
    Write-Log "Installing PSFalcon module..." -Level "WARNING"
    Install-Module -Name PSFalcon -Force -Scope CurrentUser
}
Import-Module PSFalcon -ErrorAction Stop

# Request credentials if not provided
if (-not $ClientId) { $ClientId = Read-Host "Enter CrowdStrike API Client ID" }
if (-not $ClientSecret) { $ClientSecret = Read-Host "Enter CrowdStrike API Client Secret" -AsSecureString | ConvertFrom-SecureString }

# Authenticate to CrowdStrike
Write-Log "Authenticating to CrowdStrike Falcon..." -Level "INFO"
Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret -Cloud $Cloud

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving CrowdStrike data..." -Level "INFO"

try {
    $Hosts = Get-FalconHost -Detailed -All -ErrorAction SilentlyContinue
    
    foreach ($Host in $Hosts) {
        $Results += [PSCustomObject]@{
            Hostname            = $Host.hostname
            LocalIP             = $Host.local_ip
            ExternalIP          = $Host.external_ip
            OSVersion           = $Host.os_version
            Platform            = $Host.platform_name
            AgentVersion        = $Host.agent_version
            LastSeen            = $Host.last_seen
            Status              = $Host.status
            ContainmentStatus   = $Host.containment_status
        }
    }
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Revoke-FalconToken -ErrorAction SilentlyContinue

Write-Host "`nTotal Hosts: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Add-CSIOCIndicator Completed ==========" -Level "SUCCESS"
