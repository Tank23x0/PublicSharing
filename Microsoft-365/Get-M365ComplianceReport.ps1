<#
.SYNOPSIS
    Get-M365ComplianceReport.ps1 - Microsoft 365 Management Tool

.DESCRIPTION
    Professional Microsoft 365 administration and reporting script.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Microsoft.Graph module
    - Appropriate M365 admin permissions

.EXAMPLE
    .\Get-M365ComplianceReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-M365ComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-M365ComplianceReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MICROSOFT 365 MANAGEMENT TOOL                       ║
║                      Version 1.0.0                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-M365ComplianceReport Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
    Write-Log "Installing Microsoft.Graph module..." -Level "WARNING"
    Install-Module -Name Microsoft.Graph -Force -Scope CurrentUser
}
Import-Module Microsoft.Graph.Reports -ErrorAction SilentlyContinue

# Connect to Microsoft Graph
Write-Log "Connecting to Microsoft Graph..." -Level "INFO"
Connect-MgGraph -Scopes "Reports.Read.All", "Directory.Read.All" -NoWelcome

$Results = @()

# Add specific logic for this script
Write-Log "Retrieving M365 data..." -Level "INFO"

# Example report retrieval
try {
    $Report = Get-MgReportOffice365ActiveUserDetail -Period D30 -OutFile "$env:TEMP\temp_report.csv"
    if (Test-Path "$env:TEMP\temp_report.csv") {
        $Results = Import-Csv "$env:TEMP\temp_report.csv"
        Remove-Item "$env:TEMP\temp_report.csv" -Force
    }
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-MgGraph -ErrorAction SilentlyContinue

Write-Host "`nTotal Records: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-M365ComplianceReport Completed ==========" -Level "SUCCESS"
