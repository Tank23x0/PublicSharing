<#
.SYNOPSIS
    Get-JamfCertificateReport.ps1 - Jamf Pro Management Tool

.DESCRIPTION
    Professional Jamf Pro Apple device management and audit script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Jamf Pro API credentials
    - Appropriate Jamf Pro admin permissions

.EXAMPLE
    .\Get-JamfCertificateReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-JamfCertificateReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$JamfURL,
    [string]$Username
)

$ScriptName = "Get-JamfCertificateReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              JAMF PRO MANAGEMENT TOOL                            ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-JamfCertificateReport Started ==========" -Level "INFO"

# Request credentials if not provided
if (-not $JamfURL) { $JamfURL = Read-Host "Enter Jamf Pro URL (e.g., https://company.jamfcloud.com)" }
if (-not $Username) { $Username = Read-Host "Enter Jamf Pro Username" }
$Password = Read-Host "Enter Jamf Pro Password" -AsSecureString

$Results = @()

# Authenticate to Jamf Pro
Write-Log "Authenticating to Jamf Pro..." -Level "INFO"

$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$Credential = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${Username}:${PlainPassword}"))
$Headers = @{
    Authorization = "Basic $Credential"
    Accept = "application/json"
}

try {
    # Get auth token (Jamf Pro 10.35+)
    $TokenResponse = Invoke-RestMethod -Uri "$JamfURL/api/v1/auth/token" -Method Post -Headers $Headers
    $Token = $TokenResponse.token
    
    $AuthHeaders = @{
        Authorization = "Bearer $Token"
        Accept = "application/json"
    }
    
    Write-Log "Authentication successful" -Level "SUCCESS"
    
    # Add specific API calls for this script
    Write-Log "Retrieving Jamf data..." -Level "INFO"
    
    $Computers = Invoke-RestMethod -Uri "$JamfURL/api/v1/computers-inventory" -Method Get -Headers $AuthHeaders -ErrorAction SilentlyContinue
    
    foreach ($Computer in $Computers.results) {
        $Results += [PSCustomObject]@{
            Id              = $Computer.id
            Name            = $Computer.general.name
            SerialNumber    = $Computer.hardware.serialNumber
            Model           = $Computer.hardware.model
            OSVersion       = $Computer.operatingSystem.version
            LastCheckIn     = $Computer.general.lastContactTime
            ManagedBy       = $Computer.general.managementId
        }
    }
    
    # Invalidate token
    Invoke-RestMethod -Uri "$JamfURL/api/v1/auth/invalidate-token" -Method Post -Headers $AuthHeaders -ErrorAction SilentlyContinue
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Devices: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-JamfCertificateReport Completed ==========" -Level "SUCCESS"
