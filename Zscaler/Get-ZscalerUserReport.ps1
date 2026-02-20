<#
.SYNOPSIS
    Get-ZscalerUserReport.ps1 - Zscaler Management Tool

.DESCRIPTION
    Professional Zscaler administration and security audit script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Zscaler API credentials
    - Appropriate Zscaler admin permissions

.EXAMPLE
    .\Get-ZscalerUserReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-ZscalerUserReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$ZscalerCloud = "zscloud.net",
    [string]$ApiKey,
    [string]$Username
)

$ScriptName = "Get-ZscalerUserReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              ZSCALER SECURITY MANAGEMENT TOOL                    ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-ZscalerUserReport Started ==========" -Level "INFO"

# Request credentials if not provided
if (-not $ApiKey) { $ApiKey = Read-Host "Enter Zscaler API Key" }
if (-not $Username) { $Username = Read-Host "Enter Zscaler Admin Username" }
$Password = Read-Host "Enter Zscaler Password" -AsSecureString

$Results = @()

# Authenticate to Zscaler
Write-Log "Authenticating to Zscaler..." -Level "INFO"

$BaseURL = "https://zsapi.$ZscalerCloud/api/v1"
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)

$AuthBody = @{
    apiKey = $ApiKey
    username = $Username
    password = $PlainPassword
    timestamp = [Math]::Floor([decimal](Get-Date(Get-Date).ToUniversalTime()-uformat "%s"))
} | ConvertTo-Json

try {
    $Session = Invoke-RestMethod -Uri "$BaseURL/authenticatedSession" -Method Post -Body $AuthBody -ContentType "application/json" -SessionVariable ZscalerSession
    Write-Log "Authentication successful" -Level "SUCCESS"
    
    # Add specific API calls for this script
    Write-Log "Retrieving Zscaler data..." -Level "INFO"
    
    $Users = Invoke-RestMethod -Uri "$BaseURL/users" -Method Get -WebSession $ZscalerSession -ErrorAction SilentlyContinue
    
    foreach ($User in $Users) {
        $Results += [PSCustomObject]@{
            UserName    = $User.name
            Email       = $User.email
            Department  = $User.department.name
            Groups      = ($User.groups.name -join ", ")
            AdminUser   = $User.adminUser
        }
    }
    
    # Logout
    Invoke-RestMethod -Uri "$BaseURL/authenticatedSession" -Method Delete -WebSession $ZscalerSession -ErrorAction SilentlyContinue
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Records: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-ZscalerUserReport Completed ==========" -Level "SUCCESS"
