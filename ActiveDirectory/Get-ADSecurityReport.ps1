<#
.SYNOPSIS
    Get-ADSecurityReport.ps1 - Active Directory Management Tool

.DESCRIPTION
    Professional Active Directory administration and audit script.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ActiveDirectory module (RSAT)
    - Domain Admin or delegated permissions

.EXAMPLE
    .\Get-ADSecurityReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-ADSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [string]$SearchBase,
    [int]$InactiveDays = 90
)

$ScriptName = "Get-ADSecurityReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              ACTIVE DIRECTORY MANAGEMENT TOOL                    ║
║          Version 1.0.0 — Joe Romaine — JoeRomaine.com            ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-ADSecurityReport Started ==========" -Level "INFO"

# Check and import module
if (-not (Get-Module -Name ActiveDirectory -ListAvailable)) {
    Write-Log "ActiveDirectory module not found. Install RSAT tools." -Level "ERROR"
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

$Results = @()

# Get domain info
$Domain = Get-ADDomain
Write-Log "Connected to domain: $($Domain.DNSRoot)" -Level "INFO"

# Add specific logic for this script
Write-Log "Retrieving Active Directory data..." -Level "INFO"

if (-not $SearchBase) { $SearchBase = $Domain.DistinguishedName }

try {
    $Users = Get-ADUser -Filter * -SearchBase $SearchBase -Properties * -ErrorAction SilentlyContinue | Select-Object -First 1000
    
    foreach ($User in $Users) {
        $Results += [PSCustomObject]@{
            SamAccountName      = $User.SamAccountName
            DisplayName         = $User.DisplayName
            UserPrincipalName   = $User.UserPrincipalName
            Enabled             = $User.Enabled
            LockedOut           = $User.LockedOut
            PasswordLastSet     = $User.PasswordLastSet
            LastLogonDate       = $User.LastLogonDate
            WhenCreated         = $User.WhenCreated
            Description         = $User.Description
            Department          = $User.Department
        }
    }
}
catch {
    Write-Log "Error: $_" -Level "WARNING"
}

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "`nTotal Records: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Get-ADSecurityReport Completed ==========" -Level "SUCCESS"
