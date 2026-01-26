<#
.SYNOPSIS
    Get-ModuleVersionReport.ps1 - PowerShell Environment Repair Tool

.DESCRIPTION
    Professional PowerShell module cleanup, repair, and troubleshooting script.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - PowerShell 5.1 or PowerShell 7+
    - Administrator privileges recommended

.EXAMPLE
    .\Get-ModuleVersionReport.ps1
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\Get-ModuleVersionReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$Force
)

$ScriptName = "Get-ModuleVersionReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              POWERSHELL ENVIRONMENT REPAIR TOOL                  ║
║                      Version 1.0.0                               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Get-ModuleVersionReport Started ==========" -Level "INFO"

# Check for admin rights
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Log "Running without administrator privileges - some functions may be limited" -Level "WARNING"
}

$Results = @()

# Main script logic
Write-Log "Analyzing PowerShell environment..." -Level "INFO"

# Get PSModulePath
$ModulePaths = $env:PSModulePath -split [IO.Path]::PathSeparator
Write-Log "Found $($ModulePaths.Count) module paths" -Level "INFO"

foreach ($Path in $ModulePaths) {
    $PathExists = Test-Path $Path
    $ModuleCount = 0
    
    if ($PathExists) {
        $ModuleCount = (Get-ChildItem -Path $Path -Directory -ErrorAction SilentlyContinue | Measure-Object).Count
    }
    
    $Results += [PSCustomObject]@{
        ModulePath      = $Path
        Exists          = $PathExists
        ModuleCount     = $ModuleCount
        PathType        = if ($Path -match "System32|Program Files") { "System" } elseif ($Path -match $env:USERPROFILE) { "User" } else { "Custom" }
    }
}

# Check for duplicate modules
$AllModules = Get-Module -ListAvailable
$DuplicateModules = $AllModules | Group-Object Name | Where-Object { $_.Count -gt 1 }

Write-Log "Found $($DuplicateModules.Count) modules with multiple versions" -Level $(if ($DuplicateModules.Count -gt 0) { "WARNING" } else { "INFO" })

# Check repositories
$Repositories = Get-PSRepository -ErrorAction SilentlyContinue
Write-Log "Found $($Repositories.Count) registered repositories" -Level "INFO"

# Export results
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "PowerShell Environment Summary:" -ForegroundColor Yellow
Write-Host "  Module Paths:       $($ModulePaths.Count)" -ForegroundColor White
Write-Host "  Total Modules:      $($AllModules.Count)" -ForegroundColor White
Write-Host "  Duplicate Modules:  $($DuplicateModules.Count)" -ForegroundColor $(if ($DuplicateModules.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Repositories:       $($Repositories.Count)" -ForegroundColor White
Write-Host "  PS Version:         $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Get-ModuleVersionReport Completed ==========" -Level "SUCCESS"
