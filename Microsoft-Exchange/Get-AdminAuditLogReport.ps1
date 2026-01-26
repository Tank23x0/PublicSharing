<#
.SYNOPSIS
    Get-AdminAuditLogReport.ps1 - Exchange Admin Audit Log Analysis

.DESCRIPTION
    Retrieves and analyzes Exchange admin audit logs for security review.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AdminAuditLogReport.ps1 -Days 30
#>

[CmdletBinding()]
param(
    [int]$Days = 7,
    [string]$Cmdlet,
    [string]$OutputPath = "$env:USERPROFILE\Documents\AdminAuditLog_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AdminAuditLogReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            EXCHANGE ADMIN AUDIT LOG ANALYZER                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Audit Log Analysis Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$StartDate = (Get-Date).AddDays(-$Days)
$EndDate = Get-Date

Write-Log "Searching audit logs from $($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd'))" -Level "INFO"

$SearchParams = @{
    StartDate = $StartDate
    EndDate = $EndDate
    ResultSize = 5000
}

if ($Cmdlet) { $SearchParams.Cmdlet = $Cmdlet }

$AuditLogs = Search-AdminAuditLog @SearchParams

$Results = foreach ($Log in $AuditLogs) {
    [PSCustomObject]@{
        RunDate         = $Log.RunDate
        Caller          = $Log.Caller
        CmdletName      = $Log.CmdletName
        ObjectModified  = $Log.ObjectModified
        Parameters      = ($Log.CmdletParameters | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "; "
        Succeeded       = $Log.Succeeded
        Error           = $Log.Error
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Top cmdlets
$TopCmdlets = $Results | Group-Object CmdletName | Sort-Object Count -Descending | Select-Object -First 10

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nTotal Audit Events: $($Results.Count)" -ForegroundColor White
Write-Host "`nTop Cmdlets:" -ForegroundColor Yellow
$TopCmdlets | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White }
Write-Host "`nReport: $OutputPath" -ForegroundColor Green
Write-Log "========== Analysis Completed ==========" -Level "SUCCESS"
