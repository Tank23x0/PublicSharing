<#
.SYNOPSIS
    Get-QuarantineReport.ps1 - Email Quarantine Analysis Report

.DESCRIPTION
    Analyzes quarantined messages in Exchange Online. Identifies patterns
    in blocked emails for security review and policy tuning.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-QuarantineReport.ps1 -Days 7
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Days = 7,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\QuarantineReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-QuarantineReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                QUARANTINE ANALYSIS REPORT                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Quarantine Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

$StartDate = (Get-Date).AddDays(-$Days)
$EndDate = Get-Date

Write-Log "Retrieving quarantined messages from last $Days days..." -Level "INFO"

try {
    $QuarantinedMessages = Get-QuarantineMessage -StartReceivedDate $StartDate -EndReceivedDate $EndDate -PageSize 1000
    Write-Log "Found $($QuarantinedMessages.Count) quarantined messages" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve quarantine: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

$Results = foreach ($Message in $QuarantinedMessages) {
    [PSCustomObject]@{
        ReceivedTime        = $Message.ReceivedTime
        SenderAddress       = $Message.SenderAddress
        RecipientAddress    = ($Message.RecipientAddress -join "; ")
        Subject             = $Message.Subject
        Type                = $Message.Type
        QuarantineTypes     = ($Message.QuarantineTypes -join "; ")
        ReleaseStatus       = $Message.ReleaseStatus
        Direction           = $Message.Direction
        Size                = $Message.Size
        Expires             = $Message.Expires
        MessageId           = $Message.MessageId
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics by type
$TypeStats = $Results | Group-Object Type | Sort-Object Count -Descending

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Quarantined: $($Results.Count)" -ForegroundColor White
Write-Host "`nBy Type:" -ForegroundColor Yellow
foreach ($Type in $TypeStats) {
    Write-Host "  $($Type.Name): $($Type.Count)" -ForegroundColor White
}
Write-Host "`nReport: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
