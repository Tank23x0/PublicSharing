<#
.SYNOPSIS
    Get-InactiveMailboxReport.ps1 - Identify Inactive User Mailboxes

.DESCRIPTION
    Identifies mailboxes with no logon activity within specified threshold.
    Useful for license optimization and account cleanup.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role

.EXAMPLE
    .\Get-InactiveMailboxReport.ps1 -InactiveDays 90
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\InactiveMailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-InactiveMailboxReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    $Color = switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║              INACTIVE MAILBOX REPORT GENERATOR                   ║
║                      Version $ScriptVersion                              ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner
Write-Log "========== Report Started ==========" -Level "INFO"

# Module check and import
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Log "ExchangeOnlineManagement module not found" -Level "WARNING"
    $Confirm = Read-Host "Install module? (Y/N)"
    if ($Confirm -match '^[Yy]') { Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser }
    else { exit 1 }
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

$ThresholdDate = (Get-Date).AddDays(-$InactiveDays)
Write-Log "Checking for mailboxes inactive since: $($ThresholdDate.ToString('yyyy-MM-dd'))" -Level "INFO"

# Get mailboxes
$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox
$TotalMailboxes = $Mailboxes.Count
Write-Log "Found $TotalMailboxes mailboxes to check" -Level "SUCCESS"

$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    Write-Progress -Activity "Checking Mailboxes" -Status "$($Mailbox.DisplayName) ($Counter/$TotalMailboxes)" -PercentComplete (($Counter / $TotalMailboxes) * 100)
    
    try {
        $Stats = Get-EXOMailboxStatistics -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($Stats) {
            $LastLogon = $Stats.LastLogonTime
            $IsInactive = if ($LastLogon) { $LastLogon -lt $ThresholdDate } else { $true }
            $DaysSinceLogon = if ($LastLogon) { ((Get-Date) - $LastLogon).Days } else { "Never" }
            
            if ($IsInactive) {
                $Results += [PSCustomObject]@{
                    DisplayName        = $Mailbox.DisplayName
                    UserPrincipalName  = $Mailbox.UserPrincipalName
                    LastLogonTime      = $LastLogon
                    DaysSinceLogon     = $DaysSinceLogon
                    MailboxSizeMB      = [math]::Round(($Stats.TotalItemSize.ToString() -replace ".*\(([0-9,]+).*", '$1' -replace ",", "") / 1MB, 2)
                    ItemCount          = $Stats.ItemCount
                    WhenCreated        = $Mailbox.WhenCreated
                    RecipientType      = $Mailbox.RecipientTypeDetails
                }
            }
        }
    }
    catch {
        Write-Log "Error on $($Mailbox.DisplayName): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Checking Mailboxes" -Completed

# Export
$Results = $Results | Sort-Object DaysSinceLogon -Descending
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Mailboxes Checked: $TotalMailboxes" -ForegroundColor White
Write-Host "Inactive Mailboxes:      $($Results.Count)" -ForegroundColor $(if ($Results.Count -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Report Completed ==========" -Level "SUCCESS"

#endregion
