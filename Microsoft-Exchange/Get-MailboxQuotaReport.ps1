<#
.SYNOPSIS
    Get-MailboxQuotaReport.ps1 - Mailbox Quota and Storage Analysis

.DESCRIPTION
    Analyzes mailbox storage usage against quotas. Identifies mailboxes
    approaching or exceeding quota limits. Provides recommendations
    for quota adjustments or cleanup.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator or Global Reader role

.EXAMPLE
    .\Get-MailboxQuotaReport.ps1
    
.EXAMPLE
    .\Get-MailboxQuotaReport.ps1 -WarningThreshold 80 -CriticalThreshold 95
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailboxQuotaReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [int]$WarningThreshold = 80,
    
    [Parameter(Mandatory = $false)]
    [int]$CriticalThreshold = 95
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MailboxQuotaReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    
    $Color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║               MAILBOX QUOTA REPORT GENERATOR                     ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Analyzes mailbox storage usage and quota status                 ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Convert-ToBytes {
    param([string]$Size)
    
    if ([string]::IsNullOrEmpty($Size)) { return 0 }
    
    $Size = $Size -replace "[^\d.]", ""
    try {
        return [double]$Size
    }
    catch {
        return 0
    }
}

function Convert-ToGB {
    param([double]$Bytes)
    return [math]::Round($Bytes / 1GB, 2)
}

function Get-QuotaStatus {
    param(
        [double]$UsagePercent,
        [int]$Warning,
        [int]$Critical
    )
    
    if ($UsagePercent -ge $Critical) { return "Critical" }
    elseif ($UsagePercent -ge $Warning) { return "Warning" }
    else { return "OK" }
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    return [bool](Get-Module -Name $ModuleName -ListAvailable)
}

function Install-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Test-ModuleInstalled -ModuleName $ModuleName)) {
        Write-Log "Module '$ModuleName' not found" -Level "WARNING"
        $Confirm = Read-Host "Install $ModuleName? (Y/N)"
        if ($Confirm -match '^[Yy]') {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Log "Module installed" -Level "SUCCESS"
        }
        else { exit 1 }
    }
    else {
        Write-Log "Module '$ModuleName' available" -Level "INFO"
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Quota Report Started ==========" -Level "INFO"
Write-Log "Warning Threshold: ${WarningThreshold}% | Critical Threshold: ${CriticalThreshold}%" -Level "INFO"

# Module check
Install-RequiredModule -ModuleName "ExchangeOnlineManagement"
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
try {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log "Connected successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Connection failed: $_" -Level "ERROR"
    exit 1
}

# Get mailboxes
Write-Log "Retrieving mailboxes..." -Level "INFO"

try {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets Quota
    $TotalMailboxes = $Mailboxes.Count
    Write-Log "Found $TotalMailboxes mailboxes" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve mailboxes: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Process mailboxes
$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Analyzing Mailbox Quotas" `
                   -Status "$($Mailbox.DisplayName) ($Counter/$TotalMailboxes)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get statistics
        $Stats = Get-EXOMailboxStatistics -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
        
        if ($Stats) {
            # Parse sizes
            $TotalItemSizeBytes = 0
            if ($Stats.TotalItemSize) {
                $SizeString = $Stats.TotalItemSize.ToString()
                if ($SizeString -match "\(([0-9,]+)\s*bytes\)") {
                    $TotalItemSizeBytes = [double]($Matches[1] -replace ",", "")
                }
            }
            
            # Parse quota
            $ProhibitSendQuotaBytes = 0
            if ($Mailbox.ProhibitSendQuota -and $Mailbox.ProhibitSendQuota.ToString() -ne "Unlimited") {
                $QuotaString = $Mailbox.ProhibitSendQuota.ToString()
                if ($QuotaString -match "\(([0-9,]+)\s*bytes\)") {
                    $ProhibitSendQuotaBytes = [double]($Matches[1] -replace ",", "")
                }
            }
            elseif ($Mailbox.ProhibitSendQuota.ToString() -eq "Unlimited") {
                $ProhibitSendQuotaBytes = 107374182400  # 100 GB default for calculation
            }
            
            # Calculate percentage
            $UsagePercent = if ($ProhibitSendQuotaBytes -gt 0) {
                [math]::Round(($TotalItemSizeBytes / $ProhibitSendQuotaBytes) * 100, 2)
            }
            else { 0 }
            
            # Determine status
            $Status = Get-QuotaStatus -UsagePercent $UsagePercent -Warning $WarningThreshold -Critical $CriticalThreshold
            
            $Results += [PSCustomObject]@{
                DisplayName           = $Mailbox.DisplayName
                UserPrincipalName     = $Mailbox.UserPrincipalName
                RecipientType         = $Mailbox.RecipientTypeDetails
                MailboxSizeGB         = [math]::Round($TotalItemSizeBytes / 1GB, 2)
                ItemCount             = $Stats.ItemCount
                DeletedItemSizeGB     = if ($Stats.TotalDeletedItemSize) { [math]::Round((Convert-ToBytes $Stats.TotalDeletedItemSize.ToString()) / 1GB, 2) } else { 0 }
                ProhibitSendQuotaGB   = [math]::Round($ProhibitSendQuotaBytes / 1GB, 2)
                IssueWarningQuotaGB   = if ($Mailbox.IssueWarningQuota.ToString() -ne "Unlimited") { $Mailbox.IssueWarningQuota.ToString() } else { "Unlimited" }
                UsagePercent          = $UsagePercent
                Status                = $Status
                LastLogonTime         = $Stats.LastLogonTime
                ArchiveStatus         = $Mailbox.ArchiveStatus
            }
        }
    }
    catch {
        Write-Log "Error processing $($Mailbox.DisplayName): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Analyzing Mailbox Quotas" -Completed

# Sort by usage percentage descending
$Results = $Results | Sort-Object UsagePercent -Descending

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$CriticalCount = ($Results | Where-Object { $_.Status -eq "Critical" }).Count
$WarningCount = ($Results | Where-Object { $_.Status -eq "Warning" }).Count
$OKCount = ($Results | Where-Object { $_.Status -eq "OK" }).Count
$TotalStorageGB = ($Results | Measure-Object -Property MailboxSizeGB -Sum).Sum

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                  MAILBOX QUOTA REPORT SUMMARY                 " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Mailboxes:       $($Results.Count)" -ForegroundColor White
Write-Host "Total Storage:         $([math]::Round($TotalStorageGB, 2)) GB" -ForegroundColor White
Write-Host ""
Write-Host "Quota Status:" -ForegroundColor Yellow
Write-Host "  Critical (>=$CriticalThreshold%):  $CriticalCount" -ForegroundColor $(if ($CriticalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Warning (>=$WarningThreshold%):   $WarningCount" -ForegroundColor $(if ($WarningCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  OK:                  $OKCount" -ForegroundColor Green
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Quota Report Completed ==========" -Level "SUCCESS"

#endregion
