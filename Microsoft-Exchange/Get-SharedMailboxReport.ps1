<#
.SYNOPSIS
    Get-SharedMailboxReport.ps1 - Shared Mailbox Inventory and Access Report

.DESCRIPTION
    Comprehensive report of all shared mailboxes including members,
    permissions, auto-mapping settings, and potential security issues.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role

.EXAMPLE
    .\Get-SharedMailboxReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\SharedMailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-SharedMailboxReport"
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
║               SHARED MAILBOX REPORT GENERATOR                    ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Comprehensive inventory of shared mailboxes and access          ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
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
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Shared Mailbox Report Started ==========" -Level "INFO"

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

# Get shared mailboxes
Write-Log "Retrieving shared mailboxes..." -Level "INFO"

try {
    $SharedMailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox
    $TotalShared = $SharedMailboxes.Count
    Write-Log "Found $TotalShared shared mailboxes" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve shared mailboxes: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

if ($TotalShared -eq 0) {
    Write-Log "No shared mailboxes found" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process shared mailboxes
$Results = @()
$Counter = 0

foreach ($Mailbox in $SharedMailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalShared) * 100, 2)
    
    Write-Progress -Activity "Processing Shared Mailboxes" `
                   -Status "$($Mailbox.DisplayName) ($Counter/$TotalShared)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get statistics
        $Stats = Get-EXOMailboxStatistics -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
        
        # Get Full Access permissions
        $FullAccessUsers = Get-EXOMailboxPermission -Identity $Mailbox.UserPrincipalName | 
            Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and $_.AccessRights -contains "FullAccess" } |
            Select-Object -ExpandProperty User
        
        # Get Send As permissions
        $SendAsUsers = Get-EXORecipientPermission -Identity $Mailbox.UserPrincipalName | 
            Where-Object { $_.Trustee -ne "Self" } |
            Select-Object -ExpandProperty Trustee
        
        # Check for potential issues
        $Issues = @()
        if ($FullAccessUsers.Count -eq 0) { $Issues += "No Full Access users" }
        if ($FullAccessUsers.Count -gt 10) { $Issues += "Many Full Access users ($($FullAccessUsers.Count))" }
        if ($Mailbox.HiddenFromAddressListsEnabled -eq $false) { $Issues += "Visible in GAL" }
        if ($Stats.LastLogonTime -and $Stats.LastLogonTime -lt (Get-Date).AddDays(-90)) { $Issues += "Inactive >90 days" }
        
        $Results += [PSCustomObject]@{
            DisplayName           = $Mailbox.DisplayName
            PrimarySmtpAddress    = $Mailbox.PrimarySmtpAddress
            Alias                 = $Mailbox.Alias
            MailboxSizeMB         = if ($Stats) { [math]::Round(($Stats.TotalItemSize.ToString() -replace ".*\(([0-9,]+).*", '$1' -replace ",", "") / 1MB, 2) } else { "N/A" }
            ItemCount             = if ($Stats) { $Stats.ItemCount } else { "N/A" }
            LastLogonTime         = if ($Stats) { $Stats.LastLogonTime } else { "N/A" }
            FullAccessUsers       = ($FullAccessUsers -join "; ")
            FullAccessCount       = $FullAccessUsers.Count
            SendAsUsers           = ($SendAsUsers -join "; ")
            SendAsCount           = $SendAsUsers.Count
            SendOnBehalf          = ($Mailbox.GrantSendOnBehalfTo -join "; ")
            HiddenFromGAL         = $Mailbox.HiddenFromAddressListsEnabled
            LitigationHold        = $Mailbox.LitigationHoldEnabled
            ArchiveEnabled        = $Mailbox.ArchiveStatus
            WhenCreated           = $Mailbox.WhenCreated
            Issues                = ($Issues -join "; ")
            IssueCount            = $Issues.Count
        }
    }
    catch {
        Write-Log "Error on $($Mailbox.DisplayName): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Processing Shared Mailboxes" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$InactiveCount = ($Results | Where-Object { $_.Issues -match "Inactive" }).Count
$NoAccessCount = ($Results | Where-Object { $_.FullAccessCount -eq 0 }).Count
$ManyAccessCount = ($Results | Where-Object { $_.FullAccessCount -gt 10 }).Count
$WithIssues = ($Results | Where-Object { $_.IssueCount -gt 0 }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "               SHARED MAILBOX REPORT SUMMARY                   " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Shared Mailboxes: $TotalShared" -ForegroundColor White
Write-Host ""
Write-Host "Potential Issues:" -ForegroundColor Yellow
Write-Host "  Inactive >90 days:   $InactiveCount" -ForegroundColor $(if ($InactiveCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  No Full Access:      $NoAccessCount" -ForegroundColor $(if ($NoAccessCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Too Many Users:      $ManyAccessCount" -ForegroundColor $(if ($ManyAccessCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  With Issues:         $WithIssues" -ForegroundColor $(if ($WithIssues -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Shared Mailbox Report Completed ==========" -Level "SUCCESS"

#endregion
