<#
.SYNOPSIS
    Get-MailboxReport.ps1 - Comprehensive Mailbox Inventory Report

.DESCRIPTION
    Generates a detailed report of all mailboxes in Exchange Online including
    size, item count, archive status, litigation hold, and last logon time.
    Exports results to CSV with progress tracking and logging.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator or Global Reader role
    - PowerShell 5.1 or higher

.EXAMPLE
    .\Get-MailboxReport.ps1
    
.EXAMPLE
    .\Get-MailboxReport.ps1 -OutputPath "C:\Reports\Mailboxes.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailboxReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeArchive,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeShared
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MailboxReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

# Create log directory if it doesn't exist
$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    <#
    .SYNOPSIS
        Writes messages to log file and console
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    
    # Write to log file
    Add-Content -Path $LogPath -Value $LogMessage -Force
    
    # Write to console with color
    switch ($Level) {
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
}

function Show-Banner {
    <#
    .SYNOPSIS
        Displays script banner
    #>
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║                    MAILBOX REPORT GENERATOR                      ║
║                         Version $ScriptVersion                           ║
║                                                                  ║
║  Generates comprehensive mailbox inventory for Exchange Online   ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Test-ModuleInstalled {
    <#
    .SYNOPSIS
        Checks if required module is installed
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    $Module = Get-Module -Name $ModuleName -ListAvailable
    if ($Module) {
        Write-Log "Module '$ModuleName' is already installed (Version: $($Module.Version[0]))" -Level "INFO"
        return $true
    }
    return $false
}

function Install-RequiredModule {
    <#
    .SYNOPSIS
        Installs required module if not present
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$ModuleName
    )
    
    if (-not (Test-ModuleInstalled -ModuleName $ModuleName)) {
        Write-Log "Module '$ModuleName' not found. Installing..." -Level "WARNING"
        
        $Confirm = Read-Host "Do you want to install $ModuleName? (Y/N)"
        if ($Confirm -eq 'Y' -or $Confirm -eq 'y') {
            try {
                Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
                Write-Log "Module '$ModuleName' installed successfully" -Level "SUCCESS"
            }
            catch {
                Write-Log "Failed to install module '$ModuleName': $_" -Level "ERROR"
                throw
            }
        }
        else {
            Write-Log "Module installation declined. Exiting." -Level "ERROR"
            exit 1
        }
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

# Display banner
Show-Banner

# Start logging
Write-Log "========== Script Started ==========" -Level "INFO"
Write-Log "Script: $ScriptName v$ScriptVersion" -Level "INFO"
Write-Log "User: $env:USERNAME" -Level "INFO"
Write-Log "Computer: $env:COMPUTERNAME" -Level "INFO"

# Check and install required module
Install-RequiredModule -ModuleName "ExchangeOnlineManagement"

# Import module
Write-Log "Importing ExchangeOnlineManagement module..." -Level "INFO"
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect to Exchange Online
Write-Log "Connecting to Exchange Online..." -Level "INFO"
Write-Host ""
Write-Host "Please authenticate when prompted..." -ForegroundColor Yellow
Write-Host ""

try {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log "Successfully connected to Exchange Online" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to connect to Exchange Online: $_" -Level "ERROR"
    exit 1
}

# Get mailboxes
Write-Log "Retrieving mailboxes..." -Level "INFO"

$MailboxTypes = @("UserMailbox")
if ($IncludeShared) { $MailboxTypes += "SharedMailbox" }

try {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails $MailboxTypes -PropertySets All
    $TotalMailboxes = $Mailboxes.Count
    Write-Log "Found $TotalMailboxes mailboxes to process" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve mailboxes: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Process mailboxes with progress bar
$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Processing Mailboxes" `
                   -Status "Processing: $($Mailbox.DisplayName) ($Counter of $TotalMailboxes)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get mailbox statistics
        $Stats = Get-EXOMailboxStatistics -Identity $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue
        
        # Get archive info if requested
        $ArchiveSize = "N/A"
        if ($IncludeArchive -and $Mailbox.ArchiveStatus -eq "Active") {
            $ArchiveStats = Get-EXOMailboxStatistics -Identity $Mailbox.UserPrincipalName -Archive -ErrorAction SilentlyContinue
            if ($ArchiveStats) {
                $ArchiveSize = $ArchiveStats.TotalItemSize
            }
        }
        
        # Build result object
        $Result = [PSCustomObject]@{
            DisplayName           = $Mailbox.DisplayName
            UserPrincipalName     = $Mailbox.UserPrincipalName
            PrimarySmtpAddress    = $Mailbox.PrimarySmtpAddress
            RecipientTypeDetails  = $Mailbox.RecipientTypeDetails
            MailboxSize           = if ($Stats) { $Stats.TotalItemSize } else { "N/A" }
            ItemCount             = if ($Stats) { $Stats.ItemCount } else { "N/A" }
            DeletedItemSize       = if ($Stats) { $Stats.TotalDeletedItemSize } else { "N/A" }
            LastLogonTime         = if ($Stats) { $Stats.LastLogonTime } else { "N/A" }
            ArchiveStatus         = $Mailbox.ArchiveStatus
            ArchiveSize           = $ArchiveSize
            LitigationHoldEnabled = $Mailbox.LitigationHoldEnabled
            RetentionHoldEnabled  = $Mailbox.RetentionHoldEnabled
            HiddenFromAddressBook = $Mailbox.HiddenFromAddressListsEnabled
            WhenCreated           = $Mailbox.WhenCreated
            ProhibitSendQuota     = $Mailbox.ProhibitSendQuota
        }
        
        $Results += $Result
    }
    catch {
        Write-Log "Error processing mailbox '$($Mailbox.DisplayName)': $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Processing Mailboxes" -Completed

# Export results
Write-Log "Exporting results to: $OutputPath" -Level "INFO"

try {
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Log "Report exported successfully" -Level "SUCCESS"
    Write-Log "Total mailboxes processed: $($Results.Count)" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to export report: $_" -Level "ERROR"
}

# Disconnect from Exchange Online
Write-Log "Disconnecting from Exchange Online..." -Level "INFO"
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                         SUMMARY                               " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Mailboxes Processed: $($Results.Count)" -ForegroundColor Green
Write-Host "Report Location: $OutputPath" -ForegroundColor Green
Write-Host "Log Location: $LogPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Script Completed ==========" -Level "SUCCESS"

#endregion
