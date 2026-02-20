<#
.SYNOPSIS
    Set-MailboxAutoReply.ps1 - Configure Out of Office Auto-Replies

.DESCRIPTION
    Configures automatic replies (Out of Office) for one or multiple mailboxes.
    Supports scheduling, internal/external messages, and bulk operations via CSV.

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
    .\Set-MailboxAutoReply.ps1 -Mailbox user@domain.com -Enable
    
.EXAMPLE
    .\Set-MailboxAutoReply.ps1 -CSVPath "C:\Users.csv" -Enable -InternalMessage "Out of office"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Mailbox,
    
    [Parameter(Mandatory = $false)]
    [string]$CSVPath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Enable,
    
    [Parameter(Mandatory = $false)]
    [switch]$Disable,
    
    [Parameter(Mandatory = $false)]
    [string]$InternalMessage,
    
    [Parameter(Mandatory = $false)]
    [string]$ExternalMessage,
    
    [Parameter(Mandatory = $false)]
    [datetime]$StartTime,
    
    [Parameter(Mandatory = $false)]
    [datetime]$EndTime,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Known", "None")]
    [string]$ExternalAudience = "Known"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Set-MailboxAutoReply"
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
║              MAILBOX AUTO-REPLY CONFIGURATION                    ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Configure Out of Office messages for Exchange Online            ║
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

Write-Log "========== Auto-Reply Configuration Started ==========" -Level "INFO"

# Validation
if (-not $Mailbox -and -not $CSVPath) {
    Write-Log "Please specify either -Mailbox or -CSVPath" -Level "ERROR"
    exit 1
}

if (-not $Enable -and -not $Disable) {
    Write-Log "Please specify either -Enable or -Disable" -Level "ERROR"
    exit 1
}

if ($Enable -and -not $InternalMessage) {
    Write-Log "Internal message required when enabling auto-reply" -Level "ERROR"
    exit 1
}

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

# Get target mailboxes
$Mailboxes = @()
if ($Mailbox) {
    $Mailboxes += $Mailbox
}
elseif ($CSVPath) {
    if (Test-Path $CSVPath) {
        $CSVData = Import-Csv -Path $CSVPath
        $Mailboxes = $CSVData.UserPrincipalName
        Write-Log "Loaded $($Mailboxes.Count) mailboxes from CSV" -Level "INFO"
    }
    else {
        Write-Log "CSV file not found: $CSVPath" -Level "ERROR"
        Disconnect-ExchangeOnline -Confirm:$false
        exit 1
    }
}

# Confirmation
Write-Host ""
Write-Host "Configuration Summary:" -ForegroundColor Yellow
Write-Host "  Action:            $(if ($Enable) { 'Enable' } else { 'Disable' }) Auto-Reply" -ForegroundColor White
Write-Host "  Mailboxes:         $($Mailboxes.Count)" -ForegroundColor White
if ($Enable) {
    Write-Host "  External Audience: $ExternalAudience" -ForegroundColor White
    if ($StartTime) { Write-Host "  Start Time:        $StartTime" -ForegroundColor White }
    if ($EndTime) { Write-Host "  End Time:          $EndTime" -ForegroundColor White }
}
Write-Host ""
$Confirm = Read-Host "Proceed with configuration? (Y/N)"

if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Operation cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process mailboxes
$SuccessCount = 0
$FailCount = 0
$Counter = 0

foreach ($TargetMailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $Mailboxes.Count) * 100, 2)
    
    Write-Progress -Activity "Configuring Auto-Reply" `
                   -Status "$TargetMailbox ($Counter/$($Mailboxes.Count))" `
                   -PercentComplete $PercentComplete
    
    try {
        if ($Enable) {
            $Params = @{
                Identity = $TargetMailbox
                AutoReplyState = if ($StartTime -and $EndTime) { "Scheduled" } else { "Enabled" }
                InternalMessage = $InternalMessage
                ExternalAudience = $ExternalAudience
            }
            
            if ($ExternalMessage) { $Params.ExternalMessage = $ExternalMessage }
            else { $Params.ExternalMessage = $InternalMessage }
            
            if ($StartTime) { $Params.StartTime = $StartTime }
            if ($EndTime) { $Params.EndTime = $EndTime }
            
            Set-MailboxAutoReplyConfiguration @Params
            Write-Log "Enabled auto-reply for: $TargetMailbox" -Level "SUCCESS"
        }
        else {
            Set-MailboxAutoReplyConfiguration -Identity $TargetMailbox -AutoReplyState Disabled
            Write-Log "Disabled auto-reply for: $TargetMailbox" -Level "SUCCESS"
        }
        
        $SuccessCount++
    }
    catch {
        Write-Log "Failed to configure $TargetMailbox : $_" -Level "ERROR"
        $FailCount++
    }
}

Write-Progress -Activity "Configuring Auto-Reply" -Completed

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "               AUTO-REPLY CONFIGURATION SUMMARY                " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Processed:       $Counter" -ForegroundColor White
Write-Host "Successful:            $SuccessCount" -ForegroundColor Green
Write-Host "Failed:                $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Log: $LogPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Auto-Reply Configuration Completed ==========" -Level "SUCCESS"

#endregion
