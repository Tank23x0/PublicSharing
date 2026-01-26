<#
.SYNOPSIS
    Get-RecipientReport.ps1 - Complete Recipient Inventory

.DESCRIPTION
    Generates a comprehensive report of all recipients in Exchange Online
    including mailboxes, groups, contacts, and mail users.

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
    .\Get-RecipientReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\RecipientReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "UserMailbox", "SharedMailbox", "MailContact", "MailUser", "DistributionGroup", "MailUniversalSecurityGroup")]
    [string]$RecipientType = "All"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-RecipientReport"
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
║                 RECIPIENT REPORT GENERATOR                       ║
║                      Version $ScriptVersion                              ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner
Write-Log "========== Recipient Report Started ==========" -Level "INFO"

# Module check
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Log "Installing ExchangeOnlineManagement module..." -Level "WARNING"
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

# Get recipients
Write-Log "Retrieving recipients (Type: $RecipientType)..." -Level "INFO"

try {
    if ($RecipientType -eq "All") {
        $Recipients = Get-EXORecipient -ResultSize Unlimited
    }
    else {
        $Recipients = Get-EXORecipient -ResultSize Unlimited -RecipientTypeDetails $RecipientType
    }
    $TotalRecipients = $Recipients.Count
    Write-Log "Found $TotalRecipients recipients" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve recipients: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

$Results = @()
$Counter = 0

foreach ($Recipient in $Recipients) {
    $Counter++
    if ($Counter % 100 -eq 0) {
        Write-Progress -Activity "Processing Recipients" -Status "$Counter of $TotalRecipients" -PercentComplete (($Counter / $TotalRecipients) * 100)
    }
    
    $Results += [PSCustomObject]@{
        DisplayName           = $Recipient.DisplayName
        PrimarySmtpAddress    = $Recipient.PrimarySmtpAddress
        Alias                 = $Recipient.Alias
        RecipientType         = $Recipient.RecipientType
        RecipientTypeDetails  = $Recipient.RecipientTypeDetails
        EmailAddresses        = ($Recipient.EmailAddresses | Where-Object { $_ -like "smtp:*" }) -join "; "
        HiddenFromGAL         = $Recipient.HiddenFromAddressListsEnabled
        WhenCreated           = $Recipient.WhenCreated
        WhenChanged           = $Recipient.WhenChanged
    }
}

Write-Progress -Activity "Processing Recipients" -Completed

# Export
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics by type
$TypeStats = $Results | Group-Object RecipientTypeDetails | Sort-Object Count -Descending

Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Recipients: $TotalRecipients" -ForegroundColor White
Write-Host ""
Write-Host "By Type:" -ForegroundColor Yellow
foreach ($Type in $TypeStats) {
    Write-Host "  $($Type.Name): $($Type.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Recipient Report Completed ==========" -Level "SUCCESS"

#endregion
