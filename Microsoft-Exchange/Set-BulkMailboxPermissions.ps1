<#
.SYNOPSIS
    Set-BulkMailboxPermissions.ps1 - Bulk Mailbox Permission Management

.DESCRIPTION
    Add or remove mailbox permissions (Full Access, Send As, Send on Behalf)
    for multiple users via CSV import.

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
    .\Set-BulkMailboxPermissions.ps1 -CSVPath "C:\Permissions.csv" -Action Add
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CSVPath,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Add", "Remove")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("FullAccess", "SendAs", "SendOnBehalf", "All")]
    [string]$PermissionType = "FullAccess",
    
    [Parameter(Mandatory = $false)]
    [switch]$DisableAutoMapping
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Set-BulkMailboxPermissions"
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
║             BULK MAILBOX PERMISSIONS MANAGER                     ║
║                      Version $ScriptVersion                              ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner
Write-Log "========== Bulk Permissions $Action Started ==========" -Level "INFO"

# Validate CSV
if (-not (Test-Path $CSVPath)) {
    Write-Log "CSV file not found: $CSVPath" -Level "ERROR"
    exit 1
}

# Module check
if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Write-Log "Installing ExchangeOnlineManagement module..." -Level "WARNING"
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
Connect-ExchangeOnline -ShowBanner:$false

# Import CSV (Expected columns: Mailbox, User)
$CSVData = Import-Csv -Path $CSVPath
$TotalRecords = $CSVData.Count
Write-Log "Loaded $TotalRecords records from CSV" -Level "INFO"

# Confirmation
Write-Host ""
Write-Host "Action: $Action $PermissionType permissions" -ForegroundColor Yellow
Write-Host "Records: $TotalRecords" -ForegroundColor Yellow
$Confirm = Read-Host "Continue? (Y/N)"

if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Operation cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$SuccessCount = 0
$FailCount = 0
$Counter = 0

foreach ($Record in $CSVData) {
    $Counter++
    Write-Progress -Activity "Processing Permissions" -Status "$($Record.Mailbox) ($Counter/$TotalRecords)" -PercentComplete (($Counter / $TotalRecords) * 100)
    
    $TargetMailbox = $Record.Mailbox
    $TargetUser = $Record.User
    
    try {
        if ($Action -eq "Add") {
            # Add permissions
            if ($PermissionType -eq "FullAccess" -or $PermissionType -eq "All") {
                $AutoMap = -not $DisableAutoMapping
                Add-MailboxPermission -Identity $TargetMailbox -User $TargetUser -AccessRights FullAccess -AutoMapping:$AutoMap -Confirm:$false -ErrorAction Stop
            }
            if ($PermissionType -eq "SendAs" -or $PermissionType -eq "All") {
                Add-RecipientPermission -Identity $TargetMailbox -Trustee $TargetUser -AccessRights SendAs -Confirm:$false -ErrorAction Stop
            }
            if ($PermissionType -eq "SendOnBehalf" -or $PermissionType -eq "All") {
                Set-Mailbox -Identity $TargetMailbox -GrantSendOnBehalfTo @{Add=$TargetUser} -Confirm:$false -ErrorAction Stop
            }
            Write-Log "Added $PermissionType to $TargetMailbox for $TargetUser" -Level "SUCCESS"
        }
        else {
            # Remove permissions
            if ($PermissionType -eq "FullAccess" -or $PermissionType -eq "All") {
                Remove-MailboxPermission -Identity $TargetMailbox -User $TargetUser -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
            }
            if ($PermissionType -eq "SendAs" -or $PermissionType -eq "All") {
                Remove-RecipientPermission -Identity $TargetMailbox -Trustee $TargetUser -AccessRights SendAs -Confirm:$false -ErrorAction Stop
            }
            if ($PermissionType -eq "SendOnBehalf" -or $PermissionType -eq "All") {
                Set-Mailbox -Identity $TargetMailbox -GrantSendOnBehalfTo @{Remove=$TargetUser} -Confirm:$false -ErrorAction Stop
            }
            Write-Log "Removed $PermissionType from $TargetMailbox for $TargetUser" -Level "SUCCESS"
        }
        $SuccessCount++
    }
    catch {
        Write-Log "Failed: $TargetMailbox / $TargetUser - $_" -Level "ERROR"
        $FailCount++
    }
}

Write-Progress -Activity "Processing Permissions" -Completed

Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Processed: $Counter" -ForegroundColor White
Write-Host "Successful:      $SuccessCount" -ForegroundColor Green
Write-Host "Failed:          $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Host "Log: $LogPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Bulk Permissions Completed ==========" -Level "SUCCESS"

#endregion
