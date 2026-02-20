<#
.SYNOPSIS
    Set-CalendarPermission.ps1 - Configure Calendar Permissions

.DESCRIPTION
    Sets calendar sharing permissions for a mailbox.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Set-CalendarPermission.ps1 -Mailbox user@domain.com -User delegate@domain.com -AccessRights Editor
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Mailbox,
    
    [Parameter(Mandatory = $true)]
    [string]$User,
    
    [Parameter(Mandatory = $true)]
    [ValidateSet("Owner", "PublishingEditor", "Editor", "PublishingAuthor", "Author", "Reviewer", "Contributor", "AvailabilityOnly", "LimitedDetails", "None")]
    [string]$AccessRights,
    
    [switch]$Remove
)

$ScriptName = "Set-CalendarPermission"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              CALENDAR PERMISSION CONFIGURATION                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Configuration Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$CalendarPath = "${Mailbox}:\Calendar"

Write-Host "`nAction: $(if ($Remove) { 'REMOVE' } else { 'SET' }) Calendar Permission" -ForegroundColor Yellow
Write-Host "Mailbox: $Mailbox" -ForegroundColor White
Write-Host "User:    $User" -ForegroundColor White
Write-Host "Access:  $AccessRights" -ForegroundColor White

$Confirm = Read-Host "Continue? (Y/N)"
if ($Confirm -notmatch '^[Yy]') {
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

try {
    if ($Remove) {
        Remove-MailboxFolderPermission -Identity $CalendarPath -User $User -Confirm:$false
        Write-Log "Removed calendar permission for $User on $Mailbox" -Level "SUCCESS"
    }
    else {
        # Check if permission exists
        $Existing = Get-MailboxFolderPermission -Identity $CalendarPath -User $User -ErrorAction SilentlyContinue
        
        if ($Existing) {
            Set-MailboxFolderPermission -Identity $CalendarPath -User $User -AccessRights $AccessRights
            Write-Log "Updated calendar permission for $User on $Mailbox to $AccessRights" -Level "SUCCESS"
        }
        else {
            Add-MailboxFolderPermission -Identity $CalendarPath -User $User -AccessRights $AccessRights
            Write-Log "Added calendar permission for $User on $Mailbox: $AccessRights" -Level "SUCCESS"
        }
    }
}
catch {
    Write-Log "Failed: $_" -Level "ERROR"
}

Disconnect-ExchangeOnline -Confirm:$false
Write-Log "========== Configuration Completed ==========" -Level "SUCCESS"
