<#
.SYNOPSIS
    Remove-StaleMailboxPermissions.ps1 - Clean Up Invalid Mailbox Permissions

.DESCRIPTION
    Identifies and removes mailbox permissions for deleted or disabled users.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Remove-StaleMailboxPermissions.ps1 -WhatIf
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\StalePermissions_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Remove-StaleMailboxPermissions"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║         STALE MAILBOX PERMISSIONS CLEANUP TOOL                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Cleanup Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
Write-Log "Checking permissions on $($Mailboxes.Count) mailboxes..." -Level "INFO"

$StalePermissions = @()
$Counter = 0

foreach ($MB in $Mailboxes) {
    $Counter++
    if ($Counter % 50 -eq 0) {
        Write-Progress -Activity "Checking Mailboxes" -Status "$Counter of $($Mailboxes.Count)" -PercentComplete (($Counter / $Mailboxes.Count) * 100)
    }
    
    $Permissions = Get-EXOMailboxPermission -Identity $MB.UserPrincipalName | 
        Where-Object { $_.User -like "S-1-5-*" -and $_.IsInherited -eq $false }
    
    foreach ($Perm in $Permissions) {
        $StalePermissions += [PSCustomObject]@{
            Mailbox         = $MB.DisplayName
            MailboxUPN      = $MB.UserPrincipalName
            StaleUser       = $Perm.User
            AccessRights    = ($Perm.AccessRights -join ", ")
        }
    }
}

Write-Progress -Activity "Checking Mailboxes" -Completed

if ($StalePermissions.Count -eq 0) {
    Write-Log "No stale permissions found" -Level "SUCCESS"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

$StalePermissions | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Log "Found $($StalePermissions.Count) stale permissions" -Level "WARNING"

if (-not $WhatIfPreference) {
    Write-Host "`nFound $($StalePermissions.Count) stale permissions." -ForegroundColor Yellow
    $Confirm = Read-Host "Remove these stale permissions? (Y/N)"
    
    if ($Confirm -match '^[Yy]') {
        $Removed = 0
        foreach ($Stale in $StalePermissions) {
            try {
                Remove-MailboxPermission -Identity $Stale.MailboxUPN -User $Stale.StaleUser -AccessRights FullAccess -Confirm:$false -ErrorAction Stop
                Write-Log "Removed: $($Stale.StaleUser) from $($Stale.MailboxUPN)" -Level "SUCCESS"
                $Removed++
            }
            catch {
                Write-Log "Failed to remove $($Stale.StaleUser) from $($Stale.MailboxUPN): $_" -Level "ERROR"
            }
        }
        Write-Log "Removed $Removed stale permissions" -Level "SUCCESS"
    }
}

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nStale Permissions Found: $($StalePermissions.Count)" -ForegroundColor Yellow
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Cleanup Completed ==========" -Level "SUCCESS"
