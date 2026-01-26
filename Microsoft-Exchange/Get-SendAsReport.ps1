<#
.SYNOPSIS
    Get-SendAsReport.ps1 - Send As Permissions Audit

.DESCRIPTION
    Comprehensive audit of all Send As permissions across mailboxes.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-SendAsReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\SendAsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-SendAsReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║               SEND AS PERMISSIONS AUDIT                          ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Mailboxes = Get-EXOMailbox -ResultSize Unlimited
Write-Log "Auditing $($Mailboxes.Count) mailboxes..." -Level "INFO"

$Results = @()
$Counter = 0

foreach ($MB in $Mailboxes) {
    $Counter++
    if ($Counter % 100 -eq 0) {
        Write-Progress -Activity "Auditing Send As" -Status "$Counter of $($Mailboxes.Count)" -PercentComplete (($Counter / $Mailboxes.Count) * 100)
    }
    
    $SendAs = Get-EXORecipientPermission -Identity $MB.UserPrincipalName | Where-Object { $_.Trustee -ne "Self" }
    
    foreach ($Perm in $SendAs) {
        $Results += [PSCustomObject]@{
            Mailbox     = $MB.DisplayName
            MailboxUPN  = $MB.UserPrincipalName
            Trustee     = $Perm.Trustee
            AccessRights = $Perm.AccessRights
            IsInherited = $Perm.IsInherited
        }
    }
}

Write-Progress -Activity "Auditing Send As" -Completed

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nSend As Permissions Found: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Audit Completed ==========" -Level "SUCCESS"
