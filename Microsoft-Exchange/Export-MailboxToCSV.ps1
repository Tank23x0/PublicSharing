<#
.SYNOPSIS
    Export-MailboxToCSV.ps1 - Export Mailbox Details to CSV

.DESCRIPTION
    Exports comprehensive mailbox information for selected or all mailboxes.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Export-MailboxToCSV.ps1 -All
#>

[CmdletBinding()]
param(
    [switch]$All,
    [string]$Filter,
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailboxExport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Export-MailboxToCSV"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                MAILBOX EXPORT TO CSV                             ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Export Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

if ($Filter) {
    $Mailboxes = Get-EXOMailbox -Filter $Filter -ResultSize Unlimited -PropertySets All
}
else {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets All
}

Write-Log "Exporting $($Mailboxes.Count) mailboxes..." -Level "INFO"

$Results = foreach ($MB in $Mailboxes) {
    [PSCustomObject]@{
        DisplayName = $MB.DisplayName
        UserPrincipalName = $MB.UserPrincipalName
        PrimarySmtpAddress = $MB.PrimarySmtpAddress
        Alias = $MB.Alias
        RecipientTypeDetails = $MB.RecipientTypeDetails
        WhenCreated = $MB.WhenCreated
        WhenMailboxCreated = $MB.WhenMailboxCreated
        IssueWarningQuota = $MB.IssueWarningQuota
        ProhibitSendQuota = $MB.ProhibitSendQuota
        ArchiveStatus = $MB.ArchiveStatus
        LitigationHoldEnabled = $MB.LitigationHoldEnabled
        HiddenFromAddressListsEnabled = $MB.HiddenFromAddressListsEnabled
        ForwardingAddress = $MB.ForwardingAddress
        ForwardingSmtpAddress = $MB.ForwardingSmtpAddress
        DeliverToMailboxAndForward = $MB.DeliverToMailboxAndForward
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nExported: $($Results.Count) mailboxes" -ForegroundColor Green
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Export Completed ==========" -Level "SUCCESS"
