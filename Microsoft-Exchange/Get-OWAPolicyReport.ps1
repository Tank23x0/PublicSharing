<#
.SYNOPSIS
    Get-OWAPolicyReport.ps1 - Outlook Web Access Policy Report

.DESCRIPTION
    Reports on OWA (Outlook on the web) mailbox policies and their settings.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-OWAPolicyReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\OWAPolicyReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-OWAPolicyReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              OWA MAILBOX POLICY REPORT                           ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Policies = Get-OwaMailboxPolicy
$Results = foreach ($Policy in $Policies) {
    [PSCustomObject]@{
        Name                        = $Policy.Name
        IsDefault                   = $Policy.IsDefault
        DirectFileAccessOnPublicComputersEnabled = $Policy.DirectFileAccessOnPublicComputersEnabled
        DirectFileAccessOnPrivateComputersEnabled = $Policy.DirectFileAccessOnPrivateComputersEnabled
        WebReadyDocumentViewingOnPublicComputersEnabled = $Policy.WebReadyDocumentViewingOnPublicComputersEnabled
        ForceWebReadyDocumentViewingFirstOnPublicComputers = $Policy.ForceWebReadyDocumentViewingFirstOnPublicComputers
        WacViewingOnPublicComputersEnabled = $Policy.WacViewingOnPublicComputersEnabled
        WacViewingOnPrivateComputersEnabled = $Policy.WacViewingOnPrivateComputersEnabled
        WacEditingEnabled           = $Policy.WacEditingEnabled
        ActiveSyncIntegrationEnabled = $Policy.ActiveSyncIntegrationEnabled
        ContactsEnabled             = $Policy.ContactsEnabled
        CalendarEnabled             = $Policy.CalendarEnabled
        TasksEnabled                = $Policy.TasksEnabled
        JournalEnabled              = $Policy.JournalEnabled
        NotesEnabled                = $Policy.NotesEnabled
        RulesEnabled                = $Policy.RulesEnabled
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nOWA Policies: $($Results.Count)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
