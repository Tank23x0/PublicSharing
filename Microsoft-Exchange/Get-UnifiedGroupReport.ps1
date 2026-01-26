<#
.SYNOPSIS
    Get-UnifiedGroupReport.ps1 - Microsoft 365 Groups Report

.DESCRIPTION
    Reports on all Microsoft 365 Groups (Unified Groups) in Exchange Online.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-UnifiedGroupReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\UnifiedGroupReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    [switch]$IncludeMembers
)

$ScriptName = "Get-UnifiedGroupReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            MICROSOFT 365 GROUPS REPORT GENERATOR                 ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Groups = Get-UnifiedGroup -ResultSize Unlimited
Write-Log "Found $($Groups.Count) Microsoft 365 Groups" -Level "SUCCESS"

$Counter = 0
$Results = foreach ($Group in $Groups) {
    $Counter++
    if ($Counter % 50 -eq 0) {
        Write-Progress -Activity "Processing Groups" -Status "$Counter of $($Groups.Count)" -PercentComplete (($Counter / $Groups.Count) * 100)
    }
    
    $Members = ""
    if ($IncludeMembers) {
        $GroupMembers = Get-UnifiedGroupLinks -Identity $Group.Identity -LinkType Members
        $Members = ($GroupMembers.PrimarySmtpAddress -join "; ")
    }
    
    [PSCustomObject]@{
        DisplayName         = $Group.DisplayName
        PrimarySmtpAddress  = $Group.PrimarySmtpAddress
        Alias               = $Group.Alias
        ManagedBy           = ($Group.ManagedBy -join "; ")
        GroupType           = $Group.GroupType
        AccessType          = $Group.AccessType
        MemberCount         = $Group.GroupMemberCount
        ExternalMemberCount = $Group.GroupExternalMemberCount
        HiddenFromGAL       = $Group.HiddenFromAddressListsEnabled
        HiddenFromExchangeClients = $Group.HiddenFromExchangeClientsEnabled
        WelcomeMessageEnabled = $Group.WelcomeMessageEnabled
        WhenCreated         = $Group.WhenCreated
        Members             = $Members
    }
}

Write-Progress -Activity "Processing Groups" -Completed

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$PublicGroups = ($Results | Where-Object { $_.AccessType -eq "Public" }).Count

Write-Host "`nTotal Groups:    $($Results.Count)" -ForegroundColor White
Write-Host "Public Groups:   $PublicGroups" -ForegroundColor $(if ($PublicGroups -gt 0) { "Yellow" } else { "Green" })
Write-Host "Private Groups:  $($Results.Count - $PublicGroups)" -ForegroundColor White
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
