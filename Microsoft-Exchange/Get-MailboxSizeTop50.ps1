<#
.SYNOPSIS
    Get-MailboxSizeTop50.ps1 - Top 50 Largest Mailboxes Report

.DESCRIPTION
    Reports on the 50 largest mailboxes by size.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-MailboxSizeTop50.ps1
#>

[CmdletBinding()]
param(
    [int]$Top = 50,
    [string]$OutputPath = "$env:USERPROFILE\Documents\Top${Top}Mailboxes_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-MailboxSizeTop50"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              TOP $Top LARGEST MAILBOXES REPORT                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Mailboxes = Get-EXOMailbox -ResultSize Unlimited
Write-Log "Processing $($Mailboxes.Count) mailboxes..." -Level "INFO"

$MailboxData = @()
$Counter = 0

foreach ($MB in $Mailboxes) {
    $Counter++
    if ($Counter % 100 -eq 0) {
        Write-Progress -Activity "Getting Mailbox Sizes" -Status "$Counter of $($Mailboxes.Count)" -PercentComplete (($Counter / $Mailboxes.Count) * 100)
    }
    
    $Stats = Get-EXOMailboxStatistics -Identity $MB.UserPrincipalName -ErrorAction SilentlyContinue
    if ($Stats) {
        $SizeBytes = 0
        if ($Stats.TotalItemSize) {
            $SizeString = $Stats.TotalItemSize.ToString()
            if ($SizeString -match "\(([0-9,]+)\s*bytes\)") {
                $SizeBytes = [double]($Matches[1] -replace ",", "")
            }
        }
        
        $MailboxData += [PSCustomObject]@{
            DisplayName     = $MB.DisplayName
            UserPrincipalName = $MB.UserPrincipalName
            SizeBytes       = $SizeBytes
            SizeGB          = [math]::Round($SizeBytes / 1GB, 2)
            ItemCount       = $Stats.ItemCount
            RecipientType   = $MB.RecipientTypeDetails
        }
    }
}

Write-Progress -Activity "Getting Mailbox Sizes" -Completed

$Results = $MailboxData | Sort-Object SizeBytes -Descending | Select-Object -First $Top
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Disconnect-ExchangeOnline -Confirm:$false

Write-Host "`nTop $Top Largest Mailboxes:" -ForegroundColor Yellow
$Results | Select-Object -First 10 | ForEach-Object { 
    Write-Host "  $($_.DisplayName): $($_.SizeGB) GB" -ForegroundColor White 
}
Write-Host "  ..." -ForegroundColor Gray
Write-Host "`nReport: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
