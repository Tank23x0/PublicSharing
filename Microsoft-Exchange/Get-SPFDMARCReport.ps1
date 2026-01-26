<#
.SYNOPSIS
    Get-SPFDMARCReport.ps1 - SPF and DMARC Configuration Report

.DESCRIPTION
    Reports on email authentication records (SPF, DMARC) for accepted domains.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-SPFDMARCReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\SPFDMARCReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-SPFDMARCReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║            SPF & DMARC CONFIGURATION REPORT                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Domains = Get-AcceptedDomain | Where-Object { $_.DomainType -eq "Authoritative" }
Write-Log "Checking $($Domains.Count) domains..." -Level "INFO"

$Results = foreach ($Domain in $Domains) {
    $SPF = $null
    $DMARC = $null
    
    try {
        $SPFRecord = Resolve-DnsName -Name $Domain.DomainName -Type TXT -ErrorAction SilentlyContinue | Where-Object { $_.Strings -like "*v=spf1*" }
        $SPF = if ($SPFRecord) { $SPFRecord.Strings -join " " } else { "Not Found" }
    }
    catch { $SPF = "DNS Error" }
    
    try {
        $DMARCRecord = Resolve-DnsName -Name "_dmarc.$($Domain.DomainName)" -Type TXT -ErrorAction SilentlyContinue
        $DMARC = if ($DMARCRecord) { $DMARCRecord.Strings -join " " } else { "Not Found" }
    }
    catch { $DMARC = "DNS Error" }
    
    $Issues = @()
    if ($SPF -eq "Not Found") { $Issues += "Missing SPF" }
    if ($DMARC -eq "Not Found") { $Issues += "Missing DMARC" }
    if ($DMARC -match "p=none") { $Issues += "DMARC policy=none" }
    
    [PSCustomObject]@{
        Domain      = $Domain.DomainName
        IsDefault   = $Domain.Default
        SPFRecord   = $SPF
        SPFValid    = $SPF -ne "Not Found" -and $SPF -ne "DNS Error"
        DMARCRecord = $DMARC
        DMARCValid  = $DMARC -ne "Not Found" -and $DMARC -ne "DNS Error"
        Issues      = ($Issues -join "; ")
        RiskLevel   = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Write-Host "`nDomains Checked:  $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:        $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
