<#
.SYNOPSIS
    Get-ConnectorReport.ps1 - Mail Flow Connectors Report

.DESCRIPTION
    Reports on inbound and outbound mail flow connectors in Exchange Online.
    Identifies security configuration of partner and on-premises connectors.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-ConnectorReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\ConnectorReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-ConnectorReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              MAIL FLOW CONNECTORS REPORT                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Connector Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
    Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
}
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Connect-ExchangeOnline -ShowBanner:$false

$Results = @()

# Inbound connectors
$InboundConnectors = Get-InboundConnector
foreach ($Connector in $InboundConnectors) {
    $Issues = @()
    if (-not $Connector.RequireTls) { $Issues += "TLS not required" }
    if (-not $Connector.RestrictDomainsToCertificate) { $Issues += "Certificate validation disabled" }
    
    $Results += [PSCustomObject]@{
        Name                    = $Connector.Name
        Direction               = "Inbound"
        Enabled                 = $Connector.Enabled
        ConnectorType           = $Connector.ConnectorType
        SenderDomains           = ($Connector.SenderDomains -join "; ")
        RequireTls              = $Connector.RequireTls
        TlsSenderCertificateName = $Connector.TlsSenderCertificateName
        RestrictDomainsToCertificate = $Connector.RestrictDomainsToCertificate
        TreatMessagesAsInternal = $Connector.TreatMessagesAsInternal
        CloudServicesMailEnabled = $Connector.CloudServicesMailEnabled
        Issues                  = ($Issues -join "; ")
    }
}

# Outbound connectors
$OutboundConnectors = Get-OutboundConnector
foreach ($Connector in $OutboundConnectors) {
    $Issues = @()
    if (-not $Connector.TlsSettings -or $Connector.TlsSettings -eq "Optional") { $Issues += "TLS optional or disabled" }
    
    $Results += [PSCustomObject]@{
        Name                    = $Connector.Name
        Direction               = "Outbound"
        Enabled                 = $Connector.Enabled
        ConnectorType           = $Connector.ConnectorType
        RecipientDomains        = ($Connector.RecipientDomains -join "; ")
        SmartHosts              = ($Connector.SmartHosts -join "; ")
        TlsSettings             = $Connector.TlsSettings
        UseMXRecord             = $Connector.UseMXRecord
        CloudServicesMailEnabled = $Connector.CloudServicesMailEnabled
        Issues                  = ($Issues -join "; ")
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Disconnect-ExchangeOnline -Confirm:$false

$WithIssues = ($Results | Where-Object { $_.Issues }).Count

Write-Host "`nTotal Connectors: $($Results.Count)" -ForegroundColor White
Write-Host "Inbound: $(($Results | Where-Object { $_.Direction -eq 'Inbound' }).Count)" -ForegroundColor White
Write-Host "Outbound: $(($Results | Where-Object { $_.Direction -eq 'Outbound' }).Count)" -ForegroundColor White
Write-Host "With Issues: $WithIssues" -ForegroundColor $(if ($WithIssues -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Report Completed ==========" -Level "SUCCESS"
