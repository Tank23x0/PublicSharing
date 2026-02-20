<#
.SYNOPSIS
    Get-AzureAppServiceReport.ps1 - Azure App Service Security Audit

.DESCRIPTION
    Audits Azure App Services for security configurations including HTTPS, TLS, and authentication.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureAppServiceReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureAppServiceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureAppServiceReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE APP SERVICE SECURITY AUDIT                    ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== App Service Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Websites -ListAvailable)) {
    Install-Module -Name Az.Websites -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $WebApps = Get-AzWebApp
    
    foreach ($App in $WebApps) {
        $Issues = @()
        
        if (-not $App.HttpsOnly) { $Issues += "HTTPS not enforced" }
        if ($App.SiteConfig.MinTlsVersion -ne "1.2") { $Issues += "TLS < 1.2" }
        if (-not $App.SiteConfig.FtpsState -or $App.SiteConfig.FtpsState -eq "AllAllowed") { $Issues += "FTP enabled" }
        if (-not $App.ClientCertEnabled) { $Issues += "Client cert not required" }
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $App.ResourceGroup
            AppName             = $App.Name
            Location            = $App.Location
            State               = $App.State
            Kind                = $App.Kind
            HttpsOnly           = $App.HttpsOnly
            MinTlsVersion       = $App.SiteConfig.MinTlsVersion
            FtpsState           = $App.SiteConfig.FtpsState
            ClientCertEnabled   = $App.ClientCertEnabled
            AlwaysOn            = $App.SiteConfig.AlwaysOn
            Http20Enabled       = $App.SiteConfig.Http20Enabled
            DefaultHostName     = $App.DefaultHostName
            OutboundIPs         = $App.OutboundIpAddresses
            Issues              = ($Issues -join "; ")
            RiskLevel           = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$NoHttps = ($Results | Where-Object { -not $_.HttpsOnly }).Count

Write-Host "`nTotal App Services: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:          $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "No HTTPS Enforced:  $NoHttps" -ForegroundColor $(if ($NoHttps -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== App Service Audit Completed ==========" -Level "SUCCESS"
