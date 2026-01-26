<#
.SYNOPSIS
    Get-AzureSQLReport.ps1 - Azure SQL Database Security Audit

.DESCRIPTION
    Audits Azure SQL servers and databases for security configurations.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureSQLReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureSQLReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureSQLReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE SQL DATABASE SECURITY AUDIT                   ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== SQL Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Sql -ListAvailable)) {
    Install-Module -Name Az.Sql -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $SqlServers = Get-AzSqlServer
    
    foreach ($Server in $SqlServers) {
        $Issues = @()
        
        # Check firewall rules
        $FirewallRules = Get-AzSqlServerFirewallRule -ServerName $Server.ServerName -ResourceGroupName $Server.ResourceGroupName
        $AllowAllAzure = $FirewallRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "0.0.0.0" }
        if ($AllowAllAzure) { $Issues += "Allow all Azure IPs" }
        
        $AllowAllInternet = $FirewallRules | Where-Object { $_.StartIpAddress -eq "0.0.0.0" -and $_.EndIpAddress -eq "255.255.255.255" }
        if ($AllowAllInternet) { $Issues += "Open to Internet" }
        
        # Check TDE
        $Databases = Get-AzSqlDatabase -ServerName $Server.ServerName -ResourceGroupName $Server.ResourceGroupName | Where-Object { $_.DatabaseName -ne "master" }
        
        foreach ($DB in $Databases) {
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                ResourceGroup       = $Server.ResourceGroupName
                ServerName          = $Server.ServerName
                DatabaseName        = $DB.DatabaseName
                Location            = $Server.Location
                Edition             = $DB.Edition
                ServiceObjective    = $DB.CurrentServiceObjectiveName
                MaxSizeGB           = [math]::Round($DB.MaxSizeBytes / 1GB, 2)
                Status              = $DB.Status
                TDEEnabled          = $DB.EnableTransparentDataEncryption
                MinimalTlsVersion   = $Server.MinimalTlsVersion
                PublicNetworkAccess = $Server.PublicNetworkAccess
                FirewallRuleCount   = $FirewallRules.Count
                Issues              = ($Issues -join "; ")
                RiskLevel           = if ($Issues.Count -ge 1) { "High" } else { "Low" }
            }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Write-Host "`nTotal Databases: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:       $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== SQL Audit Completed ==========" -Level "SUCCESS"
