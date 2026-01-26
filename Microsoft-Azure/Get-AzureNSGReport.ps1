<#
.SYNOPSIS
    Get-AzureNSGReport.ps1 - Network Security Group Audit

.DESCRIPTION
    Audits all NSGs and their rules. Identifies overly permissive rules
    like open RDP/SSH or any-any rules.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureNSGReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureNSGReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureNSGReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              NETWORK SECURITY GROUP AUDIT                        ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== NSG Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Network -ListAvailable)) {
    Install-Module -Name Az.Network -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()
$RiskyPorts = @(22, 3389, 445, 1433, 3306, 5432)

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $NSGs = Get-AzNetworkSecurityGroup
    
    foreach ($NSG in $NSGs) {
        foreach ($Rule in $NSG.SecurityRules) {
            $Issues = @()
            
            # Check for risky configurations
            if ($Rule.Direction -eq "Inbound" -and $Rule.Access -eq "Allow") {
                if ($Rule.SourceAddressPrefix -eq "*" -or $Rule.SourceAddressPrefix -eq "Internet") {
                    $Issues += "Open to Internet"
                    
                    if ($Rule.DestinationPortRange -eq "*") {
                        $Issues += "All ports exposed"
                    }
                    
                    foreach ($Port in $RiskyPorts) {
                        if ($Rule.DestinationPortRange -eq $Port -or $Rule.DestinationPortRange -eq "*") {
                            $Issues += "Risky port $Port exposed"
                        }
                    }
                }
            }
            
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                ResourceGroup       = $NSG.ResourceGroupName
                NSGName             = $NSG.Name
                RuleName            = $Rule.Name
                Priority            = $Rule.Priority
                Direction           = $Rule.Direction
                Access              = $Rule.Access
                Protocol            = $Rule.Protocol
                SourceAddressPrefix = ($Rule.SourceAddressPrefix -join ", ")
                DestinationPortRange = ($Rule.DestinationPortRange -join ", ")
                Issues              = ($Issues -join "; ")
                RiskLevel           = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
            }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total NSG Rules:  $($Results.Count)" -ForegroundColor White
Write-Host "High Risk Rules:  $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== NSG Audit Completed ==========" -Level "SUCCESS"
