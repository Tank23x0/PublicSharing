<#
.SYNOPSIS
    Get-AzurePolicyComplianceReport.ps1 - Azure Policy Compliance Report

.DESCRIPTION
    Reports on Azure Policy compliance status across all subscriptions.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzurePolicyComplianceReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzurePolicyComplianceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzurePolicyComplianceReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE POLICY COMPLIANCE REPORT                      ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Policy Compliance Check Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.PolicyInsights -ListAvailable)) {
    Install-Module -Name Az.PolicyInsights -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    try {
        $PolicyStates = Get-AzPolicyState -SubscriptionId $Sub.Id -ErrorAction SilentlyContinue
        
        $GroupedByPolicy = $PolicyStates | Group-Object PolicyDefinitionName
        
        foreach ($Group in $GroupedByPolicy) {
            $Compliant = ($Group.Group | Where-Object { $_.ComplianceState -eq "Compliant" }).Count
            $NonCompliant = ($Group.Group | Where-Object { $_.ComplianceState -eq "NonCompliant" }).Count
            $CompliancePercent = if (($Compliant + $NonCompliant) -gt 0) { 
                [math]::Round(($Compliant / ($Compliant + $NonCompliant)) * 100, 2) 
            } else { 100 }
            
            $Results += [PSCustomObject]@{
                Subscription        = $Sub.Name
                PolicyName          = $Group.Name
                TotalResources      = $Group.Count
                Compliant           = $Compliant
                NonCompliant        = $NonCompliant
                CompliancePercent   = $CompliancePercent
                RiskLevel           = if ($CompliancePercent -lt 50) { "High" } elseif ($CompliancePercent -lt 80) { "Medium" } else { "Low" }
            }
        }
    }
    catch {
        Write-Log "Error on $($Sub.Name): $_" -Level "WARNING"
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$NonCompliantPolicies = ($Results | Where-Object { $_.NonCompliant -gt 0 }).Count

Write-Host "`nTotal Policy Assessments: $($Results.Count)" -ForegroundColor White
Write-Host "Policies with Non-Compliance: $NonCompliantPolicies" -ForegroundColor $(if ($NonCompliantPolicies -gt 0) { "Yellow" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Policy Compliance Check Completed ==========" -Level "SUCCESS"
