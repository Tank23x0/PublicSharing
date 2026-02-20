<#
.SYNOPSIS
    Get-AzureRBACReport.ps1 - Azure RBAC Role Assignment Audit

.DESCRIPTION
    Audits all role assignments across Azure subscriptions. Identifies
    privileged access, orphaned assignments, and security concerns.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Az module
    - Reader role on subscriptions

.EXAMPLE
    .\Get-AzureRBACReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureRBACReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureRBACReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║                  AZURE RBAC AUDIT REPORT                         ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== RBAC Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Resources -ListAvailable)) {
    Install-Module -Name Az.Resources -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
Write-Log "Auditing $($Subscriptions.Count) subscriptions" -Level "INFO"

$Results = @()
$HighPrivilegedRoles = @("Owner", "Contributor", "User Access Administrator")

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $Assignments = Get-AzRoleAssignment
    
    foreach ($Assignment in $Assignments) {
        $IsHighPrivilege = $Assignment.RoleDefinitionName -in $HighPrivilegedRoles
        $IsOrphaned = $Assignment.ObjectType -eq "Unknown"
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            SubscriptionId      = $Sub.Id
            Scope               = $Assignment.Scope
            RoleDefinitionName  = $Assignment.RoleDefinitionName
            PrincipalName       = $Assignment.DisplayName
            PrincipalId         = $Assignment.ObjectId
            PrincipalType       = $Assignment.ObjectType
            RoleAssignmentId    = $Assignment.RoleAssignmentId
            IsHighPrivilege     = $IsHighPrivilege
            IsOrphaned          = $IsOrphaned
            RiskLevel           = if ($IsOrphaned) { "High" } elseif ($IsHighPrivilege) { "Medium" } else { "Low" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighPrivCount = ($Results | Where-Object { $_.IsHighPrivilege }).Count
$OrphanedCount = ($Results | Where-Object { $_.IsOrphaned }).Count

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Role Assignments:  $($Results.Count)" -ForegroundColor White
Write-Host "High Privilege:          $HighPrivCount" -ForegroundColor $(if ($HighPrivCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "Orphaned (Unknown):      $OrphanedCount" -ForegroundColor $(if ($OrphanedCount -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== RBAC Audit Completed ==========" -Level "SUCCESS"
