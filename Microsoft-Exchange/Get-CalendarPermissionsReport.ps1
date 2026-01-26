<#
.SYNOPSIS
    Get-CalendarPermissionsReport.ps1 - Calendar Permissions Audit

.DESCRIPTION
    Audits calendar sharing permissions across all mailboxes. Identifies
    overly permissive access, external sharing, and default permissions
    that may pose privacy or security risks.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role

.EXAMPLE
    .\Get-CalendarPermissionsReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\CalendarPermissionsReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-CalendarPermissionsReport"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

#endregion

#region ==================== FUNCTIONS ====================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $LogMessage -Force
    
    $Color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $LogMessage -ForegroundColor $Color
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║             CALENDAR PERMISSIONS AUDIT TOOL                      ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Audits calendar sharing permissions across mailboxes            ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Get-PermissionRiskLevel {
    param([string]$AccessRights)
    
    $HighRisk = @("Editor", "PublishingEditor", "Owner", "PublishingAuthor")
    $MediumRisk = @("Author", "Reviewer")
    
    if ($AccessRights -in $HighRisk) { return "High" }
    if ($AccessRights -in $MediumRisk) { return "Medium" }
    return "Low"
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    return [bool](Get-Module -Name $ModuleName -ListAvailable)
}

function Install-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Test-ModuleInstalled -ModuleName $ModuleName)) {
        Write-Log "Module '$ModuleName' not found" -Level "WARNING"
        $Confirm = Read-Host "Install $ModuleName? (Y/N)"
        if ($Confirm -match '^[Yy]') {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Log "Module installed" -Level "SUCCESS"
        }
        else { exit 1 }
    }
    else {
        Write-Log "Module '$ModuleName' available" -Level "INFO"
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Calendar Audit Started ==========" -Level "INFO"

# Module check
Install-RequiredModule -ModuleName "ExchangeOnlineManagement"
Import-Module ExchangeOnlineManagement -ErrorAction Stop

# Connect
Write-Log "Connecting to Exchange Online..." -Level "INFO"
try {
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log "Connected successfully" -Level "SUCCESS"
}
catch {
    Write-Log "Connection failed: $_" -Level "ERROR"
    exit 1
}

# Get mailboxes
Write-Log "Retrieving mailboxes..." -Level "INFO"

try {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox
    $TotalMailboxes = $Mailboxes.Count
    Write-Log "Found $TotalMailboxes mailboxes" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve mailboxes: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Confirmation
Write-Host ""
Write-Host "This will audit calendar permissions for $TotalMailboxes mailboxes." -ForegroundColor Yellow
$Confirm = Read-Host "Continue? (Y/N)"
if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Audit cancelled" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process mailboxes
$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Auditing Calendar Permissions" `
                   -Status "$($Mailbox.DisplayName) ($Counter/$TotalMailboxes)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get calendar folder
        $CalendarPath = "$($Mailbox.UserPrincipalName):\Calendar"
        $Permissions = Get-EXOMailboxFolderPermission -Identity $CalendarPath -ErrorAction SilentlyContinue
        
        if ($Permissions) {
            foreach ($Perm in $Permissions) {
                # Skip default entries with AvailabilityOnly
                if ($Perm.User.ToString() -eq "Default" -and $Perm.AccessRights -contains "AvailabilityOnly") {
                    continue
                }
                
                $RiskLevel = Get-PermissionRiskLevel -AccessRights ($Perm.AccessRights -join ", ")
                
                # Flag external users
                $IsExternal = $Perm.User.ToString() -match "@" -and $Perm.User.ToString() -notmatch $Mailbox.PrimarySmtpAddress.Split("@")[1]
                
                $Results += [PSCustomObject]@{
                    MailboxOwner       = $Mailbox.DisplayName
                    MailboxUPN         = $Mailbox.UserPrincipalName
                    SharedWith         = $Perm.User.ToString()
                    AccessRights       = ($Perm.AccessRights -join ", ")
                    SharingPermission  = $Perm.SharingPermissionFlags
                    IsInherited        = $Perm.IsInherited
                    IsExternal         = $IsExternal
                    RiskLevel          = $RiskLevel
                }
            }
        }
    }
    catch {
        # Skip mailboxes where we can't access calendar
        if ($_.Exception.Message -notmatch "couldn't be found") {
            Write-Log "Error on $($Mailbox.DisplayName): $_" -Level "WARNING"
        }
    }
}

Write-Progress -Activity "Auditing Calendar Permissions" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$HighRiskCount = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$MediumRiskCount = ($Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count
$ExternalCount = ($Results | Where-Object { $_.IsExternal -eq $true }).Count
$DefaultNonStandard = ($Results | Where-Object { $_.SharedWith -eq "Default" -and $_.AccessRights -ne "AvailabilityOnly" }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              CALENDAR PERMISSIONS AUDIT SUMMARY               " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Mailboxes Audited:     $TotalMailboxes" -ForegroundColor White
Write-Host "Total Permissions:     $($Results.Count)" -ForegroundColor White
Write-Host ""
Write-Host "Risk Assessment:" -ForegroundColor Yellow
Write-Host "  High Risk:           $HighRiskCount" -ForegroundColor $(if ($HighRiskCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Medium Risk:         $MediumRiskCount" -ForegroundColor $(if ($MediumRiskCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  External Sharing:    $ExternalCount" -ForegroundColor $(if ($ExternalCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Non-standard Default: $DefaultNonStandard" -ForegroundColor $(if ($DefaultNonStandard -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Calendar Audit Completed ==========" -Level "SUCCESS"

#endregion
