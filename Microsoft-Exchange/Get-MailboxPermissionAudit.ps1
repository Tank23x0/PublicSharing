<#
.SYNOPSIS
    Get-MailboxPermissionAudit.ps1 - Audit Mailbox Permissions

.DESCRIPTION
    Audits all mailbox permissions including Full Access, Send As, and Send on Behalf
    permissions. Identifies security risks from overly permissive access.
    Exports detailed report with recommendations.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role
    - PowerShell 5.1 or higher

.EXAMPLE
    .\Get-MailboxPermissionAudit.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailboxPermissionAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [string[]]$MailboxFilter,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExcludeServiceAccounts
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MailboxPermissionAudit"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"

# Create log directory
$LogDir = Split-Path -Path $LogPath -Parent
if (-not (Test-Path -Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
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
    
    switch ($Level) {
        "INFO"    { Write-Host $LogMessage -ForegroundColor Cyan }
        "WARNING" { Write-Host $LogMessage -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogMessage -ForegroundColor Green }
    }
}

function Show-Banner {
    $Banner = @"
╔══════════════════════════════════════════════════════════════════╗
║               MAILBOX PERMISSION AUDIT TOOL                      ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Audits Full Access, Send As, and Send on Behalf permissions     ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Test-ModuleInstalled {
    param([string]$ModuleName)
    
    $Module = Get-Module -Name $ModuleName -ListAvailable
    if ($Module) {
        Write-Log "Module '$ModuleName' found (v$($Module.Version[0]))" -Level "INFO"
        return $true
    }
    return $false
}

function Install-RequiredModule {
    param([string]$ModuleName)
    
    if (-not (Test-ModuleInstalled -ModuleName $ModuleName)) {
        Write-Log "Module '$ModuleName' not found" -Level "WARNING"
        $Confirm = Read-Host "Install $ModuleName? (Y/N)"
        if ($Confirm -match '^[Yy]') {
            Install-Module -Name $ModuleName -Force -AllowClobber -Scope CurrentUser
            Write-Log "Module installed successfully" -Level "SUCCESS"
        }
        else {
            Write-Log "Installation declined. Exiting." -Level "ERROR"
            exit 1
        }
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Audit Started ==========" -Level "INFO"
Write-Log "User: $env:USERNAME | Computer: $env:COMPUTERNAME" -Level "INFO"

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

if ($MailboxFilter) {
    $Mailboxes = foreach ($Filter in $MailboxFilter) {
        Get-EXOMailbox -Identity $Filter -ErrorAction SilentlyContinue
    }
}
else {
    $Mailboxes = Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox
}

$TotalMailboxes = ($Mailboxes | Measure-Object).Count
Write-Log "Found $TotalMailboxes mailboxes" -Level "SUCCESS"

# Confirmation
Write-Host ""
Write-Host "This audit will check permissions on $TotalMailboxes mailboxes." -ForegroundColor Yellow
Write-Host "This may take a while depending on the number of mailboxes." -ForegroundColor Yellow
$Confirm = Read-Host "Continue? (Y/N)"

if ($Confirm -notmatch '^[Yy]') {
    Write-Log "Audit cancelled by user" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process mailboxes
$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Auditing Mailbox Permissions" `
                   -Status "$($Mailbox.DisplayName) ($Counter/$TotalMailboxes)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get Full Access permissions
        $FullAccessPerms = Get-EXOMailboxPermission -Identity $Mailbox.UserPrincipalName | 
            Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-5-*" -and $_.IsInherited -eq $false }
        
        foreach ($Perm in $FullAccessPerms) {
            if ($ExcludeServiceAccounts -and $Perm.User -match "svc_|service|admin") { continue }
            
            $Results += [PSCustomObject]@{
                Mailbox            = $Mailbox.DisplayName
                MailboxUPN         = $Mailbox.UserPrincipalName
                MailboxType        = $Mailbox.RecipientTypeDetails
                PermissionType     = "Full Access"
                GrantedTo          = $Perm.User
                AccessRights       = ($Perm.AccessRights -join ", ")
                IsInherited        = $Perm.IsInherited
                SecurityRisk       = if ($Perm.AccessRights -contains "FullAccess") { "High" } else { "Medium" }
            }
        }
        
        # Get Send As permissions
        $SendAsPerms = Get-EXORecipientPermission -Identity $Mailbox.UserPrincipalName | 
            Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.Trustee -ne "Self" }
        
        foreach ($Perm in $SendAsPerms) {
            if ($ExcludeServiceAccounts -and $Perm.Trustee -match "svc_|service|admin") { continue }
            
            $Results += [PSCustomObject]@{
                Mailbox            = $Mailbox.DisplayName
                MailboxUPN         = $Mailbox.UserPrincipalName
                MailboxType        = $Mailbox.RecipientTypeDetails
                PermissionType     = "Send As"
                GrantedTo          = $Perm.Trustee
                AccessRights       = "SendAs"
                IsInherited        = $false
                SecurityRisk       = "High"
            }
        }
        
        # Get Send on Behalf permissions
        if ($Mailbox.GrantSendOnBehalfTo) {
            foreach ($Delegate in $Mailbox.GrantSendOnBehalfTo) {
                if ($ExcludeServiceAccounts -and $Delegate -match "svc_|service|admin") { continue }
                
                $Results += [PSCustomObject]@{
                    Mailbox            = $Mailbox.DisplayName
                    MailboxUPN         = $Mailbox.UserPrincipalName
                    MailboxType        = $Mailbox.RecipientTypeDetails
                    PermissionType     = "Send on Behalf"
                    GrantedTo          = $Delegate
                    AccessRights       = "SendOnBehalf"
                    IsInherited        = $false
                    SecurityRisk       = "Medium"
                }
            }
        }
    }
    catch {
        Write-Log "Error processing $($Mailbox.DisplayName): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Auditing Mailbox Permissions" -Completed

# Export results
Write-Log "Exporting results to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Generate summary
$HighRiskCount = ($Results | Where-Object { $_.SecurityRisk -eq "High" }).Count
$MediumRiskCount = ($Results | Where-Object { $_.SecurityRisk -eq "Medium" }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                      AUDIT SUMMARY                            " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Mailboxes Audited:     $TotalMailboxes" -ForegroundColor White
Write-Host "Total Permissions:     $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:             $HighRiskCount" -ForegroundColor $(if ($HighRiskCount -gt 0) { "Red" } else { "Green" })
Write-Host "Medium Risk:           $MediumRiskCount" -ForegroundColor $(if ($MediumRiskCount -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "Log:    $LogPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Audit Completed ==========" -Level "SUCCESS"

#endregion
