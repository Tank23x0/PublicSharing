<#
.SYNOPSIS
    Get-ForwardingRulesAudit.ps1 - Audit Email Forwarding Rules

.DESCRIPTION
    Identifies all mailbox forwarding configurations including inbox rules,
    SMTP forwarding, and delegate forwarding. Critical for detecting data
    exfiltration and unauthorized forwarding to external addresses.

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
    .\Get-ForwardingRulesAudit.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\ForwardingRulesAudit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$ExternalOnly
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-ForwardingRulesAudit"
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
║               EMAIL FORWARDING RULES AUDIT                       ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Detects all forwarding configurations for security review       ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
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
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Forwarding Rules Audit Started ==========" -Level "INFO"

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

# Get accepted domains for external detection
$AcceptedDomains = (Get-AcceptedDomain).DomainName

# Get mailboxes
Write-Log "Retrieving mailboxes..." -Level "INFO"
$Mailboxes = Get-EXOMailbox -ResultSize Unlimited -PropertySets Delivery
$TotalMailboxes = $Mailboxes.Count
Write-Log "Found $TotalMailboxes mailboxes to audit" -Level "SUCCESS"

# Process mailboxes
$Results = @()
$Counter = 0

foreach ($Mailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalMailboxes) * 100, 2)
    
    Write-Progress -Activity "Auditing Forwarding Rules" `
                   -Status "$($Mailbox.DisplayName) ($Counter/$TotalMailboxes)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Check SMTP forwarding
        if ($Mailbox.ForwardingSmtpAddress) {
            $ForwardAddress = $Mailbox.ForwardingSmtpAddress -replace "smtp:", ""
            $Domain = $ForwardAddress.Split("@")[1]
            $IsExternal = $Domain -notin $AcceptedDomains
            
            if (-not $ExternalOnly -or $IsExternal) {
                $Results += [PSCustomObject]@{
                    Mailbox           = $Mailbox.DisplayName
                    MailboxUPN        = $Mailbox.UserPrincipalName
                    ForwardingType    = "SMTP Forwarding"
                    ForwardTo         = $ForwardAddress
                    DeliverToMailbox  = $Mailbox.DeliverToMailboxAndForward
                    IsExternal        = $IsExternal
                    RiskLevel         = if ($IsExternal) { "High" } else { "Medium" }
                    RuleName          = "N/A"
                    RuleEnabled       = "N/A"
                    Source            = "Mailbox Settings"
                }
            }
        }
        
        # Check ForwardingAddress (delegate)
        if ($Mailbox.ForwardingAddress) {
            $Results += [PSCustomObject]@{
                Mailbox           = $Mailbox.DisplayName
                MailboxUPN        = $Mailbox.UserPrincipalName
                ForwardingType    = "Delegate Forwarding"
                ForwardTo         = $Mailbox.ForwardingAddress
                DeliverToMailbox  = $Mailbox.DeliverToMailboxAndForward
                IsExternal        = $false
                RiskLevel         = "Low"
                RuleName          = "N/A"
                RuleEnabled       = "N/A"
                Source            = "Mailbox Settings"
            }
        }
        
        # Check Inbox Rules with forwarding
        $InboxRules = Get-InboxRule -Mailbox $Mailbox.UserPrincipalName -ErrorAction SilentlyContinue | 
            Where-Object { $_.ForwardTo -or $_.ForwardAsAttachmentTo -or $_.RedirectTo }
        
        foreach ($Rule in $InboxRules) {
            $ForwardTargets = @()
            if ($Rule.ForwardTo) { $ForwardTargets += $Rule.ForwardTo }
            if ($Rule.ForwardAsAttachmentTo) { $ForwardTargets += $Rule.ForwardAsAttachmentTo }
            if ($Rule.RedirectTo) { $ForwardTargets += $Rule.RedirectTo }
            
            foreach ($Target in $ForwardTargets) {
                $TargetString = $Target.ToString()
                $IsExternal = $AcceptedDomains | ForEach-Object { $TargetString -notmatch $_ } | Where-Object { $_ -eq $true }
                $IsExternal = [bool]$IsExternal
                
                if (-not $ExternalOnly -or $IsExternal) {
                    $Results += [PSCustomObject]@{
                        Mailbox           = $Mailbox.DisplayName
                        MailboxUPN        = $Mailbox.UserPrincipalName
                        ForwardingType    = "Inbox Rule"
                        ForwardTo         = $TargetString
                        DeliverToMailbox  = if ($Rule.ForwardTo -or $Rule.ForwardAsAttachmentTo) { $true } else { $false }
                        IsExternal        = $IsExternal
                        RiskLevel         = if ($IsExternal) { "High" } elseif (-not $Rule.Enabled) { "Low" } else { "Medium" }
                        RuleName          = $Rule.Name
                        RuleEnabled       = $Rule.Enabled
                        Source            = "Inbox Rules"
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error on $($Mailbox.DisplayName): $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Auditing Forwarding Rules" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$SMTPForwarding = ($Results | Where-Object { $_.ForwardingType -eq "SMTP Forwarding" }).Count
$InboxRuleForwarding = ($Results | Where-Object { $_.ForwardingType -eq "Inbox Rule" }).Count
$ExternalForwarding = ($Results | Where-Object { $_.IsExternal -eq $true }).Count
$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              FORWARDING RULES AUDIT SUMMARY                   " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Mailboxes Audited:     $TotalMailboxes" -ForegroundColor White
Write-Host "Total Forwarding:      $($Results.Count)" -ForegroundColor White
Write-Host ""
Write-Host "By Type:" -ForegroundColor Yellow
Write-Host "  SMTP Forwarding:     $SMTPForwarding" -ForegroundColor White
Write-Host "  Inbox Rules:         $InboxRuleForwarding" -ForegroundColor White
Write-Host ""
Write-Host "Security Concerns:" -ForegroundColor Yellow
Write-Host "  External Forwarding: $ExternalForwarding" -ForegroundColor $(if ($ExternalForwarding -gt 0) { "Red" } else { "Green" })
Write-Host "  High Risk:           $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Forwarding Rules Audit Completed ==========" -Level "SUCCESS"

#endregion
