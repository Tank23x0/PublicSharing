<#
.SYNOPSIS
    Get-MailboxAuditLogReport.ps1 - Mailbox Audit Log Analysis

.DESCRIPTION
    Retrieves and analyzes mailbox audit logs to identify suspicious activities
    such as unauthorized access, delegate actions, and mailbox modifications.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator or Compliance Administrator role

.EXAMPLE
    .\Get-MailboxAuditLogReport.ps1 -Mailbox user@domain.com -Days 30
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Mailbox,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 7,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Owner", "Delegate", "Admin")]
    [string]$LogonType = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailboxAuditLogReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MailboxAuditLogReport"
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
║              MAILBOX AUDIT LOG ANALYZER                          ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Analyze mailbox audit logs for security investigation           ║
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

function Get-SeverityLevel {
    param([string]$Operation)
    
    $HighSeverity = @("HardDelete", "SoftDelete", "MoveToDeletedItems", "SendAs", "SendOnBehalf", "UpdateFolderPermissions", "MailboxLogin")
    $MediumSeverity = @("Update", "Move", "Copy", "Create", "FolderBind")
    
    if ($Operation -in $HighSeverity) { return "High" }
    if ($Operation -in $MediumSeverity) { return "Medium" }
    return "Low"
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Audit Log Analysis Started ==========" -Level "INFO"

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

# Calculate date range
$EndDate = Get-Date
$StartDate = $EndDate.AddDays(-$Days)

Write-Log "Search Period: $($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd'))" -Level "INFO"

# Get mailboxes to audit
$Mailboxes = @()
if ($Mailbox) {
    $Mailboxes = @($Mailbox)
    Write-Log "Auditing specific mailbox: $Mailbox" -Level "INFO"
}
else {
    Write-Log "Retrieving all mailboxes..." -Level "INFO"
    $Mailboxes = (Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox).UserPrincipalName
    Write-Log "Found $($Mailboxes.Count) mailboxes" -Level "SUCCESS"
    
    Write-Host ""
    Write-Host "This will audit $($Mailboxes.Count) mailboxes. This may take a long time." -ForegroundColor Yellow
    $Confirm = Read-Host "Continue? (Y/N)"
    if ($Confirm -notmatch '^[Yy]') {
        Disconnect-ExchangeOnline -Confirm:$false
        exit 0
    }
}

# Process mailboxes
$Results = @()
$Counter = 0

foreach ($TargetMailbox in $Mailboxes) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $Mailboxes.Count) * 100, 2)
    
    Write-Progress -Activity "Analyzing Audit Logs" `
                   -Status "$TargetMailbox ($Counter/$($Mailboxes.Count))" `
                   -PercentComplete $PercentComplete
    
    try {
        $SearchParams = @{
            Identity = $TargetMailbox
            StartDate = $StartDate
            EndDate = $EndDate
            ShowDetails = $true
            ResultSize = 5000
        }
        
        if ($LogonType -ne "All") { $SearchParams.LogonTypes = $LogonType }
        
        $AuditLogs = Search-MailboxAuditLog @SearchParams -ErrorAction SilentlyContinue
        
        foreach ($Log in $AuditLogs) {
            $Severity = Get-SeverityLevel -Operation $Log.Operation
            
            $Results += [PSCustomObject]@{
                Mailbox         = $TargetMailbox
                Operation       = $Log.Operation
                OperationResult = $Log.OperationResult
                LogonType       = $Log.LogonType
                LogonUserDisplayName = $Log.LogonUserDisplayName
                ItemSubject     = $Log.ItemSubject
                FolderPathName  = $Log.FolderPathName
                ClientIPAddress = $Log.ClientIPAddress
                ClientInfoString = $Log.ClientInfoString
                LogonTime       = $Log.LastAccessed
                Severity        = $Severity
            }
        }
    }
    catch {
        Write-Log "Error auditing $TargetMailbox : $_" -Level "WARNING"
    }
}

Write-Progress -Activity "Analyzing Audit Logs" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$HighSeverityCount = ($Results | Where-Object { $_.Severity -eq "High" }).Count
$DelegateActions = ($Results | Where-Object { $_.LogonType -eq "Delegate" }).Count
$AdminActions = ($Results | Where-Object { $_.LogonType -eq "Admin" }).Count
$UniqueOperations = ($Results | Select-Object -Property Operation -Unique).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "              MAILBOX AUDIT LOG ANALYSIS SUMMARY               " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Mailboxes Audited:     $($Mailboxes.Count)" -ForegroundColor White
Write-Host "Total Events:          $($Results.Count)" -ForegroundColor White
Write-Host "Unique Operations:     $UniqueOperations" -ForegroundColor White
Write-Host ""
Write-Host "Security Analysis:" -ForegroundColor Yellow
Write-Host "  High Severity:       $HighSeverityCount" -ForegroundColor $(if ($HighSeverityCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Delegate Actions:    $DelegateActions" -ForegroundColor $(if ($DelegateActions -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Admin Actions:       $AdminActions" -ForegroundColor White
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Audit Log Analysis Completed ==========" -Level "SUCCESS"

#endregion
