<#
.SYNOPSIS
    Get-DistributionListReport.ps1 - Distribution List Inventory and Membership Report

.DESCRIPTION
    Generates a comprehensive report of all distribution lists including members,
    owners, moderation settings, and delivery restrictions. Identifies orphaned
    and empty distribution lists.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator or Global Reader role
    - PowerShell 5.1 or higher

.EXAMPLE
    .\Get-DistributionListReport.ps1
    
.EXAMPLE
    .\Get-DistributionListReport.ps1 -IncludeMembers -OutputPath "C:\Reports\DLReport.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\DistributionListReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeMembers,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeDynamic
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-DistributionListReport"
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
║            DISTRIBUTION LIST REPORT GENERATOR                    ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Comprehensive DL inventory with membership and settings         ║
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
        else {
            exit 1
        }
    }
    else {
        Write-Log "Module '$ModuleName' available" -Level "INFO"
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Report Started ==========" -Level "INFO"

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

# Get distribution lists
Write-Log "Retrieving distribution lists..." -Level "INFO"

try {
    $DistributionLists = Get-DistributionGroup -ResultSize Unlimited
    $TotalDLs = $DistributionLists.Count
    Write-Log "Found $TotalDLs distribution lists" -Level "SUCCESS"
    
    if ($IncludeDynamic) {
        $DynamicDLs = Get-DynamicDistributionGroup -ResultSize Unlimited
        Write-Log "Found $($DynamicDLs.Count) dynamic distribution lists" -Level "SUCCESS"
    }
}
catch {
    Write-Log "Failed to retrieve distribution lists: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

# Process distribution lists
$Results = @()
$Counter = 0

foreach ($DL in $DistributionLists) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalDLs) * 100, 2)
    
    Write-Progress -Activity "Processing Distribution Lists" `
                   -Status "$($DL.DisplayName) ($Counter/$TotalDLs)" `
                   -PercentComplete $PercentComplete
    
    try {
        # Get member count
        $Members = Get-DistributionGroupMember -Identity $DL.Identity -ResultSize Unlimited
        $MemberCount = ($Members | Measure-Object).Count
        $MemberList = if ($IncludeMembers) { ($Members.PrimarySmtpAddress -join "; ") } else { "" }
        
        # Identify issues
        $Issues = @()
        if ($MemberCount -eq 0) { $Issues += "Empty DL" }
        if (-not $DL.ManagedBy -or $DL.ManagedBy.Count -eq 0) { $Issues += "No Owner" }
        if ($DL.RequireSenderAuthenticationEnabled -eq $false) { $Issues += "External senders allowed" }
        
        $Results += [PSCustomObject]@{
            DisplayName                = $DL.DisplayName
            PrimarySmtpAddress         = $DL.PrimarySmtpAddress
            Alias                      = $DL.Alias
            GroupType                  = $DL.GroupType
            MemberCount                = $MemberCount
            Members                    = $MemberList
            ManagedBy                  = ($DL.ManagedBy -join "; ")
            ModerationEnabled          = $DL.ModerationEnabled
            ModeratedBy                = ($DL.ModeratedBy -join "; ")
            RequireSenderAuth          = $DL.RequireSenderAuthenticationEnabled
            AcceptMessagesFrom         = ($DL.AcceptMessagesOnlyFrom -join "; ")
            RejectMessagesFrom         = ($DL.RejectMessagesFrom -join "; ")
            HiddenFromGAL              = $DL.HiddenFromAddressListsEnabled
            WhenCreated                = $DL.WhenCreated
            WhenChanged                = $DL.WhenChanged
            Issues                     = ($Issues -join "; ")
            IssueCount                 = $Issues.Count
        }
    }
    catch {
        Write-Log "Error processing $($DL.DisplayName): $_" -Level "WARNING"
    }
}

# Process dynamic DLs if requested
if ($IncludeDynamic -and $DynamicDLs) {
    foreach ($DDL in $DynamicDLs) {
        $Results += [PSCustomObject]@{
            DisplayName                = $DDL.DisplayName
            PrimarySmtpAddress         = $DDL.PrimarySmtpAddress
            Alias                      = $DDL.Alias
            GroupType                  = "Dynamic"
            MemberCount                = "Dynamic"
            Members                    = "Query-based membership"
            ManagedBy                  = ($DDL.ManagedBy -join "; ")
            ModerationEnabled          = $DDL.ModerationEnabled
            ModeratedBy                = ($DDL.ModeratedBy -join "; ")
            RequireSenderAuth          = $DDL.RequireSenderAuthenticationEnabled
            AcceptMessagesFrom         = ($DDL.AcceptMessagesOnlyFrom -join "; ")
            RejectMessagesFrom         = ($DDL.RejectMessagesFrom -join "; ")
            HiddenFromGAL              = $DDL.HiddenFromAddressListsEnabled
            WhenCreated                = $DDL.WhenCreated
            WhenChanged                = $DDL.WhenChanged
            Issues                     = ""
            IssueCount                 = 0
        }
    }
}

Write-Progress -Activity "Processing Distribution Lists" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$EmptyDLs = ($Results | Where-Object { $_.MemberCount -eq 0 }).Count
$NoOwnerDLs = ($Results | Where-Object { $_.Issues -match "No Owner" }).Count
$ExternalAllowed = ($Results | Where-Object { $_.RequireSenderAuth -eq $false }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "               DISTRIBUTION LIST REPORT SUMMARY                " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total DLs:             $($Results.Count)" -ForegroundColor White
Write-Host ""
Write-Host "Issues Found:" -ForegroundColor Yellow
Write-Host "  Empty DLs:           $EmptyDLs" -ForegroundColor $(if ($EmptyDLs -gt 0) { "Yellow" } else { "Green" })
Write-Host "  No Owner:            $NoOwnerDLs" -ForegroundColor $(if ($NoOwnerDLs -gt 0) { "Yellow" } else { "Green" })
Write-Host "  External Senders OK: $ExternalAllowed" -ForegroundColor $(if ($ExternalAllowed -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Report Completed ==========" -Level "SUCCESS"

#endregion
