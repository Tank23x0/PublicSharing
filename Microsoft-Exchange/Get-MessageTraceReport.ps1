<#
.SYNOPSIS
    Get-MessageTraceReport.ps1 - Email Message Trace Analysis

.DESCRIPTION
    Performs message trace searches in Exchange Online. Tracks email delivery
    status, identifies failed deliveries, and exports comprehensive reports.

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
    .\Get-MessageTraceReport.ps1 -SenderAddress user@domain.com -Days 7
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SenderAddress,
    
    [Parameter(Mandatory = $false)]
    [string]$RecipientAddress,
    
    [Parameter(Mandatory = $false)]
    [int]$Days = 7,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("All", "Delivered", "Failed", "Pending", "Quarantined", "FilteredAsSpam")]
    [string]$Status = "All",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MessageTraceReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MessageTraceReport"
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
║                 MESSAGE TRACE REPORT TOOL                        ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Track email delivery and identify mail flow issues              ║
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

Write-Log "========== Message Trace Started ==========" -Level "INFO"

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

Write-Log "Search Parameters:" -Level "INFO"
Write-Log "  Date Range: $($StartDate.ToString('yyyy-MM-dd')) to $($EndDate.ToString('yyyy-MM-dd'))" -Level "INFO"
if ($SenderAddress) { Write-Log "  Sender: $SenderAddress" -Level "INFO" }
if ($RecipientAddress) { Write-Log "  Recipient: $RecipientAddress" -Level "INFO" }
if ($Status -ne "All") { Write-Log "  Status Filter: $Status" -Level "INFO" }

# Build search parameters
$SearchParams = @{
    StartDate = $StartDate
    EndDate = $EndDate
    PageSize = 5000
}

if ($SenderAddress) { $SearchParams.SenderAddress = $SenderAddress }
if ($RecipientAddress) { $SearchParams.RecipientAddress = $RecipientAddress }
if ($Status -ne "All") { $SearchParams.Status = $Status }

# Perform message trace
Write-Log "Performing message trace (this may take a while)..." -Level "INFO"

try {
    $Messages = @()
    $Page = 1
    
    do {
        Write-Progress -Activity "Retrieving Message Trace" `
                       -Status "Page $Page" `
                       -PercentComplete -1
        
        $SearchParams.Page = $Page
        $PageResults = Get-MessageTrace @SearchParams
        
        if ($PageResults) {
            $Messages += $PageResults
            $Page++
        }
    } while ($PageResults.Count -eq 5000)
    
    Write-Progress -Activity "Retrieving Message Trace" -Completed
    
    $TotalMessages = $Messages.Count
    Write-Log "Found $TotalMessages messages" -Level "SUCCESS"
}
catch {
    Write-Log "Message trace failed: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

if ($TotalMessages -eq 0) {
    Write-Log "No messages found matching criteria" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process results
$Results = foreach ($Message in $Messages) {
    [PSCustomObject]@{
        Received          = $Message.Received
        SenderAddress     = $Message.SenderAddress
        RecipientAddress  = $Message.RecipientAddress
        Subject           = $Message.Subject
        Status            = $Message.Status
        ToIP              = $Message.ToIP
        FromIP            = $Message.FromIP
        Size              = $Message.Size
        MessageId         = $Message.MessageId
        MessageTraceId    = $Message.MessageTraceId
    }
}

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Statistics
$DeliveredCount = ($Results | Where-Object { $_.Status -eq "Delivered" }).Count
$FailedCount = ($Results | Where-Object { $_.Status -eq "Failed" }).Count
$PendingCount = ($Results | Where-Object { $_.Status -eq "Pending" }).Count
$QuarantinedCount = ($Results | Where-Object { $_.Status -eq "Quarantined" }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                MESSAGE TRACE REPORT SUMMARY                   " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Messages:        $TotalMessages" -ForegroundColor White
Write-Host ""
Write-Host "By Status:" -ForegroundColor Yellow
Write-Host "  Delivered:           $DeliveredCount" -ForegroundColor Green
Write-Host "  Failed:              $FailedCount" -ForegroundColor $(if ($FailedCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Pending:             $PendingCount" -ForegroundColor $(if ($PendingCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Quarantined:         $QuarantinedCount" -ForegroundColor $(if ($QuarantinedCount -gt 0) { "Yellow" } else { "Green" })
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Message Trace Completed ==========" -Level "SUCCESS"

#endregion
