<#
.SYNOPSIS
    Get-MailFlowRulesReport.ps1 - Mail Flow Rules Inventory and Analysis

.DESCRIPTION
    Generates a comprehensive report of all mail flow (transport) rules in
    Exchange Online. Identifies rules that may pose security risks such as
    auto-forwarding, bypassing spam filters, or modifying headers.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - ExchangeOnlineManagement module
    - Exchange Administrator role
    - PowerShell 5.1 or higher

.EXAMPLE
    .\Get-MailFlowRulesReport.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\MailFlowRulesReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-MailFlowRulesReport"
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
║              MAIL FLOW RULES REPORT GENERATOR                    ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Analyzes transport rules for security and compliance            ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $Banner -ForegroundColor Cyan
}

function Get-RuleRiskLevel {
    param($Rule)
    
    $RiskFactors = @()
    
    # Check for high-risk actions
    if ($Rule.RedirectMessageTo) { $RiskFactors += "Redirects mail externally" }
    if ($Rule.BlindCopyTo) { $RiskFactors += "BCCs messages" }
    if ($Rule.SetSCL -eq -1) { $RiskFactors += "Bypasses spam filter" }
    if ($Rule.SetHeaderName) { $RiskFactors += "Modifies headers" }
    if ($Rule.DeleteMessage) { $RiskFactors += "Deletes messages" }
    if ($Rule.Quarantine) { $RiskFactors += "Quarantines messages" }
    if ($Rule.ModerateMessageByUser) { $RiskFactors += "Requires moderation" }
    
    # Determine risk level
    if ($RiskFactors.Count -ge 2) { return @{ Level = "High"; Factors = ($RiskFactors -join "; ") } }
    if ($RiskFactors.Count -eq 1) { return @{ Level = "Medium"; Factors = ($RiskFactors -join "; ") } }
    return @{ Level = "Low"; Factors = "Standard rule" }
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
        Write-Log "Module '$ModuleName' is available" -Level "INFO"
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Report Generation Started ==========" -Level "INFO"

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

# Get transport rules
Write-Log "Retrieving mail flow rules..." -Level "INFO"

try {
    $Rules = Get-TransportRule | Sort-Object Priority
    $TotalRules = $Rules.Count
    Write-Log "Found $TotalRules mail flow rules" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to retrieve rules: $_" -Level "ERROR"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 1
}

if ($TotalRules -eq 0) {
    Write-Log "No mail flow rules found in the tenant" -Level "WARNING"
    Disconnect-ExchangeOnline -Confirm:$false
    exit 0
}

# Process rules
$Results = @()
$Counter = 0

foreach ($Rule in $Rules) {
    $Counter++
    $PercentComplete = [math]::Round(($Counter / $TotalRules) * 100, 2)
    
    Write-Progress -Activity "Analyzing Mail Flow Rules" `
                   -Status "Rule: $($Rule.Name) ($Counter/$TotalRules)" `
                   -PercentComplete $PercentComplete
    
    $RiskAssessment = Get-RuleRiskLevel -Rule $Rule
    
    $Results += [PSCustomObject]@{
        Priority              = $Rule.Priority
        Name                  = $Rule.Name
        State                 = $Rule.State
        Mode                  = $Rule.Mode
        SenderDomain          = ($Rule.SenderDomainIs -join ", ")
        RecipientDomain       = ($Rule.RecipientDomainIs -join ", ")
        FromAddressContains   = ($Rule.FromAddressContainsWords -join ", ")
        SubjectContains       = ($Rule.SubjectContainsWords -join ", ")
        Actions               = $Rule.Actions
        RedirectTo            = ($Rule.RedirectMessageTo -join ", ")
        BlindCopyTo           = ($Rule.BlindCopyTo -join ", ")
        SetSCL                = $Rule.SetSCL
        AddHeader             = $Rule.SetHeaderName
        RiskLevel             = $RiskAssessment.Level
        RiskFactors           = $RiskAssessment.Factors
        CreatedBy             = $Rule.CreatedBy
        LastModified          = $Rule.WhenChanged
        Comments              = $Rule.Comments
    }
}

Write-Progress -Activity "Analyzing Mail Flow Rules" -Completed

# Export
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Summary statistics
$EnabledRules = ($Rules | Where-Object { $_.State -eq "Enabled" }).Count
$HighRiskRules = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$MediumRiskRules = ($Results | Where-Object { $_.RiskLevel -eq "Medium" }).Count

# Disconnect
Disconnect-ExchangeOnline -Confirm:$false

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                    MAIL FLOW RULES SUMMARY                    " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Rules:           $TotalRules" -ForegroundColor White
Write-Host "Enabled Rules:         $EnabledRules" -ForegroundColor White
Write-Host "Disabled Rules:        $($TotalRules - $EnabledRules)" -ForegroundColor White
Write-Host ""
Write-Host "Risk Assessment:" -ForegroundColor Yellow
Write-Host "  High Risk:           $HighRiskRules" -ForegroundColor $(if ($HighRiskRules -gt 0) { "Red" } else { "Green" })
Write-Host "  Medium Risk:         $MediumRiskRules" -ForegroundColor $(if ($MediumRiskRules -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Low Risk:            $($TotalRules - $HighRiskRules - $MediumRiskRules)" -ForegroundColor Green
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Report Generation Completed ==========" -Level "SUCCESS"

#endregion
