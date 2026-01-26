<#
.SYNOPSIS
    Get-AzureResourceInventory.ps1 - Complete Azure Resource Inventory

.DESCRIPTION
    Generates a comprehensive inventory of all Azure resources across all
    subscriptions including resource type, location, tags, and costs.

.AUTHOR
    Anessen

.VERSION
    1.0.0

.DATE
    2025-01-26

.REQUIREMENTS
    - Az module
    - Reader role on subscriptions

.EXAMPLE
    .\Get-AzureResourceInventory.ps1
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionIds,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureResourceInventory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

#region ==================== CONFIGURATION ====================

$ScriptName = "Get-AzureResourceInventory"
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
║              AZURE RESOURCE INVENTORY GENERATOR                  ║
║                      Version $ScriptVersion                              ║
║                                                                  ║
║  Comprehensive inventory of all Azure resources                  ║
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
    else {
        Write-Log "Module '$ModuleName' available" -Level "INFO"
    }
}

#endregion

#region ==================== MAIN SCRIPT ====================

Show-Banner

Write-Log "========== Resource Inventory Started ==========" -Level "INFO"

# Module check
Install-RequiredModule -ModuleName "Az.Accounts"
Install-RequiredModule -ModuleName "Az.Resources"

# Connect to Azure
Write-Log "Connecting to Azure..." -Level "INFO"
try {
    $Context = Get-AzContext
    if (-not $Context) {
        Connect-AzAccount
    }
    Write-Log "Connected to Azure as $($Context.Account)" -Level "SUCCESS"
}
catch {
    Write-Log "Failed to connect: $_" -Level "ERROR"
    exit 1
}

# Get subscriptions
if ($SubscriptionIds) {
    $Subscriptions = $SubscriptionIds | ForEach-Object { Get-AzSubscription -SubscriptionId $_ }
}
else {
    $Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
}

Write-Log "Found $($Subscriptions.Count) subscription(s) to inventory" -Level "INFO"

$Results = @()
$TotalResources = 0

foreach ($Sub in $Subscriptions) {
    Write-Log "Processing subscription: $($Sub.Name)" -Level "INFO"
    
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    
    $Resources = Get-AzResource
    $ResourceCount = $Resources.Count
    $TotalResources += $ResourceCount
    
    Write-Log "Found $ResourceCount resources in $($Sub.Name)" -Level "INFO"
    
    $Counter = 0
    foreach ($Resource in $Resources) {
        $Counter++
        if ($Counter % 50 -eq 0) {
            Write-Progress -Activity "Inventorying Resources" `
                           -Status "$($Sub.Name): $Counter of $ResourceCount" `
                           -PercentComplete (($Counter / $ResourceCount) * 100)
        }
        
        $Tags = if ($Resource.Tags) { 
            ($Resource.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; " 
        } else { "" }
        
        $Results += [PSCustomObject]@{
            SubscriptionName    = $Sub.Name
            SubscriptionId      = $Sub.Id
            ResourceGroup       = $Resource.ResourceGroupName
            ResourceName        = $Resource.Name
            ResourceType        = $Resource.ResourceType
            Location            = $Resource.Location
            Kind                = $Resource.Kind
            Sku                 = if ($Resource.Sku) { $Resource.Sku.Name } else { "" }
            Tags                = $Tags
            ResourceId          = $Resource.ResourceId
            CreatedTime         = $Resource.CreatedTime
            ChangedTime         = $Resource.ChangedTime
        }
    }
}

Write-Progress -Activity "Inventorying Resources" -Completed

# Export results
Write-Log "Exporting report to: $OutputPath" -Level "INFO"
$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

# Generate summary by type
$TypeSummary = $Results | Group-Object ResourceType | Sort-Object Count -Descending | Select-Object -First 15

# Summary
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "               AZURE RESOURCE INVENTORY SUMMARY                " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Subscriptions Scanned: $($Subscriptions.Count)" -ForegroundColor White
Write-Host "Total Resources:       $TotalResources" -ForegroundColor White
Write-Host ""
Write-Host "Top Resource Types:" -ForegroundColor Yellow
$TypeSummary | ForEach-Object { Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White }
Write-Host ""
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

Write-Log "========== Resource Inventory Completed ==========" -Level "SUCCESS"

#endregion
