<#
.SYNOPSIS
    Get-AzureStorageReport.ps1 - Azure Storage Account Inventory

.DESCRIPTION
    Inventories all storage accounts with security configuration analysis.
    Identifies insecure configurations and public access.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureStorageReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureStorageReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureStorageReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║              AZURE STORAGE ACCOUNT SECURITY REPORT               ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Storage Report Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.Storage -ListAvailable)) {
    Install-Module -Name Az.Storage -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $StorageAccounts = Get-AzStorageAccount
    
    foreach ($SA in $StorageAccounts) {
        $Issues = @()
        
        # Check for security issues
        if ($SA.AllowBlobPublicAccess) { $Issues += "Public blob access enabled" }
        if ($SA.EnableHttpsTrafficOnly -eq $false) { $Issues += "HTTP allowed" }
        if ($SA.MinimumTlsVersion -ne "TLS1_2") { $Issues += "TLS < 1.2" }
        if ($SA.NetworkRuleSet.DefaultAction -eq "Allow") { $Issues += "Open network access" }
        if (-not $SA.EnableBlobEncryption) { $Issues += "Blob encryption disabled" }
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $SA.ResourceGroupName
            StorageAccountName  = $SA.StorageAccountName
            Location            = $SA.Location
            Kind                = $SA.Kind
            SkuName             = $SA.Sku.Name
            AccessTier          = $SA.AccessTier
            AllowBlobPublicAccess = $SA.AllowBlobPublicAccess
            HttpsOnly           = $SA.EnableHttpsTrafficOnly
            MinimumTlsVersion   = $SA.MinimumTlsVersion
            NetworkDefaultAction = $SA.NetworkRuleSet.DefaultAction
            BlobEncryption      = $SA.EnableBlobEncryption
            FileEncryption      = $SA.EnableFileEncryption
            Issues              = ($Issues -join "; ")
            RiskLevel           = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count
$PublicAccess = ($Results | Where-Object { $_.AllowBlobPublicAccess }).Count

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "Total Storage Accounts: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:              $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Public Access Enabled:  $PublicAccess" -ForegroundColor $(if ($PublicAccess -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Storage Report Completed ==========" -Level "SUCCESS"
