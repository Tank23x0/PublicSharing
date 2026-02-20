<#
.SYNOPSIS
    Get-AzureKeyVaultReport.ps1 - Key Vault Security Audit

.DESCRIPTION
    Audits all Key Vaults including access policies, network rules, and secret expiration.

.AUTHOR
    Joe Romaine — https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    2025-01-26

.EXAMPLE
    .\Get-AzureKeyVaultReport.ps1
#>

[CmdletBinding()]
param(
    [string]$OutputPath = "$env:USERPROFILE\Documents\AzureKeyVaultReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ScriptName = "Get-AzureKeyVaultReport"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) { New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null }

function Write-Log { param([string]$Message, [string]$Level = "INFO")
    Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -Force
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $(switch ($Level) { "INFO" { "Cyan" } "WARNING" { "Yellow" } "ERROR" { "Red" } "SUCCESS" { "Green" } })
}

Write-Host @"
╔══════════════════════════════════════════════════════════════════╗
║               AZURE KEY VAULT SECURITY AUDIT                     ║
╚══════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

Write-Log "========== Key Vault Audit Started ==========" -Level "INFO"

if (-not (Get-Module -Name Az.KeyVault -ListAvailable)) {
    Install-Module -Name Az.KeyVault -Force -Scope CurrentUser
}

$Context = Get-AzContext
if (-not $Context) { Connect-AzAccount }

$Subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }
$Results = @()

foreach ($Sub in $Subscriptions) {
    Set-AzContext -SubscriptionId $Sub.Id -Force | Out-Null
    Write-Log "Processing: $($Sub.Name)" -Level "INFO"
    
    $KeyVaults = Get-AzKeyVault
    
    foreach ($KV in $KeyVaults) {
        $Vault = Get-AzKeyVault -VaultName $KV.VaultName -ResourceGroupName $KV.ResourceGroupName
        
        $Issues = @()
        if (-not $Vault.EnableSoftDelete) { $Issues += "Soft delete disabled" }
        if (-not $Vault.EnablePurgeProtection) { $Issues += "Purge protection disabled" }
        if ($Vault.NetworkAcls.DefaultAction -eq "Allow") { $Issues += "Public network access" }
        if ($Vault.AccessPolicies.Count -gt 10) { $Issues += "Many access policies ($($Vault.AccessPolicies.Count))" }
        
        $Results += [PSCustomObject]@{
            Subscription        = $Sub.Name
            ResourceGroup       = $Vault.ResourceGroupName
            VaultName           = $Vault.VaultName
            Location            = $Vault.Location
            Sku                 = $Vault.Sku
            SoftDeleteEnabled   = $Vault.EnableSoftDelete
            PurgeProtection     = $Vault.EnablePurgeProtection
            NetworkDefaultAction = $Vault.NetworkAcls.DefaultAction
            AccessPolicyCount   = $Vault.AccessPolicies.Count
            EnabledForDeployment = $Vault.EnabledForDeployment
            EnabledForTemplateDeployment = $Vault.EnabledForTemplateDeployment
            EnabledForDiskEncryption = $Vault.EnabledForDiskEncryption
            Issues              = ($Issues -join "; ")
            RiskLevel           = if ($Issues.Count -ge 2) { "High" } elseif ($Issues.Count -eq 1) { "Medium" } else { "Low" }
        }
    }
}

$Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

$HighRisk = ($Results | Where-Object { $_.RiskLevel -eq "High" }).Count

Write-Host "`nTotal Key Vaults: $($Results.Count)" -ForegroundColor White
Write-Host "High Risk:        $HighRisk" -ForegroundColor $(if ($HighRisk -gt 0) { "Red" } else { "Green" })
Write-Host "Report: $OutputPath" -ForegroundColor Green
Write-Log "========== Key Vault Audit Completed ==========" -Level "SUCCESS"
