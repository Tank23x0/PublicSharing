<#
.SYNOPSIS
    Comprehensive Azure Security Audit Script
    
.DESCRIPTION
    Performs thorough security audits of Azure environments including:
    - RBAC role assignments and privileged access
    - Resource security configurations
    - Network security (NSGs, firewalls)
    - Storage account security
    - Key Vault access policies
    - Microsoft Defender for Cloud status
    - Policy compliance
    - Activity logs and diagnostics
    
.AUTHOR
    Security Operations Team
    
.VERSION
    2.0.0
    
.DATE
    2025-01-26
    
.REQUIREMENTS
    - Az PowerShell module
    - Azure subscription access (Reader + Security Reader minimum)
    - PowerShell 7.0+ recommended
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory = $false)]
    [switch]$AllSubscriptions,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:USERPROFILE\Documents\Scripts\Azure-Audit",
    
    [Parameter(Mandatory = $false)]
    [int]$StaleThresholdDays = 90,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeResourceDetails
)

#region Configuration

$script:Config = @{
    ScriptName = "Azure-Full-Audit"
    Version = "2.0.0"
    StartTime = Get-Date
    LogFile = $null
    ReportFile = $null
    TotalFindings = 0
    CriticalFindings = 0
    HighFindings = 0
    MediumFindings = 0
    LowFindings = 0
}

# Platform detection for paths
if ($PSVersionTable.Platform -eq 'Unix' -or $IsMacOS -or $IsLinux) {
    $OutputPath = $OutputPath -replace '\$env:USERPROFILE', $env:HOME
    $OutputPath = $OutputPath -replace '\\', '/'
}

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyy-MM-dd_HHmmss"
$script:Config.LogFile = Join-Path $OutputPath "Azure-Audit-Log_$timestamp.txt"
$script:Config.ReportFile = Join-Path $OutputPath "Azure-Audit-Report_$timestamp.html"

$script:AllFindings = @()

#endregion

#region Logging Functions

function Write-AuditLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS", "FINDING")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "INFO"    { "White" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        "FINDING" { "Cyan" }
    }
    
    Write-Host $logEntry -ForegroundColor $color
    Add-Content -Path $script:Config.LogFile -Value $logEntry
}

function Write-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Subscription,
        [string]$Resource,
        [string]$Finding,
        [string]$Recommendation
    )
    
    $script:Config.TotalFindings++
    switch ($Severity) {
        "CRITICAL" { $script:Config.CriticalFindings++ }
        "HIGH"     { $script:Config.HighFindings++ }
        "MEDIUM"   { $script:Config.MediumFindings++ }
        "LOW"      { $script:Config.LowFindings++ }
    }
    
    $script:AllFindings += [PSCustomObject]@{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Category = $Category
        Severity = $Severity
        Subscription = $Subscription
        Resource = $Resource
        Finding = $Finding
        Recommendation = $Recommendation
    }
    
    Write-AuditLog -Message "[$Severity] $Category - $Finding" -Level "FINDING"
}

#endregion

#region Module Verification

function Test-AzModules {
    Write-AuditLog "Checking Azure PowerShell modules..." -Level "INFO"
    
    $requiredModules = @(
        "Az.Accounts",
        "Az.Resources",
        "Az.Security",
        "Az.Storage",
        "Az.Network",
        "Az.KeyVault",
        "Az.Monitor",
        "Az.PolicyInsights"
    )
    
    $missingModules = @()
    foreach ($module in $requiredModules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            $missingModules += $module
        }
    }
    
    if ($missingModules.Count -gt 0) {
        Write-AuditLog "Missing modules: $($missingModules -join ', ')" -Level "WARNING"
        Write-AuditLog "Installing missing modules..." -Level "INFO"
        
        foreach ($module in $missingModules) {
            try {
                Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
                Write-AuditLog "Installed: $module" -Level "SUCCESS"
            }
            catch {
                Write-AuditLog "Failed to install $module`: $_" -Level "ERROR"
                return $false
            }
        }
    }
    
    foreach ($module in $requiredModules) {
        Import-Module $module -Force -ErrorAction SilentlyContinue
    }
    
    Write-AuditLog "Azure modules verified" -Level "SUCCESS"
    return $true
}

function Initialize-AzureConnection {
    Write-AuditLog "Connecting to Azure..." -Level "INFO"
    
    try {
        $context = Get-AzContext
        
        if (-not $context) {
            Connect-AzAccount
            $context = Get-AzContext
        }
        
        Write-AuditLog "Connected as: $($context.Account.Id)" -Level "SUCCESS"
        Write-AuditLog "Tenant: $($context.Tenant.Id)" -Level "INFO"
        
        return $true
    }
    catch {
        Write-AuditLog "Failed to connect to Azure: $_" -Level "ERROR"
        return $false
    }
}

#endregion

#region Subscription Audit

function Get-SubscriptionsToAudit {
    if ($AllSubscriptions) {
        $subs = Get-AzSubscription -WarningAction SilentlyContinue
        Write-AuditLog "Found $($subs.Count) subscriptions" -Level "INFO"
        return $subs
    }
    elseif ($SubscriptionId) {
        return @(Get-AzSubscription -SubscriptionId $SubscriptionId -WarningAction SilentlyContinue)
    }
    else {
        $current = (Get-AzContext).Subscription
        return @($current)
    }
}

#endregion

#region RBAC Audit

function Invoke-RBACaudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing RBAC assignments for subscription: $SubName" -Level "INFO"
    
    try {
        $roleAssignments = Get-AzRoleAssignment -Scope "/subscriptions/$SubId"
        
        # High privilege roles
        $criticalRoles = @("Owner", "Contributor", "User Access Administrator")
        $highRoles = @("Virtual Machine Contributor", "Storage Account Contributor", 
                       "Network Contributor", "Key Vault Administrator", "Security Admin")
        
        foreach ($assignment in $roleAssignments) {
            $roleName = $assignment.RoleDefinitionName
            $principal = $assignment.DisplayName ?? $assignment.ObjectId
            $principalType = $assignment.ObjectType
            $scope = $assignment.Scope
            
            # Check for subscription-level Owner/Contributor
            if ($scope -eq "/subscriptions/$SubId") {
                if ($roleName -eq "Owner") {
                    Write-Finding -Category "RBAC" -Severity "HIGH" `
                        -Subscription $SubName -Resource "$principal ($principalType)" `
                        -Finding "Subscription-level Owner role assigned" `
                        -Recommendation "Review necessity of Owner access at subscription level"
                }
            }
            
            # Check for wildcard/unknown principals
            if ($assignment.ObjectType -eq "Unknown") {
                Write-Finding -Category "RBAC" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "ObjectId: $($assignment.ObjectId)" `
                    -Finding "Orphaned role assignment (principal no longer exists)" `
                    -Recommendation "Remove orphaned role assignments"
            }
            
            # Check for User Access Administrator at high scope
            if ($roleName -eq "User Access Administrator" -and $scope -match "^/subscriptions/[^/]+$") {
                Write-Finding -Category "RBAC" -Severity "HIGH" `
                    -Subscription $SubName -Resource "$principal" `
                    -Finding "User Access Administrator at subscription level" `
                    -Recommendation "This role can grant any permission - review necessity"
            }
        }
        
        # Count privilege levels
        $ownerCount = ($roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Owner" }).Count
        $contributorCount = ($roleAssignments | Where-Object { $_.RoleDefinitionName -eq "Contributor" }).Count
        
        Write-AuditLog "  Owners: $ownerCount, Contributors: $contributorCount" -Level "INFO"
        
        if ($ownerCount -gt 5) {
            Write-Finding -Category "RBAC" -Severity "MEDIUM" `
                -Subscription $SubName -Resource "Subscription" `
                -Finding "$ownerCount Owner role assignments (excessive)" `
                -Recommendation "Reduce Owner count to essential personnel only"
        }
    }
    catch {
        Write-AuditLog "Error auditing RBAC: $_" -Level "ERROR"
    }
}

#endregion

#region Network Security Audit

function Invoke-NetworkSecurityAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Network Security for subscription: $SubName" -Level "INFO"
    
    try {
        # Network Security Groups
        $nsgs = Get-AzNetworkSecurityGroup
        
        foreach ($nsg in $nsgs) {
            $nsgName = $nsg.Name
            $rgName = $nsg.ResourceGroupName
            
            foreach ($rule in $nsg.SecurityRules) {
                if ($rule.Direction -eq "Inbound" -and $rule.Access -eq "Allow") {
                    $sourcePrefix = $rule.SourceAddressPrefix
                    
                    # Check for ANY source
                    if ($sourcePrefix -in @("*", "0.0.0.0/0", "Internet")) {
                        $destPort = $rule.DestinationPortRange
                        
                        $severity = switch -Regex ($destPort) {
                            "^(22|3389)$" { "CRITICAL" }
                            "^(3306|5432|1433|27017)$" { "CRITICAL" }
                            "^(80|443)$" { "MEDIUM" }
                            "^\*$" { "CRITICAL" }
                            default { "HIGH" }
                        }
                        
                        $portName = switch ($destPort) {
                            "22" { "SSH" }
                            "3389" { "RDP" }
                            "3306" { "MySQL" }
                            "5432" { "PostgreSQL" }
                            "1433" { "MSSQL" }
                            default { $destPort }
                        }
                        
                        Write-Finding -Category "Network" -Severity $severity `
                            -Subscription $SubName -Resource "$rgName/$nsgName" `
                            -Finding "NSG rule '$($rule.Name)' allows $sourcePrefix to port $portName" `
                            -Recommendation "Restrict source IP ranges"
                    }
                }
            }
        }
        
        # Public IPs
        $publicIPs = Get-AzPublicIpAddress
        foreach ($pip in $publicIPs) {
            if ($pip.IpAddress -and $pip.IpAddress -ne "Not Assigned") {
                Write-Finding -Category "Network" -Severity "LOW" `
                    -Subscription $SubName -Resource "$($pip.ResourceGroupName)/$($pip.Name)" `
                    -Finding "Public IP allocated: $($pip.IpAddress)" `
                    -Recommendation "Verify public IP is necessary"
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing network security: $_" -Level "ERROR"
    }
}

#endregion

#region Storage Security Audit

function Invoke-StorageSecurityAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Storage Security for subscription: $SubName" -Level "INFO"
    
    try {
        $storageAccounts = Get-AzStorageAccount
        
        foreach ($storage in $storageAccounts) {
            $saName = $storage.StorageAccountName
            $rgName = $storage.ResourceGroupName
            
            # Check HTTPS only
            if (-not $storage.EnableHttpsTrafficOnly) {
                Write-Finding -Category "Storage" -Severity "HIGH" `
                    -Subscription $SubName -Resource "$rgName/$saName" `
                    -Finding "HTTPS-only traffic not enforced" `
                    -Recommendation "Enable 'Secure transfer required'"
            }
            
            # Check blob public access
            if ($storage.AllowBlobPublicAccess) {
                Write-Finding -Category "Storage" -Severity "HIGH" `
                    -Subscription $SubName -Resource "$rgName/$saName" `
                    -Finding "Blob public access is allowed" `
                    -Recommendation "Disable blob public access unless required"
            }
            
            # Check network rules
            $networkRules = $storage.NetworkRuleSet
            if ($networkRules.DefaultAction -eq "Allow") {
                Write-Finding -Category "Storage" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "$rgName/$saName" `
                    -Finding "Storage account allows access from all networks" `
                    -Recommendation "Configure firewall to allow only specific networks"
            }
            
            # Check minimum TLS version
            if ($storage.MinimumTlsVersion -lt "TLS1_2") {
                Write-Finding -Category "Storage" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "$rgName/$saName" `
                    -Finding "Minimum TLS version is $($storage.MinimumTlsVersion)" `
                    -Recommendation "Set minimum TLS version to 1.2"
            }
            
            # Check infrastructure encryption
            if (-not $storage.Encryption.RequireInfrastructureEncryption) {
                Write-Finding -Category "Storage" -Severity "LOW" `
                    -Subscription $SubName -Resource "$rgName/$saName" `
                    -Finding "Infrastructure encryption not enabled" `
                    -Recommendation "Enable infrastructure encryption for double encryption"
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing storage: $_" -Level "ERROR"
    }
}

#endregion

#region Key Vault Audit

function Invoke-KeyVaultAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Key Vaults for subscription: $SubName" -Level "INFO"
    
    try {
        $keyVaults = Get-AzKeyVault
        
        foreach ($kv in $keyVaults) {
            $kvName = $kv.VaultName
            $kvDetails = Get-AzKeyVault -VaultName $kvName
            
            # Check soft delete
            if (-not $kvDetails.EnableSoftDelete) {
                Write-Finding -Category "KeyVault" -Severity "HIGH" `
                    -Subscription $SubName -Resource $kvName `
                    -Finding "Soft delete is not enabled" `
                    -Recommendation "Enable soft delete to prevent accidental deletion"
            }
            
            # Check purge protection
            if (-not $kvDetails.EnablePurgeProtection) {
                Write-Finding -Category "KeyVault" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource $kvName `
                    -Finding "Purge protection is not enabled" `
                    -Recommendation "Enable purge protection for critical vaults"
            }
            
            # Check network rules
            if ($kvDetails.NetworkAcls.DefaultAction -eq "Allow") {
                Write-Finding -Category "KeyVault" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource $kvName `
                    -Finding "Key Vault allows access from all networks" `
                    -Recommendation "Configure firewall to restrict network access"
            }
            
            # Check RBAC vs access policies
            if (-not $kvDetails.EnableRbacAuthorization) {
                Write-Finding -Category "KeyVault" -Severity "LOW" `
                    -Subscription $SubName -Resource $kvName `
                    -Finding "Using access policies instead of RBAC" `
                    -Recommendation "Consider migrating to RBAC for better governance"
            }
            
            # Check for keys/secrets/certs expiring
            try {
                $secrets = Get-AzKeyVaultSecret -VaultName $kvName
                foreach ($secret in $secrets) {
                    if ($secret.Expires -and $secret.Expires -lt (Get-Date).AddDays(30)) {
                        Write-Finding -Category "KeyVault" -Severity "MEDIUM" `
                            -Subscription $SubName -Resource "$kvName/$($secret.Name)" `
                            -Finding "Secret expires in less than 30 days" `
                            -Recommendation "Rotate secret before expiration"
                    }
                }
            }
            catch {
                Write-AuditLog "  Unable to access secrets in $kvName (permissions)" -Level "WARNING"
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing Key Vaults: $_" -Level "ERROR"
    }
}

#endregion

#region Security Center/Defender Audit

function Invoke-DefenderAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Microsoft Defender for Cloud for subscription: $SubName" -Level "INFO"
    
    try {
        # Check Defender plans
        $pricings = Get-AzSecurityPricing
        
        $criticalPlans = @("VirtualMachines", "StorageAccounts", "SqlServers", "KeyVaults")
        
        foreach ($plan in $criticalPlans) {
            $pricing = $pricings | Where-Object { $_.Name -eq $plan }
            if ($pricing -and $pricing.PricingTier -eq "Free") {
                Write-Finding -Category "Defender" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "Defender for $plan" `
                    -Finding "Defender for $plan is not enabled (Free tier)" `
                    -Recommendation "Enable Defender for $plan for enhanced protection"
            }
        }
        
        # Check security contacts
        try {
            $contacts = Get-AzSecurityContact
            if (-not $contacts -or $contacts.Count -eq 0) {
                Write-Finding -Category "Defender" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "Security Contacts" `
                    -Finding "No security contacts configured" `
                    -Recommendation "Configure security contacts for alert notifications"
            }
        }
        catch {}
        
        # Check auto-provisioning
        try {
            $autoProvision = Get-AzSecurityAutoProvisioningSetting
            if ($autoProvision.AutoProvision -ne "On") {
                Write-Finding -Category "Defender" -Severity "LOW" `
                    -Subscription $SubName -Resource "Auto-provisioning" `
                    -Finding "Log Analytics agent auto-provisioning is not enabled" `
                    -Recommendation "Enable auto-provisioning for comprehensive coverage"
            }
        }
        catch {}
    }
    catch {
        Write-AuditLog "Error auditing Defender for Cloud: $_" -Level "WARNING"
    }
}

#endregion

#region Policy Compliance Audit

function Invoke-PolicyComplianceAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Policy Compliance for subscription: $SubName" -Level "INFO"
    
    try {
        $policyStates = Get-AzPolicyState -SubscriptionId $SubId -Filter "complianceState eq 'NonCompliant'" -Top 100
        
        $nonCompliantCount = ($policyStates | Measure-Object).Count
        
        if ($nonCompliantCount -gt 0) {
            Write-Finding -Category "Policy" -Severity "MEDIUM" `
                -Subscription $SubName -Resource "Policy Compliance" `
                -Finding "$nonCompliantCount non-compliant policy states" `
                -Recommendation "Review and remediate non-compliant resources"
            
            # Group by policy
            $byPolicy = $policyStates | Group-Object PolicyDefinitionName | Sort-Object Count -Descending | Select-Object -First 5
            foreach ($policy in $byPolicy) {
                Write-AuditLog "  Non-compliant: $($policy.Name) - $($policy.Count) resources" -Level "INFO"
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing policy compliance: $_" -Level "WARNING"
    }
}

#endregion

#region Diagnostic Settings Audit

function Invoke-DiagnosticsAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Diagnostic Settings for subscription: $SubName" -Level "INFO"
    
    try {
        # Check Activity Log export
        $activityLogSettings = Get-AzDiagnosticSetting -ResourceId "/subscriptions/$SubId" -ErrorAction SilentlyContinue
        
        if (-not $activityLogSettings -or $activityLogSettings.Count -eq 0) {
            Write-Finding -Category "Monitoring" -Severity "HIGH" `
                -Subscription $SubName -Resource "Activity Log" `
                -Finding "Activity Log is not exported to Log Analytics or Storage" `
                -Recommendation "Configure Activity Log export for audit trail"
        }
    }
    catch {
        Write-AuditLog "Error auditing diagnostics: $_" -Level "WARNING"
    }
}

#endregion

#region Virtual Machine Audit

function Invoke-VMSecurityAudit {
    param([string]$SubName, [string]$SubId)
    
    Write-AuditLog "Auditing Virtual Machines for subscription: $SubName" -Level "INFO"
    
    try {
        $vms = Get-AzVM -Status
        
        foreach ($vm in $vms) {
            $vmName = $vm.Name
            $rgName = $vm.ResourceGroupName
            
            # Check disk encryption
            $diskEncryption = Get-AzVMDiskEncryptionStatus -ResourceGroupName $rgName -VMName $vmName -ErrorAction SilentlyContinue
            if ($diskEncryption -and $diskEncryption.OsVolumeEncrypted -ne "Encrypted") {
                Write-Finding -Category "VirtualMachines" -Severity "MEDIUM" `
                    -Subscription $SubName -Resource "$rgName/$vmName" `
                    -Finding "OS disk is not encrypted" `
                    -Recommendation "Enable Azure Disk Encryption"
            }
            
            # Check for public IP directly attached
            $nic = Get-AzNetworkInterface | Where-Object { $_.VirtualMachine.Id -eq $vm.Id }
            if ($nic) {
                foreach ($ipConfig in $nic.IpConfigurations) {
                    if ($ipConfig.PublicIpAddress) {
                        Write-Finding -Category "VirtualMachines" -Severity "MEDIUM" `
                            -Subscription $SubName -Resource "$rgName/$vmName" `
                            -Finding "VM has public IP directly attached" `
                            -Recommendation "Consider using Azure Bastion or VPN"
                    }
                }
            }
        }
    }
    catch {
        Write-AuditLog "Error auditing VMs: $_" -Level "WARNING"
    }
}

#endregion

#region Report Generation

function Export-AuditReport {
    Write-AuditLog "Generating audit report..." -Level "INFO"
    
    $endTime = Get-Date
    $duration = $endTime - $script:Config.StartTime
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Security Audit Report</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 15px; }
        h2 { color: #323130; margin-top: 30px; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #d32f2f; }
        .high { background: #f57c00; }
        .medium { background: #fbc02d; color: #333; }
        .low { background: #1976d2; }
        .info { background: #388e3c; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078d4; color: white; }
        tr:hover { background-color: #f5f5f5; }
        .severity-critical { color: #d32f2f; font-weight: bold; }
        .severity-high { color: #f57c00; font-weight: bold; }
        .severity-medium { color: #fbc02d; }
        .severity-low { color: #1976d2; }
        .metadata { color: #666; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>☁️ Azure Security Audit Report</h1>
        <div class="metadata">
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Duration:</strong> $($duration.ToString("hh\:mm\:ss"))</p>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="summary-box">
            <div class="summary-item critical">
                <h3>$($script:Config.CriticalFindings)</h3>
                <p>Critical</p>
            </div>
            <div class="summary-item high">
                <h3>$($script:Config.HighFindings)</h3>
                <p>High</p>
            </div>
            <div class="summary-item medium">
                <h3>$($script:Config.MediumFindings)</h3>
                <p>Medium</p>
            </div>
            <div class="summary-item low">
                <h3>$($script:Config.LowFindings)</h3>
                <p>Low</p>
            </div>
            <div class="summary-item info">
                <h3>$($script:Config.TotalFindings)</h3>
                <p>Total</p>
            </div>
        </div>
        
        <h2>Detailed Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Category</th>
                <th>Subscription</th>
                <th>Resource</th>
                <th>Finding</th>
                <th>Recommendation</th>
            </tr>
"@

    foreach ($finding in ($script:AllFindings | Sort-Object { 
        switch ($_.Severity) { "CRITICAL" { 0 } "HIGH" { 1 } "MEDIUM" { 2 } "LOW" { 3 } }
    })) {
        $severityClass = "severity-$($finding.Severity.ToLower())"
        $html += @"
            <tr>
                <td class="$severityClass">$($finding.Severity)</td>
                <td>$($finding.Category)</td>
                <td>$($finding.Subscription)</td>
                <td>$($finding.Resource)</td>
                <td>$($finding.Finding)</td>
                <td>$($finding.Recommendation)</td>
            </tr>
"@
    }

    $html += @"
        </table>
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666;">
            <p>Generated by Azure-Full-Audit.ps1 v$($script:Config.Version)</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $script:Config.ReportFile -Encoding UTF8
    Write-AuditLog "Report saved to: $($script:Config.ReportFile)" -Level "SUCCESS"
    
    if ($ExportToCSV) {
        $csvPath = $script:Config.ReportFile -replace "\.html$", ".csv"
        $script:AllFindings | Export-Csv -Path $csvPath -NoTypeInformation
        Write-AuditLog "CSV saved to: $csvPath" -Level "SUCCESS"
    }
}

#endregion

#region Main Execution

function Invoke-AzureSecurityAudit {
    Write-AuditLog "=" * 60 -Level "INFO"
    Write-AuditLog "AZURE COMPREHENSIVE SECURITY AUDIT" -Level "INFO"
    Write-AuditLog "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
    
    if (-not (Test-AzModules)) { return }
    if (-not (Initialize-AzureConnection)) { return }
    
    $subscriptions = Get-SubscriptionsToAudit
    
    foreach ($sub in $subscriptions) {
        Write-AuditLog "" -Level "INFO"
        Write-AuditLog "=" * 40 -Level "INFO"
        Write-AuditLog "Subscription: $($sub.Name) ($($sub.Id))" -Level "INFO"
        Write-AuditLog "=" * 40 -Level "INFO"
        
        Set-AzContext -SubscriptionId $sub.Id -WarningAction SilentlyContinue | Out-Null
        
        Invoke-RBACaudit -SubName $sub.Name -SubId $sub.Id
        Invoke-NetworkSecurityAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-StorageSecurityAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-KeyVaultAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-DefenderAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-PolicyComplianceAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-DiagnosticsAudit -SubName $sub.Name -SubId $sub.Id
        Invoke-VMSecurityAudit -SubName $sub.Name -SubId $sub.Id
    }
    
    Export-AuditReport
    
    Write-AuditLog "" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
    Write-AuditLog "AUDIT COMPLETE" -Level "SUCCESS"
    Write-AuditLog "Total Findings: $($script:Config.TotalFindings)" -Level "INFO"
    Write-AuditLog "=" * 60 -Level "INFO"
}

Invoke-AzureSecurityAudit

#endregion
