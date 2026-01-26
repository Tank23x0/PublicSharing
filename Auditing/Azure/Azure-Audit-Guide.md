# Azure Security Audit Guide

## Overview

Comprehensive guide for auditing Azure environments including RBAC, network security, storage, Key Vault, Defender for Cloud, and compliance.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [RBAC Audit](#rbac-audit)
3. [Network Security](#network-security)
4. [Storage Account Security](#storage-account-security)
5. [Key Vault Audit](#key-vault-audit)
6. [Microsoft Defender for Cloud](#microsoft-defender-for-cloud)
7. [Virtual Machine Security](#virtual-machine-security)
8. [Diagnostic Settings](#diagnostic-settings)
9. [Policy Compliance](#policy-compliance)
10. [Azure CLI Commands](#azure-cli-commands)
11. [REST API Reference](#rest-api-reference)
12. [Compliance Mapping](#compliance-mapping)
13. [Resources](#resources)

---

## Prerequisites

### Install Azure PowerShell

```powershell
# Install Az module
Install-Module -Name Az -AllowClobber -Scope CurrentUser

# Or install specific modules
Install-Module -Name Az.Accounts, Az.Resources, Az.Security, Az.Storage, Az.Network, Az.KeyVault

# Connect
Connect-AzAccount
```

### Install Azure CLI

```bash
# macOS
brew install azure-cli

# Linux
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Login
az login
```

### Required Permissions

- **Reader** - View resources
- **Security Reader** - View security settings
- **Key Vault Reader** - View Key Vault metadata
- **Storage Account Key Operator** - Access storage diagnostics

---

## RBAC Audit

### PowerShell Commands

```powershell
# List all role assignments in subscription
Get-AzRoleAssignment | Select-Object DisplayName, RoleDefinitionName, Scope, ObjectType

# Find all Owners
Get-AzRoleAssignment -RoleDefinitionName "Owner" | 
    Select-Object DisplayName, Scope, ObjectType

# Find subscription-level privileged roles
$subId = (Get-AzContext).Subscription.Id
Get-AzRoleAssignment -Scope "/subscriptions/$subId" | 
    Where-Object {$_.RoleDefinitionName -in @("Owner", "Contributor", "User Access Administrator")}

# Find orphaned assignments (deleted principals)
Get-AzRoleAssignment | Where-Object {$_.ObjectType -eq "Unknown"}

# List custom roles
Get-AzRoleDefinition -Custom | Select-Object Name, Description, AssignableScopes

# Get role definition details
Get-AzRoleDefinition -Name "Contributor" | Select-Object -ExpandProperty Actions
```

### Azure CLI Commands

```bash
# List all role assignments
az role assignment list --all --output table

# List Owners
az role assignment list --role "Owner" --all --output table

# Find assignments for specific user
az role assignment list --assignee user@domain.com --all --output table

# List custom role definitions
az role definition list --custom-role-only true --output table
```

### Manual Steps (Portal)

1. Navigate to **Subscriptions** → Select subscription
2. Click **Access control (IAM)**
3. Click **Role assignments** tab
4. Review and filter by role type
5. Export using **Download** button

---

## Network Security

### Network Security Groups

```powershell
# List all NSGs
Get-AzNetworkSecurityGroup | Select-Object Name, ResourceGroupName

# Get NSG rules allowing internet access
Get-AzNetworkSecurityGroup | ForEach-Object {
    $nsg = $_
    $_.SecurityRules | Where-Object {
        $_.Direction -eq "Inbound" -and 
        $_.Access -eq "Allow" -and 
        $_.SourceAddressPrefix -in @("*", "0.0.0.0/0", "Internet")
    } | Select-Object @{N='NSG';E={$nsg.Name}}, Name, DestinationPortRange, SourceAddressPrefix
}

# Find NSGs with RDP/SSH open to internet
Get-AzNetworkSecurityGroup | ForEach-Object {
    $_.SecurityRules | Where-Object {
        $_.Direction -eq "Inbound" -and 
        $_.Access -eq "Allow" -and 
        $_.DestinationPortRange -in @("22", "3389", "*") -and
        $_.SourceAddressPrefix -in @("*", "0.0.0.0/0", "Internet")
    }
}
```

### Azure CLI

```bash
# List NSGs
az network nsg list --output table

# Show NSG rules
az network nsg rule list --nsg-name NSG-NAME --resource-group RG-NAME --output table

# Find public IPs
az network public-ip list --output table
```

### Manual Steps (Portal)

1. Navigate to **Network security groups**
2. Select NSG → **Inbound security rules**
3. Look for rules with Source = "Any" or "Internet"
4. Check destination ports for sensitive services

---

## Storage Account Security

### PowerShell Commands

```powershell
# List all storage accounts with security settings
Get-AzStorageAccount | Select-Object StorageAccountName, ResourceGroupName, 
    EnableHttpsTrafficOnly, AllowBlobPublicAccess, MinimumTlsVersion,
    @{N='NetworkDefault';E={$_.NetworkRuleSet.DefaultAction}}

# Find storage accounts with public blob access
Get-AzStorageAccount | Where-Object {$_.AllowBlobPublicAccess -eq $true}

# Find storage accounts accessible from all networks
Get-AzStorageAccount | Where-Object {$_.NetworkRuleSet.DefaultAction -eq "Allow"}

# Check if HTTPS only enforced
Get-AzStorageAccount | Where-Object {$_.EnableHttpsTrafficOnly -ne $true}

# List blob containers and their access level
$ctx = (Get-AzStorageAccount -ResourceGroupName "RG" -Name "StorageAccountName").Context
Get-AzStorageContainer -Context $ctx | Select-Object Name, PublicAccess
```

### Azure CLI

```bash
# List storage accounts
az storage account list --query "[].{name:name,httpsOnly:enableHttpsTrafficOnly,publicAccess:allowBlobPublicAccess}" --output table

# Check specific storage account
az storage account show --name STORAGE_NAME --resource-group RG_NAME --query "{https:enableHttpsTrafficOnly,publicBlob:allowBlobPublicAccess,tls:minimumTlsVersion,network:networkRuleSet.defaultAction}"

# List containers with public access
az storage container list --account-name STORAGE_NAME --auth-mode login --query "[?properties.publicAccess!='None'].{name:name,access:properties.publicAccess}"
```

### Security Checklist

- [ ] HTTPS-only traffic enforced
- [ ] Blob public access disabled
- [ ] Minimum TLS version 1.2
- [ ] Firewall configured (not Allow All)
- [ ] Soft delete enabled
- [ ] Versioning enabled
- [ ] Encryption with customer-managed keys (for sensitive data)

---

## Key Vault Audit

### PowerShell Commands

```powershell
# List all Key Vaults
Get-AzKeyVault | Select-Object VaultName, ResourceGroupName

# Get Key Vault details
Get-AzKeyVault -VaultName "VaultName" | Select-Object VaultName, 
    EnableSoftDelete, EnablePurgeProtection, EnableRbacAuthorization,
    @{N='NetworkDefault';E={$_.NetworkAcls.DefaultAction}}

# Find Key Vaults without soft delete
Get-AzKeyVault | ForEach-Object {
    $kv = Get-AzKeyVault -VaultName $_.VaultName
    if (-not $kv.EnableSoftDelete) { $kv.VaultName }
}

# List secrets expiring soon
$secrets = Get-AzKeyVaultSecret -VaultName "VaultName"
$secrets | Where-Object {$_.Expires -and $_.Expires -lt (Get-Date).AddDays(30)} |
    Select-Object Name, Expires

# List access policies
(Get-AzKeyVault -VaultName "VaultName").AccessPolicies | 
    Select-Object DisplayName, PermissionsToSecrets, PermissionsToKeys
```

### Azure CLI

```bash
# List Key Vaults
az keyvault list --output table

# Show Key Vault details
az keyvault show --name VAULT_NAME --query "{softDelete:properties.enableSoftDelete,purgeProtection:properties.enablePurgeProtection,rbac:properties.enableRbacAuthorization}"

# List secrets
az keyvault secret list --vault-name VAULT_NAME --output table

# Show secret expiry
az keyvault secret show --vault-name VAULT_NAME --name SECRET_NAME --query "{expires:attributes.expires}"
```

---

## Microsoft Defender for Cloud

### PowerShell Commands

```powershell
# Check Defender pricing tiers
Get-AzSecurityPricing | Select-Object Name, PricingTier

# Get security recommendations
Get-AzSecurityTask | Select-Object Name, RecommendationType, State

# Get security alerts
Get-AzSecurityAlert | Select-Object AlertName, Severity, Status

# Check auto-provisioning
Get-AzSecurityAutoProvisioningSetting

# Get secure score
Get-AzSecuritySecureScore
```

### Azure CLI

```bash
# Check pricing tiers
az security pricing list --output table

# Get recommendations
az security task list --output table

# Get alerts
az security alert list --output table
```

### Manual Steps (Portal)

1. Navigate to **Microsoft Defender for Cloud**
2. Check **Environment settings** → Subscription → **Defender plans**
3. Review **Recommendations** for findings
4. Check **Regulatory compliance** dashboard
5. Review **Security alerts**

---

## Virtual Machine Security

### PowerShell Commands

```powershell
# List VMs with security info
Get-AzVM -Status | Select-Object Name, ResourceGroupName, 
    @{N='OS';E={$_.StorageProfile.OsDisk.OsType}},
    @{N='PowerState';E={$_.PowerState}}

# Check disk encryption status
Get-AzVM | ForEach-Object {
    $status = Get-AzVMDiskEncryptionStatus -ResourceGroupName $_.ResourceGroupName -VMName $_.Name -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        VM = $_.Name
        OsDiskEncrypted = $status.OsVolumeEncrypted
        DataDisksEncrypted = $status.DataVolumesEncrypted
    }
}

# Find VMs with public IPs
Get-AzVM | ForEach-Object {
    $vm = $_
    $nic = Get-AzNetworkInterface | Where-Object {$_.VirtualMachine.Id -eq $vm.Id}
    if ($nic.IpConfigurations.PublicIpAddress) {
        [PSCustomObject]@{VM=$vm.Name; HasPublicIP=$true}
    }
}

# Check Just-in-Time access
Get-AzJitNetworkAccessPolicy
```

### Security Checklist

- [ ] Azure Disk Encryption enabled
- [ ] No direct public IP (use Bastion)
- [ ] Just-in-Time VM access enabled
- [ ] Anti-malware extension installed
- [ ] Log Analytics agent installed
- [ ] Auto-shutdown configured (dev/test)

---

## Diagnostic Settings

### PowerShell Commands

```powershell
# Check Activity Log export
$subId = (Get-AzContext).Subscription.Id
Get-AzDiagnosticSetting -ResourceId "/subscriptions/$subId"

# List all diagnostic settings for resources
Get-AzResource | ForEach-Object {
    $settings = Get-AzDiagnosticSetting -ResourceId $_.ResourceId -ErrorAction SilentlyContinue
    if ($settings) {
        [PSCustomObject]@{Resource=$_.Name; DiagnosticsConfigured=$true}
    }
}

# Create Activity Log diagnostic setting
$workspaceId = "/subscriptions/xxx/resourcegroups/xxx/providers/microsoft.operationalinsights/workspaces/xxx"
Set-AzDiagnosticSetting -ResourceId "/subscriptions/$subId" -Name "ActivityLogExport" -WorkspaceId $workspaceId -Enabled $true
```

### Azure CLI

```bash
# Check Activity Log export
az monitor diagnostic-settings subscription list

# Create diagnostic setting
az monitor diagnostic-settings subscription create --name "ExportToLA" --workspace /subscriptions/.../workspaces/xxx --logs '[{"category":"Administrative","enabled":true}]'
```

---

## Policy Compliance

### PowerShell Commands

```powershell
# Get non-compliant policy states
Get-AzPolicyState -Filter "complianceState eq 'NonCompliant'" | 
    Select-Object PolicyDefinitionName, ResourceId, ComplianceState

# Get policy compliance summary
Get-AzPolicyStateSummary

# List policy assignments
Get-AzPolicyAssignment | Select-Object Name, DisplayName, Scope

# Get specific policy definition
Get-AzPolicyDefinition -Name "policy-definition-name"
```

### Azure CLI

```bash
# Get compliance summary
az policy state summarize

# List non-compliant resources
az policy state list --filter "complianceState eq 'NonCompliant'" --output table

# List policy assignments
az policy assignment list --output table
```

---

## Azure CLI Commands

### Quick Reference

```bash
# Account and subscription
az account show
az account list --output table
az account set --subscription "Subscription Name"

# Resources
az resource list --output table
az resource show --ids RESOURCE_ID

# RBAC
az role assignment list --all
az role definition list

# Network
az network nsg list
az network public-ip list

# Storage
az storage account list
az storage container list --account-name NAME

# Key Vault
az keyvault list
az keyvault secret list --vault-name NAME

# Security
az security pricing list
az security alert list
az security task list

# Policy
az policy state summarize
az policy assignment list
```

---

## REST API Reference

### Key Endpoints

| Operation | API Endpoint |
|-----------|--------------|
| List Subscriptions | GET /subscriptions |
| List Role Assignments | GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments |
| List NSGs | GET /subscriptions/{sub}/providers/Microsoft.Network/networkSecurityGroups |
| List Storage Accounts | GET /subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts |
| List Key Vaults | GET /subscriptions/{sub}/providers/Microsoft.KeyVault/vaults |
| Security Pricings | GET /subscriptions/{sub}/providers/Microsoft.Security/pricings |
| Policy States | POST /subscriptions/{sub}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults |

### Example API Call

```bash
# Get access token
token=$(az account get-access-token --query accessToken -o tsv)

# Call API
curl -H "Authorization: Bearer $token" \
    "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
```

---

## Compliance Mapping

### SOC 2

| Control | Azure Feature |
|---------|---------------|
| CC6.1 - Logical Access | RBAC, Azure AD |
| CC6.2 - Access Authorization | Role assignments |
| CC6.3 - Access Removal | RBAC cleanup |
| CC7.1 - Security Events | Activity Log, Defender |
| CC7.2 - Monitoring | Azure Monitor, Log Analytics |

### ISO 27001

| Control | Azure Feature |
|---------|---------------|
| A.9.2.3 - Privileged Access | RBAC, PIM |
| A.12.4.1 - Event Logging | Activity Log |
| A.13.1.1 - Network Controls | NSG, Firewall |
| A.14.1.2 - Secure Development | Defender for Cloud |

### CIS Azure Benchmark

Key controls covered:
- 1.x - Identity and Access Management
- 2.x - Microsoft Defender for Cloud
- 3.x - Storage Accounts
- 4.x - Database Services
- 5.x - Logging and Monitoring
- 6.x - Networking
- 7.x - Virtual Machines
- 8.x - Key Vault

---

## Resources

### Official Documentation

- [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/best-practices-and-patterns)
- [Azure RBAC Documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/)
- [Microsoft Defender for Cloud](https://docs.microsoft.com/en-us/azure/defender-for-cloud/)
- [Azure Policy](https://docs.microsoft.com/en-us/azure/governance/policy/)
- [Azure Security Benchmark](https://docs.microsoft.com/en-us/security/benchmark/azure/)

### Microsoft Tech Community

- [Azure Security Blog](https://techcommunity.microsoft.com/t5/azure-security-center/bg-p/AzureSecurityCenterBlog)
- [Microsoft Defender for Cloud Blog](https://techcommunity.microsoft.com/t5/microsoft-defender-for-cloud/bg-p/MicrosoftDefenderCloudBlog)

### Tools

- [Azure Resource Graph Explorer](https://portal.azure.com/#blade/HubsExtension/ArgQueryBlade)
- [Microsoft Secure Score](https://security.microsoft.com/securescore)
- [Azure Advisor](https://portal.azure.com/#blade/Microsoft_Azure_Expert/AdvisorMenuBlade)

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
