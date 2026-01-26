# Jamf Pro Security Audit Guide

## Overview

Comprehensive guide for auditing Jamf Pro deployments including device management, security configurations, FileVault compliance, and access controls.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Computer Inventory Audit](#computer-inventory-audit)
3. [Mobile Device Audit](#mobile-device-audit)
4. [FileVault Compliance](#filevault-compliance)
5. [Configuration Profiles](#configuration-profiles)
6. [Policy Audit](#policy-audit)
7. [Admin User Audit](#admin-user-audit)
8. [Smart Groups Review](#smart-groups-review)
9. [Software Updates](#software-updates)
10. [API Reference](#api-reference)
11. [Compliance Mapping](#compliance-mapping)
12. [Resources](#resources)

---

## Prerequisites

### API Access

1. Log into Jamf Pro as admin
2. Navigate to **Settings** → **System** → **API Integrations**
3. Create API client with required permissions
4. Or use username/password with appropriate privileges

### Required Permissions

- Computers: Read
- Mobile Devices: Read
- Configuration Profiles: Read
- Policies: Read
- User Accounts and Groups: Read
- Smart Groups: Read

---

## Computer Inventory Audit

### API Queries

```bash
# Get all computers (Classic API)
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computers" \
    -H "Accept: application/json"

# Get specific computer details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computers/id/1" \
    -H "Accept: application/json"

# Jamf Pro API (newer)
# First get token
TOKEN=$(curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/api/v1/auth/token" \
    -X POST | jq -r '.token')

# Get computers
curl -s -H "Authorization: Bearer $TOKEN" \
    "https://yourcompany.jamfcloud.com/api/v1/computers-inventory"
```

### Key Fields to Review

| Field | Purpose |
|-------|---------|
| last_contact_time | Identify stale devices |
| os_version | OS currency |
| filevault2_status | Encryption status |
| gatekeeper_status | Security status |
| sip_status | System Integrity Protection |
| firewall_enabled | Firewall status |
| remote_management | Management status |

### Manual Steps (Console)

1. Navigate to **Computers** → **Inventory**
2. Create Smart Group for:
   - Last Contact > 30 days
   - FileVault not enabled
   - Outdated macOS
3. Review and take action

### Stale Device Query

```bash
# Find computers not seen in 30+ days
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/advancedcomputersearches/id/1" \
    -H "Accept: application/json"
```

---

## Mobile Device Audit

### API Queries

```bash
# Get all mobile devices
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/mobiledevices" \
    -H "Accept: application/json"

# Get device details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/mobiledevices/id/1" \
    -H "Accept: application/json"
```

### Key Mobile Security Checks

- [ ] Passcode enabled
- [ ] Passcode complexity met
- [ ] Device encryption enabled
- [ ] Managed apps policy
- [ ] Lost mode capability
- [ ] Remote wipe capability

---

## FileVault Compliance

### API Queries

```bash
# Get FileVault status from computer details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computers/id/1" \
    -H "Accept: application/json" | jq '.computer.hardware.filevault2_status'
```

### Smart Group for Non-Compliant

Create Smart Group with criteria:
- FileVault 2 Status: **is not** "Encrypted"
- Operating System: **like** "macOS"

### Manual Steps

1. Navigate to **Computers** → **Smart Computer Groups**
2. Create group: "FileVault Not Enabled"
3. Criteria: FileVault 2 Status is not "Encrypted"
4. Review membership regularly

### FileVault Recovery Key

```bash
# Get FileVault recovery key (if escrowed)
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computers/id/1" \
    -H "Accept: application/json" | jq '.computer.hardware.filevault2_recovery_key'
```

---

## Configuration Profiles

### API Queries

```bash
# List all macOS configuration profiles
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/osxconfigurationprofiles" \
    -H "Accept: application/json"

# Get profile details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/osxconfigurationprofiles/id/1" \
    -H "Accept: application/json"

# List mobile config profiles
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/mobiledeviceconfigurationprofiles" \
    -H "Accept: application/json"
```

### Security Profiles Checklist

| Profile Type | Purpose |
|--------------|---------|
| Passcode | Enforce password requirements |
| FileVault | Enable disk encryption |
| Firewall | Enable macOS firewall |
| Gatekeeper | App installation policy |
| Privacy Preferences | Control app permissions |
| Kernel Extensions | Allowed kexts |
| System Extensions | Allowed extensions |
| Software Updates | Configure auto-updates |

### Manual Steps

1. Navigate to **Computers** → **Configuration Profiles**
2. Review each profile's scope
3. Verify security profiles are scoped to all managed computers
4. Check for conflicting profiles

---

## Policy Audit

### API Queries

```bash
# List all policies
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/policies" \
    -H "Accept: application/json"

# Get policy details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/policies/id/1" \
    -H "Accept: application/json"
```

### Policy Review Checklist

- [ ] FileVault enforcement policy exists
- [ ] Software update policy configured
- [ ] Antivirus/EDR deployment policy
- [ ] Security baseline policies
- [ ] No policies running as root unnecessarily
- [ ] Proper scoping (not "All Computers" unless needed)

### Manual Steps

1. Navigate to **Computers** → **Policies**
2. Review enabled vs. disabled policies
3. Check execution frequency
4. Review scope for each policy
5. Verify security policies are properly scoped

---

## Admin User Audit

### API Queries

```bash
# List all admin accounts
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/accounts" \
    -H "Accept: application/json"

# Get user details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/accounts/userid/1" \
    -H "Accept: application/json"

# List groups
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/accounts/groupid/1" \
    -H "Accept: application/json"
```

### Access Level Types

| Level | Description |
|-------|-------------|
| Full Access | Complete admin access |
| Site Access | Limited to specific site |
| Group Access | Limited by LDAP group |
| Custom | Specific privileges |

### Manual Steps

1. Navigate to **Settings** → **System** → **User Accounts and Groups**
2. Review each user's access level
3. Verify SSO/LDAP integration
4. Check for stale/inactive accounts
5. Ensure MFA is enabled (if supported)

---

## Smart Groups Review

### API Queries

```bash
# List computer smart groups
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computergroups" \
    -H "Accept: application/json"

# Get smart group details
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computergroups/id/1" \
    -H "Accept: application/json"
```

### Recommended Security Smart Groups

1. **FileVault Not Encrypted**
   - Criteria: FileVault 2 Status is not "Encrypted"

2. **Outdated macOS**
   - Criteria: Operating System Version is less than "14.0"

3. **Stale Devices**
   - Criteria: Last Check-in more than 30 days ago

4. **No EDR Agent**
   - Criteria: Application Title is not "CrowdStrike Falcon"

5. **SIP Disabled**
   - Criteria: System Integrity Protection is "Disabled"

---

## Software Updates

### API Queries

```bash
# Get available updates for computer
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/JSSResource/computers/id/1" \
    -H "Accept: application/json" | jq '.computer.software.available_software_updates'
```

### Update Policy Best Practices

- [ ] Automatic updates enabled
- [ ] Critical updates enforced
- [ ] Update deferral period defined
- [ ] Deadline for installation set
- [ ] User notification configured

---

## API Reference

### Classic API Endpoints

| Resource | Endpoint |
|----------|----------|
| Computers | /JSSResource/computers |
| Mobile Devices | /JSSResource/mobiledevices |
| Config Profiles | /JSSResource/osxconfigurationprofiles |
| Policies | /JSSResource/policies |
| Accounts | /JSSResource/accounts |
| Smart Groups | /JSSResource/computergroups |

### Jamf Pro API Endpoints (v1)

| Resource | Endpoint |
|----------|----------|
| Auth Token | /api/v1/auth/token |
| Computers | /api/v1/computers-inventory |
| Mobile Devices | /api/v1/mobile-devices |

### Authentication

```bash
# Get Bearer Token
curl -s -u "username:password" \
    "https://yourcompany.jamfcloud.com/api/v1/auth/token" \
    -X POST

# Use Token
curl -s -H "Authorization: Bearer TOKEN" \
    "https://yourcompany.jamfcloud.com/api/v1/computers-inventory"
```

---

## Compliance Mapping

### SOC 2

| Control | Jamf Feature |
|---------|--------------|
| CC6.6 - Endpoint Security | MDM, Config Profiles |
| CC6.7 - Malware Protection | EDR deployment policies |
| CC6.8 - Change Detection | Extension Attributes |
| CC7.2 - Monitoring | Smart Groups, Reports |

### CIS macOS Benchmark

Jamf can enforce:
- Gatekeeper enabled
- Firewall enabled
- FileVault enabled
- SIP enabled
- Remote management disabled (or controlled)
- Password policy requirements
- Automatic updates

---

## Resources

### Official Documentation

- [Jamf Pro Administrator's Guide](https://docs.jamf.com/jamf-pro/)
- [Jamf Pro API Reference](https://developer.jamf.com/jamf-pro/reference)
- [Jamf Nation Community](https://community.jamf.com/)

### Tools

- [AutoPkg](https://github.com/autopkg/autopkg) - Automated packaging
- [Jamf Migrator](https://github.com/jamf/JamfMigrator) - Configuration migration

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
