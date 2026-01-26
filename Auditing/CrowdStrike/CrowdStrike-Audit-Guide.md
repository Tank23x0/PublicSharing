# CrowdStrike Falcon Security Audit Guide

## Overview

Comprehensive guide for auditing CrowdStrike Falcon deployments including sensor coverage, detection response, policy compliance, and user access.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Sensor Deployment Audit](#sensor-deployment-audit)
3. [Detection and Incident Audit](#detection-and-incident-audit)
4. [Prevention Policy Audit](#prevention-policy-audit)
5. [User and Role Audit](#user-and-role-audit)
6. [API Key Management](#api-key-management)
7. [Response Action Audit](#response-action-audit)
8. [Exclusion Review](#exclusion-review)
9. [API Reference](#api-reference)
10. [Compliance Mapping](#compliance-mapping)
11. [Resources](#resources)

---

## Prerequisites

### API Credentials

1. Log into Falcon Console
2. Navigate to **Support** → **API Clients and Keys**
3. Click **Add new API client**
4. Grant required scopes:
   - Hosts: Read
   - Detections: Read
   - Prevention Policies: Read
   - Response Policies: Read
   - User Management: Read
   - Sensor Download: Read

### PSFalcon Module (Recommended)

```powershell
# Install PSFalcon
Install-Module -Name PSFalcon -Scope CurrentUser

# Import and authenticate
Import-Module PSFalcon
Request-FalconToken -ClientId "YOUR_CLIENT_ID" -ClientSecret "YOUR_CLIENT_SECRET" -Cloud "us-1"

# Verify connection
Test-FalconToken
```

### Cloud URLs

| Cloud | Base URL |
|-------|----------|
| US-1 | api.crowdstrike.com |
| US-2 | api.us-2.crowdstrike.com |
| EU-1 | api.eu-1.crowdstrike.com |
| US-GOV-1 | api.laggar.gcw.crowdstrike.com |

---

## Sensor Deployment Audit

### PSFalcon Commands

```powershell
# Get all hosts
$hosts = Get-FalconHost -All

# Get host details
Get-FalconHost -Id $hosts[0..99] | 
    Select-Object hostname, status, last_seen, platform_name, os_version, 
    agent_version, prevention_policy_applied

# Find offline hosts
Get-FalconHost -All -Filter "status:'offline'" |
    Select-Object hostname, last_seen

# Find hosts not seen in 14+ days
$threshold = (Get-Date).AddDays(-14).ToString("yyyy-MM-ddT00:00:00Z")
Get-FalconHost -All -Filter "last_seen:<='$threshold'" |
    Select-Object hostname, last_seen, platform_name

# Find hosts in reduced functionality mode
Get-FalconHost -All -Filter "reduced_functionality_mode:'yes'" |
    Select-Object hostname, reduced_functionality_mode

# Get sensor versions
Get-FalconHost -All | Group-Object agent_version | 
    Select-Object Name, Count | Sort-Object Count -Descending

# Find hosts without prevention policy
Get-FalconHost -All | Where-Object { -not $_.prevention_policy_applied }
```

### API Queries

```bash
# Get host IDs
curl -X GET "https://api.crowdstrike.com/devices/queries/devices/v1?limit=100" \
    -H "Authorization: Bearer $TOKEN"

# Get host details
curl -X POST "https://api.crowdstrike.com/devices/entities/devices/v2" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ids": ["host_id_1", "host_id_2"]}'

# Filter hosts by last seen
curl -X GET "https://api.crowdstrike.com/devices/queries/devices/v1?filter=last_seen:<='2024-01-01T00:00:00Z'" \
    -H "Authorization: Bearer $TOKEN"
```

### Manual Steps (Console)

1. Navigate to **Hosts** → **Host Management**
2. Click **Columns** to add: Status, Last Seen, Prevention Policy, Sensor Version
3. Filter by **Status = Offline** to find disconnected hosts
4. Sort by **Last Seen** to find stale hosts
5. Export using **Export** button

### Key Metrics to Track

- Total hosts enrolled
- Sensors online vs offline percentage
- Sensor version distribution
- Hosts without prevention policies
- Hosts in reduced functionality mode

---

## Detection and Incident Audit

### PSFalcon Commands

```powershell
# Get recent detections
$thirtyDaysAgo = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddT00:00:00Z")
$detections = Get-FalconDetection -Filter "first_behavior:>='$thirtyDaysAgo'"

# Get detection details
Get-FalconDetection -Id $detections[0..49] | 
    Select-Object detection_id, device_id, max_severity_displayname, 
    status, first_behavior, last_behavior

# Find critical/high detections
Get-FalconDetection -Filter "max_severity:>=4" |
    Select-Object detection_id, max_severity_displayname, status

# Find unreviewed detections
Get-FalconDetection -Filter "status:'new'" |
    Select-Object detection_id, device_id, max_severity_displayname

# Get detection counts by severity
Get-FalconDetection -Filter "first_behavior:>='$thirtyDaysAgo'" |
    Group-Object max_severity_displayname | Select-Object Name, Count

# Get incidents
Get-FalconIncident -Filter "start_time:>='$thirtyDaysAgo'" |
    Select-Object incident_id, state, fine_score, host_ids
```

### API Queries

```bash
# Get detection IDs
curl -X GET "https://api.crowdstrike.com/detects/queries/detects/v1?filter=first_behavior:>='2024-01-01'" \
    -H "Authorization: Bearer $TOKEN"

# Get detection details
curl -X POST "https://api.crowdstrike.com/detects/entities/summaries/GET/v1" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"ids": ["detection_id_1", "detection_id_2"]}'
```

### Manual Steps (Console)

1. Navigate to **Activity** → **Detections**
2. Filter by severity, status, time range
3. Review critical/high severity detections
4. Check for detections in "New" status (unreviewed)
5. Navigate to **Incidents** for correlated events

### Detection Status Workflow

| Status | Description | Action |
|--------|-------------|--------|
| New | Unreviewed detection | Requires triage |
| In Progress | Being investigated | Continue investigation |
| True Positive | Confirmed threat | Remediate |
| False Positive | Not a threat | Create exclusion if needed |
| Ignored | Intentionally ignored | Document reason |

---

## Prevention Policy Audit

### PSFalcon Commands

```powershell
# Get all prevention policies
Get-FalconPreventionPolicy -All | 
    Select-Object name, id, enabled, platform_name

# Get policy details
Get-FalconPreventionPolicy -Id "policy_id" -Detailed

# Get hosts assigned to policy
Get-FalconPreventionPolicyMember -Id "policy_id"

# Find disabled policies
Get-FalconPreventionPolicy -All | Where-Object { -not $_.enabled }

# Get policy settings
Get-FalconPreventionPolicy -Id "policy_id" | 
    Select-Object -ExpandProperty prevention_settings
```

### Key Policy Settings to Verify

| Setting | Recommended | Description |
|---------|-------------|-------------|
| Malware Protection | Enabled | AV-style malware prevention |
| Sensor ML | Aggressive | Machine learning detection |
| Cloud ML | Aggressive | Cloud-based ML analysis |
| Execution Blocking | Enabled | Block malicious executables |
| Exploit Mitigation | Enabled | Prevent exploit techniques |
| Script Control | Enabled/Audit | Monitor/block scripts |
| Sensor Tamper Protection | Enabled | Prevent sensor tampering |

### Manual Steps (Console)

1. Navigate to **Configuration** → **Prevention Policies**
2. Review each policy's settings
3. Check "Detection Only" vs "Prevention" mode
4. Verify production workloads have prevention enabled
5. Review policy assignments

---

## User and Role Audit

### PSFalcon Commands

```powershell
# Get all users
Get-FalconUser -All | Select-Object uuid, uid, first_name, last_name

# Get user details
Get-FalconUser -Id "user_uuid" | Select-Object uid, roles, created_at

# Get user roles
Get-FalconRole

# Find users with admin roles
Get-FalconUser -All | Where-Object { $_.roles -match "Admin" }
```

### API Queries

```bash
# Get user UUIDs
curl -X GET "https://api.crowdstrike.com/users/queries/user-uuids-by-cid/v1" \
    -H "Authorization: Bearer $TOKEN"

# Get user details
curl -X GET "https://api.crowdstrike.com/users/entities/users/v1?ids=user_uuid" \
    -H "Authorization: Bearer $TOKEN"

# Get available roles
curl -X GET "https://api.crowdstrike.com/user-management/queries/roles/v1" \
    -H "Authorization: Bearer $TOKEN"
```

### Manual Steps (Console)

1. Navigate to **Users** → **User Management**
2. Review each user's role assignments
3. Check for inactive users (sort by last login)
4. Verify MFA is enabled (SSO settings)
5. Review API client permissions

### Role Best Practices

- Limit Falcon Administrator role
- Use role-based access (Analyst, Response, Read-only)
- Regular access reviews
- Remove inactive users
- Enforce SSO/MFA

---

## API Key Management

### Manual Steps (Console)

1. Navigate to **Support** → **API Clients and Keys**
2. Review all API clients
3. Check scope permissions (minimize as needed)
4. Verify client descriptions are meaningful
5. Remove unused API clients

### API Audit Checklist

- [ ] All API clients have descriptions
- [ ] No clients have excessive scopes
- [ ] Unused clients are removed
- [ ] Client secrets are rotated periodically
- [ ] API usage is monitored

---

## Response Action Audit

### PSFalcon Commands

```powershell
# Get RTR sessions
Get-FalconRTRSession -All

# Get RTR commands executed
Get-FalconRTRCloudScripts

# Get containment status
Get-FalconHost -Filter "status:'containment_pending'+status:'contained'" |
    Select-Object hostname, status
```

### Manual Steps (Console)

1. Navigate to **Activity** → **Response Actions**
2. Review Real-Time Response sessions
3. Check containment actions
4. Review network isolation events
5. Audit file remediation actions

---

## Exclusion Review

### PSFalcon Commands

```powershell
# Get ML exclusions
Get-FalconMLExclusion -All

# Get IOA exclusions
Get-FalconIOAExclusion -All

# Get sensor visibility exclusions
Get-FalconSVExclusion -All
```

### Manual Steps (Console)

1. Navigate to **Configuration** → **Exclusions**
2. Review ML Exclusions (file hash, path, certificate)
3. Review IOA Exclusions (behavior-based)
4. Review Sensor Visibility Exclusions
5. Validate each exclusion has business justification

### Exclusion Best Practices

- Document justification for each exclusion
- Set expiration dates where possible
- Review exclusions quarterly
- Avoid broad path exclusions
- Never exclude security tools from monitoring

---

## API Reference

### Key Endpoints

| Operation | Endpoint | Method |
|-----------|----------|--------|
| Get Hosts | /devices/queries/devices/v1 | GET |
| Host Details | /devices/entities/devices/v2 | POST |
| Get Detections | /detects/queries/detects/v1 | GET |
| Detection Details | /detects/entities/summaries/GET/v1 | POST |
| Prevention Policies | /policy/queries/prevention/v1 | GET |
| Policy Details | /policy/entities/prevention/v1 | GET |
| Users | /users/queries/user-uuids-by-cid/v1 | GET |
| User Details | /users/entities/users/v1 | GET |
| Incidents | /incidents/queries/incidents/v1 | GET |

### Authentication

```bash
# Get OAuth2 token
curl -X POST "https://api.crowdstrike.com/oauth2/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=CLIENT_ID&client_secret=CLIENT_SECRET"
```

---

## Compliance Mapping

### SOC 2

| Control | CrowdStrike Feature |
|---------|---------------------|
| CC6.1 - Logical Access | User management, roles |
| CC6.6 - Threat Detection | Detection, prevention |
| CC6.8 - Malware Prevention | Prevention policies |
| CC7.2 - Security Monitoring | Real-time monitoring |
| CC7.3 - Incident Response | RTR, containment |

### NIST Cybersecurity Framework

| Function | CrowdStrike Feature |
|----------|---------------------|
| Identify | Asset inventory, host management |
| Protect | Prevention policies, sensor |
| Detect | Detections, threat intelligence |
| Respond | RTR, containment, remediation |
| Recover | Incident response, restore |

### CIS Controls

| Control | CrowdStrike Feature |
|---------|---------------------|
| 1 - Asset Inventory | Host Management |
| 7 - Continuous Vulnerability | Spotlight module |
| 8 - Audit Log Management | Audit logs |
| 10 - Malware Defense | Prevention, sensor |
| 17 - Incident Response | RTR, Incidents |

---

## Resources

### Official Documentation

- [CrowdStrike API Documentation](https://falcon.crowdstrike.com/documentation/)
- [PSFalcon GitHub](https://github.com/CrowdStrike/psfalcon)
- [Falcon Support Portal](https://supportportal.crowdstrike.com/)

### Community Resources

- [CrowdStrike Blog](https://www.crowdstrike.com/blog/)
- [CrowdStrike Community](https://community.crowdstrike.com/)

### Training

- [CrowdStrike University](https://www.crowdstrike.com/training/)
- [Falcon Certification](https://www.crowdstrike.com/services/training/)

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
