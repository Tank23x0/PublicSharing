# AWS Security Audit Guide

## Overview

This guide provides comprehensive instructions for auditing AWS environments, covering IAM, infrastructure, logging, and security services. Designed for multi-account organizations and single-account environments.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [IAM User Audit](#iam-user-audit)
3. [IAM Role Audit](#iam-role-audit)
4. [Access Key Audit](#access-key-audit)
5. [MFA Status Audit](#mfa-status-audit)
6. [Root Account Audit](#root-account-audit)
7. [Password Policy Audit](#password-policy-audit)
8. [EC2 Security Audit](#ec2-security-audit)
9. [S3 Bucket Audit](#s3-bucket-audit)
10. [CloudTrail Audit](#cloudtrail-audit)
11. [GuardDuty Audit](#guardduty-audit)
12. [Security Hub Audit](#security-hub-audit)
13. [Multi-Account Organization Audit](#multi-account-organization-audit)
14. [API Reference](#api-reference)
15. [Compliance Mapping](#compliance-mapping)
16. [Resources](#resources)

---

## Prerequisites

### Required Permissions

Minimum IAM permissions for comprehensive auditing:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GenerateCredentialReport",
                "iam:GetCredentialReport",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListRoles",
                "iam:ListGroups",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:ListUserPolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListGroupsForUser",
                "iam:GetRole",
                "iam:ListRolePolicies",
                "iam:ListAttachedRolePolicies",
                "iam:ListMFADevices",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstances",
                "ec2:DescribeVolumes",
                "ec2:GetEbsEncryptionByDefault",
                "s3:ListAllMyBuckets",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketPolicy",
                "s3:GetBucketLogging",
                "cloudtrail:DescribeTrails",
                "cloudtrail:GetTrailStatus",
                "guardduty:ListDetectors",
                "guardduty:GetDetector",
                "guardduty:ListFindings",
                "guardduty:GetFindings",
                "securityhub:DescribeHub",
                "securityhub:GetEnabledStandards",
                "securityhub:DescribeStandardsControls",
                "access-analyzer:ListAnalyzers",
                "access-analyzer:ListFindings",
                "config:DescribeConfigurationRecorders",
                "config:DescribeConfigurationRecorderStatus",
                "config:DescribeConfigRules",
                "organizations:ListAccounts",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

Or use AWS managed policy: `SecurityAudit`

### AWS CLI Installation

```bash
# macOS
brew install awscli

# Linux
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Verify
aws --version
```

### PowerShell Module Installation

```powershell
# Install all AWS modules
Install-Module -Name AWS.Tools.Installer -Force
Install-AWSToolsModule AWS.Tools.IdentityManagement, AWS.Tools.Organizations, AWS.Tools.SecurityToken, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.CloudTrail, AWS.Tools.SecurityHub, AWS.Tools.GuardDuty -Force
```

---

## IAM User Audit

### Manual Steps (Console)

1. **Navigate**: IAM → Users
2. **Enable Columns**: Click gear icon, enable "Access key age", "Password age", "MFA", "Last activity"
3. **Download**: Click "Download credential report" for CSV export
4. **Filter**: Sort by last activity to identify stale accounts

### CLI Commands

```bash
# Generate credential report
aws iam generate-credential-report

# Get credential report (base64 encoded CSV)
aws iam get-credential-report --output text --query Content | base64 -d > credential-report.csv

# List all users with details
aws iam list-users --output table

# Get user details
aws iam get-user --user-name USERNAME

# List user's access keys
aws iam list-access-keys --user-name USERNAME

# Get access key last used
aws iam get-access-key-last-used --access-key-id AKIAEXAMPLE

# Check if user has console access
aws iam get-login-profile --user-name USERNAME

# List MFA devices for user
aws iam list-mfa-devices --user-name USERNAME

# List user's group memberships
aws iam list-groups-for-user --user-name USERNAME

# List inline policies
aws iam list-user-policies --user-name USERNAME

# List attached managed policies
aws iam list-attached-user-policies --user-name USERNAME
```

### Audit Queries

#### Find users without MFA
```bash
# From credential report
awk -F',' '$4=="true" && $8=="false" {print $1}' credential-report.csv
```

#### Find inactive users (90+ days)
```bash
aws iam list-users --query 'Users[?PasswordLastUsed<`2024-10-01`].UserName'
```

#### Find users with old passwords
```bash
# Parse credential report for passwords older than 90 days
awk -F',' 'NR>1 {split($6,a,"T"); if (a[1] < "2024-10-01") print $1, $6}' credential-report.csv
```

---

## IAM Role Audit

### Manual Steps (Console)

1. **Navigate**: IAM → Roles
2. **Review**: Check each role's trust relationship
3. **Filter**: Look for roles with "Last activity" never or > 90 days

### CLI Commands

```bash
# List all roles
aws iam list-roles --query 'Roles[].{Name:RoleName,Created:CreateDate,LastUsed:RoleLastUsed.LastUsedDate}'

# Get role details including trust policy
aws iam get-role --role-name ROLENAME

# Get trust policy (assume role policy)
aws iam get-role --role-name ROLENAME --query 'Role.AssumeRolePolicyDocument'

# List role's attached policies
aws iam list-attached-role-policies --role-name ROLENAME

# List inline policies
aws iam list-role-policies --role-name ROLENAME

# Get inline policy document
aws iam get-role-policy --role-name ROLENAME --policy-name POLICYNAME
```

### Audit Queries

#### Find roles with wildcard principal (dangerous!)
```bash
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
    trust=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output text 2>/dev/null)
    if echo "$trust" | grep -q '"Principal": "\*"'; then
        echo "DANGER: $role has wildcard principal"
    fi
done
```

#### Find roles with cross-account trust
```bash
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
for role in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
    trust=$(aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' 2>/dev/null)
    if echo "$trust" | grep -qE 'arn:aws:iam::[0-9]+:' | grep -v "$ACCOUNT_ID"; then
        echo "Cross-account: $role"
    fi
done
```

---

## Access Key Audit

### Manual Steps (Console)

1. **Navigate**: IAM → Credential Report
2. **Download**: Export and open in Excel
3. **Filter**: Column H (access_key_1_last_rotated) for keys older than 90 days
4. **Check**: Column J (access_key_1_last_used_date) for unused keys

### CLI Commands

```bash
# List all access keys for a user
aws iam list-access-keys --user-name USERNAME

# Get key last used details
aws iam get-access-key-last-used --access-key-id AKIAEXAMPLE

# Find all active access keys across all users
for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
    aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?Status=='Active'].{User:'$user',KeyId:AccessKeyId,Created:CreateDate}"
done
```

### Key Audit Script

```bash
#!/bin/bash
# Find access keys older than 90 days

THRESHOLD_DATE=$(date -d "90 days ago" +%Y-%m-%d 2>/dev/null || date -v-90d +%Y-%m-%d)

echo "Access Keys older than 90 days:"
echo "================================"

for user in $(aws iam list-users --query 'Users[].UserName' --output text); do
    for key in $(aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?Status=='Active'].AccessKeyId" --output text); do
        created=$(aws iam list-access-keys --user-name "$user" --query "AccessKeyMetadata[?AccessKeyId=='$key'].CreateDate" --output text | cut -d'T' -f1)
        if [[ "$created" < "$THRESHOLD_DATE" ]]; then
            last_used=$(aws iam get-access-key-last-used --access-key-id "$key" --query 'AccessKeyLastUsed.LastUsedDate' --output text)
            echo "User: $user | Key: $key | Created: $created | Last Used: $last_used"
        fi
    done
done
```

---

## MFA Status Audit

### Manual Steps (Console)

1. **Navigate**: IAM → Account Settings → Credential Report
2. **Download**: Credential report
3. **Filter**: Column D (mfa_active) = "false" where password_enabled = "true"

### CLI Commands

```bash
# Check MFA for specific user
aws iam list-mfa-devices --user-name USERNAME

# Check virtual MFA devices
aws iam list-virtual-mfa-devices

# Find all users without MFA (with console access)
aws iam generate-credential-report
aws iam get-credential-report --output text --query Content | base64 -d | \
    awk -F',' 'NR>1 && $4=="true" && $8=="false" {print "NO MFA: "$1}'
```

### MFA Compliance Report

```bash
#!/bin/bash
echo "MFA Compliance Report"
echo "===================="

# Generate fresh report
aws iam generate-credential-report > /dev/null 2>&1
sleep 5

# Get report
aws iam get-credential-report --output text --query Content | base64 -d > /tmp/cred-report.csv

# Parse
total_console=$(awk -F',' 'NR>1 && $4=="true" {count++} END {print count}' /tmp/cred-report.csv)
with_mfa=$(awk -F',' 'NR>1 && $4=="true" && $8=="true" {count++} END {print count}' /tmp/cred-report.csv)
without_mfa=$(awk -F',' 'NR>1 && $4=="true" && $8=="false" {count++} END {print count}' /tmp/cred-report.csv)

echo "Users with console access: $total_console"
echo "With MFA: $with_mfa"
echo "WITHOUT MFA: $without_mfa"
echo ""
echo "Users requiring MFA:"
awk -F',' 'NR>1 && $4=="true" && $8=="false" {print "  - "$1}' /tmp/cred-report.csv
```

---

## Root Account Audit

### Manual Steps (Console)

1. **Sign in as root** (only if necessary)
2. **Navigate**: Account Settings → Security Credentials
3. **Check**:
   - MFA enabled
   - No access keys
   - Security questions configured
   - Account recovery email verified

### CLI Commands

```bash
# Check root account from credential report
aws iam get-credential-report --output text --query Content | base64 -d | \
    grep "<root_account>"

# Parse root account status
aws iam get-credential-report --output text --query Content | base64 -d | \
    awk -F',' '$1=="<root_account>" {
        print "Root MFA: "$8
        print "Root Access Key 1 Active: "$9
        print "Root Access Key 2 Active: "$14
    }'
```

### Root Account Best Practices Checklist

- [ ] MFA enabled (hardware token preferred)
- [ ] No access keys exist
- [ ] Strong, unique password
- [ ] Account recovery information current
- [ ] Alternate contacts configured
- [ ] Root not used for daily operations
- [ ] CloudTrail monitoring for root login

---

## Password Policy Audit

### Manual Steps (Console)

1. **Navigate**: IAM → Account Settings
2. **Review**: Password policy settings
3. **Verify** all requirements meet security standards

### CLI Commands

```bash
# Get current password policy
aws iam get-account-password-policy

# Check specific settings
aws iam get-account-password-policy --query '{
    MinLength: MinimumPasswordLength,
    RequireUpper: RequireUppercaseCharacters,
    RequireLower: RequireLowercaseCharacters,
    RequireNumbers: RequireNumbers,
    RequireSymbols: RequireSymbols,
    MaxAge: MaxPasswordAge,
    PasswordReuse: PasswordReusePrevention,
    ExpirePasswords: ExpirePasswords
}'
```

### Recommended Password Policy

```bash
# Set compliant password policy
aws iam update-account-password-policy \
    --minimum-password-length 14 \
    --require-uppercase-characters \
    --require-lowercase-characters \
    --require-numbers \
    --require-symbols \
    --max-password-age 90 \
    --password-reuse-prevention 24 \
    --hard-expiry
```

---

## EC2 Security Audit

### Manual Steps (Console)

1. **Security Groups**: VPC → Security Groups
   - Look for 0.0.0.0/0 inbound rules
   - Check for sensitive ports (22, 3389, 3306, etc.)
2. **Instances**: EC2 → Instances
   - Check for public IPs
   - Review IMDSv2 status
3. **EBS**: EC2 → Volumes
   - Check encryption status

### CLI Commands

```bash
# Find security groups allowing 0.0.0.0/0
aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName}'

# Find security groups with open SSH (22)
aws ec2 describe-security-groups \
    --filters "Name=ip-permission.from-port,Values=22" "Name=ip-permission.cidr,Values=0.0.0.0/0" \
    --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}'

# Find security groups with open RDP (3389)
aws ec2 describe-security-groups \
    --filters "Name=ip-permission.from-port,Values=3389" "Name=ip-permission.cidr,Values=0.0.0.0/0" \
    --query 'SecurityGroups[].{ID:GroupId,Name:GroupName}'

# List instances with public IPs
aws ec2 describe-instances --query 'Reservations[].Instances[?PublicIpAddress!=`null`].{ID:InstanceId,Name:Tags[?Key==`Name`].Value|[0],PublicIP:PublicIpAddress}'

# Check IMDSv2 enforcement
aws ec2 describe-instances --query 'Reservations[].Instances[].{ID:InstanceId,IMDSv2:MetadataOptions.HttpTokens}'

# Find unencrypted EBS volumes
aws ec2 describe-volumes --query 'Volumes[?Encrypted==`false`].{VolumeId:VolumeId,Size:Size,State:State}'

# Check EBS default encryption
aws ec2 get-ebs-encryption-by-default
```

### EC2 Security Audit Script

```bash
#!/bin/bash
echo "EC2 Security Audit"
echo "=================="

echo -e "\n[1] Security Groups with 0.0.0.0/0:"
aws ec2 describe-security-groups \
    --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]].{GroupId:GroupId,GroupName:GroupName,VpcId:VpcId}' \
    --output table

echo -e "\n[2] Instances with Public IPs:"
aws ec2 describe-instances \
    --query 'Reservations[].Instances[?PublicIpAddress!=`null`].{ID:InstanceId,PublicIP:PublicIpAddress,State:State.Name}' \
    --output table

echo -e "\n[3] Instances not enforcing IMDSv2:"
aws ec2 describe-instances \
    --query 'Reservations[].Instances[?MetadataOptions.HttpTokens!=`required`].{ID:InstanceId,IMDSv2:MetadataOptions.HttpTokens}' \
    --output table

echo -e "\n[4] Unencrypted EBS Volumes:"
aws ec2 describe-volumes \
    --query 'Volumes[?Encrypted==`false`].{VolumeId:VolumeId,Size:Size,AZ:AvailabilityZone}' \
    --output table

echo -e "\n[5] EBS Default Encryption:"
aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault'
```

---

## S3 Bucket Audit

### Manual Steps (Console)

1. **Navigate**: S3 → Buckets
2. **Check Access**: Look for "Public" indicator
3. **Block Public Access**: S3 → Block Public Access settings
4. **Review**: Each bucket's permissions and policies

### CLI Commands

```bash
# List all buckets
aws s3api list-buckets --query 'Buckets[].Name'

# Check bucket public access block
aws s3api get-public-access-block --bucket BUCKET-NAME

# Check bucket ACL
aws s3api get-bucket-acl --bucket BUCKET-NAME

# Check bucket policy
aws s3api get-bucket-policy --bucket BUCKET-NAME

# Check bucket encryption
aws s3api get-bucket-encryption --bucket BUCKET-NAME

# Check bucket versioning
aws s3api get-bucket-versioning --bucket BUCKET-NAME

# Check bucket logging
aws s3api get-bucket-logging --bucket BUCKET-NAME

# Check account-level public access block
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text)
```

### S3 Security Audit Script

```bash
#!/bin/bash
echo "S3 Security Audit"
echo "================="

for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
    echo -e "\n--- $bucket ---"
    
    # Public Access Block
    pab=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "  [WARN] No public access block configured"
    else
        echo "  Public Access Block: Configured"
    fi
    
    # Encryption
    enc=$(aws s3api get-bucket-encryption --bucket "$bucket" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "  [WARN] No default encryption"
    else
        echo "  Encryption: Enabled"
    fi
    
    # Versioning
    ver=$(aws s3api get-bucket-versioning --bucket "$bucket" --query 'Status' --output text)
    if [ "$ver" != "Enabled" ]; then
        echo "  [INFO] Versioning: Not enabled"
    else
        echo "  Versioning: Enabled"
    fi
    
    # Logging
    log=$(aws s3api get-bucket-logging --bucket "$bucket" --query 'LoggingEnabled.TargetBucket' --output text)
    if [ "$log" == "None" ]; then
        echo "  [INFO] Logging: Not enabled"
    else
        echo "  Logging: $log"
    fi
done
```

---

## CloudTrail Audit

### Manual Steps (Console)

1. **Navigate**: CloudTrail → Trails
2. **Verify**: Multi-region trail exists
3. **Check**: Logging enabled, log file validation, encryption
4. **Review**: Event history for recent activity

### CLI Commands

```bash
# List all trails
aws cloudtrail describe-trails

# Get trail status
aws cloudtrail get-trail-status --name TRAIL-NAME

# Check if trail is logging
aws cloudtrail get-trail-status --name TRAIL-NAME --query 'IsLogging'

# Check trail configuration
aws cloudtrail describe-trails --query 'trailList[].{Name:Name,IsMultiRegion:IsMultiRegionTrail,LogValidation:LogFileValidationEnabled,KMSKey:KmsKeyId,S3Bucket:S3BucketName}'

# Look up recent events
aws cloudtrail lookup-events --max-results 10

# Look up specific events (e.g., console logins)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin --max-results 20
```

### CloudTrail Best Practices Checklist

- [ ] Multi-region trail enabled
- [ ] All management events captured
- [ ] Log file validation enabled
- [ ] KMS encryption enabled
- [ ] CloudWatch Logs integration
- [ ] S3 bucket with versioning
- [ ] SNS notifications configured (optional)

---

## GuardDuty Audit

### Manual Steps (Console)

1. **Navigate**: GuardDuty → Settings
2. **Verify**: Service enabled in all regions
3. **Review**: Findings (filter by severity)
4. **Check**: Trusted IP and threat lists

### CLI Commands

```bash
# List detectors
aws guardduty list-detectors

# Get detector status
aws guardduty get-detector --detector-id DETECTOR-ID

# List findings
aws guardduty list-findings --detector-id DETECTOR-ID --max-results 50

# Get finding details
aws guardduty get-findings --detector-id DETECTOR-ID --finding-ids FINDING-ID

# Get findings by severity (high/critical = 7+)
aws guardduty list-findings --detector-id DETECTOR-ID \
    --finding-criteria '{"Criterion":{"severity":{"Gte":7}}}'
```

### Enable GuardDuty in All Regions

```bash
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
    echo "Enabling GuardDuty in $region"
    aws guardduty create-detector --enable --region "$region" 2>/dev/null || echo "  Already enabled or error"
done
```

---

## Security Hub Audit

### Manual Steps (Console)

1. **Navigate**: Security Hub → Summary
2. **Review**: Security score and failed controls
3. **Check**: Enabled standards (CIS, AWS Foundational)
4. **Filter**: Findings by severity

### CLI Commands

```bash
# Check if Security Hub is enabled
aws securityhub describe-hub

# List enabled standards
aws securityhub get-enabled-standards

# Get findings summary
aws securityhub get-findings --max-items 100

# Get failed controls
aws securityhub describe-standards-controls \
    --standards-subscription-arn "arn:aws:securityhub:us-east-1:ACCOUNT:subscription/aws-foundational-security-best-practices/v/1.0.0" \
    --query 'Controls[?ComplianceStatus==`FAILED`].{ID:ControlId,Title:Title}'

# Get findings by severity
aws securityhub get-findings \
    --filters '{"SeverityLabel":[{"Value":"CRITICAL","Comparison":"EQUALS"}]}'
```

---

## Multi-Account Organization Audit

### Manual Steps (Console)

1. **Navigate**: AWS Organizations → Accounts
2. **Export**: Account list
3. **Delegate**: Use CloudFormation StackSets for consistent audit roles

### CLI Commands

```bash
# List all accounts in organization
aws organizations list-accounts

# Get account details
aws organizations describe-account --account-id ACCOUNT-ID

# List organizational units
aws organizations list-roots
aws organizations list-organizational-units-for-parent --parent-id r-xxxx

# Assume role in member account
aws sts assume-role \
    --role-arn "arn:aws:iam::TARGET-ACCOUNT:role/OrganizationAccountAccessRole" \
    --role-session-name "AuditSession"
```

### Cross-Account Audit Script

```bash
#!/bin/bash
# Audit all accounts in organization

ORG_ROLE="OrganizationAccountAccessRole"
ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)

for account in $ACCOUNTS; do
    echo "========================================"
    echo "Auditing Account: $account"
    echo "========================================"
    
    # Assume role
    CREDS=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${account}:role/${ORG_ROLE}" \
        --role-session-name "Audit" \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "  [ERROR] Cannot assume role in $account"
        continue
    fi
    
    export AWS_ACCESS_KEY_ID=$(echo $CREDS | cut -d' ' -f1)
    export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | cut -d' ' -f2)
    export AWS_SESSION_TOKEN=$(echo $CREDS | cut -d' ' -f3)
    
    # Run audit commands
    echo "  Users: $(aws iam list-users --query 'length(Users)')"
    echo "  Roles: $(aws iam list-roles --query 'length(Roles)')"
    echo "  Buckets: $(aws s3api list-buckets --query 'length(Buckets)')"
    
    # Clear credentials
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
done
```

---

## API Reference

### IAM APIs

| API | Description | Documentation |
|-----|-------------|---------------|
| `GenerateCredentialReport` | Create IAM credential report | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GenerateCredentialReport.html) |
| `GetCredentialReport` | Retrieve credential report | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetCredentialReport.html) |
| `ListUsers` | List IAM users | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListUsers.html) |
| `GetUser` | Get user details | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetUser.html) |
| `ListAccessKeys` | List user access keys | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAccessKeys.html) |
| `GetAccessKeyLastUsed` | Key usage info | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccessKeyLastUsed.html) |
| `ListMFADevices` | List MFA devices | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html) |
| `GetAccountPasswordPolicy` | Get password policy | [Docs](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountPasswordPolicy.html) |

### CloudTrail APIs

| API | Description | Documentation |
|-----|-------------|---------------|
| `DescribeTrails` | List trails | [Docs](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_DescribeTrails.html) |
| `GetTrailStatus` | Get trail status | [Docs](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html) |
| `LookupEvents` | Query events | [Docs](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html) |

### Security Services APIs

| Service | API | Documentation |
|---------|-----|---------------|
| GuardDuty | `ListDetectors`, `GetFindings` | [Docs](https://docs.aws.amazon.com/guardduty/latest/APIReference/) |
| Security Hub | `DescribeHub`, `GetFindings` | [Docs](https://docs.aws.amazon.com/securityhub/1.0/APIReference/) |
| Access Analyzer | `ListAnalyzers`, `ListFindings` | [Docs](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/) |
| Config | `DescribeConfigRules`, `GetComplianceDetailsByConfigRule` | [Docs](https://docs.aws.amazon.com/config/latest/APIReference/) |

---

## Compliance Mapping

### SOC 2

| Control | AWS Service/Feature |
|---------|---------------------|
| CC6.1 - Logical Access | IAM, MFA, Password Policy |
| CC6.2 - Access Provisioning | IAM Users, Roles |
| CC6.3 - Access Removal | Credential Report, Access Keys |
| CC7.2 - Security Monitoring | CloudTrail, GuardDuty |
| CC7.3 - Incident Response | GuardDuty, Security Hub |

### ISO 27001

| Control | AWS Service/Feature |
|---------|---------------------|
| A.9.2.1 - User Registration | IAM User Management |
| A.9.2.3 - Privileged Access | IAM Roles, Policies |
| A.9.4.2 - Secure Log-on | MFA, Password Policy |
| A.12.4.1 - Event Logging | CloudTrail |
| A.12.4.3 - Admin Logs | CloudTrail Management Events |

### NIST Cybersecurity Framework

| Function | AWS Service/Feature |
|----------|---------------------|
| Identify (ID.AM) | IAM, Config |
| Protect (PR.AC) | IAM, MFA, KMS |
| Detect (DE.CM) | GuardDuty, CloudTrail |
| Respond (RS.AN) | Security Hub |
| Recover (RC.RP) | S3 Versioning, Backups |

### CIS AWS Foundations Benchmark

- 1.1 - Root account MFA
- 1.2 - No root access keys
- 1.3 - IAM user MFA
- 1.4 - Access key rotation (90 days)
- 1.5-1.11 - Password policy requirements
- 1.12 - No unused credentials
- 2.1 - CloudTrail enabled
- 2.2 - CloudTrail log validation
- 2.3 - CloudTrail S3 not public
- 2.4 - CloudTrail CloudWatch integration

---

## Resources

### Official Documentation

- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Security Best Practices in IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/IAMBestPractices.html)
- [CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/)
- [Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/)
- [AWS Well-Architected Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/)

### AWS Blog Posts

- [How to Monitor and Visualize Failed SSH Login Attempts](https://aws.amazon.com/blogs/security/how-to-monitor-and-visualize-failed-ssh-access-attempts-to-amazon-ec2-linux-instances/)
- [Automating IAM Credential Reports](https://aws.amazon.com/blogs/security/how-to-use-credential-report-and-consolidated-billing/)
- [Implementing CIS Benchmarks](https://aws.amazon.com/blogs/security/how-to-audit-your-aws-resources-and-identify-security-issues/)

### Community Resources

- [Prowler - AWS Security Tool](https://github.com/prowler-cloud/prowler)
- [ScoutSuite - Multi-cloud Security](https://github.com/nccgroup/ScoutSuite)
- [AWS Security Maturity Model](https://maturitymodel.security.aws.dev/)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/)

### Training

- [AWS Security Specialty Certification](https://aws.amazon.com/certification/certified-security-specialty/)
- [AWS Security Fundamentals (Free)](https://www.aws.training/Details/Curriculum?id=20685)

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
