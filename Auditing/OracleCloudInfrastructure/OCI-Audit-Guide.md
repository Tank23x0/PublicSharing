# Oracle Cloud Infrastructure Security Audit Guide

## Prerequisites
```bash
# Install OCI CLI
bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)"

# Configure
oci setup config
```

## Key Audit Commands

### IAM Users
```bash
# List users
oci iam user list --all --query 'data[].{name:name,mfa:"is-mfa-activated"}'

# Users without MFA
oci iam user list --all --query 'data[?"is-mfa-activated"==`false`].name'

# API keys for user
oci iam user api-key list --user-id USER_OCID
```

### Groups & Policies
```bash
oci iam group list --all
oci iam policy list --compartment-id TENANCY_OCID --all
```

### Compute
```bash
oci compute instance list --all --query 'data[].{name:"display-name",state:"lifecycle-state"}'
```

### Networking
```bash
# VCNs
oci network vcn list --all

# Security Lists (firewall rules)
oci network security-list list --all

# Network Security Groups
oci network nsg list --all
```

### Storage
```bash
# Buckets (check public access)
oci os bucket list --all --query 'data[].{name:name,public:"public-access-type"}'
```

### Audit & Security
```bash
# Audit configuration
oci audit config get

# Cloud Guard status
oci cloud-guard configuration get
```

## Security Checklist
- [ ] MFA enabled for all users
- [ ] No overly permissive policies
- [ ] Security lists restrict access
- [ ] No public buckets (unless intended)
- [ ] Cloud Guard enabled
- [ ] Audit logging configured

## Resources
- [OCI Security Guide](https://docs.oracle.com/en-us/iaas/Content/Security/Concepts/security_guide.htm)
- [OCI CLI Reference](https://docs.oracle.com/en-us/iaas/tools/oci-cli/latest/oci_cli_docs/)

---
*Version: 2.0.0 | Updated: 2025-01-26*
