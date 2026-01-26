#!/bin/bash
#===============================================================================
# Oracle Cloud Infrastructure Security Audit Script
# VERSION: 2.0.0
# REQUIREMENTS: OCI CLI configured with appropriate permissions
#===============================================================================

set -euo pipefail

OUTPUT_DIR="${HOME}/Documents/Scripts/OCI-Audit"
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
REPORT_FILE="${OUTPUT_DIR}/OCI-Audit-Report_${TIMESTAMP}.txt"

echo "=== OCI SECURITY AUDIT ===" | tee "$REPORT_FILE"
echo "Started: $(date)" | tee -a "$REPORT_FILE"

# Check OCI CLI
if ! command -v oci &>/dev/null; then
    echo "ERROR: OCI CLI not installed" | tee -a "$REPORT_FILE"
    exit 1
fi

# Get tenancy
TENANCY=$(oci iam tenancy get --query 'data.name' --raw-output 2>/dev/null || echo "Unknown")
echo "Tenancy: $TENANCY" | tee -a "$REPORT_FILE"

echo -e "\n=== IAM AUDIT ===" | tee -a "$REPORT_FILE"

# List users
echo "Listing users..." | tee -a "$REPORT_FILE"
oci iam user list --all --query 'data[].{name:name,email:email,"is-mfa-activated":"is-mfa-activated",lifecycle:lifecycleState}' 2>/dev/null | tee -a "$REPORT_FILE"

# Users without MFA
echo -e "\nUsers without MFA:" | tee -a "$REPORT_FILE"
oci iam user list --all --query 'data[?"is-mfa-activated"==`false`].name' 2>/dev/null | tee -a "$REPORT_FILE"

# List groups
echo -e "\n=== GROUPS ===" | tee -a "$REPORT_FILE"
oci iam group list --all --query 'data[].name' 2>/dev/null | tee -a "$REPORT_FILE"

# List policies
echo -e "\n=== POLICIES ===" | tee -a "$REPORT_FILE"
oci iam policy list --compartment-id "$TENANCY" --all --query 'data[].{name:name,statements:statements}' 2>/dev/null | head -100 | tee -a "$REPORT_FILE"

echo -e "\n=== COMPARTMENTS ===" | tee -a "$REPORT_FILE"
oci iam compartment list --all --query 'data[].{name:name,id:id}' 2>/dev/null | tee -a "$REPORT_FILE"

echo -e "\n=== COMPUTE INSTANCES ===" | tee -a "$REPORT_FILE"
oci compute instance list --all --query 'data[].{name:"display-name",state:"lifecycle-state",shape:shape}' 2>/dev/null | tee -a "$REPORT_FILE"

echo -e "\n=== NETWORKING ===" | tee -a "$REPORT_FILE"

# VCNs
echo "Virtual Cloud Networks:" | tee -a "$REPORT_FILE"
oci network vcn list --all --query 'data[].{name:"display-name",cidr:"cidr-block"}' 2>/dev/null | tee -a "$REPORT_FILE"

# Security Lists (check for open ingress)
echo -e "\nSecurity Lists:" | tee -a "$REPORT_FILE"
oci network security-list list --all --query 'data[].{name:"display-name",rules:"ingress-security-rules"}' 2>/dev/null | head -50 | tee -a "$REPORT_FILE"

echo -e "\n=== OBJECT STORAGE ===" | tee -a "$REPORT_FILE"
# List buckets
oci os bucket list --all --query 'data[].{name:name,public:"public-access-type"}' 2>/dev/null | tee -a "$REPORT_FILE"

echo -e "\n=== AUDIT CONFIGURATION ===" | tee -a "$REPORT_FILE"
oci audit config get --query 'data' 2>/dev/null | tee -a "$REPORT_FILE"

echo -e "\n=== CLOUD GUARD ===" | tee -a "$REPORT_FILE"
oci cloud-guard configuration get --query 'data.status' 2>/dev/null | tee -a "$REPORT_FILE"

echo -e "\n=== AUDIT COMPLETE ===" | tee -a "$REPORT_FILE"
echo "Report saved: $REPORT_FILE"
