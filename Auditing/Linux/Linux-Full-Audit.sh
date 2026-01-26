#!/bin/bash

#===============================================================================
# Comprehensive Linux Security Audit Script
#
# DESCRIPTION:
#   Performs thorough security audits of Linux systems including:
#   - User account analysis (stale, privileged, password)
#   - SSH configuration
#   - Sudo configuration
#   - Service and process audit
#   - Network configuration
#   - File permissions
#   - Patch/update status
#   - Firewall rules
#   - SELinux/AppArmor status
#
# AUTHOR: Security Operations Team
# VERSION: 2.0.0
# DATE: 2025-01-26
#
# USAGE: sudo ./Linux-Full-Audit.sh [OPTIONS]
#   -o OUTPUT_DIR   Output directory (default: ~/Documents/Scripts/Linux-Audit)
#   -d DAYS         Stale threshold days (default: 90)
#   -h              Show help
#
# REQUIREMENTS:
#   - Root or sudo access
#   - Standard Linux utilities (awk, grep, find, etc.)
#===============================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
SCRIPT_NAME="Linux-Full-Audit"
VERSION="2.0.0"
OUTPUT_DIR="${HOME}/Documents/Scripts/Linux-Audit"
STALE_DAYS=90
TIMESTAMP=$(date +"%Y-%m-%d_%H%M%S")
HOSTNAME=$(hostname)

# Counters
TOTAL_FINDINGS=0
CRITICAL_FINDINGS=0
HIGH_FINDINGS=0
MEDIUM_FINDINGS=0
LOW_FINDINGS=0

# Parse arguments
while getopts "o:d:h" opt; do
    case $opt in
        o) OUTPUT_DIR="$OPTARG" ;;
        d) STALE_DAYS="$OPTARG" ;;
        h)
            echo "Usage: $0 [-o OUTPUT_DIR] [-d STALE_DAYS] [-h]"
            exit 0
            ;;
        *)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"
LOG_FILE="${OUTPUT_DIR}/linux-audit-${TIMESTAMP}.log"
REPORT_FILE="${OUTPUT_DIR}/linux-audit-${TIMESTAMP}.html"
FINDINGS_FILE="${OUTPUT_DIR}/findings-${TIMESTAMP}.txt"

# Logging functions
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    case $level in
        INFO)    color=$NC ;;
        WARNING) color=$YELLOW ;;
        ERROR)   color=$RED ;;
        SUCCESS) color=$GREEN ;;
        FINDING) color=$CYAN ;;
    esac
    
    echo -e "${color}[$timestamp] [$level] $message${NC}"
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

write_finding() {
    local category=$1
    local severity=$2
    local object=$3
    local finding=$4
    local recommendation=$5
    
    ((TOTAL_FINDINGS++))
    case $severity in
        CRITICAL) ((CRITICAL_FINDINGS++)) ;;
        HIGH)     ((HIGH_FINDINGS++)) ;;
        MEDIUM)   ((MEDIUM_FINDINGS++)) ;;
        LOW)      ((LOW_FINDINGS++)) ;;
    esac
    
    log FINDING "[$severity] $category - $finding"
    echo "$severity|$category|$object|$finding|$recommendation" >> "$FINDINGS_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log WARNING "Not running as root. Some checks may be limited."
    else
        log INFO "Running as root"
    fi
}

#===============================================================================
# USER ACCOUNT AUDIT
#===============================================================================
audit_users() {
    log INFO "Auditing User Accounts..."
    
    # Get current date in seconds
    current_date=$(date +%s)
    stale_seconds=$((STALE_DAYS * 86400))
    
    # Count statistics
    local total_users=0
    local stale_users=0
    local no_password=0
    local empty_password=0
    
    # Check /etc/passwd
    while IFS=: read -r username password uid gid gecos home shell; do
        # Skip system accounts (UID < 1000 usually)
        [[ $uid -lt 1000 ]] && continue
        [[ $username == "nobody" ]] && continue
        
        ((total_users++))
        
        # Check last login
        last_login=$(lastlog -u "$username" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7}')
        if [[ "$last_login" == *"Never"* ]]; then
            write_finding "Users" "LOW" "$username" \
                "User has never logged in" \
                "Review account necessity"
        else
            # Try to parse last login date
            if command -v date &>/dev/null && [[ -n "$last_login" ]]; then
                last_date=$(date -d "$last_login" +%s 2>/dev/null || echo "0")
                if [[ $last_date -gt 0 ]]; then
                    age=$(( (current_date - last_date) / 86400 ))
                    if [[ $age -gt $STALE_DAYS ]]; then
                        ((stale_users++))
                        write_finding "Users" "MEDIUM" "$username" \
                            "User has not logged in for $age days" \
                            "Review account necessity and consider disabling"
                    fi
                fi
            fi
        fi
        
        # Check for no shell (nologin)
        if [[ "$shell" == *"nologin"* ]] || [[ "$shell" == *"false"* ]]; then
            continue
        fi
        
    done < /etc/passwd
    
    # Check for users with UID 0 (root equivalents)
    uid0_users=$(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    if [[ -n "$uid0_users" ]]; then
        write_finding "Users" "CRITICAL" "UID 0 Users" \
            "Non-root users with UID 0: $uid0_users" \
            "Remove UID 0 from non-root accounts immediately"
    fi
    
    # Check /etc/shadow for password issues (requires root)
    if [[ -r /etc/shadow ]]; then
        # Empty passwords
        empty_pw=$(awk -F: '$2 == "" {print $1}' /etc/shadow | tr '\n' ' ')
        if [[ -n "$empty_pw" ]]; then
            write_finding "Users" "CRITICAL" "Empty Passwords" \
                "Users with empty passwords: $empty_pw" \
                "Set passwords for all accounts or disable them"
        fi
        
        # Accounts with ! or * (disabled/no password)
        # This is usually fine for system accounts
        
        # Check password age
        while IFS=: read -r username pw lastchange min max warn inactive expire reserved; do
            [[ $username == "root" ]] && continue
            [[ $lastchange == "" ]] && continue
            
            # lastchange is days since epoch
            if [[ $lastchange -gt 0 ]]; then
                days_since=$(($(date +%s) / 86400 - lastchange))
                if [[ $days_since -gt 365 ]]; then
                    write_finding "Users" "MEDIUM" "$username" \
                        "Password is $days_since days old (over 1 year)" \
                        "Enforce password rotation"
                fi
            fi
        done < /etc/shadow
    fi
    
    log INFO "User audit complete: $total_users users, $stale_users stale"
}

#===============================================================================
# PRIVILEGED ACCESS AUDIT
#===============================================================================
audit_privileged_access() {
    log INFO "Auditing Privileged Access..."
    
    # Check sudo group members
    sudo_group="sudo"
    [[ -f /etc/redhat-release ]] && sudo_group="wheel"
    
    sudo_members=$(getent group "$sudo_group" 2>/dev/null | cut -d: -f4)
    if [[ -n "$sudo_members" ]]; then
        member_count=$(echo "$sudo_members" | tr ',' '\n' | wc -l)
        log INFO "Sudo group ($sudo_group) has $member_count members: $sudo_members"
        
        if [[ $member_count -gt 10 ]]; then
            write_finding "Privileged Access" "MEDIUM" "$sudo_group" \
                "$member_count users in sudo group" \
                "Review sudo access and apply least privilege"
        fi
    fi
    
    # Check sudoers file for dangerous configurations
    if [[ -r /etc/sudoers ]]; then
        # NOPASSWD entries
        nopasswd=$(grep -E "NOPASSWD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v "^#" || true)
        if [[ -n "$nopasswd" ]]; then
            write_finding "Privileged Access" "HIGH" "sudoers" \
                "NOPASSWD entries found in sudoers" \
                "Remove NOPASSWD unless absolutely necessary"
        fi
        
        # ALL=(ALL) ALL entries
        all_access=$(grep -E "ALL.*=.*\(ALL\).*ALL" /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v "^#" | grep -v "%sudo\|%wheel" || true)
        if [[ -n "$all_access" ]]; then
            write_finding "Privileged Access" "MEDIUM" "sudoers" \
                "Broad ALL access in sudoers (beyond sudo group)" \
                "Review and restrict sudo permissions"
        fi
    fi
    
    # Check for SUID binaries
    log INFO "Checking SUID binaries..."
    suid_files=$(find / -type f -perm -4000 2>/dev/null | head -50)
    suid_count=$(echo "$suid_files" | wc -l)
    log INFO "Found $suid_count SUID files (showing first 50)"
    
    # Check for unusual SUID files (not in standard locations)
    unusual_suid=$(echo "$suid_files" | grep -v -E "^/(usr/(bin|sbin|lib)|bin|sbin)" || true)
    if [[ -n "$unusual_suid" ]]; then
        write_finding "Privileged Access" "HIGH" "SUID Files" \
            "Unusual SUID files found outside standard paths" \
            "Review and remove unnecessary SUID bits"
    fi
}

#===============================================================================
# SSH CONFIGURATION AUDIT
#===============================================================================
audit_ssh() {
    log INFO "Auditing SSH Configuration..."
    
    local ssh_config="/etc/ssh/sshd_config"
    
    if [[ ! -f "$ssh_config" ]]; then
        log WARNING "SSH config not found at $ssh_config"
        return
    fi
    
    # Check PermitRootLogin
    root_login=$(grep -E "^PermitRootLogin" "$ssh_config" | awk '{print $2}' || echo "not set")
    if [[ "$root_login" == "yes" ]] || [[ "$root_login" == "not set" ]]; then
        write_finding "SSH" "HIGH" "PermitRootLogin" \
            "Root login is permitted via SSH" \
            "Set PermitRootLogin to 'no' or 'prohibit-password'"
    fi
    
    # Check PasswordAuthentication
    password_auth=$(grep -E "^PasswordAuthentication" "$ssh_config" | awk '{print $2}' || echo "not set")
    if [[ "$password_auth" == "yes" ]] || [[ "$password_auth" == "not set" ]]; then
        write_finding "SSH" "MEDIUM" "PasswordAuthentication" \
            "Password authentication is enabled" \
            "Consider using key-based authentication only"
    fi
    
    # Check PermitEmptyPasswords
    empty_pw=$(grep -E "^PermitEmptyPasswords" "$ssh_config" | awk '{print $2}' || echo "not set")
    if [[ "$empty_pw" == "yes" ]]; then
        write_finding "SSH" "CRITICAL" "PermitEmptyPasswords" \
            "Empty passwords are permitted for SSH" \
            "Set PermitEmptyPasswords to 'no'"
    fi
    
    # Check Protocol
    protocol=$(grep -E "^Protocol" "$ssh_config" | awk '{print $2}' || echo "not set")
    if [[ "$protocol" == "1" ]]; then
        write_finding "SSH" "CRITICAL" "Protocol" \
            "SSH Protocol 1 is enabled" \
            "Use Protocol 2 only"
    fi
    
    # Check X11Forwarding
    x11=$(grep -E "^X11Forwarding" "$ssh_config" | awk '{print $2}' || echo "not set")
    if [[ "$x11" == "yes" ]]; then
        write_finding "SSH" "LOW" "X11Forwarding" \
            "X11 forwarding is enabled" \
            "Disable X11Forwarding unless required"
    fi
    
    log INFO "SSH configuration audit complete"
}

#===============================================================================
# NETWORK CONFIGURATION AUDIT
#===============================================================================
audit_network() {
    log INFO "Auditing Network Configuration..."
    
    # Check listening services
    log INFO "Checking listening services..."
    if command -v ss &>/dev/null; then
        listening=$(ss -tuln 2>/dev/null)
    elif command -v netstat &>/dev/null; then
        listening=$(netstat -tuln 2>/dev/null)
    else
        log WARNING "Neither ss nor netstat available"
        return
    fi
    
    # Check for services listening on all interfaces
    all_interfaces=$(echo "$listening" | grep -E "0\.0\.0\.0:|:::" | grep -v "127\.0\.0\.1\|::1" || true)
    if [[ -n "$all_interfaces" ]]; then
        write_finding "Network" "LOW" "Listening Services" \
            "Services listening on all interfaces detected" \
            "Review and restrict to specific interfaces where possible"
    fi
    
    # Check IP forwarding
    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [[ "$ipv4_forward" == "1" ]]; then
        write_finding "Network" "MEDIUM" "IP Forwarding" \
            "IPv4 forwarding is enabled" \
            "Disable unless this is a router/gateway"
    fi
    
    # Check firewall status
    if command -v iptables &>/dev/null; then
        rules=$(iptables -L -n 2>/dev/null | wc -l)
        if [[ $rules -lt 10 ]]; then
            write_finding "Network" "HIGH" "Firewall" \
                "Minimal iptables rules detected ($rules lines)" \
                "Configure firewall rules"
        fi
    fi
    
    if command -v ufw &>/dev/null; then
        ufw_status=$(ufw status 2>/dev/null | head -1)
        if [[ "$ufw_status" == *"inactive"* ]]; then
            write_finding "Network" "HIGH" "Firewall" \
                "UFW firewall is inactive" \
                "Enable UFW firewall"
        fi
    fi
    
    if command -v firewall-cmd &>/dev/null; then
        fw_state=$(firewall-cmd --state 2>/dev/null || echo "not running")
        if [[ "$fw_state" != "running" ]]; then
            write_finding "Network" "HIGH" "Firewall" \
                "firewalld is not running" \
                "Enable firewalld"
        fi
    fi
}

#===============================================================================
# SELINUX / APPARMOR AUDIT
#===============================================================================
audit_mac() {
    log INFO "Auditing Mandatory Access Control..."
    
    # Check SELinux
    if command -v getenforce &>/dev/null; then
        selinux_status=$(getenforce 2>/dev/null || echo "Unknown")
        log INFO "SELinux status: $selinux_status"
        
        if [[ "$selinux_status" == "Disabled" ]] || [[ "$selinux_status" == "Permissive" ]]; then
            write_finding "MAC" "HIGH" "SELinux" \
                "SELinux is $selinux_status" \
                "Enable SELinux in Enforcing mode"
        fi
    fi
    
    # Check AppArmor
    if command -v aa-status &>/dev/null; then
        if aa-status &>/dev/null; then
            profiles=$(aa-status 2>/dev/null | grep "profiles are loaded" | awk '{print $1}')
            log INFO "AppArmor: $profiles profiles loaded"
        else
            write_finding "MAC" "MEDIUM" "AppArmor" \
                "AppArmor is not running" \
                "Enable AppArmor"
        fi
    fi
    
    # If neither is available
    if ! command -v getenforce &>/dev/null && ! command -v aa-status &>/dev/null; then
        write_finding "MAC" "MEDIUM" "MAC System" \
            "No MAC system (SELinux/AppArmor) detected" \
            "Consider implementing SELinux or AppArmor"
    fi
}

#===============================================================================
# FILE PERMISSIONS AUDIT
#===============================================================================
audit_permissions() {
    log INFO "Auditing File Permissions..."
    
    # Check /etc/passwd permissions
    passwd_perms=$(stat -c "%a" /etc/passwd 2>/dev/null || echo "000")
    if [[ "$passwd_perms" != "644" ]]; then
        write_finding "Permissions" "MEDIUM" "/etc/passwd" \
            "Incorrect permissions: $passwd_perms (should be 644)" \
            "chmod 644 /etc/passwd"
    fi
    
    # Check /etc/shadow permissions
    shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "000")
    if [[ "$shadow_perms" != "640" ]] && [[ "$shadow_perms" != "600" ]] && [[ "$shadow_perms" != "000" ]]; then
        write_finding "Permissions" "HIGH" "/etc/shadow" \
            "Incorrect permissions: $shadow_perms (should be 600 or 640)" \
            "chmod 600 /etc/shadow"
    fi
    
    # Check /etc/gshadow permissions
    if [[ -f /etc/gshadow ]]; then
        gshadow_perms=$(stat -c "%a" /etc/gshadow 2>/dev/null || echo "000")
        if [[ "$gshadow_perms" != "640" ]] && [[ "$gshadow_perms" != "600" ]] && [[ "$gshadow_perms" != "000" ]]; then
            write_finding "Permissions" "HIGH" "/etc/gshadow" \
                "Incorrect permissions: $gshadow_perms" \
                "chmod 600 /etc/gshadow"
        fi
    fi
    
    # Check home directory permissions
    log INFO "Checking home directory permissions..."
    for home_dir in /home/*; do
        [[ ! -d "$home_dir" ]] && continue
        perms=$(stat -c "%a" "$home_dir" 2>/dev/null || echo "000")
        if [[ "${perms:2:1}" != "0" ]]; then
            write_finding "Permissions" "MEDIUM" "$home_dir" \
                "Home directory is world-readable/writable: $perms" \
                "chmod 700 or 750 $home_dir"
        fi
    done
    
    # Check for world-writable files
    log INFO "Checking for world-writable files..."
    world_writable=$(find /etc /var -type f -perm -o+w 2>/dev/null | head -20)
    if [[ -n "$world_writable" ]]; then
        write_finding "Permissions" "HIGH" "World-Writable Files" \
            "World-writable files found in /etc or /var" \
            "Review and remove world-writable permissions"
    fi
}

#===============================================================================
# PATCH/UPDATE STATUS
#===============================================================================
audit_updates() {
    log INFO "Auditing Update Status..."
    
    # Detect package manager and check for updates
    if command -v apt &>/dev/null; then
        # Debian/Ubuntu
        apt update &>/dev/null
        updates=$(apt list --upgradable 2>/dev/null | grep -v "Listing" | wc -l)
        security_updates=$(apt list --upgradable 2>/dev/null | grep -i security | wc -l)
        
        log INFO "Available updates: $updates (Security: $security_updates)"
        
        if [[ $security_updates -gt 0 ]]; then
            write_finding "Updates" "HIGH" "Security Updates" \
                "$security_updates security updates available" \
                "Apply security updates: apt upgrade"
        elif [[ $updates -gt 20 ]]; then
            write_finding "Updates" "MEDIUM" "System Updates" \
                "$updates updates available" \
                "Apply system updates"
        fi
        
    elif command -v yum &>/dev/null; then
        # RHEL/CentOS
        updates=$(yum check-update 2>/dev/null | grep -v "^$\|^Loaded\|^Last" | wc -l)
        security_updates=$(yum check-update --security 2>/dev/null | grep -v "^$\|^Loaded\|^Last" | wc -l)
        
        log INFO "Available updates: $updates (Security: $security_updates)"
        
        if [[ $security_updates -gt 0 ]]; then
            write_finding "Updates" "HIGH" "Security Updates" \
                "$security_updates security updates available" \
                "Apply security updates: yum update --security"
        fi
        
    elif command -v dnf &>/dev/null; then
        # Fedora/newer RHEL
        updates=$(dnf check-update 2>/dev/null | grep -v "^$\|^Last" | wc -l)
        
        if [[ $updates -gt 20 ]]; then
            write_finding "Updates" "MEDIUM" "System Updates" \
                "$updates updates available" \
                "Apply updates: dnf update"
        fi
    fi
    
    # Check kernel version
    current_kernel=$(uname -r)
    log INFO "Current kernel: $current_kernel"
}

#===============================================================================
# GENERATE REPORT
#===============================================================================
generate_report() {
    log INFO "Generating HTML report..."
    
    cat > "$REPORT_FILE" << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Linux Security Audit Report</title>
    <style>
        body { font-family: 'Ubuntu', 'DejaVu Sans', Arial, sans-serif; margin: 40px; background: #2c001e; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; background: #300a24; padding: 30px; border-radius: 8px; }
        h1 { color: #e95420; border-bottom: 3px solid #e95420; padding-bottom: 15px; }
        h2 { color: #aea79f; }
        .summary-box { display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }
        .summary-item { padding: 20px; border-radius: 8px; color: white; min-width: 120px; text-align: center; }
        .critical { background: #c7162b; }
        .high { background: #e95420; }
        .medium { background: #f99b11; color: #300a24; }
        .low { background: #0e8420; }
        .info { background: #19b6ee; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #5e2750; }
        th { background: #77216f; color: white; }
        tr:hover { background: #5e2750; }
        .severity-critical { color: #c7162b; font-weight: bold; }
        .severity-high { color: #e95420; font-weight: bold; }
        .severity-medium { color: #f99b11; }
        .severity-low { color: #0e8420; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐧 Linux Security Audit Report</h1>
        <p><strong>Hostname:</strong> $HOSTNAME</p>
        <p><strong>Generated:</strong> $(date +"%Y-%m-%d %H:%M:%S")</p>
        <p><strong>Kernel:</strong> $(uname -r)</p>
        <p><strong>Distribution:</strong> $(cat /etc/os-release 2>/dev/null | grep "PRETTY_NAME" | cut -d'"' -f2 || echo "Unknown")</p>
        
        <h2>Summary</h2>
        <div class="summary-box">
            <div class="summary-item critical"><h3>$CRITICAL_FINDINGS</h3><p>Critical</p></div>
            <div class="summary-item high"><h3>$HIGH_FINDINGS</h3><p>High</p></div>
            <div class="summary-item medium"><h3>$MEDIUM_FINDINGS</h3><p>Medium</p></div>
            <div class="summary-item low"><h3>$LOW_FINDINGS</h3><p>Low</p></div>
            <div class="summary-item info"><h3>$TOTAL_FINDINGS</h3><p>Total</p></div>
        </div>
        
        <h2>Findings</h2>
        <table>
            <tr><th>Severity</th><th>Category</th><th>Object</th><th>Finding</th><th>Recommendation</th></tr>
EOF

    # Sort findings by severity and add to report
    if [[ -f "$FINDINGS_FILE" ]]; then
        sort -t'|' -k1,1 "$FINDINGS_FILE" | while IFS='|' read -r severity category object finding recommendation; do
            severity_class=$(echo "$severity" | tr '[:upper:]' '[:lower:]')
            echo "<tr><td class='severity-$severity_class'>$severity</td><td>$category</td><td>$object</td><td>$finding</td><td>$recommendation</td></tr>" >> "$REPORT_FILE"
        done
    fi

    cat >> "$REPORT_FILE" << EOF
        </table>
        <footer style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #5e2750; color: #aea79f;">
            <p>Generated by $SCRIPT_NAME v$VERSION</p>
        </footer>
    </div>
</body>
</html>
EOF

    log SUCCESS "Report saved: $REPORT_FILE"
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    echo "============================================================"
    echo " LINUX COMPREHENSIVE SECURITY AUDIT"
    echo " Version: $VERSION"
    echo " Started: $(date)"
    echo "============================================================"
    
    # Initialize findings file
    echo "" > "$FINDINGS_FILE"
    
    check_root
    audit_users
    audit_privileged_access
    audit_ssh
    audit_network
    audit_mac
    audit_permissions
    audit_updates
    
    generate_report
    
    echo ""
    echo "============================================================"
    log SUCCESS "AUDIT COMPLETE"
    echo "Total Findings: $TOTAL_FINDINGS"
    echo "  Critical: $CRITICAL_FINDINGS"
    echo "  High: $HIGH_FINDINGS"
    echo "  Medium: $MEDIUM_FINDINGS"
    echo "  Low: $LOW_FINDINGS"
    echo ""
    echo "Report: $REPORT_FILE"
    echo "Log: $LOG_FILE"
    echo "============================================================"
}

main "$@"
