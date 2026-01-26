# Linux Security Audit Guide

## Overview

Comprehensive guide for auditing Linux systems including user accounts, SSH configuration, privileged access, network security, and compliance.

---

## Table of Contents

1. [User Account Audit](#user-account-audit)
2. [Password Policy](#password-policy)
3. [Privileged Access (sudo)](#privileged-access-sudo)
4. [SSH Configuration](#ssh-configuration)
5. [Network Security](#network-security)
6. [Firewall Configuration](#firewall-configuration)
7. [SELinux/AppArmor](#selinuxapparmor)
8. [File Permissions](#file-permissions)
9. [Patch Management](#patch-management)
10. [Logging and Auditing](#logging-and-auditing)
11. [Compliance Mapping](#compliance-mapping)
12. [Resources](#resources)

---

## User Account Audit

### Commands

```bash
# List all users
cat /etc/passwd

# List users with shell access
cat /etc/passwd | grep -v nologin | grep -v false

# Find users with UID 0 (root equivalents) - CRITICAL
awk -F: '$3 == 0 {print $1}' /etc/passwd

# Find users without passwords
awk -F: '$2 == "" {print $1}' /etc/shadow

# Check user last login
lastlog

# Find stale users (no login in 90 days)
lastlog | awk '$NF !~ /Never/ && $NF != "" {print}'

# List locked accounts
passwd -S -a | grep "L"

# Check account expiration
chage -l username

# Find users in sudo/wheel group
getent group sudo  # Debian/Ubuntu
getent group wheel # RHEL/CentOS
```

### Key Files to Review

| File | Purpose |
|------|---------|
| /etc/passwd | User accounts |
| /etc/shadow | Password hashes |
| /etc/group | Group memberships |
| /etc/gshadow | Group passwords |
| /etc/login.defs | Login defaults |

### Security Checks

- [ ] No UID 0 accounts besides root
- [ ] No empty passwords
- [ ] No users with shells that shouldn't have them
- [ ] Stale accounts disabled/removed
- [ ] Service accounts have nologin shell

---

## Password Policy

### Check Current Policy

```bash
# View password aging settings
cat /etc/login.defs | grep -E "PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_MIN_LEN|PASS_WARN_AGE"

# Check PAM password quality (Debian/Ubuntu)
cat /etc/pam.d/common-password

# Check PAM password quality (RHEL)
cat /etc/pam.d/system-auth

# Check pwquality settings
cat /etc/security/pwquality.conf

# Check specific user password settings
chage -l username
```

### Recommended Settings (/etc/login.defs)

```bash
PASS_MAX_DAYS   90      # Maximum password age
PASS_MIN_DAYS   1       # Minimum days between changes
PASS_MIN_LEN    14      # Minimum password length
PASS_WARN_AGE   14      # Warning days before expiry
```

### PAM Configuration (pwquality)

```bash
# /etc/security/pwquality.conf
minlen = 14
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
minclass = 3
maxrepeat = 3
```

---

## Privileged Access (sudo)

### Audit Commands

```bash
# View sudoers file
visudo -c  # Validate syntax
cat /etc/sudoers
ls -la /etc/sudoers.d/

# Find NOPASSWD entries (risky)
grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/

# Check who can sudo
grep -E "^%sudo|^%wheel|ALL.*ALL" /etc/sudoers /etc/sudoers.d/*

# View sudo group members
getent group sudo
getent group wheel

# Check recent sudo usage
cat /var/log/auth.log | grep sudo  # Debian
cat /var/log/secure | grep sudo     # RHEL
```

### Best Practices

```bash
# Example secure sudoers entry
username ALL=(ALL) /usr/bin/systemctl restart nginx

# Instead of dangerous:
# username ALL=(ALL) NOPASSWD: ALL
```

### Security Checks

- [ ] No NOPASSWD entries (unless absolutely required)
- [ ] Specific commands, not ALL
- [ ] Minimal users in sudo/wheel
- [ ] Sudo logging enabled

---

## SSH Configuration

### Audit Commands

```bash
# View SSH configuration
cat /etc/ssh/sshd_config

# Check specific settings
grep -E "^(PermitRootLogin|PasswordAuthentication|PermitEmptyPasswords|Protocol|X11Forwarding|MaxAuthTries|AllowUsers|AllowGroups)" /etc/ssh/sshd_config

# Check SSH key permissions
ls -la ~/.ssh/
stat ~/.ssh/authorized_keys
stat ~/.ssh/id_rsa  # Private key

# Find all authorized_keys files
find /home -name "authorized_keys" 2>/dev/null

# Check SSH daemon status
systemctl status sshd
```

### Recommended Settings (/etc/ssh/sshd_config)

```bash
# Disable root login
PermitRootLogin no

# Use key-based auth only
PasswordAuthentication no
PubkeyAuthentication yes

# Security settings
PermitEmptyPasswords no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

# Protocol 2 only (default in modern SSH)
Protocol 2

# Restrict users (optional)
AllowUsers admin deploy
AllowGroups ssh-users
```

### Security Checks

- [ ] PermitRootLogin no
- [ ] PasswordAuthentication no (use keys)
- [ ] PermitEmptyPasswords no
- [ ] X11Forwarding no (unless needed)
- [ ] Key permissions: 600 for private, 644 for public

---

## Network Security

### Audit Commands

```bash
# List listening services
ss -tuln
netstat -tuln

# List all network connections
ss -tuna
netstat -tuna

# Check routing table
ip route
route -n

# Check IP forwarding status
cat /proc/sys/net/ipv4/ip_forward

# Check network interfaces
ip addr
ifconfig -a

# DNS configuration
cat /etc/resolv.conf

# Hosts file
cat /etc/hosts
```

### Sysctl Security Settings

```bash
# Check current values
sysctl -a | grep -E "net.ipv4.ip_forward|net.ipv4.conf.all.accept_redirects|net.ipv4.conf.all.accept_source_route"

# Recommended settings (/etc/sysctl.conf)
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
```

---

## Firewall Configuration

### iptables

```bash
# List all rules
iptables -L -n -v
iptables -L -n --line-numbers

# Save rules
iptables-save > /etc/iptables.rules

# Check for default policies
iptables -L | grep policy
```

### UFW (Ubuntu)

```bash
# Check status
ufw status verbose

# List rules
ufw status numbered

# Default policies
ufw default deny incoming
ufw default allow outgoing
```

### firewalld (RHEL/CentOS)

```bash
# Check status
firewall-cmd --state

# List zones
firewall-cmd --get-active-zones

# List rules
firewall-cmd --zone=public --list-all

# List services
firewall-cmd --list-services
```

### Security Checks

- [ ] Default policy is DROP/DENY
- [ ] Only necessary ports open
- [ ] No 0.0.0.0:22 if possible
- [ ] Rate limiting on SSH

---

## SELinux/AppArmor

### SELinux

```bash
# Check status
getenforce
sestatus

# List SELinux booleans
getsebool -a

# Check for denials
ausearch -m avc -ts recent
cat /var/log/audit/audit.log | grep denied

# Fix common issues
restorecon -Rv /path/to/directory
```

### AppArmor

```bash
# Check status
aa-status

# List profiles
aa-status --profiles

# Check for denials
cat /var/log/kern.log | grep apparmor
dmesg | grep apparmor
```

### Security Checks

- [ ] SELinux in Enforcing mode OR AppArmor active
- [ ] No significant denials in logs
- [ ] Custom policies for applications

---

## File Permissions

### Critical File Checks

```bash
# Check critical file permissions
stat /etc/passwd  # Should be 644
stat /etc/shadow  # Should be 600 or 640
stat /etc/gshadow # Should be 600 or 640
stat /etc/group   # Should be 644

# Find world-writable files
find / -type f -perm -o+w 2>/dev/null

# Find SUID files
find / -type f -perm -4000 2>/dev/null

# Find SGID files
find / -type f -perm -2000 2>/dev/null

# Check home directory permissions
ls -la /home/

# Find files without owner
find / -nouser -o -nogroup 2>/dev/null
```

### Security Checks

- [ ] /etc/passwd: 644
- [ ] /etc/shadow: 600
- [ ] Home directories: 700 or 750
- [ ] No unexpected SUID/SGID files
- [ ] No world-writable files in /etc

---

## Patch Management

### Debian/Ubuntu

```bash
# Update package list
apt update

# List available updates
apt list --upgradable

# Security updates only
apt list --upgradable | grep -i security

# Apply updates
apt upgrade
apt full-upgrade

# Check for reboot required
cat /var/run/reboot-required
```

### RHEL/CentOS

```bash
# Check for updates
yum check-update

# Security updates only
yum check-update --security

# Apply updates
yum update
yum update --security

# Check needs-restarting
needs-restarting -r
```

### Kernel Check

```bash
# Current kernel
uname -r

# Installed kernels
dpkg --list | grep linux-image  # Debian
rpm -qa kernel                   # RHEL
```

---

## Logging and Auditing

### Log Locations

| Log | Location |
|-----|----------|
| Auth logs | /var/log/auth.log (Debian) /var/log/secure (RHEL) |
| System log | /var/log/syslog or /var/log/messages |
| Audit log | /var/log/audit/audit.log |
| Boot log | /var/log/boot.log |
| Kernel log | /var/log/kern.log |

### Audit Commands

```bash
# Check auditd status
systemctl status auditd

# List audit rules
auditctl -l

# Recent authentication attempts
grep "Failed password" /var/log/auth.log
grep "Accepted" /var/log/auth.log

# Check for log tampering
ls -la /var/log/
```

### Security Checks

- [ ] Auditd running
- [ ] Logs being rotated (logrotate)
- [ ] Remote syslog configured
- [ ] Log permissions restricted

---

## Compliance Mapping

### CIS Benchmarks

| Section | Topic |
|---------|-------|
| 1 | Initial Setup |
| 2 | Services |
| 3 | Network Configuration |
| 4 | Logging and Auditing |
| 5 | Access, Authentication, Authorization |
| 6 | System Maintenance |

### SOC 2

| Control | Linux Feature |
|---------|---------------|
| CC6.1 | User accounts, authentication |
| CC6.6 | Endpoint security, patching |
| CC7.2 | Logging, auditd |

### NIST 800-53

| Control | Linux Feature |
|---------|---------------|
| AC-2 | Account management |
| AC-6 | Least privilege (sudo) |
| AU-2 | Audit logging |
| CM-6 | Configuration management |
| IA-5 | Password policy |

---

## Resources

### Official Documentation

- [Ubuntu Security Guide](https://ubuntu.com/security)
- [Red Hat Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html/security_hardening/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks)

### Tools

- [Lynis](https://cisofy.com/lynis/) - Security auditing tool
- [OpenSCAP](https://www.open-scap.org/) - Security compliance
- [AIDE](https://aide.github.io/) - File integrity monitoring
- [Tiger](https://www.nongnu.org/tiger/) - Security audit

---

*Document Version: 2.0.0 | Last Updated: 2025-01-26*
