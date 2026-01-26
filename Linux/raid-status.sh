#!/bin/bash
#==============================================================================
# raid-status.sh - Linux System Administration Tool
#==============================================================================
# Description: Professional Linux system administration and audit script
# Author:      Anessen
# Version:     1.0.0
# Date:        2025-01-26
#
# Requirements:
#   - Root or sudo privileges
#   - Standard Linux utilities
#
# Usage:
#   ./raid-status.sh
#==============================================================================

set -euo pipefail

# Configuration
SCRIPT_NAME="raid-status"
LOG_DIR="$HOME/Documents/Scripts"
LOG_FILE="$LOG_DIR/$SCRIPT_NAME.log"
REPORT_FILE="$LOG_DIR/${SCRIPT_NAME}_$(date +%Y%m%d_%H%M%S).txt"

# Create log directory
mkdir -p "$LOG_DIR"

# Logging function
log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Banner
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              LINUX SYSTEM ADMINISTRATION TOOL                    ║"
echo "║                      Version 1.0.0                               ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

log "INFO" "========== $SCRIPT_NAME Started =========="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log "WARNING" "This script should be run as root for full functionality"
    echo "Some functions may require sudo privileges"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Main script logic
log "INFO" "Gathering system information..."

{
    echo "System Report - $(date)"
    echo "========================================"
    echo ""
    echo "Hostname: $(hostname)"
    echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo ""
    echo "CPU Information:"
    lscpu 2>/dev/null | grep -E "Model name|Socket|Core|Thread" || echo "Unable to retrieve CPU info"
    echo ""
    echo "Memory Information:"
    free -h 2>/dev/null || echo "Unable to retrieve memory info"
    echo ""
    echo "Disk Usage:"
    df -h 2>/dev/null || echo "Unable to retrieve disk info"
    echo ""
    echo "Network Interfaces:"
    ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Unable to retrieve network info"
} > "$REPORT_FILE"

log "SUCCESS" "Report generated: $REPORT_FILE"

# Summary
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Report Location: $REPORT_FILE"
echo "Log Location:    $LOG_FILE"
echo "═══════════════════════════════════════════════════════════════"

log "INFO" "========== $SCRIPT_NAME Completed =========="
