# Coding Conventions & Standards

**Author:** Joe Romaine | [JoeRomaine.com](https://JoeRomaine.com)
**Applies to:** All scripts in this repository
**Last Updated:** 2025

---

## Overview

Every script in this arsenal follows a standardized format. This ensures consistency, auditability, and operational reliability across all tools regardless of language.

---

## PowerShell (.ps1) Standard Template

```powershell
<#
.SYNOPSIS
    Verb-Noun.ps1 — One-line description of what this script does

.DESCRIPTION
    Detailed description of the script's purpose, what it audits/reports/modifies,
    and what output it produces.

.AUTHOR
    Joe Romaine
    https://JoeRomaine.com

.VERSION
    1.0.0

.DATE
    YYYY-MM-DD

.REQUIREMENTS
    - Required PowerShell modules (e.g., Az, ExchangeOnlineManagement)
    - Minimum permissions needed
    - PowerShell version requirements

.EXAMPLE
    .\Verb-Noun.ps1
    .\Verb-Noun.ps1 -OutputPath "C:\Reports\output.csv"

.OUTPUTS
    CSV report to $OutputPath
    Log file to $LogPath
#>

[CmdletBinding()]
param(
    [Parameter(HelpMessage = "Path for the output report")]
    [string]$OutputPath = "$env:USERPROFILE\Documents\ScriptName_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv",

    [Parameter(HelpMessage = "Optional parameter description")]
    [string]$OptionalParam = "default"
)

# ============================================================================
# CONFIGURATION
# ============================================================================
$ScriptName = "Verb-Noun"
$ScriptVersion = "1.0.0"
$LogPath = "C:\Scripts\$ScriptName.log"
if (-not (Test-Path (Split-Path $LogPath))) {
    New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
}

# ============================================================================
# FUNCTIONS
# ============================================================================
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $Entry = "[$Timestamp] [$Level] $Message"
    Add-Content -Path $LogPath -Value $Entry -Force
    $Color = switch ($Level) {
        "INFO"    { "Cyan" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
    }
    Write-Host $Entry -ForegroundColor $Color
}

# ============================================================================
# BANNER
# ============================================================================
Write-Host @"

 ╔══════════════════════════════════════════════════════════════════╗
 ║  $ScriptName
 ║  Version $ScriptVersion — Joe Romaine — JoeRomaine.com
 ╚══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Log "========== $ScriptName Started ==========" -Level "INFO"

# ============================================================================
# MODULE CHECKS
# ============================================================================
$RequiredModules = @("ModuleName")
foreach ($Module in $RequiredModules) {
    if (-not (Get-Module -Name $Module -ListAvailable)) {
        Write-Log "Installing $Module module..." -Level "WARNING"
        Install-Module -Name $Module -Force -Scope CurrentUser -AllowClobber
    }
    Import-Module $Module -ErrorAction Stop
}

# ============================================================================
# MAIN LOGIC
# ============================================================================
$Results = @()

try {
    # Core script operations here
    Write-Log "Executing primary operations..." -Level "INFO"
}
catch {
    Write-Log "Error: $($_.Exception.Message)" -Level "ERROR"
}

# ============================================================================
# OUTPUT
# ============================================================================
if ($Results.Count -gt 0) {
    $Results | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "`nTotal Results: $($Results.Count)" -ForegroundColor White
    Write-Host "Report: $OutputPath" -ForegroundColor Green
}
else {
    Write-Log "No results found." -Level "WARNING"
}

Write-Log "========== $ScriptName Completed ==========" -Level "SUCCESS"
```

### PowerShell Conventions

| Rule | Standard |
|------|----------|
| **Naming** | `Verb-Noun.ps1` using approved PowerShell verbs (`Get-`, `Set-`, `New-`, `Remove-`, `Export-`, etc.) |
| **Parameters** | Always use `[CmdletBinding()]` and `param()` block with type declarations |
| **Help** | Comment-based help (`.SYNOPSIS`, `.DESCRIPTION`, `.AUTHOR`, `.VERSION`, `.DATE`) |
| **Logging** | `Write-Log` function with INFO/WARNING/ERROR/SUCCESS levels |
| **Banner** | Box-drawn banner with script name and version |
| **Error handling** | `try/catch` blocks around external calls |
| **Output** | Export to CSV with timestamp in filename |
| **Log location** | Windows: `C:\Scripts\`, Linux/Mac: `~/Documents/Scripts/` |

---

## Bash (.sh) Standard Template

```bash
#!/bin/bash
#==============================================================================
# script-name.sh — One-line description
#==============================================================================
# Description:  Detailed description of what this script does
# Author:       Joe Romaine — https://JoeRomaine.com
# Version:      1.0.0
# Date:         YYYY-MM-DD
#
# Requirements:
#   - Root or sudo privileges (if needed)
#   - Required packages (e.g., nmap, jq, curl)
#
# Usage:
#   ./script-name.sh
#   ./script-name.sh --output /path/to/report.txt
#==============================================================================

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================
readonly SCRIPT_NAME="script-name"
readonly SCRIPT_VERSION="1.0.0"
readonly LOG_DIR="${HOME}/Documents/Scripts"
readonly LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
readonly REPORT_FILE="${LOG_DIR}/${SCRIPT_NAME}_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$LOG_DIR"

# ============================================================================
# FUNCTIONS
# ============================================================================
log() {
    local level="${1:-INFO}"
    local message="${2:-}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

banner() {
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║  ${SCRIPT_NAME}"
    echo "║  Version ${SCRIPT_VERSION} — Joe Romaine — JoeRomaine.com"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo ""
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "WARNING" "This script should be run as root for full functionality"
        read -p "Continue without root? (y/n): " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
}

check_dependencies() {
    local deps=("$@")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            log "ERROR" "Required dependency not found: $dep"
            exit 1
        fi
    done
}

# ============================================================================
# MAIN
# ============================================================================
main() {
    banner
    log "INFO" "========== ${SCRIPT_NAME} Started =========="

    # Dependency checks
    check_dependencies "grep" "awk"

    # Core operations here
    log "INFO" "Executing primary operations..."

    {
        echo "Report: ${SCRIPT_NAME}"
        echo "Generated: $(date)"
        echo "========================================"
        # Report content here
    } > "$REPORT_FILE"

    # Summary
    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "Report: $REPORT_FILE"
    echo "Log:    $LOG_FILE"
    echo "═══════════════════════════════════════════════════════════════"

    log "SUCCESS" "========== ${SCRIPT_NAME} Completed =========="
}

main "$@"
```

### Bash Conventions

| Rule | Standard |
|------|----------|
| **Naming** | `kebab-case.sh` (lowercase, hyphens) |
| **Shebang** | `#!/bin/bash` always first line |
| **Safety** | `set -euo pipefail` immediately after header |
| **Variables** | `readonly` for constants, `local` inside functions, `UPPER_SNAKE_CASE` for globals |
| **Functions** | `snake_case()` names, `main()` as entry point |
| **Header** | Comment block with description, author, version, date, requirements, usage |
| **Logging** | `log()` function with level and message, tee to log file |
| **Dependencies** | `check_dependencies()` function verifying required commands |
| **Quoting** | Always quote variables: `"$var"` not `$var` |

---

## Python (.py) Standard Template

```python
#!/usr/bin/env python3
"""
script_name.py — One-line description

Description:
    Detailed description of what this script does, what inputs it takes,
    and what outputs it produces.

Author:     Joe Romaine — https://JoeRomaine.com
Version:    1.0.0
Date:       YYYY-MM-DD

Requirements:
    - Python 3.9+
    - Required packages: flask, requests (see requirements.txt)

Usage:
    python script_name.py
    python script_name.py --port 8080
"""

import argparse
import logging
import sys
from datetime import datetime
from pathlib import Path

# ============================================================================
# CONFIGURATION
# ============================================================================
SCRIPT_NAME = "script_name"
SCRIPT_VERSION = "1.0.0"
LOG_DIR = Path.home() / "Documents" / "Scripts"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"{SCRIPT_NAME}.log"

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(SCRIPT_NAME)


# ============================================================================
# FUNCTIONS
# ============================================================================
def banner() -> None:
    """Display the script banner."""
    print("╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  {SCRIPT_NAME}")
    print(f"║  Version {SCRIPT_VERSION} — Joe Romaine — JoeRomaine.com")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description=f"{SCRIPT_NAME} — Security tool description",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=LOG_DIR / f"{SCRIPT_NAME}_{datetime.now():%Y%m%d_%H%M%S}.txt",
        help="Output report path",
    )
    return parser.parse_args()


# ============================================================================
# MAIN
# ============================================================================
def main() -> None:
    """Main entry point."""
    args = parse_args()
    banner()
    logger.info("========== %s Started ==========", SCRIPT_NAME)

    try:
        # Core operations here
        logger.info("Executing primary operations...")

    except Exception:
        logger.exception("Unhandled error during execution")
        sys.exit(1)

    logger.info("Report: %s", args.output)
    logger.info("========== %s Completed ==========", SCRIPT_NAME)


if __name__ == "__main__":
    main()
```

### Python Conventions

| Rule | Standard |
|------|----------|
| **Naming** | `snake_case.py` for files, `snake_case` for functions/variables, `PascalCase` for classes |
| **Shebang** | `#!/usr/bin/env python3` |
| **Docstring** | Module-level docstring with description, author, version, date, requirements, usage |
| **Type hints** | Use type hints on function signatures |
| **Logging** | `logging` module with file + stdout handlers |
| **Arguments** | `argparse` for CLI tools, sensible defaults |
| **Entry point** | `if __name__ == "__main__": main()` pattern |
| **Dependencies** | `requirements.txt` per project/directory |
| **Error handling** | `try/except` with `logger.exception()` for unhandled errors |

---

## General Rules (All Languages)

1. **Author block** must include `Joe Romaine` and `JoeRomaine.com`
2. **Version** follows semantic versioning: `MAJOR.MINOR.PATCH`
3. **Date** in ISO format: `YYYY-MM-DD`
4. **Logging** always writes to both file and console
5. **Destructive operations** require user confirmation before execution
6. **Output files** include timestamp in filename to prevent overwrites
7. **No hardcoded credentials** -- use environment variables, config files, or interactive prompts
8. **Module/package checks** run before main logic
9. **Banner** displayed at script start with name and version
10. **Exit cleanly** with appropriate status codes (0 = success, 1 = error)
