# PublicSharing — AI Assistant Instructions

## Repository Context
- **Author:** Joe Romaine — JoeRomaine.com
- **Purpose:** Cyber Operations Arsenal — security automation, auditing, and web tools
- **Languages:** PowerShell (.ps1), Bash (.sh), Python (.py)
- **Standards:** See /CONVENTIONS.md for all coding standards

## Code Generation Rules

### All Languages
- Always include the standardized header block from CONVENTIONS.md
- Author line must read: `Joe Romaine` with `https://JoeRomaine.com`
- Include version (semver), date (ISO), and requirements in every header
- Use structured logging with levels: INFO, WARNING, ERROR, SUCCESS
- Include a banner display at script start
- Never hardcode credentials — use environment variables or interactive prompts
- Include module/dependency checks before main logic
- Confirm before destructive operations

### PowerShell
- Use `Verb-Noun.ps1` naming with approved PowerShell verbs
- Always include `[CmdletBinding()]` and `param()` block
- Use comment-based help: `.SYNOPSIS`, `.DESCRIPTION`, `.AUTHOR`, `.VERSION`, `.DATE`
- Include `Write-Log` function with color-coded console output
- Export results to CSV with timestamped filenames
- Log to `C:\Scripts\` on Windows, `~/Documents/Scripts/` on Linux/Mac

### Bash
- Use `kebab-case.sh` naming
- Start with `#!/bin/bash` and `set -euo pipefail`
- Use `readonly` for constants, `local` inside functions
- Include `main()` as entry point pattern
- Always quote variables: `"$var"`
- Include dependency checking with `command -v`

### Python
- Use `snake_case.py` naming
- Start with `#!/usr/bin/env python3` and module docstring
- Use type hints on function signatures
- Use `logging` module (file + stdout handlers)
- Use `argparse` for CLI tools
- Use `if __name__ == "__main__": main()` pattern
- Include `requirements.txt` for dependencies

## Azure Rule
- @azure Rule - Use Azure Best Practices: When generating code for Azure, running terminal commands for Azure, or performing operations related to Azure, invoke your `azure_development-get_best_practices` tool if available.
