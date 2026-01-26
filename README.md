# PublicSharing - Security & Sysadmin Script Library

A comprehensive collection of **650+ professional scripts** for security engineers, system administrators, and IT professionals.

## 📁 Repository Structure

| Folder | Description | Scripts |
|--------|-------------|---------|
| `/Microsoft-Exchange/` | Exchange Online & on-prem management | 50 |
| `/Microsoft-Azure/` | Azure resource management & security | 50 |
| `/Microsoft-Entra/` | Identity & access management (formerly Azure AD) | 50 |
| `/Microsoft-Purview/` | Data governance, DLP & compliance | 50 |
| `/Microsoft-Teams/` | Teams administration & auditing | 50 |
| `/Microsoft-365/` | M365 tenant management & secure score | 50 |
| `/CrowdStrike/` | EDR management & threat hunting | 50 |
| `/AWS/` | Amazon Web Services security & management | 50 |
| `/Linux/` | System administration & hardening | 50 |
| `/ActiveDirectory/` | On-premises AD management | 50 |
| `/Zscaler/` | Zero trust network security | 50 |
| `/Jamf/` | Apple device management | 50 |
| `/PowerShell-Bandaid/` | Module management & troubleshooting | 50 |
| `/Custom-Scripts/` | Legacy & miscellaneous scripts | Varies |

## ✨ Script Features

Every script in this library includes:

- **Professional headers** with name, description, author, version, and date
- **Detailed comments** explaining each section
- **User confirmation prompts** before destructive operations
- **Progress indicators** for long-running tasks
- **Comprehensive logging** (Windows: `C:\Scripts\`, Mac/Linux: `~/Documents/Scripts/`)
- **Module dependency checks** with automatic installation
- **Clean, professional output** formatting

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Anessen/PublicSharing.git
   ```

2. Navigate to the desired category folder

3. Review the script header and requirements

4. Run with appropriate permissions:
   ```powershell
   # PowerShell (Windows)
   .\ScriptName.ps1
   
   # Bash (Linux/Mac)
   chmod +x script-name.sh
   ./script-name.sh
   ```

## 📋 Requirements

- **PowerShell 5.1+** or **PowerShell 7+** for Windows scripts
- **Bash 4.0+** for Linux/Mac scripts
- **Python 3.8+** for Python scripts
- Appropriate admin/elevated permissions
- Required modules (installed automatically or prompted)

## 🔒 Security Note

These scripts are provided for **legitimate administrative purposes only**. Always:

- Review scripts before running in production
- Test in a non-production environment first
- Ensure you have proper authorization
- Follow your organization's change management process

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Anessen** - Security Engineer & Systems Administrator

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the existing script format
4. Submit a pull request

---

*Built with ❤️ for the IT community*
