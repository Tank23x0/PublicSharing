# WebApps — Security Operations Web Tools

**Author:** Joe Romaine | [JoeRomaine.com](https://JoeRomaine.com)
**Classification:** UNCLASSIFIED // INTERNAL USE

---

## Overview

Flask-based web application providing a suite of security operations tools accessible through a browser interface. Designed for blue team operators and penetration testers who need quick access to common security utilities without switching between CLI tools.

## Tools Included

| Tool | Description |
|------|-------------|
| **Log Analyzer** | Parse and search log files for IOCs, suspicious patterns, and anomalies |
| **HTTP Header Scanner** | Analyze security headers of target URLs — CSP, HSTS, X-Frame-Options |
| **Hash Toolkit** | Generate and verify MD5, SHA-1, SHA-256, SHA-512 hashes |
| **Subnet Calculator** | CIDR notation calculator with host enumeration and network details |
| **Base64 Codec** | Encode/decode Base64 strings — useful for analyzing obfuscated payloads |
| **URL Decoder** | Decode URL-encoded strings and analyze query parameters |

## Quick Start

```bash
cd WebApps
pip install -r requirements.txt
python app.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Requirements

- Python 3.9+
- pip packages listed in `requirements.txt`

## Security Notes

- Runs on localhost only by default — do not expose to untrusted networks without additional hardening
- No data is stored server-side — all operations are stateless
- HTTP Header Scanner makes outbound requests to user-specified URLs — use responsibly
