#!/usr/bin/env python3
"""
app.py — Security Operations Web Toolkit

Description:
    Flask-based web application providing a suite of security operations tools:
    log analyzer, HTTP header scanner, hash toolkit, subnet calculator,
    Base64 codec, and URL decoder.

Author:     Joe Romaine — https://JoeRomaine.com
Version:    1.0.0
Date:       2025-01-26

Requirements:
    - Python 3.9+
    - flask, requests (see requirements.txt)

Usage:
    python app.py
    python app.py --port 8080
"""

import argparse
import hashlib
import ipaddress
import logging
import re
import sys
import urllib.parse
from base64 import b64decode, b64encode
from datetime import datetime
from pathlib import Path

from flask import Flask, render_template, request

# ============================================================================
# CONFIGURATION
# ============================================================================
SCRIPT_NAME = "security-webtools"
SCRIPT_VERSION = "1.0.0"
LOG_DIR = Path.home() / "Documents" / "Scripts"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / f"{SCRIPT_NAME}.log"

app = Flask(__name__)

# ============================================================================
# LOGGING
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
# ROUTES
# ============================================================================
@app.route("/")
def index():
    """Main dashboard."""
    return render_template("index.html")


@app.route("/hash", methods=["GET", "POST"])
def hash_toolkit():
    """Generate and verify hashes."""
    result = None
    if request.method == "POST":
        action = request.form.get("action", "generate")
        text = request.form.get("text", "")

        if action == "generate" and text:
            result = {
                "input": text,
                "md5": hashlib.md5(text.encode()).hexdigest(),
                "sha1": hashlib.sha1(text.encode()).hexdigest(),
                "sha256": hashlib.sha256(text.encode()).hexdigest(),
                "sha512": hashlib.sha512(text.encode()).hexdigest(),
            }
            logger.info("Hash generated for input (length=%d)", len(text))

        elif action == "verify":
            known_hash = request.form.get("known_hash", "").strip().lower()
            algorithms = {
                32: ("md5", hashlib.md5),
                40: ("sha1", hashlib.sha1),
                64: ("sha256", hashlib.sha256),
                128: ("sha512", hashlib.sha512),
            }
            algo_info = algorithms.get(len(known_hash))
            if algo_info and text:
                algo_name, algo_func = algo_info
                computed = algo_func(text.encode()).hexdigest()
                result = {
                    "match": computed == known_hash,
                    "algorithm": algo_name,
                    "computed": computed,
                    "provided": known_hash,
                }
            else:
                result = {"error": "Unrecognized hash length or empty input"}

    return render_template("hash.html", result=result)


@app.route("/subnet", methods=["GET", "POST"])
def subnet_calculator():
    """Calculate subnet details from CIDR notation."""
    result = None
    if request.method == "POST":
        cidr = request.form.get("cidr", "").strip()
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            result = {
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address) if network.version == 4 else "N/A (IPv6)",
                "netmask": str(network.netmask) if network.version == 4 else str(network.prefixlen),
                "prefix_length": network.prefixlen,
                "total_hosts": network.num_addresses,
                "usable_hosts": max(0, network.num_addresses - 2) if network.version == 4 and network.prefixlen < 31 else network.num_addresses,
                "first_host": str(network.network_address + 1) if network.num_addresses > 2 else str(network.network_address),
                "last_host": str(network.broadcast_address - 1) if network.version == 4 and network.num_addresses > 2 else str(network.broadcast_address),
                "version": network.version,
                "is_private": network.is_private,
                "cidr": str(network),
            }
            logger.info("Subnet calculated: %s", cidr)
        except ValueError as e:
            result = {"error": str(e)}

    return render_template("subnet.html", result=result)


@app.route("/base64", methods=["GET", "POST"])
def base64_codec():
    """Encode or decode Base64 strings."""
    result = None
    if request.method == "POST":
        action = request.form.get("action", "encode")
        text = request.form.get("text", "")

        if action == "encode" and text:
            encoded = b64encode(text.encode()).decode()
            result = {"action": "Encoded", "input": text, "output": encoded}
        elif action == "decode" and text:
            try:
                decoded = b64decode(text).decode("utf-8", errors="replace")
                result = {"action": "Decoded", "input": text, "output": decoded}
            except Exception as e:
                result = {"error": f"Decode failed: {e}"}

        logger.info("Base64 %s operation performed", action)

    return render_template("base64.html", result=result)


@app.route("/urldecode", methods=["GET", "POST"])
def url_decoder():
    """Decode URL-encoded strings and parse query parameters."""
    result = None
    if request.method == "POST":
        url_string = request.form.get("text", "")
        if url_string:
            decoded = urllib.parse.unquote(url_string)
            parsed = urllib.parse.urlparse(url_string)
            params = urllib.parse.parse_qs(parsed.query)
            result = {
                "original": url_string,
                "decoded": decoded,
                "scheme": parsed.scheme or "N/A",
                "host": parsed.netloc or "N/A",
                "path": parsed.path or "/",
                "params": params,
            }
            logger.info("URL decoded: %s", url_string[:50])

    return render_template("urldecode.html", result=result)


@app.route("/headers", methods=["GET", "POST"])
def header_scanner():
    """Scan HTTP response headers for security configurations."""
    result = None
    if request.method == "POST":
        import requests as req

        target_url = request.form.get("url", "").strip()
        if target_url and not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url

        if target_url:
            try:
                resp = req.get(target_url, timeout=10, allow_redirects=True, verify=True)
                headers = dict(resp.headers)

                security_headers = {
                    "Strict-Transport-Security": {
                        "present": "Strict-Transport-Security" in headers,
                        "value": headers.get("Strict-Transport-Security", "MISSING"),
                        "description": "HSTS — Forces HTTPS connections",
                    },
                    "Content-Security-Policy": {
                        "present": "Content-Security-Policy" in headers,
                        "value": headers.get("Content-Security-Policy", "MISSING"),
                        "description": "CSP — Controls resource loading sources",
                    },
                    "X-Frame-Options": {
                        "present": "X-Frame-Options" in headers,
                        "value": headers.get("X-Frame-Options", "MISSING"),
                        "description": "Clickjacking protection",
                    },
                    "X-Content-Type-Options": {
                        "present": "X-Content-Type-Options" in headers,
                        "value": headers.get("X-Content-Type-Options", "MISSING"),
                        "description": "MIME sniffing prevention",
                    },
                    "X-XSS-Protection": {
                        "present": "X-XSS-Protection" in headers,
                        "value": headers.get("X-XSS-Protection", "MISSING"),
                        "description": "XSS filter (legacy)",
                    },
                    "Referrer-Policy": {
                        "present": "Referrer-Policy" in headers,
                        "value": headers.get("Referrer-Policy", "MISSING"),
                        "description": "Controls referrer information leakage",
                    },
                    "Permissions-Policy": {
                        "present": "Permissions-Policy" in headers,
                        "value": headers.get("Permissions-Policy", "MISSING"),
                        "description": "Controls browser feature access",
                    },
                    "X-Permitted-Cross-Domain-Policies": {
                        "present": "X-Permitted-Cross-Domain-Policies" in headers,
                        "value": headers.get("X-Permitted-Cross-Domain-Policies", "MISSING"),
                        "description": "Cross-domain policy control",
                    },
                }

                present_count = sum(1 for h in security_headers.values() if h["present"])
                total_count = len(security_headers)
                grade = "A" if present_count >= 7 else "B" if present_count >= 5 else "C" if present_count >= 3 else "F"

                result = {
                    "url": target_url,
                    "status_code": resp.status_code,
                    "server": headers.get("Server", "Not disclosed"),
                    "security_headers": security_headers,
                    "score": f"{present_count}/{total_count}",
                    "grade": grade,
                    "all_headers": headers,
                }
                logger.info("Header scan completed: %s (grade=%s)", target_url, grade)

            except req.RequestException as e:
                result = {"error": f"Request failed: {e}"}
                logger.warning("Header scan failed for %s: %s", target_url, e)

    return render_template("headers.html", result=result)


@app.route("/logs", methods=["GET", "POST"])
def log_analyzer():
    """Analyze pasted log entries for suspicious patterns."""
    result = None
    if request.method == "POST":
        log_text = request.form.get("text", "")
        if log_text:
            lines = log_text.strip().split("\n")
            findings = []

            patterns = {
                "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                "URL": r"https?://[^\s\"'>]+",
                "Windows Path": r"[A-Z]:\\(?:[^\\\s\"]+\\)*[^\\\s\"]*",
                "Unix Path": r"(?:/[a-zA-Z0-9._-]+){2,}",
                "MAC Address": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
                "MD5 Hash": r"\b[a-fA-F0-9]{32}\b",
                "SHA256 Hash": r"\b[a-fA-F0-9]{64}\b",
                "Error Keyword": r"(?i)\b(?:error|fail(?:ed|ure)?|denied|unauthorized|forbidden|critical|alert|emergency)\b",
                "Base64 Blob": r"\b[A-Za-z0-9+/]{20,}={0,2}\b",
                "CVE Reference": r"CVE-\d{4}-\d{4,}",
            }

            for pattern_name, regex in patterns.items():
                matches = set(re.findall(regex, log_text))
                if matches:
                    findings.append({
                        "pattern": pattern_name,
                        "count": len(matches),
                        "samples": sorted(matches)[:10],
                    })

            result = {
                "total_lines": len(lines),
                "findings": findings,
                "total_findings": sum(f["count"] for f in findings),
            }
            logger.info("Log analysis: %d lines, %d pattern matches", len(lines), result["total_findings"])

    return render_template("logs.html", result=result)


# ============================================================================
# MAIN
# ============================================================================
def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Security Operations Web Toolkit")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_args()
    print("╔══════════════════════════════════════════════════════════════════╗")
    print(f"║  {SCRIPT_NAME} v{SCRIPT_VERSION}")
    print("║  Joe Romaine — JoeRomaine.com")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print()
    logger.info("========== %s Started on %s:%d ==========", SCRIPT_NAME, args.host, args.port)
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
