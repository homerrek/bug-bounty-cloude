#!/usr/bin/env python3
"""
kali_tool_detector.py — Kali Linux security tool detector and health checker.

Detects installed Kali security tools, checks versions, validates configurations,
and provides installation guidance for missing tools.

Usage:
  python3 tools/kali_tool_detector.py
  python3 tools/kali_tool_detector.py --check-all
  python3 tools/kali_tool_detector.py --install-missing
"""

import argparse
import json
import os
import subprocess

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# Comprehensive tool catalog
KALI_TOOLS = {
    "reconnaissance": {
        "nmap": {"package": "nmap", "version_cmd": ["nmap", "--version"], "priority": "high"},
        "masscan": {"package": "masscan", "version_cmd": ["masscan", "--version"], "priority": "medium"},
        "netdiscover": {"package": "netdiscover", "version_cmd": ["netdiscover", "-h"], "priority": "medium"},
        "whatweb": {"package": "whatweb", "version_cmd": ["whatweb", "--version"], "priority": "medium"},
        "subfinder": {"package": None, "install": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "priority": "high"},
        "httpx": {"package": None, "install": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest", "priority": "high"},
    },
    "webapp": {
        "nikto": {"package": "nikto", "version_cmd": ["nikto", "-Version"], "priority": "high"},
        "dirb": {"package": "dirb", "version_cmd": ["dirb"], "priority": "medium"},
        "gobuster": {"package": "gobuster", "version_cmd": ["gobuster", "version"], "priority": "high"},
        "ffuf": {"package": "ffuf", "version_cmd": ["ffuf", "-V"], "priority": "high"},
        "wpscan": {"package": "wpscan", "version_cmd": ["wpscan", "--version"], "priority": "medium"},
        "sqlmap": {"package": "sqlmap", "version_cmd": ["sqlmap", "--version"], "priority": "high"},
        "nuclei": {"package": None, "install": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "priority": "high"},
    },
    "exploitation": {
        "metasploit": {"package": "metasploit-framework", "version_cmd": ["msfconsole", "--version"], "priority": "high"},
        "searchsploit": {"package": "exploitdb", "version_cmd": ["searchsploit", "--version"], "priority": "medium"},
        "sqlmap": {"package": "sqlmap", "version_cmd": ["sqlmap", "--version"], "priority": "high"},
    },
    "password": {
        "john": {"package": "john", "version_cmd": ["john", "--version"], "priority": "medium"},
        "hashcat": {"package": "hashcat", "version_cmd": ["hashcat", "--version"], "priority": "medium"},
        "hydra": {"package": "hydra", "version_cmd": ["hydra", "-h"], "priority": "medium"},
        "medusa": {"package": "medusa", "version_cmd": ["medusa", "-V"], "priority": "low"},
    },
    "wireless": {
        "aircrack-ng": {"package": "aircrack-ng", "version_cmd": ["aircrack-ng", "--version"], "priority": "low"},
        "wifite": {"package": "wifite", "version_cmd": ["wifite", "--help"], "priority": "low"},
        "reaver": {"package": "reaver", "version_cmd": ["reaver", "-h"], "priority": "low"},
    },
    "enumeration": {
        "enum4linux": {"package": "enum4linux", "version_cmd": ["enum4linux"], "priority": "medium"},
        "smbclient": {"package": "smbclient", "version_cmd": ["smbclient", "--version"], "priority": "medium"},
        "ldapsearch": {"package": "ldap-utils", "version_cmd": ["ldapsearch", "-VV"], "priority": "low"},
    },
    "proxies": {
        "burpsuite": {"package": "burpsuite", "priority": "high"},
        "zaproxy": {"package": "zaproxy", "version_cmd": ["zaproxy", "-version"], "priority": "high"},
    }
}


def check_tool(tool_name, tool_info):
    """Check if a tool is installed and get version"""
    try:
        # Check if command exists
        result = subprocess.run(["which", tool_name], capture_output=True, timeout=5)
        if result.returncode != 0:
            return {"installed": False, "version": None}

        # Try to get version
        version = None
        if "version_cmd" in tool_info:
            try:
                version_result = subprocess.run(
                    tool_info["version_cmd"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                # Extract version from output (first line usually)
                version_output = version_result.stdout or version_result.stderr
                version = version_output.split("\n")[0] if version_output else "Unknown"
            except Exception:
                version = "Installed (version unknown)"

        return {"installed": True, "version": version}

    except Exception:
        return {"installed": False, "version": None}


def detect_os():
    """Detect if running on Kali Linux"""
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release", "r") as f:
                content = f.read()
                if "kali" in content.lower():
                    return "kali"
                elif "debian" in content.lower() or "ubuntu" in content.lower():
                    return "debian-based"
                else:
                    return "other"
    except Exception:
        pass
    return "unknown"


def check_wordlists():
    """Check for common wordlist locations"""
    wordlist_paths = [
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists",
        "/usr/share/wordlists",
    ]

    found = []
    missing = []

    for path in wordlist_paths:
        if os.path.exists(path):
            found.append(path)
        else:
            missing.append(path)

    return found, missing


def generate_install_script(missing_tools, os_type):
    """Generate installation script for missing tools"""
    script_lines = ["#!/bin/bash", "", "# Auto-generated installation script", ""]

    if os_type == "kali" or os_type == "debian-based":
        script_lines.append("# Update package list")
        script_lines.append("sudo apt update")
        script_lines.append("")

        # Group by installation method
        apt_tools = []
        go_tools = []
        other = []

        for category, tools in missing_tools.items():
            for tool_name, tool_info in tools.items():
                if "package" in tool_info and tool_info["package"]:
                    apt_tools.append(tool_info["package"])
                elif "install" in tool_info:
                    if "go install" in tool_info["install"]:
                        go_tools.append((tool_name, tool_info["install"]))
                    else:
                        other.append((tool_name, tool_info["install"]))

        if apt_tools:
            script_lines.append("# Install via apt")
            script_lines.append(f"sudo apt install -y {' '.join(set(apt_tools))}")
            script_lines.append("")

        if go_tools:
            script_lines.append("# Install Go tools")
            script_lines.append("# Requires Go: https://golang.org/doc/install")
            for tool_name, cmd in go_tools:
                script_lines.append(f"# {tool_name}")
                script_lines.append(cmd)
            script_lines.append("")

        if other:
            script_lines.append("# Other installations")
            for tool_name, cmd in other:
                script_lines.append(f"# {tool_name}")
                script_lines.append(cmd)

    else:
        script_lines.append("# Platform-specific installation required")
        script_lines.append("# Visit: https://www.kali.org/tools/")

    return "\n".join(script_lines)


def main():
    parser = argparse.ArgumentParser(description="Kali tool detector and health checker")
    parser.add_argument("--check-all", action="store_true", help="Check all tools (not just high priority)")
    parser.add_argument("--install-missing", action="store_true", help="Generate install script for missing tools")
    parser.add_argument("--category", choices=KALI_TOOLS.keys(), help="Check specific category only")
    parser.add_argument("--json", dest="json_out", action="store_true", help="JSON output")
    args = parser.parse_args()

    print(f"\n{BOLD}Kali Tool Detector{RESET}\n")

    # Detect OS
    os_type = detect_os()
    if os_type == "kali":
        print(f"{GREEN}✓ Running on Kali Linux{RESET}\n")
    elif os_type == "debian-based":
        print(f"{YELLOW}⚠ Running on Debian-based system (not Kali){RESET}\n")
    else:
        print(f"{RED}⚠ Not running on Kali or Debian-based system{RESET}\n")

    # Check tools
    results = {}
    missing_tools = {}
    installed_count = 0
    total_count = 0

    categories_to_check = [args.category] if args.category else KALI_TOOLS.keys()

    for category in categories_to_check:
        tools = KALI_TOOLS[category]
        results[category] = {}
        missing_tools[category] = {}

        print(f"{BOLD}{category.upper()}{RESET}")

        for tool_name, tool_info in tools.items():
            # Skip low priority unless --check-all
            if not args.check_all and tool_info.get("priority") == "low":
                continue

            total_count += 1
            status = check_tool(tool_name, tool_info)
            results[category][tool_name] = status

            if status["installed"]:
                installed_count += 1
                version_str = f" ({status['version']})" if status["version"] else ""
                print(f"  {GREEN}✓{RESET} {tool_name}{DIM}{version_str}{RESET}")
            else:
                missing_tools[category][tool_name] = tool_info
                priority_color = RED if tool_info.get("priority") == "high" else YELLOW
                priority_str = f"[{tool_info.get('priority', 'medium').upper()}]"
                print(f"  {priority_color}✗{RESET} {tool_name} {priority_color}{priority_str}{RESET}")

        print()

    # Check wordlists
    print(f"{BOLD}WORDLISTS{RESET}")
    found_wordlists, missing_wordlists = check_wordlists()
    for wl in found_wordlists:
        print(f"  {GREEN}✓{RESET} {wl}")
    for wl in missing_wordlists[:3]:  # Show only first 3
        print(f"  {YELLOW}✗{RESET} {wl}")

    # Summary
    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  Installed: {GREEN}{installed_count}/{total_count}{RESET}")
    print(f"  Missing: {RED}{total_count - installed_count}{RESET}")
    print(f"  Wordlists: {GREEN}{len(found_wordlists)}{RESET} found, {YELLOW}{len(missing_wordlists)}{RESET} missing")

    # Generate install script if requested
    if args.install_missing and missing_tools:
        script_path = "install_missing_tools.sh"
        script = generate_install_script(missing_tools, os_type)

        with open(script_path, "w") as f:
            f.write(script)

        os.chmod(script_path, 0o755)

        print(f"\n{GREEN}Install script generated: {script_path}{RESET}")
        print(f"Run: chmod +x {script_path} && ./{script_path}")

    # JSON output
    if args.json_out:
        output = {
            "os": os_type,
            "installed": installed_count,
            "total": total_count,
            "results": results,
            "wordlists": {
                "found": found_wordlists,
                "missing": missing_wordlists
            }
        }
        print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
