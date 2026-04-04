#!/usr/bin/env python3
"""
CTF Web Toolkit — Entry Point
Run any module from a single command.

Usage:
  python3 -m ctf_toolkit recon   -u http://target.com
  python3 -m ctf_toolkit fuzz    -u http://target.com --smart
  python3 -m ctf_toolkit scan    -u http://target.com/api/user
  python3 -m ctf_toolkit vuln    -u http://target.com
  python3 -m ctf_toolkit auth    -u http://target.com
  python3 -m ctf_toolkit full    -u http://target.com
  python3 -m ctf_toolkit words   --custom-names admin,flag --save wl.txt
"""
import sys, os

COMMANDS = {
    "recon":  ("ctf_toolkit.recon",    "Recon module — headers, files, JS, crawl"),
    "fuzz":   ("ctf_toolkit.fuzzer",   "Fuzzer  module — endpoint discovery"),
    "scan":   ("ctf_toolkit.scanner",  "Scanner module — hidden parameter discovery"),
    "vuln":   ("ctf_toolkit.vulnscan", "VulnScan module — SQLi, XSS, SSTI, LFI, SSRF …"),
    "auth":   ("ctf_toolkit.authtest", "Auth module — JWT, cookies, default creds"),
    "full":   ("ctf_toolkit.fullscan", "Full scan — runs everything"),
    "words":  ("ctf_toolkit.wordlist", "Wordlist builder"),
}

def print_help():
    print("\n  CTF Web Toolkit v3.0\n")
    print("  Usage: python3 -m ctf_toolkit <command> [options]\n")
    print("  Commands:")
    for cmd, (_, desc) in COMMANDS.items():
        print(f"    {cmd:<8}  {desc}")
    print("\n  Run any command with -h for full options.\n")

if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help", "help"):
    print_help()
    sys.exit(0)

cmd = sys.argv[1].lower()
if cmd not in COMMANDS:
    print(f"\n  Unknown command: {cmd}")
    print_help()
    sys.exit(1)

# Remove the sub-command so the target module sees a clean argv
sys.argv = [f"ctf_toolkit/{cmd}"] + sys.argv[2:]

module_name, _ = COMMANDS[cmd]
import importlib
mod = importlib.import_module(module_name)
