#!/usr/bin/env python3
"""
Example: Standard CTF web challenge workflow.

Step 1 — Recon (gather info, find exposed files/endpoints)
Step 2 — Fuzz (discover hidden API paths)
Step 3 — VulnScan (test promising endpoints)
Step 4 — Auth (test authentication bypass)
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import urllib3
urllib3.disable_warnings()

from ctf_toolkit.core import make_session, section
from ctf_toolkit.recon import Recon
from ctf_toolkit.fuzzer import Fuzzer
from ctf_toolkit.vulnscan import VulnScanner
from ctf_toolkit.authtest import AuthTester
from ctf_toolkit.wordlist import build_endpoints

TARGET = "http://target.com"   # ← change this

sess = make_session()

# 1. Recon
section("STEP 1: RECON")
recon_data = Recon(TARGET, sess).run()

# 2. Fuzz common CTF paths (flag, admin, debug, secret…)
section("STEP 2: FUZZ")
wordlist = build_endpoints(
    custom_names=["flag", "secret", "admin", "debug"],
    api_style=True,
    depth=2,
)
endpoints = Fuzzer(TARGET, sess, threads=15).run(wordlist, ["GET", "POST"], smart=True)

# 3. Vuln-scan each live endpoint
section("STEP 3: VULNSCAN")
for ep in endpoints:
    url = ep["url"]
    VulnScanner(url, sess).run(types=["sqli", "ssti", "lfi", "ssrf"])

# 4. Auth testing
section("STEP 4: AUTH")
AuthTester(TARGET, sess).run()
