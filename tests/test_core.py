"""
Basic import and unit tests — no network required.
Run: python3 -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ctf_toolkit.core import find_flags, find_secrets, analyze_response
from ctf_toolkit.wordlist import build_endpoints, build_params, ENDPOINTS, PARAMETERS


# ── Flag detection ──────────────────────────────────────────────────────────

def test_find_standard_flags():
    text = "You got it! flag{s3cr3t_f0und} well done"
    assert "flag{s3cr3t_f0und}" in find_flags(text)

def test_find_thm_flag():
    assert "THM{abc123}" in find_flags("Here is THM{abc123}")

def test_find_htb_flag():
    assert "HTB{xyz_789}" in find_flags("HTB{xyz_789}")

def test_no_false_positives():
    assert find_flags("no flags here, just normal text") == []


# ── Secret detection ────────────────────────────────────────────────────────

def test_jwt_detection():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.signature"
    secrets = find_secrets(f"token: {jwt}")
    assert "JWT" in secrets

def test_api_key_detection():
    text = 'api_key="abcdef1234567890abcd"'
    secrets = find_secrets(text)
    assert "API Key" in secrets


# ── Wordlist builder ────────────────────────────────────────────────────────

def test_build_endpoints_includes_defaults():
    wl = build_endpoints()
    assert "admin" in wl
    assert "flag" in wl
    assert "api/v1" in wl

def test_build_endpoints_custom_names():
    wl = build_endpoints(custom_names=["myparam"])
    assert "myparam" in wl

def test_build_params_includes_defaults():
    params = build_params()
    assert "id" in params
    assert "token" in params

def test_build_params_custom():
    params = build_params(custom_params=["ctf_id"])
    assert "ctf_id" in params

def test_wordlist_no_duplicates():
    wl = build_endpoints()
    assert len(wl) == len(set(wl))
