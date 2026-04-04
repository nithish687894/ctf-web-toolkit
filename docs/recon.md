# Recon Module

Performs full passive and active reconnaissance on a target before exploitation.

## What it checks

| Check | Details |
|-------|---------|
| HTTP Headers | Server info, security headers, missing CSP/HSTS/X-Frame-Options |
| Sensitive Files | `.env`, `.git/config`, `robots.txt`, `swagger.json`, `flag.txt`, 30+ more |
| HTTP Methods | OPTIONS, TRACE, PUT, DELETE — flags dangerous methods like XST |
| JavaScript Parsing | Extracts endpoints, API paths, secrets, and tokens from `.js` files |
| Link Crawling | Finds all same-domain links on the page |

## Usage

```bash
# Basic recon
python3 -m ctf_toolkit recon -u http://target.com

# Save results
python3 -m ctf_toolkit recon -u http://target.com -o recon.json

# Through Burp proxy
python3 -m ctf_toolkit recon -u http://target.com --proxy http://127.0.0.1:8080

# With auth
python3 -m ctf_toolkit recon -u http://target.com --cookie "session=abc123"
python3 -m ctf_toolkit recon -u http://target.com --auth-token "eyJhbGci..."
```

## CTF Tip

Always run recon first. The `robots.txt`, `.git/config`, and `swagger.json` files
alone have won many CTF challenges. JS parsing often leaks internal API routes.
