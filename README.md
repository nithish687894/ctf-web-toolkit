# CTF Web Toolkit v3.0 — Modular Edition

## 📁 Files

| File | What it does | When to use |
|------|-------------|-------------|
| `core.py` | Shared code + **FLAG FORMATS** | Edit flag formats here |
| `wordlist.py` | Generate wordlists | Before fuzzing / standalone |
| `fuzzer.py` | Find hidden endpoints | Step 1 of any challenge |
| `scanner.py` | Find hidden parameters | After finding endpoints |
| `vulnscan.py` | Test 9 vuln types | Test interesting endpoints |
| `authtest.py` | Crack JWT, test creds | Login/auth challenges |
| `recon.py` | Full recon | First look at target |
| `fullscan.py` | Runs EVERYTHING | When you want it all |

---

## 🚀 Quick Start

```bash
# Run everything at once
python3 fullscan.py -u http://target.com

# With your custom keywords
python3 fullscan.py -u http://target.com --custom-names admin,flag,secret --smart
```

---

## 🔧 Individual Tools

```bash
# 1. Recon (always start here)
python3 recon.py -u http://target.com

# 2. Fuzz endpoints
python3 fuzzer.py -u http://target.com --smart --depth 2
python3 fuzzer.py -u http://target.com --custom-names player,game --api-style

# 3. Scan parameters
python3 scanner.py -u http://target.com/api/status
python3 scanner.py -u http://target.com/api --custom-params role,debug --all-methods

# 4. Test vulnerabilities
python3 vulnscan.py -u http://target.com/api/search
python3 vulnscan.py -u http://target.com --type sqli,ssti,lfi

# 5. Test authentication
python3 authtest.py -u http://target.com
python3 authtest.py -u http://target.com --jwt-only
```

---

## 🏁 Change Flag Format

Edit `core.py` line ~18:
```python
FLAG_FORMATS = [
    r'flag\{[^}]+\}',
    r'MYCTF\{[^}]+\}',   # ← add yours here
    ...
]
```

---

## ⚙️ Common Options (work on all tools)

```
-u URL          Target URL
-t 20           Threads
-d 0.5          Delay between requests
--proxy URL     Send through Burp
--cookie "..."  Add cookie
--auth-token "eyJ..."  Add JWT
--header "X-Key: val"  Custom header
-o file.json    Save results
```
