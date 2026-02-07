"""
CTF Toolkit - Shared Core Module
All tools import from here. Edit FLAG_FORMATS to add your CTF's flag format.
"""
import base64,hashlib,json,os,re,sys,time,urllib.parse
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    os.system(f"{sys.executable} -m pip install requests --break-system-packages -q")
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

# ╔══════════════════════════════════════════════════════════════╗
# ║  EDIT YOUR FLAG FORMATS HERE                                ║
# ║  Add your CTF's flag format like: r'MYCTF\{[^}]+\}'        ║
# ╚══════════════════════════════════════════════════════════════╝
FLAG_FORMATS = [
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'ctf\{[^}]+\}',
    r'CTF\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'THM\{[^}]+\}',
    r'picoCTF\{[^}]+\}',
    r'DUCTF\{[^}]+\}',
    r'hackdemy\{[^}]+\}',
    r'HACKDEMY\{[^}]+\}',
    r'0xTi\{[^}]+\}',
    r'cybernova\{[^}]+\}',
    r'CYBERNOVA\{[^}]+\}',
    # ──── ADD YOUR FLAG FORMAT BELOW ────
    # r'MYCTF\{[^}]+\}',
    # r'competition2025\{[^}]+\}',
    # ────────────────────────────────────
    r'[A-Za-z0-9_]+\{[A-Za-z0-9_\-!@#$%^&*]+\}',  # generic catch-all (keep last)
]

SECRET_PATTERNS = {
    'JWT':r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    'API Key':r'(?:api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9_\-]{16,})',
    'AWS Key':r'AKIA[0-9A-Z]{16}',
    'Password':r'(?:password|passwd|pwd)["\s:=]+["\']?([^\s"\']{4,})',
    'Token':r'(?:token|secret|auth)["\s:=]+["\']?([A-Za-z0-9_\-\.]{8,})',
    'MD5 Hash':r'\b[a-fA-F0-9]{32}\b',
    'SHA256 Hash':r'\b[a-fA-F0-9]{64}\b',
    'Internal IP':r'(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)',
    'Email':r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
}

# ═══════════════ COLORS ═══════════════
class C:
    R="\033[91m";G="\033[92m";Y="\033[93m";B="\033[94m"
    M="\033[95m";CY="\033[96m";W="\033[97m"
    BOLD="\033[1m";DIM="\033[2m";X="\033[0m"

def info(m):    print(f"  {C.B}[*]{C.X} {m}")
def success(m): print(f"  {C.G}[+]{C.X} {m}")
def warn(m):    print(f"  {C.Y}[!]{C.X} {m}")
def error(m):   print(f"  {C.R}[-]{C.X} {m}")
def flag(m):    print(f"\n  {C.BOLD}{C.G}🚩 FLAG: {m}{C.X}\n")
def vuln(t,d):  print(f"  {C.R}{C.BOLD}[VULN]{C.X} {C.Y}{t}{C.X}: {d}")
def section(t): print(f"\n{C.CY}{'═'*60}\n  {t}\n{'═'*60}{C.X}\n")

# ═══════════════ SESSION ═══════════════
def make_session(proxy=None, cookie=None, token=None, headers=None):
    s = requests.Session()
    a = HTTPAdapter(max_retries=Retry(total=2, backoff_factor=0.3, status_forcelist=[500,502,503]), pool_maxsize=20)
    s.mount("http://", a); s.mount("https://", a)
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8",
    })
    if proxy:  s.proxies = {"http": proxy, "https": proxy}
    if cookie: s.headers["Cookie"] = cookie
    if token:  s.headers["Authorization"] = f"Bearer {token}"
    if headers:
        for h in headers:
            if ":" in h:
                n, v = h.split(":", 1)
                s.headers[n.strip()] = v.strip()
    return s

def safe_request(sess, method, url, timeout=10, **kw):
    try:
        return sess.request(method, url, timeout=timeout, allow_redirects=False, verify=False, **kw), None
    except requests.exceptions.ConnectTimeout: return None, "timeout"
    except requests.exceptions.ConnectionError: return None, "refused"
    except Exception as e: return None, str(e)

# ═══════════════ DETECTION ═══════════════
def find_flags(text):
    found = []
    for pattern in FLAG_FORMATS:
        found.extend(re.findall(pattern, text))
    return list(set(found))

def find_secrets(text):
    found = {}
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, text)
        if matches: found[name] = list(set(matches))[:5]
    return found

def analyze_response(resp):
    """Analyze any HTTP response for flags, secrets, interesting headers."""
    results = {"flags": [], "secrets": {}, "info": []}
    if not resp: return results
    results["flags"] = find_flags(resp.text)
    results["secrets"] = find_secrets(resp.text)
    for h, v in resp.headers.items():
        hl = h.lower()
        if any(x in hl for x in ['x-debug','x-powered','server','x-flag','x-token','x-secret']):
            results["info"].append(f"Header {h}: {v}")
        results["flags"].extend(find_flags(v))
    for c in resp.cookies:
        results["info"].append(f"Cookie: {c.name}={c.value}")
        results["flags"].extend(find_flags(c.value))
    results["flags"] = list(set(results["flags"]))
    return results

def show_findings(findings, prefix=""):
    for f in findings.get("flags", []): flag(f)
    for stype, vals in findings.get("secrets", {}).items():
        for v in vals: success(f"{prefix}[{stype}]: {str(v)[:77]}")
    for i in findings.get("info", [])[:10]: info(f"{prefix}{i}")

# ═══════════════ COMMON ARGS ═══════════════
def add_common_args(parser):
    """Add standard args that every tool uses."""
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--cookie", help="Cookie header value")
    parser.add_argument("--auth-token", help="Bearer token")
    parser.add_argument("--header", action="append", help="Custom header (Name: Value)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")

def session_from_args(args):
    """Create session from parsed args."""
    return make_session(
        proxy=getattr(args, 'proxy', None),
        cookie=getattr(args, 'cookie', None),
        token=getattr(args, 'auth_token', None),
        headers=getattr(args, 'header', None),
    )

def save_results(results, output_file):
    """Save results to JSON."""
    if output_file:
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        success(f"Results saved → {output_file}")
