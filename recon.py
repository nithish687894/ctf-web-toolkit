"""
CTF Toolkit - Recon Engine
Full reconnaissance: headers, sensitive files, JS parsing, link crawling, HTTP methods.

Usage:
  python3 recon.py -u http://target.com
  python3 recon.py -u http://target.com -o recon_results.json
"""
import argparse, re, sys, os, urllib.parse
sys.path.insert(0, os.path.dirname(__file__))
from core import *
from wordlist import HTTP_METHODS

class Recon:
    def __init__(self, url, sess):
        self.url = url.rstrip("/"); self.sess = sess
        self.data = {}; self.flags = []

    def headers(self):
        info("HTTP Headers...")
        r, e = safe_request(self.sess, "GET", self.url)
        if e: error(f"Unreachable: {e}"); return
        for h, v in r.headers.items(): print(f"    {C.CY}{h}{C.X}: {v}")
        print()
        for hdr, desc in {"Strict-Transport-Security":"HSTS","Content-Security-Policy":"CSP",
            "X-Frame-Options":"Clickjack","X-Content-Type-Options":"MIME sniff"}.items():
            if hdr.lower() not in [h.lower() for h in r.headers]: warn(f"Missing: {hdr} ({desc})")
        srv = r.headers.get("Server",""); xpb = r.headers.get("X-Powered-By","")
        if srv: info(f"Server: {srv}")
        if xpb: info(f"Powered: {xpb}")
        fi = analyze_response(r); self.flags.extend(fi["flags"]); show_findings(fi)

    def sensitive_files(self):
        info("Sensitive Files...")
        files = [
            "robots.txt","sitemap.xml",".env",".git/config",".git/HEAD",".htaccess",
            ".htpasswd","web.config","package.json","composer.json","requirements.txt",
            "backup.sql","dump.sql","debug.log","error.log","phpinfo.php","flag.txt",
            "flag","secret.txt","admin.txt","swagger.json","openapi.json",
            "actuator","actuator/env","actuator/health","Dockerfile","docker-compose.yml",
            ".well-known/security.txt","api-docs","swagger.yaml",".dockerenv",
        ]
        found_files = []
        for f in files:
            r, e = safe_request(self.sess, "GET", f"{self.url}/{f}", timeout=5)
            if e or not r: continue
            if r.status_code == 200 and len(r.content) > 0:
                success(f"/{f}  [{len(r.content)}B]")
                fi = analyze_response(r); self.flags.extend(fi["flags"]); show_findings(fi,"      ")
                found_files.append({"file": f, "size": len(r.content), "status": r.status_code})
        self.data["files"] = found_files

    def js_parse(self):
        info("JavaScript Parsing...")
        r, e = safe_request(self.sess, "GET", self.url)
        if e or not r: return
        js_urls = list(set(re.findall(r'(?:src|href)=["\']([^"\']*\.js[^"\']*)["\']', r.text)))
        eps = set(); secs = {}
        for ju in js_urls[:20]:
            if not ju.startswith("http"): ju = urllib.parse.urljoin(self.url, ju)
            r, e = safe_request(self.sess, "GET", ju, timeout=5)
            if e or not r: continue
            info(f"  {ju}")
            for pat in [r'["\']/(api/[^"\'?\s]+)["\']', r'["\']/(v[0-9]/[^"\'?\s]+)["\']',
                r'fetch\(["\']([^"\']+)["\']', r'axios\.\w+\(["\']([^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']', r'\.get\(["\']([^"\']+)["\']',
                r'\.post\(["\']([^"\']+)["\']']:
                eps.update(re.findall(pat, r.text))
            s = find_secrets(r.text)
            for k, v in s.items(): secs.setdefault(k, []).extend(v)
            self.flags.extend(find_flags(r.text))
        if eps:
            success(f"JS endpoints ({len(eps)}):")
            for ep in sorted(eps): print(f"      {C.G}→{C.X} {ep}")
        for st, vs in secs.items():
            for v in set(vs): success(f"JS [{st}]: {str(v)[:60]}")
        self.data["js_endpoints"] = sorted(eps)

    def crawl(self):
        info("Crawling Links...")
        r, e = safe_request(self.sess, "GET", self.url)
        if e or not r: return
        links = set()
        for pat in [r'href=["\']([^"\'#]+)["\']', r'src=["\']([^"\']+)["\']',
                    r'action=["\']([^"\']+)["\']']:
            for m in re.findall(pat, r.text): links.add(urllib.parse.urljoin(self.url, m))
        parsed = urllib.parse.urlparse(self.url)
        same = [l for l in links if urllib.parse.urlparse(l).netloc == parsed.netloc]
        if same:
            success(f"Same-domain links ({len(same)}):")
            for l in sorted(same)[:30]: print(f"      {C.CY}→{C.X} {l}")
        self.data["links"] = sorted(same)

    def methods(self):
        info("HTTP Methods...")
        for m in HTTP_METHODS:
            r, e = safe_request(self.sess, m, self.url)
            if e: continue
            clr = C.G if r.status_code < 400 else C.R
            print(f"    {clr}{m:8s}{C.X} → {r.status_code}")
            if m in ["TRACE","TRACK"] and r.status_code == 200:
                vuln("Method", f"{m} enabled (XST)")

    def run(self):
        section("FULL RECONNAISSANCE")
        info(f"Target: {self.url}\n")
        self.headers(); print()
        self.sensitive_files(); print()
        self.methods(); print()
        self.js_parse(); print()
        self.crawl()
        for f in set(self.flags): flag(f)
        return self.data

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Recon Engine")
    add_common_args(ap)
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()
    sess = session_from_args(args)
    results = Recon(args.url, sess).run()
    save_results(results, args.output)
