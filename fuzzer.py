"""
CTF Toolkit - API Endpoint Fuzzer
Discover hidden endpoints on a target.

Usage:
  python3 fuzzer.py -u http://target.com
  python3 fuzzer.py -u http://target.com --smart --depth 2
  python3 fuzzer.py -u http://target.com --custom-names admin,flag --api-style
  python3 fuzzer.py -u http://target.com --all-methods --smart
  python3 fuzzer.py -u http://target.com --wordlist-file my_words.txt
"""
import argparse, sys, os, time
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(__file__))
from core import *
from wordlist import build_endpoints, load_file, HTTP_METHODS

class Fuzzer:
    def __init__(self, base_url, sess, threads=10, delay=0):
        self.base = base_url.rstrip("/")
        self.sess = sess
        self.threads = threads
        self.delay = delay
        self.found = []
        self.flags = []

    def fuzz_one(self, path, methods):
        url = f"{self.base}/{path.lstrip('/')}"
        for m in methods:
            if self.delay: time.sleep(self.delay)
            r, e = safe_request(self.sess, m, url)
            if e: continue
            if r.status_code not in [404, 502, 503]:
                res = {"url": url, "path": path, "method": m, "status": r.status_code,
                       "length": len(r.content), "type": r.headers.get("Content-Type",""),
                       "redirect": r.headers.get("Location","")}
                sc = r.status_code
                clr = {200:C.G,301:C.CY,302:C.CY,307:C.CY,403:C.Y,405:C.M}.get(sc, C.R if sc>=500 else C.W)
                rd = f" → {res['redirect']}" if res['redirect'] else ""
                print(f"    {clr}{sc}{C.X}  {m:7s}  /{path:40s}  [{res['length']:>6}B]  {res['type'][:30]}{rd}")
                fi = analyze_response(r); show_findings(fi, "      ")
                self.flags.extend(fi["flags"])
                self.found.append(res)

    def run(self, wordlist, methods, smart=False):
        section("API ENDPOINT FUZZER")
        info(f"Target: {self.base}")
        info(f"Words: {len(wordlist)} | Methods: {methods} | Threads: {self.threads}")
        print(f"\n    {'STS':6}  {'METHOD':7}  {'PATH':40}  {'SIZE':>8}  TYPE")
        print(f"    {'─'*6}  {'─'*7}  {'─'*40}  {'─'*8}  {'─'*30}")

        if self.threads > 1 and not self.delay:
            with ThreadPoolExecutor(max_workers=self.threads) as ex:
                fs = {ex.submit(self.fuzz_one, p, methods): p for p in wordlist}
                for f in as_completed(fs):
                    try: f.result()
                    except: pass
        else:
            for p in wordlist: self.fuzz_one(p, methods)

        if smart and self.found:
            info("\n  [SMART] Probing discovered endpoints deeper...")
            known = {e["path"] for e in self.found}
            new_paths = set()
            for ep in self.found:
                b = ep["path"].rstrip("/")
                for sfx in ["/1","/0","/admin","/config","/debug","/status",
                            "/info","/list","/all","/export","/search","/flag",
                            "/new","/edit","/delete","/create"]:
                    p = f"{b}{sfx}"
                    if p not in known: new_paths.add(p)
            for p in sorted(new_paths): self.fuzz_one(p, methods)

        print()
        success(f"Found {len(self.found)} live endpoints")
        for f in set(self.flags): flag(f)
        return self.found

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF API Endpoint Fuzzer")
    add_common_args(ap)
    ap.add_argument("--depth", type=int, default=1, help="Fuzz depth 1-3")
    ap.add_argument("--smart", action="store_true", help="Auto-probe found endpoints deeper")
    ap.add_argument("--methods", nargs="+", default=["GET"], help="HTTP methods")
    ap.add_argument("--all-methods", action="store_true", help="Test all HTTP methods")
    ap.add_argument("--custom-names", help="Your keywords (comma-sep)")
    ap.add_argument("--custom-endpoints", help="Your endpoints (comma-sep)")
    ap.add_argument("--api-style", action="store_true", help="API path variations")
    ap.add_argument("--wordlist-file", help="External wordlist file")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()
    sess = session_from_args(args)
    cn = args.custom_names.split(",") if args.custom_names else None
    ce = args.custom_endpoints.split(",") if args.custom_endpoints else None
    methods = HTTP_METHODS if args.all_methods else [m.upper() for m in args.methods]

    wl = build_endpoints(cn, ce, args.api_style or bool(cn), args.depth)
    if args.wordlist_file: wl = sorted(set(wl + load_file(args.wordlist_file)))

    results = Fuzzer(args.url, sess, args.threads, args.delay).run(wl, methods, args.smart)
    save_results({"endpoints": results}, args.output)
