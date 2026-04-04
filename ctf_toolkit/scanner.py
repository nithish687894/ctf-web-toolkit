"""
CTF Toolkit - Parameter Scanner
Find hidden parameters on any endpoint.

Usage:
  python3 scanner.py -u http://target.com/api/status
  python3 scanner.py -u http://target.com/api/status --all-methods
  python3 scanner.py -u http://target.com/page --custom-params role,debug,token
  python3 scanner.py -u http://target.com/api --param-values admin,true,1
"""
import argparse, hashlib, sys, os, time, urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
sys.path.insert(0, os.path.dirname(__file__))
from core import *
from wordlist import build_params, HTTP_METHODS

class ParamScanner:
    def __init__(self, url, sess, threads=10, delay=0):
        self.url = url; self.sess = sess
        self.threads = threads; self.delay = delay
        self.found = []; self.flags = []

    def get_baseline(self):
        r, e = safe_request(self.sess, "GET", self.url)
        if e: error(f"Unreachable: {e}"); return None
        return {"status": r.status_code, "length": len(r.content),
                "hash": hashlib.md5(r.content).hexdigest()}

    def test_param(self, param, bl, method="GET", values=None):
        if not values:
            values = ["1","admin","true","test","' OR 1=1--","{{7*7}}",
                      "<script>alert(1)</script>","../etc/passwd","${7*7}",
                      "0","-1","null","[]","{}","999999"]
        for v in values:
            if self.delay: time.sleep(self.delay)
            if method == "GET":
                sep = "&" if "?" in self.url else "?"
                r, e = safe_request(self.sess, "GET",
                    f"{self.url}{sep}{param}={urllib.parse.quote(str(v))}")
            else:
                r, e = safe_request(self.sess, method, self.url, data={param: v},
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
            if e: continue

            diff = []
            if r.status_code != bl["status"]: diff.append(f"sts={r.status_code}")
            if abs(len(r.content) - bl["length"]) > 50: diff.append(f"Δsz={len(r.content)-bl['length']}")
            if hashlib.md5(r.content).hexdigest() != bl["hash"] and not diff: diff.append("body_changed")

            if diff:
                clr = C.G if r.status_code == 200 else C.Y
                print(f"    {clr}[HIT]{C.X}  {param}={v[:30]:30s}  sts={r.status_code}  sz={len(r.content)}  ({', '.join(diff)})")
                fi = analyze_response(r); show_findings(fi, "          ")
                self.flags.extend(fi["flags"])
                self.found.append({"param":param,"value":v,"method":method,
                                   "status":r.status_code,"diff":", ".join(diff)})

    def scan(self, param_list, methods, values=None):
        section("PARAMETER SCANNER")
        info(f"Target: {self.url}")
        info(f"Params: {len(param_list)} | Methods: {methods}")
        bl = self.get_baseline()
        if not bl: return []
        info(f"Baseline: sts={bl['status']}, sz={bl['length']}\n")

        for m in methods:
            info(f"Testing {m}...")
            if self.threads > 1 and not self.delay:
                with ThreadPoolExecutor(max_workers=self.threads) as ex:
                    fs = {ex.submit(self.test_param, p, bl, m, values): p for p in param_list}
                    for f in as_completed(fs):
                        try: f.result()
                        except: pass
            else:
                for p in param_list: self.test_param(p, bl, m, values)

        print()
        success(f"Found {len(self.found)} responsive parameters")
        for f in set(self.flags): flag(f)
        return self.found

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Parameter Scanner")
    add_common_args(ap)
    ap.add_argument("--methods", nargs="+", default=["GET"], help="HTTP methods")
    ap.add_argument("--all-methods", action="store_true", help="All HTTP methods")
    ap.add_argument("--custom-params", help="Your param names (comma-sep)")
    ap.add_argument("--param-values", help="Custom test values (comma-sep)")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()
    sess = session_from_args(args)
    cp = args.custom_params.split(",") if args.custom_params else None
    pv = args.param_values.split(",") if args.param_values else None
    methods = HTTP_METHODS if args.all_methods else [m.upper() for m in args.methods]

    results = ParamScanner(args.url, sess, args.threads, args.delay).scan(build_params(cp), methods, pv)
    save_results({"parameters": results}, args.output)
