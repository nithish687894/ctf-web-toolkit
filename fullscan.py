"""
CTF Toolkit - Full Scan (runs everything)
Master script that combines all tools.

Usage:
  python3 fullscan.py -u http://target.com
  python3 fullscan.py -u http://target.com --custom-names admin,flag --smart
  python3 fullscan.py -u http://target.com --all-methods --depth 2 -o report.json
"""
import argparse, json, sys, os
from datetime import datetime
sys.path.insert(0, os.path.dirname(__file__))
from core import *
from wordlist import build_endpoints, build_params, HTTP_METHODS
from fuzzer import Fuzzer
from scanner import ParamScanner
from vulnscan import VulnScanner
from authtest import AuthTester
from recon import Recon

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Full Scan - Run All Tools")
    add_common_args(ap)
    ap.add_argument("--depth", type=int, default=1, help="Fuzz depth")
    ap.add_argument("--smart", action="store_true", help="Smart fuzzing")
    ap.add_argument("--methods", nargs="+", default=["GET"])
    ap.add_argument("--all-methods", action="store_true")
    ap.add_argument("--custom-names", help="Keywords (comma-sep)")
    ap.add_argument("--custom-endpoints", help="Endpoints (comma-sep)")
    ap.add_argument("--custom-params", help="Parameters (comma-sep)")
    ap.add_argument("--api-style", action="store_true")
    ap.add_argument("--skip", help="Skip modules: fuzz,scan,vuln,auth,recon (comma-sep)")
    args = ap.parse_args()

    import urllib3; urllib3.disable_warnings()

    print(f"\n{C.CY}{'═'*60}\n  CTF WEB ULTIMATE TOOLKIT v3.0 - FULL SCAN\n{'═'*60}{C.X}\n")

    sess = session_from_args(args)
    methods = HTTP_METHODS if args.all_methods else [m.upper() for m in args.methods]
    cn = args.custom_names.split(",") if args.custom_names else None
    ce = args.custom_endpoints.split(",") if args.custom_endpoints else None
    cp = args.custom_params.split(",") if args.custom_params else None
    skip = args.skip.split(",") if args.skip else []
    R = {}

    if "recon" not in skip:
        R["recon"] = Recon(args.url, sess).run()

    if "fuzz" not in skip:
        wl = build_endpoints(cn, ce, args.api_style or bool(cn), args.depth)
        R["endpoints"] = Fuzzer(args.url, sess, args.threads, args.delay).run(wl, methods, args.smart)

    if "scan" not in skip:
        sm = methods if args.all_methods else ["GET","POST"]
        R["parameters"] = ParamScanner(args.url, sess, args.threads, args.delay).scan(build_params(cp), sm)

    if "vuln" not in skip:
        R["vulnerabilities"] = VulnScanner(args.url, sess).run()

    if "auth" not in skip:
        R["auth"] = AuthTester(args.url, sess).run()

    # Summary
    section("SCAN COMPLETE")
    te = len(R.get("endpoints",[])); tp = len(R.get("parameters",[]))
    tv = len(R.get("vulnerabilities",[])); ta = len(R.get("auth",[]))
    print(f"    Endpoints:       {C.G}{te}{C.X}")
    print(f"    Parameters:      {C.G}{tp}{C.X}")
    print(f"    Vulnerabilities: {C.R}{tv}{C.X}")
    print(f"    Auth findings:   {C.Y}{ta}{C.X}")

    if args.output:
        R["meta"] = {"target": args.url, "time": datetime.now().isoformat(), "tool": "CTF Toolkit v3.0"}
        with open(args.output, "w") as f: json.dump(R, f, indent=2, default=str)
        print(f"    Report:          {C.CY}{args.output}{C.X}")
    print()
