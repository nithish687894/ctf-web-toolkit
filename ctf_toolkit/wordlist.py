"""
CTF Toolkit - Wordlist Builder
Generate smart wordlists for fuzzing and scanning.

Usage:
  python3 wordlist.py --custom-names admin,flag,secret --api-style --save wl.txt
  python3 wordlist.py --custom-names player,game --depth 2 --save endpoints.txt
  python3 wordlist.py --params --custom-params token,role --save params.txt
"""
import argparse, sys, os
sys.path.insert(0, os.path.dirname(__file__))
from core import *

ENDPOINTS = [
    "api","api/v1","api/v2","api/v3","v1","v2","v3","rest","graphql","gql","swagger","openapi",
    "auth","login","logout","register","signup","signin","session","oauth","token","refresh",
    "verify","activate","reset","forgot","password","2fa","mfa","otp","sso","callback","authorize",
    "user","users","profile","account","me","self","whoami","settings","preferences","upload",
    "admin","administrator","dashboard","panel","console","manage","management","control",
    "superadmin","root","sudo","staff","moderator","internal","private","restricted",
    "data","export","import","download","file","files","documents","report","reports",
    "analytics","stats","statistics","metrics","logs","log","audit","events","history","archive",
    "create","read","update","delete","edit","modify","remove","add","new","list","get","set",
    "search","find","query","filter","sort","page","paginate","browse","explore","lookup",
    "items","products","orders","posts","comments","messages","categories","tags","groups",
    "roles","permissions","keys","secrets","config","configuration","env","environment",
    "flag","flags","challenge","hint","hints","submit","score","scoreboard","leaderboard",
    "debug","test","testing","dev","development","staging","sandbox","demo","health",
    "status","ping","info","version","about","help","docs","documentation","monitor",
    "backup","backups","bak","old","temp","tmp","cache","dump","sql","db","database",
    "robots.txt","sitemap.xml",".env",".git",".git/config",".git/HEAD",".htaccess",".DS_Store",
    "wp-admin","wp-login.php","wp-json","server-status",".well-known",
    "actuator","actuator/env","actuator/health","actuator/mappings",
    "phpinfo.php","info.php","swagger.json","openapi.json",
    "flag.txt","secret.txt","admin.txt","package.json","requirements.txt","Dockerfile",
]

PARAMETERS = [
    "id","ID","uid","user_id","userId","username","user","name","email","password","passwd",
    "pass","token","auth","key","api_key","apikey","secret","session","sid","cookie",
    "q","query","search","s","keyword","term","text","input","filter","sort","order",
    "page","p","limit","offset","start","count","size","per_page",
    "file","filename","path","filepath","dir","url","uri","href","link","src","source",
    "dest","target","redirect","redirect_url","redirect_uri","return","return_url",
    "next","continue","goto","to","from","ref",
    "data","content","body","message","msg","comment","note","title","description",
    "value","val","type","category","tag","status","state","action","cmd","command",
    "exec","run","code","payload","template","tpl","view","render","format","output",
    "callback","jsonp","num","number","amount","pid","gid","rid","cid","oid",
    "flag","answer","solution","submit","check","verify","debug","test","admin","role",
    "level","access","privilege","is_admin","isAdmin","group",
    "include","require","load","read","write","open","show","lang","language","locale",
    "host","hostname","ip","port","server","proxy","xml","json","yaml","log","config",
]

COMMON_CREDS = [
    ("admin","admin"),("admin","password"),("admin","admin123"),("admin","123456"),
    ("root","root"),("root","toor"),("test","test"),("user","user"),("guest","guest"),
    ("admin","flag"),("admin","secret"),("admin",""),("administrator","administrator"),
    ("admin","P@ssw0rd"),("root","password"),("user","password"),
]

HTTP_METHODS = ["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD","TRACE"]

def build_endpoints(custom_names=None, custom_endpoints=None, api_style=True, depth=1):
    w = set(ENDPOINTS)
    if custom_endpoints: w.update(custom_endpoints)
    if custom_names:
        for n in custom_names:
            w.update([n, n.lower(), n.upper()])
            if api_style:
                for pfx in ["api","api/v1","api/v2","v1","v2",""]:
                    b = f"{pfx}/{n}" if pfx else n
                    for sfx in ["","s","/list","/all","/1","/0","/info","/details",
                                "/admin","/config","/debug","/status","/new","/create",
                                "/delete","/update","/edit","/export","/search","/flag"]:
                        w.add(f"{b}{sfx}")
    if depth >= 2:
        bw = list(w)[:50]
        for w1 in ["api","api/v1","api/v2","admin","internal","debug","v1","v2"]:
            for w2 in bw[:30]:
                if w1 != w2 and "/" not in w2: w.add(f"{w1}/{w2}")
    return sorted(w)

def build_params(custom_params=None):
    w = set(PARAMETERS)
    if custom_params:
        w.update(custom_params)
        for p in custom_params: w.update([p.lower(), p.upper(), f"_{p}", f"{p}_id"])
    return sorted(w)

def load_file(filepath):
    words = []
    try:
        with open(filepath, "r", errors="ignore") as f:
            for l in f:
                l = l.strip()
                if l and not l.startswith("#"): words.append(l)
        success(f"Loaded {len(words)} from {filepath}")
    except FileNotFoundError: error(f"Not found: {filepath}")
    return words

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CTF Wordlist Builder")
    ap.add_argument("--custom-names", help="Your keywords, comma-separated")
    ap.add_argument("--custom-endpoints", help="Your endpoints, comma-separated")
    ap.add_argument("--custom-params", help="Your param names, comma-separated")
    ap.add_argument("--api-style", action="store_true", help="Generate API path variations")
    ap.add_argument("--depth", type=int, default=1, help="Combination depth (1-3)")
    ap.add_argument("--params", action="store_true", help="Generate parameter wordlist")
    ap.add_argument("--save", help="Save to file")
    args = ap.parse_args()

    section("WORDLIST BUILDER")
    cn = args.custom_names.split(",") if args.custom_names else None
    ce = args.custom_endpoints.split(",") if args.custom_endpoints else None

    if args.params:
        cp = args.custom_params.split(",") if args.custom_params else None
        wl = build_params(cp)
        success(f"Generated {len(wl)} parameters")
    else:
        wl = build_endpoints(cn, ce, args.api_style, args.depth)
        success(f"Generated {len(wl)} endpoints")

    for w in wl[:50]: print(f"    {w}")
    if len(wl) > 50: print(f"    ... +{len(wl)-50} more")

    if args.save:
        with open(args.save, "w") as f: f.write("\n".join(wl))
        success(f"Saved → {args.save}")
