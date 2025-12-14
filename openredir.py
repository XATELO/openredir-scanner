#!/usr/bin/env python3
import argparse
import requests
import urllib3
import re
import sys
import html
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, Style, init
from tqdm import tqdm

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
MARKER = "devsecopter.com"
TIMEOUT = 10

BANNER = f"""{Fore.CYAN}
  ____          _     _      _____                      
 |  _ \\ ___  __| | __| | ___|__  /___ _ __ ___  ___ ___ 
 | |_) / _ \\/ _` |/ _` |/ _ \\ / // _ \\ '__/ _ \\/ __/ __|
 |  _ <  __/ (_| | (_| |  __// /|  __/ | |  __/\\__ \\__ \\
 |_| \\_\\___|\\__,_|\\__,_|\\___/____\\___|_|  \\___||___/___/
                                                       
{Fore.YELLOW}        ReddeZeress — Open Redirect Scanner
{Fore.MAGENTA}                by DevSecOpter
{Style.RESET_ALL}"""


PAYLOADS = [
    f"http://{MARKER}",
    f"https://{MARKER}",
    f"//{MARKER}",
    f"///{MARKER}",
    f"\\/\\/{MARKER}",
    f"http:{MARKER}",
    f"https:{MARKER}",
    f"http://{MARKER}%2f",
    f"http%3a%2f%2f{MARKER}",
    f"//%2f%2f{MARKER}",
]

PATHS = [
    "/", "/redirect", "/redirect-to", "/redirect.php", "/login", "/user/login", 
    "/auth/login", "/logout", "/out", "/go", "/exit", "/link", "/click", 
    "/forward", "/jump", "/signin", "/signout", "/track", "/trace", "/nav", 
    "/return", "/connect", "/account", "/auth", "/callback", "/checkout", 
    "/api/redirect", "/v1/redirect", "/r", "/u", "/l", "/img", "/proxy"
]

PARAMS = [
    "next", "url", "target", "dest", "destination", "redirect", "redirect_uri", 
    "redirect_url", "redirect_to", "return", "return_to", "return_path", "return_url",
    "r", "u", "link", "go", "uri", "path", "continue", "view", "out", "image_url",
    "go_to", "to", "site", "html", "val", "validate", "domain", "callback", 
    "returnUrl", "returnUri", "service", "sp", "q", "query", "src", "source"
]

IGNORE_SIGS = [
    "access denied", "forbidden", "cloudflare", "captcha", "security check", 
    "unauthorized", "not found", "block id", "incident", "waf", "403", "406"
]

session = requests.Session()
retry_strategy = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"]
)
adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retry_strategy)
session.mount("http://", adapter)
session.mount("https://", adapter)
session.headers.update({'User-Agent': USER_AGENT})

def generate_vectors(url):
    if not url.startswith('http'): url = 'https://' + url
    try:
        parsed = urlparse(url)
    except:
        return []

    vectors = []
    q = parse_qs(parsed.query)

    if q:
        for p in q:
            for pl in PAYLOADS:
                qd = q.copy()
                qd[p] = pl
                vectors.append(urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(qd, doseq=True), parsed.fragment)))
                
                base = urlencode(q, doseq=True)
                raw = re.sub(f"({re.escape(p)}=)([^&]*)", f"\\1{pl}", base)
                vectors.append(urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, raw, parsed.fragment)))
    else:
        root = parsed.path if parsed.path else "/"
        targets = PATHS if (root == "/" or root == "") else [root]
        
        for path in targets:
            clean_path = path if path.startswith("/") else "/" + path
            for param in PARAMS:
                for pl in PAYLOADS:
                    vectors.append(urlunparse((parsed.scheme, parsed.netloc, clean_path, "", urlencode({param: pl}), "")))
                    vectors.append(urlunparse((parsed.scheme, parsed.netloc, clean_path, "", f"{param}={pl}", "")))

    return list(set(vectors))

def check(url, verbose):
    try:
        # Jitter для обхода WAF
        time.sleep(random.uniform(0.1, 0.3))
        
        req = requests.Request('GET', url)
        prepped = session.prepare_request(req)
        res = session.send(prepped, verify=False, timeout=TIMEOUT, allow_redirects=False)

        if res.status_code in [301, 302, 303, 307, 308]:
            loc = res.headers.get('Location', '')
            if verbose: tqdm.write(f"{Fore.CYAN}[DEBUG 3xx] {url} -> {loc}")
            
            try:
                dec_loc = unquote(loc).strip()
            except:
                dec_loc = loc.strip()

            if any(dec_loc.startswith(x) for x in [f"http://{MARKER}", f"https://{MARKER}", f"//{MARKER}", f"http:{MARKER}", f"https:{MARKER}"]):
                return f"{Fore.GREEN}[+] HEADER: {Style.RESET_ALL}{url} -> {Fore.YELLOW}{loc}"
            
            try:
                if urlparse(dec_loc).netloc == MARKER:
                    return f"{Fore.GREEN}[+] HEADER: {Style.RESET_ALL}{url} -> {Fore.YELLOW}{loc}"
            except: pass

        if res.status_code == 200:
            if MARKER in res.text:
                body = html.unescape(res.text).lower()
                if any(x in body for x in IGNORE_SIGS): return None
                
                if re.search(r'<meta[^>]*refresh[^>]*url=([^"\'>]*)', res.text, re.IGNORECASE):
                    if MARKER in re.search(r'<meta[^>]*refresh[^>]*url=([^"\'>]*)', res.text, re.IGNORECASE).group(1):
                        return f"{Fore.GREEN}[+] META: {Style.RESET_ALL}{url}"
                
                dom_pat = re.compile(r'(location\s*[=\(]|open\s*\()', re.IGNORECASE)
                if dom_pat.search(body):
                    return f"{Fore.RED}[+] DOM: {Style.RESET_ALL}{url} -> {Fore.YELLOW}JS Sink"

    except Exception as e:
        if verbose: tqdm.write(f"{Fore.RED}[ERR] {url}: {e}")
    return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("-l", "--list", help="List file")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads (Default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose")
    args = parser.parse_args()

    urls = []
    if args.url: urls.append(args.url)
    if args.list:
        try:
            with open(args.list) as f: urls.extend([x.strip() for x in f if x.strip()])
        except: sys.exit(1)
            
    if not urls: sys.exit(1)

    tasks = []
    print(f"{Fore.BLUE}[*] Generating vectors...")
    for u in urls:
        tasks.extend(generate_vectors(u))

    print(f"{Fore.BLUE}[*] Vectors: {len(tasks)}")
    print(f"{Fore.BLUE}[*] Scanning with {args.threads} threads (Auto-Retry enabled)...")
    
    found = 0
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(check, t, args.verbose): t for t in tasks}
        for future in tqdm(as_completed(futures), total=len(tasks), unit="req", ncols=85, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
            res = future.result()
            if res:
                tqdm.write(res)
                found += 1

    print(f"\n{Fore.BLUE}[*] Findings: {found}")

if __name__ == "__main__":
    main()