#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import re
import warnings
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl, quote, quote_plus, urljoin
import httpx
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed
from playwright.async_api import async_playwright
from dom_cleaner import filter_dom_redirect

R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
M = "\033[35m"
C = "\033[36m"
W = "\033[0m"

BANNER = f"""{C}
  ____          _     _      _____                      
 |  _ \\ ___  __| | __| | ___|__  /___ _ __ ___  ___ ___ 
 | |_) / _ \\/ _` |/ _` |/ _ \\ / // _ \\ '__/ _ \\/ __/ __|
 |  _ <  __/ (_| | (_| |  __// /|  __/ | |  __/\\__ \\__ \\
 |_| \\_\\___|\\__,_|\\__,_|\\___/____\\___|_|  \\___||___/___/
                                                       
{Y}           ReddeZeress — Open Redirect Scanner
{M}                  by DevSecOpter
{W}"""

DEFAULT_UA = "ReddeZeress (+security-testing)"
REDIR_PARAMS = {
    "next", "url", "target", "dest", "destination", "redir", "redirect", "redirect_url",
    "redirect_to", "redirect_uri", "out", "link", "to", "r", "u", "go", "return", "returnTo",
    "return_to", "continue", "continueTo", "continue_to", "checkout_url", "callback", "cb",
    "forward", "nav", "NavigationTarget", "relay", "referer", "ref", "ret", "page", "jump",
    "path", "image_url", "folder", "view", "login_url", "from_url", "service", "sso_redirect",
    "state", "ru", "SAMLRequest", "RelayState", "OpenId.RedirectUri", "oauth_redirect",
    "oauth_callback", "post_login_redirect", "ReturnUrl", "ReturnURL", "returnurl", "ReturnURI",
    "returnuri", "return_path", "ext_url", "ext", "external"
}
  
DENYLIST = {
    "facebook.com", "google.com", "instagram.com", "t.co", "twitter.com",
    "x.com", "linkedin.com", "bit.ly", "goo.gl", "vk.com", "ok.ru", "t.me", "telegram.me",
    "discord.gg", "discord.com", "youtube.com", "youtu.be"
}
      
META_REFRESH_RE = re.compile(
    r'<meta[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)', re.I
)

JS_REDIRECT_RE = re.compile(
    r'(?:location\.href|location\.assign|location\.replace|window\.location)\s*=\s*["\']([^"\']+)["\']', re.I
)

NAV_KEYWORDS = ["location", "href", "assign", "replace", "open", "navigate"]
def norm_netloc(n):
    return n.split(":")[0].lower() if ":" in n else n.lower()

def same_host(a, b):
    return norm_netloc(urlparse(a).netloc) == norm_netloc(urlparse(b).netloc)

def is_external(start, final):
    a = urlparse(start)
    b = urlparse(final)
    return bool(b.netloc) and not same_host(start, final)

def in_denylist(u):
    d = norm_netloc(urlparse(u).netloc)
    parts = d.split(".")
    return any(".".join(parts[i:]) in DENYLIST for i in range(len(parts) - 1))

def join_query(url, new_params):
    p = urlparse(url)
    base = dict(parse_qsl(p.query, keep_blank_values=True))
    base.update(new_params)
    return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, urlencode(base, doseq=True), p.fragment))

def gen_variants(dest):
    d_net = urlparse(dest).netloc or dest
    return [dest, f"//{d_net}", quote_plus(dest, safe=""), quote(dest, safe="")]

def fetch_static(client, url):
    try:
        r = client.get(url, follow_redirects=False)
        if "location" in r.headers:
            return ("direct", r.headers["location"], r.text)
        body = r.text or ""
        if m := META_REFRESH_RE.search(body):
            return ("meta", m.group(1), body)
        if j := JS_REDIRECT_RE.search(body):
            return ("js_assign", j.group(1), body)
        return (None, None, body)
    except:
        return (None, None, "")

def extract_paths_and_params(base_url, ua, timeout, max_pages=25):
    seen = set()
    paths = set()
    params = set()
    q = [base_url]
    transport = httpx.HTTPTransport(retries=2)
    client = httpx.Client(http2=True, transport=transport, timeout=timeout, headers={"User-Agent": ua})
    while q and len(seen) < max_pages:
        u = q.pop(0)
        if u in seen:
            continue
        seen.add(u)
        try:
            r = client.get(u)
        except:
            continue
        if not same_host(base_url, str(r.url)):
            continue
        if r.status_code >= 400:
            continue
        soup = BeautifulSoup(r.text, "html.parser")
        for tag in soup(["a", "link", "script", "img", "form"]):
            href = tag.get("href") or tag.get("src") or ""
            if not href:
                continue
            link = urljoin(u, href)
            if not same_host(base_url, link):
                continue
            pu = urlparse(link)
            paths.add(pu.path or "/")
            for k, _ in parse_qsl(pu.query, keep_blank_values=True):
                if 1 <= len(k) <= 50:
                    params.add(k)
            if tag.name == "form":
                act = urljoin(u, tag.get("action") or "")
                if act and same_host(base_url, act):
                    paths.add(urlparse(act).path or "/")
        for a in soup.find_all("a", href=True):
            link = urljoin(u, a["href"])
            if same_host(base_url, link) and link not in seen:
                q.append(link)
    client.close()
    return list(paths) or ["/"], list(params)

def looks_promising(body, params):
    if not body:
        return False
    low = body.lower()
    return "<script" in low and any(k in low for k in NAV_KEYWORDS) and any(p.lower() in low for p in params)

INIT_HOOK = r"""
(() => {
  try {
    const log=(k,u)=>{try{window.__nav_hits.push({kind:k,url:String(u||''),ts:Date.now()});}catch(e){}};
    window.__nav_hits=[];
    const _setTimeout=window.setTimeout.bind(window);
    window.setTimeout=(fn,t,...rest)=>_setTimeout(fn,Math.min(Number(t)||0,200),...rest);
    const mk=(fn,k)=>function(u){try{const val=(typeof u==='string')?u:(u&&(u.href||u.url))||'';log(k,val);}catch(e){}return fn.apply(this,arguments);};
    try{const loc=window.location;const a=loc.assign.bind(loc),r=loc.replace.bind(loc);Object.defineProperty(window.location,'assign',{value:mk(a,'assign')});Object.defineProperty(window.location,'replace',{value:mk(r,'replace')});Object.defineProperty(window.location,'href',{set(v){log('location.href=set',v);return r(String(v));},get(){return loc.toString();}});}catch(e){}
    try{const open=window.open.bind(window);window.open=mk(open,'open');}catch(e){}
    try{const A=HTMLAnchorElement.prototype;const origClick=A.click;A.click=mk(origClick,'a.click');}catch(e){}
    try{const meta=document.querySelector('meta[http-equiv=\"refresh\" i]');if(meta){const c=meta.getAttribute('content')||'';const m=c.match(/url=([^;]+)/i);if(m)log('meta-refresh',m[1]);}}catch(e){}
  }catch(e){}
})();
"""
async def dom_worker(pw, queue, ua, findings, pbar):
    browser = await pw.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox", "--disable-setuid-sandbox",
            "--disable-dev-shm-usage", "--disable-gpu",
            "--disable-software-rasterizer", "--mute-audio"
        ]
    )
    ctx = await browser.new_context(user_agent=ua)
    page = await ctx.new_page()  

    try:
        while True:
            url = await queue.get()
            if url is None:
                queue.task_done()
                break

            base_host = urlparse(url).netloc.lower()
            hit = None
            rel_nav = None
            popup_url = None
            found = False

            def on_request(req):
                nonlocal hit
                try:
                    if req.resource_type == "document":
                        h = urlparse(req.url).netloc.lower()
                        if h and h != base_host and not in_denylist(req.url):
                            hit = hit or req.url
                except:
                    pass

            def on_response(resp):
                nonlocal hit
                try:
                    if 300 <= resp.status < 400:
                        loc = resp.headers.get("location")
                        if loc and is_external(url, loc) and not in_denylist(loc):
                            hit = hit or loc
                except:
                    pass

            async def on_popup(p):
                nonlocal popup_url
                try:
                    await p.wait_for_load_state("domcontentloaded", timeout=2000)
                except:
                    pass
                try:
                    u = p.url
                    if is_external(url, u) and not in_denylist(u):
                        popup_url = popup_url or u
                except:
                    pass

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("popup", lambda p: asyncio.create_task(on_popup(p)))
            await page.add_init_script(INIT_HOOK)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=1500)
            except:
                pass
            await page.wait_for_timeout(400)

            



            try:
                if await filter_dom_redirect(page, url):
                    final = page.url
                    if is_external(url, final) and not in_denylist(final):
                        findings.append((url, final, "dom-filter"))
                        tqdm.write(f"{M}[+] DOM FILTER{W} {url} -> {final}")
                        found = True
            except Exception as e:
                tqdm.write(f"{R}[!] DOM FILTER ERROR{W} {url} → {e}")  
            #if not await filter_dom_redirect(page, url):
                #return

            final = page.url
            if is_external(url, final) and not in_denylist(final):
                findings.append((url, final, "dom"))
                tqdm.write(f"{M}[+] DOM redirect{W} {url} -> {final}")
                found = True

            if not found:
                try:
                    nav_hits = await page.evaluate("window.__nav_hits || []")
                except:
                    nav_hits = []
                chosen = None
                for h in nav_hits:
                    u = (h.get("url") or "").strip()
                    if not u:
                        continue
                    try:
                        absu = str((await page.evaluate("(u)=>new URL(u, location.href).href", u)))
                    except:
                        absu = u
                    if is_external(url, absu) and not in_denylist(absu):
                        chosen = absu
                        break
                    elif absu.startswith(urlparse(url).scheme + "://" + base_host):
                        rel_nav = absu
                if chosen:
                    findings.append((url, chosen, "dom-hook"))
                    tqdm.write(f"{M}[+] DOM HOOK{W} {url} -> {chosen}")
                    found = True

            if not found and rel_nav:
                try:
                    await page.goto(rel_nav, wait_until="domcontentloaded", timeout=1500)
                except:
                    pass
                await page.wait_for_timeout(400)
                final2 = page.url
                if is_external(url, final2) and not in_denylist(final2):
                    findings.append((url, final2, "dom-rel"))
                    tqdm.write(f"{M}[+] DOM REL{W} {url} -> {final2}")
                    found = True

            if not found and popup_url:
                findings.append((url, popup_url, "dom-popup"))
                tqdm.write(f"{M}[+] DOM POPUP{W} {url} -> {popup_url}")
                found = True

            if not found and hit:
                findings.append((url, hit, "dom-net"))
                tqdm.write(f"{M}[+] DOM NET{W} {url} -> {hit}")
                found = True

            pbar.update(1)
            queue.task_done()
    finally:
        await page.close()
        await ctx.close()
        await browser.close()

async def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url")
    g.add_argument("-L", "--list")
    ap.add_argument("--dest", default="https://example.com")
    ap.add_argument("-t", "--timeout", type=float, default=5.0)
    ap.add_argument("-T", "--threads", type=int, default=50)
    ap.add_argument("--ua", default=DEFAULT_UA)
    ap.add_argument("--dom-workers", type=int, default=12)
    ap.add_argument("--max-pages", type=int, default=25)
    args = ap.parse_args()

    print(BANNER)

    raw_bases = [args.url.strip()] if args.url else [
        x.strip() for x in open(args.list, encoding="utf-8", errors="ignore")
        if x.strip() and not x.startswith("#")
    ]

    valid_bases = []
    for b in raw_bases:
        p = urlparse(b)
        if p.scheme and p.netloc:
            base = b if (p.path and p.path != "/") else (p.scheme + "://" + p.netloc + "/")
            valid_bases.append(base)

    if not valid_bases:
        print(f"{R}[-] No valid base URLs{W}")
        return

    all_paths = set()
    all_params = set()
    for base in valid_bases:
        paths, params = extract_paths_and_params(base, args.ua, args.timeout, max_pages=args.max_pages)
        all_paths.update(paths)
        all_params.update(params)

    target_params = list(all_params & REDIR_PARAMS) or list(REDIR_PARAMS)

    targets = []
    for base in valid_bases:
        basep = urlparse(base)
        for path in (all_paths or {"/"}):
            u = urlunparse((basep.scheme, basep.netloc, path, "", "", ""))
            for p in target_params:
                for v in gen_variants(args.dest):
                    targets.append(join_query(u, {p: v}))
    targets = list(dict.fromkeys(targets))

    findings = []
    dom_candidates = []

    transport = httpx.HTTPTransport(retries=2)
    client = httpx.Client(http2=True, transport=transport, timeout=args.timeout, headers={"User-Agent": args.ua})

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(fetch_static, client, u): u for u in targets}
        for fut in tqdm(as_completed(futures), total=len(futures), desc="Static scan", unit="url"):
            src = futures[fut]
            kind, hit, body = fut.result()
            if kind in ("direct", "meta", "js_assign") and hit:
                if is_external(src, hit) and not in_denylist(hit):
                    findings.append((src, hit, "static"))
                    tqdm.write(f"{G}[+] Static redirect{W} {src} -> {hit}")
            else:
                if looks_promising(body, target_params):
                    dom_candidates.append(src)

    client.close()
    dom_candidates = list(dict.fromkeys(dom_candidates))

    if dom_candidates:
        from asyncio import Queue
        q = Queue()
        for u in dom_candidates:
            await q.put(u)
        pbar = tqdm(total=len(dom_candidates), desc="DOM scan", unit="url")
        async with async_playwright() as pw:
            tasks = [asyncio.create_task(dom_worker(pw, q, args.ua, findings, pbar)) for _ in range(max(1, args.dom_workers))]
            for _ in range(len(tasks)):
                await q.put(None)
            await asyncio.gather(*tasks, return_exceptions=True)
        pbar.close()

    print("\n" + "-" * 60)
    print(f"{Y}Static targets scanned:{W} {len(targets)}")
    print(f"{Y}DOM candidates:{W} {len(dom_candidates)}")
    print(f"{M}Results:{W} {len(findings)} finding(s)")
    for s1, f, t in findings:
        print(f"- {t.upper()}: {s1} -> {f}")

if __name__ == "__main__":
    asyncio.run(main())
