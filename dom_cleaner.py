import re
from bs4 import BeautifulSoup
import jsbeautifier

WHITELIST = [
    "youtube.com", "youtube-nocookie.com", "vimeo.com",
    "facebook.com", "twitter.com", "linkedin.com"
]

def is_whitelisted(url: str) -> bool:
    return any(domain in url for domain in WHITELIST)

def find_js_redirects(js_code: str) -> bool:
    patterns = [
        r'location\.(href|assign|replace)\s*=\s*',
        r'window\.location\.(href|assign|replace)\s*=\s*',
        r'(top|self)\.location\.(href|assign|replace)\s*=\s*',
        r'window\.open\s*\(',
        r'document\.location\s*=\s*',
        r'setTimeout\s*\(\s*function\s*\(\)\s*{[^}]*location\.',
        r'eval\s*\(\s*["\'].*location\.',
        r'window\s*\.\s*location\s*\.\s*href\s*=\s*["\']',
        r'window\s*\[\s*[\'"]location[\'"]\s*\]\s*\[\s*[\'"]href[\'"]\s*\]\s*=\s*["\']'

    ]
    return any(re.search(p, js_code, re.I | re.S) for p in patterns)

async def filter_dom_redirect(page, final_url: str) -> bool:
    try:
        await page.wait_for_load_state("networkidle", timeout=5000)
        html = await page.content()
        soup = BeautifulSoup(html, "html.parser")

        if is_whitelisted(final_url):
            if soup.find("iframe", src=True) or soup.find("embed", src=True):
                return False

        scripts = soup.find_all("script")
        for script in scripts:
            raw_code = script.get_text()
            if raw_code:
                try:
                    beautified = jsbeautifier.beautify(raw_code)
                    if find_js_redirects(raw_code) or find_js_redirects(beautified):
                        print(f"[JS REDIRECT FOUND] {final_url} → {raw_code[:100]}...")
                        return True
                except Exception as js_err:
                    print(f"[JSBEAUTIFIER ERROR] {final_url} → {js_err}")

        for tag in soup.find_all(True):
            for attr in tag.attrs:
                if attr.startswith("on"):
                    js_code = tag.attrs[attr]
                    if find_js_redirects(js_code):
                        print(f"[INLINE JS REDIRECT] {final_url} → {js_code[:100]}...")
                        return True

        try:
            nav_hits = await page.evaluate("window.__nav_hits || []")
            for hit in nav_hits:
                url = hit.get("url", "")
                if url and not is_whitelisted(url):
                    print(f"[HOOK REDIRECT] {final_url} → {url}")
                    return True
        except Exception as e:
            print(f"[NAV_HITS ERROR] {final_url} → {e}")

        return False

    except Exception as e:
        print(f"[DOM-CLEANER ERROR] {final_url} → {e}")
        return False
