"""
heuristics.py
--------------
Rule-based (classic cybersecurity) phishing indicators.
These are checks real security tools use BEFORE ever involving AI —
having this layer shows you understand phishing detection fundamentals,
not just "call an API and print the answer".
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "signin", "webscr", "ebayisapi",
    "suspended", "urgent", "click-here", "reset"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy"
]


def extract_urls(text: str):
    """Pull URLs out of pasted text/email content."""
    url_pattern = r'(https?://[^\s<>"\']+|www\.[^\s<>"\']+)'
    return re.findall(url_pattern, text, flags=re.IGNORECASE)


def analyze_url(url: str) -> dict:
    """
    Runs a set of classic phishing heuristics on a single URL.
    Returns a score (0-100, higher = more suspicious) and the
    list of specific red flags found, so the report can explain WHY.
    """
    flags = []
    score = 0

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.netloc.lower()

    # 1. No HTTPS
    if parsed.scheme != "https":
        flags.append("No HTTPS encryption (uses plain http://)")
        score += 15

    # 2. IP address instead of a domain name
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host.split(':')[0]):
        flags.append("Uses a raw IP address instead of a domain name")
        score += 25

    # 3. '@' symbol trick (browser ignores everything before '@')
    if "@" in url:
        flags.append("Contains '@' symbol (classic URL-masking trick)")
        score += 25

    # 4. Too many subdomains (e.g. paypal.com.verify-login.xyz.com)
    subdomain_count = host.count(".")
    if subdomain_count >= 4:
        flags.append(f"Unusually deep subdomain chain ({subdomain_count} dots)")
        score += 15

    # 5. Known link-shortener (hides real destination)
    if any(short in host for short in SHORTENER_DOMAINS):
        flags.append("Uses a URL shortener (real destination is hidden)")
        score += 10

    # 6. Suspicious keywords in the URL itself
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        flags.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        score += 10 * min(len(found_keywords), 3)

    # 7. Hyphens in domain (common in fake lookalike domains)
    if host.count("-") >= 2:
        flags.append("Domain has multiple hyphens (common in spoofed domains)")
        score += 10

    # 8. Very long URL (often used to hide real domain / obfuscate)
    if len(url) > 75:
        flags.append("Unusually long URL")
        score += 5

    score = min(score, 100)

    return {
        "url": url,
        "heuristic_score": score,
        "flags": flags
    }


def analyze_text(text: str) -> dict:
    """Runs heuristics on every URL found inside a block of text/email."""
    urls = extract_urls(text)
    results = [analyze_url(u) for u in urls]
    return {
        "urls_found": len(urls),
        "results": results
    }
