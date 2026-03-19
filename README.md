# NuScrape

A web reconnaissance and vulnerability scanner built for responsible disclosure research. NuScrape crawls a target domain, passively enumerates its attack surface, and actively probes for common vulnerability classes — surfacing findings in a real-time web UI backed by a persistent SQLite database.

---

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Usage](#usage)
  - [Command Line](#command-line)
  - [Web UI](#web-ui)
- [What It Detects](#what-it-detects)
  - [Reconnaissance](#reconnaissance)
  - [Vulnerability Checks](#vulnerability-checks)
  - [Alert Severity Levels](#alert-severity-levels)
- [Database](#database)
- [False Positives & Noise Reduction](#false-positives--noise-reduction)
- [Responsible Disclosure](#responsible-disclosure)
- [Workflow](#workflow)

---

## Overview

NuScrape is two components:

- **`main.py`** — the crawler and scanner engine. Run from the command line, or launched and controlled via the web UI.
- **`app.py`** — a Flask web server providing a real-time control panel, live log stream, and tabbed data viewer. Stores all findings in `ScrapeDB` (SQLite).

All findings persist across sessions. Multiple scans accumulate into the same database unless you clear it via the UI.

---

## Installation

**Python dependencies:**

```bash
pip install requests aiohttp flask beautifulsoup4 lxml dnspython python-whois --break-system-packages
```

**Optional — JS rendering for heavily JavaScript-dependent sites:**

```bash
pip install playwright --break-system-packages
playwright install chromium
```

**Optional — enhanced browser fingerprint suppression:**

```bash
pip install playwright-stealth --break-system-packages
```

**Start the web UI:**

```bash
python3 app.py
# Open http://localhost:5000
```

**Or run the scanner directly from the command line:**

```bash
python3 main.py -D https://example.com
```

---

## Usage

### Command Line

```
python3 main.py -D <url> [options]
```

| Flag | Default | Description |
|---|---|---|
| `-D`, `--Domain` | — | Target URL including scheme, e.g. `https://example.com` |
| `--rate-min` | `1.0` | Minimum seconds between requests |
| `--rate-max` | `3.0` | Maximum seconds between requests |
| `--concurrency` | `5` | Number of concurrent async requests |
| `--same-domain-only` | off | Only follow links that stay on the starting domain |
| `--resume` | off | Resume a previously interrupted crawl from saved state |
| `--ignore-robots` | off | Ignore `robots.txt` restrictions |
| `--playwright` | off | Enable Chromium rendering for JS-heavy pages |
| `--no-social` | off | Skip crawling into social media domains |
| `--no-skip-google-tracking` | off | Crawl Google Play and analytics URLs (skipped by default) |
| `--stealth` | `LOUD` | Stealth profile: `LOUD` (fast), `NORMAL` (moderate delays), `GHOST` (slow, rotated UAs, randomised) |
| `--bug-bounty-header` | — | Injects `X-Bug-Bounty: <value>` into all requests — required by some bug bounty programs |
| `--active-probes` | off | Enable payload-injecting checks: path traversal, SSTI, CRLF injection, CORS evil-origin probes, default credential tests, and dangerous HTTP method testing (TRACE/PUT/DELETE/CONNECT). **Only use against targets you are authorised to test.** |

**Examples:**

```bash
# Basic scan
python3 main.py -D https://example.com

# Stay on the target domain, slower rate
python3 main.py -D https://example.com --same-domain-only --rate-min 2 --rate-max 5

# JS-heavy site with Playwright rendering
python3 main.py -D https://app.example.com --playwright --same-domain-only

# Resume an interrupted scan
python3 main.py -D https://example.com --resume

# Ghost mode for low-noise scanning with bug bounty header
python3 main.py -D https://example.com --stealth GHOST --bug-bounty-header "HackerOne-username"

# Full active scan with payload-injecting checks (authorised targets only)
python3 main.py -D https://example.com --active-probes
```

### Web UI

Start `app.py` and open `http://localhost:5000`. The control panel sidebar lets you configure all scan options including stealth profile, bug bounty header, social media filter, Google tracking filter, and active probes. All views update live as the crawler runs.

**Views available in the UI:**

| Tab | Contents |
|---|---|
| Live Log | Real-time crawler output stream |
| Alerts | All vulnerability findings sorted by severity |
| Domains | Discovered domains with IP, ASN, server, title |
| Technologies | Detected tech stack per URL |
| Open Ports | Port scan results with service labels |
| SSL / WHOIS | Certificate details, expiry dates, registrar info |
| Emails | Scraped email addresses |
| DNS / MX | A records and mail exchange records |
| HTTP History | Status codes for all crawled URLs |
| Subdomains | Enumerated subdomains with IP and status |
| Sec Headers | Security header audit per domain |
| XHR Endpoints | API endpoints captured from JS bundles |
| Recon | JS findings: secrets, endpoints, IDOR candidates, JWTs |
| Report / Export | Summary report and CSV/JSON export for all tables |

---

## What It Detects

### Reconnaissance

NuScrape collects the following for every domain it encounters during crawling:

- **DNS A records** — IP resolution for all discovered domains
- **MX records** — mail server configuration
- **SSL/TLS certificates** — common name, issuer, validity dates, expiry warnings
- **WHOIS** — registrar, creation date, expiration date
- **ASN / IP intelligence** — autonomous system, organisation name, country, CDN detection
- **Open ports** — scans common ports (21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, etc.)
- **Technology fingerprinting** — detects ~20 technologies from response headers and HTML signatures including WordPress, React, Vue, Angular, jQuery, Bootstrap, Cloudflare, nginx, Apache, PHP, Laravel, Django, Shopify, and others
- **Subdomain enumeration** — probes a wordlist of common subdomain names against each root domain, with wildcard DNS detection to suppress false positives
- **Certificate Transparency log mining** — queries `crt.sh` for all historical SSL certificate SANs matching the root domain, discovering subdomains that wordlist enumeration misses (historical certs, wildcard certs, unusual names)
- **WAF / security appliance fingerprinting** — two-pass detection (passive header inspection + WAF-triggering probe) against signatures for Cloudflare, Akamai, Imperva Incapsula, AWS WAF, Sucuri, F5 BIG-IP ASM, Barracuda, Wordfence, ModSecurity, Fortinet FortiWeb, and Reblaze
- **Email addresses** — scraped from page content, filtered against image filename false positives and generic support addresses
- **Page titles** — for every crawled URL
- **HTTP history** — status code for every request made
- **robots.txt and sitemap.xml** — fetched and stored
- **XHR/API endpoints** — extracted from JS bundles via regex pattern matching
- **Security headers** — presence/absence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and leaking headers (Server version strings, X-Powered-By)
- **SPF, DMARC, and DKIM** — full DNS-based email authentication analysis: SPF mechanism audit (recursive lookup counting, `+all`/`?all`/`~all` detection), DMARC policy enforcement grading (`p=none/quarantine/reject`), aggregate/forensic reporting gaps (`rua=`/`ruf=`), partial enforcement (`pct<100`), subdomain policy weaker than parent (`sp=`), and DKIM selector probing against seven common selectors

---

### Vulnerability Checks

Every check runs automatically during crawling. No manual configuration required.

---

#### `.git` Directory Exposure
Probes `/.git/HEAD` and `/.git/config`. If accessible, the entire source code repository may be downloadable. **CRITICAL.**

---

#### `.env` File Exposure
Probes `/.env`, `/.env.local`, `/.env.production`, and similar paths. These files frequently contain database passwords, API keys, and service credentials. **CRITICAL.**

---

#### Directory Listing
Checks whether the web server returns a browsable file index at the root and common paths. Exposes file structure and sensitive files. **MEDIUM/HIGH.**

---

#### Backup File Exposure
Probes for common backup file patterns (`index.php.bak`, `config.bak`, `db.sql.gz`, etc.). Uses a canary probe to suppress false positives from catch-all 200 responses. **HIGH.**

---

#### Admin Panel Detection
Probes 59 paths covering common admin interfaces, CMS dashboards, database tools (phpMyAdmin, Adminer), API documentation consoles (Swagger, Redoc), and debug endpoints. Uses a canary probe to detect catch-all servers. Body signatures confirm ambiguous paths. 401/403 responses are reported at one severity level lower than a confirmed 200. **MEDIUM/HIGH/CRITICAL.**

---

#### Security Headers
Audits every domain for missing defensive headers and leaking server headers:

| Check | Severity | Detail |
|---|---|---|
| Missing HSTS | MEDIUM | HTTP-only or short `max-age` |
| Missing CSP | MEDIUM | No `Content-Security-Policy` |
| Missing X-Frame-Options | LOW | Unless CSP has `frame-ancestors` |
| Missing X-Content-Type-Options | LOW | `nosniff` absent |
| Missing Referrer-Policy | LOW | |
| Missing Permissions-Policy | LOW | |
| Server version exposed | LOW | e.g. `nginx/1.18.0`, `Apache/2.4.51` |
| X-Powered-By exposed | LOW | e.g. `PHP/8.1.2` |

---

#### CORS Misconfiguration
Tests whether the server reflects arbitrary `Origin` headers with `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`. Enables cross-origin data theft when combined with an XSS. **HIGH.**

---

#### Host Header Injection
Injects a canary value into the `Host` header and checks whether it is reflected in the response body or a redirect `Location`. Exploitable for password-reset poisoning, cache poisoning, and SSRF. **HIGH.**

---

#### Path Traversal
Injects common path traversal sequences (`../`, URL-encoded variants, null bytes) into URL path segments and parameters. Confirms findings by checking for known file content signatures (`root:`, `[boot loader]`, etc.) in the response. **HIGH/CRITICAL.**

---

#### SSTI (Server-Side Template Injection)
Injects template expression payloads (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`) into URL parameters and checks for the evaluated result (`49`) in the response. **CRITICAL** when confirmed.

---

#### CRLF Injection
For each URL parameter found on crawled pages, appends a URL-encoded `%0d%0a` (CR+LF) sequence followed by a canary header (`X-CRLF-Test: nuscrape-crlf-canary`) to the parameter value. Checks whether the injected header appears in the response headers — body reflection is not sufficient. Only tests parameters on in-scope URLs. Stops probing a domain after the first confirmed finding. Exploitable for response splitting, log poisoning, cache poisoning, and cookie injection. **HIGH** when confirmed.

---

#### Open Redirect
Parses all links on every crawled page looking for 30 common redirect parameter names (`next`, `url`, `redirect`, `return_to`, `goto`, `callback`, etc.). Injects the canary URL `https://example.com/nuscrape-redirect-test` and checks whether the `Location` header in the response points to it. Does not follow the redirect. Suppresses findings where the response shows a WAF fingerprint. Deduplicated per `(path, parameter)` pair. Requires `--active-probes`. **HIGH** when confirmed.

---

#### Mass Assignment Detection
For each POST/PUT form endpoint found on crawled pages, sends the normal form fields plus a set of 13 privileged field names (`role`, `admin`, `is_admin`, `isAdmin`, `user_role`, `permissions`, `is_superuser`, `verified`, `balance`, `credits`, `group_id`, etc.) in a JSON body. If any injected field name appears in the response body or headers, the server reflected it — strong indicator that the field was bound to a model object. Also probes the current URL directly when the path contains `/api/`, `/v1/`, `/v2/`, or `/rest/`. Requires `--active-probes`. Deduplicated per endpoint URL. **HIGH** — manual verification required to confirm the server processed (not just echoed) the field.

---

#### API Version Enumeration
For any crawled URL with a versioned path segment (`/v1/`, `/v2/`, etc.), probes the two prior versions and one future version by substituting the version number in place. Compares HTTP response codes to the current version's response.

| Finding | Severity |
|---|---|
| Older version returns 200 where current requires auth (401/403) | HIGH — auth controls may be absent |
| Older version returns 200 (different accessibility from current) | MEDIUM — verify manually |
| Older version returns 404 or 401/403 | skipped |

Requires `--active-probes`. Deduplicated per `(host, path)` pattern.

---

#### SSRF Candidate Parameters
Scans page links and form inputs for URL-accepting parameter names (`url`, `endpoint`, `webhook`, `callback`, `fetch`, `proxy`, `dest`, etc.). Flags them for manual follow-up. Downgraded to LOW when a WAF fingerprint is detected on the page. **MEDIUM** (no WAF) / **LOW** (WAF detected).

---

#### SPF / DMARC / DKIM Analysis
Checks DNS for SPF, DMARC, and DKIM records. All three checks run automatically via `check_spf_dmarc()` on every new domain enriched during the crawl.

**SPF**

| Issue | Severity |
|---|---|
| Missing SPF record | HIGH |
| SPF `+all` — any server permitted to send | HIGH |
| SPF `?all` — neutral, provides no spoofing protection | HIGH |
| SPF `~all` — softfail, not a hard reject | LOW |
| SPF lookup count > 10 (RFC 7208 permerror) | MEDIUM |

**DMARC**

| Issue | Severity |
|---|---|
| Missing DMARC record | HIGH |
| `p=none` — monitoring only, no enforcement | MEDIUM |
| `p=quarantine` — partial enforcement, upgrade to `reject` | MEDIUM |
| `p=reject` — correctly configured | ✓ pass |
| `rua=` missing — no aggregate reporting | LOW |
| `ruf=` missing — no forensic reporting | INFO |
| `pct<100` — policy only partially applied | LOW |
| `sp=` weaker than parent `p=` — subdomain spoofing less restricted | MEDIUM |

**DKIM**

Probes seven common selectors (`default`, `google`, `k1`, `mail`, `dkim`, `selector1`, `selector2`) at `<selector>._domainkey.<domain>`. Confirms a valid `v=DKIM1` or `p=` TXT record is present.

| Issue | Severity |
|---|---|
| No DKIM selectors found at any standard selector | MEDIUM |

---

#### Cookie Security Flag Auditing
Inspects every `Set-Cookie` header observed during crawling. Each missing flag generates its own alert, deduplicated per `(domain, cookie name, flag)` so each unique problem fires exactly once.

| Issue | Severity | Condition |
|---|---|---|
| Missing `HttpOnly` | HIGH | Cookie name contains `session`, `token`, `auth`, `jwt`, `sid`, or `login` |
| Missing `HttpOnly` | MEDIUM | Any other session-identifying cookie name |
| Missing `Secure` | MEDIUM | HTTPS pages only — expected on plain HTTP |
| `SameSite=None` without `Secure` | HIGH | Cross-site requests include the cookie over plain HTTP |
| Missing `SameSite` | LOW | Cookie not protected against CSRF |

---

#### Dangerous HTTP Methods
Sends `TRACE`, `PUT`, `DELETE`, `CONNECT`, and `PATCH` to the root path of each base URL. A 2xx response means the server accepted the method; a 405 is flagged for TRACE only (server parsed it, possible XST even if ultimately rejected). Requires `--active-probes`.

| Method | Severity | Risk |
|---|---|---|
| `TRACE` accepted (2xx) | HIGH | Cross-site tracing — can expose session cookies to attacker-controlled scripts |
| `PUT` accepted (2xx) | HIGH | File write — attacker may be able to upload arbitrary content |
| `DELETE` accepted (2xx) | HIGH | File deletion — destructive write access to the server |
| `CONNECT` accepted (2xx) | MEDIUM | Open proxy abuse |
| `PATCH` accepted (2xx) | LOW | Partial write access |
| `TRACE` responded with 405 | MEDIUM | Server parsed TRACE; verify header reflection for XST |

---

#### Default Credentials
After fingerprinting admin panels via tech detection, attempts default credential pairs against login endpoints. Covers:

| Service | Default Credentials Tested |
|---|---|
| Jenkins | admin/admin, admin/password, admin/(empty) |
| Grafana | admin/admin, admin/Admin@123, admin/grafana |
| Kibana | elastic/elastic, kibana/kibana, admin/admin |
| Jupyter | (empty password), jupyter, admin |
| Adminer | root/(empty), admin/admin |
| phpMyAdmin | root/(empty), root/root, admin/admin |
| Traefik | Unauthenticated dashboard access |
| RabbitMQ | guest/guest, admin/admin |

Success requires a body or header confirmation signature — a bare 200 response is not sufficient. Jenkins requires `X-Jenkins` header or `Dashboard [Jenkins]` in body. Adminer requires `adminer.org`, `>Adminer<`, or `Select database` in body. **CRITICAL** when confirmed.

---

#### Spring Boot Actuator Exposure
Probes 17 Spring Boot Actuator endpoints across both 2.x (`/actuator/*`) and legacy 1.x paths.

| Endpoint | Severity | Risk |
|---|---|---|
| `/actuator/env` | CRITICAL | All environment variables — may contain DB passwords, API keys |
| `/actuator/heapdump` | CRITICAL | Full JVM memory dump — contains in-memory secrets and session tokens |
| `/actuator/httptrace` | HIGH | Full HTTP request/response history including auth headers |
| `/actuator/mappings` | HIGH | Complete internal API route map |
| `/actuator/beans` | HIGH | All Spring beans and internal architecture |
| `/actuator/configprops` | HIGH | All configuration property values |
| `/actuator/loggers` | MEDIUM | Log level configuration |
| `/actuator/metrics` | MEDIUM | Performance metrics |
| `/actuator/info` | MEDIUM | App version, git commit, build info |

Confirms findings via body signature matching before alerting to avoid false positives. 401/403 responses are logged quietly (endpoint exists but protected).

---

#### GraphQL Introspection
Two-pronged check. Requires `--active-probes`.

**Per-host path probing** — Probes 10 common GraphQL paths (`/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/gql`, `/graphiql`, `/playground`, etc.) on every enriched host with the standard introspection query `{"query":"{__schema{types{name fields{name}}}}"}`.

**Per-page URL detection** — During crawling, any URL whose path contains `graphql`, `graph`, or `/api` is probed directly. This catches non-standard GraphQL paths that the fixed wordlist would miss.

Both paths share a URL-level dedup set to avoid double-probing the same endpoint.

| Finding | Severity |
|---|---|
| Introspection enabled — schema returned | HIGH (includes visible type count) |
| Endpoint exists but introspection disabled | MEDIUM |

---

#### JWT Analysis
Scans page HTML, JS bundles, and response headers for JWT tokens. Analyses each unique token for:

- **`alg:none`** — signature verification bypassed entirely. Full token forgery possible. **CRITICAL.**
- **Weak HS256 secret** — tests against a list of common development secrets by recomputing HMAC-SHA256. If cracked, full token forgery is possible. Known documentation placeholder secrets (`your-256-bit-secret`, `secret`, etc.) and the jwt.io demo token are suppressed. **CRITICAL.**
- **Expired tokens** — server may not be validating the `exp` claim. Logged to Recon tab.
- **Sensitive payload fields** — PII or credentials in a base64-decoded (not encrypted) payload. **HIGH.**

---

#### IDOR Candidates (Verified)
Collects URLs from page links containing numeric IDs or UUIDs in query parameters or REST-style paths. Runs each through a 5-stage verification pipeline before alerting:

1. **Path blocklist** — drops static asset paths, public content directories, and known non-data paths
2. **Extension blocklist** — drops `.css`, `.js`, `.png`, `.woff`, `.pdf`, and other static files
3. **Auth-gate check** — fetches the URL with no cookies; drops it if content is returned unauthenticated (public resource)
4. **ID substitution** — fetches `id+1` and `id-1` variants
5. **Response diff** — only proceeds if different IDs return meaningfully different responses (proving per-object data access)

Alerts only on confirmed auth-gated endpoints with per-object data variation. **HIGH** when verified.

---

#### JS Bundle Analysis
For every JS bundle fetched during crawling:

- **Secrets** — detects API keys, tokens, passwords, AWS access keys, GitHub tokens, OpenAI keys, and Mapbox secret tokens (`sk.eyJ`). Mapbox public tokens (`pk.eyJ`) are downgraded to INFO — they are intentionally client-side and carry no server privilege.
- **Endpoints** — extracts API paths and full URLs for the XHR Endpoints tab
- **Staging/internal URLs** — flags `dev.`, `staging.`, `.internal`, `.corp` URLs embedded in production bundles
- **TODO/FIXME comments** — scans first-party JS only (CDN and vendor files excluded) for `TODO`, `FIXME`, `HACK`, and `NOTE` comments
- **S3 bucket references** — extracts and probes any S3 bucket names found in source
- **JWT tokens** — analyses any embedded JWTs (see JWT Analysis above)
- **Source map exposure** — see below

---

#### JavaScript Source Map Exposure
For every JS bundle fetched during crawling, checks for:
- `SourceMap` / `X-SourceMap` response headers (explicit bundler reference)
- `<bundle>.map` — the conventional path used by webpack, esbuild, Vite, Rollup, and Parcel

Confirms findings by requiring all three required JSON fields (`"version"`, `"mappings"`, `"sources"`) in the response body, then extracts source file paths for the alert detail. Exposed source maps leak the original unminified source code, internal file paths, variable and function names, and occasionally inline developer comments. **HIGH.**

---

#### `/.well-known/` Enumeration
Probes standard well-known paths:

| Path | Category | Action |
|---|---|---|
| `/.well-known/security.txt` | OSINT | Extracts Contact, Encryption, Policy, and Expires fields. Stored in `WellKnown` table. |
| `/.well-known/openid-configuration` | Auth | Confirms valid JSON, extracts all OAuth/OIDC endpoints and supported grant types. **HIGH alert** — exposes complete auth surface. |
| `/.well-known/oauth-authorization-server` | Auth | Same as above (RFC 8414). |
| `/.well-known/jwks.json` | Auth | Counts exposed public keys. Informational. |
| `/.well-known/change-password` | Info | Logged if present. |
| `/.well-known/apple-app-site-association` | Info | Logged if present. |
| `/.well-known/assetlinks.json` | Info | Logged if present. |

---

#### S3 Bucket Exposure
Extracts AWS S3 bucket names from three URL patterns found in page HTML and JS bundles:
- `https://bucketname.s3.amazonaws.com`
- `https://s3.amazonaws.com/bucketname`
- `s3://bucketname`

Probes each unique bucket name once. **CRITICAL** if the bucket returns a public `ListBucket` XML response. Logs quietly if private (403) or non-existent (404/NoSuchBucket).

---

#### Subdomain Takeover
Checks the CNAME chain for every discovered live subdomain against 23 known takeover-vulnerable services including GitHub Pages, Heroku, AWS S3, Azure App Service, Fastly, Shopify, Netlify, Zendesk, Tumblr, Surge, Webflow, and others.

| Result | Severity | Meaning |
|---|---|---|
| CNAME matches + body fingerprint confirmed | CRITICAL | Subdomain is confirmed unclaimed and takeable |
| CNAME matches + body unconfirmed | MEDIUM | Service is vulnerable class; verify manually whether the target is claimable |
| CNAME matches + no HTTP response (confirm-required service) | MEDIUM | Azure internal LB / AWS EB internal DNS — dangling CNAME is common noise, verify manually |
| CNAME matches + no HTTP response (standard service) | HIGH | Endpoint is dead but DNS record persists |

**GitHub Pages** requires both conditions before a CRITICAL alert fires:
1. `github.com/<orgname>` returns non-200 (org does not exist — GitHub protects the namespace for existing orgs)
2. `<orgname>.github.io` returns 404

If either condition is not met the finding is suppressed entirely.

---

#### DNS Zone Transfer (AXFR)
Resolves all authoritative nameservers for the root domain, then attempts a zone transfer (`AXFR`) against each. A misconfigured nameserver that permits AXFR dumps the entire DNS zone in a single query — every subdomain, internal hostname, and IP address. **CRITICAL** when successful. All transferred records are stored in the `ZoneTransfer` table.

---

#### FTP Anonymous Login
If port 21 is found open during port scanning, attempts an anonymous FTP login. **HIGH** when successful.

---

#### MySQL Unauthenticated Access
If port 3306 is found open, probes for access without credentials. **CRITICAL** when the server accepts a connection without authentication.

---

### Alert Severity Levels

| Severity | Meaning |
|---|---|
| CRITICAL | Immediate exploitability — credentials exposed, authentication bypassed, data directly accessible |
| HIGH | Serious vulnerability requiring manual confirmation or a second step to exploit |
| MEDIUM | Meaningful security weakness — lower impact or requires specific conditions |
| LOW | Informational finding worth noting — low direct risk, may assist further attack |
| INFO | Expected or intentional behaviour noted for completeness (e.g. Mapbox public token) |

---

## Database

All findings are stored in `ScrapeDB` (SQLite) in the same directory as `main.py`. The database persists between runs and accumulates findings across multiple scans.

| Table | Contents |
|---|---|
| `Alerts` | All vulnerability findings with severity, type, target, detail, timestamp |
| `Domains` | Discovered domains with IP, server, content-type, title |
| `Emails` | Scraped email addresses |
| `DNS` | A record lookups |
| `MX` | Mail exchange records |
| `SSL` | Certificate info per domain |
| `WHOIS` | Registrar and expiry per domain |
| `Ports` | Open ports per domain |
| `HTTPHistory` | Status code history per URL |
| `Technologies` | Detected technologies per URL |
| `SecurityHeaders` | Header audit per domain |
| `Subdomains` | Enumerated subdomains with IP and status |
| `ASN` | IP → ASN/org/country/CDN mapping |
| `XHREndpoints` | API endpoints extracted from JS bundles |
| `JSFindings` | Secrets, endpoints, staging URLs, source maps, IDOR candidates, JWT findings |
| `Robots` | robots.txt content per domain |
| `Sitemap` | Sitemap URL inventory |
| `ZoneTransfer` | DNS records obtained via successful AXFR zone transfers |
| `WAF` | Detected WAF vendor and evidence per domain |
| `WellKnown` | `/.well-known/` path findings with category and content snippet |

**Export:** Every table is exportable as CSV or JSON from the Report tab in the UI, or directly via `/api/export/<table>.<csv|json>`.

**Clear:** The "Clear Database" button in the UI wipes all tables without deleting the file.

---

## False Positives & Noise Reduction

Several measures are in place to reduce noise:

**Wildcard DNS suppression** — Before subdomain enumeration, two random canary subdomains are probed. If both resolve (indicating a wildcard `*.domain.com` record), all subdomains resolving to the same IP are suppressed. A secondary HTTP-level check catches CDN wildcard responses (e.g. Cloudflare) that return HTTP 200 for any subdomain via shared IPs.

**Backup file / admin panel canary probes** — Before flagging backup file or admin panel exposure, a random canary path is tested. If it also returns 200, the server is returning catch-all responses and findings for that domain are suppressed.

**WAF-aware finding suppression** — Responses showing Akamai (`edgesuite.net`), Cloudflare (`cf-ray`, `cf-cache-status`), or Incapsula/Imperva (`x-iinfo`, `Incapsula incident`) fingerprints are treated as WAF intercepts rather than real application responses. Open redirect findings are suppressed outright; port scan and SSRF findings are downgraded to LOW with an "UNCONFIRMED — WAF" note.

**GitHub Pages org namespace check** — Before flagging a GitHub Pages CNAME as a takeover, both `github.com/<orgname>` (must be non-200) and `<orgname>.github.io` (must be 404) are verified. GitHub protects the namespace for existing orgs even without an active Pages site.

**Azure / AWS internal infrastructure** — Azure SCM (`cloudapp.net`) and AWS Elastic Beanstalk (`elasticbeanstalk.com`) CNAMEs with no HTTP response are downgraded from HIGH to MEDIUM — these are internal endpoints that cannot be publicly claimed, making dangling CNAMEs low-signal noise.

**JS endpoint noise filter** — Endpoints extracted from JS bundles are filtered against a blocklist of ~40 known public/CDN domains including all ArcGIS/Esri services, Google Maps, Mapbox, Google Analytics/Tag Manager, Cloudflare, jsDelivr, Segment, HotJar, Sentry, HubSpot, Intercom, and others.

**JS secret false positive filters** — Extracted secrets are checked against placeholder patterns (`example`, `your_key`, `REPLACE`, `changeme`, etc.) and known public key formats (Stripe publishable keys, Google Maps embed keys, Mapbox `pk.eyJ` public tokens) before alerting. Mapbox public tokens are reported as INFO rather than suppressed entirely.

**JWT demo token and placeholder secrets** — The jwt.io demo token is suppressed entirely. Weak-secret findings where the cracked secret is a known documentation placeholder (`your-256-bit-secret`, `secret`, etc.) are also suppressed.

**i18n / UI string filter** — Password field values containing no digits and no special characters (e.g. `Contraseña`, `Mot de passe`, garbled encodings) are treated as display labels, not credentials.

**Email false positive filter** — Email regex matches are validated before storing: domain part must not contain slashes (image path artifacts), TLD must not be a media extension (`.png`, `.jpg`, `.mp4`, etc.), and single generic addresses (`support@`, `info@`, `noreply@`, etc.) do not generate alerts.

**Google tracking / Play Store URL filter** — `play.google.com`, `google-analytics.com`, `analytics.google.com`, `googletagmanager.com`, `googleadservices.com`, and `doubleclick.net` are skipped during crawling by default. Disable with `--no-skip-google-tracking`.

**TODO comment scope** — Comment scanning is restricted to first-party JS only (CDN and vendor URLs excluded) and requires explicit `TODO`, `FIXME`, `HACK`, or `NOTE` keywords — not arbitrary keyword matches.

**IDOR 5-stage verification** — See [IDOR Candidates](#idor-candidates-verified) above. Eliminates the vast majority of false positives from numeric IDs in CSS paths, public help article IDs, cache-busting hashes, etc.

**Default credential confirmation** — Login attempts require body or header confirmation signatures before declaring success. A bare 200 response is never sufficient.

---

## Responsible Disclosure

NuScrape is designed for **responsible disclosure research only**. All active probes (backup files, credential testing, open redirect injection, IDOR verification) are limited to confirming the existence of a vulnerability and do not exfiltrate data, maintain persistence, or cause service disruption.

> **Note:** Payload-injecting checks (path traversal, SSTI, CRLF injection, CORS evil-origin probes, default credential tests) are **disabled by default** and must be explicitly enabled with `--active-probes`. A warning is printed at startup and displayed in the UI whenever this flag is active. Only enable it against targets you are authorised to test.

**When reporting findings:**

1. Check the target's security policy at `/.well-known/security.txt` or their website
2. For US government domains (`*.gov`), report via `vulndisclosure@cisa.dhs.gov`
3. For companies with bug bounty programs, submit via HackerOne or Bugcrowd
4. For companies without a program, contact `security@<domain>` or `abuse@<domain>`
5. Allow 30–90 days for remediation before any public disclosure
6. Do not access, download, or retain any user data encountered during testing

---

## Workflow

```
Start scan
    │
    ├─ Crawl pages (async, rate-limited)
    │       │
    │       ├─ Per page response
    │       │     ├─ Cookie security flag auditing (per-flag, per-cookie-name dedup)
    │       │     ├─ JWT scan (HTML + headers)
    │       │     ├─ SSRF candidate parameter detection (WAF-downgraded)
    │       │     ├─ Host header injection
    │       │     ├─ Open redirect detection (WAF-suppressed)  ┐
    │       │     ├─ GraphQL introspection (per-page URL)      │
    │       │     ├─ Mass assignment (POST/PUT form endpoints)  │ requires --active-probes
    │       │     ├─ API version enumeration                    │
    │       │     ├─ Path traversal                            │
    │       │     ├─ SSTI                                      │
    │       │     ├─ CRLF injection                            ┘
    │       │     ├─ IDOR candidate collection + verification
    │       │     ├─ JS bundle analysis (endpoints, secrets, staging URLs, JWTs, S3 refs, TODO comments)
    │       │     ├─ JS source map exposure check
    │       │     └─ S3 bucket probing
    │       │
    │       └─ Per new domain discovered
    │             ├─ DNS / MX / SSL / WHOIS
    │             ├─ Zone transfer attempt (AXFR against all NSes)
    │             ├─ ASN lookup
    │             ├─ Technology fingerprinting
    │             ├─ Port scan (WAF check on HTTP ports)
    │             ├─ Subdomain enumeration (wordlist + CT log mining)
    │             │     ├─ Per subdomain: DNS + HTTP liveness confirmation
    │             │     ├─ Per subdomain: takeover check (GitHub org verification)
    │             │     └─ CT-confirmed live subdomains → enrichment pipeline (deduplicated vs wordlist)
    │             ├─ Security header audit
    │             ├─ SPF / DMARC / DKIM
    │             └─ Exposure checks (once per base URL)
    │                   ├─ .git / .env exposure
    │                   ├─ Directory listing
    │                   ├─ Backup file exposure
    │                   ├─ Admin panel detection (59 paths)
    │                   ├─ Spring Boot Actuator
    │                   ├─ GraphQL introspection (common paths) ┐
    │                   ├─ CORS misconfiguration                │ requires --active-probes
    │                   ├─ Default credentials                  │
    │                   └─ Dangerous HTTP methods               ┘
    │                        (TRACE/PUT/DELETE/CONNECT)
    │                   ├─ WAF fingerprinting
    │                   └─ /.well-known/ enumeration
    │
    └─ All findings → ScrapeDB → UI alerts tab
```
