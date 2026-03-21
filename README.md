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
pip install requests aiohttp flask beautifulsoup4 lxml dnspython python-whois colorama --break-system-packages
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
| `--no-skip-google-tracking` | off | Crawl Google tracking, Maps, and Fonts CDN URLs (skipped by default) |
| `--stealth` | `LOUD` | Stealth profile: `LOUD` (fast), `NORMAL` (moderate delays), `GHOST` (slow, rotated UAs, randomised) |
| `--bug-bounty-header` | — | Injects `X-Bug-Bounty: <value>` into all requests — required by some bug bounty programs |
| `--active-probes` | off | Enable payload-injecting checks: path traversal, SSTI, CRLF injection, CORS evil-origin probes, default credential tests, dangerous HTTP method testing (TRACE/PUT/DELETE/CONNECT), WebSocket security probes (origin validation, auth, scheme), XXE injection (XML/SOAP entity expansion), prototype pollution (server-side body/query probes + client-side JS sink detection), and HTTP request smuggling (CL.TE, TE.CL, TE.TE via raw sockets). **Only use against targets you are authorised to test.** |

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

Start `app.py` and open `http://localhost:5000`. The control panel sidebar lets you configure all scan options including stealth profile, bug bounty header, social media filter, Google tracking/CDN filter, and active probes. All views update live as the crawler runs.

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
- **Technology fingerprinting** — detects 28 technologies from response headers, cookies, and HTML; automatically runs targeted security checks for WordPress, Laravel, Spring Boot, Django, Rails, Drupal, and Joomla once confirmed
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
Runs four distinct Origin probes against each base URL. Requires `--active-probes`. Deduplication is handled by the per-base-URL exposure check gate.

| Probe | Origin sent | Flag condition | Severity |
|---|---|---|---|
| Arbitrary reflection | `https://evil-cors-probe.com` | Reflected + `Allow-Credentials: true` | CRITICAL |
| Arbitrary reflection | `https://evil-cors-probe.com` | Reflected, no credentials | HIGH |
| Wildcard + credentials | `https://evil-cors-probe.com` | `ACAO: *` + `Allow-Credentials: true` | HIGH |
| Null origin bypass | `null` | `ACAO: null` + `Allow-Credentials: true` | HIGH — browsers send null from sandboxed iframes |
| Pre-domain prefix match | `https://evil<domain>` | Injected origin reflected + credentials | HIGH — server is prefix-matching, not exact-matching |
| Subdomain wildcard trust | `https://evil.<domain>` | Injected origin reflected + credentials | HIGH — any compromised subdomain can steal cookies |

All bypass tests (null, pre-domain, subdomain) only flag when `Access-Control-Allow-Credentials: true` is also present — without credentials the cross-origin impact is minimal. The reflected origin value is included in the finding detail.

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

#### WebSocket Endpoint Detection and Security Checks

**Discovery (runs unconditionally on every crawled page):**
- Scans page source for explicit `ws://` / `wss://` URL literals
- Detects JavaScript WebSocket construction calls: `new WebSocket(...)`, `io(...)`, `socket.connect(...)`
- Checks response headers for `Upgrade: websocket` and promotes the page URL to a WS endpoint
- All discovered endpoints are stored in the `WebSockets` database table

**Security checks (requires `--active-probes`):**

| Check | Finding | Severity |
|---|---|---|
| Unencrypted scheme | Endpoint uses `ws://` — traffic transmitted in plaintext | MEDIUM |
| Origin validation | Server accepts connection from `Origin: https://evil.com` — cross-site WebSocket hijacking (CSWSH) | HIGH |
| Unauthenticated data | Server sends data to a client with no cookies or auth headers | HIGH |

- Uses the `websockets` library (gracefully skipped if not installed)
- 5-second connection and receive timeout per check
- Deduplicated per unique WebSocket URL across the full scan session

---

#### XXE Injection Detection

**Endpoint discovery** — identifies XML-accepting endpoints on each crawled page by:
- Server `Content-Type` response header containing `text/xml`, `application/xml`, `application/soap+xml`, or `application/xhtml+xml`
- URL path matching SOAP patterns: `/ws`, `/soap`, `/wsdl`, `/service`, `/services`, `/xmlrpc`, `/rpc`
- File upload form inputs whose `accept` attribute includes `.xml`
- Anchor hrefs on the page matching the same SOAP path patterns

**Probes (requires `--active-probes`):**

| Check | Method | Finding | Severity |
|---|---|---|---|
| Static-entity XXE | POST `text/xml` | Canary `xxe-test-nuscrape` reflected in response — entity processing confirmed | HIGH |
| SOAP-wrapped XXE | POST `application/soap+xml` | Same canary reflected inside SOAP envelope | HIGH |
| WSDL exposure | GET `?wsdl` | 200 response with XML/WSDL body without auth — exposes full service contract | MEDIUM |

The test payload uses a safe static string entity (`<!ENTITY xxe "xxe-test-nuscrape">`) — no file reads, no network callbacks, no sensitive data access. Confirmation requires the canary to appear verbatim in the response body.

- 8-second timeout per probe
- Deduplicated per `(endpoint_url, content_type)` pair

---

#### Prototype Pollution Detection

Three complementary detection surfaces, all requiring `--active-probes`.

**1. Server-side body probes**

For each POST/PUT endpoint found in page forms and API-style page URLs, sends a baseline request then up to 2 pollution payloads injected alongside normal fields:

```
{"__proto__": {"nuscrape": "pp-test"}}
{"constructor": {"prototype": {"nuscrape": "pp-test"}}}
```

| Finding | Severity |
|---|---|
| Canary `pp-test` reflected in response body | HIGH — entity injection confirmed |
| Server returns 500 on probe but not on baseline | MEDIUM — possible prototype corruption crash |

**2. URL query-string probes**

For the same endpoints, appends bracket-notation pollution params to the query string:

```
?__proto__[nuscrape]=pp-test
?constructor[prototype][nuscrape]=pp-test
```

| Finding | Severity |
|---|---|
| Canary `pp-test` reflected in response body | HIGH |

**3. Client-side sink detection**

During JS bundle analysis, scans first-party JS for known prototype pollution sinks (`Object.assign(`, `$.extend(`, `_.merge(`, `_.defaultsDeep(`, `JSON.parse(…)[`) with a user-controlled input source (`req.body`, `location.search`, `URLSearchParams`, etc.) within 300 characters. CDN and vendor bundles are skipped.

| Finding | Severity |
|---|---|
| Sink + nearby user-input source in first-party JS | MEDIUM — manual verification required |

- At most 3 probes per endpoint (body + query combined) to avoid application instability
- 8-second timeout per probe
- Deduplicated per endpoint URL per probe type

---

#### SSRF Detection

**Passive candidate flagging** (always runs): scans page links and form inputs for URL-accepting parameter names (`url`, `endpoint`, `webhook`, `callback`, `fetch`, `proxy`, `dest`, etc.). Flags them for manual follow-up. Downgraded to LOW when a WAF fingerprint is detected on the page. **MEDIUM** (no WAF) / **LOW** (WAF detected).

**OOB confirmation** (requires `--active-probes` and `pip install interactsh-client`): for each URL-accepting parameter, injects interactsh subdomain payloads (`http://<id>.interact.sh`, `https://<id>.interact.sh`, `http://<id>.interact.sh/nuscrape-ssrf-test`) and polls for DNS/HTTP callbacks for 10 seconds.

| Finding | Severity | Signal |
|---|---|---|
| SSRF confirmed — OOB interaction from target IP | HIGH | DNS or HTTP callback received from the target server's own IP |
| SSRF likely — OOB interaction, unexpected IP | MEDIUM | Callback received from CDN or public DNS resolver, not target IP |
| SSRF candidate — no OOB interaction | LOW | Parameter accepts URLs but no callback received within 10s |
| SSRF candidate — OOB unavailable | LOW | `interactsh-client` not installed; blind fallback |
| SSRF: cloud metadata accessible | CRITICAL | Confirmed SSRF endpoint returned AWS/GCP/Azure metadata indicators |

**Cloud metadata probing** (only on confirmed SSRF endpoints): injects safe non-sensitive metadata paths into the confirmed parameter and checks the response body for metadata indicators.

| Cloud | URL probed | Indicators checked |
|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/meta-data/` | `ami-id`, `instance-id`, `instance-type` |
| AWS IMDSv2 | `http://169.254.169.254/latest/api/token` | `EC2-IMDS`, `instance-id` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `computeMetadata`, `serviceAccounts` |
| Azure | `http://169.254.169.254/metadata/instance` | `azureMetadata`, `vmId`, `subscriptionId` |

IAM credential paths are never accessed. Cloud metadata probing confirms reachability only.

- One interactsh client registered per scan session (shared across all domains)
- 10-second request timeout + 10-second polling window per parameter
- Deduplicated per `(base_url, param)` pair

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

#### HTTP Request Smuggling Detection

Probes the target host for CL.TE, TE.CL, and TE.TE desync vulnerabilities using **raw socket connections** (bypasses `requests` header normalisation). Detection is timing- and status-based only — no queue poisoning, no interference with other users. All findings are MEDIUM and require manual confirmation with Burp Suite's HTTP Request Smuggler. Requires `--active-probes`. Deduplicated per host.

**CL.TE** — sends a request with `Content-Length` deliberately off by one and `Transfer-Encoding: chunked` with body `0\r\n\r\nX`. If the front-end uses Content-Length and the back-end uses Transfer-Encoding, the trailing `X` is left in the pipeline causing a stall.

**TE.CL** — sends a valid chunked body (`8\r\nSMUGGLED\r\n0\r\n\r\n`) with `Content-Length: 3`. If the front-end uses TE and the back-end uses CL, only 3 bytes are consumed, leaving the rest in the pipeline.

**TE.TE obfuscation** — tests five Transfer-Encoding variants (`xchunked`, duplicate header, trailing space, `CHUNKED`, `x`) to detect whether one layer processes and another ignores the header.

| Signal | Severity | Interpretation |
|---|---|---|
| Probe times out (baseline did not) | MEDIUM | Back-end stalled waiting for more data |
| Probe returns 400 or 408 (baseline did not) | MEDIUM | Ambiguous request rejected by one layer |

- Baseline request sent first; probe is skipped if baseline itself times out
- 10-second socket timeout per probe; TLS supported
- At most one TE.TE signal per host (stops after first matching variant)

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

#### Technology Fingerprinting and Technology-Specific Security Checks

**Fingerprinting** runs on every enriched domain from response headers, cookies, HTML meta tags, and page source. Detected technologies are stored in the `Technologies` database table and logged alongside findings.

Detected stacks: WordPress, Drupal, Joomla, Shopify, Wix, Squarespace, React, Next.js, Vue.js, Nuxt.js, Angular, Gatsby, jQuery, Bootstrap, Cloudflare, Nginx, Apache, IIS, LiteSpeed, CloudFront, Google Analytics, Tag Manager, PHP, ASP.NET, Laravel, Spring Boot, Django, Ruby on Rails.

**Technology-specific checks** fire automatically once a CMS or framework is confirmed. Each check: uses a catch-all canary probe to avoid false positives, requires body/content-type confirmation before alerting, and deduplicates per domain.

**WordPress**

| Check | Severity | Signal |
|---|---|---|
| `/wp-login.php` accessible | MEDIUM | Login page exposed — enables brute force |
| `/xmlrpc.php` accessible | MEDIUM | XML-RPC enabled — brute force amplification, SSRF vector |
| `/wp-json/wp/v2/users` returns user list | HIGH | Unauthenticated user enumeration via REST API |
| `/wp-content/debug.log` accessible | HIGH | PHP error log with paths, queries, and stack traces |

**Laravel**

| Check | Severity | Signal |
|---|---|---|
| `/storage/logs/laravel.log` accessible | HIGH | Application log with stack traces and SQL queries |
| `/.env` accessible with APP_KEY/DB_PASSWORD | CRITICAL | Full credential exposure — rotate all secrets immediately |
| `/telescope` accessible without auth | HIGH | Request/response history, SQL, queued jobs |
| `/horizon` accessible without auth | HIGH | Queue worker config and job history |
| 404 returns Whoops/Ignition error page | HIGH | Debug mode enabled — exposes source code and env vars |

**Spring Boot**

| Check | Severity | Signal |
|---|---|---|
| `/actuator/env` accessible | CRITICAL | All environment variables — passwords and API keys |
| `/actuator/heapdump` accessible (HPROF magic confirmed) | CRITICAL | Full JVM heap dump |
| `/actuator/shutdown` accepts POST | CRITICAL | Remote application shutdown |
| `/actuator/httptrace` accessible | HIGH | Full HTTP history including auth headers |
| `/actuator/mappings`, `/actuator/beans`, `/actuator/configprops` | HIGH | Internal architecture |
| `/actuator/loggers`, `/actuator/metrics`, `/actuator/info` | MEDIUM | Informational endpoints |
| Whitelabel error page on unknown path | INFO | Confirms Spring Boot identity |

Spring Boot actuator checks require body signature confirmation before alerting. 401/403 responses are logged quietly. `/actuator/shutdown` is tested via POST only.

**Django**

| Check | Severity | Signal |
|---|---|---|
| 404 returns Django debug page with URL patterns | HIGH | Debug mode enabled — version and routing exposed |
| `/admin/` accessible | MEDIUM | Admin panel publicly reachable |
| `/__debug__/` accessible | MEDIUM | Django Debug Toolbar exposed |

**Ruby on Rails**

| Check | Severity | Signal |
|---|---|---|
| `/rails/info/properties` accessible | HIGH | Ruby/Rails versions, middleware stack |
| `/rails/mailers` accessible | MEDIUM | Action Mailer email preview exposed |

**Drupal**

| Check | Severity | Signal |
|---|---|---|
| `/CHANGELOG.txt` accessible | LOW | Version disclosure — aids CVE targeting |
| `/sites/default/settings.php` accessible | CRITICAL | Database credentials and config |
| `/admin/` accessible | MEDIUM | Admin panel publicly reachable |

**Joomla**

| Check | Severity | Signal |
|---|---|---|
| `/administrator/` accessible | MEDIUM | Admin panel publicly reachable |
| `/configuration.php.bak` accessible | CRITICAL | Database credentials and secret key |
| `/README.txt` accessible | LOW | Version disclosure |

---

#### Spring Boot Actuator Exposure
Probes 18 Spring Boot Actuator endpoints across both 2.x (`/actuator/*`) and legacy 1.x paths.

| Endpoint | Severity | Risk |
|---|---|---|
| `/actuator/env` | CRITICAL | All environment variables — may contain DB passwords, API keys |
| `/actuator/heapdump` | CRITICAL | Full JVM memory dump — contains in-memory secrets and session tokens |
| `/actuator/shutdown` | CRITICAL | Remote shutdown — POST terminates the JVM process |
| `/actuator/httptrace` | HIGH | Full HTTP request/response history including auth headers |
| `/actuator/mappings` | HIGH | Complete internal API route map |
| `/actuator/beans` | HIGH | All Spring beans and internal architecture |
| `/actuator/configprops` | HIGH | All configuration property values |
| `/actuator/loggers` | MEDIUM | Log level configuration |
| `/actuator/metrics` | MEDIUM | Performance metrics |
| `/actuator/info` | MEDIUM | App version, git commit, build info |

Confirms findings via body signature matching before alerting to avoid false positives. 401/403 responses are logged quietly (endpoint exists but protected). `/actuator/shutdown` is probed via POST only and never retried.

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
Resolves all authoritative nameservers for the root domain, then attempts a zone transfer (`AXFR`) against each using a 5-second timeout. A misconfigured nameserver that permits AXFR dumps the entire DNS zone in a single query — every subdomain, internal hostname, and IP address. REFUSED responses and timeouts are skipped silently (expected behaviour for correctly configured servers).

**CRITICAL** when successful. The alert includes the total record count and a sample of up to 8 discovered hostnames. All transferred records are stored in the `ZoneTransfer` table.

On success, every A and CNAME hostname from the zone is fed back into the subdomain enumeration pipeline: DNS liveness confirmation, HTTP HEAD probe, wildcard filtering, high-value subdomain alerting, takeover checking, and full domain enrichment — the same pipeline used by wordlist brute-force and CT log discovery.

---

#### FTP Anonymous Login
If port 21 is found open during port scanning, attempts an anonymous FTP login. **HIGH** when successful.

---

#### MySQL Unauthenticated Access
If port 3306 is found open, probes for access without credentials. **CRITICAL** when the server accepts a connection without authentication.

---

#### SQL Injection Detection

Probes every URL query parameter discovered on crawled pages (from page URL, `<a href>` links, and `<form action>` attributes) for SQL injection. Requires `--active-probes`. Deduplicates per `(base_url, param)` pair.

**Phase 1 — error-based:** Appends 9 quote/comment payloads (`'`, `''`, `` ` ``, `')`, `'))`, `' OR '1'='1`, etc.) to each parameter. Flags **CRITICAL** when any of 11 database error strings appear in the response (`SQL syntax`, `mysql_fetch`, `ORA-01756`, `PostgreSQL ERROR`, `unclosed quotation`, etc.).

**Phase 2 — time-based blind (statistical):** First establishes a per-endpoint timing profile (5 cache-busted baseline requests → mean/σ). Skips time-based probing if σ > 500ms (noisy link). Sends three escalating probes at 2s / 4s / 6s using DB-specific templates (`SLEEP({N})`, `pg_sleep({N})`, `WAITFOR DELAY '0:0:{N}'`, `randomblob(...)`, `dbms_pipe.receive_message`, or generic fallback). Each probe threshold is `mean + 3σ + delay`. Stops on first miss (proportional scaling).

| Finding | Severity | Signal |
|---|---|---|
| SQL error string in response | CRITICAL | Error-based injection confirmed |
| 2–3 of 3 probes exceed adaptive threshold | HIGH | Time-based blind confirmed |
| 1 of 3 probes exceeds adaptive threshold | MEDIUM | Time-based blind — weak signal |

Log format: `[Timing] Baseline: 180ms ±42ms | Probe(SLEEP 2): 2243ms (threshold 2740ms) ✓ | ... → CONFIRMED`

- Skips static asset URLs (CSS, JS, images, archives)
- Skips third-party CDN domains
- WAF vendor noted in finding detail when detected
- Stops testing a domain after first confirmed HIGH finding

---

#### Command Injection Detection

Injects harmless canary echo payloads into every URL query parameter. Flags **CRITICAL** only when the literal canary string `nuscrape-ci-canary` appears in the response — proving the OS shell executed the input. Requires `--active-probes`.

| Platform | Payloads tested | Confirmation signal |
|---|---|---|
| Unix/Linux | `;echo`, `\|echo`, `` `echo` ``, `$(echo)`, `${IFS}echo`, `%0aecho` | `nuscrape-ci-canary` in response body |
| Windows | `&echo`, `\|echo`, `;dir` | `nuscrape-ci-canary` in body; or `Volume in drive` / `Directory of` |

**Phase 2 — blind timing:** When canary-based Phase 1 finds nothing, applies the same statistical timing approach as SQLi: 5-request baseline profile (σ > 500ms → skip), then three escalating `; sleep {N}` / `| sleep {N}` / `$(sleep {N})` probes at 2s / 4s / 6s. Threshold: `mean + 3σ + delay`.

| Finding | Severity | Signal |
|---|---|---|
| Canary echoed in response | CRITICAL | Shell execution confirmed |
| Windows dir output detected | CRITICAL | Shell execution confirmed (Windows) |
| 2–3 of 3 sleep probes exceed adaptive threshold | HIGH | Blind timing — confirmed |
| 1 of 3 sleep probes exceeds adaptive threshold | MEDIUM | Blind timing — weak signal |

- 10-second timeout per canary probe; `delay + 10s` for timing probes
- Skips third-party CDN domains and static asset paths
- WAF vendor noted in finding detail

---

#### LDAP Injection Detection

Two-phase detection against endpoints handling directory lookups. Requires `--active-probes`.

**Phase 1 — error-based URL parameter injection:** Appends 10 LDAP metacharacter payloads (`*`, `)(uid=*`, `*(|(uid=*))`, `\2a`, etc.) to each URL query parameter. Flags **CRITICAL** when any of 11 LDAP error strings are reflected (`LDAPException`, `javax.naming`, `Bad search filter`, `LdapErr`, `DSA is unwilling to perform`, etc.).

**Phase 2 — login form authentication bypass:** Identifies POST forms containing both a username-type and password-type field. Sends a baseline request with garbage credentials, then retries with classic LDAP wildcard payloads (`*`/`*`, `admin)(&)`/`anything`). Flags **HIGH** if the bypass response indicates a successful login via any of three independent signals:
- Final URL path contains a post-login segment (`dashboard`, `admin`, `profile`, `portal`, etc.)
- A new auth-related cookie appeared that was absent in the baseline response
- Response body contains a success phrase (`welcome`, `logged in`, `sign out`, etc.)

| Finding | Severity | Signal |
|---|---|---|
| LDAP error string reflected | CRITICAL | Error-based injection confirmed |
| Bypass response shows login success | HIGH | Authentication bypass confirmed |

- 8-second timeout per probe
- Skips third-party CDN domains and static asset paths
- WAF vendor noted in finding detail

---

#### Insecure Deserialization Detection

Two-tier detection: **passive** (runs on every crawled response, always active) and **active** (requires `--active-probes`).

**Passive detection** — scans each response body, `Content-Type`, and `Set-Cookie` header for serialized data format indicators:

| Format | Indicator | Severity |
|---|---|---|
| Java serialization | `AC ED 00 05` magic bytes in body; `rO0AB` Base64 prefix in body or cookie; `Content-Type: application/x-java-serialized-object` | MEDIUM |
| PHP serialization | `O:\d+:` / `a:\d+:` / `s:\d+:` patterns in response body or `Set-Cookie` | MEDIUM |
| Python pickle | `80 02`–`80 05` magic bytes; `Content-Type: application/python-pickle` | MEDIUM |
| Ruby Marshal | `04 08` magic bytes | MEDIUM |
| .NET ViewState | `__VIEWSTATE` hidden form field present | INFO |

**Active confirmation** (requires `--active-probes`) — only fires on endpoints where passive detection already found a signal:

| Target | Probe | Confirmation | Severity |
|---|---|---|---|
| Java endpoint | POST malformed serialization stream (magic header + truncated class descriptor for non-existent class `NuScrape`) | `InvalidClassException`, `ClassNotFoundException`, `StreamCorruptedException` in response | HIGH |
| PHP endpoint | POST syntactically incomplete serialized string (`O:9:"NuScrape":1:{`) | `unserialize(): Error`, `Cannot unserialize`, `__wakeup`, `__destruct` in response | HIGH |
| .NET ViewState | Extract `__VIEWSTATE`, flip last Base64 character, resubmit to form action | Server accepts tampered ViewState without MAC validation error → MAC disabled | HIGH |

The Java probe uses a truncated class descriptor that triggers a deserialization exception before any class is resolved — no class loading, no gadget chain execution. The PHP probe uses an incomplete object literal that PHP's unserialize() rejects immediately. No ysoserial payloads or exploit gadget chains are used.

- 10-second timeout per probe
- Deduplicates per `(endpoint, format)` pair
- WAF vendor noted in finding detail

---

#### Price Manipulation Detection

Tests checkout, cart, order, and payment endpoints for client-side price/quantity bypass vulnerabilities. Requires `--active-probes`. Only fires on endpoints matching a URL pattern (`/checkout`, `/cart`, `/order`, `/payment`, `/purchase`, `/buy`, `/basket`, `/booking`, `/ticket`) that accept a JSON request body containing price or quantity fields.

**Probes sent per detected field:**

| Probe | Payload | Detection signal |
|---|---|---|
| Negative price | `-1` | 2xx response with different body → server accepted negative value |
| Zero price | `0` | 2xx response with different body → zero-cost accepted |
| Fractional negative | `-0.01` | 2xx response with different body → float underflow accepted |
| Field removal | Field omitted from body | 2xx response with different body → missing field not validated |

| Finding | Severity |
|---|---|
| Server accepted negative/zero price | HIGH |
| Server accepted missing required price field | MEDIUM |

- `allow_redirects=False` to avoid completing transactions
- 8-second timeout per probe
- Deduplicates per `(endpoint, field_path)` pair

---

#### JWT Algorithm Confusion Detection

Tests for JWT security flaws on endpoints that return JWT tokens in response headers or body. Requires `--active-probes`. Three attack classes are probed:

**alg:none** — Strips the signature and rewrites the header to `{"alg":"none","typ":"JWT"}`. If the server accepts the token (non-401/403 response), the signature requirement is completely disabled.

**RS256 → HS256 confusion** — Fetches the server's public key from common JWKS paths (`/.well-known/jwks.json`, `/api/auth/keys`, etc.). Re-signs the original payload with the public key used as the HMAC-SHA256 secret. If the server accepts this token, it is verifying with the public key as a symmetric secret — a critical algorithm confusion vulnerability.

**Weak HS256 secret brute-force** — Re-signs the original payload with each of ~20 common development secrets (`secret`, `password`, `123456`, etc.). If any is accepted, full token forgery is possible.

| Finding | Severity |
|---|---|
| alg:none accepted | CRITICAL |
| RS256 → HS256 confusion confirmed | CRITICAL |
| Weak HS256 secret cracked | CRITICAL |

- Requires `pyjwt[crypto]` — skipped gracefully if not installed
- Deduplicates per `(endpoint, attack_class)` pair
- Known documentation placeholder secrets suppressed from findings

---

#### Race Condition Detection

Tests state-changing endpoints for race condition vulnerabilities by firing 10 simultaneous requests using a threading barrier. Requires `--active-probes`. Only fires on endpoints matching known sensitive operation patterns.

**Endpoint categories tested:**

| Pattern | Example paths | Risk |
|---|---|---|
| Coupon/promo redemption | `/coupon`, `/promo`, `/voucher`, `/redeem` | Double-spend a one-use code |
| Password reset | `/reset-password`, `/forgot-password` | Multiple valid reset tokens issued |
| Payment/checkout | `/checkout`, `/pay`, `/purchase` | Double-charge or double-fulfil |
| Vote/like/reaction | `/vote`, `/like`, `/upvote` | Ballot stuffing |
| Transfer/withdraw | `/transfer`, `/withdraw`, `/payout` | Balance race allowing overdraft |
| Account/resource creation | `/register`, `/signup`, `/create` | Duplicate account creation |
| Gift card/credit | `/gift-card`, `/credit`, `/redeem` | Multiple redemptions of single-use credit |

**Confirmation process (3 stages before alerting):**

**1. Reproducibility check** — the initial burst counts as attempt 1. If a signal is detected, NuScrape waits 5 seconds and fires two more bursts (attempts 2 and 3). A finding is only carried forward if ≥2 of 3 attempts reproduce the signal. Transient server errors that cause a one-time false positive are discarded.

Log format:
```
[Race] Attempt 1/3: 3/10 requests succeeded
[Race] Attempt 2/3: 2/10 requests succeeded
[Race] Attempt 3/3: 4/10 requests succeeded
```

**2. Response analysis** — successful response bodies are compared across all confirmed attempts:

| Signal | Interpretation |
|---|---|
| Distinct IDs, UUIDs, or tokens across responses | True race — separate operations were created |
| Sequential numeric IDs in responses | True race — multiple records created |
| All responses identical | Possible race but server may be idempotent — MEDIUM |
| Responses differ only in timestamp fields | False positive — timestamp-only diff ignored |
| ≥70% of concurrent requests returned non-200 | Rate limiting is working — skipped |

**3. Idempotency check** — before alerting, sends the same request twice sequentially (not concurrently). If both succeed with the same effective body the endpoint is designed to handle duplicates and the severity is downgraded to LOW.

| Sequential result | Idempotency verdict |
|---|---|
| Second request fails (4xx/5xx) where first succeeded | Non-idempotent — proceed |
| Both succeed with different response bodies | Non-idempotent — proceed |
| Both succeed with same effective body (modulo timestamps) | Idempotent — downgrade to LOW |

**Detection logic:**

| Finding | Severity | Signal |
|---|---|---|
| Race condition — distinct IDs returned | HIGH | ≥2/3 bursts confirm; responses contain different IDs/tokens |
| Race condition — multiple successes | HIGH | ≥2/3 bursts confirm; concurrent requests both succeed; non-idempotent |
| Race condition — identical responses | MEDIUM | Reproducible concurrent successes but all responses identical |
| Race condition — inconsistent responses | MEDIUM | Mixed status codes across simultaneous requests |
| Race condition — rate limit bypass | MEDIUM | All requests succeed on a rate-limited endpoint |
| Race condition — idempotent endpoint | LOW | Reproducible concurrent successes but sequential check confirms idempotency |

- Destructive endpoints (`/delete`, `/drop`, `/purge`, etc.) are blocklisted and never tested
- 10-second timeout per request; `delay + 5s` between confirmation attempts
- Deduplicates per endpoint URL

---

#### HTTP Parameter Pollution (HPP) Detection

Tests URL query parameters for server-side parsing discrepancies caused by duplicate parameter names. Requires `--active-probes`. Targets every query parameter found on crawled pages, linked `<a href>` URLs, and form actions.

**Three probe classes per parameter:**

**1. Duplicate order probes** — sends `?param=orig&param=nuscrape-hpp` and the reverse. Checks whether the canary appears in the response and in which position.

**2. WAF bypass split** — sends the full XSS payload `<script>` first (to test if WAF blocks it), then sends the payload split across two duplicate params: `?param=<scr&param=ipt>...`. If the single payload is blocked (4xx) but the split is not, the WAF can be bypassed by parameter duplication.

**3. Auth/privilege change detection** — if duplicating the parameter introduces privilege-indicating words (`admin`, `dashboard`, `privilege`, `role`, etc.) that were absent in the baseline response, flags as HIGH.

| Finding | Severity | Signal |
|---|---|---|
| Duplicate param triggers auth/privilege change | HIGH | Privilege keyword appeared only with duplicate param |
| WAF bypass via split payload | MEDIUM | Single payload blocked but split across duplicates was not |
| Last-wins parsing | MEDIUM | Canary reflected only when it is the second duplicate value |
| First-wins parsing | MEDIUM | Canary reflected only when it is the first duplicate value |
| Unexpected canary reflection | LOW | Canary reflected in both or either probe — unexpected parsing |

- 8-second timeout per probe; `stealth_delay` between requests
- Deduplicates per `(base_url, param)` pair

---

#### Web Cache Poisoning Detection

Tests cacheable endpoints for web cache poisoning vectors using safe canary values. Requires `--active-probes`. Only runs on endpoints that appear to be cached (see cacheability detection below).

**Cacheability detection** — an endpoint is considered cacheable if any of the following are present:
- `Cache-Control: public` or `Cache-Control: max-age=...`
- `Vary` response header
- CDN indicator headers: `x-cache`, `cf-cache-status`, `x-amz-cf-id`, `x-varnish`, `age`, `x-served-by`, etc.
- Static file extension (`.js`, `.css`, `.html`, `.json`, `.xml`, `.svg`, `.ico`, `.woff`)

**Three detection classes:**

**1. Unkeyed header injection** — sends each of the following headers individually and checks whether the injected value is reflected in the response body or any response header (`Location`, `Link`, etc.):

| Header | Injected value |
|---|---|
| `X-Forwarded-Host` | `nuscrape-cache-test.com` |
| `X-Forwarded-Scheme` | `nuscrape-cache-test` |
| `X-Original-URL` | `/nuscrape-cache-test` |
| `X-Rewrite-URL` | `/nuscrape-cache-test` |
| `X-Custom-IP-Authorization` | `127.0.0.1` |
| `X-Forwarded-For` | `127.0.0.1` |

**2. Fat GET detection** — sends a `GET` request with a conflicting body parameter. If the body value appears in the response instead of the URL parameter value, the server processes GET request bodies and may allow cache poisoning via the body parameter.

**3. Parameter cloaking** — appends `;param=nuscrape-cache-test-cloak` to the URL. If the cloaked value appears in the response, the cache may key on the URL before the semicolon while the backend processes the full string.

| Finding | Severity | Signal |
|---|---|---|
| Unkeyed header reflected in response | HIGH | Injected header value appears in body or response headers |
| Fat GET body parameter reflected | MEDIUM | GET body parameter overrides or appears alongside URL parameter |
| Semicolon parameter cloaking | MEDIUM | Cloaked parameter value reflected in response body |

**Safety rules enforced:**
- Canary values are harmless strings — no XSS or HTML payloads
- Only one probe per `(endpoint, header)` pair — never re-sends a poisoned header to avoid polluting the cache for real users
- Stops testing an endpoint immediately on first confirmed reflection
- Does not fetch the cached copy from a different IP — reflection in the direct response is the signal; manual verification confirms actual cache storage

- 8-second timeout per probe
- Deduplicates per `(base_url, test_name)` pair

---

#### Accuracy Improvements: Response Diffing, Context-Aware Payloads, and Multi-Stage Verification

Three cross-cutting accuracy mechanisms apply to all injection detection checks that require `--active-probes`.

**Multi-stage verification**

Before firing a CRITICAL or HIGH alert, NuScrape automatically sends an identical second probe 2 seconds later to confirm the finding is independently reproducible.

- If the second response confirms the finding → alert fires at original severity
- If the second response does not reproduce the finding → severity is downgraded by one level and `(UNVERIFIED)` is appended to the finding detail

| Original severity | Verified | Unverified |
|---|---|---|
| CRITICAL | CRITICAL | HIGH (UNVERIFIED) |
| HIGH | HIGH | MEDIUM (UNVERIFIED) |

Applied to: SQL injection (error-based and time-based), command injection, SSTI, path traversal, XXE injection, LDAP injection, open redirect, and default credential acceptance.

Log output:
```
[Verify] Confirming CRITICAL SQL INJECTION (ERROR-BASED) on example.com ...
[Verify] Confirmed — firing alert
[Verify] Failed — downgrading to HIGH (UNVERIFIED)
```

**Response diffing**

Before flagging a finding, NuScrape fetches and caches a clean baseline response (no payload) for each `(endpoint, params)` combination. A finding is only raised if the difference between the probe response and the baseline is meaningful:

| Condition | Verdict |
|---|---|
| HTTP status code changed | Meaningful |
| Canary appears in probe but not in baseline | Meaningful |
| New server/DB error string appeared absent in baseline | Meaningful |
| Body length changed by >10% and >50 bytes | Meaningful |
| Only change is <50 bytes (timestamp / session noise) | Not meaningful — suppressed |
| Error string was already present in baseline | Not meaningful — suppressed |

Applied to: SQL injection, command injection, SSTI, path traversal, CRLF injection.

**Context-aware payload selection**

Before injecting payloads, NuScrape examines the baseline response body to determine where the parameter value is rendered. The detected context is logged as `[Context] param=<name> in <context> context` and selects the most appropriate payload variant:

| Detected context | How identified | Effect |
|---|---|---|
| `html_attr` | Param value inside `attr="...value..."` | Context-breaking CMDi payloads prepended: `" && echo canary` |
| `html_body` | Param value between `>...value...<` tags | (logged; generic payloads used) |
| `js_string` | Param value inside a JS string literal | JS string-breaking CMDi payloads prepended: `"; echo canary;//` |
| `json` | Param value inside a JSON string value | JSON-breaking CMDi payloads prepended: `"; echo canary; "` |
| `url_context` | Param value inside `href`/`src`/`action` | (logged; generic payloads used) |
| `unknown` | Value not found in response | Generic payloads used |

For SQL injection, when Phase 1 fingerprints the DB via an error string, DB-specific templates are prioritised in Phase 2. The `{N}` placeholder is replaced by the actual probe delay (2, 4, or 6 seconds):

| DB fingerprinted | Fingerprint strings | Time template |
|---|---|---|
| MySQL | `mysql_fetch`, `SQL syntax`, `Warning: mysql` | `' OR SLEEP({N})--` |
| PostgreSQL | `PostgreSQL ERROR`, `Warning: pg_` | `' OR pg_sleep({N})--` |
| MSSQL | `Microsoft OLE DB`, `ODBC SQL Server` | `'; WAITFOR DELAY '0:0:{N}'--` |
| SQLite | `SQLite3::` | `' OR randomblob({N}×50M)--` |
| Oracle | `ORA-` | `dbms_pipe.receive_message(chr(0),{N})` |
| Generic (fallback) | — | `' OR SLEEP({N})--` / `WAITFOR DELAY '0:0:{N}'--` |

Applied to: SQL injection (diffing + DB-specific time payloads), command injection (diffing + context-breaking payloads), SSTI (diffing), path traversal (diffing), CRLF injection (diffing).

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

## Terminal Output and Confidence Scoring

### Color-coded output

When running in a real terminal (not piped to a file), NuScrape uses ANSI colors via `colorama` to make findings immediately scannable. Colors are suppressed automatically when `sys.stdout.isatty()` is False — piped or redirected output is always plain text.

| Element | Color |
|---|---|
| CRITICAL alert banner and `!!` markers | Bright red |
| HIGH severity label | Red |
| MEDIUM severity label | Yellow |
| LOW severity label | Cyan |
| INFO severity label | White |
| `ERROR:` log prefix | Bright red |
| Subdomain found / CT subdomain live | Green |
| Scan start and completion messages | Bright green |

### Confidence scoring

Every finding stored in the `Alerts` table (and displayed in the UI) carries a **confidence** level that indicates how certain NuScrape is that the finding represents a real vulnerability rather than a false positive.

| Level | Meaning |
|---|---|
| `CONFIRMED` | Finding was verified with body content, header reflection, or credential check with body fingerprinting — no manual follow-up required to confirm existence |
| `LIKELY` | Strong automated indicators present but not fully verified — review recommended before reporting |
| `NEEDS VERIFICATION` | Automated detection only; manual confirmation required before reporting |

**Mapping by finding type:**

| Finding type | Confidence |
|---|---|
| Default credentials accepted (body-verified) | CONFIRMED |
| Open redirect (Location header verified) | CONFIRMED |
| CRLF injection (header reflected) | CONFIRMED |
| Path traversal (file content signatures) | CONFIRMED |
| SSTI (arithmetic result reflected) | CONFIRMED |
| XXE injection (canary reflected) | CONFIRMED |
| Prototype pollution (canary reflected in body) | CONFIRMED |
| Spring Boot Actuator (body signature confirmed) | CONFIRMED |
| Exposed secrets in JS (value confirmed in bundle) | CONFIRMED |
| Laravel / Django / Drupal / Joomla file exposure (body-confirmed) | CONFIRMED |
| Missing or misconfigured security headers | CONFIRMED (factual observation) |
| Insecure cookies / JWT findings | CONFIRMED |
| Subdomain takeover (404 on unclaimed service) | LIKELY |
| HTTP request smuggling (timing/status signal) | LIKELY |
| GraphQL introspection (schema returned) | LIKELY |
| CORS misconfiguration (header reflected) | LIKELY |
| Mass assignment (field reflected) | LIKELY |
| Dangerous HTTP method accepted | LIKELY |
| WebSocket origin / auth findings | LIKELY |
| API version enumeration | LIKELY |
| DNS zone transfer, SPF/DMARC/DKIM | LIKELY |
| SSRF confirmed (OOB interaction from target IP) | CONFIRMED |
| SSRF likely (OOB interaction, unexpected source IP) | LIKELY |
| SSRF: cloud metadata accessible | CONFIRMED |
| SSRF candidate (no OOB interaction / OOB unavailable) | NEEDS VERIFICATION |
| IDOR candidates | NEEDS VERIFICATION |
| Admin panel 200 (generic, no body verification) | NEEDS VERIFICATION |
| Prototype pollution crash (500 on injection) | NEEDS VERIFICATION |
| Command injection (canary confirmed in body) | CONFIRMED |
| Command injection (blind timing — 2–3 probes confirmed) | CONFIRMED |
| Command injection (blind timing — 1 probe, weak signal) | NEEDS VERIFICATION |
| SQL injection (error string reflected) | CONFIRMED |
| SQL injection (time-based blind — 2–3 probes confirmed) | CONFIRMED |
| SQL injection (time-based blind — 1 probe, weak signal) | NEEDS VERIFICATION |
| LDAP injection (error string reflected) | CONFIRMED |
| JWT algorithm confusion (alg:none / RS256→HS256 / weak secret) | CONFIRMED |
| Price manipulation (server accepted probe) | CONFIRMED |
| Race condition — distinct IDs returned (2/3 bursts confirmed) | CONFIRMED |
| Race condition — multiple successes (2/3 bursts confirmed) | CONFIRMED |
| Race condition — identical responses | NEEDS VERIFICATION |
| Race condition — inconsistent responses | NEEDS VERIFICATION |
| Race condition — idempotent endpoint (downgraded) | NEEDS VERIFICATION |
| Insecure deserialization (active probe exception reflected) | CONFIRMED |
| Insecure deserialization (passive format signal) | NEEDS VERIFICATION |
| HTTP parameter pollution — auth/privilege change | CONFIRMED |
| HTTP parameter pollution — WAF bypass, first/last-wins | CONFIRMED |
| HTTP parameter pollution — unexpected reflection | LIKELY |
| Web cache poisoning — unkeyed header reflected | CONFIRMED |
| Web cache poisoning — fat GET / parameter cloaking | NEEDS VERIFICATION |

Confidence is inferred automatically from the `alert_type` string — no changes to existing call sites are needed. The level is stored in the `Alerts` database table and displayed in both the terminal alert banner and the UI findings table as a colored badge (green = CONFIRMED, yellow = LIKELY, cyan = NEEDS VERIFICATION).

Findings that pass multi-stage verification are always CONFIRMED. Findings that fail verification carry `(UNVERIFIED)` in their detail and are downgraded one severity level.

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

**Google tracking / CDN URL filter** — `play.google.com`, `google-analytics.com`, `analytics.google.com`, `googletagmanager.com`, `googleadservices.com`, `doubleclick.net`, `maps.google.com`, `maps.googleapis.com`, `fonts.googleapis.com`, and `fonts.gstatic.com` are skipped during crawling by default. Disable with `--no-skip-google-tracking`.

**TODO comment scope** — Comment scanning is restricted to first-party JS only (CDN and vendor URLs excluded) and requires explicit `TODO`, `FIXME`, `HACK`, or `NOTE` keywords — not arbitrary keyword matches.

**IDOR 5-stage verification** — See [IDOR Candidates](#idor-candidates-verified) above. Eliminates the vast majority of false positives from numeric IDs in CSS paths, public help article IDs, cache-busting hashes, etc.

**Default credential confirmation** — Login attempts require body or header confirmation signatures before declaring success. A bare 200 response is never sufficient.

---

## Responsible Disclosure

NuScrape is designed for **responsible disclosure research only**. All active probes (backup files, credential testing, open redirect injection, IDOR verification) are limited to confirming the existence of a vulnerability and do not exfiltrate data, maintain persistence, or cause service disruption.

> **Note:** Payload-injecting checks (path traversal, SSTI, CRLF injection, CORS evil-origin probes, default credential tests, WebSocket security probes, XXE injection, prototype pollution, HTTP request smuggling) are **disabled by default** and must be explicitly enabled with `--active-probes`. A warning is printed at startup and displayed in the UI whenever this flag is active. Only enable it against targets you are authorised to test.

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
    │       │     ├─ WebSocket endpoint discovery (ws://, JS calls, Upgrade header)
    │       │     ├─ Open redirect detection (WAF-suppressed)  ┐
    │       │     ├─ GraphQL introspection (per-page URL)      │
    │       │     ├─ Mass assignment (POST/PUT form endpoints)  │ requires --active-probes
    │       │     ├─ API version enumeration                    │
    │       │     ├─ WebSocket security (origin, auth, scheme) │
    │       │     ├─ XXE injection (XML/SOAP endpoints)        │
    │       │     ├─ Prototype pollution (body, query, JS sinks)│
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
    │             ├─ Zone transfer attempt (AXFR against all NSes, 5s timeout)
    │             │     └─ On success: all A/CNAME hostnames → subdomain pipeline
    │             ├─ ASN lookup
    │             ├─ Technology fingerprinting (headers, cookies, HTML meta, page source)
    │             │     └─ On detection: technology-specific checks
    │             │           (WP login/xmlrpc/users/debug.log, Laravel log/.env/Telescope/Horizon/debug,
    │             │            Spring Boot Whitelabel, Django debug/admin/toolbar,
    │             │            Rails info/mailers, Drupal changelog/settings/admin,
    │             │            Joomla admin/config.bak/readme)
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
    │                   ├─ CORS misconfiguration                │
    │                   ├─ Default credentials                  │ requires --active-probes
    │                   ├─ Dangerous HTTP methods               │
    │                   └─ HTTP request smuggling (CL.TE/TE.CL) ┘
    │                   ├─ WAF fingerprinting
    │                   └─ /.well-known/ enumeration
    │
    └─ All findings → ScrapeDB → UI alerts tab
```
