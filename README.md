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
```

### Web UI

Start `app.py` and open `http://localhost:5000`. The control panel sidebar lets you configure all scan options and toggle features including `--no-social` and Playwright. All views update live as the crawler runs.

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
- **Email addresses** — scraped from page content
- **Page titles** — for every crawled URL
- **HTTP history** — status code for every request made
- **robots.txt and sitemap.xml** — fetched and stored
- **XHR/API endpoints** — extracted from JS bundles via regex pattern matching
- **Security headers** — presence/absence of CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and leaking headers (Server, X-Powered-By)
- **SPF and DMARC** — DNS-based email authentication policy analysis

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

#### CORS Misconfiguration
Tests whether the server reflects arbitrary `Origin` headers with `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials: true`. Enables cross-origin data theft when combined with an XSS. **HIGH.**

---

#### SPF / DMARC Analysis
Checks DNS for SPF and DMARC records. Flags missing records, weak policies (`p=none`), and overly permissive SPF (`+all`). Missing or weak email authentication enables spoofing of the domain in phishing emails. **MEDIUM/HIGH.**

---

#### Insecure Session Cookies
Inspects `Set-Cookie` headers on every page response for session-identifying cookies (`session`, `auth`, `token`, `jwt`, `sid`, etc.) missing `HttpOnly`, `Secure`, or `SameSite` flags.

- Missing `HttpOnly` — cookie readable by JavaScript, enabling theft via XSS
- Missing `Secure` — cookie transmitted over HTTP, interceptable
- Missing `SameSite` — vulnerable to CSRF attacks

**MEDIUM** (one flag missing) / **HIGH** (two or more missing).

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

**CRITICAL** when login succeeds.

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
Probes 10 common GraphQL paths (`/graphql`, `/api/graphql`, `/gql`, `/graphiql`, `/playground`, etc.) with a full introspection query. If the schema is returned, the complete API surface — all types, queries, mutations, and field names — is exposed to unauthenticated attackers. **HIGH.**

---

#### Open Redirect
Parses all links on every crawled page looking for 30 common redirect parameter names (`next`, `url`, `redirect`, `return_to`, `goto`, `callback`, etc.). Injects an external canary URL and checks for a 3xx response pointing to it. Deduplicates per `(endpoint, parameter)` pair. **HIGH** when confirmed.

---

#### JWT Analysis
Scans page HTML, JS bundles, and response headers for JWT tokens. Analyses each unique token for:

- **`alg:none`** — signature verification bypassed entirely. Full token forgery possible. **CRITICAL.**
- **Weak HS256 secret** — tests 30 common development secrets by recomputing HMAC-SHA256. If cracked, full token forgery is possible. **CRITICAL.**
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

#### Subdomain Takeover
Checks the CNAME chain for every discovered live subdomain against 20 known takeover-vulnerable services including GitHub Pages, Heroku, AWS S3, Azure, Fastly, Shopify, Netlify, Zendesk, Tumblr, Surge, Webflow, and others.

| Result | Severity | Meaning |
|---|---|---|
| CNAME matches + body fingerprint confirmed | CRITICAL | Subdomain is confirmed unclaimed and takeable |
| CNAME matches + body unconfirmed | MEDIUM | Service is vulnerable class; verify manually whether the target is claimable |
| CNAME matches + no HTTP response | HIGH | Endpoint is dead but DNS record persists |

The MEDIUM alert exists because some services (e.g. Netlify with a custom domain attached) return non-standard responses that don't match the fingerprint, but the underlying site name may still be unclaimed.

---

#### S3 Bucket Exposure
Extracts AWS S3 bucket names from three URL patterns found in page HTML and JS bundles:
- `https://bucketname.s3.amazonaws.com`
- `https://s3.amazonaws.com/bucketname`
- `s3://bucketname`

Probes each unique bucket name once. **CRITICAL** if the bucket returns a public `ListBucket` XML response. Logs quietly if private (403) or non-existent (404/NoSuchBucket).

---

#### FTP Anonymous Login
If port 21 is found open during port scanning, attempts an anonymous FTP login. **CRITICAL** when successful.

---

#### MySQL Unauthenticated Access
If port 3306 is found open, probes for access without credentials. **CRITICAL** when the server accepts a connection without authentication.

---

### Alert Severity Levels

| Severity | Colour | Meaning |
|---|---|---|
| CRITICAL | Red | Immediate exploitability — credentials exposed, authentication bypassed, data directly accessible |
| HIGH | Orange | Serious vulnerability requiring manual confirmation or a second step to exploit |
| MEDIUM | Yellow | Meaningful security weakness — lower impact or requires specific conditions |

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
| `JSFindings` | Secrets, endpoints, staging URLs, IDOR candidates, JWT findings |
| `Robots` | robots.txt content per domain |
| `Sitemap` | Sitemap URL inventory |

**Export:** Every table is exportable as CSV or JSON from the Report tab in the UI, or directly via `/api/export/<table>.<csv|json>`.

**Clear:** The "Clear Database" button in the UI wipes all tables without deleting the file.

---

## False Positives & Noise Reduction

Several measures are in place to reduce noise:

**Wildcard DNS suppression** — Before subdomain enumeration, two random canary subdomains are probed. If both resolve (indicating a wildcard `*.domain.com` record), all subdomains resolving to the same IP are suppressed. A secondary HTTP-level check catches CDN wildcard responses (e.g. Cloudflare) that return HTTP 200 for any subdomain via shared IPs.

**Backup file canary probes** — Before flagging backup file exposure, a random canary path is tested. If it also returns 200, the server is returning catch-all responses and backup findings for that domain are suppressed.

**JS endpoint noise filter** — Endpoints extracted from JS bundles are filtered against a blocklist of ~40 known public/CDN domains including all ArcGIS/Esri services, Google Maps, Mapbox, Google Analytics/Tag Manager, Cloudflare, jsDelivr, Segment, HotJar, Sentry, HubSpot, Intercom, and others.

**JS secret false positive filters** — Extracted secrets are checked against a list of placeholder patterns (`example`, `your_key`, `REPLACE`, `changeme`, etc.) and known public key formats (Stripe publishable keys, Google Maps embed keys) before alerting.

**IDOR 5-stage verification** — See [IDOR Candidates](#idor-candidates-verified) above. Eliminates the vast majority of false positives from numeric IDs in CSS paths, public help article IDs, cache-busting hashes, etc.

**Default credential false positive guard** — Login attempts check for explicit failure strings and failure redirect URLs before declaring success. A 200 response alone is not sufficient to trigger an alert.

---

## Responsible Disclosure

NuScrape is designed for **responsible disclosure research only**. All active probes (backup files, credential testing, open redirect injection, IDOR verification) are limited to confirming the existence of a vulnerability and do not exfiltrate data, maintain persistence, or cause service disruption.

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
    │       │     ├─ Cookie security flags
    │       │     ├─ JWT scan (HTML + headers)
    │       │     ├─ Open redirect detection
    │       │     ├─ IDOR candidate collection + verification
    │       │     ├─ JS bundle analysis (endpoints, secrets, staging URLs, JWTs, S3 refs)
    │       │     └─ S3 bucket probing
    │       │
    │       └─ Per new domain discovered
    │             ├─ DNS / MX / SSL / WHOIS
    │             ├─ ASN lookup
    │             ├─ Technology fingerprinting
    │             ├─ Port scan
    │             ├─ Subdomain enumeration (with wildcard suppression)
    │             │     └─ Per subdomain: takeover check
    │             ├─ Security header audit
    │             ├─ SPF / DMARC
    │             └─ Exposure checks (once per base URL)
    │                   ├─ .git / .env exposure
    │                   ├─ Directory listing
    │                   ├─ Backup file exposure
    │                   ├─ CORS misconfiguration
    │                   ├─ Default credentials
    │                   ├─ GraphQL introspection
    │                   └─ Spring Boot Actuator
    │
    └─ All findings → ScrapeDB → UI alerts tab
```
