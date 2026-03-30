#!/usr/bin/env python3
import os, sys, sqlite3, subprocess, threading, time, json, signal, csv, io
from datetime import datetime
from collections import deque
from flask import Flask, jsonify, request, Response

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "ScrapeDB")
CRAWLER  = os.path.join(BASE_DIR, "main.py")
SCAN_LOG = os.path.join(BASE_DIR, "scan.log")   # persistent rolling log

# ── Crawler state ─────────────────────────────────────────────
crawler_proc  = None
crawler_lock  = threading.Lock()
log_buffer    = deque(maxlen=500)
log_total     = [0]   # mutable so stream thread can increment
log_lock      = threading.Lock()
crawler_stats = {"started": None, "domain": None}
_stopped_by_user = [False]   # set True when /api/stop is called — suppresses auto-restart

def ts():
    return datetime.now().strftime("%H:%M:%S")

def push_log(line):
    with log_lock:
        log_buffer.append({"t": ts(), "msg": line.rstrip()})
        log_total[0] += 1

def _write_scan_log(text):
    """Append a line to the persistent scan log file (best-effort)."""
    try:
        with open(SCAN_LOG, "a", encoding="utf-8") as f:
            f.write(text if text.endswith("\n") else text + "\n")
    except Exception:
        pass

def stream_proc(proc, cleanup_files=None):
    """Read subprocess stdout, push to in-memory buffer, write to scan.log.

    cleanup_files: optional list of temp file paths to delete after the
    process exits (e.g. the domains list written for --domains).
    """
    for line in iter(proc.stdout.readline, b""):
        decoded = line.decode("utf-8", errors="replace")
        push_log(decoded)
        _write_scan_log(decoded)
    proc.stdout.close()

    # ── Post-exit: detect unexpected crash and auto-restart ───
    exit_code = proc.wait()

    # Clean up any temporary files created for this run
    for _path in (cleanup_files or []):
        try:
            os.unlink(_path)
        except OSError:
            pass

    domain    = crawler_stats.get("domain")
    # Guard against poisoned domain values (e.g. error strings from a previous crash loop)
    if domain and not (domain.startswith("http://") or domain.startswith("https://")):
        domain = None

    if exit_code != 0 and not _stopped_by_user[0] and domain:
        msg = (f"[NuScrape] main.py exited with code {exit_code} — "
               f"restarting in 15 s (domain: {domain})")
        push_log(msg)
        _write_scan_log(msg)
        time.sleep(15)
        # Only restart if no new scan was started in the meantime
        with crawler_lock:
            if crawler_proc is proc:   # still the same dead process
                _launch_crawler(domain)
    elif exit_code == 0 and not _stopped_by_user[0]:
        msg = f"[NuScrape] Scan completed cleanly (exit 0) for {domain}."
        push_log(msg)
        _write_scan_log(msg)

# ── DB helpers ────────────────────────────────────────────────
def qdb(sql, args=()):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = [dict(r) for r in conn.execute(sql, args).fetchall()]
        conn.close()
        return rows
    except Exception:
        return []

def count(table, col="*"):
    try:
        r = qdb(f"SELECT COUNT({col}) as c FROM {table}")
        return r[0]["c"] if r else 0
    except Exception:
        return 0

# ── Routes ────────────────────────────────────────────────────

def nocache(resp):
    """Attach no-store headers so browsers never cache API responses."""
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp

@app.route("/")
def index():
    return Response(HTML, mimetype="text/html")

# -- Crawler control --

# Stored launch args so auto-restart can reuse them
_last_cmd = [None]

def _launch_crawler(domain, cmd=None, cleanup_files=None):
    """Spawn main.py and start the stream/watchdog thread. Must be called
    with crawler_lock held (or at startup before Flask is serving).

    cleanup_files: optional list of temp file paths deleted after the
    subprocess exits (e.g. the --domains targets file).
    """
    global crawler_proc
    if not domain or not (domain.startswith("http://") or domain.startswith("https://")):
        _write_scan_log(f"[NuScrape] _launch_crawler blocked: invalid domain {domain!r}\n")
        return
    if cmd is None:
        cmd = _last_cmd[0]
    _last_cmd[0] = cmd
    _stopped_by_user[0] = False

    _write_scan_log(f"\n{'='*60}\n[NuScrape] Starting scan → {domain}  @ {datetime.now()}\n{'='*60}\n")
    push_log(f"[NuScrape] Starting crawler → {domain}")

    crawler_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=BASE_DIR,
    )
    crawler_stats["started"] = ts()
    crawler_stats["domain"]  = domain

    t = threading.Thread(target=stream_proc,
                         args=(crawler_proc,),
                         kwargs={"cleanup_files": cleanup_files or []},
                         daemon=True)
    t.start()

@app.route("/api/start", methods=["POST"])
def api_start():
    global crawler_proc
    data        = request.json or {}
    domain      = data.get("domain", "").strip()
    rate_min    = float(data.get("rate_min", 1.0))
    rate_max    = float(data.get("rate_max", 3.0))
    concurrency = int(data.get("concurrency", 5))
    same_domain   = bool(data.get("same_domain", False))
    resume        = bool(data.get("resume", False))
    ignore_robots = bool(data.get("ignore_robots", False))
    use_playwright = bool(data.get("playwright", False))
    no_social           = bool(data.get("no_social", False))
    skip_google_tracking = bool(data.get("skip_google_tracking", True))
    stealth_profile = data.get("stealth_profile", "LOUD").upper()
    if stealth_profile not in ("LOUD", "NORMAL", "GHOST"):
        stealth_profile = "LOUD"
    # custom_headers: list of "Key:Value" strings from the UI textarea
    custom_headers_raw = data.get("custom_headers", [])
    if not isinstance(custom_headers_raw, list):
        custom_headers_raw = []
    custom_headers = [
        h.strip() for h in custom_headers_raw
        if isinstance(h, str) and h.strip() and ":" in h.strip()
    ]
    active_probes   = bool(data.get("active_probes", False))
    no_baseline     = bool(data.get("no_baseline", False))
    tutorial_mode   = bool(data.get("tutorial_mode", False))
    scope_file      = data.get("scope_file", "").strip()
    # Validate that the path refers to a temp file we created — never allow
    # arbitrary filesystem paths supplied by the client.
    if scope_file and not (
        scope_file.startswith(BASE_DIR) and os.path.isfile(scope_file)
    ):
        scope_file = ""

    # Multi-domain: optional list of domains from the UI textarea
    domains_list = data.get("domains_list", [])
    if not isinstance(domains_list, list):
        domains_list = []
    import re as _re
    _cidr_re     = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$')
    _ip_re       = _re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')
    _wildcard_re = _re.compile(r'^\*\..+')
    domains_list = [
        d.strip() for d in domains_list
        if isinstance(d, str) and d.strip()
           and (
               d.strip().startswith("http://")
               or d.strip().startswith("https://")
               or _cidr_re.match(d.strip())
               or _ip_re.match(d.strip())
               or _wildcard_re.match(d.strip())
           )
    ]
    # use_domains_file: any non-empty domains_list goes through --domains so that
    # CIDR entries and plain IPs are handled by main.py's expansion logic.
    use_domains_file = len(domains_list) >= 1
    parallel    = bool(data.get("parallel", False)) and len(domains_list) > 1

    # Derive a valid https:// URL for _launch_crawler's display/logging from
    # the first entry, which may be a wildcard, CIDR, bare IP, or plain URL.
    def _to_display_url(entry: str) -> str:
        if entry.startswith("http://") or entry.startswith("https://"):
            return entry
        if entry.startswith("*."):
            return "https://" + entry[2:]   # *.example.com → https://example.com
        return "https://" + entry           # bare IP, CIDR root, or hostname

    raw_first = domains_list[0] if domains_list else domain
    first_domain = _to_display_url(raw_first) if raw_first else ""

    if not first_domain:
        return jsonify({"ok": False, "error": "No domain provided"}), 400

    with crawler_lock:
        if crawler_proc and crawler_proc.poll() is None:
            return jsonify({"ok": False, "error": "Crawler already running"}), 400

        # ── Write domains file whenever a list is present ─────────────────
        # Always use --domains for textarea targets so CIDR/IP entries are
        # expanded by main.py's run_multi_domain path rather than being passed
        # raw as -D arguments.
        domains_file = None
        if use_domains_file:
            import tempfile
            tf = tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, dir=BASE_DIR,
                prefix="nuscrape_targets_",
            )
            tf.write("\n".join(domains_list))
            tf.close()
            domains_file = tf.name

        # ── Build command ─────────────────────────────────────────────────
        cmd = [sys.executable, "-u", CRAWLER, "--rate-min", str(rate_min),
               "--rate-max", str(rate_max), "--concurrency", str(concurrency)]

        if use_domains_file:
            cmd.extend(["--domains", domains_file])
            if parallel:
                cmd.append("--parallel")
        else:
            cmd.extend(["-D", first_domain])
            if resume:
                cmd.append("--resume")

        if same_domain:
            cmd.append("--same-domain-only")
        if ignore_robots:
            cmd.append("--ignore-robots")
        if use_playwright:
            cmd.append("--playwright")
        if no_social:
            cmd.append("--no-social")
        if not skip_google_tracking:
            cmd.append("--no-skip-google-tracking")
        if stealth_profile != "LOUD":
            cmd.extend(["--stealth", stealth_profile])
        if active_probes:
            cmd.append("--active-probes")
        if no_baseline:
            cmd.append("--no-baseline")
        if tutorial_mode:
            cmd.append("--tutorial")
        if scope_file:
            cmd.extend(["--scope", scope_file])
        for _hdr in custom_headers:
            cmd.extend(["--header", _hdr])
        cmd.append("--yes")  # UI handles confirmation; never block on interactive prompts

        with log_lock:
            log_buffer.clear()
            log_total[0] = 0

        mode_note = (f"multi-domain ({len(domains_list)}"
                     f"{' parallel' if parallel else ' sequential'})"
                     if use_domains_file else "single-domain")
        push_log(f"[NuScrape] Args: rate={rate_min}-{rate_max}s  concurrency={concurrency}"
                 f"  same-domain={same_domain}  stealth={stealth_profile}  mode={mode_note}")
        _launch_crawler(first_domain, cmd,
                        cleanup_files=[domains_file] if domains_file else [])

    return jsonify({"ok": True})

@app.route("/api/upload-scope", methods=["POST"])
def api_upload_scope():
    """Accept a HackerOne scope CSV upload and save it to a temp file.
    Returns {"ok": True, "path": "<absolute path>"} on success."""
    import tempfile
    f = request.files.get("scope_file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "No file provided"}), 400
    if not f.filename.lower().endswith(".csv"):
        return jsonify({"ok": False, "error": "File must be a .csv"}), 400
    tf = tempfile.NamedTemporaryFile(
        mode="wb", suffix=".csv", delete=False, dir=BASE_DIR,
        prefix="nuscrape_scope_",
    )
    f.save(tf.name)
    tf.close()
    return jsonify({"ok": True, "path": tf.name})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    global crawler_proc
    with crawler_lock:
        if crawler_proc and crawler_proc.poll() is None:
            _stopped_by_user[0] = True   # suppress auto-restart
            # SIGTERM triggers _handle_stop_signal in main.py, which sets
            # _stop_event so all worker threads observe the stop flag and
            # return early, then shuts down Playwright and exits cleanly.
            crawler_proc.terminate()
            _write_scan_log(f"[NuScrape] Scan stopped by user @ {datetime.now()}\n")
            push_log("[NuScrape] Crawler stopped by user.")
            # Wait up to 5 seconds for the process to exit gracefully,
            # then force-kill if it is still running.
            def _force_kill_if_needed(proc):
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    push_log("[NuScrape] Crawler did not exit within 5 s — sending SIGKILL.")
                    proc.kill()
            threading.Thread(
                target=_force_kill_if_needed, args=(crawler_proc,), daemon=True
            ).start()
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "No crawler running"})

@app.route("/api/status")
def api_status():
    running = crawler_proc is not None and crawler_proc.poll() is None
    return jsonify({
        "running": running,
        "domain":  crawler_stats["domain"],
        "started": crawler_stats["started"],
        "pid":     crawler_proc.pid if running else None,
    })

@app.route("/api/logs")
def api_logs():
    since = int(request.args.get("since", 0))
    with log_lock:
        all_logs  = list(log_buffer)
        total     = log_total[0]
    # Buffer holds the last N lines. Absolute index of first line in buffer:
    buf_start = max(0, total - len(all_logs))
    # Client offset is absolute. Find where to slice from in the buffer:
    if since <= buf_start:
        # Client is behind the buffer window — send everything we have
        new_lines = all_logs
    else:
        new_lines = all_logs[since - buf_start:]
    return jsonify({"lines": new_lines, "total": total})

@app.route("/api/scanlog")
def api_scanlog():
    """Return the last N lines of the persistent scan.log file.
    Useful for post-mortem debugging when the in-memory buffer has been cleared."""
    n = int(request.args.get("lines", 200))
    try:
        if not os.path.exists(SCAN_LOG):
            return jsonify({"lines": [], "size": 0})
        with open(SCAN_LOG, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        tail = [l.rstrip() for l in all_lines[-n:]]
        return jsonify({"lines": tail, "size": os.path.getsize(SCAN_LOG)})
    except Exception as e:
        return jsonify({"lines": [], "error": str(e)})

@app.route("/api/clear_db", methods=["POST"])
def api_clear_db():
    tables = ["Domains","Emails","DNS","MX","SSL","WHOIS","Ports",
              "HTTPHistory","Technologies","Robots","Sitemap",
              "SecurityHeaders","Subdomains","ASN","XHREndpoints","JSFindings","Alerts",
              "ZoneTransfer","WAF","WellKnown"]
    try:
        conn = sqlite3.connect(DB_PATH)
        for t in tables:
            try:
                conn.execute(f"DELETE FROM {t}")
            except Exception:
                pass   # table may not exist yet
        conn.commit()
        conn.close()
        push_log("[NuScrape] Database cleared.")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# -- Data APIs --

@app.route("/api/stats")
def api_stats():
    return nocache(jsonify({
        "domains":      count("Domains"),
        "emails":       count("Emails"),
        "ports":        count("Ports"),
        "tech":         count("Technologies", "DISTINCT technology"),
        "ssl":          count("SSL"),
        "mx":           count("MX"),
        "http":         count("HTTPHistory"),
        "subdomains":   count("Subdomains"),
        "secheaders":   count("SecurityHeaders"),
        "asn":          count("ASN"),
        "xhr":          count("XHREndpoints"),
        "js":           count("JSFindings"),
        "alerts":       count("Alerts"),
        "zone_records": count("ZoneTransfer"),
        "waf":          count("WAF"),
        "well_known":   count("WellKnown"),
    }))

@app.route("/api/domains")
def api_domains():
    return jsonify(qdb("""
        SELECT d.url, d.ip, d.servertype, d.content_type, d.title,
               a.asn, a.org, a.country, a.is_cdn, a.cdn_name
        FROM Domains d
        LEFT JOIN ASN a ON d.ip = a.ip
        ORDER BY d.url
    """))

@app.route("/api/asn")
def api_asn():
    return jsonify(qdb("SELECT ip,asn,org,country,is_cdn,cdn_name,looked_up FROM ASN ORDER BY org"))

@app.route("/api/xhr")
def api_xhr():
    return jsonify(qdb("SELECT url,endpoint,method,found_at FROM XHREndpoints ORDER BY found_at DESC"))

@app.route("/api/alerts")
def api_alerts():
    try:
        return nocache(jsonify(qdb("SELECT id,alert_type,severity,target,detail,confidence,found_at FROM Alerts ORDER BY id DESC")))
    except Exception:
        return nocache(jsonify([]))

@app.route("/api/js")
def api_js():
    return jsonify(qdb("SELECT url,js_url,finding_type,value,context,found_at FROM JSFindings ORDER BY finding_type,found_at DESC"))


@app.route("/api/technologies")
def api_technologies():
    return jsonify(qdb("SELECT url,technology FROM Technologies ORDER BY technology,url"))

@app.route("/api/ports")
def api_ports():
    return jsonify(qdb("SELECT DISTINCT domain,ip,port FROM Ports ORDER BY domain,port"))

@app.route("/api/ssl")
def api_ssl():
    return jsonify(qdb("SELECT DISTINCT domain,common_name,issuer,not_before,not_after FROM SSL ORDER BY domain"))

@app.route("/api/whois")
def api_whois():
    return jsonify(qdb("SELECT DISTINCT domain,registrar,creation_date,expiration_date FROM WHOIS ORDER BY domain"))

@app.route("/api/emails")
def api_emails():
    return jsonify(qdb("SELECT DISTINCT email_address FROM Emails ORDER BY email_address"))

@app.route("/api/dns")
def api_dns():
    return jsonify(qdb("SELECT DISTINCT domain,ip FROM DNS ORDER BY domain"))

@app.route("/api/mx")
def api_mx():
    return jsonify(qdb("SELECT DISTINCT domain,mx_host,preference FROM MX ORDER BY domain,preference"))

@app.route("/api/http_history")
def api_http_history():
    return jsonify(qdb("SELECT url,status_code,checked_at FROM HTTPHistory ORDER BY checked_at DESC LIMIT 200"))

@app.route("/api/security_headers")
def api_security_headers():
    return jsonify(qdb("SELECT domain,present,missing,leaking,checked_at FROM SecurityHeaders ORDER BY checked_at DESC"))

@app.route("/api/subdomains")
def api_subdomains():
    return jsonify(qdb("SELECT root_domain,subdomain,ip,status_code,found_at FROM Subdomains ORDER BY root_domain,subdomain"))

@app.route("/api/zone_transfers")
def api_zone_transfers():
    return jsonify(qdb("SELECT root_domain,nameserver,record,found_at FROM ZoneTransfer ORDER BY root_domain,nameserver"))

@app.route("/api/waf")
def api_waf():
    return jsonify(qdb("SELECT domain,waf_vendor,detected_by,found_at FROM WAF ORDER BY domain"))

@app.route("/api/well_known")
def api_well_known():
    return jsonify(qdb("SELECT domain,path,category,content_snippet,found_at FROM WellKnown ORDER BY domain,path"))

# -- Resume state --

@app.route("/api/resume_state")
def api_resume_state():
    state_file = os.path.join(BASE_DIR, "crawl_state.json")
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                s = json.load(f)
            return jsonify({
                "available": True,
                "domain":    s.get("start_url"),
                "saved_at":  s.get("saved_at"),
                "queue":     len(s.get("url_queue", [])),
                "crawled":   s.get("pages_crawled", 0),
            })
        except Exception:
            pass
    return jsonify({"available": False})

# -- Reporting & export --

@app.route("/api/report")
def api_report():
    top_tech = qdb("SELECT technology, COUNT(*) as cnt FROM Technologies GROUP BY technology ORDER BY cnt DESC LIMIT 10")
    open_ports = qdb("SELECT port, COUNT(*) as cnt FROM Ports GROUP BY port ORDER BY cnt DESC")
    status_breakdown = qdb("SELECT status_code, COUNT(*) as cnt FROM HTTPHistory GROUP BY status_code ORDER BY cnt DESC")
    ssl_expiring = qdb("SELECT domain, not_after FROM SSL WHERE not_after != 'Unknown' ORDER BY not_after ASC LIMIT 10")
    top_registrars = qdb("SELECT registrar, COUNT(*) as cnt FROM WHOIS GROUP BY registrar ORDER BY cnt DESC LIMIT 5")
    worst_headers = qdb("""
        SELECT domain, missing, leaking FROM SecurityHeaders
        WHERE missing != '' OR leaking != ''
        ORDER BY checked_at DESC LIMIT 10
    """)
    return jsonify({
        "generated_at": ts(),
        "totals": {
            "domains":      count("Domains"),
            "emails":       count("Emails"),
            "open_ports":   count("Ports"),
            "technologies": count("Technologies", "DISTINCT technology"),
            "ssl_certs":    count("SSL"),
            "mx_records":   count("MX"),
            "http_requests":count("HTTPHistory"),
            "subdomains":   count("Subdomains"),
        },
        "top_technologies":      top_tech,
        "open_ports":            open_ports,
        "http_status_breakdown": status_breakdown,
        "ssl_expiring_soonest":  ssl_expiring,
        "top_registrars":        top_registrars,
        "worst_security_headers":worst_headers,
    })

def make_csv(rows, fieldnames):
    out = io.StringIO()
    w = csv.DictWriter(out, fieldnames=fieldnames, extrasaction='ignore')
    w.writeheader()
    w.writerows(rows)
    return out.getvalue()

@app.route("/api/export/<table>.<fmt>")
def api_export(table, fmt):
    exports = {
        "domains":         ("SELECT DISTINCT url,ip,servertype,content_type,title FROM Domains ORDER BY url",
                            ["url","ip","servertype","content_type","title"]),
        "emails":          ("SELECT DISTINCT email_address FROM Emails ORDER BY email_address",
                            ["email_address"]),
        "ports":           ("SELECT DISTINCT domain,ip,port FROM Ports ORDER BY domain,port",
                            ["domain","ip","port"]),
        "ssl":             ("SELECT DISTINCT domain,common_name,issuer,not_before,not_after FROM SSL ORDER BY domain",
                            ["domain","common_name","issuer","not_before","not_after"]),
        "whois":           ("SELECT DISTINCT domain,registrar,creation_date,expiration_date FROM WHOIS ORDER BY domain",
                            ["domain","registrar","creation_date","expiration_date"]),
        "technologies":    ("SELECT url,technology FROM Technologies ORDER BY technology,url",
                            ["url","technology"]),
        "dns":             ("SELECT DISTINCT domain,ip FROM DNS ORDER BY domain",
                            ["domain","ip"]),
        "mx":              ("SELECT DISTINCT domain,mx_host,preference FROM MX ORDER BY domain",
                            ["domain","mx_host","preference"]),
        "subdomains":      ("SELECT root_domain,subdomain,ip,status_code,found_at FROM Subdomains ORDER BY root_domain,subdomain",
                            ["root_domain","subdomain","ip","status_code","found_at"]),
        "security_headers":("SELECT domain,present,missing,leaking,checked_at FROM SecurityHeaders ORDER BY domain",
                            ["domain","present","missing","leaking","checked_at"]),
        "asn":             ("SELECT ip,asn,org,country,is_cdn,cdn_name,looked_up FROM ASN ORDER BY org",
                            ["ip","asn","org","country","is_cdn","cdn_name","looked_up"]),
        "xhr":             ("SELECT url,endpoint,method,found_at FROM XHREndpoints ORDER BY found_at DESC",
                            ["url","endpoint","method","found_at"]),
        "js_findings":     ("SELECT url,js_url,finding_type,value,context,found_at FROM JSFindings ORDER BY finding_type",
                            ["url","js_url","finding_type","value","context","found_at"]),
        "alerts":          ("SELECT alert_type,severity,confidence,target,detail,found_at FROM Alerts ORDER BY found_at DESC",
                            ["alert_type","severity","confidence","target","detail","found_at"]),
        "waf":             ("SELECT domain,waf_vendor,detected_by,found_at FROM WAF ORDER BY domain",
                            ["domain","waf_vendor","detected_by","found_at"]),
        "zone_transfers":  ("SELECT root_domain,nameserver,record,found_at FROM ZoneTransfer ORDER BY root_domain,nameserver",
                            ["root_domain","nameserver","record","found_at"]),
        "well_known":      ("SELECT domain,path,category,content_snippet,found_at FROM WellKnown ORDER BY domain,path",
                            ["domain","path","category","content_snippet","found_at"]),
    }
    if table not in exports:
        return jsonify({"error": "Unknown table"}), 404
    sql, fields = exports[table]
    rows = qdb(sql)
    if fmt == "json":
        return Response(json.dumps(rows, indent=2), mimetype="application/json",
                        headers={"Content-Disposition": f"attachment; filename={table}.json"})
    elif fmt == "csv":
        return Response(make_csv(rows, fields), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={table}.csv"})
    return jsonify({"error": "Format must be csv or json"}), 400

# ── HTML ──────────────────────────────────────────────────────

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NuScrape</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#060a0e;--surf:#0b1118;--surf2:#0f1820;--border:#182030;
  --accent:#00e5ff;--red:#ff3e5e;--green:#00ff88;--yellow:#ffc542;--purple:#b06aff;
  --text:#ccdaeb;--muted:#3d5470;--white:#eaf2fa;--bg2:#0f1318;
  --mono:'Share Tech Mono',monospace;--sans:'Exo 2',sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{background:var(--bg);color:var(--text);font-family:var(--sans);font-size:14px;display:flex;flex-direction:column;height:100vh;overflow:hidden}
body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,229,255,.012) 3px,rgba(0,229,255,.012) 4px)}

/* HEADER */
header{flex:0 0 auto;display:flex;align-items:center;gap:1.5rem;padding:.9rem 1.8rem;border-bottom:1px solid var(--border);background:var(--surf);position:relative}
header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),transparent)}
.logo{font-family:var(--mono);font-size:1.4rem;color:var(--accent);text-shadow:0 0 18px rgba(0,229,255,.5);letter-spacing:.08em}
.logo em{color:var(--red);font-style:normal}
.hstats{margin-left:auto;display:flex;gap:1.8rem}
.hstat{display:flex;flex-direction:column;align-items:flex-end}
.hstat .n{font-family:var(--mono);font-size:1.2rem;color:var(--accent);line-height:1}
.hstat .l{font-size:.65rem;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
.status-dot{width:9px;height:9px;border-radius:50%;background:var(--muted);transition:background .3s,box-shadow .3s;flex-shrink:0}
.status-dot.running{background:var(--green);box-shadow:0 0 8px var(--green)}
.status-dot.stopped{background:var(--red)}

/* LAYOUT */
.body{flex:1;display:flex;min-height:0}

/* SIDEBAR */
.sidebar{flex:0 0 260px;background:var(--surf);border-right:1px solid var(--border);display:flex;flex-direction:column;overflow-y:auto}
.sidebar-section{padding:1.2rem 1.4rem;border-bottom:1px solid var(--border)}
.sidebar-section:last-child{border-bottom:none}
.sid-title{font-size:.65rem;font-weight:800;letter-spacing:.18em;text-transform:uppercase;color:var(--muted);margin-bottom:1rem}

/* Form controls */
.field{margin-bottom:.8rem}
.field label{display:block;font-size:.7rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.35rem}
.field input[type=text],.field input[type=number]{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:.82rem;padding:.45rem .7rem;outline:none;transition:border-color .2s}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,229,255,.07)}
.field input::placeholder{color:var(--muted)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}
.toggle-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:.8rem}
.toggle-row label{font-size:.75rem;color:var(--text)}
.toggle{position:relative;width:36px;height:20px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{position:absolute;inset:0;background:var(--border);cursor:pointer;transition:background .2s;border-radius:20px}
.toggle-slider::before{content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;background:var(--muted);transition:.2s;border-radius:50%}
.toggle input:checked+.toggle-slider{background:rgba(0,229,255,.25)}
.toggle input:checked+.toggle-slider::before{transform:translateX(16px);background:var(--accent)}
.btn{width:100%;padding:.55rem;border:none;cursor:pointer;font-family:var(--sans);font-size:.8rem;font-weight:600;letter-spacing:.1em;text-transform:uppercase;transition:all .2s}
.stealth-btn{display:block;padding:.3rem .2rem;font-size:.68rem;font-family:var(--mono);text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--surface);border:1px solid var(--border);border-radius:4px;cursor:pointer;transition:all .15s;text-align:center}
.stealth-btn:hover{color:var(--text);border-color:var(--muted)}
.stealth-btn.active{color:var(--accent);border-color:rgba(0,229,255,.5);background:rgba(0,229,255,.08);box-shadow:0 0 8px rgba(0,229,255,.1)}
.tut-details{margin-top:.45rem;border:1px solid rgba(0,229,255,.18);border-radius:3px;background:rgba(0,229,255,.03)}
.tut-summary{font-family:var(--mono);font-size:.68rem;color:var(--accent);padding:.3rem .55rem;cursor:pointer;user-select:none;list-style:none}
.tut-summary::-webkit-details-marker{display:none}
.tut-body{font-family:var(--mono);font-size:.68rem;color:var(--text);padding:.4rem .7rem .5rem;line-height:1.55;border-top:1px solid rgba(0,229,255,.1)}
.tut-auth{display:block;color:var(--white);margin-bottom:.55rem}
.tut-cmd{display:block;color:var(--green);background:var(--bg2);padding:.12rem .7rem;border-radius:2px;margin:.15rem -.7rem}
.btn-start{background:rgba(0,229,255,.1);color:var(--accent);border:1px solid rgba(0,229,255,.25)}
.btn-start:hover{background:rgba(0,229,255,.2);box-shadow:0 0 14px rgba(0,229,255,.15)}
.btn-start:disabled{opacity:.35;cursor:not-allowed}
.btn-stop{background:rgba(255,62,94,.1);color:var(--red);border:1px solid rgba(255,62,94,.25);margin-top:.5rem}
.btn-stop:hover{background:rgba(255,62,94,.2)}
.btn-stop:disabled{opacity:.35;cursor:not-allowed}
.btn-danger{background:rgba(255,62,94,.07);color:var(--red);border:1px solid rgba(255,62,94,.2);margin-top:.4rem;font-size:.72rem}
.btn-danger:hover{background:rgba(255,62,94,.15)}
.run-info{margin-top:.8rem;font-family:var(--mono);font-size:.72rem;color:var(--muted);line-height:1.7}
.run-info span{color:var(--text)}

/* Nav pills */
.nav-pills{display:flex;flex-direction:column;gap:2px}
.nav-pill{background:none;border:none;text-align:left;font-family:var(--sans);font-size:.78rem;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);padding:.55rem .9rem;cursor:pointer;transition:color .15s,background .15s;border-left:2px solid transparent}
.nav-pill:hover{color:var(--text);background:rgba(255,255,255,.03)}
.nav-pill.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05)}
.nav-pill .pill-count{float:right;font-family:var(--mono);font-size:.68rem;color:var(--muted);background:rgba(255,255,255,.04);padding:.05rem .45rem;border-radius:2px}
.nav-pill.active .pill-count{color:var(--accent)}

/* CONTENT */
.content{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0}
.tab-panel{display:none;flex:1;flex-direction:column;min-height:0;overflow:hidden}
.tab-panel.active{display:flex}
@keyframes fadeUp{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.tab-panel.active{animation:fadeUp .18s ease}

/* Log panel */
.log-wrap{flex:1;overflow-y:auto;padding:1rem 1.4rem;font-family:var(--mono);font-size:.78rem;line-height:1.7}
.log-line{border-bottom:1px solid rgba(24,32,48,.5);padding:.15rem 0}
.log-line .lt{color:var(--muted);margin-right:.8rem;user-select:none}
.log-line .lm{color:var(--text)}
.log-line.info .lm{color:var(--accent)}
.log-line.warn .lm{color:var(--yellow)}
.log-line.err .lm{color:var(--red)}
.log-line.sys .lm{color:var(--purple)}
.log-controls{flex:0 0 auto;display:flex;align-items:center;gap:1rem;padding:.7rem 1.4rem;border-top:1px solid var(--border);background:var(--surf)}
.log-controls label{font-size:.7rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}

/* Data panels */
.panel-inner{flex:1;overflow-y:auto;padding:1.4rem 1.8rem}
.panel-header{display:flex;align-items:center;gap:.8rem;margin-bottom:1.2rem;flex-wrap:wrap}
.panel-title{font-size:1rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--accent)}
.cnt-badge{font-family:var(--mono);font-size:.7rem;background:rgba(0,229,255,.08);color:var(--accent);border:1px solid rgba(0,229,255,.18);padding:.1rem .5rem;border-radius:2px}
.search-row{margin-bottom:1rem}
.search-row input{background:var(--surf2);border:1px solid var(--border);color:var(--text);font-family:var(--mono);font-size:.8rem;padding:.5rem .9rem;width:100%;max-width:380px;outline:none;transition:border-color .2s}
.search-row input:focus{border-color:var(--accent)}
.search-row input::placeholder{color:var(--muted)}

/* Tables */
.tbl-wrap{overflow-x:auto;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead tr{background:#090e14;border-bottom:1px solid var(--border)}
th{font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);padding:.65rem 1rem;text-align:left;white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(24,32,48,.5);transition:background .12s}
tbody tr:hover{background:rgba(0,229,255,.025)}
td{padding:.55rem 1rem;color:var(--text);font-family:var(--mono);font-size:.78rem;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
td.wrap{white-space:normal;word-break:break-all}
td a{color:var(--accent);text-decoration:none}
td a:hover{text-decoration:underline}

/* Badges */
.b{display:inline-block;font-family:var(--mono);font-size:.68rem;padding:.08rem .45rem;border-radius:2px;margin:1px}
.bc{background:rgba(0,229,255,.1);color:var(--accent);border:1px solid rgba(0,229,255,.2)}
.bg{background:rgba(0,255,136,.1);color:var(--green);border:1px solid rgba(0,255,136,.2)}
.br{background:rgba(255,62,94,.1);color:var(--red);border:1px solid rgba(255,62,94,.2)}
.by{background:rgba(255,197,66,.1);color:var(--yellow);border:1px solid rgba(255,197,66,.2)}
.bp{background:rgba(176,106,255,.1);color:var(--purple);border:1px solid rgba(176,106,255,.2)}
.bm{background:rgba(61,84,112,.15);color:var(--muted);border:1px solid rgba(61,84,112,.3)}

.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}

/* Tech summary grid */
.tech-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:1.4rem}
.tech-card{background:var(--surf2);padding:.9rem 1.1rem;transition:background .15s}
.tech-card:hover{background:#131c28}
.tech-card .tn{font-family:var(--mono);font-size:.78rem;color:var(--accent);margin-bottom:.25rem}
.tech-card .tv{font-size:1.6rem;font-weight:800;color:var(--text);line-height:1}
.tech-card .tl{font-size:.62rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}

.empty{padding:2.5rem;text-align:center;color:var(--muted);font-family:var(--mono);font-size:.8rem;letter-spacing:.08em}
.s2{color:var(--green)}.s3{color:var(--accent)}.s4{color:var(--yellow)}.s5{color:var(--red)}

/* Export buttons */
.xbtn{display:inline-block;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.35rem .8rem;cursor:pointer;text-decoration:none;transition:all .15s}
.xbtn:hover{border-color:var(--accent);color:var(--accent)}

/* Scrollbars */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.pulsing{animation:pulse 1.4s ease-in-out infinite}
</style>
</head>
<body>

<header>
  <span id="statusDot" class="status-dot"></span>
  <div class="logo">Nu<em>Scrape</em></div>
  <div id="runLabel" style="font-family:var(--mono);font-size:.75rem;color:var(--muted)">idle</div>
  <div class="hstats">
    <div class="hstat"><span class="n" id="hDomains">—</span><span class="l">Domains</span></div>
    <div class="hstat"><span class="n" id="hEmails">—</span><span class="l">Emails</span></div>
    <div class="hstat"><span class="n" id="hPorts">—</span><span class="l">Ports</span></div>
    <div class="hstat"><span class="n" id="hTech">—</span><span class="l">Tech</span></div>
    <div class="hstat"><span class="n" id="hSubs">—</span><span class="l">Subdomains</span></div>
    <div class="hstat"><span class="n" id="hAlerts" style="color:var(--muted)">—</span><span class="l" style="color:var(--red)">Alerts</span></div>
  </div>
</header>

<div class="body">
  <aside class="sidebar">
    <div class="sidebar-section">
      <div class="sid-title">Crawler Control</div>
      <div class="field">
        <label>Target Domain</label>
        <input type="text" id="domain" placeholder="https://example.com">
      </div>
      <div class="field" style="margin-top:.3rem">
        <label style="display:flex;align-items:center;gap:.5rem">
          Multiple Domains
          <span style="font-size:.62rem;color:var(--dim);font-family:var(--mono)">(one per line — overrides single domain above)</span>
        </label>
        <textarea id="multiDomains" rows="4" placeholder="https://target1.com&#10;https://target2.com&#10;https://target3.com"
          style="width:100%;box-sizing:border-box;resize:vertical;background:var(--surface);border:1px solid var(--border);color:var(--fg);font-family:var(--mono);font-size:.72rem;padding:.35rem .5rem;border-radius:4px;outline:none;transition:border-color .15s"></textarea>
      </div>
      <div style="margin-bottom:.7rem">
        <label style="font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:.4rem">Custom Headers</label>
        <textarea id="customHeaders" rows="3" placeholder="User-Agent:qinetiqvdpChr0nic&#10;X-HackerOne-Researcher:chr0nic"
          style="width:100%;box-sizing:border-box;resize:vertical;background:var(--surface);border:1px solid var(--border);color:var(--fg);font-family:var(--mono);font-size:.72rem;padding:.35rem .5rem;border-radius:4px;outline:none;transition:border-color .15s"></textarea>
        <div style="font-size:.62rem;color:var(--dim);margin-top:.25rem;font-family:var(--mono)">One header per line in Key:Value format. Use for program-specific headers like User-Agent or X-HackerOne-Researcher.</div>
      </div>
      <div class="toggle-row" id="parallelRow" style="display:none">
        <label>Parallel Scan (max 3 concurrent)</label>
        <label class="toggle"><input type="checkbox" id="parallelScan"><span class="toggle-slider"></span></label>
      </div>
      <div class="row2">
        <div class="field"><label>Rate Min (s)</label><input type="number" id="rateMin" value="1.0" step="0.5" min="0"></div>
        <div class="field"><label>Rate Max (s)</label><input type="number" id="rateMax" value="3.0" step="0.5" min="0"></div>
      </div>
      <div class="field"><label>Concurrency</label><input type="number" id="concurrency" value="5" min="1" max="20"></div>
      <div class="toggle-row">
        <label>Same Domain Only</label>
        <label class="toggle"><input type="checkbox" id="sameDomain"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Resume Previous Crawl</label>
        <label class="toggle"><input type="checkbox" id="resumeCrawl"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Ignore robots.txt</label>
        <label class="toggle"><input type="checkbox" id="ignoreRobots"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>JS Rendering (Playwright)</label>
        <label class="toggle"><input type="checkbox" id="usePW"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Skip Social Media</label>
        <label class="toggle"><input type="checkbox" id="noSocial"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Skip Google Tracking/CDN URLs</label>
        <label class="toggle"><input type="checkbox" id="skipGoogleTracking" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Baseline Profiling</label>
        <label class="toggle"><input type="checkbox" id="baselineProfiling" checked><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row">
        <label>Tutorial Mode <span style="font-size:.65rem;color:var(--muted)">(adds verify steps to findings)</span></label>
        <label class="toggle"><input type="checkbox" id="tutorialMode"><span class="toggle-slider"></span></label>
      </div>
      <div class="toggle-row" style="margin-top:.6rem">
        <label style="color:var(--yellow)">Active Probes</label>
        <label class="toggle"><input type="checkbox" id="activeProbes" onchange="toggleActiveProbesWarning(this)"><span class="toggle-slider"></span></label>
      </div>
      <div id="activeProbesWarning" style="display:none;background:rgba(255,200,0,.08);border:1px solid rgba(255,200,0,.35);border-radius:4px;padding:.45rem .6rem;margin-bottom:.5rem;font-family:var(--mono);font-size:.65rem;color:var(--yellow);line-height:1.6">
        ⚠ Active probes ON — payload-injecting checks enabled:<br>
        path traversal · SSTI · CRLF injection · CORS evil-origin · default credentials · dangerous HTTP methods (TRACE/PUT/DELETE)<br>
        <strong>Only scan targets you are authorised to test.</strong>
      </div>
      <div id="resumeInfo" style="display:none;font-family:var(--mono);font-size:.68rem;color:var(--yellow);margin-bottom:.6rem;line-height:1.6"></div>
      <div style="margin-bottom:.7rem">
        <div style="font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.4rem">Stealth Profile</div>
        <div style="display:flex;gap:.3rem" id="stealthBtns">
          <label style="flex:1;text-align:center">
            <input type="radio" name="stealthProfile" value="LOUD" checked style="display:none">
            <span class="stealth-btn active" data-tip="Fast, no delays" onclick="setStealthBtn(this,'LOUD')">LOUD</span>
          </label>
          <label style="flex:1;text-align:center">
            <input type="radio" name="stealthProfile" value="NORMAL" style="display:none">
            <span class="stealth-btn" data-tip="Moderate delays" onclick="setStealthBtn(this,'NORMAL')">NORMAL</span>
          </label>
          <label style="flex:1;text-align:center">
            <input type="radio" name="stealthProfile" value="GHOST" style="display:none">
            <span class="stealth-btn" data-tip="Slow, randomised, rotates UA" onclick="setStealthBtn(this,'GHOST')">GHOST</span>
          </label>
        </div>
        <div id="stealthDesc" style="font-size:.65rem;color:var(--dim);margin-top:.3rem;font-family:var(--mono)">Fast scanning, no rate limiting beyond base settings</div>
      </div>
      <div style="margin-bottom:.7rem">
        <label style="font-size:.7rem;color:var(--dim);text-transform:uppercase;letter-spacing:.08em;display:block;margin-bottom:.4rem">HackerOne Scope CSV</label>
        <input type="file" id="scopeFile" accept=".csv"
          style="width:100%;box-sizing:border-box;background:var(--surface);border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .5rem;border-radius:4px;outline:none">
        <div style="font-size:.62rem;color:var(--dim);margin-top:.25rem;font-family:var(--mono)">Optional — restricts scan to in-scope assets and skips excluded assets</div>
        <div id="scopeStatus" style="font-size:.62rem;color:var(--dim);margin-top:.2rem;font-family:var(--mono);display:none"></div>
      </div>
      <button class="btn btn-start" id="btnStart" onclick="startCrawler()">▶ Start Crawler</button>
      <button class="btn btn-stop"  id="btnStop"  onclick="stopCrawler()" disabled>■ Stop Crawler</button>
      <div class="run-info" id="runInfo" style="display:none">
        <div>Domain: <span id="riDomain">—</span></div>
        <div>Started: <span id="riStarted">—</span></div>
        <div>PID: <span id="riPid">—</span></div>
      </div>
      <button class="btn btn-danger" onclick="clearDB()">⚠ Clear Database</button>
    </div>

    <div class="sidebar-section" style="flex:1">
      <div class="sid-title">Views</div>
      <div class="nav-pills">
        <button class="nav-pill active" onclick="switchTab('log')" id="pill-log">
          Live Log <span class="pill-count" id="pc-log">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('domains')" id="pill-domains">
          Domains <span class="pill-count" id="pc-domains">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('technologies')" id="pill-technologies">
          Technologies <span class="pill-count" id="pc-technologies">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('ports')" id="pill-ports">
          Open Ports <span class="pill-count" id="pc-ports">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('ssl')" id="pill-ssl">
          SSL / WHOIS <span class="pill-count" id="pc-ssl">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('emails')" id="pill-emails">
          Emails <span class="pill-count" id="pc-emails">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('dns')" id="pill-dns">
          DNS / MX <span class="pill-count" id="pc-dns">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('http')" id="pill-http">
          HTTP History <span class="pill-count" id="pc-http">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('subdomains')" id="pill-subdomains">
          Subdomains <span class="pill-count" id="pc-subdomains">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('secheaders')" id="pill-secheaders">
          Sec Headers <span class="pill-count" id="pc-secheaders">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('xhr')" id="pill-xhr">
          XHR Endpoints <span class="pill-count" id="pc-xhr">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('alerts')" id="pill-alerts">
          !! Alerts <span class="pill-count" id="pc-alerts" style="color:var(--red)">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('recon')" id="pill-recon">
          Recon <span class="pill-count" id="pc-recon">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('waf')" id="pill-waf">
          WAF <span class="pill-count" id="pc-waf">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('zonetransfer')" id="pill-zonetransfer">
          Zone Transfers <span class="pill-count" id="pc-zonetransfer">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('wellknown')" id="pill-wellknown">
          Well-Known <span class="pill-count" id="pc-wellknown">0</span>
        </button>
        <button class="nav-pill" onclick="switchTab('report')" id="pill-report">
          Report / Export
        </button>
      </div>
    </div>
  </aside>

  <div class="content">

    <!-- ALERTS -->
    <div class="tab-panel" id="tab-alerts">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title" style="color:var(--red)">!! Alerts</span>
          <span class="cnt-badge" id="c-alerts" style="background:rgba(255,62,94,.1);color:var(--red);border-color:rgba(255,62,94,.3)">0</span>
          <button onclick="loadAlerts(true)" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/alerts.csv" class="xbtn">↓ CSV</a>
          <a href="/api/export/alerts.json" class="xbtn">↓ JSON</a>
        </div>
        <div style="font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-bottom:1.2rem;padding:.7rem 1rem;border:1px solid rgba(255,62,94,.15);background:rgba(255,62,94,.04)">
          Exploitable findings requiring immediate attention — exposed secrets, critical open ports, EOL software, high-value subdomains, and expiring certificates.
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tAlerts',this.value)"></div>
        <div class="tbl-wrap"><table id="tAlerts">
          <thead><tr><th>Severity</th><th>Confidence</th><th>Type</th><th>Target</th><th>Detail</th><th>Found</th></tr></thead>
          <tbody id="bAlerts"></tbody>
        </table></div>
      </div>
    </div>

    <!-- LOG -->
    <div class="tab-panel active" id="tab-log">
      <div class="log-wrap" id="logWrap"></div>
      <div class="log-controls">
        <span class="pulsing" id="logPulse" style="color:var(--accent);font-family:var(--mono);font-size:.75rem;display:none">● LIVE</span>
        <label><input type="checkbox" id="autoScroll" checked style="margin-right:.4rem">Auto-scroll</label>
        <button onclick="clearLog()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">Clear</button>
      </div>
    </div>

    <!-- DOMAINS -->
    <div class="tab-panel" id="tab-domains">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Domains</span>
          <span class="cnt-badge" id="c-domains">0</span>
          <button onclick="loadDomains()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/domains.csv"  class="xbtn">↓ CSV</a>
          <a href="/api/export/domains.json" class="xbtn">↓ JSON</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tDomains',this.value)"></div>
        <div class="tbl-wrap"><table id="tDomains">
          <thead><tr><th>URL</th><th>IP</th><th>ASN / Org</th><th>Server</th><th>Content-Type</th><th>Title</th></tr></thead>
          <tbody id="bDomains"></tbody>
        </table></div>
      </div>
    </div>

    <!-- TECHNOLOGIES -->
    <div class="tab-panel" id="tab-technologies">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Technologies</span>
          <span class="cnt-badge" id="c-technologies">0</span>
          <button onclick="loadTech()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/technologies.csv" class="xbtn">↓ CSV</a>
        </div>
        <div class="tech-grid" id="techGrid"></div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tTech',this.value)"></div>
        <div class="tbl-wrap"><table id="tTech">
          <thead><tr><th>URL</th><th>Technology</th></tr></thead>
          <tbody id="bTech"></tbody>
        </table></div>
      </div>
    </div>

    <!-- PORTS -->
    <div class="tab-panel" id="tab-ports">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Open Ports</span>
          <span class="cnt-badge" id="c-ports">0</span>
          <button onclick="loadPorts()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/ports.csv" class="xbtn">↓ CSV</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tPorts',this.value)"></div>
        <div class="tbl-wrap"><table id="tPorts">
          <thead><tr><th>Domain</th><th>IP</th><th>Port</th><th>Service</th></tr></thead>
          <tbody id="bPorts"></tbody>
        </table></div>
      </div>
    </div>

    <!-- SSL / WHOIS -->
    <div class="tab-panel" id="tab-ssl">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">SSL / WHOIS</span>
          <span class="cnt-badge" id="c-ssl">0</span>
          <button onclick="loadSSL()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/ssl.csv"   class="xbtn">↓ SSL CSV</a>
          <a href="/api/export/whois.csv" class="xbtn">↓ WHOIS CSV</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tSSL',this.value)"></div>
        <div class="tbl-wrap"><table id="tSSL">
          <thead><tr><th>Domain</th><th>CN</th><th>Issuer</th><th>SSL Expires</th><th>Registrar</th><th>WHOIS Expires</th></tr></thead>
          <tbody id="bSSL"></tbody>
        </table></div>
      </div>
    </div>

    <!-- EMAILS -->
    <div class="tab-panel" id="tab-emails">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Emails</span>
          <span class="cnt-badge" id="c-emails">0</span>
          <button onclick="loadEmails()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/emails.csv" class="xbtn">↓ CSV</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tEmails',this.value)"></div>
        <div class="tbl-wrap"><table id="tEmails">
          <thead><tr><th>Email Address</th></tr></thead>
          <tbody id="bEmails"></tbody>
        </table></div>
      </div>
    </div>

    <!-- DNS / MX -->
    <div class="tab-panel" id="tab-dns">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">DNS / MX Records</span>
          <button onclick="loadDNS()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/dns.csv" class="xbtn">↓ DNS CSV</a>
          <a href="/api/export/mx.csv"  class="xbtn">↓ MX CSV</a>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1.4rem">
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">A Records <span class="cnt-badge" id="c-dns">0</span></div>
            <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tDNS',this.value)"></div>
            <div class="tbl-wrap"><table id="tDNS"><thead><tr><th>Domain</th><th>IP</th></tr></thead><tbody id="bDNS"></tbody></table></div>
          </div>
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">MX Records <span class="cnt-badge" id="c-mx">0</span></div>
            <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tMX',this.value)"></div>
            <div class="tbl-wrap"><table id="tMX"><thead><tr><th>Domain</th><th>MX Host</th><th>Priority</th></tr></thead><tbody id="bMX"></tbody></table></div>
          </div>
        </div>
      </div>
    </div>

    <!-- HTTP HISTORY -->
    <div class="tab-panel" id="tab-http">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">HTTP History</span>
          <span class="cnt-badge" id="c-http">0</span>
          <button onclick="loadHTTP()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tHTTP',this.value)"></div>
        <div class="tbl-wrap"><table id="tHTTP">
          <thead><tr><th>Status</th><th>URL</th><th>Time</th></tr></thead>
          <tbody id="bHTTP"></tbody>
        </table></div>
      </div>
    </div>

    <!-- SUBDOMAINS -->
    <div class="tab-panel" id="tab-subdomains">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Subdomains</span>
          <span class="cnt-badge" id="c-subdomains">0</span>
          <button onclick="loadSubdomains()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/subdomains.csv"  class="xbtn">↓ CSV</a>
          <a href="/api/export/subdomains.json" class="xbtn">↓ JSON</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tSubdomains',this.value)"></div>
        <div class="tbl-wrap"><table id="tSubdomains">
          <thead><tr><th>Root Domain</th><th>Subdomain</th><th>IP</th><th>HTTP Status</th><th>Found At</th></tr></thead>
          <tbody id="bSubdomains"></tbody>
        </table></div>
      </div>
    </div>

    <!-- SECURITY HEADERS -->
    <div class="tab-panel" id="tab-secheaders">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Security Headers</span>
          <span class="cnt-badge" id="c-secheaders">0</span>
          <button onclick="loadSecHeaders()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/security_headers.csv" class="xbtn">↓ CSV</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tSecHeaders',this.value)"></div>
        <div class="tbl-wrap"><table id="tSecHeaders">
          <thead><tr><th>Domain</th><th>Present</th><th>Missing</th><th>Leaking</th><th>Checked</th></tr></thead>
          <tbody id="bSecHeaders"></tbody>
        </table></div>
      </div>
    </div>

    <!-- XHR ENDPOINTS -->
    <div class="tab-panel" id="tab-xhr">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">XHR / Fetch Endpoints</span>
          <span class="cnt-badge" id="c-xhr">0</span>
          <button onclick="loadXhr()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">&#8635; Refresh</button>
          <a href="/api/export/xhr.csv" class="xbtn">&#8595; CSV</a>
          <a href="/api/export/xhr.json" class="xbtn">&#8595; JSON</a>
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tXhr',this.value)"></div>
        <div class="tbl-wrap"><table id="tXhr">
          <thead><tr><th>Page URL</th><th>Method</th><th>Endpoint</th><th>Found</th></tr></thead>
          <tbody id="bXhr"></tbody>
        </table></div>
      </div>
    </div>

    <!-- RECON -->
    <div class="tab-panel" id="tab-recon">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">JS Bundle Analysis</span>
          <span class="cnt-badge" id="c-recon">0</span>
          <button onclick="loadRecon()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">&#8635; Refresh</button>
          <a href="/api/export/js_findings.csv" class="xbtn">&#8595; CSV</a>
          <a href="/api/export/js_findings.json" class="xbtn">&#8595; JSON</a>
        </div>
        <div class="search-row">
          <input type="text" placeholder="Filter findings..." oninput="filterTbl('tRecon',this.value)" style="flex:1">
          <select onchange="filterReconType(this.value)" style="background:var(--bg);border:1px solid var(--border);color:var(--fg);padding:.35rem .6rem;font-family:var(--mono);font-size:.75rem;cursor:pointer">
            <option value="">All types</option>
            <option value="api_key">api_key</option>
            <option value="secret">secret</option>
            <option value="token">token</option>
            <option value="password">password</option>
            <option value="aws_access_key">aws_access_key</option>
            <option value="github_token">github_token</option>
            <option value="openai_key">openai_key</option>
            <option value="endpoint">endpoint</option>
            <option value="staging_url">staging_url</option>
            <option value="source_map">source_map</option>
          </select>
        </div>
        <div class="tbl-wrap"><table id="tRecon">
          <thead><tr><th>Type</th><th>Value</th><th>Context</th><th>JS File</th><th>Page</th><th>Found</th></tr></thead>
          <tbody id="bRecon"></tbody>
        </table></div>
      </div>
    </div>

    <!-- WAF -->
    <div class="tab-panel" id="tab-waf">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">WAF Detection</span>
          <span class="cnt-badge" id="c-waf">0</span>
          <button onclick="loadWaf()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/waf.csv" class="xbtn">↓ CSV</a>
        </div>
        <div style="font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-bottom:1.2rem;padding:.7rem 1rem;border:1px solid rgba(0,229,255,.1);background:rgba(0,229,255,.03)">
          WAF vendor fingerprinted from response headers, cookies, and error page signatures. Informational — not a vulnerability, but critical context for choosing techniques.
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tWaf',this.value)"></div>
        <div class="tbl-wrap"><table id="tWaf">
          <thead><tr><th>Domain</th><th>WAF Vendor</th><th>Evidence</th><th>Found</th></tr></thead>
          <tbody id="bWaf"></tbody>
        </table></div>
      </div>
    </div>

    <!-- ZONE TRANSFERS -->
    <div class="tab-panel" id="tab-zonetransfer">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title" style="color:var(--red)">Zone Transfers</span>
          <span class="cnt-badge" id="c-zonetransfer" style="background:rgba(255,62,94,.1);color:var(--red);border-color:rgba(255,62,94,.3)">0</span>
          <button onclick="loadZoneTransfers()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/zone_transfers.csv" class="xbtn">↓ CSV</a>
          <a href="/api/export/zone_transfers.json" class="xbtn">↓ JSON</a>
        </div>
        <div style="font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-bottom:1.2rem;padding:.7rem 1rem;border:1px solid rgba(255,62,94,.15);background:rgba(255,62,94,.04)">
          Records obtained via successful DNS AXFR zone transfer. Any data here means the nameserver is critically misconfigured — the full DNS zone was publicly downloadable.
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tZoneTransfer',this.value)"></div>
        <div class="tbl-wrap"><table id="tZoneTransfer">
          <thead><tr><th>Root Domain</th><th>Nameserver</th><th>Record</th><th>Found</th></tr></thead>
          <tbody id="bZoneTransfer"></tbody>
        </table></div>
      </div>
    </div>

    <!-- WELL-KNOWN -->
    <div class="tab-panel" id="tab-wellknown">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Well-Known</span>
          <span class="cnt-badge" id="c-wellknown">0</span>
          <button onclick="loadWellKnown()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
          <a href="/api/export/well_known.csv" class="xbtn">↓ CSV</a>
        </div>
        <div style="font-family:var(--mono);font-size:.72rem;color:var(--muted);margin-bottom:1.2rem;padding:.7rem 1rem;border:1px solid rgba(0,229,255,.1);background:rgba(0,229,255,.03)">
          Accessible <code>/.well-known/</code> paths. Auth category findings (OpenID/OAuth config) indicate the full authentication surface is exposed.
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tWellKnown',this.value)"></div>
        <div class="tbl-wrap"><table id="tWellKnown">
          <thead><tr><th>Domain</th><th>Path</th><th>Category</th><th>Content</th><th>Found</th></tr></thead>
          <tbody id="bWellKnown"></tbody>
        </table></div>
      </div>
    </div>

    <!-- REPORT / EXPORT -->
    <div class="tab-panel" id="tab-report">
      <div class="panel-inner">
        <div class="panel-header">
          <span class="panel-title">Report &amp; Export</span>
          <button onclick="loadReport()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
        </div>

        <div id="reportTotals" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:1.4rem"></div>

        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.4rem;margin-bottom:1.4rem">
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">Top Technologies</div>
            <div class="tbl-wrap"><table><thead><tr><th>Technology</th><th>Count</th></tr></thead><tbody id="bRTech"></tbody></table></div>
          </div>
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">Open Ports</div>
            <div class="tbl-wrap"><table><thead><tr><th>Port</th><th>Service</th><th>Count</th></tr></thead><tbody id="bRPorts"></tbody></table></div>
          </div>
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">HTTP Status Codes</div>
            <div class="tbl-wrap"><table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody id="bRStatus"></tbody></table></div>
          </div>
        </div>

        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.4rem;margin-bottom:1.4rem">
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">SSL Expiring Soonest</div>
            <div class="tbl-wrap"><table><thead><tr><th>Domain</th><th>Expires</th></tr></thead><tbody id="bRSSL"></tbody></table></div>
          </div>
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">Top Registrars</div>
            <div class="tbl-wrap"><table><thead><tr><th>Registrar</th><th>Count</th></tr></thead><tbody id="bRReg"></tbody></table></div>
          </div>
          <div>
            <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">Worst Sec Headers</div>
            <div class="tbl-wrap"><table><thead><tr><th>Domain</th><th>Missing</th><th>Leaking</th></tr></thead><tbody id="bRSecH"></tbody></table></div>
          </div>
        </div>

        <div style="font-size:.7rem;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:var(--muted);margin-bottom:.8rem">Export All Data</div>
        <div style="display:flex;flex-wrap:wrap;gap:.5rem">
          <a href="/api/export/domains.csv"          class="xbtn">Domains CSV</a>
          <a href="/api/export/domains.json"         class="xbtn">Domains JSON</a>
          <a href="/api/export/emails.csv"           class="xbtn">Emails CSV</a>
          <a href="/api/export/technologies.csv"     class="xbtn">Technologies CSV</a>
          <a href="/api/export/ports.csv"            class="xbtn">Ports CSV</a>
          <a href="/api/export/ssl.csv"              class="xbtn">SSL CSV</a>
          <a href="/api/export/whois.csv"            class="xbtn">WHOIS CSV</a>
          <a href="/api/export/dns.csv"              class="xbtn">DNS CSV</a>
          <a href="/api/export/mx.csv"               class="xbtn">MX CSV</a>
          <a href="/api/export/subdomains.csv"       class="xbtn">Subdomains CSV</a>
          <a href="/api/export/subdomains.json"      class="xbtn">Subdomains JSON</a>
          <a href="/api/export/security_headers.csv" class="xbtn">Sec Headers CSV</a>
          <a href="/api/export/asn.csv" class="xbtn">ASN CSV</a>
          <a href="/api/export/asn.json" class="xbtn">ASN JSON</a>
          <a href="/api/export/waf.csv" class="xbtn">WAF CSV</a>
          <a href="/api/export/zone_transfers.csv" class="xbtn">Zone Transfers CSV</a>
          <a href="/api/export/zone_transfers.json" class="xbtn">Zone Transfers JSON</a>
          <a href="/api/export/well_known.csv" class="xbtn">Well-Known CSV</a>
        </div>
      </div>
    </div>

  </div><!-- /content -->
</div><!-- /body -->

<script>
const PORT_SVC={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',443:'HTTPS',8080:'HTTP-Alt',8443:'HTTPS-Alt',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB'};
const TECH_CLS={'WordPress':'bc','Shopify':'bg','React':'bp','Vue.js':'bp','Angular':'bp','jQuery':'by','Bootstrap':'by','Cloudflare':'bc','Nginx':'bg','Apache':'br','Google Analytics':'bm','Google Tag Mgr':'bm','PHP':'br','ASP.NET':'br','Cloudfront':'bc','Drupal':'bc','Joomla':'bc','Wix':'by','Squarespace':'by'};

let logOffset=0, logLines=0, currentTab='log', _lastAlertCount=-1;

// ── Tab switching ──────────────────────────────────────
function switchTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-pill').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.getElementById('pill-'+name).classList.add('active');
  currentTab=name;
  // Immediately catch up on logs when returning to log tab
  if(name==='log') pollLogs();
  ({log:()=>{},domains:loadDomains,technologies:loadTech,ports:loadPorts,
    ssl:loadSSL,emails:loadEmails,dns:loadDNS,http:loadHTTP,
    subdomains:loadSubdomains,secheaders:loadSecHeaders,xhr:loadXhr,recon:loadRecon,
    alerts:loadAlerts,waf:loadWaf,zonetransfer:loadZoneTransfers,wellknown:loadWellKnown,
    report:loadReport})[name]?.();
}

// ── Active probes warning toggle ───────────────────────
function toggleActiveProbesWarning(cb){
  document.getElementById('activeProbesWarning').style.display=cb.checked?'block':'none';
}

// ── Stealth profile selector ───────────────────────────
const _stealthDesc={LOUD:'Fast scanning, no rate limiting beyond base settings',NORMAL:'Moderate random delays (0.5–1.5s) between requests',GHOST:'Slow randomised delays (2–6s), rotated User-Agents, periodic burst pauses'};
function setStealthBtn(el,val){
  document.querySelectorAll('.stealth-btn').forEach(b=>b.classList.remove('active'));
  el.classList.add('active');
  document.querySelector(`input[name="stealthProfile"][value="${val}"]`).checked=true;
  document.getElementById('stealthDesc').textContent=_stealthDesc[val]||'';
}

// ── Crawler control ────────────────────────────────────

// Show/hide parallel toggle when multi-domain textarea has content
document.addEventListener('DOMContentLoaded',()=>{
  const ta=document.getElementById('multiDomains');
  if(ta)ta.addEventListener('input',()=>{
    const lines=ta.value.split('\n').map(l=>l.trim()).filter(Boolean);
    document.getElementById('parallelRow').style.display=lines.length>1?'flex':'none';
  });
});

async function startCrawler(){
  logOffset=0;logLines=0;clearLog();
  const taVal=(document.getElementById('multiDomains').value||'');
  const _cidrRe=/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;
  const _ipRe=/^\d{1,3}(?:\.\d{1,3}){3}$/;
  const _wildcardRe=/^\*\..+/;
  const domainsList=taVal.split('\n').map(l=>l.trim()).filter(l=>
    l && (l.startsWith('http://')||l.startsWith('https://')||_cidrRe.test(l)||_ipRe.test(l)||_wildcardRe.test(l))
  );
  const singleDomain=document.getElementById('domain').value.trim();

  if(domainsList.length===0 && !singleDomain){alert('Enter a target domain');return}

  // Upload scope CSV first if one is selected
  let scopeFilePath='';
  const scopeInput=document.getElementById('scopeFile');
  if(scopeInput&&scopeInput.files&&scopeInput.files.length>0){
    const scopeStatus=document.getElementById('scopeStatus');
    scopeStatus.style.display='block';
    scopeStatus.textContent='Uploading scope file…';
    const fd=new FormData();
    fd.append('scope_file',scopeInput.files[0]);
    try{
      const ur=await fetch('/api/upload-scope',{method:'POST',body:fd});
      const ud=await ur.json();
      if(ud.ok){scopeFilePath=ud.path;scopeStatus.textContent='Scope loaded ✓';}
      else{scopeStatus.textContent='Scope upload failed: '+ud.error;}
    }catch(e){scopeStatus.textContent='Scope upload error: '+e;}
  }

  const payload={
    domain: domainsList.length>0 ? domainsList[0] : singleDomain,
    rate_min:parseFloat(document.getElementById('rateMin').value)||1,
    rate_max:parseFloat(document.getElementById('rateMax').value)||3,
    concurrency:parseInt(document.getElementById('concurrency').value)||5,
    same_domain:document.getElementById('sameDomain').checked,
    resume:document.getElementById('resumeCrawl').checked,
    ignore_robots:document.getElementById('ignoreRobots').checked,
    playwright:document.getElementById('usePW').checked,
    no_social:document.getElementById('noSocial').checked,
    skip_google_tracking:document.getElementById('skipGoogleTracking').checked,
    no_baseline:!document.getElementById('baselineProfiling').checked,
    tutorial_mode:document.getElementById('tutorialMode').checked,
    active_probes:document.getElementById('activeProbes').checked,
    stealth_profile:document.querySelector('input[name="stealthProfile"]:checked')?.value||'LOUD',
    ...(scopeFilePath ? {scope_file: scopeFilePath} : {}),
    custom_headers: (document.getElementById('customHeaders').value||'')
      .split('\n').map(l=>l.trim()).filter(l=>l.includes(':')),
  };
  if(domainsList.length>1){
    payload.domains_list=domainsList;
    payload.parallel=document.getElementById('parallelScan').checked;
  }

  const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)});
  const d=await r.json();
  if(!d.ok){alert('Error: '+d.error);return}
  switchTab('log');pollStatus();
}

async function stopCrawler(){await fetch('/api/stop',{method:'POST'})}

async function clearDB(){
  if(!confirm('Delete all data from the database?'))return;
  const r=await fetch('/api/clear_db',{method:'POST'});
  const d=await r.json();
  if(d.ok)pollStats();else alert('Error: '+d.error);
}

// ── Status polling ─────────────────────────────────────
async function pollStatus(){
  const r=await fetch('/api/status');
  const d=await r.json();
  const dot=document.getElementById('statusDot');
  const lbl=document.getElementById('runLabel');
  const info=document.getElementById('runInfo');
  const pulse=document.getElementById('logPulse');
  if(d.running){
    dot.className='status-dot running';
    lbl.textContent='running → '+d.domain;lbl.style.color='var(--green)';
    info.style.display='block';
    document.getElementById('riDomain').textContent=d.domain||'-';
    document.getElementById('riStarted').textContent=d.started||'-';
    document.getElementById('riPid').textContent=d.pid||'-';
    document.getElementById('btnStart').disabled=true;
    document.getElementById('btnStop').disabled=false;
    pulse.style.display='inline';
  } else {
    dot.className='status-dot stopped';
    lbl.textContent='idle';lbl.style.color='var(--muted)';
    info.style.display='none';
    document.getElementById('btnStart').disabled=false;
    document.getElementById('btnStop').disabled=true;
    pulse.style.display='none';
  }
}

// ── Log polling ────────────────────────────────────────
function logClass(msg){
  if(msg.startsWith('[NuScrape]'))return'sys';
  if(/error|fail|exception/i.test(msg))return'err';
  if(/warning|warn/i.test(msg))return'warn';
  if(/found|saved|detected|open port|subdomain/i.test(msg))return'info';
  return'';
}

async function pollLogs(){
  const r=await fetch('/api/logs?since='+logOffset);
  const data=await r.json();
  const lines=data.lines||[];
  // Always sync offset to server total so we never drift out of range
  if(typeof data.total==='number') logOffset=data.total;
  if(!lines.length)return;
  const wrap=document.getElementById('logWrap');
  lines.forEach(l=>{
    logLines++;
    document.getElementById('pc-log').textContent=logLines;
    const div=document.createElement('div');
    div.className='log-line '+logClass(l.msg);
    div.innerHTML=`<span class="lt">${l.t}</span><span class="lm">${escHtml(l.msg)}</span>`;
    wrap.appendChild(div);
  });
  if(document.getElementById('autoScroll').checked)wrap.scrollTop=wrap.scrollHeight;
}

function clearLog(){
  document.getElementById('logWrap').innerHTML='';
  logOffset=0;logLines=0;
  document.getElementById('pc-log').textContent='0';
}

function escHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}
function renderDetail(detail){
  const SEP='\n\nHOW TO VERIFY: ';
  const idx=detail.indexOf(SEP);
  if(idx===-1)return escHtml(detail);
  const main=detail.substring(0,idx);
  const verify=detail.substring(idx+SEP.length).trim();

  // First paragraph before the blank line is the auth/warning note — render bright
  const nlnl=verify.indexOf('\n\n');
  const authNote=nlnl===-1?verify:verify.substring(0,nlnl);
  const body=nlnl===-1?'':verify.substring(nlnl+2);

  // Render body line-by-line: command lines get green-on-dark styling,
  // empty lines become spacers, everything else is plain --text
  const CMD_RE=/^\s*(curl|python3?|dig)\b/i;
  const bodyHtml=body.split('\n').map(line=>{
    if(!line)return '<br>';
    if(CMD_RE.test(line))return `<span class="tut-cmd">${escHtml(line)}</span>`;
    return escHtml(line)+'<br>';
  }).join('');

  const verifyHtml=`<span class="tut-auth">${escHtml(authNote)}</span>${bodyHtml}`;
  return escHtml(main)+`<details class="tut-details"><summary class="tut-summary">▶ How to verify</summary><div class="tut-body">${verifyHtml}</div></details>`;
}

// ── Stats polling ──────────────────────────────────────
async function pollStats(){
  const r=await fetch('/api/stats');
  const d=await r.json();
  document.getElementById('hDomains').textContent=d.domains??0;
  document.getElementById('hEmails').textContent=d.emails??0;
  document.getElementById('hPorts').textContent=d.ports??0;
  document.getElementById('hTech').textContent=d.tech??0;
  document.getElementById('hSubs').textContent=d.subdomains??0;
  document.getElementById('pc-domains').textContent=d.domains??0;
  document.getElementById('pc-technologies').textContent=d.tech??0;
  document.getElementById('pc-emails').textContent=d.emails??0;
  document.getElementById('pc-ports').textContent=d.ports??0;
  document.getElementById('pc-ssl').textContent=d.ssl??0;
  document.getElementById('pc-dns').textContent=d.mx??0;
  document.getElementById('pc-http').textContent=d.http??0;
  document.getElementById('pc-subdomains').textContent=d.subdomains??0;
  document.getElementById('pc-secheaders').textContent=d.secheaders??0;
  document.getElementById('pc-xhr').textContent=d.xhr??0;
  document.getElementById('pc-recon').textContent=d.js??0;
  document.getElementById('pc-waf').textContent=d.waf??0;
  document.getElementById('pc-zonetransfer').textContent=d.zone_records??0;
  document.getElementById('pc-wellknown').textContent=d.well_known??0;
  const alertCount=d.alerts??0;
  document.getElementById('pc-alerts').textContent=alertCount;
  document.getElementById('c-alerts').textContent=alertCount;
  document.getElementById('hAlerts').textContent=alertCount;
  if(alertCount>0){
    document.getElementById('hAlerts').style.color='var(--red)';
    document.getElementById('pill-alerts').style.color='var(--red)';
  }
  if(alertCount!==_lastAlertCount || currentTab==='alerts'){
    _lastAlertCount=alertCount;
    loadAlerts();
  }
}

// ── Filter ─────────────────────────────────────────────
function filterTbl(id,q){
  q=q.toLowerCase();
  document.querySelectorAll('#'+id+' tbody tr').forEach(r=>{
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
  });
}

function empty(msg='// no records found'){return`<tr><td colspan="99" class="empty">${msg}</td></tr>`}
function expiryClass(s){if(!s||s==='Unknown')return'';const d=(new Date(s)-new Date())/86400000;return d<0?'bad':d<30?'warn':'ok'}

// ── Data loaders ───────────────────────────────────────
async function loadDomains(){
  const rows=await(await fetch('/api/domains')).json();
  document.getElementById('c-domains').textContent=rows.length;
  document.getElementById('bDomains').innerHTML=rows.length
    ?rows.map(d=>{
      const href=d.url.startsWith('http')?d.url:'https://'+d.url;
      const srv=d.servertype?'<span class="b bm">'+d.servertype+'</span>':'-';
      const ct=(d.content_type||'').split(';')[0]||'-';
      let asnCell='-';
      if(d.org){
        const cdnBadge=d.is_cdn?'<span class="b br" style="margin-left:3px">CDN</span>':'';
        const asnTag=d.asn?'<span class="b bm" style="font-size:.65rem">'+d.asn+'</span> ':'';
        const orgShort=(d.org||'').replace(/^AS\d+\s*/,'').substring(0,32);
        asnCell=asnTag+orgShort+cdnBadge;
      }
      return '<tr>'
        +'<td class="wrap"><a href="'+href+'" target="_blank">'+d.url+'</a></td>'
        +'<td style="font-family:var(--mono);font-size:.75rem">'+(d.ip||'-')+'</td>'
        +'<td class="wrap" style="font-size:.75rem">'+asnCell+'</td>'
        +'<td>'+srv+'</td>'
        +'<td>'+(ct||'-')+'</td>'
        +'<td>'+(d.title||'-')+'</td>'
        +'</tr>';
    }).join('')
    :empty();
}

async function loadTech(){
  const rows=await(await fetch('/api/technologies')).json();
  document.getElementById('c-technologies').textContent=rows.length;
  const counts={};rows.forEach(r=>{counts[r.technology]=(counts[r.technology]||0)+1});
  document.getElementById('techGrid').innerHTML=
    Object.entries(counts).sort((a,b)=>b[1]-a[1])
    .map(([t,c])=>`<div class="tech-card"><div class="tn">${t}</div><div class="tv">${c}</div><div class="tl">detections</div></div>`).join('');
  document.getElementById('bTech').innerHTML=rows.length
    ?rows.map(r=>`<tr><td class="wrap">${r.url}</td><td><span class="b ${TECH_CLS[r.technology]||'bm'}">${r.technology}</span></td></tr>`).join('')
    :empty();
}

async function loadPorts(){
  const PORT_CLS={80:'bc',443:'bc',8080:'bc',8443:'bc',22:'by',3306:'br',5432:'br',6379:'br',27017:'br'};
  const rows=await(await fetch('/api/ports')).json();
  document.getElementById('c-ports').textContent=rows.length;
  document.getElementById('bPorts').innerHTML=rows.length
    ?rows.map(r=>`<tr>
      <td>${r.domain}</td><td>${r.ip}</td>
      <td><span class="b ${PORT_CLS[r.port]||'bm'}">${r.port}</span></td>
      <td>${PORT_SVC[r.port]||'Unknown'}</td>
    </tr>`).join('')
    :empty();
}

async function loadSSL(){
  const [ssl,whois]=await Promise.all([(await fetch('/api/ssl')).json(),(await fetch('/api/whois')).json()]);
  const wm={};whois.forEach(w=>{wm[w.domain]=w});
  document.getElementById('c-ssl').textContent=ssl.length;
  document.getElementById('bSSL').innerHTML=ssl.length
    ?ssl.map(d=>{const w=wm[d.domain]||{};return`<tr>
      <td>${d.domain}</td><td>${d.common_name||'-'}</td><td>${d.issuer||'-'}</td>
      <td class="${expiryClass(d.not_after)}">${d.not_after||'-'}</td>
      <td>${w.registrar||'-'}</td>
      <td class="${expiryClass(w.expiration_date)}">${w.expiration_date||'-'}</td>
    </tr>`}).join('')
    :empty();
}

async function loadEmails(){
  const rows=await(await fetch('/api/emails')).json();
  document.getElementById('c-emails').textContent=rows.length;
  document.getElementById('bEmails').innerHTML=rows.length
    ?rows.map(r=>`<tr><td><span class="b bg">${r.email_address}</span></td></tr>`).join('')
    :empty();
}

// ── Alerts: interaction guard & smart diffing ──────────
// Row IDs already rendered — used to detect new findings without replacing the DOM
const _alertRowIds=new Set();
// Timestamp of last mouse activity over the alerts table (ms)
let _alertsLastMouse=0;

function _alertsUserActive(){
  // 1. Any HOW TO VERIFY collapsible is open
  if(document.querySelector('#bAlerts details[open]'))return true;
  // 2. Focus is inside the alerts tab (filter input, etc.)
  if(document.activeElement&&document.activeElement.closest('#tab-alerts'))return true;
  // 3. Mouse was recently over the alerts table (3-second grace period)
  if(Date.now()-_alertsLastMouse<3000)return true;
  return false;
}

function _renderAlertRow(r){
  const sevCls={CRITICAL:'br',HIGH:'br',MEDIUM:'by'};
  const sevIcon={CRITICAL:'🔴',HIGH:'🟠',MEDIUM:'🟡'};
  const confCls={'CONFIRMED':'bg','LIKELY':'by','NEEDS VERIFICATION':'bc'};
  const confIcon={'CONFIRMED':'✓','LIKELY':'~','NEEDS VERIFICATION':'?'};
  const cls=sevCls[r.severity]||'by';
  const conf=r.confidence||'NEEDS VERIFICATION';
  const ccls=confCls[conf]||'bc';
  return`<tr data-aid="${r.id}">
    <td><span class="b ${cls}">${sevIcon[r.severity]||''} ${escHtml(r.severity||'-')}</span></td>
    <td><span class="b ${ccls}" title="${escHtml(conf)}">${confIcon[conf]||'?'} ${escHtml(conf)}</span></td>
    <td style="font-family:var(--mono);font-size:.72rem;color:var(--red)">${escHtml(r.alert_type||'-')}</td>
    <td class="wrap" style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${escHtml(r.target||'-')}</td>
    <td class="wrap" style="font-size:.72rem;white-space:normal;min-width:200px">${renderDetail(r.detail||'-')}</td>
    <td style="font-size:.72rem;white-space:nowrap;color:var(--muted)">${escHtml(r.found_at||'-')}</td>
  </tr>`;
}

async function loadAlerts(force=false){
  const rows=await(await fetch('/api/alerts?_='+Date.now())).json();
  // Always update counts and pill — never blocked
  document.getElementById('c-alerts').textContent=rows.length;
  document.getElementById('pc-alerts').textContent=rows.length;
  const pill=document.getElementById('pill-alerts');
  if(rows.length>0){pill.style.color='var(--red)';pill.style.borderLeftColor='var(--red)';}

  // Pause DOM update while user is interacting (unless manually forced)
  if(!force&&_alertsUserActive())return;

  const tbody=document.getElementById('bAlerts');
  const wrap=tbody.closest('.tbl-wrap');

  if(force||_alertRowIds.size===0){
    // Full render: initial load or manual refresh button
    const scrollTop=wrap?wrap.scrollTop:0;
    _alertRowIds.clear();
    tbody.innerHTML=rows.length
      ?rows.map(r=>_renderAlertRow(r)).join('')
      :`<tr><td colspan="6" class="empty">// no alerts — system looks clean</td></tr>`;
    rows.forEach(r=>_alertRowIds.add(r.id));
    if(wrap)wrap.scrollTop=scrollTop;
  } else {
    // Incremental: prepend only new rows, preserving existing DOM state
    const newRows=rows.filter(r=>!_alertRowIds.has(r.id));
    if(!newRows.length)return;
    const scrollTop=wrap?wrap.scrollTop:0;
    tbody.insertAdjacentHTML('afterbegin',newRows.map(r=>_renderAlertRow(r)).join(''));
    newRows.forEach(r=>_alertRowIds.add(r.id));
    // Restore scroll — new rows are added above so offset by their height
    if(wrap){
      const added=tbody.querySelectorAll('tr[data-aid]');
      let addedH=0;
      for(let i=0;i<newRows.length&&i<added.length;i++)addedH+=added[i].offsetHeight;
      wrap.scrollTop=scrollTop+addedH;
    }
  }
  // Re-apply any active filter so newly added rows respect it
  const fi=document.querySelector('#tab-alerts .search-row input');
  if(fi&&fi.value)filterTbl('tAlerts',fi.value);
}

async function loadDNS(){
  const [dns,mx]=await Promise.all([(await fetch('/api/dns')).json(),(await fetch('/api/mx')).json()]);
  document.getElementById('c-dns').textContent=dns.length;
  document.getElementById('c-mx').textContent=mx.length;
  document.getElementById('bDNS').innerHTML=dns.length
    ?dns.map(r=>`<tr><td>${r.domain}</td><td>${r.ip}</td></tr>`).join(''):empty();
  document.getElementById('bMX').innerHTML=mx.length
    ?mx.map(r=>`<tr><td>${r.domain}</td><td>${r.mx_host}</td><td><span class="b by">${r.preference}</span></td></tr>`).join(''):empty();
}

async function loadHTTP(){
  const rows=await(await fetch('/api/http_history')).json();
  document.getElementById('c-http').textContent=rows.length;
  document.getElementById('bHTTP').innerHTML=rows.length
    ?rows.map(r=>{
      const s=r.status_code;
      return`<tr>
        <td><span class="b ${s<300?'bg':s<400?'bc':s<500?'by':'br'}">${s}</span></td>
        <td class="wrap ${s<300?'s2':s<400?'s3':s<500?'s4':'s5'}">${r.url}</td>
        <td style="color:var(--muted)">${r.checked_at}</td>
      </tr>`;
    }).join('')
    :empty();
}

async function loadXhr(){
  const rows=await(await fetch('/api/xhr')).json();
  document.getElementById('c-xhr').textContent=rows.length;
  document.getElementById('bXhr').innerHTML=rows.length
    ?rows.map(r=>{
      const mCls=r.method==='POST'?'br':r.method==='PUT'?'bw':r.method==='DELETE'?'bad':'bm';
      return '<tr>'
        +'<td class="wrap" style="font-size:.72rem">'+escHtml(r.url||'-')+'</td>'
        +'<td><span class="b '+mCls+'">'+escHtml(r.method||'GET')+'</span></td>'
        +'<td class="wrap" style="font-family:var(--mono);font-size:.72rem">'+escHtml(r.endpoint||'-')+'</td>'
        +'<td style="font-size:.72rem">'+escHtml(r.found_at||'-')+'</td>'
        +'</tr>';
    }).join('')
    :empty();
}

async function loadRecon(){
  const rows=await(await fetch('/api/js')).json();
  document.getElementById('c-recon').textContent=rows.length;
  const typeColor={
    'api_key':'br','secret':'br','token':'br','password':'br',
    'aws_access_key':'br','github_token':'br','openai_key':'br',
    'private_key':'br','client_secret':'br',
    'endpoint':'bm','staging_url':'bw'
  };
  document.getElementById('bRecon').innerHTML=rows.length
    ?rows.map(r=>{
      const cls=typeColor[r.finding_type]||'bc';
      const jsPath=r.js_url.replace(/^https?:\/\//,'').split('?')[0];
      return`<tr data-type="${escHtml(r.finding_type||'')}">
        <td><span class="b ${cls}">${escHtml(r.finding_type||'-')}</span></td>
        <td class="wrap" style="font-family:var(--mono);font-size:.72rem;word-break:break-all">${escHtml(r.value||'-')}</td>
        <td class="wrap" style="font-family:var(--mono);font-size:.72rem;color:var(--muted);white-space:pre-wrap;max-width:320px">${escHtml(r.context||'')}</td>
        <td style="font-family:var(--mono);font-size:.72rem;word-break:break-all;white-space:normal;min-width:180px">${escHtml(jsPath)}</td>
        <td class="wrap" style="font-size:.72rem">${escHtml(r.url||'-')}</td>
        <td style="font-size:.72rem;white-space:nowrap">${escHtml(r.found_at||'-')}</td>
      </tr>`;
    }).join('')
    :empty();
}
function filterReconType(type){
  document.querySelectorAll('#tRecon tbody tr').forEach(r=>{
    r.style.display=(!type||r.dataset.type===type)?'':'none';
  });
}

async function loadSubdomains(){
  const rows=await(await fetch('/api/subdomains')).json();
  document.getElementById('c-subdomains').textContent=rows.length;
  document.getElementById('bSubdomains').innerHTML=rows.length
    ?rows.map(r=>{
      const s=r.status_code;
      const scls=s?s<300?'bg':s<400?'bc':s<500?'by':'br':'bm';
      return`<tr>
        <td>${r.root_domain}</td>
        <td><a href="https://${r.subdomain}" target="_blank">${r.subdomain}</a></td>
        <td>${r.ip||'-'}</td>
        <td>${s?`<span class="b ${scls}">${s}</span>`:'-'}</td>
        <td style="color:var(--muted)">${r.found_at}</td>
      </tr>`;
    }).join('')
    :empty();
}

async function loadSecHeaders(){
  const rows=await(await fetch('/api/security_headers')).json();
  document.getElementById('c-secheaders').textContent=rows.length;
  document.getElementById('bSecHeaders').innerHTML=rows.length
    ?rows.map(r=>`<tr>
      <td>${r.domain}</td>
      <td class="wrap" style="color:var(--green);font-size:.7rem">${r.present||'-'}</td>
      <td class="wrap" style="color:var(--red);font-size:.7rem">${r.missing||'-'}</td>
      <td class="wrap" style="color:var(--yellow);font-size:.7rem">${r.leaking||'-'}</td>
      <td style="color:var(--muted)">${r.checked_at}</td>
    </tr>`).join('')
    :empty();
}

async function loadWaf(){
  const rows=await(await fetch('/api/waf')).json();
  document.getElementById('c-waf').textContent=rows.length;
  document.getElementById('pc-waf').textContent=rows.length;
  const vendorCls={'Cloudflare':'bc','Akamai':'bc','Imperva Incapsula':'br','AWS WAF':'by',
    'Sucuri':'bg','F5 BIG-IP ASM':'br','Barracuda':'by','Wordfence':'bm',
    'ModSecurity':'bm','Fortinet FortiWeb':'br','Reblaze':'bc'};
  document.getElementById('bWaf').innerHTML=rows.length
    ?rows.map(r=>`<tr>
      <td>${escHtml(r.domain||'-')}</td>
      <td><span class="b ${vendorCls[r.waf_vendor]||'bm'}">${escHtml(r.waf_vendor||'-')}</span></td>
      <td class="wrap" style="font-family:var(--mono);font-size:.72rem;white-space:normal">${escHtml(r.detected_by||'-')}</td>
      <td style="color:var(--muted)">${escHtml(r.found_at||'-')}</td>
    </tr>`).join('')
    :empty('// no WAF detected on any domain');
}

async function loadZoneTransfers(){
  const rows=await(await fetch('/api/zone_transfers')).json();
  document.getElementById('c-zonetransfer').textContent=rows.length;
  document.getElementById('pc-zonetransfer').textContent=rows.length;
  document.getElementById('bZoneTransfer').innerHTML=rows.length
    ?rows.map(r=>`<tr>
      <td><span class="b br">${escHtml(r.root_domain||'-')}</span></td>
      <td style="font-family:var(--mono);font-size:.72rem">${escHtml(r.nameserver||'-')}</td>
      <td class="wrap" style="font-family:var(--mono);font-size:.72rem;white-space:normal;word-break:break-all">${escHtml(r.record||'-')}</td>
      <td style="color:var(--muted)">${escHtml(r.found_at||'-')}</td>
    </tr>`).join('')
    :empty('// no successful zone transfers — nameservers correctly refuse AXFR');
}

async function loadWellKnown(){
  const rows=await(await fetch('/api/well_known')).json();
  document.getElementById('c-wellknown').textContent=rows.length;
  document.getElementById('pc-wellknown').textContent=rows.length;
  const catCls={osint:'bg',auth:'br',info:'bm'};
  document.getElementById('bWellKnown').innerHTML=rows.length
    ?rows.map(r=>`<tr>
      <td>${escHtml(r.domain||'-')}</td>
      <td style="font-family:var(--mono);font-size:.72rem">${escHtml(r.path||'-')}</td>
      <td><span class="b ${catCls[r.category]||'bm'}">${escHtml(r.category||'-')}</span></td>
      <td class="wrap" style="font-size:.72rem;white-space:normal;max-width:320px">${escHtml(r.content_snippet||'-')}</td>
      <td style="color:var(--muted)">${escHtml(r.found_at||'-')}</td>
    </tr>`).join('')
    :empty('// no /.well-known/ paths found');
}

// ── Resume state check ─────────────────────────────────
async function checkResumeState(){
  const r=await fetch('/api/resume_state');
  const d=await r.json();
  const info=document.getElementById('resumeInfo');
  if(d.available){
    info.style.display='block';
    info.innerHTML=`Saved: ${d.domain}<br>At: ${d.saved_at} | ${d.crawled} crawled | ${d.queue} queued`;
    if(d.domain)document.getElementById('domain').value=d.domain;
  } else {
    info.style.display='none';
    document.getElementById('resumeCrawl').checked=false;
  }
}

// ── Report loader ──────────────────────────────────────
async function loadReport(){
  const r=await fetch('/api/report');
  const d=await r.json();
  const labels={domains:'Domains',emails:'Emails',open_ports:'Open Ports',
    technologies:'Technologies',ssl_certs:'SSL Certs',mx_records:'MX Records',
    http_requests:'HTTP Req',subdomains:'Subdomains'};
  document.getElementById('reportTotals').innerHTML=
    Object.entries(d.totals).map(([k,v])=>`
      <div style="background:var(--surf2);padding:.9rem 1.1rem">
        <div style="font-family:var(--mono);font-size:.72rem;color:var(--accent);margin-bottom:.2rem">${labels[k]||k}</div>
        <div style="font-size:1.5rem;font-weight:800;color:var(--text);line-height:1">${v}</div>
      </div>`).join('');

  document.getElementById('bRTech').innerHTML=d.top_technologies.length
    ?d.top_technologies.map(r=>`<tr><td><span class="b ${TECH_CLS[r.technology]||'bm'}">${r.technology}</span></td><td style="color:var(--accent);font-family:var(--mono)">${r.cnt}</td></tr>`).join('')
    :empty('// none');

  const PORT_CLS2={80:'bc',443:'bc',8080:'bc',8443:'bc',22:'by',3306:'br',5432:'br',6379:'br',27017:'br'};
  document.getElementById('bRPorts').innerHTML=d.open_ports.length
    ?d.open_ports.map(r=>`<tr><td><span class="b ${PORT_CLS2[r.port]||'bm'}">${r.port}</span></td><td style="color:var(--muted)">${PORT_SVC[r.port]||'-'}</td><td style="color:var(--accent);font-family:var(--mono)">${r.cnt}</td></tr>`).join('')
    :empty('// none');

  document.getElementById('bRStatus').innerHTML=d.http_status_breakdown.length
    ?d.http_status_breakdown.map(r=>{const s=r.status_code;return`<tr><td><span class="b ${s<300?'bg':s<400?'bc':s<500?'by':'br'}">${s}</span></td><td style="color:var(--accent);font-family:var(--mono)">${r.cnt}</td></tr>`}).join('')
    :empty('// none');

  document.getElementById('bRSSL').innerHTML=d.ssl_expiring_soonest.length
    ?d.ssl_expiring_soonest.map(r=>`<tr><td>${r.domain}</td><td class="${expiryClass(r.not_after)}">${r.not_after}</td></tr>`).join('')
    :empty('// none');

  document.getElementById('bRReg').innerHTML=d.top_registrars.length
    ?d.top_registrars.map(r=>`<tr><td>${r.registrar}</td><td style="color:var(--accent);font-family:var(--mono)">${r.cnt}</td></tr>`).join('')
    :empty('// none');

  document.getElementById('bRSecH').innerHTML=d.worst_security_headers.length
    ?d.worst_security_headers.map(r=>`<tr>
        <td>${r.domain}</td>
        <td class="wrap" style="color:var(--red);font-size:.7rem">${r.missing||'-'}</td>
        <td class="wrap" style="color:var(--yellow);font-size:.7rem">${r.leaking||'-'}</td>
      </tr>`).join('')
    :empty('// none');
}

// ── Init ───────────────────────────────────────────────
// Use a Web Worker for polling so the browser cannot throttle it
// when the tab is hidden or loses focus. Workers run in a separate
// thread and are exempt from background timer throttling.
const _workerSrc = `
  let tid = null;
  function tick(){
    postMessage('tick');
    tid = setTimeout(tick, 2000);
  }
  tick();
  onmessage = function(e){
    if(e.data === 'stop'){ clearTimeout(tid); }
  };
`;
const _workerBlob = new Blob([_workerSrc], {type:'application/javascript'});
const _pollWorker = new Worker(URL.createObjectURL(_workerBlob));

_pollWorker.onmessage = function(){
  pollStatus();
  pollStats();
  pollLogs();
};

// Catch-up poll immediately when tab becomes visible again
document.addEventListener('visibilitychange',()=>{
  if(document.visibilityState==='visible'){
    pollStatus();pollStats();pollLogs();
  }
});

// ── Alerts interaction guard — event wiring ─────────────
// Update mouse timestamp whenever the pointer moves over the alerts table body
// (covers: hovering over open details, hovering over rows, tooltip inspection)
document.getElementById('bAlerts').addEventListener('mouseover',()=>{
  _alertsLastMouse=Date.now();
},true);
// Also fire when a details element inside the table is toggled open
document.getElementById('bAlerts').addEventListener('toggle',e=>{
  if(e.target.open)_alertsLastMouse=Date.now();
},true);

pollLogs();
pollStatus();
pollStats();
checkResumeState();
loadAlerts();
</script>
</body>
</html>
"""

if __name__=="__main__":
    print("NuScrape control panel → http://0.0.0.0:5000")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
