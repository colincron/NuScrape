#!/usr/bin/env python3
import os, sys, sqlite3, subprocess, threading, time, json, signal
from datetime import datetime
from collections import deque
from flask import Flask, render_template_string, jsonify, request, Response, stream_with_context

app = Flask(__name__)

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
DB_PATH     = os.path.join(BASE_DIR, "ScrapeDB")
CRAWLER     = os.path.join(BASE_DIR, "main.py")

# ── Crawler state ────────────────────────────────────────────────────────────
crawler_proc   = None
crawler_lock   = threading.Lock()
log_buffer     = deque(maxlen=500)   # ring buffer — last 500 lines
log_lock       = threading.Lock()
crawler_stats  = {"started": None, "domain": None, "pages": 0}

def ts():
    return datetime.now().strftime("%H:%M:%S")

def push_log(line):
    with log_lock:
        log_buffer.append({"t": ts(), "msg": line.rstrip()})

def stream_proc(proc):
    """Read stdout/stderr from crawler and push into log_buffer."""
    for line in iter(proc.stdout.readline, b""):
        push_log(line.decode("utf-8", errors="replace"))
    proc.stdout.close()

# ── DB helper ────────────────────────────────────────────────────────────────
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

# ── Flask routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)

# -- Crawler control --

@app.route("/api/start", methods=["POST"])
def api_start():
    global crawler_proc
    data = request.json or {}
    domain      = data.get("domain", "").strip()
    rate_min    = float(data.get("rate_min", 1.0))
    rate_max    = float(data.get("rate_max", 3.0))
    concurrency = int(data.get("concurrency", 5))
    same_domain = bool(data.get("same_domain", False))

    if not domain:
        return jsonify({"ok": False, "error": "No domain provided"}), 400

    with crawler_lock:
        if crawler_proc and crawler_proc.poll() is None:
            return jsonify({"ok": False, "error": "Crawler already running"}), 400

        cmd = [
            sys.executable, "-u", CRAWLER,
            "-D", domain,
            "--rate-min", str(rate_min),
            "--rate-max", str(rate_max),
            "--concurrency", str(concurrency),
        ]
        if same_domain:
            cmd.append("--same-domain-only")

        with log_lock:
            log_buffer.clear()

        push_log(f"[NuScrape] Starting crawler → {domain}")
        push_log(f"[NuScrape] Args: rate={rate_min}-{rate_max}s  concurrency={concurrency}  same-domain={same_domain}")

        crawler_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=BASE_DIR,
        )
        crawler_stats["started"] = ts()
        crawler_stats["domain"]  = domain
        crawler_stats["pages"]   = 0

        t = threading.Thread(target=stream_proc, args=(crawler_proc,), daemon=True)
        t.start()

    return jsonify({"ok": True})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    global crawler_proc
    with crawler_lock:
        if crawler_proc and crawler_proc.poll() is None:
            crawler_proc.terminate()
            push_log("[NuScrape] Crawler stopped by user.")
            return jsonify({"ok": True})
    return jsonify({"ok": False, "error": "No crawler running"})

@app.route("/api/status")
def api_status():
    global crawler_proc
    running = crawler_proc is not None and crawler_proc.poll() is None
    return jsonify({
        "running":  running,
        "domain":   crawler_stats["domain"],
        "started":  crawler_stats["started"],
        "pid":      crawler_proc.pid if running else None,
    })

@app.route("/api/logs")
def api_logs():
    since = int(request.args.get("since", 0))
    with log_lock:
        all_logs = list(log_buffer)
    return jsonify(all_logs[since:])

@app.route("/api/clear_db", methods=["POST"])
def api_clear_db():
    tables = ["Domains","Emails","DNS","MX","SSL","WHOIS","Ports",
              "HTTPHistory","Technologies","Robots","Sitemap"]
    try:
        conn = sqlite3.connect(DB_PATH)
        for t in tables:
            conn.execute(f"DELETE FROM {t}")
        conn.commit()
        conn.close()
        push_log("[NuScrape] Database cleared.")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

# -- Data APIs --

@app.route("/api/stats")
def api_stats():
    return jsonify({
        "domains": count("Domains"),
        "emails":  count("Emails"),
        "ports":   count("Ports"),
        "tech":    count("Technologies","DISTINCT technology"),
        "ssl":     count("SSL"),
        "mx":      count("MX"),
        "http":    count("HTTPHistory"),
    })

@app.route("/api/domains")
def api_domains():
    return jsonify(qdb("SELECT DISTINCT url,ip,servertype,content_type,title FROM Domains ORDER BY url"))

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

# ── HTML ─────────────────────────────────────────────────────────────────────

HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NuScrape</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #060a0e;
  --surf:    #0b1118;
  --surf2:   #0f1820;
  --border:  #182030;
  --accent:  #00e5ff;
  --red:     #ff3e5e;
  --green:   #00ff88;
  --yellow:  #ffc542;
  --purple:  #b06aff;
  --text:    #ccdaeb;
  --muted:   #3d5470;
  --mono:    'Share Tech Mono', monospace;
  --sans:    'Exo 2', sans-serif;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--sans);
  font-size:14px;
  display:flex;
  flex-direction:column;
  height:100vh;
  overflow:hidden;
}
/* scanlines */
body::after{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:9999;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,229,255,.012) 3px,rgba(0,229,255,.012) 4px);
}

/* ── HEADER ── */
header{
  flex:0 0 auto;
  display:flex;align-items:center;gap:1.5rem;
  padding:.9rem 1.8rem;
  border-bottom:1px solid var(--border);
  background:var(--surf);
  position:relative;
}
header::after{
  content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--accent),transparent);
}
.logo{font-family:var(--mono);font-size:1.4rem;color:var(--accent);text-shadow:0 0 18px rgba(0,229,255,.5);letter-spacing:.08em}
.logo em{color:var(--red);font-style:normal}
.hstats{margin-left:auto;display:flex;gap:1.8rem}
.hstat{display:flex;flex-direction:column;align-items:flex-end}
.hstat .n{font-family:var(--mono);font-size:1.2rem;color:var(--accent);line-height:1}
.hstat .l{font-size:.65rem;color:var(--muted);letter-spacing:.12em;text-transform:uppercase}
.status-dot{
  width:9px;height:9px;border-radius:50%;
  background:var(--muted);
  box-shadow:none;
  transition:background .3s,box-shadow .3s;
  flex-shrink:0;
}
.status-dot.running{background:var(--green);box-shadow:0 0 8px var(--green)}
.status-dot.stopped{background:var(--red)}

/* ── LAYOUT ── */
.body{flex:1;display:flex;min-height:0}

/* ── SIDEBAR ── */
.sidebar{
  flex:0 0 260px;
  background:var(--surf);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  overflow-y:auto;
}
.sidebar-section{padding:1.2rem 1.4rem;border-bottom:1px solid var(--border)}
.sidebar-section:last-child{border-bottom:none}
.sid-title{
  font-size:.65rem;font-weight:800;letter-spacing:.18em;
  text-transform:uppercase;color:var(--muted);margin-bottom:1rem;
}

/* Control form */
.field{margin-bottom:.8rem}
.field label{display:block;font-size:.7rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase;margin-bottom:.35rem}
.field input[type=text],
.field input[type=number]{
  width:100%;background:var(--bg);border:1px solid var(--border);
  color:var(--text);font-family:var(--mono);font-size:.82rem;
  padding:.45rem .7rem;outline:none;transition:border-color .2s;
}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,229,255,.07)}
.field input::placeholder{color:var(--muted)}
.row2{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}

.toggle-row{display:flex;align-items:center;justify-content:space-between;margin-bottom:.8rem}
.toggle-row label{font-size:.75rem;color:var(--text)}
.toggle{position:relative;width:36px;height:20px;flex-shrink:0}
.toggle input{opacity:0;width:0;height:0}
.toggle-slider{
  position:absolute;inset:0;background:var(--border);cursor:pointer;
  transition:background .2s;border-radius:20px;
}
.toggle-slider::before{
  content:'';position:absolute;height:14px;width:14px;left:3px;bottom:3px;
  background:var(--muted);transition:.2s;border-radius:50%;
}
.toggle input:checked + .toggle-slider{background:rgba(0,229,255,.25)}
.toggle input:checked + .toggle-slider::before{transform:translateX(16px);background:var(--accent)}

.btn{
  width:100%;padding:.55rem;border:none;cursor:pointer;
  font-family:var(--sans);font-size:.8rem;font-weight:600;
  letter-spacing:.1em;text-transform:uppercase;transition:all .2s;
}
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
.nav-pill{
  background:none;border:none;text-align:left;
  font-family:var(--sans);font-size:.78rem;font-weight:600;
  letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);padding:.55rem .9rem;cursor:pointer;
  transition:color .15s,background .15s;border-left:2px solid transparent;
}
.nav-pill:hover{color:var(--text);background:rgba(255,255,255,.03)}
.nav-pill.active{color:var(--accent);border-left-color:var(--accent);background:rgba(0,229,255,.05)}
.nav-pill .pill-count{
  float:right;font-family:var(--mono);font-size:.68rem;
  color:var(--muted);background:rgba(255,255,255,.04);
  padding:.05rem .45rem;border-radius:2px;
}
.nav-pill.active .pill-count{color:var(--accent)}

/* ── CONTENT ── */
.content{flex:1;display:flex;flex-direction:column;min-width:0;min-height:0}
.tab-panel{display:none;flex:1;flex-direction:column;min-height:0;overflow:hidden}
.tab-panel.active{display:flex}

/* Log panel */
.log-wrap{flex:1;overflow-y:auto;padding:1rem 1.4rem;font-family:var(--mono);font-size:.78rem;line-height:1.7}
.log-line{border-bottom:1px solid rgba(24,32,48,.5);padding:.15rem 0}
.log-line .lt{color:var(--muted);margin-right:.8rem;user-select:none}
.log-line .lm{color:var(--text)}
.log-line.info .lm{color:var(--accent)}
.log-line.warn .lm{color:var(--yellow)}
.log-line.err  .lm{color:var(--red)}
.log-line.sys  .lm{color:var(--purple)}
.log-controls{
  flex:0 0 auto;display:flex;align-items:center;gap:1rem;
  padding:.7rem 1.4rem;border-top:1px solid var(--border);background:var(--surf);
}
.log-controls label{font-size:.7rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}

/* Data panels */
.panel-inner{flex:1;overflow-y:auto;padding:1.4rem 1.8rem}
.panel-header{display:flex;align-items:center;gap:.8rem;margin-bottom:1.2rem}
.panel-title{font-size:1rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--accent)}
.cnt-badge{
  font-family:var(--mono);font-size:.7rem;
  background:rgba(0,229,255,.08);color:var(--accent);
  border:1px solid rgba(0,229,255,.18);padding:.1rem .5rem;border-radius:2px;
}
.search-row{margin-bottom:1rem}
.search-row input{
  background:var(--surf2);border:1px solid var(--border);
  color:var(--text);font-family:var(--mono);font-size:.8rem;
  padding:.5rem .9rem;width:100%;max-width:380px;outline:none;
  transition:border-color .2s;
}
.search-row input:focus{border-color:var(--accent)}
.search-row input::placeholder{color:var(--muted)}

/* Tables */
.tbl-wrap{overflow-x:auto;border:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.8rem}
thead tr{background:#090e14;border-bottom:1px solid var(--border)}
th{
  font-family:var(--mono);font-size:.65rem;letter-spacing:.12em;
  text-transform:uppercase;color:var(--muted);padding:.65rem 1rem;
  text-align:left;white-space:nowrap;
}
tbody tr{border-bottom:1px solid rgba(24,32,48,.5);transition:background .12s}
tbody tr:hover{background:rgba(0,229,255,.025)}
td{
  padding:.55rem 1rem;color:var(--text);font-family:var(--mono);
  font-size:.78rem;max-width:280px;overflow:hidden;
  text-overflow:ellipsis;white-space:nowrap;
}
td.wrap{white-space:normal;word-break:break-all}
td a{color:var(--accent);text-decoration:none}
td a:hover{text-decoration:underline}

/* Badges */
.b{display:inline-block;font-family:var(--mono);font-size:.68rem;padding:.08rem .45rem;border-radius:2px;margin:1px}
.bc {background:rgba(0,229,255,.1); color:var(--accent);  border:1px solid rgba(0,229,255,.2)}
.bg {background:rgba(0,255,136,.1); color:var(--green);   border:1px solid rgba(0,255,136,.2)}
.br {background:rgba(255,62,94,.1); color:var(--red);     border:1px solid rgba(255,62,94,.2)}
.by {background:rgba(255,197,66,.1);color:var(--yellow);  border:1px solid rgba(255,197,66,.2)}
.bp {background:rgba(176,106,255,.1);color:var(--purple); border:1px solid rgba(176,106,255,.2)}
.bm {background:rgba(61,84,112,.15);color:var(--muted);   border:1px solid rgba(61,84,112,.3)}

.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}

/* Tech summary grid */
.tech-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:1.4rem}
.tech-card{background:var(--surf2);padding:.9rem 1.1rem;transition:background .15s}
.tech-card:hover{background:#131c28}
.tech-card .tn{font-family:var(--mono);font-size:.78rem;color:var(--accent);margin-bottom:.25rem}
.tech-card .tv{font-size:1.6rem;font-weight:800;color:var(--text);line-height:1}
.tech-card .tl{font-size:.62rem;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}

.empty{padding:2.5rem;text-align:center;color:var(--muted);font-family:var(--mono);font-size:.8rem;letter-spacing:.08em}

/* HTTP status colours */
.s2{color:var(--green)}.s3{color:var(--accent)}.s4{color:var(--yellow)}.s5{color:var(--red)}

/* Scrollbars */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg)}
::-webkit-scrollbar-thumb{background:var(--border);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--muted)}

@keyframes fadeUp{from{opacity:0;transform:translateY(5px)}to{opacity:1;transform:translateY(0)}}
.tab-panel.active{animation:fadeUp .18s ease}

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
  </div>
</header>

<div class="body">

  <!-- SIDEBAR -->
  <aside class="sidebar">

    <div class="sidebar-section">
      <div class="sid-title">Crawler Control</div>

      <div class="field">
        <label>Target Domain</label>
        <input type="text" id="domain" placeholder="https://example.com">
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
      </div>
    </div>

  </aside>

  <!-- CONTENT -->
  <div class="content">

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
        </div>
        <div class="search-row"><input type="text" placeholder="Filter..." oninput="filterTbl('tDomains',this.value)"></div>
        <div class="tbl-wrap"><table id="tDomains">
          <thead><tr><th>URL</th><th>IP</th><th>Server</th><th>Content-Type</th><th>Title</th></tr></thead>
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
        <div class="panel-header"><span class="panel-title">DNS / MX Records</span>
          <button onclick="loadDNS()" style="margin-left:auto;background:none;border:1px solid var(--border);color:var(--muted);font-family:var(--mono);font-size:.72rem;padding:.3rem .7rem;cursor:pointer">↻ Refresh</button>
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

  </div><!-- /content -->
</div><!-- /body -->

<script>
const PORT_SVC={21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',443:'HTTPS',8080:'HTTP-Alt',8443:'HTTPS-Alt',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB'};
const TECH_CLS={'WordPress':'bc','Shopify':'bg','React':'bp','Vue.js':'bp','Angular':'bp','jQuery':'by','Bootstrap':'by','Cloudflare':'bc','Nginx':'bg','Apache':'br','Google Analytics':'bm','Google Tag Mgr':'bm','PHP':'br','ASP.NET':'br','Cloudfront':'bc','Drupal':'bc','Joomla':'bc','Wix':'by','Squarespace':'by'};

let logOffset=0, logLines=0;
let pollInterval=null;
let currentTab='log';

// ── Tab switching ────────────────────────────────────────────
function switchTab(name){
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-pill').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-'+name).classList.add('active');
  document.getElementById('pill-'+name).classList.add('active');
  currentTab=name;
  ({log:()=>{},domains:loadDomains,technologies:loadTech,ports:loadPorts,
    ssl:loadSSL,emails:loadEmails,dns:loadDNS,http:loadHTTP})[name]?.();
}

// ── Crawler control ──────────────────────────────────────────
async function startCrawler(){
  const domain=document.getElementById('domain').value.trim();
  if(!domain){alert('Enter a target domain');return}
  const r=await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({
      domain,
      rate_min:parseFloat(document.getElementById('rateMin').value)||1,
      rate_max:parseFloat(document.getElementById('rateMax').value)||3,
      concurrency:parseInt(document.getElementById('concurrency').value)||5,
      same_domain:document.getElementById('sameDomain').checked
    })});
  const d=await r.json();
  if(!d.ok){alert('Error: '+d.error);return}
  switchTab('log');
  pollStatus();
}

async function stopCrawler(){
  await fetch('/api/stop',{method:'POST'});
}

async function clearDB(){
  if(!confirm('Delete all data from the database?'))return;
  const r=await fetch('/api/clear_db',{method:'POST'});
  const d=await r.json();
  if(d.ok) pollStats();
  else alert('Error: '+d.error);
}

// ── Status polling ───────────────────────────────────────────
async function pollStatus(){
  const r=await fetch('/api/status');
  const d=await r.json();
  const dot=document.getElementById('statusDot');
  const lbl=document.getElementById('runLabel');
  const info=document.getElementById('runInfo');
  const btnStart=document.getElementById('btnStart');
  const btnStop=document.getElementById('btnStop');
  const pulse=document.getElementById('logPulse');

  if(d.running){
    dot.className='status-dot running';
    lbl.textContent='running → '+d.domain;
    lbl.style.color='var(--green)';
    info.style.display='block';
    document.getElementById('riDomain').textContent=d.domain||'—';
    document.getElementById('riStarted').textContent=d.started||'—';
    document.getElementById('riPid').textContent=d.pid||'—';
    btnStart.disabled=true;
    btnStop.disabled=false;
    pulse.style.display='inline';
  } else {
    dot.className='status-dot stopped';
    lbl.textContent='idle';
    lbl.style.color='var(--muted)';
    info.style.display='none';
    btnStart.disabled=false;
    btnStop.disabled=true;
    pulse.style.display='none';
  }
}

// ── Log polling ──────────────────────────────────────────────
function logClass(msg){
  if(msg.startsWith('[NuScrape]'))return'sys';
  if(/error|fail|exception/i.test(msg))return'err';
  if(/warning|warn/i.test(msg))return'warn';
  if(/found|saved|detected|open port/i.test(msg))return'info';
  return'';
}

async function pollLogs(){
  const r=await fetch('/api/logs?since='+logOffset);
  const lines=await r.json();
  if(!lines.length)return;
  const wrap=document.getElementById('logWrap');
  lines.forEach(l=>{
    logOffset++;logLines++;
    document.getElementById('pc-log').textContent=logLines;
    const div=document.createElement('div');
    div.className='log-line '+logClass(l.msg);
    div.innerHTML=`<span class="lt">${l.t}</span><span class="lm">${escHtml(l.msg)}</span>`;
    wrap.appendChild(div);
  });
  if(document.getElementById('autoScroll').checked)
    wrap.scrollTop=wrap.scrollHeight;
}

function clearLog(){
  document.getElementById('logWrap').innerHTML='';
  logOffset=0;logLines=0;
  document.getElementById('pc-log').textContent='0';
}

function escHtml(s){
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Stats polling ────────────────────────────────────────────
async function pollStats(){
  const r=await fetch('/api/stats');
  const d=await r.json();
  document.getElementById('hDomains').textContent=d.domains??0;
  document.getElementById('hEmails').textContent=d.emails??0;
  document.getElementById('hPorts').textContent=d.ports??0;
  document.getElementById('hTech').textContent=d.tech??0;
  document.getElementById('pc-domains').textContent=d.domains??0;
  document.getElementById('pc-technologies').textContent=d.tech??0;
  document.getElementById('pc-emails').textContent=d.emails??0;
  document.getElementById('pc-ports').textContent=d.ports??0;
  document.getElementById('pc-ssl').textContent=d.ssl??0;
  document.getElementById('pc-dns').textContent=d.mx??0;
  document.getElementById('pc-http').textContent=d.http??0;
}

// ── Filter ───────────────────────────────────────────────────
function filterTbl(id,q){
  q=q.toLowerCase();
  document.querySelectorAll('#'+id+' tbody tr').forEach(r=>{
    r.style.display=r.textContent.toLowerCase().includes(q)?'':'none';
  });
}

// ── Data loaders ─────────────────────────────────────────────
function empty(msg='// no records found'){
  return`<tr><td colspan="99" class="empty">${msg}</td></tr>`;
}

function expiryClass(s){
  if(!s||s==='Unknown')return'';
  const d=(new Date(s)-new Date())/86400000;
  return d<0?'bad':d<30?'warn':'ok';
}

async function loadDomains(){
  const rows=await(await fetch('/api/domains')).json();
  document.getElementById('c-domains').textContent=rows.length;
  document.getElementById('bDomains').innerHTML=rows.length
    ?rows.map(d=>`<tr>
      <td class="wrap"><a href="http://${d.url}" target="_blank">${d.url}</a></td>
      <td>${d.ip||'—'}</td>
      <td>${d.servertype?`<span class="b bm">${d.servertype}</span>`:'—'}</td>
      <td>${(d.content_type||'').split(';')[0]||'—'}</td>
      <td>${d.title||'—'}</td>
    </tr>`).join('')
    :empty();
}

async function loadTech(){
  const rows=await(await fetch('/api/technologies')).json();
  document.getElementById('c-technologies').textContent=rows.length;
  const counts={};
  rows.forEach(r=>{counts[r.technology]=(counts[r.technology]||0)+1});
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
  const [ssl,whois]=await Promise.all([
    (await fetch('/api/ssl')).json(),
    (await fetch('/api/whois')).json()
  ]);
  const wm={};whois.forEach(w=>{wm[w.domain]=w});
  document.getElementById('c-ssl').textContent=ssl.length;
  document.getElementById('bSSL').innerHTML=ssl.length
    ?ssl.map(d=>{const w=wm[d.domain]||{};return`<tr>
      <td>${d.domain}</td>
      <td>${d.common_name||'—'}</td>
      <td>${d.issuer||'—'}</td>
      <td class="${expiryClass(d.not_after)}">${d.not_after||'—'}</td>
      <td>${w.registrar||'—'}</td>
      <td class="${expiryClass(w.expiration_date)}">${w.expiration_date||'—'}</td>
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

async function loadDNS(){
  const [dns,mx]=await Promise.all([
    (await fetch('/api/dns')).json(),
    (await fetch('/api/mx')).json()
  ]);
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
      const cls=s<300?'s2':s<400?'s3':s<500?'s4':'s5';
      return`<tr>
        <td><span class="b ${s<300?'bg':s<400?'bc':s<500?'by':'br'}">${s}</span></td>
        <td class="wrap ${cls}">${r.url}</td>
        <td style="color:var(--muted)">${r.checked_at}</td>
      </tr>`;
    }).join('')
    :empty();
}

// ── Init ─────────────────────────────────────────────────────
pollStatus();
pollStats();
pollLogs();

setInterval(()=>{
  pollStatus();
  pollStats();
  pollLogs();
},2000);
</script>
</body>
</html>
"""

if __name__=="__main__":
    print("NuScrape control panel → http://0.0.0.0:5000")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
