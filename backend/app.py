"""
OSEF OSINT v2.0 — Backend Principal
Architecture: Flask + SSE streaming + agents parallèles + Groq IA + SQLite
"""
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, Response, stream_with_context, send_from_directory
import os, json, time, uuid, sqlite3, threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue

# ── AGENTS CORE ──────────────────────────────────────────────────────────────
from agents.entreprise    import agent_sirene, agent_bodacc, agent_pappers
from agents.sanctions     import agent_opensanctions
from agents.presse        import agent_news
from agents.infra         import agent_whois, agent_shodan_free
from agents.personne      import agent_person_search
from agents.crypto        import agent_crypto
from agents.ia_cross      import agent_verificateur, agent_synthese_finale
from agents.graph_builder import build_graph_data
from agents.theharvester  import agent_theharvester
from agents.sherlock      import agent_sherlock
from agents.holehe        import agent_holehe
from agents.spiderfoot    import agent_spiderfoot
from agents.tool_manager  import check_all_tools, test_agent as _test_agent
from agents.recondns      import agent_recondns, build_recondns_nodes
from agents.hibp          import agent_hibp
from agents.wayback       import agent_wayback
from agents.dorks         import agent_dorks
from agents.urlscan       import agent_urlscan
from agents.github_search import agent_github
from agents.threat_intel  import agent_threat_intel
from agents.registres_fr  import agent_registres_fr

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend/static")

# ── SQLite ───────────────────────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "osef.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS investigations (
            id               TEXT PRIMARY KEY,
            query            TEXT NOT NULL,
            target_type      TEXT,
            depth            TEXT,
            risk_score       INTEGER DEFAULT 0,
            alerts           TEXT DEFAULT '[]',
            rapport          TEXT DEFAULT '',
            graph            TEXT DEFAULT '{}',
            verified_sources TEXT DEFAULT '[]',
            raw_results      TEXT DEFAULT '[]',
            elapsed          REAL DEFAULT 0,
            timestamp        TEXT,
            client_ref       TEXT DEFAULT '',
            flags            TEXT DEFAULT '[]',
            status           TEXT DEFAULT 'running'
        );
        CREATE TABLE IF NOT EXISTS agent_runs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            inv_id      TEXT NOT NULL,
            agent_id    TEXT NOT NULL,
            agent_name  TEXT,
            status      TEXT,
            duration_ms INTEGER DEFAULT 0,
            hit         INTEGER DEFAULT 0,
            timestamp   TEXT
        );
        CREATE TABLE IF NOT EXISTS surveillance (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            query            TEXT NOT NULL,
            target_type      TEXT DEFAULT 'entreprise',
            depth            TEXT DEFAULT 'quick',
            interval_h       INTEGER DEFAULT 24,
            last_run         TEXT,
            last_score       INTEGER DEFAULT 0,
            alert_threshold  INTEGER DEFAULT 10,
            active           INTEGER DEFAULT 1,
            created_at       TEXT
        );
        """)
    print(f"[DB] SQLite OK: {DB_PATH}")

init_db()

# ── LOG BUFFER ───────────────────────────────────────────────────────────────
_log_buffer = []
_log_lock   = threading.Lock()
_log_cursor = 0

def _push_log(level, msg):
    with _log_lock:
        _log_buffer.append({"time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg})
        if len(_log_buffer) > 500:
            _log_buffer.pop(0)

# ── ROUTES PAGES ─────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/landing")
def landing():
    return send_from_directory("../frontend", "landing.html")

@app.route("/app")
def dashboard():
    return send_from_directory("../frontend", "app.html")

@app.route("/admin")
def admin():
    return send_from_directory("../frontend", "admin.html")

# ── HELPERS ──────────────────────────────────────────────────────────────────

def _get_keys():
    return {
        "groq_key":          os.environ.get("GROQ_API_KEY", ""),
        "pappers_key":       os.environ.get("PAPPERS_API_KEY", ""),
        "opensanctions_key": os.environ.get("OPENSANCTIONS_API_KEY", ""),
        "shodan_key":        os.environ.get("SHODAN_API_KEY", ""),
        "virustotal_key":    os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "abuseipdb_key":     os.environ.get("ABUSEIPDB_API_KEY", ""),
        "github_token":      os.environ.get("GITHUB_TOKEN", ""),
        "hibp_key":          os.environ.get("HIBP_API_KEY", ""),
        "rapidapi_key":      os.environ.get("RAPIDAPI_KEY", ""),
    }

def _save_investigation(inv_id, data):
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO investigations
                (id, query, target_type, depth, risk_score, alerts, rapport,
                 graph, verified_sources, raw_results, elapsed, timestamp, client_ref, flags, status)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                inv_id,
                data.get("query",""),
                data.get("target_type",""),
                data.get("depth",""),
                data.get("risk_score", 0),
                json.dumps(data.get("alerts",[]), ensure_ascii=False),
                data.get("rapport",""),
                json.dumps(data.get("graph",{}), ensure_ascii=False),
                json.dumps(data.get("verified_sources",[]), ensure_ascii=False),
                json.dumps(data.get("raw_results",[]), ensure_ascii=False),
                data.get("elapsed", 0),
                data.get("timestamp", datetime.now().isoformat()),
                data.get("client_ref",""),
                json.dumps(data.get("flags",[]), ensure_ascii=False),
                "complete"
            ))
    except Exception as e:
        _push_log("error", f"[DB] Save error: {e}")

def _save_agent_run(inv_id, agent_id, agent_name, status, duration_ms, hit=False):
    try:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO agent_runs (inv_id, agent_id, agent_name, status, duration_ms, hit, timestamp)
                VALUES (?,?,?,?,?,?,?)
            """, (inv_id, agent_id, agent_name, status, duration_ms, 1 if hit else 0, datetime.now().isoformat()))
    except Exception as e:
        _push_log("error", f"[DB] Agent run error: {e}")

# ── PIPELINE BUILDER ─────────────────────────────────────────────────────────

def _build_agent_pipeline(ctx, emit):
    calls = []
    q, t, depth = ctx["query"], ctx["target_type"], ctx["depth"]

    def make(fn, mid, name, desc, icon):
        return {"fn": lambda f=fn, c=ctx, e=emit: f(q, c, e),
                "meta": {"id": mid, "name": name, "desc": desc, "icon": icon}}

    if t in ["entreprise", "all"]:
        calls += [
            make(agent_sirene,        "sirene",       "INSEE Sirene",   "Registre officiel FR",    "🏛️"),
            make(agent_bodacc,        "bodacc",        "Bodacc",         "Procédures légales FR",   "📋"),
            make(agent_opensanctions, "opensanctions", "OpenSanctions",  "330 listes mondiales",    "⚖️"),
            make(agent_news,          "news",          "Google News",    "Presse FR + EN",          "📰"),
            make(agent_registres_fr,  "registres_fr",  "Registres FR",   "Infogreffe + HATVP + JO", "🏢"),
            make(agent_dorks,         "dorks",         "Google Dorks",   "Recherche avancée",       "🔎"),
        ]
        if ctx.get("pappers_key"):
            calls.append(make(agent_pappers, "pappers", "Pappers", "Registre national FR+", "🇫🇷"))
        if depth in ["standard", "deep"]:
            calls += [
                make(agent_whois,        "whois",        "WHOIS/RDAP",      "Domaine & infra",      "🌐"),
                make(agent_wayback,      "wayback",      "Wayback Machine", "Historique web",        "📜"),
                make(agent_threat_intel, "threat_intel", "ThreatIntel",     "crt.sh + VirusTotal",  "🛡️"),
            ]
        if depth == "deep":
            calls += [
                make(agent_github,  "github",  "GitHub",     "Leaks & code exposé",     "🐙"),
                make(agent_urlscan, "urlscan", "URLScan.io", "Screenshot & analyse web","📸"),
            ]

    if t in ["personne", "all"]:
        calls += [
            make(agent_person_search, "person",        "Person Search",  "Recherche personne",    "👤"),
            make(agent_opensanctions, "opensanctions",  "OpenSanctions",  "Listes sanctions",      "⚖️"),
            make(agent_news,          "news",           "Google News",    "Presse FR + EN",        "📰"),
            make(agent_hibp,          "hibp",           "HaveIBeenPwned", "Fuites de données",     "🔓"),
            make(agent_dorks,         "dorks",          "Google Dorks",   "Recherche avancée",     "🔎"),
        ]
        if depth in ["standard", "deep"]:
            calls += [
                make(agent_bodacc,  "bodacc",   "Bodacc",   "Procédures légales",      "📋"),
                make(agent_sherlock,"sherlock",  "Sherlock", "Username 300+ sites",     "🔍"),
                make(agent_holehe,  "holehe",    "Holehe",   "Email → réseaux sociaux", "📧"),
                make(agent_github,  "github",    "GitHub",   "Mentions & leaks",        "🐙"),
            ]

    if t in ["domaine", "all"]:
        calls += [
            make(agent_whois,        "whois",        "WHOIS/RDAP",      "Domaine & RDAP",       "🌐"),
            make(agent_news,         "news",         "Google News",     "Presse",               "📰"),
            make(agent_threat_intel, "threat_intel", "ThreatIntel",     "crt.sh + VirusTotal",  "🛡️"),
            make(agent_wayback,      "wayback",      "Wayback Machine", "Historique web",        "📜"),
            make(agent_urlscan,      "urlscan",      "URLScan.io",      "Screenshot & analyse", "📸"),
            make(agent_hibp,         "hibp",         "HaveIBeenPwned",  "Fuites de données",     "🔓"),
            make(agent_dorks,        "dorks",        "Google Dorks",    "Configs exposées",      "🔎"),
        ]
        if ctx.get("shodan_key") and depth in ["standard", "deep"]:
            calls.append(make(agent_shodan_free, "shodan", "Shodan", "Scan infra", "🔍"))
        if depth in ["standard", "deep"]:
            calls.append(make(agent_theharvester,"theharvester","theHarvester","Emails & subdomains","🌱"))
        if depth == "deep":
            calls += [
                make(agent_github,    "github",    "GitHub",    "Code & configs exposés", "🐙"),
                make(agent_spiderfoot,"spiderfoot","SpiderFoot","OSINT automation",        "🕷️"),
            ]

    if t in ["crypto", "all"]:
        calls += [
            make(agent_crypto,       "crypto",       "Crypto Trace",  "Blockchain analysis", "🔗"),
            make(agent_opensanctions,"opensanctions", "OpenSanctions", "Listes sanctions",    "⚖️"),
            make(agent_news,         "news",          "Google News",   "Presse",              "📰"),
        ]

    seen, unique = set(), []
    for c in calls:
        if c["meta"]["id"] not in seen:
            seen.add(c["meta"]["id"])
            unique.append(c)
    return unique

# ── SSE STREAM ───────────────────────────────────────────────────────────────

@app.route("/api/investigate/stream")
def investigate_stream():
    query       = request.args.get("query","").strip()
    target_type = request.args.get("target_type","entreprise")
    depth       = request.args.get("depth","standard")
    siren       = request.args.get("siren","").strip()
    domain      = request.args.get("domain","").strip()
    country     = request.args.get("country","FR")
    extra_info  = request.args.get("extra_info","").strip()
    crypto_addr = request.args.get("crypto_addr","").strip()
    client_ref  = request.args.get("client_ref","").strip()

    if not query:
        return jsonify({"error":"Requête vide"}), 400

    inv_id = str(uuid.uuid4())[:8].upper()
    _push_log("info", f"[INV] {inv_id} — {query} [{target_type}/{depth}]")

    def generate():
        q = queue.Queue()
        agent_timings = {}

        def emit(event_type, data):
            q.put({"type": event_type, "data": data})

        def run_pipeline():
            start_total = time.time()
            keys = _get_keys()
            context = {
                "query": query, "target_type": target_type, "depth": depth,
                "siren": siren, "domain": domain, "country": country,
                "extra_info": extra_info, "crypto_addr": crypto_addr,
                "client_ref": client_ref, "inv_id": inv_id, **keys
            }

            emit("init", {"inv_id": inv_id, "query": query, "target_type": target_type,
                          "depth": depth, "timestamp": datetime.now().isoformat()})

            agent_calls = _build_agent_pipeline(context, emit)
            emit("pipeline_start", {"total_agents": len(agent_calls),
                                    "agents": [a["meta"] for a in agent_calls]})

            raw_results = []
            max_workers = 12 if depth == "deep" else 8

            def run_agent_timed(agent_call):
                meta = agent_call["meta"]
                aid  = meta["id"]
                t0   = time.time()
                agent_timings[aid] = {"start_ms": int(t0 * 1000)}
                try:
                    result = agent_call["fn"]()
                    duration_ms = int((time.time() - t0) * 1000)
                    agent_timings[aid].update({"duration_ms": duration_ms, "status": result.get("status","ok")})
                    result["_duration_ms"] = duration_ms
                    result["_agent_id"]    = aid
                    _save_agent_run(inv_id, aid, meta["name"], result.get("status","ok"), duration_ms, result.get("hit",False))
                    emit("agent_timing", {"id": aid, "duration_ms": duration_ms})
                    return result
                except Exception as e:
                    duration_ms = int((time.time() - t0) * 1000)
                    agent_timings[aid].update({"duration_ms": duration_ms, "status": "error"})
                    emit("agent_error", {"id": aid, "error": str(e)[:80]})
                    _save_agent_run(inv_id, aid, meta["name"], "error", duration_ms)
                    return {"source": meta["name"], "status": "error", "data": str(e)}

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(run_agent_timed, a): a["meta"] for a in agent_calls}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            raw_results.append(result)
                    except Exception as e:
                        emit("agent_error", {"id": futures[future]["id"], "error": str(e)[:80]})

            emit("phase", {"phase":"verification","msg":"Croisement IA des sources..."})
            verified, alerts, risk_score, flags = agent_verificateur(raw_results, context, emit)

            emit("phase", {"phase":"synthesis","msg":"Génération rapport IA..."})
            rapport = agent_synthese_finale(query, verified, alerts, risk_score, flags, context, emit)

            # Graphe en thread parallèle
            graph_data_container = [{"nodes":[],"edges":[]}]
            def build_graph():
                try:
                    graph_data_container[0] = build_graph_data(raw_results, context)
                    emit("graph_ready", {"graph": graph_data_container[0]})
                except Exception as e:
                    _push_log("error", f"[GRAPH] {e}")
            gt = threading.Thread(target=build_graph, daemon=True)
            gt.start()
            gt.join(timeout=30)
            graph_data = graph_data_container[0]

            elapsed = round(time.time() - start_total, 2)

            inv_data = {
                "query": query, "target_type": target_type, "depth": depth,
                "risk_score": risk_score, "alerts": alerts, "rapport": rapport,
                "graph": graph_data, "verified_sources": verified,
                "raw_results": raw_results, "elapsed": elapsed,
                "timestamp": datetime.now().isoformat(), "client_ref": client_ref, "flags": flags,
            }
            _save_investigation(inv_id, inv_data)
            _push_log("ok", f"[INV] Done {inv_id} score:{risk_score} {elapsed}s")

            emit("complete", {
                "inv_id": inv_id, "risk_score": risk_score, "alerts": alerts,
                "rapport": rapport, "graph": graph_data, "elapsed": elapsed,
                "sources_count": len(verified), "verified_sources": verified,
                "raw_results": raw_results, "agent_timings": agent_timings,
                "timestamp": datetime.now().isoformat()
            })
            q.put(None)

        threading.Thread(target=run_pipeline, daemon=True).start()

        while True:
            item = q.get()
            if item is None:
                yield "data: [DONE]\n\n"
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Access-Control-Allow-Origin":"*"})

# ── INVESTIGATIONS API ───────────────────────────────────────────────────────

@app.route("/api/investigations")
def list_investigations():
    try:
        limit  = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
        search = request.args.get("q","").strip()
        with get_db() as conn:
            if search:
                rows = conn.execute("""
                    SELECT id, query, target_type, depth, risk_score, alerts, elapsed, timestamp, client_ref, status
                    FROM investigations WHERE query LIKE ? OR client_ref LIKE ?
                    ORDER BY timestamp DESC LIMIT ? OFFSET ?
                """, (f"%{search}%", f"%{search}%", limit, offset)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, query, target_type, depth, risk_score, alerts, elapsed, timestamp, client_ref, status
                    FROM investigations ORDER BY timestamp DESC LIMIT ? OFFSET ?
                """, (limit, offset)).fetchall()
        return jsonify([{
            "id": r["id"], "query": r["query"], "target_type": r["target_type"],
            "depth": r["depth"], "risk_score": r["risk_score"],
            "alerts": json.loads(r["alerts"] or "[]"), "elapsed": r["elapsed"],
            "timestamp": r["timestamp"], "client_ref": r["client_ref"], "status": r["status"]
        } for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/investigation/<inv_id>")
def get_investigation(inv_id):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if not row:
            return jsonify({"error":"Non trouvée"}), 404
        data = dict(row)
        for f in ["alerts","graph","verified_sources","raw_results","flags"]:
            try:
                data[f] = json.loads(data[f] or "[]")
            except:
                pass
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/investigation/<inv_id>", methods=["DELETE"])
def delete_investigation(inv_id):
    try:
        with get_db() as conn:
            conn.execute("DELETE FROM investigations WHERE id=?", (inv_id,))
            conn.execute("DELETE FROM agent_runs WHERE inv_id=?", (inv_id,))
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/graph/<inv_id>")
def get_graph(inv_id):
    try:
        with get_db() as conn:
            row = conn.execute("SELECT graph FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if not row:
            return jsonify({"nodes":[],"edges":[]}), 404
        return jsonify(json.loads(row["graph"] or "{}"))
    except:
        return jsonify({"nodes":[],"edges":[]}), 500

# ── STATS API ────────────────────────────────────────────────────────────────

@app.route("/api/stats")
def get_stats():
    try:
        with get_db() as conn:
            total      = conn.execute("SELECT COUNT(*) as n FROM investigations").fetchone()["n"]
            avg_score  = conn.execute("SELECT AVG(risk_score) as v FROM investigations WHERE status='complete'").fetchone()["v"] or 0
            avg_elapsed= conn.execute("SELECT AVG(elapsed) as v FROM investigations WHERE status='complete'").fetchone()["v"] or 0
            by_type    = conn.execute("SELECT target_type, COUNT(*) as n FROM investigations GROUP BY target_type").fetchall()
            sb         = conn.execute("""
                SELECT
                    SUM(CASE WHEN risk_score < 30 THEN 1 ELSE 0 END) as low,
                    SUM(CASE WHEN risk_score>=30 AND risk_score<50 THEN 1 ELSE 0 END) as medium,
                    SUM(CASE WHEN risk_score>=50 AND risk_score<70 THEN 1 ELSE 0 END) as high,
                    SUM(CASE WHEN risk_score>=70 THEN 1 ELSE 0 END) as critical
                FROM investigations WHERE status='complete'
            """).fetchone()
            agent_stats= conn.execute("""
                SELECT agent_id, agent_name,
                    COUNT(*) as total_runs,
                    SUM(CASE WHEN status IN ('ok','done','warn','alert') THEN 1 ELSE 0 END) as successes,
                    SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) as errors,
                    SUM(hit) as hits,
                    AVG(duration_ms) as avg_ms,
                    MIN(duration_ms) as min_ms,
                    MAX(duration_ms) as max_ms
                FROM agent_runs GROUP BY agent_id, agent_name ORDER BY total_runs DESC
            """).fetchall()
            daily      = conn.execute("""
                SELECT DATE(timestamp) as day, COUNT(*) as n, AVG(risk_score) as avg_score
                FROM investigations WHERE timestamp >= DATE('now','-30 days')
                GROUP BY DATE(timestamp) ORDER BY day ASC
            """).fetchall()
            all_alerts = conn.execute(
                "SELECT alerts FROM investigations WHERE status='complete' ORDER BY timestamp DESC LIMIT 100"
            ).fetchall()

        alert_counts = {}
        for row in all_alerts:
            for a in json.loads(row["alerts"] or "[]"):
                key = a[:80].strip()
                alert_counts[key] = alert_counts.get(key, 0) + 1
        top_alerts = sorted(alert_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return jsonify({
            "total_investigations": total,
            "avg_risk_score": round(avg_score, 1),
            "avg_elapsed": round(avg_elapsed, 1),
            "by_type": {r["target_type"]: r["n"] for r in by_type},
            "score_distribution": {"low": sb["low"] or 0,"medium":sb["medium"] or 0,"high":sb["high"] or 0,"critical":sb["critical"] or 0},
            "agent_stats": [dict(r) for r in agent_stats],
            "daily_activity": [{"day":r["day"],"n":r["n"],"avg_score":round(r["avg_score"] or 0,1)} for r in daily],
            "top_alerts": [{"text":a[0],"count":a[1]} for a in top_alerts],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── EXPAND NODE ──────────────────────────────────────────────────────────────

@app.route("/api/expand_node", methods=["POST"])
def expand_node():
    data       = request.json or {}
    node_type  = data.get("node_type","")
    node_label = data.get("node_label","")
    node_id    = data.get("node_id","")
    if not node_label:
        return jsonify({"error":"node_label requis"}), 400

    keys = _get_keys()
    context = {"query":node_label,"target_type":node_type,"depth":"quick",
               "siren":"","domain":node_label if node_type=="domain" else "","country":"FR",
               "extra_info":"","crypto_addr":"",**keys}
    def noop(t,d): pass
    results = []
    if node_type in ["company","company_main"]:
        results += [agent_sirene(node_label,context,noop), agent_bodacc(node_label,context,noop)]
    elif node_type == "person":
        results.append(agent_person_search(node_label,context,noop))
    elif node_type == "domain":
        results += [agent_whois(node_label,context,noop), agent_threat_intel(node_label,context,noop)]
    elif node_type in ["crypto","wallet"]:
        results.append(agent_crypto(node_label,context,noop))
    new_graph = build_graph_data(results, context)
    return jsonify({"nodes":new_graph["nodes"],"edges":new_graph["edges"],"parent_node":node_id})

# ── SURVEILLANCE ─────────────────────────────────────────────────────────────

@app.route("/api/surveillance", methods=["GET"])
def list_surveillance():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM surveillance ORDER BY created_at DESC").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/surveillance", methods=["POST"])
def add_surveillance():
    data = request.json or {}
    if not data.get("query"):
        return jsonify({"error":"query requis"}), 400
    with get_db() as conn:
        conn.execute("""
            INSERT INTO surveillance (query, target_type, depth, interval_h, alert_threshold, created_at)
            VALUES (?,?,?,?,?,?)
        """, (data["query"], data.get("target_type","entreprise"), data.get("depth","quick"),
              data.get("interval_h",24), data.get("alert_threshold",10), datetime.now().isoformat()))
    return jsonify({"ok":True})

@app.route("/api/surveillance/<int:sid>", methods=["DELETE"])
def delete_surveillance(sid):
    with get_db() as conn:
        conn.execute("DELETE FROM surveillance WHERE id=?", (sid,))
    return jsonify({"ok":True})

# ── STATUS ───────────────────────────────────────────────────────────────────

@app.route("/api/status")
def status():
    keys = _get_keys()
    with get_db() as conn:
        inv_count = conn.execute("SELECT COUNT(*) as n FROM investigations").fetchone()["n"]
    return jsonify({"status":"ok","version":"2.0.0","investigations_count":inv_count,
                    "keys":{k:bool(v) for k,v in keys.items()},"db":DB_PATH})

# ── ADMIN ────────────────────────────────────────────────────────────────────

@app.route("/api/admin/tools")
def admin_tools():
    try:
        return jsonify(check_all_tools())
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/admin/test_key", methods=["POST"])
def admin_test_key():
    import requests as req
    data=request.json or {}; key_name=data.get("key",""); value=data.get("value","")
    valid=False
    try:
        if "GROQ" in key_name:
            r=req.get("https://api.groq.com/openai/v1/models",headers={"Authorization":f"Bearer {value}"},timeout=8); valid=r.status_code==200
        elif "PAPPERS" in key_name:
            r=req.get("https://api.pappers.fr/v2/entreprise",params={"api_token":value,"siren":"542051180"},timeout=8); valid=r.status_code in[200,404]
        elif "OPENSANCTIONS" in key_name:
            r=req.get("https://api.opensanctions.org/search/default",params={"q":"test","limit":1},headers={"Authorization":f"ApiKey {value}"},timeout=8); valid=r.status_code==200
        elif "SHODAN" in key_name:
            r=req.get("https://api.shodan.io/api-info",params={"key":value},timeout=8); valid=r.status_code==200
        else:
            valid=bool(value)
    except: valid=False
    _push_log("ok" if valid else "warn",f"[KEY TEST] {key_name} -> {'valide' if valid else 'invalide'}")
    return jsonify({"valid":valid})

@app.route("/api/admin/save_key", methods=["POST"])
def admin_save_key():
    data=request.json or {}; key_name=data.get("key",""); value=data.get("value","")
    if not key_name or not value:
        return jsonify({"ok":False,"error":"key et value requis"}),400
    try:
        env_path=os.path.join(os.path.dirname(__file__),".env")
        lines=[]
        if os.path.exists(env_path):
            with open(env_path) as f: lines=f.readlines()
        found,new_lines=False,[]
        for line in lines:
            if line.strip().startswith(f"{key_name}="):
                new_lines.append(f"{key_name}={value}\n"); found=True
            else:
                new_lines.append(line)
        if not found: new_lines.append(f"{key_name}={value}\n")
        with open(env_path,"w") as f: f.writelines(new_lines)
        os.environ[key_name]=value
        _push_log("ok",f"[KEY SAVED] {key_name}")
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})

@app.route("/api/admin/logs")
def admin_logs():
    global _log_cursor
    with _log_lock:
        new_entries=_log_buffer[_log_cursor:]; _log_cursor=len(_log_buffer)
    return jsonify({"entries":new_entries})

@app.route("/api/admin/test_agent")
def admin_test_agent():
    agent_name=request.args.get("agent",""); query=request.args.get("query","TotalEnergies")
    if not agent_name: return jsonify({"error":"agent requis"}),400
    result=_test_agent(agent_name,query)
    _push_log("info",f"[TEST] {agent_name} -> {result.get('status','?')}")
    return jsonify(result)

if __name__ == "__main__":
    print("╔══════════════════════════╗")
    print("║  OSEF OSINT v2.0         ║")
    print("║  http://localhost:5000   ║")
    print("╚══════════════════════════╝")
    app.run(debug=True, port=5000, threaded=True)