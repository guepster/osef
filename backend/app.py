"""
NEXUS OSINT — Backend Principal
Architecture: Flask + SSE streaming + agents parallèles + Groq IA
"""
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify, Response, stream_with_context, send_from_directory
import os, json, time, uuid
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue, threading

# Agents core
from agents.entreprise    import agent_sirene, agent_bodacc, agent_pappers
from agents.sanctions     import agent_opensanctions
from agents.presse        import agent_news
from agents.infra         import agent_whois, agent_shodan_free
from agents.personne      import agent_person_search
from agents.crypto        import agent_crypto
from agents.ia_cross      import agent_verificateur, agent_synthese_finale
from agents.graph_builder import build_graph_data

# Agents open-source tools
from agents.theharvester  import agent_theharvester
from agents.sherlock       import agent_sherlock
from agents.holehe         import agent_holehe
from agents.spiderfoot     import agent_spiderfoot
from agents.tool_manager   import check_all_tools, test_agent as _test_agent
from agents.recondns       import agent_recondns, build_recondns_nodes

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend/static")

# ── CONFIG ──────────────────────────────────────────────────────────────────
GROQ_API_KEY        = os.environ.get("GROQ_API_KEY", "")
PAPPERS_API_KEY     = os.environ.get("PAPPERS_API_KEY", "")
OPENSANCTIONS_KEY   = os.environ.get("OPENSANCTIONS_API_KEY", "")
SHODAN_API_KEY      = os.environ.get("SHODAN_API_KEY", "")

# Storage en mémoire (à remplacer par Redis/DB en prod)
investigations = {}

# Log buffer circulaire
_log_buffer = []
_log_lock   = threading.Lock()
_log_cursor = 0

def _push_log(level, msg):
    with _log_lock:
        _log_buffer.append({"time": datetime.now().strftime("%H:%M:%S"), "level": level, "msg": msg})
        if len(_log_buffer) > 300:
            _log_buffer.pop(0)

# ── ROUTES PAGES ────────────────────────────────────────────────────────────

@app.route("/admin")
def admin():
    return send_from_directory("../frontend", "admin.html")


    return send_from_directory("../frontend", "landing.html")

@app.route("/app")
def dashboard():
    return send_from_directory("../frontend", "app.html")

@app.route("/report/<inv_id>")
def report(inv_id):
    return send_from_directory("../frontend", "report.html")

@app.route("/graph/<inv_id>")
def graph_view(inv_id):
    return send_from_directory("../frontend", "graph.html")

# ── API ──────────────────────────────────────────────────────────────────────

@app.route("/api/investigate/stream")
def investigate_stream():
    """SSE endpoint — lance le pipeline complet et stream les events"""
    # Lire les paramètres du formulaire d'intake
    query        = request.args.get("query", "").strip()
    target_type  = request.args.get("target_type", "entreprise")  # entreprise|personne|domaine|crypto
    depth        = request.args.get("depth", "standard")           # quick|standard|deep
    siren        = request.args.get("siren", "").strip()
    domain       = request.args.get("domain", "").strip()
    country      = request.args.get("country", "FR")
    extra_info   = request.args.get("extra_info", "").strip()
    crypto_addr  = request.args.get("crypto_addr", "").strip()
    client_ref   = request.args.get("client_ref", "").strip()

    if not query:
        return jsonify({"error": "Requête vide"}), 400

    inv_id = str(uuid.uuid4())[:8].upper()

    def generate():
        q = queue.Queue()

        def emit(event_type, data):
            q.put({"type": event_type, "data": data})

        def run_pipeline():
            start = time.time()
            context = {
                "query": query, "target_type": target_type, "depth": depth,
                "siren": siren, "domain": domain, "country": country,
                "extra_info": extra_info, "crypto_addr": crypto_addr,
                "client_ref": client_ref, "inv_id": inv_id,
                "pappers_key": PAPPERS_API_KEY,
                "opensanctions_key": OPENSANCTIONS_KEY,
                "shodan_key": SHODAN_API_KEY,
                "groq_key": GROQ_API_KEY,
            }

            emit("init", {
                "inv_id": inv_id, "query": query, "target_type": target_type,
                "depth": depth, "timestamp": datetime.now().isoformat()
            })

            # ── SÉLECTION DES AGENTS selon type + profondeur ──────────────
            agent_calls = _build_agent_pipeline(context, emit)

            emit("pipeline_start", {
                "total_agents": len(agent_calls),
                "agents": [a["meta"] for a in agent_calls]
            })

            # ── EXÉCUTION PARALLÈLE ───────────────────────────────────────
            raw_results = []
            max_workers = 12 if depth == "deep" else 8

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {executor.submit(a["fn"]): a["meta"] for a in agent_calls}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        raw_results.append(result)
                    except Exception as e:
                        meta = futures[future]
                        emit("agent_error", {"id": meta["id"], "error": str(e)[:80]})

            # ── VÉRIFICATION CROISÉE IA ───────────────────────────────────
            emit("phase", {"phase": "verification", "msg": "Croisement IA des sources..."})
            verified, alerts, risk_score, flags = agent_verificateur(raw_results, context, emit)

            # ── SYNTHÈSE FINALE GROQ ──────────────────────────────────────
            emit("phase", {"phase": "synthesis", "msg": "Génération rapport IA..."})
            rapport = agent_synthese_finale(query, verified, alerts, risk_score, flags, context, emit)

            # ── CONSTRUCTION GRAPHE ───────────────────────────────────────
            emit("phase", {"phase": "graph", "msg": "Construction graphe relationnel..."})
            graph_data = build_graph_data(raw_results, context)

            elapsed = round(time.time() - start, 2)

            # Stocker pour accès ultérieur
            investigations[inv_id] = {
                "query": query, "target_type": target_type,
                "risk_score": risk_score, "alerts": alerts,
                "verified_sources": verified, "rapport": rapport,
                "graph": graph_data, "elapsed": elapsed,
                "timestamp": datetime.now().isoformat(),
                "client_ref": client_ref, "flags": flags
            }

            emit("complete", {
                "inv_id": inv_id, "risk_score": risk_score,
                "alerts": alerts, "rapport": rapport,
                "graph": graph_data, "elapsed": elapsed,
                "sources_count": len(verified),
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

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no",
                 "Access-Control-Allow-Origin": "*"}
    )


@app.route("/api/investigation/<inv_id>")
def get_investigation(inv_id):
    inv = investigations.get(inv_id)
    if not inv:
        return jsonify({"error": "Investigation non trouvée"}), 404
    return jsonify(inv)


@app.route("/api/graph/<inv_id>")
def get_graph(inv_id):
    inv = investigations.get(inv_id)
    if not inv:
        return jsonify({"nodes": [], "edges": []}), 404
    return jsonify(inv.get("graph", {"nodes": [], "edges": []}))


@app.route("/api/expand_node", methods=["POST"])
def expand_node():
    """Lance un sous-pipeline sur un nœud du graphe (comme les transforms Maltego)"""
    data = request.json
    node_id    = data.get("node_id", "")
    node_type  = data.get("node_type", "")
    node_label = data.get("node_label", "")
    parent_inv = data.get("inv_id", "")

    if not node_label:
        return jsonify({"error": "node_label requis"}), 400

    # Mini pipeline selon le type du nœud
    results = []
    context = {
        "query": node_label, "target_type": node_type, "depth": "quick",
        "pappers_key": PAPPERS_API_KEY, "opensanctions_key": OPENSANCTIONS_KEY,
        "groq_key": GROQ_API_KEY, "shodan_key": SHODAN_API_KEY,
        "siren": "", "domain": node_label if node_type == "domain" else "",
        "country": "FR", "extra_info": "", "crypto_addr": "",
    }

    def dummy_emit(t, d): pass

    if node_type in ["company", "company_main"]:
        results.append(agent_sirene(node_label, context, dummy_emit))
        results.append(agent_bodacc(node_label, context, dummy_emit))
    elif node_type == "person":
        results.append(agent_person_search(node_label, context, dummy_emit))
    elif node_type == "domain":
        results.append(agent_whois(node_label, context, dummy_emit))
    elif node_type in ["crypto", "wallet"]:
        results.append(agent_crypto(node_label, context, dummy_emit))

    new_graph = build_graph_data(results, context)
    return jsonify({"nodes": new_graph["nodes"], "edges": new_graph["edges"], "parent_node": node_id})


@app.route("/api/status")
def status():
    return jsonify({
        "status": "ok",
        "version": "2.0.0",
        "agents": ["sirene", "bodacc", "pappers", "opensanctions",
                   "news", "whois", "shodan", "person", "crypto", "ia_cross"],
        "investigations_count": len(investigations),
        "keys": {
            "groq": bool(GROQ_API_KEY),
            "pappers": bool(PAPPERS_API_KEY),
            "opensanctions": bool(OPENSANCTIONS_KEY),
            "shodan": bool(SHODAN_API_KEY),
        }
    })


# ── PIPELINE BUILDER ─────────────────────────────────────────────────────────

def _build_agent_pipeline(ctx, emit):
    """Construit la liste d'agents selon le type de cible et la profondeur"""
    calls = []
    q, t, depth = ctx["query"], ctx["target_type"], ctx["depth"]

    def make(agent_fn, meta_id, meta_name, meta_desc, meta_icon):
        return {
            "fn": lambda fn=agent_fn, c=ctx, e=emit: fn(q, c, e),
            "meta": {"id": meta_id, "name": meta_name, "desc": meta_desc, "icon": meta_icon}
        }

    # ── ENTREPRISE ──────────────────────────────────────────────────────────
    if t in ["entreprise", "all"]:
        calls.append(make(agent_sirene, "sirene", "INSEE Sirene", "Registre officiel FR", "🏛️"))
        calls.append(make(agent_bodacc, "bodacc", "Bodacc", "Procédures légales FR", "📋"))
        calls.append(make(agent_opensanctions, "opensanctions", "OpenSanctions", "330 listes mondiales", "⚖️"))
        calls.append(make(agent_news, "news", "Google News", "Presse FR + EN", "📰"))
        if ctx["pappers_key"]:
            calls.append(make(agent_pappers, "pappers", "Pappers", "Registre national FR+", "🇫🇷"))
        if depth in ["standard", "deep"]:
            calls.append(make(agent_whois, "whois", "WHOIS/RDAP", "Domaine & infra", "🌐"))

    # ── PERSONNE ────────────────────────────────────────────────────────────
    if t in ["personne", "all"]:
        calls.append(make(agent_person_search, "person", "Person Search", "Recherche personne", "👤"))
        calls.append(make(agent_opensanctions, "opensanctions", "OpenSanctions", "Listes sanctions", "⚖️"))
        calls.append(make(agent_news, "news", "Google News", "Presse FR + EN", "📰"))
        if depth in ["standard", "deep"]:
            calls.append(make(agent_bodacc, "bodacc", "Bodacc", "Procédures légales", "📋"))

    # ── DOMAINE / INFRA ─────────────────────────────────────────────────────
    if t in ["domaine", "all"]:
        calls.append(make(agent_whois, "whois", "WHOIS/RDAP", "Domaine & RDAP", "🌐"))
        calls.append(make(agent_news, "news", "Google News", "Presse", "📰"))
        if ctx["shodan_key"] and depth in ["standard", "deep"]:
            calls.append(make(agent_shodan_free, "shodan", "Shodan", "Scan infra", "🔍"))
        if depth in ["standard", "deep"]:
            calls.append(make(agent_theharvester, "theharvester", "theHarvester", "Emails & subdomains", "🌱"))
        if depth == "deep":
            calls.append(make(agent_spiderfoot, "spiderfoot", "SpiderFoot", "OSINT automation", "🕷️"))

    # ── PERSONNE enrichie ────────────────────────────────────────────────────
    if t in ["personne", "all"]:
        if depth in ["standard", "deep"]:
            calls.append(make(agent_sherlock, "sherlock", "Sherlock", "Username 300+ sites", "🔍"))
            calls.append(make(agent_holehe, "holehe", "Holehe", "Email → réseaux sociaux", "📧"))

    # ── CRYPTO ──────────────────────────────────────────────────────────────
    if t in ["crypto", "all"]:
        calls.append(make(agent_crypto, "crypto", "Crypto Trace", "Blockchain analysis", "🔗"))
        calls.append(make(agent_opensanctions, "opensanctions", "OpenSanctions", "Listes sanctions", "⚖️"))

    # Dédoublonner par id
    seen = set()
    unique = []
    for c in calls:
        if c["meta"]["id"] not in seen:
            seen.add(c["meta"]["id"])
            unique.append(c)

    return unique


# ── ADMIN API ────────────────────────────────────────────────────────────────

@app.route("/admin")
def admin_page():
    return send_from_directory("../frontend", "admin.html")

@app.route("/api/admin/tools")
def admin_tools():
    try:
        return jsonify(check_all_tools())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/admin/test_agent")
def admin_test_agent():
    agent_name = request.args.get("agent", "")
    query = request.args.get("query", "TotalEnergies")
    if not agent_name:
        return jsonify({"error": "agent requis"}), 400
    result = _test_agent(agent_name, query)
    _push_log("info", f"[TEST] Agent {agent_name} sur '{query}' -> {result.get('status','?')}")
    return jsonify(result)

@app.route("/api/admin/test_key", methods=["POST"])
def admin_test_key():
    import requests as req
    data = request.json or {}
    key_name = data.get("key", "")
    value    = data.get("value", "")
    valid = False
    try:
        if "GROQ" in key_name:
            r = req.get("https://api.groq.com/openai/v1/models", headers={"Authorization": f"Bearer {value}"}, timeout=8)
            valid = r.status_code == 200
        elif "PAPPERS" in key_name:
            r = req.get("https://api.pappers.fr/v2/entreprise", params={"api_token": value, "siren": "542051180"}, timeout=8)
            valid = r.status_code in [200, 404]  # 404 = clé valide mais SIREN inconnu
        elif "OPENSANCTIONS" in key_name:
            r = req.get("https://api.opensanctions.org/search/default", params={"q": "test", "limit": 1}, headers={"Authorization": f"ApiKey {value}"}, timeout=8)
            valid = r.status_code == 200
        elif "SHODAN" in key_name:
            r = req.get("https://api.shodan.io/api-info", params={"key": value}, timeout=8)
            valid = r.status_code == 200
        else:
            valid = bool(value)
    except:
        valid = False
    _push_log("ok" if valid else "warn", f"[KEY TEST] {key_name} -> {'valide' if valid else 'invalide'}")
    return jsonify({"valid": valid})

@app.route("/api/admin/save_key", methods=["POST"])
def admin_save_key():
    data = request.json or {}
    key_name = data.get("key", "")
    value    = data.get("value", "")
    if not key_name or not value:
        return jsonify({"ok": False, "error": "key et value requis"}), 400
    try:
        env_path = os.path.join(os.path.dirname(__file__), ".env")
        lines = []
        if os.path.exists(env_path):
            with open(env_path) as f:
                lines = f.readlines()
        found = False
        new_lines = []
        for line in lines:
            if line.strip().startswith(f"{key_name}="):
                new_lines.append(f"{key_name}={value}\n")
                found = True
            else:
                new_lines.append(line)
        if not found:
            new_lines.append(f"{key_name}={value}\n")
        with open(env_path, "w") as f:
            f.writelines(new_lines)
        os.environ[key_name] = value
        _push_log("ok", f"[KEY SAVED] {key_name} mis a jour")
        return jsonify({"ok": True})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/admin/logs")
def admin_logs():
    global _log_cursor
    with _log_lock:
        new_entries = _log_buffer[_log_cursor:]
        _log_cursor = len(_log_buffer)
    return jsonify({"entries": new_entries})

@app.route("/api/investigations")
def list_investigations():
    result = []
    for inv_id, inv in investigations.items():
        result.append({
            "id": inv_id, "query": inv.get("query"),
            "target_type": inv.get("target_type"),
            "risk_score": inv.get("risk_score"),
            "alerts": inv.get("alerts", []),
            "elapsed": inv.get("elapsed"),
            "timestamp": inv.get("timestamp"),
        })
    result.sort(key=lambda x: x.get("timestamp",""), reverse=True)
    return jsonify(result)


if __name__ == "__main__":
    print("NEXUS OSINT v2.0")
    print("App:   http://localhost:5000/app")
    print("Admin: http://localhost:5000/admin")
    app.run(debug=True, port=5000, threaded=True)