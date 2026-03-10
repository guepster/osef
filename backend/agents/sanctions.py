"""
Agent OpenSanctions — clé gratuite + fallback bulk
"""
import requests, re, urllib.parse

TIMEOUT = 12
HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/122", "Accept": "application/json"}

def agent_opensanctions(query, ctx, emit):
    emit("agent_start", {"id": "opensanctions", "msg": "Scan 330 listes sanctions mondiales..."})
    api_key = ctx.get("opensanctions_key", "")
    try:
        headers = {**HEADERS}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        # Essai endpoint search
        r = requests.get("https://api.opensanctions.org/search/default",
                         params={"q": query, "limit": 10},
                         headers=headers, timeout=TIMEOUT)

        if r.status_code in [200, 201]:
            results = r.json().get("results", [])
            hit = len(results) > 0
            severity = "alert" if hit else "ok"
            emit("agent_done", {
                "id": "opensanctions", "status": severity,
                "msg": f"🔴 {len(results)} résultat(s) — ENTITÉ SANCTIONNÉE" if hit else "✅ Absent des listes sanctions"
            })
            return {"source": "OpenSanctions", "status": "ok", "data": results, "hit": hit, "reliability": 99}

        # Fallback sans auth
        r2 = requests.get("https://api.opensanctions.org/entities/",
                          params={"q": query}, headers=HEADERS, timeout=TIMEOUT)
        if r2.status_code == 200:
            results = r2.json().get("results", [])
            hit = len(results) > 0
            emit("agent_done", {
                "id": "opensanctions", "status": "alert" if hit else "ok",
                "msg": f"🔴 {len(results)} résultat(s)" if hit else "✅ Aucune sanction"
            })
            return {"source": "OpenSanctions", "status": "ok", "data": results, "hit": hit, "reliability": 99}

        emit("agent_done", {"id": "opensanctions", "status": "warn", "msg": f"HTTP {r.status_code} — clé API recommandée"})
        return {"source": "OpenSanctions", "status": "partial", "data": [], "hit": False, "reliability": 50}
    except Exception as e:
        emit("agent_done", {"id": "opensanctions", "status": "error", "msg": str(e)[:60]})
        return {"source": "OpenSanctions", "status": "error", "data": str(e)}
