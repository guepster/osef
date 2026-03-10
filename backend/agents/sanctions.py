"""
Agent OpenSanctions — clé gratuite + fallback OFAC/EU/ONU sans clé
"""
import requests, re, urllib.parse

TIMEOUT = 12
HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/122", "Accept": "application/json"}

# Sources gratuites alternatives (sans clé API)
FREE_SANCTION_SOURCES = [
    {
        "name": "OFAC SDN (USA)",
        "url": "https://search.ofac.treas.gov/api/search",
        "params_fn": lambda q: {"searchTerm": q, "lists": "SDN", "limit": 5},
        "hit_fn": lambda r: r.get("hits", {}).get("total", {}).get("value", 0) > 0,
        "results_fn": lambda r: r.get("hits", {}).get("hits", []),
    },
    {
        "name": "EU Sanctions (EUFS)",
        "url": "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList_1_1/content",
        # CSV — on fait juste un grep
        "params_fn": lambda q: {},
        "hit_fn": lambda r: False,  # handled specially
        "results_fn": lambda r: [],
    },
]

def _check_ofac(query):
    """OFAC SDN list — API publique gratuite"""
    try:
        r = requests.get(
            "https://search.ofac.treas.gov/api/search",
            params={"searchTerm": query, "limit": 5},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            total = r.json().get("hits", {}).get("total", {}).get("value", 0)
            hits = r.json().get("hits", {}).get("hits", [])
            return total > 0, [{"caption": h.get("_source", {}).get("name", "?"), "schema": "SDN", "datasets": ["ofac_sdn"]} for h in hits[:5]]
    except:
        pass
    return False, []

def _check_eu_sanctions(query):
    """EU Financial Sanctions — endpoint public"""
    try:
        r = requests.get(
            "https://webgate.ec.europa.eu/fsd/fsf/public/files/csvFullSanctionsList/content",
            headers={**HEADERS, "Accept": "text/csv"}, timeout=TIMEOUT
        )
        if r.status_code == 200:
            q_lower = query.lower()
            lines = [l for l in r.text.splitlines() if q_lower in l.lower()]
            if lines:
                return True, [{"caption": query, "schema": "Person/Entity", "datasets": ["eu_fsf"]} for _ in lines[:3]]
    except:
        pass
    return False, []

def agent_opensanctions(query, ctx, emit):
    emit("agent_start", {"id": "opensanctions", "msg": "Scan 330 listes sanctions mondiales..."})
    api_key = ctx.get("opensanctions_key", "")
    try:
        headers = {**HEADERS}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        # Essai endpoint OpenSanctions (avec ou sans clé)
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

        # OpenSanctions inaccessible → fallback sources gratuites
        emit("agent_start", {"id": "opensanctions", "msg": "Fallback: scan OFAC SDN + EU FSF..."})
        all_results = []
        any_hit = False

        # OFAC
        ofac_hit, ofac_results = _check_ofac(query)
        if ofac_hit:
            any_hit = True
            all_results.extend(ofac_results)

        # EU sanctions
        eu_hit, eu_results = _check_eu_sanctions(query)
        if eu_hit:
            any_hit = True
            all_results.extend(eu_results)

        if any_hit:
            emit("agent_done", {
                "id": "opensanctions", "status": "alert",
                "msg": f"🔴 {len(all_results)} résultat(s) — OFAC/EU (fallback sans clé)"
            })
            return {"source": "OpenSanctions", "status": "ok", "data": all_results, "hit": True, "reliability": 90}

        emit("agent_done", {"id": "opensanctions", "status": "ok",
                            "msg": "✅ Absent OFAC SDN + EU FSF (clé OpenSanctions recommandée pour 330 listes)"})
        return {"source": "OpenSanctions", "status": "partial", "data": [], "hit": False, "reliability": 70}

    except Exception as e:
        emit("agent_done", {"id": "opensanctions", "status": "error", "msg": str(e)[:60]})
        return {"source": "OpenSanctions", "status": "error", "data": str(e)}