"""
Agent Personne Physique — sources gratuites
"""
import requests, re, urllib.parse

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/122", "Accept": "application/json"}

def agent_person_search(query, ctx, emit):
    emit("agent_start", {"id": "person", "msg": "Recherche personne physique..."})
    results = {}
    try:
        # 1. Bodacc — dirigeants impliqués
        r = requests.get(
            "https://bodacc.fr/api/explore/v2.1/catalog/datasets/annonces-commerciales/records",
            params={"q": query, "limit": 5, "order_by": "dateparution desc"},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            records = r.json().get("results", [])
            results["bodacc"] = records

        # 2. OpenSanctions — personne sur liste
        sanction_headers = {**HEADERS}
        if ctx.get("opensanctions_key"):
            sanction_headers["Authorization"] = f"ApiKey {ctx['opensanctions_key']}"
        r2 = requests.get(
            "https://api.opensanctions.org/search/default",
            params={"q": query, "limit": 5, "schema": "Person"},
            headers=sanction_headers, timeout=TIMEOUT
        )
        if r2.status_code == 200:
            results["sanctions"] = r2.json().get("results", [])

        # 3. Recherche entreprises via Sirene (dirigeants)
        r3 = requests.get(
            "https://recherche-entreprises.api.gouv.fr/search",
            params={"q": query, "per_page": 5},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r3.status_code == 200:
            companies_linked = r3.json().get("results", [])
            results["companies_linked"] = companies_linked

        nb_sanctions = len(results.get("sanctions", []))
        nb_companies = len(results.get("companies_linked", []))
        nb_bodacc    = len(results.get("bodacc", []))

        status = "alert" if nb_sanctions > 0 else "ok"
        emit("agent_done", {
            "id": "person", "status": status,
            "msg": f"{'🔴 Sanctionné' if nb_sanctions else '✅'} — {nb_companies} entreprise(s) liée(s), {nb_bodacc} annonce(s)"
        })

        return {
            "source": "Person Search",
            "status": "ok",
            "data": results,
            "reliability": 80
        }
    except Exception as e:
        emit("agent_done", {"id": "person", "status": "error", "msg": str(e)[:60]})
        return {"source": "Person Search", "status": "error", "data": str(e)}
