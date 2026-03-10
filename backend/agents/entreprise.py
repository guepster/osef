"""
Agents Entreprise — INSEE Sirene (gratuit), Bodacc, Pappers
"""
import requests, os, json, urllib.parse

TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122",
    "Accept": "application/json",
    "Accept-Language": "fr-FR,fr;q=0.9",
}

def agent_sirene(query, ctx, emit):
    emit("agent_start", {"id": "sirene", "msg": "Interrogation INSEE Sirene..."})
    try:
        # API Recherche Entreprises (data.gouv.fr) — 100% gratuite, zéro auth
        url = "https://recherche-entreprises.api.gouv.fr/search"
        params = {"q": query, "per_page": 5}
        if ctx.get("siren") and ctx["siren"].isdigit():
            params = {"q": ctx["siren"], "per_page": 1}

        r = requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            if results:
                top = results[0]
                nb = len(results)
                emit("agent_done", {
                    "id": "sirene",
                    "status": "ok",
                    "msg": f"✅ {top.get('nom_complet', top.get('nom_raison_sociale', '?'))} — {top.get('nature_juridique_libelle', '?')}"
                })
                return {
                    "source": "Sirene",
                    "status": "ok",
                    "data": results,
                    "top": top,
                    "reliability": 98,
                    "count": nb
                }
            emit("agent_done", {"id": "sirene", "status": "not_found", "msg": "⚠️ Aucune entreprise trouvée"})
            return {"source": "Sirene", "status": "not_found", "data": []}

        emit("agent_done", {"id": "sirene", "status": "warn", "msg": f"HTTP {r.status_code}"})
        return {"source": "Sirene", "status": "error", "data": f"HTTP {r.status_code}"}

    except Exception as e:
        emit("agent_done", {"id": "sirene", "status": "error", "msg": str(e)[:60]})
        return {"source": "Sirene", "status": "error", "data": str(e)}


def agent_bodacc(query, ctx, emit):
    emit("agent_start", {"id": "bodacc", "msg": "Scan procédures collectives Bodacc..."})
    try:
        # Dataset Bodacc — annonces-commerciales
        datasets = [
            "annonces-commerciales",
            "annonces-civiles",
        ]
        all_records = []
        for ds in datasets:
            url = f"https://bodacc.fr/api/explore/v2.1/catalog/datasets/{ds}/records"
            r = requests.get(url, params={"q": query, "limit": 10, "order_by": "dateparution desc"},
                             headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                all_records.extend(r.json().get("results", []))

        nb = len(all_records)
        # Classifier les types d'annonces
        critical = [r for r in all_records if any(
            t in (r.get("typeavis_lib","") + r.get("familleavis_lib","")).lower()
            for t in ["liquidation","redressement","sauvegarde","radiation","dissolution"]
        )]

        if nb > 0:
            emit("agent_done", {
                "id": "bodacc", "status": "alert",
                "msg": f"🔴 {nb} annonce(s) — {len(critical)} critique(s)"
            })
        else:
            emit("agent_done", {"id": "bodacc", "status": "ok", "msg": "✅ Aucune procédure collective"})

        return {
            "source": "Bodacc",
            "status": "ok",
            "data": all_records,
            "critical": critical,
            "reliability": 99,
            "count": nb
        }
    except Exception as e:
        emit("agent_done", {"id": "bodacc", "status": "error", "msg": str(e)[:60]})
        return {"source": "Bodacc", "status": "error", "data": str(e)}


def agent_pappers(query, ctx, emit):
    emit("agent_start", {"id": "pappers", "msg": "Interrogation Pappers — données enrichies..."})
    api_key = ctx.get("pappers_key", "")
    if not api_key:
        emit("agent_done", {"id": "pappers", "status": "skip", "msg": "Clé API Pappers manquante"})
        return {"source": "Pappers", "status": "no_key", "data": None}
    try:
        params = {"api_token": api_key}
        if ctx.get("siren") and ctx["siren"].isdigit():
            params["siren"] = ctx["siren"]
        elif query.replace(" ","").isdigit() and len(query.replace(" ","")) in [9,14]:
            params["siren"] = query.replace(" ","")
        else:
            params["nom_entreprise"] = query

        r = requests.get("https://api.pappers.fr/v2/entreprise", params=params,
                         headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            emit("agent_done", {
                "id": "pappers", "status": "ok",
                "msg": f"✅ {d.get('nom_entreprise','?')} — {len(d.get('dirigeants',[]))} dirigeant(s)"
            })
            return {"source": "Pappers", "status": "ok", "data": d, "reliability": 97}

        emit("agent_done", {"id": "pappers", "status": "warn", "msg": f"HTTP {r.status_code}"})
        return {"source": "Pappers", "status": "error", "data": f"HTTP {r.status_code}"}
    except Exception as e:
        emit("agent_done", {"id": "pappers", "status": "error", "msg": str(e)[:60]})
        return {"source": "Pappers", "status": "error", "data": str(e)}
