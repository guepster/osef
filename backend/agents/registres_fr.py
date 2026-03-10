"""
Agent Registres FR — Infogreffe + HATVP + data.gouv datasets
Bilans financiers, actes déposés, lobbys, déclarations d'intérêts
"""
import requests, re, urllib.parse

TIMEOUT = 12
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122",
    "Accept": "application/json",
}


def _infogreffe_search(query, siren=""):
    """Infogreffe — actes et bilans (données publiques via data.gouv)"""
    results = {}
    try:
        # API RNE (Registre National des Entreprises) — data.gouv.fr
        if siren and siren.isdigit():
            r = requests.get(
                f"https://api.pappers.fr/v2/entreprise",
                params={"siren": siren, "api_token": ""},  # données publiques limitées
                headers=HEADERS, timeout=TIMEOUT
            )

        # Tribunaux de commerce via data.gouv
        r2 = requests.get(
            "https://data.inpi.fr/api/entreprises/search",
            params={"q": query, "pageNum": 0, "pageSize": 5},
            headers={**HEADERS, "Accept": "application/json"},
            timeout=TIMEOUT
        )
        if r2.status_code == 200:
            data = r2.json()
            results["inpi"] = data.get("results", [])[:5]

        # BODACC enrichi — actes de dépôt de bilans
        r3 = requests.get(
            "https://bodacc.fr/api/explore/v2.1/catalog/datasets/annonces-commerciales/records",
            params={"q": query, "limit": 5, "order_by": "dateparution desc",
                    "where": "familleavis_lib LIKE 'Dépôt%'"},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r3.status_code == 200:
            results["depot_bilans"] = r3.json().get("results", [])

    except Exception as e:
        results["error"] = str(e)

    return results


def _hatvp_search(query):
    """HATVP — Haute Autorité pour la Transparence de la Vie Publique"""
    results = {}
    try:
        # API HATVP — déclarations d'intérêts et lobbys
        r = requests.get(
            "https://www.hatvp.fr/foad/api/v1/assujettis",
            params={"q": query, "per_page": 10},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            results["declarations"] = r.json().get("data", [])[:5]

        # Répertoire des représentants d'intérêts (lobbys)
        r2 = requests.get(
            "https://www.hatvp.fr/foad/api/v1/representants-interets",
            params={"q": query, "per_page": 5},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r2.status_code == 200:
            results["lobbying"] = r2.json().get("data", [])[:5]

    except Exception as e:
        # HATVP peut bloquer les requêtes automatisées
        pass

    return results


def _journal_officiel(query):
    """Journal Officiel — publications légales (data.gouv.fr)"""
    try:
        r = requests.get(
            "https://jorfsearch.steinertriples.ch/",
            params={"q": f'"{query}"', "format": "json", "size": 5},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            return r.json().get("hits", [])[:5]
    except:
        pass
    return []


def agent_registres_fr(query, ctx, emit):
    emit("agent_start", {"id": "registres_fr", "msg": "Registres FR — Infogreffe, HATVP, JO..."})
    try:
        siren = ctx.get("siren", "")
        results = {}
        alerts = []

        # 1. Infogreffe / INPI
        infogreffe = _infogreffe_search(query, siren)
        if infogreffe:
            results["infogreffe"] = infogreffe
            depot = infogreffe.get("depot_bilans", [])
            if depot:
                alerts.append(f"{len(depot)} dépôt(s) de bilan(s) trouvé(s) au greffe")

        # 2. HATVP — Lobbying
        hatvp = _hatvp_search(query)
        if hatvp:
            results["hatvp"] = hatvp
            if hatvp.get("lobbying"):
                nb_lobby = len(hatvp["lobbying"])
                alerts.append(f"⚠️ Entité enregistrée comme lobbyiste ({nb_lobby} entrée(s))")
            if hatvp.get("declarations"):
                alerts.append(f"📋 {len(hatvp['declarations'])} déclaration(s) d'intérêts HATVP")

        # 3. Journal Officiel
        jo_results = _journal_officiel(query)
        if jo_results:
            results["journal_officiel"] = jo_results

        # 4. Données ouvertes DGFIP (entreprises publiques)
        try:
            r = requests.get(
                "https://data.economie.gouv.fr/api/explore/v2.1/catalog/datasets/ratios_inpi_bce/records",
                params={"q": query, "limit": 3},
                headers=HEADERS, timeout=TIMEOUT
            )
            if r.status_code == 200:
                ratios = r.json().get("results", [])
                if ratios:
                    results["ratios_financiers"] = ratios
        except:
            pass

        nb_alerts = len(alerts)
        status = "alert" if nb_alerts > 0 else "ok"
        msg = f"🔴 {nb_alerts} signal(aux) trouvé(s)" if nb_alerts else \
              f"✅ Registres FR consultés — aucun signal"

        emit("agent_done", {"id": "registres_fr", "status": status, "msg": msg})

        return {
            "source": "Registres FR",
            "status": "ok",
            "data": results,
            "alerts": alerts,
            "reliability": 85
        }

    except Exception as e:
        emit("agent_done", {"id": "registres_fr", "status": "error", "msg": str(e)[:60]})
        return {"source": "Registres FR", "status": "error", "data": str(e)}
