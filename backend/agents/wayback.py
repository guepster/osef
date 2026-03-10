"""
Agent Wayback — Archive.org Wayback Machine + CDX API (100% gratuit)
Historique complet d'un domaine : pages archivées, évolution, URLs sensibles
"""
import requests, re
from datetime import datetime

TIMEOUT = 12
HEADERS = {"User-Agent": "OSEF-OSINT/2.0", "Accept": "application/json"}

# Patterns d'URLs sensibles à détecter
SENSITIVE_PATTERNS = [
    r"/admin", r"/login", r"/wp-admin", r"/api/", r"/config",
    r"/backup", r"/\.env", r"/passwd", r"/phpinfo", r"/debug",
    r"/internal", r"/secret", r"/private", r"/\.git", r"/upload",
    r"/employee", r"/staff", r"/invoice", r"/financial", r"/report",
]

def agent_wayback(query, ctx, emit):
    emit("agent_start", {"id": "wayback", "msg": "Wayback Machine — historique web de la cible..."})
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
        if not domain or " " in domain or "." not in domain:
            domain = ctx.get("domain", "").strip()
        if not domain:
            # Pour une entreprise, on va chercher le domaine probable
            domain = _guess_domain(query)

        if not domain:
            emit("agent_done", {"id": "wayback", "status": "skip", "msg": "Domaine non détectable"})
            return {"source": "Wayback", "status": "skip", "data": None}

        results = {}

        # 1. CDX API — liste de toutes les captures
        cdx_url = "http://web.archive.org/cdx/search/cdx"
        r = requests.get(cdx_url, params={
            "url": f"*.{domain}",
            "output": "json",
            "fl": "timestamp,original,statuscode,mimetype",
            "limit": 500,
            "collapse": "urlkey",
            "filter": "statuscode:200",
        }, headers=HEADERS, timeout=TIMEOUT)

        urls_data = []
        sensitive_urls = []
        first_seen = None
        last_seen = None

        if r.status_code == 200:
            rows = r.json()
            if rows and len(rows) > 1:
                headers_row = rows[0]
                data_rows = rows[1:]

                timestamps = []
                for row in data_rows:
                    try:
                        ts_str = row[0]
                        original = row[1]
                        status = row[2]
                        mime = row[3]

                        ts = datetime.strptime(ts_str[:14], "%Y%m%d%H%M%S")
                        timestamps.append(ts)

                        # Détecter URLs sensibles
                        is_sensitive = any(re.search(p, original, re.I) for p in SENSITIVE_PATTERNS)
                        url_info = {
                            "url": original,
                            "timestamp": ts.isoformat()[:10],
                            "status": status,
                            "mime": mime,
                            "sensitive": is_sensitive
                        }
                        urls_data.append(url_info)
                        if is_sensitive:
                            sensitive_urls.append(url_info)
                    except:
                        continue

                if timestamps:
                    first_seen = min(timestamps).isoformat()[:10]
                    last_seen = max(timestamps).isoformat()[:10]

        # 2. Availability API — dernière capture disponible
        avail_r = requests.get(
            f"https://archive.org/wayback/available",
            params={"url": domain},
            headers=HEADERS, timeout=TIMEOUT
        )
        last_snapshot = None
        if avail_r.status_code == 200:
            snap = avail_r.json().get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                last_snapshot = {
                    "url": snap.get("url"),
                    "timestamp": snap.get("timestamp"),
                    "status": snap.get("status"),
                }

        # 3. Extraire les sous-domaines découverts
        subdomains_found = set()
        for url_info in urls_data:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_info["url"])
                host = parsed.netloc
                if host and host.endswith(domain) and host != domain:
                    subdomains_found.add(host)
            except:
                pass

        nb_urls = len(urls_data)
        nb_sensitive = len(sensitive_urls)
        nb_subs = len(subdomains_found)

        status = "alert" if nb_sensitive > 0 else "ok"
        msg = f"✅ {nb_urls} URLs archivées depuis {first_seen or '?'}"
        if nb_sensitive > 0:
            msg = f"🔴 {nb_sensitive} URL(s) sensible(s) — {nb_urls} total depuis {first_seen or '?'}"

        emit("agent_done", {"id": "wayback", "status": status, "msg": msg})

        return {
            "source": "Wayback",
            "status": "ok",
            "data": {
                "domain": domain,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "total_urls": nb_urls,
                "sensitive_urls": sensitive_urls[:20],
                "nb_sensitive": nb_sensitive,
                "subdomains": sorted(subdomains_found)[:30],
                "last_snapshot": last_snapshot,
                "sample_urls": [u for u in urls_data[:10]],
            },
            "reliability": 90
        }

    except Exception as e:
        emit("agent_done", {"id": "wayback", "status": "error", "msg": str(e)[:60]})
        return {"source": "Wayback", "status": "error", "data": str(e)}


def _guess_domain(company_name):
    """Tente de deviner le domaine d'une entreprise depuis son nom"""
    # Nettoyage basique
    name = company_name.lower().strip()
    name = re.sub(r'\b(sa|sas|sarl|srl|gmbh|ltd|inc|corp|group|groupe|france|fr)\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)
    if len(name) > 3:
        return f"{name}.fr"
    return None
