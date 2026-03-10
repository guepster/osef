"""
Agent URLScan — urlscan.io (gratuit, sans clé en lecture)
Screenshot + analyse complète d'un domaine : technologies, IPs, redirects, malware
"""
import requests, re

TIMEOUT = 15
HEADERS = {"User-Agent": "OSEF-OSINT/2.0", "Accept": "application/json"}

def agent_urlscan(query, ctx, emit):
    emit("agent_start", {"id": "urlscan", "msg": "URLScan.io — analyse web & screenshot..."})
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
        if not domain or " " in domain or "." not in domain:
            domain = ctx.get("domain", "")
        if not domain:
            domain = _guess_domain(query)
        if not domain:
            emit("agent_done", {"id": "urlscan", "status": "skip", "msg": "Domaine requis"})
            return {"source": "URLScan", "status": "skip", "data": None}

        results = {}

        # 1. Recherche des scans existants (sans clé)
        r = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 10},
            headers=HEADERS, timeout=TIMEOUT
        )

        scans = []
        if r.status_code == 200:
            hits = r.json().get("results", [])
            for hit in hits[:5]:
                page = hit.get("page", {})
                task = hit.get("task", {})
                verdicts = hit.get("verdicts", {})

                scan_info = {
                    "scan_id": hit.get("_id", ""),
                    "url": page.get("url", ""),
                    "domain": page.get("domain", ""),
                    "ip": page.get("ip", ""),
                    "country": page.get("country", ""),
                    "server": page.get("server", ""),
                    "date": task.get("time", "")[:10],
                    "screenshot": f"https://urlscan.io/screenshots/{hit.get('_id','')}.png",
                    "report": f"https://urlscan.io/result/{hit.get('_id','')}/",
                    "malicious": verdicts.get("overall", {}).get("malicious", False),
                    "score": verdicts.get("overall", {}).get("score", 0),
                    "tags": verdicts.get("overall", {}).get("tags", []),
                    "technologies": [],
                }

                # Détails du scan
                if hit.get("_id"):
                    detail_r = requests.get(
                        f"https://urlscan.io/api/v1/result/{hit['_id']}/",
                        headers=HEADERS, timeout=TIMEOUT
                    )
                    if detail_r.status_code == 200:
                        detail = detail_r.json()
                        # Technologies détectées
                        techs = detail.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])
                        scan_info["technologies"] = [t.get("app", "") for t in techs[:10]]
                        # IPs contactées
                        ips = list(set(
                            d.get("remoteIPAddress", "")
                            for d in detail.get("data", {}).get("requests", [])[:50]
                            if d.get("remoteIPAddress")
                        ))
                        scan_info["ips_contacted"] = ips[:10]
                        # Domaines tiers
                        domains_third = list(set(
                            d.get("request", {}).get("documentURL", "").split("/")[2]
                            for d in detail.get("data", {}).get("requests", [])[:100]
                            if d.get("request", {}).get("documentURL", "").startswith("http")
                        ))
                        scan_info["third_party_domains"] = [d for d in domains_third if domain not in d][:15]

                scans.append(scan_info)
                break  # Prendre seulement le premier pour les détails

        any_malicious = any(s.get("malicious") for s in scans)
        status = "alert" if any_malicious else "ok"

        if scans:
            last = scans[0]
            msg = f"🔴 MALVEILLANT détecté" if any_malicious else \
                  f"✅ {last.get('domain','?')} — {last.get('ip','?')} ({last.get('country','?')})"
            if last.get("technologies"):
                msg += f" — Stack: {', '.join(last['technologies'][:3])}"
        else:
            msg = f"⚠️ Aucun scan trouvé pour {domain}"
            status = "warn"

        emit("agent_done", {"id": "urlscan", "status": status, "msg": msg})

        return {
            "source": "URLScan",
            "status": "ok",
            "data": {
                "domain": domain,
                "scans": scans,
                "malicious": any_malicious,
            },
            "reliability": 88
        }

    except Exception as e:
        emit("agent_done", {"id": "urlscan", "status": "error", "msg": str(e)[:60]})
        return {"source": "URLScan", "status": "error", "data": str(e)}


def _guess_domain(company_name):
    name = company_name.lower().strip()
    name = re.sub(r'\b(sa|sas|sarl|srl|gmbh|ltd|inc|corp|group|groupe|france|fr)\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)
    return f"{name}.fr" if len(name) > 3 else None
