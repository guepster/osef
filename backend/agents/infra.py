"""
Agents Infrastructure — WHOIS/RDAP + Shodan free tier
"""
import requests, json

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/122", "Accept": "application/json"}

def agent_whois(query, ctx, emit):
    emit("agent_start", {"id": "whois", "msg": "Analyse WHOIS/RDAP domaine & IP..."})
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
        if not domain:
            domain = ctx.get("domain", query)

        results = {}

        # RDAP domain
        r = requests.get(f"https://rdap.org/domain/{domain}", headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            d = r.json()
            results["rdap"] = d
            handle = d.get("ldhName", d.get("handle", domain))

            # Extraire dates et nameservers
            events = {ev.get("eventAction"): ev.get("eventDate","")[:10]
                      for ev in d.get("events", [])}
            ns = [n.get("ldhName","") for n in d.get("nameservers", [])][:4]
            registrant = next(
                (e.get("vcardArray", [[],[]]) for e in d.get("entities", [])
                 if "registrant" in e.get("roles", [])), None
            )

            emit("agent_done", {
                "id": "whois", "status": "ok",
                "msg": f"✅ {handle} — créé {events.get('registration','?')}"
            })
            return {
                "source": "WHOIS/RDAP",
                "status": "ok",
                "data": {
                    "domain": handle,
                    "registered": events.get("registration",""),
                    "expiration": events.get("expiration",""),
                    "last_changed": events.get("last changed",""),
                    "nameservers": ns,
                    "status": d.get("status", []),
                    "raw": d
                },
                "reliability": 90
            }

        # Fallback IP lookup si c'est une IP
        if all(c.isdigit() or c == "." for c in domain):
            r2 = requests.get(f"https://ipapi.co/{domain}/json/", headers=HEADERS, timeout=TIMEOUT)
            if r2.status_code == 200:
                ip_data = r2.json()
                emit("agent_done", {
                    "id": "whois", "status": "ok",
                    "msg": f"✅ IP {domain} — {ip_data.get('org','?')} ({ip_data.get('country_name','?')})"
                })
                return {
                    "source": "WHOIS/RDAP",
                    "status": "ok",
                    "data": {"ip": domain, "ip_info": ip_data},
                    "reliability": 85
                }

        emit("agent_done", {"id": "whois", "status": "warn", "msg": f"HTTP {r.status_code}"})
        return {"source": "WHOIS/RDAP", "status": "not_found", "data": None}

    except Exception as e:
        emit("agent_done", {"id": "whois", "status": "error", "msg": str(e)[:60]})
        return {"source": "WHOIS/RDAP", "status": "error", "data": str(e)}


def agent_shodan_free(query, ctx, emit):
    """Shodan avec clé API (plan gratuit = 1 requête/s)"""
    emit("agent_start", {"id": "shodan", "msg": "Scan Shodan infrastructure..."})
    api_key = ctx.get("shodan_key", "")
    if not api_key:
        emit("agent_done", {"id": "shodan", "status": "skip", "msg": "Clé Shodan manquante"})
        return {"source": "Shodan", "status": "no_key", "data": None}
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0]
        # DNS lookup via Shodan
        r = requests.get(f"https://api.shodan.io/dns/resolve",
                         params={"hostnames": domain, "key": api_key},
                         headers=HEADERS, timeout=TIMEOUT)
        ips = {}
        if r.status_code == 200:
            ips = r.json()

        # Host info pour chaque IP
        host_data = []
        for hn, ip in list(ips.items())[:2]:
            r2 = requests.get(f"https://api.shodan.io/shodan/host/{ip}",
                              params={"key": api_key}, headers=HEADERS, timeout=TIMEOUT)
            if r2.status_code == 200:
                hd = r2.json()
                host_data.append({
                    "ip": ip, "hostname": hn,
                    "org": hd.get("org","?"),
                    "country": hd.get("country_name","?"),
                    "ports": hd.get("ports", []),
                    "vulns": list(hd.get("vulns", {}).keys())[:5],
                    "tags": hd.get("tags", [])
                })

        nb_vulns = sum(len(h.get("vulns",[])) for h in host_data)
        status = "alert" if nb_vulns > 0 else "ok"
        emit("agent_done", {
            "id": "shodan", "status": status,
            "msg": f"🔴 {nb_vulns} CVE(s) détectée(s)" if nb_vulns else f"✅ {len(host_data)} host(s) analysé(s)"
        })
        return {"source": "Shodan", "status": "ok", "data": host_data, "reliability": 88}

    except Exception as e:
        emit("agent_done", {"id": "shodan", "status": "error", "msg": str(e)[:60]})
        return {"source": "Shodan", "status": "error", "data": str(e)}
