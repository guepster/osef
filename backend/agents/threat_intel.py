"""
Agent ThreatIntel — VirusTotal (gratuit) + AbuseIPDB (gratuit) + crt.sh (gratuit)
Analyse de réputation : malware, IP abusives, certificats SSL
"""
import requests, re, json

TIMEOUT = 10
HEADERS = {"User-Agent": "OSEF-OSINT/2.0", "Accept": "application/json"}


# ── CRT.SH — Certificats SSL (100% gratuit, sans clé) ───────────────────────

def _crtsh(domain):
    """Énumération de subdomains via Certificate Transparency logs"""
    try:
        r = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            headers=HEADERS, timeout=TIMEOUT
        )
        if r.status_code == 200:
            certs = r.json()
            subdomains = set()
            cert_list = []
            for cert in certs[:200]:
                name = cert.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub and domain in sub:
                        subdomains.add(sub)
                if len(cert_list) < 20:
                    cert_list.append({
                        "id": cert.get("id"),
                        "name": cert.get("name_value", "")[:80],
                        "issuer": cert.get("issuer_name", "")[:60],
                        "not_before": cert.get("not_before", "")[:10],
                        "not_after": cert.get("not_after", "")[:10],
                    })
            return list(subdomains), cert_list
    except:
        pass
    return [], []


# ── VIRUSTOTAL — Gratuit (4 requêtes/min sans clé) ─────────────────────────

def _virustotal_domain(domain, api_key=""):
    """Check domaine sur VirusTotal"""
    try:
        headers = {**HEADERS}
        if api_key:
            headers["x-apikey"] = api_key
        else:
            # API publique v2 (deprecated mais encore fonctionnelle)
            r = requests.get(
                "https://www.virustotal.com/vtapi/v2/url/report",
                params={"resource": f"http://{domain}", "apikey": "public"},
                headers=HEADERS, timeout=TIMEOUT
            )
            if r.status_code == 200:
                d = r.json()
                positives = d.get("positives", 0)
                total = d.get("total", 0)
                return {
                    "positives": positives,
                    "total": total,
                    "scan_date": d.get("scan_date", ""),
                    "permalink": d.get("permalink", ""),
                    "malicious": positives > 2
                }
            return None

        # API v3 avec clé
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers=headers, timeout=TIMEOUT
        )
        if r.status_code == 200:
            attrs = r.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "positives": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values()),
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
                "malicious": stats.get("malicious", 0) > 0,
            }
    except:
        pass
    return None


# ── ABUSEIPDB — Gratuit (1000 req/jour avec clé gratuite) ───────────────────

def _abuseipdb(ip, api_key=""):
    """Check IP sur AbuseIPDB"""
    try:
        if not api_key:
            return None
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={**HEADERS, "Key": api_key},
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            d = r.json().get("data", {})
            return {
                "ip": ip,
                "score": d.get("abuseConfidenceScore", 0),
                "country": d.get("countryCode", ""),
                "reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt", ""),
                "is_malicious": d.get("abuseConfidenceScore", 0) > 25,
                "usage_type": d.get("usageType", ""),
                "isp": d.get("isp", ""),
            }
    except:
        pass
    return None


# ── AGENT PRINCIPAL ──────────────────────────────────────────────────────────

def agent_threat_intel(query, ctx, emit):
    emit("agent_start", {"id": "threat_intel", "msg": "ThreatIntel — VirusTotal + crt.sh + AbuseIPDB..."})
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
        if not domain or " " in domain or "." not in domain:
            domain = ctx.get("domain", "")
        if not domain:
            domain = _guess_domain(query)

        vt_key = ctx.get("virustotal_key", "")
        abuse_key = ctx.get("abuseipdb_key", "")

        results = {}
        alerts = []

        # 1. crt.sh — Subdomains via SSL certs (toujours dispo)
        if domain:
            subdomains, certs = _crtsh(domain)
            results["crtsh"] = {
                "subdomains": subdomains[:50],
                "subdomains_count": len(subdomains),
                "certs": certs[:10],
            }
            if len(subdomains) > 20:
                alerts.append(f"{len(subdomains)} sous-domaines détectés via SSL")

        # 2. VirusTotal
        if domain:
            vt = _virustotal_domain(domain, vt_key)
            if vt:
                results["virustotal"] = vt
                if vt.get("malicious"):
                    alerts.append(f"CRITIQUE: Domaine signalé malveillant sur VirusTotal ({vt.get('positives',0)} détections)")

        # 3. AbuseIPDB (si clé dispo)
        if abuse_key and ctx.get("ips_from_whois"):
            for ip in ctx.get("ips_from_whois", [])[:3]:
                abuse = _abuseipdb(ip, abuse_key)
                if abuse:
                    if "abuseipdb" not in results:
                        results["abuseipdb"] = []
                    results["abuseipdb"].append(abuse)
                    if abuse.get("is_malicious"):
                        alerts.append(f"IP {ip} signalée malveillante (score: {abuse['score']}/100)")

        nb_subs = len(results.get("crtsh", {}).get("subdomains", []))
        vt_malicious = results.get("virustotal", {}).get("malicious", False)

        status = "alert" if vt_malicious or any("CRITIQUE" in a for a in alerts) else "ok"
        msg = f"🔴 {len(alerts)} alerte(s) ThreatIntel" if alerts else \
              f"✅ {nb_subs} sous-domaines SSL — aucune menace détectée"

        emit("agent_done", {"id": "threat_intel", "status": status, "msg": msg})

        return {
            "source": "ThreatIntel",
            "status": "ok",
            "data": results,
            "alerts": alerts,
            "reliability": 90
        }

    except Exception as e:
        emit("agent_done", {"id": "threat_intel", "status": "error", "msg": str(e)[:60]})
        return {"source": "ThreatIntel", "status": "error", "data": str(e)}


def _guess_domain(company_name):
    name = company_name.lower().strip()
    name = re.sub(r'\b(sa|sas|sarl|srl|gmbh|ltd|inc|corp|group|groupe|france|fr)\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)
    return f"{name}.fr" if len(name) > 3 else None
