"""
Agent HIBP — Have I Been Pwned (gratuit, sans clé pour domaines)
Vérifie si un domaine ou email a été compromis dans des fuites de données
"""
import requests, re

TIMEOUT = 10
HEADERS = {"User-Agent": "OSEF-OSINT/2.0", "Accept": "application/json"}

def agent_hibp(query, ctx, emit):
    emit("agent_start", {"id": "hibp", "msg": "Have I Been Pwned — scan fuites de données..."})
    try:
        results = {}

        # Détecter email vs domaine
        email = None
        domain = None

        if "@" in query:
            email = query.strip()
            domain = email.split("@")[1]
        else:
            # Chercher email dans extra_info
            extra = ctx.get("extra_info", "")
            emails_found = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', extra)
            if emails_found:
                email = emails_found[0]
                domain = email.split("@")[1]
            else:
                # Traiter comme domaine
                domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
                if " " in domain or "." not in domain:
                    domain = None

        breaches = []
        pastes = []
        domain_breaches = []

        # 1. Check domaine sur HIBP (sans clé, endpoint public)
        if domain:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}",
                headers={**HEADERS, "hibp-api-key": ctx.get("hibp_key", "")},
                timeout=TIMEOUT
            )
            if r.status_code == 200:
                domain_breaches = r.json()
            elif r.status_code == 404:
                domain_breaches = []

        # 2. Fallback — API publique non-authentifiée (breaches seulement)
        if not domain_breaches and domain:
            r2 = requests.get(
                f"https://haveibeenpwned.com/api/v3/breaches",
                headers=HEADERS, timeout=TIMEOUT
            )
            if r2.status_code == 200:
                all_breaches = r2.json()
                # Filtrer par domaine
                domain_breaches = [
                    b for b in all_breaches
                    if domain.lower() in b.get("Domain", "").lower()
                    or domain.lower() in b.get("Name", "").lower()
                ]

        # 3. Check BreachDirectory API (gratuit, email)
        if email:
            r3 = requests.get(
                f"https://breachdirectory.p.rapidapi.com/",
                params={"func": "auto", "term": email},
                headers={**HEADERS,
                         "x-rapidapi-host": "breachdirectory.p.rapidapi.com",
                         "x-rapidapi-key": ctx.get("rapidapi_key", "free")},
                timeout=TIMEOUT
            )
            if r3.status_code == 200:
                bd = r3.json()
                if bd.get("found"):
                    pastes = bd.get("result", [])[:10]

        # Analyser les breaches
        critical_data_classes = ["Passwords", "Credit cards", "Social security numbers",
                                  "Bank account numbers", "Private messages", "Health records"]

        critical_breaches = []
        for b in domain_breaches[:20]:
            data_classes = b.get("DataClasses", [])
            is_critical = any(dc in critical_data_classes for dc in data_classes)
            breach_info = {
                "name": b.get("Name", "?"),
                "date": b.get("BreachDate", "?"),
                "pwn_count": b.get("PwnCount", 0),
                "data_classes": data_classes[:5],
                "is_verified": b.get("IsVerified", False),
                "is_critical": is_critical,
            }
            if is_critical:
                critical_breaches.append(breach_info)
            breaches.append(breach_info)

        nb_breaches = len(breaches)
        nb_critical = len(critical_breaches)
        nb_pastes = len(pastes)

        status = "alert" if nb_critical > 0 or nb_pastes > 0 else ("warn" if nb_breaches > 0 else "ok")

        msg = f"🔴 {nb_breaches} breach(es) — {nb_critical} critique(s)" if nb_breaches > 0 \
              else "✅ Aucune fuite détectée"
        if nb_pastes > 0:
            msg += f" — {nb_pastes} paste(s)"

        emit("agent_done", {"id": "hibp", "status": status, "msg": msg})

        return {
            "source": "HaveIBeenPwned",
            "status": "ok",
            "data": {
                "domain": domain,
                "email": email,
                "breaches": breaches,
                "critical_breaches": critical_breaches,
                "pastes": pastes,
                "total_breaches": nb_breaches,
                "total_critical": nb_critical,
            },
            "hit": nb_breaches > 0 or nb_pastes > 0,
            "reliability": 95
        }

    except Exception as e:
        emit("agent_done", {"id": "hibp", "status": "error", "msg": str(e)[:60]})
        return {"source": "HaveIBeenPwned", "status": "error", "data": str(e)}
