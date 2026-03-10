"""
Agent Google Dorks — Recherches avancées automatisées (100% gratuit)
Utilise Google News RSS + DuckDuckGo HTML pour les dorks sensibles
"""
import requests, re, urllib.parse, time

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122"}

# Dorks organisés par catégorie
DORK_TEMPLATES = {
    "leaks": [
        '"{query}" filetype:pdf confidential',
        '"{query}" filetype:xls OR filetype:xlsx password',
        '"{query}" intext:"internal use only"',
        '"{query}" filetype:doc OR filetype:docx "ne pas diffuser"',
    ],
    "credentials": [
        '"{query}" intext:password intext:username',
        '"{query}" intext:"api_key" OR intext:"api key"',
        '"{query}" site:pastebin.com OR site:paste.ee',
        '"{query}" intext:login intext:mot de passe',
    ],
    "infrastructure": [
        'site:{domain} inurl:admin OR inurl:login OR inurl:wp-admin',
        'site:{domain} filetype:env OR filetype:log OR filetype:sql',
        'site:{domain} inurl:test OR inurl:dev OR inurl:staging',
        'site:{domain} intitle:"index of"',
    ],
    "social": [
        '"{query}" site:linkedin.com',
        '"{query}" site:twitter.com OR site:x.com',
        '"{query}" site:github.com',
        '"{query}" site:glassdoor.com',
    ],
    "judicial": [
        '"{query}" inurl:tribunal OR inurl:justice',
        '"{query}" "arrêt" OR "jugement" OR "condamné" site:legifrance.gouv.fr',
        '"{query}" "mise en examen" OR "garde à vue"',
    ],
    "financial": [
        '"{query}" "résultats financiers" OR "chiffre d\'affaires" filetype:pdf',
        '"{query}" site:bfmtv.com OR site:lesechos.fr OR site:lefigaro.fr',
        '"{query}" "levée de fonds" OR "investissement" OR "rachat"',
    ],
}


def _ddg_search(query, max_results=5):
    """DuckDuckGo HTML scraping (gratuit, pas d'API)"""
    try:
        encoded = urllib.parse.quote(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}"
        r = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code != 200:
            return []

        # Parser les résultats
        results = []
        # Extraire les titres et URLs
        title_pattern = r'class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)</a>'
        snippet_pattern = r'class="result__snippet"[^>]*>([^<]+)'

        titles_urls = re.findall(title_pattern, r.text)
        snippets = re.findall(snippet_pattern, r.text)

        for i, (url_raw, title) in enumerate(titles_urls[:max_results]):
            # Décoder l'URL DuckDuckGo redirect
            url_clean = urllib.parse.unquote(url_raw)
            if url_clean.startswith("//duckduckgo.com/l/?uddg="):
                url_clean = urllib.parse.unquote(url_clean.split("uddg=")[1].split("&")[0])

            results.append({
                "title": title.strip(),
                "url": url_clean,
                "snippet": snippets[i].strip() if i < len(snippets) else "",
            })

        return results
    except:
        return []


def agent_dorks(query, ctx, emit):
    emit("agent_start", {"id": "dorks", "msg": "Google Dorks — recherche avancée automatisée..."})
    try:
        depth = ctx.get("depth", "standard")
        domain = ctx.get("domain", "") or _guess_domain(query)
        target_type = ctx.get("target_type", "entreprise")

        # Sélectionner les catégories selon profondeur
        if depth == "quick":
            categories = ["social", "judicial"]
        elif depth == "standard":
            categories = ["leaks", "social", "judicial", "financial"]
        else:  # deep
            categories = list(DORK_TEMPLATES.keys())

        all_findings = {}
        critical_findings = []

        for category in categories:
            templates = DORK_TEMPLATES.get(category, [])
            category_results = []

            for template in templates[:2]:  # Max 2 dorks par catégorie pour éviter le rate limit
                dork = template.format(query=query, domain=domain or query.lower().replace(" ", ""))
                results = _ddg_search(dork, max_results=3)

                if results:
                    for r in results:
                        r["dork"] = dork
                        r["category"] = category
                        category_results.append(r)

                        # Signaux critiques
                        if category in ["leaks", "credentials"]:
                            critical_findings.append(r)

                time.sleep(0.5)  # Rate limiting poli

            if category_results:
                all_findings[category] = category_results

        total = sum(len(v) for v in all_findings.values())
        nb_critical = len(critical_findings)

        status = "alert" if nb_critical > 0 else ("ok" if total > 0 else "warn")
        msg = f"🔴 {nb_critical} résultat(s) sensible(s) trouvé(s)" if nb_critical > 0 \
              else f"✅ {total} résultat(s) — aucun critique"

        emit("agent_done", {"id": "dorks", "status": status, "msg": msg})

        return {
            "source": "Google Dorks",
            "status": "ok",
            "data": {
                "query": query,
                "domain": domain,
                "findings": all_findings,
                "critical": critical_findings[:10],
                "total": total,
            },
            "reliability": 70
        }

    except Exception as e:
        emit("agent_done", {"id": "dorks", "status": "error", "msg": str(e)[:60]})
        return {"source": "Google Dorks", "status": "error", "data": str(e)}


def _guess_domain(company_name):
    name = company_name.lower().strip()
    name = re.sub(r'\b(sa|sas|sarl|srl|gmbh|ltd|inc|corp|group|groupe|france|fr)\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)
    return f"{name}.fr" if len(name) > 3 else None
