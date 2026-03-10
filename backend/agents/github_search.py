"""
Agent GitHub Search — Recherche de leaks, code, mentions sur GitHub (gratuit)
Détecte: credentials leakés, code source exposé, mentions de l'entité
"""
import requests, re

TIMEOUT = 10
HEADERS = {
    "User-Agent": "OSEF-OSINT/2.0",
    "Accept": "application/vnd.github.v3+json"
}

SENSITIVE_KEYWORDS = [
    "password", "passwd", "secret", "api_key", "apikey", "token",
    "credentials", "private_key", "access_key", "mot de passe",
    "connection_string", "database_url", "db_password"
]

def agent_github(query, ctx, emit):
    emit("agent_start", {"id": "github", "msg": "GitHub — scan leaks, code & mentions..."})
    try:
        headers = {**HEADERS}
        if ctx.get("github_token"):
            headers["Authorization"] = f"token {ctx['github_token']}"

        domain = ctx.get("domain", "") or _guess_domain(query)
        results = {}

        # 1. Recherche de code avec credentials
        sensitive_findings = []
        for keyword in SENSITIVE_KEYWORDS[:4]:
            search_q = f'"{query}" {keyword}'
            r = requests.get(
                "https://api.github.com/search/code",
                params={"q": search_q, "per_page": 5},
                headers=headers, timeout=TIMEOUT
            )
            if r.status_code == 200:
                items = r.json().get("items", [])
                for item in items[:3]:
                    sensitive_findings.append({
                        "file": item.get("name", ""),
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "url": item.get("html_url", ""),
                        "keyword": keyword,
                    })
            elif r.status_code == 403:
                # Rate limit sans token
                break

        # 2. Recherche de repos mentionnant l'entité
        r2 = requests.get(
            "https://api.github.com/search/repositories",
            params={"q": query, "sort": "updated", "per_page": 10},
            headers=headers, timeout=TIMEOUT
        )
        repos = []
        if r2.status_code == 200:
            for repo in r2.json().get("items", [])[:8]:
                repos.append({
                    "name": repo.get("full_name", ""),
                    "description": repo.get("description", ""),
                    "url": repo.get("html_url", ""),
                    "stars": repo.get("stargazers_count", 0),
                    "updated": repo.get("updated_at", "")[:10],
                    "language": repo.get("language", ""),
                    "is_fork": repo.get("fork", False),
                })

        # 3. Recherche dans les issues/commits (mentions)
        r3 = requests.get(
            "https://api.github.com/search/commits",
            params={"q": query, "per_page": 5},
            headers={**headers, "Accept": "application/vnd.github.cloak-preview"},
            timeout=TIMEOUT
        )
        commits = []
        if r3.status_code == 200:
            for commit in r3.json().get("items", [])[:5]:
                commits.append({
                    "message": commit.get("commit", {}).get("message", "")[:100],
                    "repo": commit.get("repository", {}).get("full_name", ""),
                    "url": commit.get("html_url", ""),
                    "date": commit.get("commit", {}).get("author", {}).get("date", "")[:10],
                })

        # 4. Si domaine dispo — chercher des configs exposées
        domain_findings = []
        if domain:
            r4 = requests.get(
                "https://api.github.com/search/code",
                params={"q": f'"{domain}" extension:env OR extension:config OR extension:yml', "per_page": 5},
                headers=headers, timeout=TIMEOUT
            )
            if r4.status_code == 200:
                for item in r4.json().get("items", [])[:5]:
                    domain_findings.append({
                        "file": item.get("name", ""),
                        "repo": item.get("repository", {}).get("full_name", ""),
                        "url": item.get("html_url", ""),
                    })

        nb_sensitive = len(sensitive_findings)
        nb_repos = len(repos)
        nb_domain = len(domain_findings)

        status = "alert" if nb_sensitive > 0 or nb_domain > 0 else "ok"
        msg = f"🔴 {nb_sensitive} fichier(s) sensible(s) trouvé(s)" if nb_sensitive > 0 \
              else f"✅ {nb_repos} repo(s) — aucun credential exposé"
        if nb_domain > 0:
            msg += f" — {nb_domain} config(s) exposée(s)"

        emit("agent_done", {"id": "github", "status": status, "msg": msg})

        return {
            "source": "GitHub",
            "status": "ok",
            "data": {
                "sensitive_findings": sensitive_findings[:10],
                "repos": repos,
                "commits": commits,
                "domain_findings": domain_findings,
                "total_sensitive": nb_sensitive,
            },
            "reliability": 82
        }

    except Exception as e:
        emit("agent_done", {"id": "github", "status": "error", "msg": str(e)[:60]})
        return {"source": "GitHub", "status": "error", "data": str(e)}


def _guess_domain(company_name):
    name = company_name.lower().strip()
    name = re.sub(r'\b(sa|sas|sarl|srl|gmbh|ltd|inc|corp|group|groupe|france|fr)\b', '', name)
    name = re.sub(r'[^a-z0-9]', '', name)
    return f"{name}.fr" if len(name) > 3 else None
