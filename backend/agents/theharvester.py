"""
Agent theHarvester — emails, subdomains, IPs, ASNs
Chemin attendu: backend/theHarvester/.venv/Scripts/theHarvester.exe
Installation:
  git clone https://github.com/laramies/theHarvester
  cd theHarvester && py -3.13 -m uv venv && py -3.13 -m uv sync
  .venv\Scripts\pip install python-dateutil playwright censys shodan pyairtable netaddr ujson aiosqlite fastapi httpx slowapi uvicorn winloop
"""
import subprocess, json, tempfile, os, re

SOURCES = {
    "quick":    "crtsh,hackertarget,rapiddns",
    "standard": "crtsh,hackertarget,rapiddns,urlscan,threatminer",
    "deep":     "crtsh,hackertarget,rapiddns,urlscan,threatminer,otx,anubis,dnsdumpster",
}
TIMEOUT = {"quick": 60, "standard": 120, "deep": 300}


def _find_exe():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "theHarvester", ".venv", "Scripts", "theHarvester.exe"),
        os.path.join(base, "theHarvester", ".venv", "bin", "theHarvester"),
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    import shutil
    return shutil.which("theHarvester")


def agent_theharvester(query, ctx, emit):
    emit("agent_start", {"id": "theharvester", "msg": "theHarvester — scan subdomains, IPs, emails..."})
    try:
        domain = query.replace("https://","").replace("http://","").split("/")[0].strip()
        if not domain or " " in domain or "." not in domain:
            domain = ctx.get("domain", "").strip()
        if not domain:
            emit("agent_done", {"id": "theharvester", "status": "skip", "msg": "Nécessite un domaine valide"})
            return {"source": "theHarvester", "status": "skip", "data": None}

        exe = _find_exe()
        if not exe:
            emit("agent_done", {"id": "theharvester", "status": "skip", "msg": "theHarvester non installé — voir /admin"})
            return {"source": "theHarvester", "status": "not_installed", "data": None,
                    "install": "git clone https://github.com/laramies/theHarvester && cd theHarvester && py -3.13 -m uv venv && py -3.13 -m uv sync"}

        depth   = ctx.get("depth", "standard")
        sources = SOURCES.get(depth, SOURCES["standard"])
        limit   = {"quick": 100, "standard": 300, "deep": 500}.get(depth, 300)

        emit("agent_start", {"id": "theharvester", "msg": f"theHarvester — {domain} [{sources}]..."})

        with tempfile.TemporaryDirectory() as tmpdir:
            out_base = os.path.join(tmpdir, "result")
            cmd = [exe, "-d", domain, "-b", sources, "-l", str(limit), "-f", out_base]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT.get(depth, 120))

            emails, hosts, ips, asns, urls = set(), set(), set(), set(), set()

            # Parser JSON si dispo
            json_path = out_base + ".json"
            if os.path.exists(json_path):
                try:
                    with open(json_path, encoding="utf-8") as f:
                        data = json.load(f)
                    emails = set(data.get("emails", []))
                    hosts  = set(data.get("hosts",  []))
                    ips    = set(data.get("ips",    []))
                    asns   = set(data.get("asns",   []))
                    urls   = set(data.get("urls",   []))
                except Exception:
                    pass

            # Fallback: parser stdout
            if not hosts and not ips:
                section = None
                for line in (result.stdout or "").splitlines():
                    line = line.strip()
                    if not line or line.startswith("*") or line.startswith("-"): continue
                    if "Hosts found"       in line: section = "hosts"
                    elif "IPs found"       in line: section = "ips"
                    elif "emails found"    in line.lower(): section = "emails"
                    elif "ASNS found"      in line: section = "asns"
                    elif "Interesting Urls" in line: section = "urls"
                    elif line.startswith("[") or "Target:" in line or "Searching" in line: section = None
                    elif section == "hosts"  and "." in line: hosts.add(line.split(":")[0])
                    elif section == "ips"    and re.match(r'^\d{1,3}\.\d{1,3}', line): ips.add(line.split(":")[0])
                    elif section == "emails" and "@" in line: emails.add(line)
                    elif section == "asns"   and line.startswith("AS"): asns.add(line)
                    elif section == "urls"   and line.startswith("http"): urls.add(line)

            total = len(emails) + len(hosts) + len(ips)
            if total == 0:
                emit("agent_done", {"id": "theharvester", "status": "warn", "msg": f"⚠️ Aucun résultat pour {domain}"})
                return {"source": "theHarvester", "status": "empty", "data": {"domain": domain, "emails": [], "hosts": [], "ips": [], "asns": [], "urls": []}}

            emit("agent_done", {"id": "theharvester", "status": "ok",
                                "msg": f"✅ {len(hosts)} host(s) · {len(ips)} IP(s) · {len(emails)} email(s) · {len(asns)} ASN(s)"})
            return {
                "source": "theHarvester", "status": "ok",
                "data": {
                    "domain": domain,
                    "emails": sorted(emails)[:50],
                    "hosts":  sorted(hosts)[:150],
                    "ips":    sorted(ips)[:100],
                    "asns":   sorted(asns)[:30],
                    "urls":   sorted(urls)[:20],
                },
                "reliability": 85,
            }

    except FileNotFoundError:
        emit("agent_done", {"id": "theharvester", "status": "skip", "msg": "theHarvester introuvable"})
        return {"source": "theHarvester", "status": "not_installed", "data": None}
    except subprocess.TimeoutExpired:
        emit("agent_done", {"id": "theharvester", "status": "warn", "msg": "Timeout"})
        return {"source": "theHarvester", "status": "timeout", "data": None}
    except Exception as e:
        emit("agent_done", {"id": "theharvester", "status": "error", "msg": str(e)[:80]})
        return {"source": "theHarvester", "status": "error", "data": str(e)}