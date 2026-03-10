"""
Agent RECONDNS — Intégration de guepster/recondns dans NEXUS
DNS recon, subdomains, takeover detection, mail security, risk score
"""
import subprocess, sys, os, json, shutil, tempfile
from pathlib import Path

# Cherche l'exe recondns dans l'ordre :
# 1. venv local backend/recondns/.venv
# 2. PATH système
def _find_recondns():
    base = Path(__file__).parent.parent
    candidates = [
        base / "recondns" / ".venv" / "Scripts" / "recondns.exe",  # Windows
        base / "recondns" / ".venv" / "bin" / "recondns",           # Linux/Mac
    ]
    for c in candidates:
        if c.exists():
            return str(c)
    found = shutil.which("recondns")
    return found  # None si pas installé

def agent_recondns(query: str, depth: str = "standard", push_log=None) -> dict:
    """
    Lance recondns info <domain> et parse la sortie JSON.
    query  : nom de domaine (ex: totalenergies.com)
    depth  : quick | standard | deep
    """
    def log(msg):
        if push_log:
            push_log("info", f"[RECONDNS] {msg}")

    exe = _find_recondns()
    if not exe:
        return {
            "status": "skipped",
            "reason": "recondns non installé — pip install -e . dans le repo",
            "data": {}
        }

    # Construire la commande selon la profondeur
    cmd = [exe, "info", query, "--out", "-"]  # --out - = stdout JSON

    if depth == "quick":
        cmd += ["--minimal", "--no-crt"]
    elif depth == "standard":
        cmd += ["--web-scan"]
    elif depth == "deep":
        cmd += ["--web-scan", "--check-takeover"]

    log(f"Lancement: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120 if depth == "deep" else 60
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        if result.returncode != 0:
            log(f"Erreur returncode={result.returncode}: {stderr[:200]}")
            # Fallback : tenter de parser quand même
            if not stdout:
                return {"status": "error", "reason": stderr[:300], "data": {}}

        # Tenter de parser en JSON
        try:
            data = json.loads(stdout)
            return _parse_recondns_output(data, log)
        except json.JSONDecodeError:
            # recondns a sorti du texte console — on parse manuellement
            return _parse_recondns_text(stdout, query, log)

    except subprocess.TimeoutExpired:
        log("Timeout après 120s")
        return {"status": "timeout", "reason": "recondns trop long", "data": {}}
    except Exception as e:
        log(f"Exception: {e}")
        return {"status": "error", "reason": str(e), "data": {}}


def _parse_recondns_output(data: dict, log) -> dict:
    """Parse la sortie JSON structurée de recondns"""
    subdomains = data.get("subdomains", [])
    dns        = data.get("dns", {})
    mail       = data.get("mail_sec", {})
    risk       = data.get("risk", {})
    takeovers  = data.get("takeover", [])
    ips        = data.get("ips", [])

    log(f"Trouvé {len(subdomains)} sous-domaines, {len(ips)} IPs, score={risk.get('score','?')}")

    alerts = []
    if takeovers:
        alerts.append(f"{len(takeovers)} takeover(s) potentiel(s) détecté(s)")
    if not mail.get("spf"):
        alerts.append("SPF manquant")
    if not mail.get("dmarc"):
        alerts.append("DMARC manquant")

    return {
        "status": "ok",
        "alerts": alerts,
        "data": {
            "subdomains": subdomains[:100],  # max 100 pour le graphe
            "subdomains_count": len(subdomains),
            "dns": dns,
            "mail_security": mail,
            "risk_score": risk.get("score"),
            "risk_level": risk.get("level"),
            "takeovers": takeovers,
            "ips": ips[:50],
            "ips_count": len(ips),
        }
    }


def _parse_recondns_text(text: str, domain: str, log) -> dict:
    """
    Fallback : parse la sortie console texte de recondns
    pour extraire les sous-domaines et infos clés
    """
    lines = text.split("\n")
    subdomains = []
    ips = []
    in_subdomains = False
    spf = None
    dmarc = None
    risk_score = None

    for line in lines:
        stripped = line.strip()

        # Détection sections
        if "SUBDOMAINS" in line.upper():
            in_subdomains = True
            continue
        if in_subdomains and stripped.startswith("[") and "SUBDOMAINS" not in line.upper():
            in_subdomains = False

        # Extraction sous-domaines
        if in_subdomains and domain in stripped:
            sub = stripped.split()[0] if stripped.split() else ""
            if sub and "." in sub:
                subdomains.append(sub)

        # SPF / DMARC
        if "SPF" in line and ":" in line:
            spf = "v=spf1" in line
        if "DMARC" in line and ":" in line:
            dmarc = "v=DMARC1" in line

        # Risk score
        if "RISK SCORE" in line.upper() or "score" in line.lower():
            import re
            m = re.search(r"\b(\d+)\b", line)
            if m:
                risk_score = int(m.group(1))

        # IPs
        import re
        ips_found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ips.extend(ips_found)

    # Dédup
    subdomains = list(dict.fromkeys(subdomains))
    ips = list(dict.fromkeys(ips))

    log(f"Parse texte: {len(subdomains)} sous-domaines, {len(ips)} IPs")

    return {
        "status": "ok",
        "alerts": [],
        "data": {
            "subdomains": subdomains[:100],
            "subdomains_count": len(subdomains),
            "dns": {},
            "mail_security": {"spf": spf, "dmarc": dmarc},
            "risk_score": risk_score,
            "risk_level": None,
            "takeovers": [],
            "ips": ips[:50],
            "ips_count": len(ips),
        }
    }


def build_recondns_nodes(result: dict, query: str) -> list:
    """
    Génère les nœuds Cytoscape pour le graphe NEXUS
    à partir des résultats recondns
    """
    nodes = []
    data = result.get("data", {})

    # Nœuds sous-domaines
    for sub in data.get("subdomains", [])[:50]:
        nodes.append({
            "id": f"sub_{sub}",
            "label": sub,
            "type": "subdomain",
            "source": "recondns"
        })

    # Nœuds IPs
    for ip in data.get("ips", [])[:20]:
        nodes.append({
            "id": f"ip_{ip}",
            "label": ip,
            "type": "ip",
            "source": "recondns"
        })

    # Nœuds takeovers (rouge)
    for tk in data.get("takeovers", []):
        host = tk.get("host", "")
        provider = tk.get("provider", "")
        nodes.append({
            "id": f"takeover_{host}",
            "label": f"⚠ {host}",
            "type": "alert",
            "source": "recondns",
            "detail": f"Takeover potentiel: {provider}"
        })

    return nodes
