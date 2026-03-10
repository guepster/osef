"""
Agent Holehe — vérifie si un email est enregistré sur 120+ services
Nécessite: pip install holehe
"""
import subprocess, re, json, sys, os, shutil

def _find_holehe():
    """Cherche holehe dans PATH + dossiers Python Scripts (Windows/Linux)"""
    found = shutil.which("holehe")
    if found:
        return found
    python_dirs = [
        os.path.dirname(sys.executable),
        os.path.join(os.path.dirname(sys.executable), "Scripts"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "Python", "Python313", "Scripts"),
        os.path.join(os.path.expanduser("~"), "AppData", "Local", "Programs", "Python", "Python312", "Scripts"),
        os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Python", "Python313", "Scripts"),
        os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Python", "Python312", "Scripts"),
        "/usr/local/bin", "/usr/bin", os.path.expanduser("~/.local/bin"),
    ]
    for d in python_dirs:
        for name in ["holehe.exe", "holehe"]:
            full = os.path.join(d, name)
            if os.path.exists(full):
                return full
    return None

def agent_holehe(query, ctx, emit):
    emit("agent_start", {"id": "holehe", "msg": f"Holehe — vérification email sur 120+ services..."})
    try:
        # Détecter si c'est un email
        email = query.strip()
        if "@" not in email:
            # Chercher un email dans extra_info
            extra = ctx.get("extra_info", "")
            emails_found = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', extra)
            if emails_found:
                email = emails_found[0]
            else:
                emit("agent_done", {"id": "holehe", "status": "skip",
                                    "msg": "Holehe nécessite un email valide"})
                return {"source": "Holehe", "status": "skip", "data": None}

        cmd = ["holehe", email, "--no-color", "--only-used"]
        holehe_exe = _find_holehe()
        if not holehe_exe:
            raise FileNotFoundError("holehe not found")
        cmd = [holehe_exe, email, "--no-color", "--only-used"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        registered = []
        not_registered = []
        errors = []

        for line in (result.stdout + result.stderr).splitlines():
            line = line.strip()
            # [+] = enregistré
            if line.startswith("[+]") or "✔" in line or "is used" in line.lower():
                service = re.sub(r'[\[\+\]✔]', '', line).strip().split()[0]
                if service:
                    registered.append(service)
            # [-] = non enregistré (on ignore pour garder compact)
            elif line.startswith("[-]") or "✘" in line:
                pass
            # [?] = erreur
            elif line.startswith("[?]"):
                service = re.sub(r'[\[\?\]]', '', line).strip().split()[0]
                if service:
                    errors.append(service)

        nb = len(registered)
        # Services sensibles
        sensitive_services = ["telegram","discord","onlyfans","patreon","ashley","darkweb",
                               "pornhub","xvideos","4chan","leaks","breach"]
        sensitive_found = [s for s in registered if any(ss in s.lower() for ss in sensitive_services)]

        status = "alert" if sensitive_found else ("ok" if nb > 0 else "warn")
        emit("agent_done", {
            "id": "holehe", "status": status,
            "msg": f"✅ {nb} service(s) enregistré(s)" + (f" — dont {len(sensitive_found)} sensible(s)" if sensitive_found else "")
                   if nb > 0 else "⚠️ Email non trouvé ou Holehe non installé"
        })

        return {
            "source": "Holehe",
            "status": "ok",
            "data": {
                "email": email,
                "registered": registered,
                "sensitive": sensitive_found,
                "total": nb,
            },
            "reliability": 82
        }

    except FileNotFoundError:
        emit("agent_done", {"id": "holehe", "status": "skip",
                            "msg": "Holehe non installé — pip install holehe"})
        return {"source": "Holehe", "status": "not_installed",
                "data": None, "install": "pip install holehe"}
    except subprocess.TimeoutExpired:
        emit("agent_done", {"id": "holehe", "status": "warn", "msg": "Timeout (120s)"})
        return {"source": "Holehe", "status": "timeout", "data": None}
    except Exception as e:
        emit("agent_done", {"id": "holehe", "status": "error", "msg": str(e)[:60]})
        return {"source": "Holehe", "status": "error", "data": str(e)}