"""
Agent SpiderFoot — OSINT automation framework via API REST
Lance SpiderFoot en subprocess ou se connecte à une instance existante
Nécessite: pip install spiderfoot  ou  docker run -p 5001:5001 spiderfoot
"""
import subprocess, requests, time, json, os, threading

SPIDERFOOT_URL = os.environ.get("SPIDERFOOT_URL", "http://localhost:5001")

def agent_spiderfoot(query, ctx, emit):
    emit("agent_start", {"id": "spiderfoot", "msg": "SpiderFoot — OSINT automation framework..."})
    try:
        # 1. Tenter connexion instance existante
        if _check_spiderfoot_running():
            return _run_spiderfoot_scan(query, ctx, emit)

        # 2. Tenter lancement subprocess
        emit("agent_start", {"id": "spiderfoot", "msg": "SpiderFoot — démarrage instance locale..."})
        proc = _start_spiderfoot_subprocess()
        if proc:
            time.sleep(4)  # Attendre démarrage
            if _check_spiderfoot_running():
                result = _run_spiderfoot_scan(query, ctx, emit)
                proc.terminate()
                return result

        emit("agent_done", {"id": "spiderfoot", "status": "skip",
                            "msg": "SpiderFoot non disponible — voir README pour installation"})
        return {
            "source": "SpiderFoot",
            "status": "not_available",
            "data": None,
            "install": "pip install spiderfoot && sf.py -l 127.0.0.1:5001"
        }

    except Exception as e:
        emit("agent_done", {"id": "spiderfoot", "status": "error", "msg": str(e)[:60]})
        return {"source": "SpiderFoot", "status": "error", "data": str(e)}


def _check_spiderfoot_running():
    try:
        r = requests.get(f"{SPIDERFOOT_URL}/api/v1/ping", timeout=3)
        return r.status_code == 200
    except:
        return False


def _start_spiderfoot_subprocess():
    """Cherche sf.py dans les chemins communs (Windows + Linux/Mac)"""
    import sys
    sf_dirs = [
        os.path.join(os.path.expanduser("~"), "spiderfoot"),
        os.path.join(os.path.expanduser("~"), "Documents", "spiderfoot"),
        os.path.join(os.path.dirname(__file__), "..", "..", "spiderfoot"),
        "C:\\spiderfoot",
        "C:\\tools\\spiderfoot",
        "/opt/spiderfoot",
        "/usr/local/spiderfoot",
    ]
    for sf_dir in sf_dirs:
        sf_py = os.path.join(sf_dir, "sf.py")
        if os.path.exists(sf_py):
            try:
                proc = subprocess.Popen(
                    [sys.executable, sf_py, "-l", "127.0.0.1:5001"],
                    cwd=sf_dir,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                return proc
            except Exception:
                continue
    return None


def _run_spiderfoot_scan(query, ctx, emit):
    """Lance un scan SpiderFoot via API REST"""
    depth = ctx.get("depth", "standard")

    # Modules selon profondeur
    modules_quick    = "sfp_bing,sfp_dns,sfp_whois,sfp_crtsh,sfp_hackertarget"
    modules_standard = modules_quick + ",sfp_threatminer,sfp_urlscan,sfp_passivedns,sfp_emailrep"
    modules_deep     = modules_standard + ",sfp_shodan,sfp_virustotal,sfp_spyse,sfp_leakix"
    modules = {"quick": modules_quick, "standard": modules_standard, "deep": modules_deep}.get(depth, modules_standard)

    try:
        # Créer le scan
        r = requests.post(f"{SPIDERFOOT_URL}/api/v1/startscan", json={
            "scanname": f"nexus-{query[:20]}",
            "scantarget": query,
            "modulelist": modules,
            "typelist": "",
        }, timeout=10)

        if r.status_code != 200:
            return {"source": "SpiderFoot", "status": "error", "data": f"HTTP {r.status_code}"}

        scan_id = r.json().get("id", "")
        if not scan_id:
            return {"source": "SpiderFoot", "status": "error", "data": "Scan ID manquant"}

        emit("agent_start", {"id": "spiderfoot", "msg": f"SpiderFoot scan {scan_id[:8]}... en cours"})

        # Polling jusqu'à completion
        max_wait = {"quick": 60, "standard": 180, "deep": 480}.get(depth, 180)
        start = time.time()

        while time.time() - start < max_wait:
            time.sleep(8)
            status_r = requests.get(f"{SPIDERFOOT_URL}/api/v1/scanstatus/{scan_id}", timeout=5)
            if status_r.status_code == 200:
                status_data = status_r.json()
                scan_status = status_data.get("status", "")
                if scan_status in ["FINISHED", "ERROR-FAILED", "ABORTED"]:
                    break

        # Récupérer les résultats
        results_r = requests.get(f"{SPIDERFOOT_URL}/api/v1/scaneventresults/{scan_id}/MALICIOUS_IPADDR,MALICIOUS_INTERNET_NAME,EMAILADDR,INTERNET_NAME,IP_ADDRESS,PHONE_NUMBER,USERNAME,SOCIAL_MEDIA", timeout=15)

        findings = {}
        if results_r.status_code == 200:
            for item in results_r.json():
                etype = item.get("type", "OTHER")
                if etype not in findings:
                    findings[etype] = []
                findings[etype].append(item.get("data", ""))

        # Compter les éléments critiques
        malicious = len(findings.get("MALICIOUS_IPADDR", [])) + len(findings.get("MALICIOUS_INTERNET_NAME", []))
        total = sum(len(v) for v in findings.values())

        status = "alert" if malicious > 0 else "ok"
        emit("agent_done", {
            "id": "spiderfoot", "status": status,
            "msg": f"🔴 {malicious} élément(s) malveillant(s) — {total} données collectées" if malicious
                   else f"✅ {total} données collectées"
        })

        return {
            "source": "SpiderFoot",
            "status": "ok",
            "data": {
                "scan_id": scan_id,
                "findings": {k: v[:10] for k, v in findings.items()},
                "malicious_count": malicious,
                "total": total,
            },
            "reliability": 88
        }

    except Exception as e:
        return {"source": "SpiderFoot", "status": "error", "data": str(e)}
