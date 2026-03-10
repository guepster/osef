"""
Tool Manager — détecte les outils installés, vérifie les clés API, gère les statuts
"""
import subprocess, os, requests, shutil, json
from datetime import datetime

TIMEOUT = 8

def check_all_tools():
    """Vérifie tous les outils et clés disponibles"""
    return {
        "cli_tools":  _check_cli_tools(),
        "api_keys":   _check_api_keys(),
        "agents":     _check_agents(),
        "checked_at": datetime.now().isoformat(),
    }


def _check_cli_tools():
    tools = {
        "theharvester": {
            "cmd": ["theHarvester", "--version"],
            "install": "pip install theHarvester",
            "desc": "Emails, subdomains, IPs",
            "type": "domain"
        },
        "sherlock": {
            "cmd": ["sherlock", "--version"],
            "install": "pip install sherlock-project",
            "desc": "Username search 300+ sites",
            "type": "personne"
        },
        "holehe": {
            "cmd": ["holehe", "--help"],
            "install": "pip install holehe",
            "desc": "Email → 120+ réseaux sociaux",
            "type": "personne"
        },
        "spiderfoot": {
            "cmd": ["__sf_check__"],   # handled specially below
            "install": "git clone https://github.com/smicallef/spiderfoot ~/spiderfoot && py -3.11 -m pip install -r ~/spiderfoot/requirements.txt",
            "desc": "OSINT automation framework",
            "type": "all"
        },
        "nmap": {
            "cmd": ["nmap", "--version"],
            "install": "https://nmap.org/download",
            "desc": "Network scanner",
            "type": "domaine"
        },
        "exiftool": {
            "cmd": ["exiftool", "-ver"],
            "install": "https://exiftool.org",
            "desc": "Metadata extractor",
            "type": "all"
        },
        "whois": {
            "cmd": ["whois", "--version"],
            "install": "apt install whois",
            "desc": "WHOIS lookup",
            "type": "domaine"
        },
        "dnsrecon": {
            "cmd": ["dnsrecon", "--help"],
            "install": "pip install dnsrecon",
            "desc": "DNS reconnaissance",
            "type": "domaine"
        },
        "wafw00f": {
            "cmd": ["wafw00f", "--help"],
            "install": "pip install wafw00f",
            "desc": "WAF detection",
            "type": "domaine"
        },
        "sublist3r": {
            "cmd": ["python3", "-c", "import sublist3r"],
            "install": "pip install sublist3r",
            "desc": "Subdomain enumeration",
            "type": "domaine"
        },
    }

    results = {}
    for name, info in tools.items():
        try:
            r = subprocess.run(
                info["cmd"], capture_output=True, text=True, timeout=5
            )
            installed = r.returncode in [0, 1, 2]  # Certains tools retournent 1 pour --help
            results[name] = {
                "installed": installed,
                "install": info["install"],
                "desc": info["desc"],
                "type": info["type"],
                "version": _extract_version(r.stdout + r.stderr) if installed else None,
            }
        except (FileNotFoundError, subprocess.TimeoutExpired):
            results[name] = {
                "installed": False,
                "install": info["install"],
                "desc": info["desc"],
                "type": info["type"],
                "version": None,
            }
        except Exception:
            results[name] = {"installed": False, "install": info["install"], "desc": info["desc"], "type": info["type"]}

    return results


def _check_api_keys():
    keys = {}

    # GROQ
    key = os.environ.get("GROQ_API_KEY", "")
    if key:
        try:
            r = requests.get("https://api.groq.com/openai/v1/models",
                             headers={"Authorization": f"Bearer {key}"}, timeout=TIMEOUT)
            keys["groq"] = {"set": True, "valid": r.status_code == 200, "label": "Groq LLaMA", "required": True}
        except:
            keys["groq"] = {"set": True, "valid": False, "label": "Groq LLaMA", "required": True}
    else:
        keys["groq"] = {"set": False, "valid": False, "label": "Groq LLaMA", "required": True}

    # PAPPERS
    key = os.environ.get("PAPPERS_API_KEY", "")
    if key:
        try:
            r = requests.get("https://api.pappers.fr/v2/entreprise",
                             params={"api_token": key, "siren": "542051180"}, timeout=TIMEOUT)
            keys["pappers"] = {"set": True, "valid": r.status_code == 200, "label": "Pappers", "required": False}
        except:
            keys["pappers"] = {"set": True, "valid": False, "label": "Pappers", "required": False}
    else:
        keys["pappers"] = {"set": False, "valid": False, "label": "Pappers", "required": False}

    # OPENSANCTIONS
    key = os.environ.get("OPENSANCTIONS_API_KEY", "")
    if key:
        try:
            r = requests.get("https://api.opensanctions.org/search/default",
                             params={"q": "test", "limit": 1},
                             headers={"Authorization": f"ApiKey {key}"}, timeout=TIMEOUT)
            keys["opensanctions"] = {"set": True, "valid": r.status_code == 200, "label": "OpenSanctions", "required": False}
        except:
            keys["opensanctions"] = {"set": True, "valid": False, "label": "OpenSanctions", "required": False}
    else:
        keys["opensanctions"] = {"set": False, "valid": False, "label": "OpenSanctions", "required": False}

    # SHODAN
    key = os.environ.get("SHODAN_API_KEY", "")
    if key:
        try:
            r = requests.get(f"https://api.shodan.io/api-info",
                             params={"key": key}, timeout=TIMEOUT)
            data = r.json() if r.status_code == 200 else {}
            keys["shodan"] = {
                "set": True, "valid": r.status_code == 200,
                "label": "Shodan",
                "required": False,
                "credits": data.get("query_credits", "?")
            }
        except:
            keys["shodan"] = {"set": True, "valid": False, "label": "Shodan", "required": False}
    else:
        keys["shodan"] = {"set": False, "valid": False, "label": "Shodan", "required": False}

    # SPIDERFOOT URL
    sf_url = os.environ.get("SPIDERFOOT_URL", "http://localhost:5001")
    try:
        r = requests.get(f"{sf_url}/api/v1/ping", timeout=3)
        keys["spiderfoot"] = {"set": True, "valid": r.status_code == 200, "label": "SpiderFoot", "required": False, "url": sf_url}
    except:
        keys["spiderfoot"] = {"set": bool(os.environ.get("SPIDERFOOT_URL")), "valid": False, "label": "SpiderFoot", "required": False, "url": sf_url}

    return keys


def _check_agents():
    """Liste les agents Python disponibles"""
    agents_dir = os.path.join(os.path.dirname(__file__))
    agents = {}
    for f in os.listdir(agents_dir):
        if f.endswith(".py") and not f.startswith("_") and f != "tool_manager.py":
            name = f[:-3]
            agents[name] = {"available": True, "file": f}
    return agents


def test_agent(agent_name, test_query="TotalEnergies"):
    """Teste un agent avec une requête de test"""
    results = {"agent": agent_name, "query": test_query, "ok": False, "data": None, "error": None}
    try:
        ctx = {
            "query": test_query, "depth": "quick",
            "target_type": "entreprise", "siren": "", "domain": "",
            "country": "FR", "extra_info": "", "crypto_addr": "",
            "pappers_key": os.environ.get("PAPPERS_API_KEY",""),
            "opensanctions_key": os.environ.get("OPENSANCTIONS_API_KEY",""),
            "shodan_key": os.environ.get("SHODAN_API_KEY",""),
            "groq_key": os.environ.get("GROQ_API_KEY",""),
        }
        logs = []
        def test_emit(t, d): logs.append({"type": t, "data": d})

        if agent_name == "sirene":
            from agents.entreprise import agent_sirene
            r = agent_sirene(test_query, ctx, test_emit)
        elif agent_name == "bodacc":
            from agents.entreprise import agent_bodacc
            r = agent_bodacc(test_query, ctx, test_emit)
        elif agent_name == "pappers":
            from agents.entreprise import agent_pappers
            r = agent_pappers(test_query, ctx, test_emit)
        elif agent_name == "opensanctions":
            from agents.sanctions import agent_opensanctions
            r = agent_opensanctions(test_query, ctx, test_emit)
        elif agent_name == "news":
            from agents.presse import agent_news
            r = agent_news(test_query, ctx, test_emit)
        elif agent_name == "whois":
            from agents.infra import agent_whois
            r = agent_whois("google.com", ctx, test_emit)
        elif agent_name == "theharvester":
            from agents.theharvester import agent_theharvester
            r = agent_theharvester("google.com", ctx, test_emit)
        elif agent_name == "sherlock":
            from agents.sherlock import agent_sherlock
            r = agent_sherlock("johndoe", ctx, test_emit)
        elif agent_name == "holehe":
            from agents.holehe import agent_holehe
            r = agent_holehe("test@example.com", ctx, test_emit)
        else:
            return {"agent": agent_name, "ok": False, "error": "Agent inconnu"}

        results["ok"] = r.get("status") not in ["error"]
        results["status"] = r.get("status")
        results["data_preview"] = str(r.get("data"))[:200] if r.get("data") else None
        results["logs"] = logs[-3:]
    except Exception as e:
        results["error"] = str(e)
    return results


def _extract_version(text):
    m = re.search(r'(\d+\.\d+[\.\d]*)', text) if text else None
    return m.group(1) if m else None


# Import manquant
import re
