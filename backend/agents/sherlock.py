"""
Agent Sherlock — recherche username sur 300+ plateformes
Nécessite: pip install sherlock-project
"""
import subprocess, json, re, tempfile, os

KNOWN_PLATFORMS = [
    "Twitter","Instagram","GitHub","LinkedIn","Reddit","TikTok","YouTube",
    "Facebook","Pinterest","Snapchat","Telegram","Discord","Twitch","Medium",
    "HackerNews","ProductHunt","DeviantArt","Flickr","Tumblr","WordPress",
    "Patreon","OnlyFans","Fiverr","Upwork","Behance","Dribbble","Vimeo",
]

def agent_sherlock(query, ctx, emit):
    emit("agent_start", {"id": "sherlock", "msg": f"Sherlock — recherche username '{query}' sur 300+ sites..."})
    try:
        # Nettoyer le username
        username = query.strip().replace(" ", "").replace("@", "")
        if not username or len(username) < 2:
            emit("agent_done", {"id": "sherlock", "status": "skip", "msg": "Username invalide"})
            return {"source": "Sherlock", "status": "skip", "data": None}

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = os.path.join(tmpdir, f"{username}.txt")
            cmd = [
                "sherlock",
                username,
                "--output", out_file,
                "--timeout", "10",
                "--print-found",
            ]

            # Mode deep = plus de timeout par site
            if ctx.get("depth") == "deep":
                cmd = ["sherlock", username, "--output", out_file, "--timeout", "20", "--print-found"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)

            found_profiles = []
            stdout = result.stdout + (open(out_file).read() if os.path.exists(out_file) else "")

            # Parser les résultats
            for line in stdout.splitlines():
                line = line.strip()
                # Format: [+] Platform: https://...
                m = re.match(r'\[\+\]\s+(.+?):\s+(https?://\S+)', line)
                if m:
                    platform = m.group(1).strip()
                    url      = m.group(2).strip()
                    found_profiles.append({"platform": platform, "url": url})
                # Format simple URL
                elif line.startswith("http") and "://" in line:
                    found_profiles.append({"platform": "?", "url": line})

            # Dédoublonner
            seen_urls = set()
            unique_profiles = []
            for p in found_profiles:
                if p["url"] not in seen_urls:
                    seen_urls.add(p["url"])
                    unique_profiles.append(p)

            nb = len(unique_profiles)
            # Classifier par risque (plateformes sensibles)
            sensitive = [p for p in unique_profiles if any(
                s.lower() in p["platform"].lower()
                for s in ["dark","onion","leak","breach","pastebin","4chan","8chan","telegram"]
            )]

            status = "alert" if sensitive else ("ok" if nb > 0 else "warn")
            emit("agent_done", {
                "id": "sherlock", "status": status,
                "msg": f"✅ {nb} profil(s) trouvé(s)" + (f" — {len(sensitive)} plateforme(s) sensible(s)" if sensitive else "")
            })

            return {
                "source": "Sherlock",
                "status": "ok",
                "data": {
                    "username": username,
                    "profiles": unique_profiles[:80],
                    "sensitive": sensitive,
                    "total_found": nb,
                },
                "reliability": 80
            }

    except FileNotFoundError:
        emit("agent_done", {"id": "sherlock", "status": "skip",
                            "msg": "Sherlock non installé — pip install sherlock-project"})
        return {"source": "Sherlock", "status": "not_installed",
                "data": None, "install": "pip install sherlock-project"}
    except subprocess.TimeoutExpired:
        emit("agent_done", {"id": "sherlock", "status": "warn", "msg": "Timeout (180s)"})
        return {"source": "Sherlock", "status": "timeout", "data": None}
    except Exception as e:
        emit("agent_done", {"id": "sherlock", "status": "error", "msg": str(e)[:60]})
        return {"source": "Sherlock", "status": "error", "data": str(e)}
