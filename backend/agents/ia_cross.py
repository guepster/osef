"""
Agent IA — Vérification croisée + Synthèse finale Groq LLaMA
"""
import json
from groq import Groq

SUSPECTS_FR = ["fraude","condamné","escroquerie","liquidation","détournement",
               "corruption","garde à vue","mis en examen","faillite",
               "redressement judiciaire","arnaque","abus de confiance","blanchiment",
               "malversation","perquisition","mis en cause","peine","tribunal"]
SUSPECTS_EN = ["fraud","convicted","scam","bankruptcy","corruption","arrested",
               "indicted","money laundering","embezzlement","ponzi","scandal",
               "criminal","investigation","bribery","misconduct","default",
               "lawsuit","charges","guilty","sentenced","probe","scheme"]

SCORE_WEIGHTS = {
    "sanction_hit":      55,
    "bodacc_liquidation": 35,
    "bodacc_redressement": 28,
    "bodacc_radiation":   18,
    "bodacc_other":       12,
    "press_negative":     15,
    "press_critical":     25,
    "company_dissolved":  20,
    "crypto_sanctioned":  50,
}


def agent_verificateur(raw_results, ctx, emit):
    emit("agent_start", {"id": "verificateur", "msg": "Vérification croisée IA des sources..."})
    verified = []
    alerts = []
    score_factors = []
    global_flags = []

    for result in raw_results:
        if result.get("status") not in ["ok", "partial"]:
            continue

        entry = {
            "source": result["source"],
            "reliability": result.get("reliability", 70),
            "data_summary": "",
            "flags": [],
            "raw": result.get("data")
        }

        # ── SIRENE ─────────────────────────────────────────────────────────
        if result["source"] == "Sirene" and result.get("data"):
            companies = result["data"]
            top = result.get("top", companies[0] if companies else {})
            statut = (top.get("etat_administratif") or "?")
            if statut == "F":
                entry["flags"].append("🟡 Entreprise fermée (Sirene)")
                score_factors.append(SCORE_WEIGHTS["company_dissolved"])
            else:
                entry["flags"].append(f"✅ Active — {top.get('nature_juridique_libelle','?')}")
            nb_dir = len(top.get("dirigeants", []) or [])
            if nb_dir:
                entry["flags"].append(f"👤 {nb_dir} dirigeant(s) enregistré(s)")
            adresse = (top.get("siege") or {}).get("adresse", "")
            if adresse:
                entry["flags"].append(f"📍 {adresse[:60]}")
            entry["data_summary"] = json.dumps(top, ensure_ascii=False)[:800]

        # ── PAPPERS ────────────────────────────────────────────────────────
        if result["source"] == "Pappers" and result.get("data"):
            d = result["data"]
            statut = d.get("statut", "?")
            if statut in ["Radiée", "Dissoute", "Fermée"]:
                entry["flags"].append(f"🟡 {statut}")
                score_factors.append(SCORE_WEIGHTS["company_dissolved"])
            else:
                entry["flags"].append(f"✅ Statut: {statut}")
            for dg in d.get("dirigeants", [])[:4]:
                nom = f"{dg.get('prenom','')} {dg.get('nom','')}".strip()
                role = dg.get("titre", "Dirigeant")
                if nom:
                    entry["flags"].append(f"👤 {role}: {nom}")
            for be in d.get("beneficiaires_effectifs", [])[:3]:
                nom = f"{be.get('prenom','')} {be.get('nom','')}".strip()
                pct = be.get("pourcentage_parts", 0)
                if nom:
                    entry["flags"].append(f"💼 Bénéficiaire {pct}%: {nom}")
            capital = d.get("capital")
            if capital:
                entry["flags"].append(f"💰 Capital: {capital:,} €" if isinstance(capital, int) else f"💰 Capital: {capital}")
            entry["data_summary"] = json.dumps(d, ensure_ascii=False)[:800]

        # ── BODACC ─────────────────────────────────────────────────────────
        if result["source"] == "Bodacc":
            records = result.get("data") or []
            critical = result.get("critical") or []
            if records:
                alerts.append(f"BODACC: {len(records)} annonce(s) légale(s) détectée(s)")
                global_flags.append("bodacc_hit")
                for rec in records:
                    type_a = (rec.get("typeavis_lib","") + rec.get("familleavis_lib","")).lower()
                    date = rec.get("dateparution","?")[:10]
                    trib = rec.get("tribunal","?")
                    label = rec.get("typeavis_lib", rec.get("familleavis_lib","Annonce"))
                    entry["flags"].append(f"📋 {date} — {label} ({trib})")
                    if "liquidation" in type_a:
                        score_factors.append(SCORE_WEIGHTS["bodacc_liquidation"])
                        alerts.append(f"CRITIQUE: Liquidation judiciaire détectée ({date})")
                    elif "redressement" in type_a:
                        score_factors.append(SCORE_WEIGHTS["bodacc_redressement"])
                    elif "radiation" in type_a:
                        score_factors.append(SCORE_WEIGHTS["bodacc_radiation"])
                    else:
                        score_factors.append(SCORE_WEIGHTS["bodacc_other"])
            else:
                entry["flags"].append("✅ Aucune procédure collective")

        # ── OPENSANCTIONS ──────────────────────────────────────────────────
        if result["source"] == "OpenSanctions":
            if result.get("hit"):
                hits = result.get("data", [])
                score_factors.append(SCORE_WEIGHTS["sanction_hit"])
                global_flags.append("sanction_hit")
                alerts.append(f"CRITIQUE: Entité présente sur {len(hits)} liste(s) de sanctions")
                for h in hits[:3]:
                    entry["flags"].append(f"🔴 SANCTION: {h.get('caption','?')} ({h.get('schema','?')})")
                    datasets = h.get("datasets", [])
                    if datasets:
                        entry["flags"].append(f"   └─ Listes: {', '.join(datasets[:3])}")
            else:
                entry["flags"].append("✅ Absent des 330 listes de sanctions")

        # ── GOOGLE NEWS ────────────────────────────────────────────────────
        if result["source"] == "Google News":
            articles = result.get("data") or []
            neg_articles = [a for a in articles if a.get("is_negative")]
            if neg_articles:
                score_add = min(40, len(neg_articles) * SCORE_WEIGHTS["press_negative"])
                score_factors.append(score_add)
                global_flags.append("press_negative")
                alerts.append(f"PRESSE: {len(neg_articles)} article(s) négatif(s) détecté(s)")
                for a in neg_articles[:3]:
                    flags_str = ", ".join(a.get("negative_flags", [])[:3])
                    entry["flags"].append(f"🔴 [{a.get('lang','?').upper()}] {a['title'][:70]} [{flags_str}]")
            positive = [a for a in articles if not a.get("is_negative")]
            if positive:
                entry["flags"].append(f"✅ {len(positive)} article(s) neutre(s)/positif(s)")
            entry["data_summary"] = "\n".join([f"• {a['title'][:80]}" for a in articles[:8]])

        # ── WHOIS ──────────────────────────────────────────────────────────
        if result["source"] == "WHOIS/RDAP" and result.get("data"):
            d = result["data"]
            if isinstance(d, dict):
                if d.get("domain"):
                    entry["flags"].append(f"🌐 Domaine: {d['domain']}")
                if d.get("registered"):
                    entry["flags"].append(f"📅 Enregistré: {d['registered'][:10]}")
                if d.get("expiration"):
                    entry["flags"].append(f"📅 Expire: {d['expiration'][:10]}")
                if d.get("nameservers"):
                    entry["flags"].append(f"🖥️ NS: {', '.join(d['nameservers'][:2])}")
                if d.get("ip_info"):
                    ip = d["ip_info"]
                    entry["flags"].append(f"🌍 IP → {ip.get('org','?')} ({ip.get('country_name','?')})")

        # ── CRYPTO ─────────────────────────────────────────────────────────
        if result["source"] == "Crypto Trace" and result.get("data"):
            d = result["data"]
            if d.get("btc"):
                btc = d["btc"]
                entry["flags"].append(f"₿ Balance: {btc['balance_btc']:.6f} BTC")
                entry["flags"].append(f"₿ Total reçu: {btc['total_received_btc']:.6f} BTC ({btc['n_tx']} tx)")
            if d.get("eth"):
                entry["flags"].append(f"Ξ Balance: {d['eth']['balance_eth']:.6f} ETH")
            if d.get("sanctions"):
                score_factors.append(SCORE_WEIGHTS["crypto_sanctioned"])
                global_flags.append("crypto_sanctioned")
                alerts.append("CRITIQUE: Wallet présent sur liste de sanctions")
                entry["flags"].append("🔴 WALLET SANCTIONNÉ")

        # ── PERSON ─────────────────────────────────────────────────────────
        if result["source"] == "Person Search" and result.get("data"):
            d = result["data"]
            companies_linked = d.get("companies_linked", [])
            if companies_linked:
                entry["flags"].append(f"🏢 {len(companies_linked)} entreprise(s) liée(s)")
            bodacc_hits = d.get("bodacc", [])
            if bodacc_hits:
                entry["flags"].append(f"📋 {len(bodacc_hits)} annonce(s) Bodacc liée(s)")
                score_factors.append(SCORE_WEIGHTS["bodacc_other"] * len(bodacc_hits))
            sanctions = d.get("sanctions", [])
            if sanctions:
                entry["flags"].append(f"🔴 {len(sanctions)} sanction(s) internationale(s)")
                score_factors.append(SCORE_WEIGHTS["sanction_hit"])

        verified.append(entry)

    # Score final (plafonné à 100)
    risk_score = min(100, sum(score_factors))

    nb = len(verified)
    emit("agent_done", {
        "id": "verificateur", "status": "done",
        "msg": f"✅ {nb} source(s) croisée(s) — Score brut: {risk_score}/100"
    })

    return verified, alerts, risk_score, global_flags


def agent_synthese_finale(query, verified, alerts, risk_score, flags, ctx, emit):
    emit("agent_start", {"id": "synthese", "msg": "Génération rapport IA — Groq LLaMA 3.3 70B..."})
    groq_key = ctx.get("groq_key", "")
    if not groq_key:
        emit("agent_done", {"id": "synthese", "status": "warn", "msg": "Clé Groq manquante"})
        return "⚠️ Rapport IA indisponible — GROQ_API_KEY manquante."

    try:
        client = Groq(api_key=groq_key)

        sources_summary = json.dumps(
            [{"source": v["source"], "reliability": v["reliability"], "flags": v["flags"]}
             for v in verified],
            ensure_ascii=False, indent=2
        )

        # Système prompt orienté OSINT professionnel
        system = """Tu es un analyste OSINT senior, expert en compliance, due diligence et crime économique (ex-TRACFIN, ex-OCRGDF).
Tu rédiges des rapports professionnels précis, factuels et actionnables pour des clients corporate.
Ton analyse combine les données structurées avec ta connaissance des affaires publiques.
Si la cible est impliquée dans des affaires connues (scandales, fraudes, condamnations), enrichis OBLIGATOIREMENT le rapport.
Langue: Français. Style: rapport d'expert, ton neutre et professionnel."""

        user_prompt = f"""
═══ DOSSIER D'INVESTIGATION ═══
Cible : {query}
Type : {ctx.get('target_type','?')}
Profondeur : {ctx.get('depth','?')}
Infos additionnelles : {ctx.get('extra_info','') or 'Aucune'}
Score de risque calculé : {risk_score}/100
Flags globaux : {', '.join(flags) or 'Aucun'}

═══ DONNÉES VÉRIFIÉES ═══
{sources_summary}

═══ ALERTES AUTOMATIQUES ═══
{json.dumps(alerts, ensure_ascii=False)}

═══ FORMAT RAPPORT REQUIS ═══

## 🎯 Score de Risque Final : {risk_score}/100
**Niveau** : [CRITIQUE > 70 / ÉLEVÉ 50-70 / MODÉRÉ 30-50 / FAIBLE < 30]
**Justification** : [2-3 lignes synthétiques]

## 🔴 Alertes Critiques
[Liste des éléments les plus graves ou RAS]

## 🟡 Signaux Faibles
[Éléments à surveiller ou Aucun]

## ✅ Éléments Positifs / Conformité
[Points rassurants ou Aucun]

## 🔗 Connexions & Réseau
[Relations identifiées entre entités, personnes, adresses]

## 📋 Recommandations
1. [Action immédiate si risque critique]
2. [Vérification complémentaire recommandée]
3. [Niveau de surveillance préconisé]

## ⚠️ Limites de l'Analyse
[Sources non accessibles, données manquantes]
"""

        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user_prompt}
            ],
            max_tokens=2000,
            temperature=0.1
        )
        rapport = response.choices[0].message.content
        emit("agent_done", {"id": "synthese", "status": "ok", "msg": "✅ Rapport généré avec succès"})
        return rapport

    except Exception as e:
        emit("agent_done", {"id": "synthese", "status": "error", "msg": str(e)[:80]})
        return f"Erreur génération rapport: {str(e)}"
