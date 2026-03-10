"""
Graph Builder — Construit le graphe relationnel pour Cytoscape.js
Nœuds typés + edges enrichis + clustering + métadonnées
"""
import json, re
from datetime import datetime

NODE_TYPES = {
    "company_main":    {"color": "#00ff88", "shape": "ellipse",   "size": 80, "icon": "🏢"},
    "company":         {"color": "#00d4ff", "shape": "ellipse",   "size": 55, "icon": "🏢"},
    "person":          {"color": "#a78bfa", "shape": "roundrect", "size": 50, "icon": "👤"},
    "person_be":       {"color": "#f59e0b", "shape": "roundrect", "size": 45, "icon": "💼"},
    "address":         {"color": "#6b7280", "shape": "round-tag", "size": 35, "icon": "📍"},
    "domain":          {"color": "#06b6d4", "shape": "diamond",   "size": 45, "icon": "🌐"},
    "sanction":        {"color": "#ef4444", "shape": "star",      "size": 60, "icon": "⚠️"},
    "legal_alert":     {"color": "#f97316", "shape": "triangle",  "size": 55, "icon": "📋"},
    "news_negative":   {"color": "#dc2626", "shape": "octagon",   "size": 40, "icon": "📰"},
    "news_neutral":    {"color": "#4b5563", "shape": "octagon",   "size": 30, "icon": "📰"},
    "crypto_wallet":   {"color": "#f59e0b", "shape": "hexagon",   "size": 50, "icon": "₿"},
    "ip":              {"color": "#0ea5e9", "shape": "diamond",   "size": 40, "icon": "🖥️"},
    "country":         {"color": "#16a34a", "shape": "round-tag", "size": 35, "icon": "🌍"},
    "finance":         {"color": "#22c55e", "shape": "roundrect", "size": 35, "icon": "💰"},
    "cluster":         {"color": "#1e293b", "shape": "roundrect", "size": 100,"icon": "📦"},
}

EDGE_STYLES = {
    "dirige":         {"color": "#a78bfa", "width": 2.5, "style": "solid"},
    "beneficiaire":   {"color": "#f59e0b", "width": 2, "style": "solid"},
    "adresse":        {"color": "#6b7280", "width": 1.5, "style": "dashed"},
    "procédure":      {"color": "#f97316", "width": 3, "style": "solid"},
    "sanction":       {"color": "#ef4444", "width": 3.5, "style": "solid"},
    "news":           {"color": "#94a3b8", "width": 1, "style": "dotted"},
    "domaine":        {"color": "#06b6d4", "width": 2, "style": "dashed"},
    "liée_à":         {"color": "#00d4ff", "width": 1.5, "style": "dashed"},
    "crypto":         {"color": "#f59e0b", "width": 2, "style": "solid"},
    "default":        {"color": "#334155", "width": 1, "style": "solid"},
}


def _make_id(*parts):
    raw = "_".join(str(p) for p in parts if p)
    return re.sub(r'[^a-zA-Z0-9_\-]', '_', raw.lower())[:60]


def build_graph_data(raw_results, ctx):
    nodes = {}  # id -> node dict
    edges = []  # list of edge dicts

    query = ctx.get("query", "?")
    center_id = _make_id("main", query)

    def add_node(node_id, label, node_type, extra=None, risk=0, group=None):
        if node_id in nodes:
            # Merge risk
            nodes[node_id]["risk"] = max(nodes[node_id].get("risk", 0), risk)
            return node_id
        style = NODE_TYPES.get(node_type, NODE_TYPES["company"])
        nodes[node_id] = {
            "id":       node_id,
            "label":    label[:45],
            "type":     node_type,
            "color":    style["color"],
            "shape":    style["shape"],
            "size":     style["size"],
            "icon":     style.get("icon", ""),
            "risk":     risk,
            "group":    group or node_type,
            "extra":    extra or {},
            "source_count": 1,
        }
        return node_id

    def add_edge(source, target, rel, extra=None):
        # Éviter doublons
        key = f"{source}→{target}:{rel}"
        for e in edges:
            if e.get("_key") == key:
                return
        style = EDGE_STYLES.get(rel, EDGE_STYLES["default"])
        edges.append({
            "_key":  key,
            "id":    _make_id("edge", source, target, rel),
            "source": source,
            "target": target,
            "rel":   rel,
            "label": rel,
            "color": style["color"],
            "width": style["width"],
            "style": style["style"],
            "extra": extra or {}
        })

    # Nœud central
    add_node(center_id, query, "company_main", extra={"query": query, "is_center": True})

    # ── SIRENE ──────────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Sirene" and res.get("data"):
            companies = res["data"]
            top = res.get("top", companies[0] if companies else {})
            if not top:
                continue
            # Mettre à jour le label du centre avec le vrai nom
            nom_reel = top.get("nom_complet") or top.get("nom_raison_sociale") or query
            nodes[center_id]["label"] = nom_reel[:45]
            nodes[center_id]["extra"].update({
                "siren": top.get("siren",""),
                "siret": top.get("siret",""),
                "statut": top.get("etat_administratif",""),
                "nature": top.get("nature_juridique_libelle",""),
                "activite": top.get("activite_principale_libelle",""),
                "code_ape": top.get("activite_principale",""),
                "tranche_eff": top.get("tranche_effectif_salarie",""),
                "date_creation": top.get("date_creation",""),
            })
            if top.get("etat_administratif") == "F":
                nodes[center_id]["risk"] = max(nodes[center_id]["risk"], 20)
                nodes[center_id]["color"] = "#f97316"

            # Siège social
            siege = top.get("siege") or {}
            adresse = siege.get("adresse","") or siege.get("libelle_voie","")
            if adresse:
                addr_id = _make_id("addr", adresse[:30])
                add_node(addr_id, adresse[:40], "address", extra={"full": adresse, "cp": siege.get("code_postal","")})
                add_edge(center_id, addr_id, "adresse")

            # Autres entités liées (sauf la principale)
            for co in companies[1:4]:
                co_nom = co.get("nom_complet","?")
                co_id = _make_id("co", co.get("siren",""), co_nom[:20])
                add_node(co_id, co_nom[:40], "company", extra={
                    "siren": co.get("siren",""),
                    "statut": co.get("etat_administratif",""),
                    "activite": co.get("activite_principale_libelle","")
                })
                add_edge(center_id, co_id, "liée_à", {"source": "Sirene"})

    # ── PAPPERS ─────────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Pappers" and res.get("data"):
            d = res["data"]
            nom_reel = d.get("nom_entreprise", query)
            nodes[center_id]["label"] = nom_reel[:45]
            nodes[center_id]["extra"].update({
                "siren": d.get("siren",""),
                "capital": d.get("capital",""),
                "forme_juridique": d.get("forme_juridique",""),
                "statut_pappers": d.get("statut",""),
            })

            # Dirigeants
            for dg in d.get("dirigeants", [])[:8]:
                nom  = f"{dg.get('prenom','')} {dg.get('nom','')}".strip()
                role = dg.get("titre","Dirigeant")
                if not nom:
                    continue
                did = _make_id("person", nom)
                add_node(did, nom, "person", extra={
                    "role": role,
                    "nationalite": dg.get("nationalite",""),
                    "date_naissance": dg.get("date_naissance",""),
                    "source": "Pappers"
                })
                add_edge(center_id, did, "dirige", {"role": role})

            # Bénéficiaires effectifs
            for be in d.get("beneficiaires_effectifs", [])[:5]:
                nom = f"{be.get('prenom','')} {be.get('nom','')}".strip()
                pct = be.get("pourcentage_parts", 0)
                if not nom:
                    continue
                bid = _make_id("be", nom)
                add_node(bid, nom, "person_be", extra={
                    "parts": f"{pct}%",
                    "nationalite": be.get("nationalite",""),
                    "source": "Pappers — BE"
                }, risk=0)
                add_edge(center_id, bid, "beneficiaire", {"pct": pct})

            # Finances
            for fi in d.get("finances", [])[:3]:
                yr = fi.get("annee","?")
                ca = fi.get("chiffre_affaires","")
                if ca:
                    fid = _make_id("finance", yr)
                    lbl = f"CA {yr}: {ca:,}€" if isinstance(ca, int) else f"CA {yr}"
                    add_node(fid, lbl, "finance", extra={"annee": yr, "ca": ca, "resultat": fi.get("resultat","")})
                    add_edge(center_id, fid, "liée_à", {"type": "finance"})

    # ── BODACC ──────────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Bodacc":
            records = res.get("data") or []
            for rec in records[:8]:
                type_a = rec.get("typeavis_lib", rec.get("familleavis_lib","Annonce"))
                date   = rec.get("dateparution","?")[:10]
                trib   = rec.get("tribunal","?")
                bid    = _make_id("bodacc", date, type_a[:12])
                risk_lvl = 35 if any(t in type_a.lower() for t in ["liquidation","redressement"]) else 18
                add_node(bid, f"{type_a[:25]}\n{date}", "legal_alert",
                         extra={"date": date, "tribunal": trib, "type": type_a, "ville": rec.get("ville","")},
                         risk=risk_lvl)
                add_edge(center_id, bid, "procédure", {"date": date, "tribunal": trib})
                nodes[center_id]["risk"] = max(nodes[center_id].get("risk",0), risk_lvl)

    # ── OPENSANCTIONS ────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "OpenSanctions" and res.get("hit"):
            for hit in res.get("data", [])[:4]:
                sid  = _make_id("sanction", hit.get("id",""))
                name = hit.get("caption","Entité sanctionnée")
                datasets = hit.get("datasets",[])
                add_node(sid, name[:40], "sanction",
                         extra={"schema": hit.get("schema",""), "datasets": datasets[:5], "id": hit.get("id","")},
                         risk=55)
                add_edge(center_id, sid, "sanction", {"datasets": datasets[:3]})
                nodes[center_id]["risk"] = max(nodes[center_id].get("risk",0), 55)

    # ── GOOGLE NEWS ──────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Google News":
            articles = res.get("data") or []
            for a in articles[:6]:
                title = a.get("title","?")[:50]
                is_neg = a.get("is_negative", False)
                ntype  = "news_negative" if is_neg else "news_neutral"
                nid    = _make_id("news", title[:20])
                risk   = 20 if is_neg else 0
                add_node(nid, title, ntype,
                         extra={"url": a.get("link",""), "date": a.get("date",""), "lang": a.get("lang",""),
                                "flags": a.get("negative_flags",[])},
                         risk=risk)
                add_edge(center_id, nid, "news", {"negative": is_neg})

    # ── WHOIS ────────────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "WHOIS/RDAP" and res.get("data"):
            d = res["data"]
            if isinstance(d, dict):
                if d.get("domain"):
                    dom = d["domain"]
                    did = _make_id("domain", dom)
                    add_node(did, dom, "domain", extra={
                        "registered": d.get("registered",""),
                        "expiration": d.get("expiration",""),
                        "nameservers": d.get("nameservers",[]),
                        "status": d.get("status",[])
                    })
                    add_edge(center_id, did, "domaine")
                    # NSs
                    for ns in d.get("nameservers",[])[:3]:
                        ns_id = _make_id("ns", ns)
                        add_node(ns_id, ns[:30], "ip", extra={"type": "nameserver"})
                        add_edge(did, ns_id, "liée_à", {"type": "nameserver"})

                if d.get("ip_info"):
                    ip_info = d["ip_info"]
                    ip_id = _make_id("ip", ip_info.get("ip",""))
                    add_node(ip_id, ip_info.get("ip","?"), "ip", extra={
                        "org": ip_info.get("org",""),
                        "country": ip_info.get("country_name",""),
                        "city": ip_info.get("city",""),
                        "asn": ip_info.get("asn","")
                    })
                    add_edge(center_id, ip_id, "domaine")

    # ── CRYPTO ───────────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Crypto Trace" and res.get("data"):
            d = res["data"]
            addr = ctx.get("crypto_addr","") or ctx.get("query","?")
            wid = _make_id("wallet", addr[:20])
            risk = 50 if d.get("sanctions") else 0
            add_node(wid, addr[:30], "crypto_wallet", extra={
                "addr_type": res.get("addr_type","?"),
                "balance_btc": d.get("btc",{}).get("balance_btc","") if d.get("btc") else "",
                "n_tx": d.get("btc",{}).get("n_tx","") if d.get("btc") else "",
            }, risk=risk)
            add_edge(center_id, wid, "crypto")

    # ── PERSON SEARCH ────────────────────────────────────────────────────────
    for res in raw_results:
        if res.get("source") == "Person Search" and res.get("data"):
            d = res["data"]
            for co in (d.get("companies_linked") or [])[:4]:
                nom = co.get("nom_complet","?")
                co_id = _make_id("co_linked", co.get("siren",""), nom[:15])
                add_node(co_id, nom[:40], "company", extra={"siren": co.get("siren",""), "source": "PersonSearch"})
                add_edge(center_id, co_id, "liée_à")

    # ── POST-PROCESSING ──────────────────────────────────────────────────────
    # Enlever les _key des edges (interne)
    clean_edges = [{k: v for k, v in e.items() if k != "_key"} for e in edges]

    # Stats
    stats = {
        "total_nodes": len(nodes),
        "total_edges": len(clean_edges),
        "risk_nodes": sum(1 for n in nodes.values() if n.get("risk",0) > 20),
        "center_id": center_id,
        "generated_at": datetime.now().isoformat(),
    }

    return {
        "nodes": list(nodes.values()),
        "edges": clean_edges,
        "center": center_id,
        "stats": stats
    }
