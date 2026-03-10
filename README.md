# NEXUS — OSINT Intelligence Platform v2.0

Pipeline multi-agents OSINT entièrement automatisé. Un formulaire, tout se lance.

## Architecture

```
nexus-osint/
├── backend/
│   ├── app.py                  # Flask + SSE streaming
│   ├── requirements.txt
│   ├── .env.example
│   └── agents/
│       ├── entreprise.py       # Sirene (gratuit) + Bodacc + Pappers
│       ├── sanctions.py        # OpenSanctions (330 listes)
│       ├── presse.py           # Google News RSS + scan négatif
│       ├── infra.py            # WHOIS/RDAP + Shodan
│       ├── personne.py         # Recherche personne physique
│       ├── crypto.py           # BTC/ETH blockchain analysis
│       ├── ia_cross.py         # Vérificateur + Groq LLaMA 3.3 70B
│       └── graph_builder.py    # Graphe Cytoscape.js
└── frontend/
    ├── landing.html            # Page de vente
    └── app.html                # Dashboard + pipeline + graphe
```

## Installation

```bash
cd backend
pip install -r requirements.txt
cp .env.example .env
# Remplir GROQ_API_KEY dans .env
python app.py
# → http://localhost:5000
```

## Sources (toutes gratuites en MVP)

| Source | Données | Auth |
|--------|---------|------|
| INSEE Sirene | Registre entreprises FR officiel | ❌ Aucune |
| Bodacc | Procédures légales & faillites | ❌ Aucune |
| Google News RSS | Presse FR + EN | ❌ Aucune |
| WHOIS/RDAP | Domaines & IP | ❌ Aucune |
| OpenSanctions | 330 listes sanctions mondiales | Clé gratuite |
| Pappers | Registre enrichi + dirigeants | Clé gratuite |
| Groq | LLaMA 3.3 70B synthèse IA | Clé gratuite |
| Shodan | Scan infrastructure | Clé gratuite |
| Blockchain.info | Wallets BTC | ❌ Aucune |
| Etherscan | Wallets ETH | ❌ Aucune |

## Graphe relationnel

- **Moteur**: Cytoscape.js avec layout Cola (physics)
- **Nœuds typés**: entreprise, personne, dirigeant, BE, adresse, domaine, sanction, procédure, news, crypto
- **Edges enrichis**: relation typée, couleur, style, poids
- **Expand on click**: double-clic sur un nœud = sous-pipeline OSINT automatique
- **Export**: PNG haute-def

## Roadmap

- [ ] Auth utilisateurs + multi-tenant
- [ ] Stockage PostgreSQL + historique investigations
- [ ] PDF export rapport formaté
- [ ] Webhooks alertes
- [ ] API REST complète pour intégration
- [ ] Agents additionnels: LinkedIn, Twitter, Infogreffe, OFAC direct
- [ ] Score ML affiné
- [ ] Mode surveillance (cron sur une cible)
