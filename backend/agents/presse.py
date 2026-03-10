"""
Agent Presse — Google News RSS (gratuit)
"""
import requests, re, urllib.parse

TIMEOUT = 10

SUSPECTS_FR = ["fraude","condamné","escroquerie","liquidation","détournement",
               "corruption","garde à vue","mis en examen","faillite",
               "redressement judiciaire","arnaque","abus de confiance",
               "blanchiment","malversation","perquisition","mis en cause"]
SUSPECTS_EN = ["fraud","convicted","scam","bankruptcy","corruption","arrested",
               "indicted","money laundering","embezzlement","ponzi","scandal",
               "criminal","investigation","bribery","misconduct","default",
               "lawsuit","charges","guilty","sentenced","probe"]

def _fetch_rss(query, lang, country, extra=""):
    try:
        q = f"{query} {extra}".strip()
        encoded = urllib.parse.quote(q)
        url = f"https://news.google.com/rss/search?q={encoded}&hl={lang}&gl={country}&ceid={country}:{lang}"
        r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": "Mozilla/5.0"})
        if r.status_code != 200:
            return []
        text = r.text
        titles  = re.findall(r'<title><!\[CDATA\[(.*?)\]\]></title>', text)[1:8]
        if not titles:
            titles = re.findall(r'<title>(.*?)</title>', text)[1:8]
        links   = re.findall(r'<link>(https://.*?)</link>', text)[:8]
        dates   = re.findall(r'<pubDate>(.*?)</pubDate>', text)[:8]
        sources = re.findall(r'<source[^>]*>(.*?)</source>', text)[:8]
        return [{
            "title":  t,
            "link":   links[i]   if i < len(links)   else "",
            "date":   dates[i]   if i < len(dates)   else "",
            "source": sources[i] if i < len(sources) else "",
            "lang":   lang
        } for i, t in enumerate(titles)]
    except:
        return []

def agent_news(query, ctx, emit):
    emit("agent_start", {"id": "news", "msg": "Scan presse FR + EN + négatif..."})
    try:
        fr       = _fetch_rss(query, "fr", "FR")
        en       = _fetch_rss(query, "en", "US")
        fr_neg   = _fetch_rss(query, "fr", "FR", "fraude OR escroquerie OR condamné OR faillite")
        en_neg   = _fetch_rss(query, "en", "US", "fraud OR scam OR lawsuit OR criminal")

        # Dédoublonner par titre
        seen = set()
        all_articles = []
        for a in fr + en + fr_neg + en_neg:
            key = a["title"][:50]
            if key not in seen:
                seen.add(key)
                # Annoter avec flags négatifs
                tl = a["title"].lower()
                a["negative_flags"] = [m for m in SUSPECTS_FR + SUSPECTS_EN if m.lower() in tl]
                a["is_negative"] = len(a["negative_flags"]) > 0
                all_articles.append(a)

        all_articles = all_articles[:15]
        negative_count = sum(1 for a in all_articles if a["is_negative"])

        if negative_count > 0:
            emit("agent_done", {
                "id": "news", "status": "alert",
                "msg": f"🔴 {negative_count} article(s) négatif(s) / {len(all_articles)} total"
            })
        else:
            emit("agent_done", {
                "id": "news", "status": "ok",
                "msg": f"✅ {len(all_articles)} article(s) — aucun signal négatif"
            })

        return {
            "source": "Google News",
            "status": "ok",
            "data": all_articles,
            "negative_count": negative_count,
            "reliability": 75
        }
    except Exception as e:
        emit("agent_done", {"id": "news", "status": "error", "msg": str(e)[:60]})
        return {"source": "Google News", "status": "error", "data": str(e)}
