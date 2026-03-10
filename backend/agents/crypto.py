"""
Agent Crypto — Blockchain analysis (APIs gratuites)
"""
import requests

TIMEOUT = 10
HEADERS = {"User-Agent": "Mozilla/5.0 Chrome/122", "Accept": "application/json"}

def agent_crypto(query, ctx, emit):
    emit("agent_start", {"id": "crypto", "msg": "Analyse blockchain & wallet..."})
    addr = ctx.get("crypto_addr", "") or query
    results = {}

    try:
        # Détecter le type d'adresse
        addr_type = _detect_addr_type(addr)

        if addr_type == "btc":
            # Blockchain.info API (gratuit)
            r = requests.get(f"https://blockchain.info/rawaddr/{addr}",
                             headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200:
                d = r.json()
                results["btc"] = {
                    "address": addr,
                    "balance_btc": d.get("final_balance", 0) / 1e8,
                    "total_received_btc": d.get("total_received", 0) / 1e8,
                    "n_tx": d.get("n_tx", 0),
                    "transactions": d.get("txs", [])[:5]
                }

        elif addr_type == "eth":
            # Etherscan API (gratuit, rate limited)
            r = requests.get("https://api.etherscan.io/api",
                             params={"module": "account", "action": "balance",
                                     "address": addr, "tag": "latest"},
                             headers=HEADERS, timeout=TIMEOUT)
            if r.status_code == 200 and r.json().get("status") == "1":
                balance_wei = int(r.json().get("result", 0))
                results["eth"] = {
                    "address": addr,
                    "balance_eth": balance_wei / 1e18,
                }

        # OpenSanctions — adresse wallet sur liste ?
        sanction_headers = {**HEADERS}
        if ctx.get("opensanctions_key"):
            sanction_headers["Authorization"] = f"ApiKey {ctx['opensanctions_key']}"
        r_sanc = requests.get("https://api.opensanctions.org/search/default",
                              params={"q": addr, "limit": 5},
                              headers=sanction_headers, timeout=TIMEOUT)
        if r_sanc.status_code == 200:
            results["sanctions"] = r_sanc.json().get("results", [])

        nb_sanctions = len(results.get("sanctions", []))
        status = "alert" if nb_sanctions > 0 else "ok"
        emit("agent_done", {
            "id": "crypto", "status": status,
            "msg": f"🔴 Wallet sanctionné" if nb_sanctions else f"✅ Wallet analysé ({addr_type.upper()})"
        })

        return {
            "source": "Crypto Trace",
            "status": "ok",
            "data": results,
            "addr_type": addr_type,
            "reliability": 85
        }
    except Exception as e:
        emit("agent_done", {"id": "crypto", "status": "error", "msg": str(e)[:60]})
        return {"source": "Crypto Trace", "status": "error", "data": str(e)}


def _detect_addr_type(addr):
    if addr.startswith(("1", "3", "bc1")) and 25 <= len(addr) <= 62:
        return "btc"
    if addr.startswith("0x") and len(addr) == 42:
        return "eth"
    return "unknown"
