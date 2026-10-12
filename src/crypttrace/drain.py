"""Was this wallet drained? — the check a victim can run on their own address.

A drain looks the same on every chain where the attacker holds the key: within
minutes, several signed transfers move everything — tokens, NFTs, then the coin
itself — to one address the wallet never paid before, and the wallet is left
empty. Nobody approves a dozen transfers a minute by hand, so a burst like that
means the key or seed phrase is in someone else's hands.

Three more facts turn "my wallet is empty" into something a victim can act on:
- the same address emptied many other wallets in the same hour: a mass drain
  (leaked keys from a shared service or tool), not a scam aimed at you;
- money that arrived after the drain was taken too: the attacker still has
  the key, and anything sent to this wallet will be lost;
- where the money went next — an exchange, with the deposit memo that names
  the account there.
"""
from collections import defaultdict
from typing import Dict, List, Optional

from crypttrace import analysis, chains, spam
from crypttrace.labels import labels

WINDOW = 15 * 60        # a drain empties a wallet within minutes
BURST = 120             # signed transfers this close together are automated
MASS_SENDERS = 10       # wallets swept into one address within an hour of yours
MASS_SPAN = 3600
_ALL_TOKENS = {"contract": None, "symbol": "*"}


def _history(address: str, chain: str, limit: int) -> List[dict]:
    rows = list(chains.transfers(address, chain, limit))
    if chain != "btc":
        try:
            rows += [r for r in chains.transfers(address, chain, limit, asset=_ALL_TOKENS)
                     if not spam.verdict(chain, r.get("contract", ""), r.get("symbol", ""),
                                         r.get("name", ""), bool(r.get("flagged")))]
        except chains.ChainError:
            pass
    if chain == "ton":
        from crypttrace.fetchers import ton
        try:
            rows += ton.nft_transfers(address, limit)
        except ton.TonError:
            pass
    return rows


def _best_burst(rows: List[dict], native: str) -> Optional[dict]:
    """The WINDOW of outgoing transfers to one destination that took the most:
    most kinds of asset first, then the most of the chain's own coin."""
    by_dest: Dict[str, List[dict]] = defaultdict(list)
    for r in rows:
        by_dest[r["to"]].append(r)
    best = None
    for dest, rs in by_dest.items():
        rs.sort(key=lambda r: r["timestamp"])
        for i, first in enumerate(rs):
            win = [r for r in rs[i:] if r["timestamp"] - first["timestamp"] <= WINDOW]
            assets = {r.get("symbol") for r in win}
            coin = sum(r.get("value", 0) or 0 for r in win if r.get("symbol") == native)
            score = (len(assets), coin, len({r.get("hash") for r in win}))
            if best is None or score > best["score"]:
                best = {"score": score, "to": dest, "rows": win,
                        "start": first["timestamp"], "end": win[-1]["timestamp"]}
    return best


def _amounts(rows: List[dict]) -> Dict[str, float]:
    tot: Dict[str, float] = defaultdict(float)
    for r in rows:
        tot[r.get("symbol") or "?"] += r.get("value", 0) or 0
    return dict(tot)


def check(address: str, chain: str, limit: int = 1000) -> Dict:
    """Verdict on one wallet: drained (and how), suspicious, or no drain found."""
    me = chains.norm_addr(address, chain)
    rows = _history(address, chain, limit)
    out = [r for r in rows if r.get("from") == me and r.get("to") and r.get("to") != me
           and not r.get("kind") and (r.get("value") or 0) > 0]
    res: Dict = {"address": me, "chain": chain, "verdict": "no_drain", "reasons": []}
    try:
        res["balance"] = chains.balance(address, chain)
    except chains.ChainError:
        res["balance"] = None
    if not out:
        res["reasons"].append("this wallet has sent nothing in the history read")
        return res

    burst = _best_burst(out, chains.symbol(chain))
    dest, win = burst["to"], burst["rows"]
    labels.enrich([dest], chain)
    paid_before = any(r.get("to") == dest and r["timestamp"] < burst["start"] for r in out)
    times = sorted(r["timestamp"] for r in win)
    tight = sum(1 for a, b in zip(times, times[1:]) if b - a <= BURST)
    dust = analysis.dust_threshold(chain)
    emptied = res["balance"] is not None and res["balance"] <= max(dust, 1e-9) * 5
    nfts = sum(1 for r in win if r.get("symbol") == "NFT")
    assets = _amounts([r for r in win if r.get("symbol") != "NFT"])
    res.update({"to": dest, "to_label": labels.label_of(dest), "to_type": labels.type_of(dest),
                "start": burst["start"], "end": burst["end"], "transfers": len({r.get("hash") for r in win}),
                "assets": assets, "nfts": nfts, "emptied": emptied, "new_destination": not paid_before,
                "tight_pairs": tight})

    # a mass drain: the same address swept many wallets around the same time
    try:
        inflow = _history(dest, chain, limit) if labels.type_of(dest) != "exchange" else []
    except chains.ChainError:
        inflow = []
    senders = {r["from"] for r in inflow
               if r.get("to") == dest and not r.get("kind") and r.get("from") != dest
               and abs(r["timestamp"] - burst["start"]) <= MASS_SPAN}
    res["other_wallets_same_hour"] = max(0, len(senders) - 1)
    mass = res["other_wallets_same_hour"] >= MASS_SENDERS

    automated = tight >= 2 or (len(assets) + (1 if nfts else 0)) >= 2 or mass
    if labels.type_of(dest) == "exchange":
        res["reasons"].append("the largest outflow went to an exchange — usually your own deposit")
    elif emptied and automated and not paid_before:
        res["verdict"] = "drained"
    elif emptied and not paid_before:
        res["verdict"] = "suspicious"
    if res["verdict"] == "no_drain":
        return res

    if tight >= 2 or len(assets) + (1 if nfts else 0) >= 2:
        res["reasons"].append(f"{res['transfers']} transfers to one new address within "
                              f"{max(1, (burst['end'] - burst['start']) // 60)} min, "
                              "several seconds apart — signed by a program holding your key")
    if emptied:
        res["reasons"].append("the wallet was left empty")
    if labels.type_of(dest) == "scam":
        res["reasons"].append(f"the receiving address is a known drainer: {labels.label_of(dest)}")

    if mass:
        res["reasons"].append(f"the same address took money from {res['other_wallets_same_hour']} other "
                              "wallets within an hour — a mass drain from leaked keys, not a scam aimed at you")

    # taken again after the drain: the attacker still has the key
    later = [r for r in out if r["timestamp"] > burst["end"] + 60 and r.get("to") == dest]
    res["resweeps"] = len({r.get("hash") for r in later})
    if res["resweeps"]:
        res["reasons"].append(f"{res['resweeps']} later transfer(s) to the same address after the wallet "
                              "was topped up — the attacker still has the key")

    # where it went next: exchange deposits (with memo) of the receiver and its next hop
    nxt = []
    try:
        hops = [dest] + [o for o, _, _ in chains.outflows(dest, chain, 3)]
        labels.enrich(hops, chain)
        for h in hops:
            for d in chains.exchange_deposits(h, chain):
                nxt.append({**d, "from": h})
            if h != dest and labels.type_of(h) == "exchange":
                nxt.append({"exchange_address": h, "exchange": labels.label_of(h), "memo": "",
                            "value": None, "txs": None, "symbol": "", "from": dest})
    except chains.ChainError:
        pass
    res["next"] = nxt

    # what can still be saved
    if chain == "ton":
        res["remaining_tokens"], res["remaining_nfts"] = _ton_left(me)
    else:
        keep = []
        try:
            keep = [h for h in chains.token_holdings(address, chain) if not h.get("spam")]
        except chains.ChainError:
            pass
        res["remaining_tokens"] = [{"symbol": h["symbol"], "amount": h["net"]} for h in keep[:10]]
    return res


def _ton_left(address: str):
    """Jettons the wallet holds now (not spam), and NFTs from collections tonapi trusts —
    airdropped spam NFTs are not worth the gas to move."""
    from crypttrace.fetchers import http, ton
    tokens = []
    try:
        for w in ton._get("/jetton/wallets", {"owner_address": address, "limit": 100}).get("jetton_wallets") or []:
            master = (w.get("jetton") or "").lower()
            meta = ton._meta(master)
            if not meta or not int(w.get("balance") or 0):
                continue
            if spam.verdict("ton", master, meta["symbol"], meta["name"], meta["scam"]):
                continue
            tokens.append({"symbol": meta["symbol"], "amount": int(w["balance"]) / 10 ** meta["decimals"]})
    except (ton.TonError, ValueError, TypeError):
        pass
    nfts = None
    try:
        items = http.request_json(f"https://tonapi.io/v2/accounts/{address}/nfts", {"limit": 100},
                                  timeout=20).get("nft_items") or []
        nfts = sum(1 for i in items if i.get("trust") == "whitelist" or i.get("approved_by"))
    except Exception:                                    # tonapi down: say nothing rather than guess
        pass
    return tokens[:10], nfts
