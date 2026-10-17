"""EVM clustering by gas funding — wallets started by the same funder.

A new EVM wallet cannot send anything until someone gives it coin for gas, so
the first payment into a wallet says who set it up. An attacker who spins up
many fresh wallets usually tops them all up from one place. Wallets whose
*first* funding came from the same address — and wallets this one started —
are therefore likely one entity.

The rule only holds when the funder is a person's wallet. An exchange,
mixer, bridge or DEX "funds" countless unrelated wallets, and so does any
contract (a first funding that arrived as an internal transaction came from
one) — a wallet funded like that is not linked to anything by it, and the
result says so.
Same-day funding with similar amounts makes a sibling link stronger: that is
what a script setting up wallets looks like.
"""
from typing import Dict, List, Optional

from crypttrace import chains, funder
from crypttrace.labels import labels

# a funder of this kind funds the public, not a set of its own wallets
SERVICE_TYPES = {"exchange", "mixer", "bridge", "dex", "service"}
DAY = 86400


def _first(addr: str, chain: str) -> Optional[dict]:
    try:
        return funder.first_funder(addr, chain)
    except chains.ChainError:
        return None


def _recipients(addr: str, chain: str, limit: int) -> List[dict]:
    """Distinct addresses `addr` paid in the native coin, first payment each."""
    seen: Dict[str, dict] = {}
    for r in sorted(chains.transfers(addr, chain, 1000, oldest_first=True), key=lambda r: r["timestamp"]):
        to = r.get("to")
        if r.get("from") != addr or not to or to == addr or (r.get("value") or 0) <= 0 or r.get("kind"):
            continue
        seen.setdefault(to, {"address": to, "value": r["value"], "timestamp": r["timestamp"], "hash": r.get("hash", "")})
    return list(seen.values())[:limit]


def cluster(address: str, chain: str, max_checks: int = 60) -> Dict:
    """Siblings (same first funder) and children (wallets this one funded first)."""
    me = chains.norm_addr(address, chain)
    res: Dict = {"address": me, "chain": chain, "funder": None, "siblings": [], "children": [],
                 "note": "", "checked": 0}
    mine = _first(me, chain)
    if mine:
        f = mine["funder"]
        labels.enrich([f], chain)
        res["funder"] = {"address": f, "label": labels.label_of(f), "type": labels.type_of(f),
                         "value": mine["value"], "timestamp": int(mine["timestamp"]), "hash": mine["hash"]}
        if mine.get("internal"):
            res["note"] = ("first funded by a contract (a withdrawal from a bridge, protocol or mixer), "
                           "not by a wallet — that links nothing")
        elif res["funder"]["type"] in SERVICE_TYPES:
            res["note"] = (f"first funded by {res['funder']['label'] or 'a ' + res['funder']['type']} — "
                           "a service funds countless unrelated wallets, so this links nothing")
        else:
            cands = [c for c in _recipients(f, chain, 1000) if c["address"] != me]
            # the wallets funded closest in time to this one are the likeliest siblings
            t0 = res["funder"]["timestamp"]
            cands.sort(key=lambda c: abs(c["timestamp"] - t0))
            for c in cands[:max_checks]:
                res["checked"] += 1
                first = _first(c["address"], chain)
                if first and first["funder"] == f and not first.get("internal"):
                    near = abs(c["timestamp"] - t0) <= DAY
                    similar = mine["value"] > 0 and 1 / 3 <= c["value"] / mine["value"] <= 3
                    res["siblings"].append({**c, "same_day": near, "similar_amount": similar,
                                            "label": labels.label_of(c["address"])})
    else:
        res["note"] = "no funding into this wallet was found in the history read"

    for c in _recipients(me, chain, max_checks):
        first = _first(c["address"], chain)
        if first and first["funder"] == me and not first.get("internal"):
            res["children"].append({**c, "label": labels.label_of(c["address"])})

    same_day = [s for s in res["siblings"] if s["same_day"] and s["similar_amount"]]
    similar = [s for s in res["siblings"] if s["similar_amount"]]
    res["strength"] = ("strong" if len(same_day) >= 2 or len(similar) >= 5 else
                       "moderate" if res["siblings"] or res["children"] else "none")
    return res
