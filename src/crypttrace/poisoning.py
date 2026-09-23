"""Address poisoning — look-alike addresses planted in a wallet's history.

Wallets show addresses shortened, "0x1234…abcd". An attacker who sees a victim
pay 0x1234…abcd generates an address with the same first and last characters,
then sends the victim a zero-value transfer (or a fake token) from it, so the
look-alike sits at the top of the victim's history. The next time the victim
copies "the address I paid last time", they copy the attacker's.

Three views of the same attack:

  * lookalikes(victim)  — pairs of counterparties in one wallet's history that
    share their visible characters, which one arrived later with a zero or dust
    transfer, and whether real money was then sent to it;
  * baited_payments(address) — the poisoner's side, which is usually the
    address a victim brings to an investigation: someone paid it real money
    after exchanging a zero or dust transfer with it. On EVM chains the bait is
    often transferFrom(victim, look-alike, 0), which records a zero transfer
    *from the victim*, so the look-alike itself never has to send anything;
  * campaign(address)   — an address sending zero/dust transfers to many
    unrelated wallets (the dust-sending style, common on Tron).
"""
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from crypttrace import analysis, assets, chains

# How closely two addresses must match at the ends (after "0x", "T", "bc1q"…).
# Strong: rare by chance, flagged on resemblance alone. Weak: the cheap
# look-alikes seen on Tron (first and last two characters), flagged only when
# the look-alike arrived with bait after the genuine address was in use.
STRONG = (3, 3, 7)          # min prefix, min suffix, min total
WEAK = (1, 2, 3)
# A campaign: this many distinct recipients of zero/dust transfers.
CAMPAIGN_MIN_TARGETS = 10

_ALL_TOKENS = {"contract": None, "symbol": "*"}


def _body(address: str, chain: str) -> str:
    """The part of an address that varies — what a shortened display shows."""
    a = address if chains.case_sensitive(chain) else address.lower()
    for p in ("0x", "bc1q", "bc1p", "bc1", "tb1q", "T"):
        if a.startswith(p) and (p != "T" or chain == "tron"):
            return a[len(p):]
    return a


def match_lengths(a: str, b: str, chain: str) -> Tuple[int, int]:
    """How many leading and trailing characters two addresses share."""
    x, y = _body(a, chain), _body(b, chain)
    pre = 0
    while pre < min(len(x), len(y)) and x[pre] == y[pre]:
        pre += 1
    suf = 0
    while suf < min(len(x), len(y)) - pre and x[-1 - suf] == y[-1 - suf]:
        suf += 1
    return pre, suf


def resemblance(a: str, b: str, chain: str) -> Optional[str]:
    """'strong', 'weak' or None."""
    if chains.norm_addr(a, chain) == chains.norm_addr(b, chain):
        return None
    pre, suf = match_lengths(a, b, chain)
    for name, (p, s, t) in (("strong", STRONG), ("weak", WEAK)):
        if pre >= p and suf >= s and pre + suf >= t:
            return name
    return None


def _history(address: str, chain: str, limit: int) -> List[dict]:
    """Native and every-token transfers, fakes included — they are the bait."""
    rows = list(chains.transfers(address, chain, limit))
    if chain != "btc":
        try:
            rows += chains.transfers(address, chain, limit, asset=_ALL_TOKENS)
        except chains.ChainError:
            pass
    return rows


def _is_bait(row: dict, chain: str) -> bool:
    """A transfer whose only purpose is to appear in a history: zero value, dust,
    or a counterfeit token wearing a real token's symbol."""
    v = row.get("value", 0) or 0
    if v <= 0:
        return True
    contract = (row.get("contract") or "").lower()
    if not contract:
        return v < analysis.dust_threshold(chain)
    real = assets.tokens_for(chain).get((row.get("symbol") or "").lower())
    if real:
        if contract != real["contract"].lower():
            return True                        # 'USDT' from the wrong contract
        return real.get("stable", False) and v < 1.0
    return False                               # unknown token, real amount: not bait


def lookalikes(address: str, chain: str, limit: int = 1000) -> List[dict]:
    """Look-alike counterparty pairs in `address`'s history, newest risk first.

    For each pair the earlier-used address is taken as the genuine one; the
    later one is the suspected look-alike. `sent_to_lookalike` > 0 means real
    value went to it after it appeared — the usual way this theft completes.
    """
    me = chains.norm_addr(address, chain)
    seen: Dict[str, dict] = {}
    for r in _history(address, chain, limit):
        frm, to = r.get("from") or "", r.get("to") or ""
        if frm == me and to and to != me:
            other, outgoing = to, True
        elif to == me and frm and frm != me:
            other, outgoing = frm, False
        else:
            continue
        ts = int(r.get("timestamp") or 0)
        c = seen.setdefault(other, {"address": other, "first_ts": ts, "rows": 0, "bait": 0,
                                    "bait_first_ts": None, "sent_value": 0.0,
                                    "sent_first_ts": None, "symbols": set()})
        c["first_ts"] = min(c["first_ts"], ts) if c["first_ts"] else ts
        c["rows"] += 1
        c["symbols"].add(r.get("symbol") or "?")
        if _is_bait(r, chain):
            c["bait"] += 1
            c["bait_first_ts"] = ts if c["bait_first_ts"] is None else min(c["bait_first_ts"], ts)
        elif outgoing:
            c["sent_value"] += r.get("value", 0) or 0
            c["sent_first_ts"] = ts if c["sent_first_ts"] is None else min(c["sent_first_ts"], ts)

    # only compare addresses that could match: bucket by visible ends
    buckets = defaultdict(list)
    for a in seen:
        b = _body(a, chain)
        if len(b) >= WEAK[0] + WEAK[1]:
            buckets[(b[:WEAK[0]], b[-WEAK[1]:])].append(a)

    findings = []
    for group in buckets.values():
        if len(group) < 2:
            continue
        # genuine = the one this wallet paid real value to first (else the earliest seen)
        def rank(a):
            c = seen[a]
            return (c["sent_first_ts"] is None, c["sent_first_ts"] or c["first_ts"], c["first_ts"])
        genuine = min(group, key=rank)
        for fake in group:
            level = resemblance(genuine, fake, chain) if fake != genuine else None
            if not level:
                continue
            g, f = seen[genuine], seen[fake]
            baited = f["bait"] > 0 and (f["bait_first_ts"] or 0) >= (g["first_ts"] or 0)
            if level == "weak" and not baited:
                continue            # a two-character coincidence is not evidence by itself
            pre, suf = match_lengths(genuine, fake, chain)
            findings.append({
                "genuine": genuine, "lookalike": fake, "resemblance": level,
                "confidence": "high" if level == "strong" or f["sent_value"] > 0 else "medium",
                "matching": {"prefix": pre, "suffix": suf},
                "lookalike_first_seen": f["first_ts"],
                "lookalike_after_genuine_s": (f["first_ts"] - g["first_ts"])
                if f["first_ts"] and g["first_ts"] else None,
                "bait_transfers": f["bait"],
                "sent_to_lookalike": f["sent_value"],
                "sent_to_genuine": g["sent_value"],
                "symbols": sorted(f["symbols"]),
            })
    findings.sort(key=lambda x: (x["sent_to_lookalike"] <= 0, -x["bait_transfers"]))
    return findings


def _substantial(row: dict, chain: str) -> bool:
    """Money a victim would actually lose: native well above dust, or a real
    stablecoin of at least $10. Excludes the few-dollar top-ups an operator
    uses to activate a fresh look-alike."""
    v = row.get("value", 0) or 0
    contract = (row.get("contract") or "").lower()
    if not contract:
        return v >= 100 * analysis.dust_threshold(chain)
    real = assets.tokens_for(chain).get((row.get("symbol") or "").lower())
    return bool(real and real.get("stable") and contract == real["contract"].lower() and v >= 10)


def baited_payments(address: str, chain: str, limit: int = 1000,
                    confirm: int = 3) -> List[dict]:
    """Payers who sent `address` real money right after it lured them.

    The lure is either bait (a zero, dust or counterfeit transfer between the
    two) or this address first sending the payer a small real amount — what
    makes it appear in the payer's history. For up to `confirm` payers their
    own history is read for the address this one imitates, which turns a
    pattern into a specific claim.
    """
    me = chains.norm_addr(address, chain)
    rows = _history(address, chain, limit)
    first_active = min((int(r.get("timestamp") or 0) for r in rows if r.get("timestamp")), default=0)
    lure: Dict[str, dict] = {}           # counterparty -> earliest lure
    paid: Dict[Tuple[str, str], dict] = {}
    for r in rows:
        frm, to = r.get("from") or "", r.get("to") or ""
        other = to if frm == me else frm if to == me else ""
        if not other or other == me:
            continue
        ts, v = int(r.get("timestamp") or 0), r.get("value", 0) or 0
        if _is_bait(r, chain):
            kind = "bait"
        elif frm == me:
            kind = "small transfer from this address"
        elif _substantial(r, chain):
            p = paid.setdefault((other, r.get("symbol") or "?"), {"value": 0.0, "first_ts": ts})
            p["value"] += v
            p["first_ts"] = min(p["first_ts"], ts)
            continue
        else:
            continue
        l = lure.get(other)
        if l is None or ts < l["ts"]:
            lure[other] = {"ts": ts, "kind": kind, "value": v, "symbol": r.get("symbol")}
    out = []
    for (payer, symbol), p in paid.items():
        l = lure.get(payer)
        if not l or l["ts"] > p["first_ts"]:
            continue
        if l["kind"] != "bait" and l["symbol"] == symbol and l["value"] > 0.01 * p["value"]:
            continue                      # a real exchange of similar size, not a lure
        out.append({"payer": payer, "paid": p["value"], "symbol": symbol,
                    "lure": l["kind"], "lure_ts": l["ts"], "paid_ts": p["first_ts"],
                    "address_age_s": p["first_ts"] - first_active if first_active else None,
                    "imitates": None})
    out.sort(key=lambda x: -x["paid"])
    for x in out[:confirm]:
        try:
            for pair in lookalikes(x["payer"], chain, limit):
                if chains.norm_addr(pair["lookalike"], chain) == me:
                    x["imitates"] = pair["genuine"]
                    break
        except chains.ChainError:
            pass
    return out


def campaign(address: str, chain: str, limit: int = 1000) -> Optional[dict]:
    """Does `address` send zero/dust transfers to many unrelated wallets?"""
    me = chains.norm_addr(address, chain)
    targets, bait, real_out = set(), 0, 0
    for r in _history(address, chain, limit):
        if r.get("from") != me or not r.get("to") or r.get("to") == me:
            continue
        if _is_bait(r, chain):
            bait += 1
            targets.add(r["to"])
        else:
            real_out += 1
    if len(targets) < CAMPAIGN_MIN_TARGETS or bait < 2 * real_out:
        return None
    return {"targets": len(targets), "bait_transfers": bait, "real_transfers_out": real_out,
            "sample": sorted(targets)[:5]}


def short(address: str, chain: str, pre: int = 6, suf: int = 6) -> str:
    """How a wallet would show it — the part a poisoner imitates."""
    head = len(address) - len(_body(address, chain))
    return address[:head + pre] + "…" + address[-suf:]
