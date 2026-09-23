"""Assessment — turning observations into a stated conclusion.

Collecting public data and drawing a graph is collection. Intelligence is the
step after: saying what the data supports, how strongly, and on what evidence.

So every signal here carries four things — what was *observed*, what it
*implies*, how *confident* we are, and the numbers a reader can check. The
overall confidence is deliberately reduced when the underlying figures could
not be reconciled with the chain, or when the labels involved carry no source.
An assessment that cannot be checked should not sound certain.
"""
import math
from collections import Counter
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from crypttrace import analysis, chains, freeze, poisoning
from crypttrace.labels import labels


@dataclass
class Signal:
    name: str
    observed: str
    implication: str
    confidence: str          # high / medium / low
    weight: int              # contribution to the risk figure
    evidence: dict = field(default_factory=dict)


CONF_ORDER = {"high": 3, "medium": 2, "low": 1}


# ---------------------------------------------------------------- detectors

def constant_fee_signature(values: List[float], min_hits: int = 5) -> Optional[dict]:
    """Do the amounts look like round sums minus one fixed fee?

    A person sends round-ish numbers. An automated sweeper takes whatever is in
    a wallet and subtracts a hardcoded fee, so the *gap to the next round
    number* repeats exactly across unrelated victims. That repetition is the
    fingerprint — it found the 3,300-sat fee in the Coldcard case by hand.
    """
    deltas = Counter()
    for v in values:
        if v <= 0:
            continue
        for step in (1.0, 0.5, 0.1, 0.05, 0.01):
            up = math.ceil(round(v / step, 9)) * step
            d = round(up - v, 8)
            if 0 < d < step * 0.5:
                deltas[d] += 1
                break
    if not deltas:
        return None
    delta, hits = deltas.most_common(1)[0]
    total = len([v for v in values if v > 0])
    if hits < min_hits or total == 0 or hits / total < 0.10:
        return None
    return {"fee": delta, "hits": hits, "of": total, "share": hits / total}


def repeated_amounts(values: List[float], min_repeat: int = 3) -> List[tuple]:
    """Identical amounts arriving from unrelated addresses — batch automation."""
    c = Counter(round(v, 8) for v in values if v > 0)
    return [(amt, n) for amt, n in c.most_common(5) if n >= min_repeat]


def burst(timestamps: List[int], fraction: float = 0.8) -> Optional[tuple]:
    """(span_seconds, count, start_ts, end_ts) of the tightest burst; None under 5 events."""
    if sum(1 for t in timestamps if t) < 5:
        return None
    return analysis.tightest_window(timestamps, fraction)


# ---------------------------------------------------------------- assessment

def assess(address: str, chain: str = "eth", asset: Optional[dict] = None,
           depth: int = 2, branching: int = 5) -> Dict:
    """Produce a reasoned assessment of an address, with evidence."""
    from crypttrace import verify as verify_mod

    me = chains.norm_addr(address, chain)
    signals: List[Signal] = []
    caveats: List[str] = []

    # --- what the address itself is -----------------------------------
    hit = labels.lookup(address)
    sourced = bool(hit and hit.get("source"))
    if hit:
        kind = hit.get("type", "unknown")
        conf = "high" if sourced else "medium"
        weight = {"sanctioned": 60, "mixer": 45, "scam": 55,
                  "bridge": 10, "exchange": 5}.get(kind, 0)
        signals.append(Signal(
            name="known entity",
            observed=f"address is labelled '{hit['name']}'",
            implication={"sanctioned": "on an international sanctions list",
                         "mixer": "a privacy service that breaks the on-chain trail",
                         "scam": "tied to a recorded theft or fraud",
                         "exchange": "a custodial service that holds customer identity",
                         "bridge": "a cross-chain bridge"}.get(kind, "a known service"),
            confidence=conf, weight=weight,
            evidence={"label": hit["name"], "source": hit.get("source", ""),
                      "source_kind": hit.get("source_kind", "")}))
        if not sourced:
            caveats.append("the label on this address carries no recorded source, "
                           "so it is inherited rather than evidenced")

    # --- flows --------------------------------------------------------
    try:
        rows = chains.transfers(address, chain, 1000, asset=asset)
    except chains.ChainError as e:
        return {"address": address, "chain": chain, "error": str(e),
                "signals": [], "risk": 0, "confidence": "none"}

    inbound = [r for r in rows if r.get("to") == me]
    outbound = [r for r in rows if r.get("from") == me]
    received = sum(r.get("value", 0) for r in inbound)
    sent = sum(r.get("value", 0) for r in outbound)

    # --- automation ----------------------------------------------------
    fee_sig = constant_fee_signature([r.get("value", 0) for r in inbound])
    if fee_sig:
        signals.append(Signal(
            name="automated collection",
            observed=(f"{fee_sig['hits']} of {fee_sig['of']} incoming amounts are a round "
                      f"figure minus exactly {fee_sig['fee']:.8f}"),
            implication="funds were swept by a tool with a hardcoded fee, not moved by owners",
            confidence="high" if fee_sig["share"] > 0.3 else "medium",
            weight=35, evidence=fee_sig))

    b = burst([int(r.get("timestamp") or 0) for r in inbound])
    if b and b[0] > 0:
        span_min = b[0] / 60
        rate = b[1] / max(span_min, 0.01)
        if span_min <= 90 and b[1] >= 20:
            signals.append(Signal(
                name="burst of activity",
                observed=f"{b[1]} transfers arrived within {span_min:.0f} minutes (~{rate:.0f}/min)",
                implication="a rate consistent with automation rather than human activity",
                confidence="high", weight=25,
                evidence={"count": b[1], "span_minutes": round(span_min, 1),
                          "from_ts": b[2], "to_ts": b[3]}))

    rep = repeated_amounts([r.get("value", 0) for r in inbound])
    if rep:
        top = rep[0]
        signals.append(Signal(
            name="repeated amounts",
            observed=f"the exact amount {top[0]} arrived {top[1]} times from different addresses",
            implication="batch processing rather than independent human transfers",
            confidence="medium", weight=10,
            evidence={"repeats": rep[:3]}))

    # --- where the money goes -----------------------------------------
    try:
        onward = chains.flows(address, chain, branching, "out", asset=asset)
    except chains.ChainError:
        onward = []

    exposure = {"mixer": 0.0, "sanctioned": 0.0, "exchange": 0.0, "bridge": 0.0}
    named: Dict[str, str] = {}
    for other, val, _cnt in onward:
        t = labels.type_of(other)
        if t in exposure:
            exposure[t] += val
            named.setdefault(t, labels.label_of(other) or other)

    if exposure["sanctioned"] > 0:
        signals.append(Signal(
            name="sanctions exposure",
            observed=f"{exposure['sanctioned']:.8f} sent to sanctioned wallets ({named['sanctioned']})",
            implication="funds moved to entities on an official sanctions list",
            confidence="high", weight=50,
            evidence={"amount": exposure["sanctioned"], "entity": named["sanctioned"]}))
    if exposure["mixer"] > 0:
        signals.append(Signal(
            name="mixer exposure",
            observed=f"{exposure['mixer']:.8f} sent into {named['mixer']}",
            implication="the on-chain trail is deliberately broken from that point",
            confidence="high", weight=40,
            evidence={"amount": exposure["mixer"], "service": named["mixer"]}))
    if exposure["exchange"] > 0:
        signals.append(Signal(
            name="exchange contact",
            observed=f"{exposure['exchange']:.8f} sent to {named['exchange']}",
            implication="reaches a custodial service that holds the recipient's identity — "
                        "the point where a legal request can work",
            confidence="high", weight=5,
            evidence={"amount": exposure["exchange"], "exchange": named["exchange"]}))
    if exposure["bridge"] > 0:
        signals.append(Signal(
            name="cross-chain movement",
            observed=f"{exposure['bridge']:.8f} sent into {named['bridge']}",
            implication="funds left this chain; the trail continues elsewhere",
            confidence="medium", weight=15,
            evidence={"amount": exposure["bridge"], "bridge": named["bridge"]}))

    # --- address poisoning ----------------------------------------------
    try:
        lured = poisoning.baited_payments(address, chain)
        pairs = poisoning.lookalikes(address, chain)
        spam = poisoning.campaign(address, chain)
    except chains.ChainError:
        lured, pairs, spam = [], [], None
    if lured:
        top = lured[0]
        confirmed = [x for x in lured if x["imitates"]]
        signals.append(Signal(
            name="address poisoning",
            observed=(f"{len(lured)} payer(s) sent real money right after this address lured "
                      f"them ({top['lure']}); largest {top['paid']:.2f} {top['symbol']}"
                      + (f", imitating {confirmed[0]['imitates']}" if confirmed else "")),
            implication="payments made to a look-alike of an address the payer really meant — "
                        "the victim copied this address from their own history",
            confidence="high" if confirmed else "medium", weight=55,
            evidence={"payments": lured[:5]}))
    if spam:
        signals.append(Signal(
            name="poisoning campaign",
            observed=(f"sent {spam['bait_transfers']} zero, dust or counterfeit transfers to "
                      f"{spam['targets']} different wallets"),
            implication="plants itself in strangers' histories — the address-poisoning pattern",
            confidence="high", weight=40, evidence=spam))
    sent_to_fake = [p for p in pairs if p["sent_to_lookalike"] > 0]
    if sent_to_fake:
        p = sent_to_fake[0]
        signals.append(Signal(
            name="paid a look-alike",
            observed=(f"sent {p['sent_to_lookalike']:.2f} to {p['lookalike']}, which imitates "
                      f"{p['genuine']} (same first {p['matching']['prefix']} and last "
                      f"{p['matching']['suffix']} characters)"),
            implication="this wallet was likely the victim of address poisoning",
            confidence=p["confidence"], weight=0, evidence={"pairs": sent_to_fake[:5]}))

    # --- stablecoin issuer freeze ---------------------------------------
    frozen = [e for e in freeze.check(address, chain) if e.get("frozen")]
    if frozen:
        e = frozen[0]
        signals.append(Signal(
            name="frozen by issuer",
            observed=freeze.describe_frozen(e),
            implication="the issuer blocked it — usually at the request of law enforcement "
                        "or under sanctions",
            confidence="high", weight=40, evidence={"freezes": frozen}))

    # --- holding behaviour ---------------------------------------------
    if received > 0 and sent == 0 and len(inbound) >= 3:
        signals.append(Signal(
            name="funds held",
            observed=f"received {received:.8f} across {len(inbound)} transfers, spent nothing",
            implication="proceeds are being held rather than cashed out — "
                        "the window to act is still open",
            confidence="high", weight=0,
            evidence={"received": received, "transfers": len(inbound)}))

    # --- can we trust our own numbers? ---------------------------------
    v = verify_mod.reconcile(address, chain, asset)
    if v["status"] == "mismatch":
        caveats.append("the tool's own totals do not reconcile with the chain — "
                       "treat every figure here as unreliable until explained")
    elif v["status"] == "partial":
        caveats.append("only part of this address's history was read, so amounts are "
                       "a lower bound and absent signals may simply be unseen")
    elif v["status"] == "consistent":
        caveats.append("this chain publishes no independent gross totals, so attribution "
                       "could only be partly cross-checked")

    # --- overall --------------------------------------------------------
    risk = min(100, sum(s.weight for s in signals))
    if v["status"] == "mismatch":
        confidence = "low"
    elif not signals:
        confidence = "low"
    else:
        best = max(CONF_ORDER[s.confidence] for s in signals)
        confidence = {3: "high", 2: "medium", 1: "low"}[best]
        if v["status"] in ("partial", "consistent") and confidence == "high":
            confidence = "medium"

    return {
        "address": address, "chain": chain,
        "risk": risk, "confidence": confidence,
        "assessment": _statement(signals, risk, confidence, hit),
        "signals": [asdict(s) for s in signals],
        "caveats": caveats,
        "verification": {"status": v["status"], "headline": verify_mod.headline(v)},
        "totals": {"received": received, "sent": sent,
                   "inbound": len(inbound), "outbound": len(outbound)},
    }


def _statement(signals: List[Signal], risk: int, confidence: str, hit) -> str:
    """One paragraph a person can read, act on, and argue with."""
    if not signals:
        return ("Nothing in the data collected distinguishes this address. That is not a "
                "clearance — an unlabelled address with unremarkable flows is simply "
                "unknown.")
    names = {s.name for s in signals}
    parts = []
    if hit:
        parts.append(f"This address is a known entity: {hit['name']}.")
    if "automated collection" in names or "burst of activity" in names:
        parts.append("The pattern of incoming funds indicates an automated sweep rather "
                     "than owners moving their own money.")
    if "sanctions exposure" in names:
        parts.append("Funds moved on to sanctioned wallets, which puts this in "
                     "law-enforcement territory.")
    if "mixer exposure" in names:
        parts.append("Part of the value entered a mixer, where on-chain tracing ends.")
    if "exchange contact" in names:
        parts.append("Some value reached a custodial exchange — the one point in this "
                     "chain where identity can realistically be obtained.")
    if "cross-chain movement" in names:
        parts.append("Some value left this chain through a bridge and would need to be "
                     "picked up on the destination network.")
    if "address poisoning" in names:
        parts.append("Money reached this address through address poisoning: it was made to "
                     "look like an address the payer really meant, and planted in their "
                     "history first.")
    if "poisoning campaign" in names:
        parts.append("It sends worthless transfers to many strangers, the way poisoners "
                     "plant look-alike addresses.")
    if "paid a look-alike" in names:
        parts.append("This wallet sent money to a look-alike of an address it had used "
                     "before — the signature of an address-poisoning theft.")
    if "frozen by issuer" in names:
        parts.append("Stablecoins here are frozen by their issuer, which usually follows a "
                     "law-enforcement request or a sanctions listing.")
    if "funds held" in names:
        parts.append("The proceeds have not been spent, so intervention is still possible.")
    parts.append(f"Overall risk {risk}/100, confidence {confidence}.")
    return " ".join(parts)
