"""First-funder heuristic — the classic on-chain deanonymization primitive.

A wallet can't do anything without gas, and its first gas has to come from
somewhere. Whoever sent a wallet its first incoming ETH "bootstrapped" it.
Following that funding link backward, address by address, very often lands on a
funding hub or — the prize — a centralised-exchange withdrawal, which is a KYC
identification point. Investigators like ZachXBT lean on this constantly to tie
"unrelated" laundering wallets back to a single controller.

Limitation: this uses normal (external) transactions. Wallets first funded by an
internal contract call (some exchanges, disperse tools) need internal-tx data,
a natural next extension.
"""
from typing import Optional, List, Dict

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config


def first_funder(address: str, chain: str = "eth") -> Optional[dict]:
    """Return the first address that funded this wallet (its bootstrapping funder).

    Works on every supported chain. {funder, value, timestamp, hash} or None.
    """
    from crypttrace import chains
    me = address if chain in ("btc", "tron", "sol") else address.lower()
    rows = chains.transfers(address, chain, limit=200, oldest_first=True)
    for r in rows:  # ascending => first match is the earliest funding
        if r.get("to") != me or r.get("value", 0) <= 0:
            continue
        return {
            "funder": r.get("from", ""),
            "value": r.get("value", 0.0),
            "timestamp": str(r.get("timestamp", 0)),
            "hash": r.get("hash", ""),
        }
    return None


def _terminal(address: str) -> bool:
    """A labelled entity worth stopping at (exchange = KYC point, or flagged)."""
    return labels.type_of(address) in ("exchange", "mixer", "sanctioned", "bridge")


def funding_chain(address: str, chain: str = "eth", max_hops: int = 6) -> List[Dict]:
    """Walk the funding link backward: who funded X, who funded that funder, …

    Returns a list of hops, each {address, funder, value, timestamp, funder_type,
    funder_label, terminal}. Stops at a labelled entity, a dead end, or a cycle.
    """
    chain_hops: List[Dict] = []
    seen = {address.lower()}
    current = address.lower()

    for _ in range(max_hops):
        info = first_funder(current, chain)
        if info is None:
            break
        funder = info["funder"]
        hop = {
            "address": current,
            "funder": funder,
            "value": info["value"],
            "timestamp": info["timestamp"],
            "funder_type": labels.type_of(funder),
            "funder_label": labels.label_of(funder),
            "terminal": _terminal(funder),
        }
        chain_hops.append(hop)
        if hop["terminal"] or funder in seen:
            break
        seen.add(funder)
        current = funder

    return chain_hops
