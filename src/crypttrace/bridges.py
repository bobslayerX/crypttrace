"""Cross-chain tracing across bridges.

When funds cross a bridge, the on-chain trail on the source chain ends at the
bridge contract, and the money reappears on another chain — there is no free,
deterministic link between the two. This module uses a behavioural heuristic
that catches a large share of real cases:

  Launderers very often bridge to the *same address they control* on the
  destination chain. So after spotting a transfer into a bridge, we search every
  other supported chain for an inbound transfer to the same address, of a
  similar amount (bridges take a fee), shortly afterwards.

A match is a strong *lead*, not proof: amounts and timing can coincide. Results
are reported as likely continuations with the delay and amount so the analyst
can judge. (v1 matches native-coin value; token-bridging and recipient-address
decoding from bridge calldata are natural extensions.)
"""
from typing import List, Dict

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config


def bridge_outflows(address: str, chain: str = "eth") -> List[Dict]:
    """Native transfers from `address` into a labelled bridge contract."""
    me = address.lower()
    outs = []
    for tx in etherscan.get_txs(address, chain, limit=1000):
        if tx.get("from", "").lower() != me:
            continue
        to = tx.get("to", "").lower()
        if labels.type_of(to) != "bridge":
            continue
        val = int(tx.get("value", 0)) / config.WEI
        if val <= 0:
            continue
        outs.append({
            "bridge": labels.label_of(to) or to,
            "bridge_address": to,
            "amount": val,
            "timestamp": int(tx.get("timeStamp", "0")),
            "hash": tx.get("hash", ""),
        })
    return outs


def find_arrivals(address: str, source_chain: str, amount: float, after_ts: int,
                  tol: float = 0.05, window_h: int = 48) -> List[Dict]:
    """Search every other supported chain for an inbound transfer to `address`
    of ~`amount` (within `tol`) within `window_h` hours after `after_ts`."""
    me = address.lower()
    hits = []
    for ch in config.CHAINS:
        if ch == source_chain:
            continue
        try:
            txs = etherscan.get_txs(address, ch, limit=200, sort="asc")
        except etherscan.EtherscanError:
            continue
        for tx in txs:
            if tx.get("to", "").lower() != me:
                continue
            ts = int(tx.get("timeStamp", "0"))
            if ts < after_ts or ts > after_ts + window_h * 3600:
                continue
            val = int(tx.get("value", 0)) / config.WEI
            if val <= 0 or amount <= 0:
                continue
            if abs(val - amount) / amount <= tol:
                hits.append({
                    "chain": ch,
                    "from": tx.get("from", "").lower(),
                    "amount": val,
                    "timestamp": ts,
                    "delay_min": round((ts - after_ts) / 60, 1),
                    "hash": tx.get("hash", ""),
                })
    return hits


def trace_cross(address: str, chain: str = "eth", tol: float = 0.05,
                window_h: int = 48) -> List[Dict]:
    """For each bridge-out from `address`, list likely continuations on other chains."""
    results = []
    for out in bridge_outflows(address, chain):
        arrivals = find_arrivals(address, chain, out["amount"], out["timestamp"],
                                 tol=tol, window_h=window_h)
        results.append({"bridge_out": out, "arrivals": arrivals})
    return results
