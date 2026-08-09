"""Self-verification: check the tool's own arithmetic against the chain.

A forensics tool that quietly miscounts is worse than no tool — its output
looks authoritative and gets pasted into reports. This module re-derives the
totals from what we parsed and compares them with the figures the chain index
reports independently, then says plainly whether the numbers agree.

It catches the two failure modes that matter:

  * **wrong maths** — e.g. crediting one wallet with funds a hundred others
    supplied, which is a real bug this tool once had;
  * **incomplete history** — when an address has more transactions than were
    fetched, so a conclusion is drawn from a slice rather than the whole
    record. That one is dangerous precisely because nothing looks broken.
"""
from typing import Dict, List, Optional

from crypttrace import chains
from crypttrace.fetchers import bitcoin

# how far computed and reported totals may drift before we complain
REL_TOLERANCE = 0.005     # 0.5%
ABS_TOLERANCE = 1e-6


def _within(a: float, b: float) -> bool:
    if a is None or b is None:
        return True
    diff = abs(a - b)
    return diff <= ABS_TOLERANCE or diff <= max(abs(a), abs(b)) * REL_TOLERANCE


def reconcile(address: str, chain: str = "btc", asset: Optional[dict] = None,
              limit: int = 1000) -> Dict:
    """Compare our parsed totals with the chain's own aggregates."""
    me = chains.norm_addr(address, chain)
    notes: List[str] = []

    try:
        rows = chains.transfers(address, chain, limit, asset=asset)
    except chains.ChainError as e:
        return {"status": "unavailable", "notes": [str(e)], "address": address,
                "chain": chain, "analysed": 0}

    got_in = sum(r["value"] for r in rows if r.get("to") == me)
    got_out = sum(r["value"] for r in rows if r.get("from") == me)

    # Miner fees are spent from the address but never arrive anywhere, so the
    # chain's "sent" figure exceeds what recipients received by exactly the fees.
    # Count each transaction's fee once, no matter how many outputs it had.
    fees_by_tx = {}
    for r in rows:
        if r.get("from") == me and "fee_share" in r:
            fees_by_tx[r.get("hash", "")] = r["fee_share"]
    fees = sum(fees_by_tx.values())

    ref_in = ref_out = ref_balance = None
    ref_tx = None

    if chain == "btc" and asset is None:
        try:
            s = bitcoin.stats(address)
            ref_in, ref_out = s["received"], s["sent"]
            ref_balance, ref_tx = s["balance"], s["tx_count"]
        except bitcoin.BitcoinError as e:
            notes.append(f"chain totals unavailable: {e}")
    else:
        try:
            ref_balance = chains.balance(address, chain)
        except chains.ChainError as e:
            notes.append(f"balance unavailable: {e}")

    # --- completeness -------------------------------------------------
    complete = True
    if ref_tx is not None:
        # rows are per-transfer, a tx can produce several — compare loosely
        if ref_tx > limit:
            complete = False
            notes.append(f"address has {ref_tx} transactions on chain but only "
                         f"{limit} were fetched — this is a partial view")
    elif len(rows) >= limit:
        complete = False
        notes.append(f"hit the {limit}-transfer fetch limit — history may be truncated")

    # --- arithmetic ---------------------------------------------------
    checks = []
    if ref_in is not None:
        ok = _within(got_in, ref_in) or not complete
        checks.append(("received", got_in, ref_in, ok))
    if ref_out is not None:
        # compare like with like: what recipients got, plus the fees we paid
        sent_incl_fees = got_out + fees
        ok = _within(sent_incl_fees, ref_out) or not complete
        checks.append(("sent (incl. fees)", sent_incl_fees, ref_out, ok))
        if fees > 0:
            notes.append(f"of which {fees:.8f} went to miner fees across "
                         f"{len(fees_by_tx)} transaction(s) — recipients received "
                         f"{got_out:.8f}")
    if ref_in is None and ref_balance is not None and asset is None and complete:
        # no aggregate feed: fall back to net vs balance (fees make it inexact)
        net = got_in - got_out
        ok = abs(net - ref_balance) <= max(0.01, abs(ref_balance) * 0.02)
        checks.append(("net vs balance", net, ref_balance, ok))
        if not ok:
            notes.append("net flow differs from the current balance; on account-based "
                         "chains gas costs explain small gaps, large ones do not")

    failed = [c for c in checks if not c[3]]
    strong = ref_in is not None or ref_out is not None   # gross totals from the chain
    if failed:
        status = "mismatch"
        for name, got, ref, _ in failed:
            notes.append(f"{name}: computed {got:.8f}, chain reports {ref:.8f} "
                         f"(off by {abs(got-ref):.8f})")
    elif not complete:
        status = "partial"
    elif checks and strong:
        status = "verified"
    elif checks:
        # only the balance reconciled: weaker evidence, so don't claim more
        status = "consistent"
        notes.append("this chain publishes no independent gross totals, so only the "
                     "net balance could be checked — per-counterparty attribution "
                     "is not cross-verified")
    else:
        status = "unchecked"
        notes.append("no independent totals available for this chain — "
                     "figures could not be cross-checked")

    return {
        "address": address, "chain": chain, "status": status,
        "analysed": len(rows), "chain_tx_count": ref_tx, "complete": complete,
        "computed_received": got_in, "chain_received": ref_in,
        "computed_sent": got_out, "chain_sent": ref_out, "fees": fees,
        "chain_balance": ref_balance,
        "checks": [{"name": n, "computed": g, "chain": r, "ok": o} for n, g, r, o in checks],
        "notes": notes,
    }


def headline(v: Dict) -> str:
    """One line a human can act on."""
    return {
        "verified": "Verified — gross totals match the chain independently.",
        "consistent": "Consistent — the balance reconciles, but this chain offers no "
                      "independent gross totals, so attribution is only partly checked.",
        "partial": "Partial view — only some of this address's history was read, "
                   "so totals are a floor, not the whole picture.",
        "mismatch": "MISMATCH — the computed totals disagree with the chain. "
                    "Do not rely on this output until it is explained.",
        "unchecked": "Not cross-checked — no independent totals for this chain.",
        "unavailable": "Could not reach the chain to verify.",
    }.get(v.get("status"), "Unknown verification state.")
