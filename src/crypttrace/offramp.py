"""Off-ramp detection — spotting exchange deposit addresses.

When laundered funds reach a centralised exchange, they almost never land on the
exchange's labelled hot wallet directly. They land on a per-user *deposit
address* the exchange generated, which then forwards the funds inward to the hot
wallet. There are millions of these, so they're not in any label list — but they
give themselves away by behaviour: a deposit address receives money and sends
almost all of it onward to one known exchange wallet.

Detecting them turns a plain "⚪ unknown wallet" into "→ Binance deposit address",
i.e. the cash-out point — the exact place an investigation hands off to a legal
request (the exchange holds the depositor's KYC).
"""
from typing import Optional

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config


def detect(address: str, chain: str = "eth", threshold: float = 0.6) -> Optional[dict]:
    """Is `address` acting as a deposit/forwarding address for a known exchange?

    Returns {exchange, exchange_address, forwarded, out_total, fraction} when at
    least `threshold` of outgoing value goes to labelled exchange wallets,
    otherwise None.
    """
    me = address.lower()
    txs = etherscan.get_txs(address, chain, limit=1000)  # cached; shared with trace
    out_total = 0.0
    to_exchange = {}  # exchange_addr -> value
    for tx in txs:
        if tx.get("from", "").lower() != me:
            continue
        to = tx.get("to", "").lower()
        if not to:
            continue
        val = int(tx.get("value", 0)) / config.WEI
        out_total += val
        if labels.type_of(to) == "exchange":
            to_exchange[to] = to_exchange.get(to, 0.0) + val

    if out_total <= 0 or not to_exchange:
        return None

    forwarded = sum(to_exchange.values())
    fraction = forwarded / out_total
    if fraction < threshold:
        return None

    best = max(to_exchange, key=to_exchange.get)
    return {
        "exchange": labels.label_of(best),
        "exchange_address": best,
        "forwarded": forwarded,
        "out_total": out_total,
        "fraction": fraction,
    }
