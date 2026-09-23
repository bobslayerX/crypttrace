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
from typing import List, Optional

from crypttrace import assets, chains
from crypttrace.labels import labels

# Where thefts mostly move as stablecoins, a deposit address sweeps those rather
# than the native coin (on Tron it may never send TRX at all).
STABLECOIN_CHAINS = {"tron": ("usdt", "usdc"), "sol": ("usdc", "usdt")}


def _one(address: str, chain: str, threshold: float, asset: Optional[dict]) -> Optional[dict]:
    me = chains.norm_addr(address, chain)
    rows = chains.transfers(address, chain, 1000, asset=asset)   # stored; shared with trace
    out_total = 0.0
    to_exchange = {}  # exchange_addr -> value
    for r in rows:
        to = r.get("to") or ""
        if r.get("from") != me or not to:
            continue
        val = r.get("value", 0) or 0
        out_total += val
        # sending *into* another customer's deposit address is a cash-out by
        # this wallet, not evidence that this wallet is itself a deposit address
        if labels.type_of(to) == "exchange" and not labels.is_deposit(to):
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
        "company": labels.company(labels.label_of(best)),
        "exchange_address": best,
        "forwarded": forwarded,
        "out_total": out_total,
        "fraction": fraction,
        "symbol": asset["symbol"] if asset else chains.symbol(chain),
    }


def detect(address: str, chain: str = "eth", threshold: float = 0.6,
           asset: Optional[dict] = None, stablecoins: bool = True) -> Optional[dict]:
    """Is `address` acting as a deposit/forwarding address for a known exchange?

    Returns {exchange, exchange_address, forwarded, out_total, fraction, symbol}
    when at least `threshold` of outgoing value (in one asset) goes to labelled
    exchange wallets, otherwise None. Checks `asset` if given; otherwise the
    native coin and, on Tron and Solana, their stablecoins.
    """
    tries: List[Optional[dict]] = [asset]
    if asset is None and stablecoins:
        tries += [assets.resolve_asset(s, chain) for s in STABLECOIN_CHAINS.get(chain, ())]
    for a in tries:
        hit = _one(address, chain, threshold, a)
        if hit:
            return hit
    return None
