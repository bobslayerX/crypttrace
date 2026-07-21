"""Asset registry + normalized token-transfer helpers.

Lets the tracer follow a specific asset (native ETH or an ERC-20 token) and
converts raw on-chain integer amounts into human units using each transfer's
declared decimals.
"""
from typing import Optional, List, Dict

from crypttrace.fetchers import etherscan

# Common ERC-20 tokens by symbol -> mainnet contract (lowercased).
# Users can also pass a raw contract address to --asset.
TOKENS: Dict[str, dict] = {
    "usdt": {"contract": "0xdac17f958d2ee523a2206206994597c13d831ec7", "symbol": "USDT", "stable": True},
    "usdc": {"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "symbol": "USDC", "stable": True},
    "dai":  {"contract": "0x6b175474e89094c44da98b954eedeac495271d0f", "symbol": "DAI", "stable": True},
    "busd": {"contract": "0x4fabb145d64652a948d72533023f6e7a623c7c53", "symbol": "BUSD", "stable": True},
    "weth": {"contract": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "symbol": "WETH", "stable": False},
    "wbtc": {"contract": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "symbol": "WBTC", "stable": False},
}


def resolve_asset(asset: Optional[str]) -> Optional[dict]:
    """Turn a --asset value into an asset descriptor.

    None or 'eth' -> None (native coin). A known symbol or a 0x contract ->
    {contract, symbol, stable}.
    """
    if asset is None or asset.lower() in ("eth", "native"):
        return None
    a = asset.lower()
    if a in TOKENS:
        return dict(TOKENS[a])
    if a.startswith("0x") and len(a) == 42:
        return {"contract": a, "symbol": asset.upper()[:8], "stable": False}
    raise ValueError(f"Unknown asset '{asset}'. Use eth, a known symbol "
                     f"({', '.join(TOKENS)}), or a 0x contract address.")


def _norm(tx: dict) -> dict:
    """Normalize one token-transfer row to decimal-adjusted float value."""
    try:
        dec = int(tx.get("tokenDecimal") or 18)
    except ValueError:
        dec = 18
    try:
        val = int(tx.get("value", 0)) / (10 ** dec)
    except ValueError:
        val = 0.0
    return {
        "from": tx.get("from", "").lower(),
        "to": tx.get("to", "").lower(),
        "value": val,
        "symbol": tx.get("tokenSymbol", "?"),
        "contract": tx.get("contractAddress", "").lower(),
        "timeStamp": tx.get("timeStamp", "0"),
        "hash": tx.get("hash", ""),
    }


def token_transfers(address: str, chain: str, contract: Optional[str] = None) -> List[dict]:
    """Normalized ERC-20 transfers for an address, optionally one token only."""
    rows = [_norm(t) for t in etherscan.get_token_txs(address, chain, limit=1000)]
    if contract:
        c = contract.lower()
        rows = [r for r in rows if r["contract"] == c]
    return rows


def token_holdings(address: str, chain: str) -> List[dict]:
    """Approximate current holdings from transfer history (net in - out per token)."""
    me = address.lower()
    agg: Dict[str, dict] = {}
    for r in token_transfers(address, chain):
        key = r["contract"]
        rec = agg.setdefault(key, {"symbol": r["symbol"], "contract": key, "net": 0.0, "txs": 0})
        if r["to"] == me:
            rec["net"] += r["value"]
        if r["from"] == me:
            rec["net"] -= r["value"]
        rec["txs"] += 1
    holdings = [h for h in agg.values() if h["net"] > 1e-9]
    return sorted(holdings, key=lambda h: h["net"], reverse=True)
