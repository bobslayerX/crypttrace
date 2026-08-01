"""USD price lookups, with graceful offline degradation.

Stablecoins are pinned to $1. Everything else is fetched from CoinGecko
(free, no key) by contract address and cached for the session. If the network
is unavailable, price() returns None and callers simply show '—' for USD.
"""
from typing import Optional, Dict

import requests

# symbols treated as ~$1
_STABLE = {"usdt", "usdc", "dai", "busd", "tusd", "usdp", "gusd", "frax", "lusd"}

# CoinGecko platform id per chain
_PLATFORM = {"eth": "ethereum", "bsc": "binance-smart-chain", "polygon": "polygon-pos",
             "arbitrum": "arbitrum-one", "optimism": "optimistic-ethereum", "base": "base"}
_COINGECKO_NATIVE = {"eth": "ethereum", "bsc": "binancecoin", "polygon": "matic-network",
                     "arbitrum": "ethereum", "optimism": "ethereum", "base": "ethereum",
                     "btc": "bitcoin", "tron": "tron", "sol": "solana"}

_cache: Dict[str, Optional[float]] = {}


def _get_json(url: str, params: dict, timeout: int = 15):
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except (requests.RequestException, ValueError):
        return None


def native_price(chain: str = "eth") -> Optional[float]:
    """USD price of the chain's native coin (ETH, BTC, TRX, SOL, …).

    Unknown chains return None rather than guessing — pricing a BTC balance with
    ETH's price would silently corrupt an investigation.
    """
    key = f"native:{chain}"
    if key in _cache:
        return _cache[key]
    cid = _COINGECKO_NATIVE.get(chain)
    if cid is None:
        _cache[key] = None
        return None
    data = _get_json("https://api.coingecko.com/api/v3/simple/price",
                     {"ids": cid, "vs_currencies": "usd"})
    price = None
    if data and cid in data:
        price = data[cid].get("usd")
    _cache[key] = price
    return price


def token_price(contract: str, chain: str = "eth", symbol: str = "") -> Optional[float]:
    """USD price of an ERC-20 token by contract. Stablecoins short-circuit to $1."""
    if symbol.lower() in _STABLE:
        return 1.0
    key = f"{chain}:{contract.lower()}"
    if key in _cache:
        return _cache[key]
    platform = _PLATFORM.get(chain, "ethereum")
    data = _get_json(f"https://api.coingecko.com/api/v3/simple/token_price/{platform}",
                     {"contract_addresses": contract, "vs_currencies": "usd"})
    price = None
    if data:
        entry = data.get(contract.lower()) or next(iter(data.values()), None)
        if isinstance(entry, dict):
            price = entry.get("usd")
    _cache[key] = price
    return price


def usd(amount: float, price: Optional[float]) -> Optional[float]:
    if price is None:
        return None
    return amount * price


def fmt_usd(value: Optional[float]) -> str:
    """Human-friendly USD string: $1.2M, $340.5K, $12.34, or '—'."""
    if value is None:
        return "—"
    a = abs(value)
    if a >= 1_000_000:
        return f"${value/1_000_000:.2f}M"
    if a >= 1_000:
        return f"${value/1_000:.1f}K"
    return f"${value:.2f}"
