"""Etherscan (v2 multichain) fetcher with a small SQLite cache.

The blockchain is public: every transaction is queryable. This module wraps the
Etherscan API and caches responses so repeated traces don't re-hit the API.
"""
import json
import sqlite3
import time
from typing import List, Dict, Optional

import requests

from crypttrace import config


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.CACHE_DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cache ("
        "  key TEXT PRIMARY KEY,"
        "  ts INTEGER,"
        "  payload TEXT)"
    )
    return conn


def _cache_get(key: str, max_age: int = 3600) -> Optional[dict]:
    conn = _db()
    row = conn.execute("SELECT ts, payload FROM cache WHERE key=?", (key,)).fetchone()
    conn.close()
    if not row:
        return None
    ts, payload = row
    if time.time() - ts > max_age:
        return None
    return json.loads(payload)


def _cache_put(key: str, payload: dict) -> None:
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO cache(key, ts, payload) VALUES (?,?,?)",
        (key, int(time.time()), json.dumps(payload)),
    )
    conn.commit()
    conn.close()


class EtherscanError(RuntimeError):
    pass


MIN_INTERVAL = 0.22        # the free plan allows 5 calls a second
_last_call = 0.0


def _call(chain: str, params: Dict[str, str], cache_age: int = 3600, _tries: int = 0) -> dict:
    if chain not in config.CHAINS:
        raise EtherscanError(f"unsupported chain '{chain}'. Options: {list(config.CHAINS)}")
    if not config.ETHERSCAN_API_KEY:
        raise EtherscanError(
            "No API key. Get a free one at https://etherscan.io/myapikey "
            "then run: export ETHERSCAN_API_KEY=xxxx"
        )
    q = {
        "chainid": config.CHAINS[chain],
        "apikey": config.ETHERSCAN_API_KEY,
        **params,
    }
    key = f"{chain}:" + "&".join(f"{k}={v}" for k, v in sorted(q.items()) if k != "apikey")
    from crypttrace.fetchers import http
    cached = None if http.FRESH else _cache_get(key, cache_age)
    if cached is not None:
        return cached

    global _last_call
    wait = MIN_INTERVAL - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()
    resp = requests.get(config.ETHERSCAN_BASE, params=q, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    # status "0" with "No transactions found" is a valid empty result, not an error
    if data.get("status") == "0" and "No transactions" not in str(data.get("message", "")):
        # rate-limit or bad key etc.
        if "rate limit" in str(data.get("result", "")).lower() and _tries < 4:
            time.sleep(1 + _tries)
            return _call(chain, params, cache_age, _tries + 1)
        # otherwise return as-is; caller handles empty
    _cache_put(key, data)
    return data


def get_balance(address: str, chain: str = "eth") -> float:
    data = _call(chain, {"module": "account", "action": "balance",
                         "address": address, "tag": "latest"})
    try:
        return int(data["result"]) / config.WEI
    except (KeyError, ValueError):
        return 0.0


def get_txs(address: str, chain: str = "eth", limit: int = 1000,
            sort: str = "desc") -> List[dict]:
    """Normal (native-coin) transactions. sort='desc' (newest first) or 'asc' (oldest first)."""
    data = _call(chain, {
        "module": "account", "action": "txlist", "address": address,
        "startblock": "0", "endblock": "99999999",
        "page": "1", "offset": str(limit), "sort": sort,
    })
    result = data.get("result")
    return result if isinstance(result, list) else []


def get_internal_txs(address: str, chain: str = "eth", limit: int = 1000,
                     sort: str = "desc") -> List[dict]:
    """Internal transactions: the native coin a contract sent or received as part of a call
    (a mixer or exchange withdrawal, ETH back from a DEX swap, a multisig payout)."""
    data = _call(chain, {
        "module": "account", "action": "txlistinternal", "address": address,
        "startblock": "0", "endblock": "99999999",
        "page": "1", "offset": str(limit), "sort": sort,
    })
    result = data.get("result")
    return result if isinstance(result, list) else []


def get_token_txs(address: str, chain: str = "eth", limit: int = 1000) -> List[dict]:
    """ERC-20 token transfers, newest first."""
    data = _call(chain, {
        "module": "account", "action": "tokentx", "address": address,
        "startblock": "0", "endblock": "99999999",
        "page": "1", "offset": str(limit), "sort": "desc",
    })
    result = data.get("result")
    return result if isinstance(result, list) else []
