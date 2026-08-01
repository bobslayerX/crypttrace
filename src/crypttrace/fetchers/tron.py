"""Tron fetcher via TronGrid — no API key required for basic use.

Tron matters for victim cases: a very large share of everyday scams (romance
scams, fake investment platforms, "pig butchering") move USDT-TRC20 on Tron
because fees are near zero.

Tron uses an account model like EVM, but the API returns addresses in hex
(41-prefixed) for native transfers, so they're converted to the familiar base58
"T..." form here.
"""
import hashlib
from typing import List, Dict

import requests

BASE = "https://api.trongrid.io"
SUN = 1_000_000  # 1 TRX
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class TronError(RuntimeError):
    pass


def hex_to_base58(h: str) -> str:
    """Convert a Tron hex address (41…) to base58check (T…)."""
    if not h:
        return ""
    if h.startswith("T"):  # already base58
        return h
    if h.startswith("0x"):
        h = h[2:]
    try:
        b = bytes.fromhex(h)
    except ValueError:
        return h
    if len(b) == 20:
        b = b"\x41" + b
    chk = hashlib.sha256(hashlib.sha256(b).digest()).digest()[:4]
    b = b + chk
    n = int.from_bytes(b, "big")
    s = ""
    while n > 0:
        n, r = divmod(n, 58)
        s = _B58[r] + s
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return "1" * pad + s


def _get(path: str, params: dict = None, timeout: int = 30):
    """Cached, throttled GET. Set TRONGRID_API_KEY for a higher rate limit."""
    import os
    from crypttrace.fetchers import http
    headers = {}
    key = os.environ.get("TRONGRID_API_KEY")
    if key:
        headers["TRON-PRO-API-KEY"] = key
    try:
        data = http.request_json(f"{BASE}{path}", params or {},
                                 timeout=timeout, headers=headers or None)
    except http.RateLimited as e:
        raise TronError(str(e))
    except requests.RequestException as e:
        raise TronError(f"TronGrid request failed: {e}")
    except ValueError as e:
        raise TronError(f"bad response from TronGrid: {e}")
    if isinstance(data, dict) and "__status__" in data:
        return {"data": []}
    return data


def balance(address: str) -> float:
    d = _get(f"/v1/accounts/{address}")
    data = d.get("data") or []
    if not data:
        return 0.0
    return (data[0].get("balance") or 0) / SUN


def _native(address: str, limit: int) -> List[Dict]:
    d = _get(f"/v1/accounts/{address}/transactions", {"limit": min(limit, 200)})
    rows = []
    for tx in d.get("data", []) or []:
        try:
            c = (tx.get("raw_data", {}).get("contract") or [])[0]
            if c.get("type") != "TransferContract":
                continue
            v = c["parameter"]["value"]
            frm = hex_to_base58(v.get("owner_address", ""))
            to = hex_to_base58(v.get("to_address", ""))
            amt = (v.get("amount") or 0) / SUN
        except (KeyError, IndexError, TypeError):
            continue
        if amt <= 0:
            continue
        rows.append({"from": frm, "to": to, "value": amt,
                     "timestamp": int((tx.get("block_timestamp") or 0) / 1000),
                     "hash": tx.get("txID", ""), "symbol": "TRX"})
    return rows


def token_transfers(address: str, limit: int = 200) -> List[Dict]:
    """TRC20 transfers (USDT and friends) — already base58 in the API."""
    d = _get(f"/v1/accounts/{address}/transactions/trc20", {"limit": min(limit, 200)})
    rows = []
    for t in d.get("data", []) or []:
        info = t.get("token_info") or {}
        dec = int(info.get("decimals") or 6)
        try:
            val = int(t.get("value") or 0) / (10 ** dec)
        except (ValueError, TypeError):
            continue
        rows.append({"from": t.get("from", ""), "to": t.get("to", ""), "value": val,
                     "timestamp": int((t.get("block_timestamp") or 0) / 1000),
                     "hash": t.get("transaction_id", ""),
                     "symbol": info.get("symbol", "TRC20"),
                     "contract": (info.get("address") or "").lower()})
    return rows


def transfers(address: str, limit: int = 200) -> List[Dict]:
    """Native TRX transfers (use token_transfers for USDT-TRC20)."""
    return _native(address, limit)
