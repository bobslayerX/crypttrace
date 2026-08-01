"""Solana fetcher via public JSON-RPC — no API key required.

Solana has no "list transfers for an address" endpoint: you fetch the address's
recent signatures, then each transaction, and read the parsed instructions. That
means one RPC call per transaction, so this fetcher is slower and intentionally
capped. Set CRYPTTRACE_SOLANA_RPC to use your own (faster) endpoint.
"""
import os
from typing import List, Dict

import requests

RPC = os.environ.get("CRYPTTRACE_SOLANA_RPC", "https://api.mainnet-beta.solana.com")
LAMPORTS = 1_000_000_000
MAX_TXS = 25  # keep the number of RPC round-trips sane


class SolanaError(RuntimeError):
    pass


def _rpc(method: str, params: list, timeout: int = 30):
    """Cached, throttled JSON-RPC call."""
    import json as _json
    from crypttrace.fetchers import http
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    key = f"sol:{method}:{_json.dumps(params, sort_keys=True, default=str)}"
    try:
        j = http.request_json(RPC, body=body, cache_key=key, timeout=timeout)
    except http.RateLimited as e:
        raise SolanaError(str(e) + " (tip: set CRYPTTRACE_SOLANA_RPC to your own endpoint)")
    except requests.RequestException as e:
        raise SolanaError(f"Solana RPC request failed: {e}")
    except ValueError as e:
        raise SolanaError(f"bad response from Solana RPC: {e}")
    if not isinstance(j, dict):
        return None
    if "error" in j:
        raise SolanaError(f"Solana RPC error: {j['error'].get('message')}")
    return j.get("result")


def balance(address: str) -> float:
    res = _rpc("getBalance", [address])
    if isinstance(res, dict):
        return (res.get("value") or 0) / LAMPORTS
    return 0.0


def _signatures(address: str, limit: int) -> List[str]:
    res = _rpc("getSignaturesForAddress", [address, {"limit": min(limit, MAX_TXS)}]) or []
    return [s.get("signature") for s in res if s.get("signature")]


def _parse_tx(sig: str) -> List[Dict]:
    tx = _rpc("getTransaction", [sig, {"encoding": "jsonParsed",
                                       "maxSupportedTransactionVersion": 0}])
    if not tx:
        return []
    ts = int(tx.get("blockTime") or 0)
    rows = []
    msg = (tx.get("transaction") or {}).get("message") or {}
    instrs = list(msg.get("instructions") or [])
    for inner in (tx.get("meta") or {}).get("innerInstructions") or []:
        instrs.extend(inner.get("instructions") or [])
    for ins in instrs:
        parsed = ins.get("parsed")
        if not isinstance(parsed, dict):
            continue
        info = parsed.get("info") or {}
        ptype = parsed.get("type")
        prog = ins.get("program")
        if prog == "system" and ptype in ("transfer", "transferWithSeed"):
            rows.append({"from": info.get("source", ""), "to": info.get("destination", ""),
                         "value": (info.get("lamports") or 0) / LAMPORTS,
                         "timestamp": ts, "hash": sig, "symbol": "SOL"})
        elif prog == "spl-token" and ptype in ("transfer", "transferChecked"):
            amt = info.get("tokenAmount") or {}
            try:
                val = float(amt.get("uiAmountString") or amt.get("uiAmount") or info.get("amount") or 0)
            except (TypeError, ValueError):
                val = 0.0
            rows.append({"from": info.get("source", "") or info.get("authority", ""),
                         "to": info.get("destination", ""), "value": val,
                         "timestamp": ts, "hash": sig, "symbol": "SPL"})
    return rows


def transfers(address: str, limit: int = MAX_TXS) -> List[Dict]:
    """Normalized transfer rows. Note: capped at MAX_TXS transactions."""
    rows: List[Dict] = []
    for sig in _signatures(address, limit):
        try:
            rows.extend(_parse_tx(sig))
        except SolanaError:
            continue
    return rows
