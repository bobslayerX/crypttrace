"""Solana fetcher via public JSON-RPC — no API key required.

Solana has no "list transfers for an address" endpoint: you fetch the address's
recent signatures, then each transaction, and read the parsed instructions. That
means one RPC call per transaction, so this fetcher is slower and intentionally
capped. Set CRYPTTRACE_SOLANA_RPC to use your own (faster) endpoint.
"""
import os
from typing import List, Dict

import requests

from crypttrace import assets

RPC = os.environ.get("CRYPTTRACE_SOLANA_RPC", "https://api.mainnet-beta.solana.com")
LAMPORTS = 1_000_000_000
MAX_TXS = 25  # keep the number of RPC round-trips sane

# mint -> symbol for the tokens crypttrace knows; others show as "SPL"
_KNOWN_MINTS = {t["contract"]: t["symbol"] for t in assets.tokens_for("sol").values()}


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
    meta = tx.get("meta") or {}
    msg = (tx.get("transaction") or {}).get("message") or {}
    instrs = list(msg.get("instructions") or [])
    for inner in meta.get("innerInstructions") or []:
        instrs.extend(inner.get("instructions") or [])

    # An SPL transfer names token *accounts*, not wallets. The token balances in
    # the transaction's metadata say which wallet owns each account, which mint
    # it holds and how many decimals that mint has.
    keys = [k.get("pubkey") if isinstance(k, dict) else k for k in msg.get("accountKeys") or []]
    loaded = meta.get("loadedAddresses") or {}
    if not any(isinstance(k, dict) and k.get("source") == "lookupTable"
               for k in msg.get("accountKeys") or []):
        keys += list(loaded.get("writable") or []) + list(loaded.get("readonly") or [])
    accounts = {}
    for b in (meta.get("preTokenBalances") or []) + (meta.get("postTokenBalances") or []):
        i = b.get("accountIndex")
        if isinstance(i, int) and i < len(keys):
            accounts[keys[i]] = {"owner": b.get("owner") or "", "mint": b.get("mint") or "",
                                 "decimals": (b.get("uiTokenAmount") or {}).get("decimals")}
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
            src = accounts.get(info.get("source", ""), {})
            dst = accounts.get(info.get("destination", ""), {})
            mint = info.get("mint") or src.get("mint") or dst.get("mint") or ""
            decimals = src.get("decimals") if src.get("decimals") is not None else dst.get("decimals")
            amt = info.get("tokenAmount") or {}
            try:
                if amt.get("uiAmountString") or amt.get("uiAmount") is not None:
                    val = float(amt.get("uiAmountString") or amt.get("uiAmount") or 0)
                elif decimals is not None:        # plain "transfer" gives raw base units
                    val = int(info.get("amount") or 0) / (10 ** int(decimals))
                else:
                    continue                      # no way to know the unit: don't guess
            except (TypeError, ValueError):
                continue
            rows.append({
                # the wallets behind the token accounts; the account itself if unknown
                "from": src.get("owner") or info.get("authority") or info.get("source", ""),
                "to": dst.get("owner") or info.get("destination", ""),
                "value": val, "timestamp": ts, "hash": sig,
                "symbol": _KNOWN_MINTS.get(mint, "SPL"),
                "contract": mint or "spl"})       # the mint; keeps token rows apart from SOL
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
