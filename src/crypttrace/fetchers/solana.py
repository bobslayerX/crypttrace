"""Solana fetcher via public JSON-RPC — no API key required.

Solana has no "list transfers for an address" endpoint: you fetch the address's
signatures (page after page), then the transactions, and read the parsed
instructions; failed transactions are skipped — they moved nothing.

The public endpoint sustains about one getTransaction call a second — faster,
and most calls come back 429 with a 10-second wait; JSON-RPC batches fare worse.
So on it transactions are fetched one at a time, paced to that rate, and history
is capped at MAX_TXS = 50 transactions per address. With your own endpoint in
CRYPTTRACE_SOLANA_RPC (e.g. a free Helius or QuickNode key) calls run in parallel
and the cap is 1,000. CRYPTTRACE_SOLANA_MAX_TXS overrides either.
"""
import os
from typing import List, Dict

import requests

from crypttrace import assets

PUBLIC_RPC = "https://api.mainnet-beta.solana.com"
RPC = os.environ.get("CRYPTTRACE_SOLANA_RPC", PUBLIC_RPC)
LAMPORTS = 1_000_000_000
MAX_TXS = int(os.environ.get("CRYPTTRACE_SOLANA_MAX_TXS") or (50 if RPC == PUBLIC_RPC else 1000))
WORKERS = 1 if RPC == PUBLIC_RPC else 8   # calls in flight; the HTTP layer spaces their starts
if RPC == PUBLIC_RPC:
    from crypttrace.fetchers import http as _http
    _http.MIN_INTERVAL["api.mainnet-beta.solana.com"] = 1.1
SIG_PAGE = 1000       # the most getSignaturesForAddress returns at once

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
    """Signatures of successful transactions, newest first, page after page."""
    want = min(limit, MAX_TXS)
    out: List[str] = []
    before = None
    while len(out) < want:
        opts = {"limit": min(SIG_PAGE, want - len(out) + 50)}
        if before:
            opts["before"] = before
        page = _rpc("getSignaturesForAddress", [address, opts]) or []
        if not page:
            break
        out += [s["signature"] for s in page if s.get("signature") and s.get("err") is None]
        before = page[-1].get("signature")
        if len(page) < opts["limit"]:
            break
    return out[:want]


def _transactions(sigs: List[str]) -> List[tuple]:
    """(signature, transaction) for each signature — one cached call each, a few at a time."""
    from concurrent.futures import ThreadPoolExecutor

    def one(sig):
        try:
            return sig, _rpc("getTransaction", [sig, {"encoding": "jsonParsed",
                                                      "maxSupportedTransactionVersion": 1}])
        except SolanaError:
            return sig, None
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        return list(pool.map(one, sigs))


def _parse_tx(sig: str, tx=None) -> List[Dict]:
    if tx is None:
        tx = _rpc("getTransaction", [sig, {"encoding": "jsonParsed",
                                           "maxSupportedTransactionVersion": 1}])
    if not tx or (tx.get("meta") or {}).get("err") is not None:
        return []                               # a failed transaction moved nothing
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
    """Normalized transfer rows from the latest `limit` (at most MAX_TXS) successful transactions."""
    rows: List[Dict] = []
    for sig, tx in _transactions(_signatures(address, limit)):
        if tx:                                  # unreadable ones are skipped, not refetched
            rows.extend(_parse_tx(sig, tx))
    return rows
