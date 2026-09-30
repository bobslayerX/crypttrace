"""TON fetcher via toncenter's v3 indexer — no API key required for basic use.

TON matters for the same reason Tron does: USDT on TON is cheap to move and is
built into Telegram's wallet, so scams that start in a Telegram chat end here.

Every address comes back from the indexer in the raw "0:<hex>" form and is
rewritten into the canonical "UQ…" spelling (see addresses.ton_friendly), so it
matches what wallets show, the labels, and what a victim pastes. Jetton
transfers (USDT and friends) are reported between the owners' wallets, not the
per-owner jetton-wallet contracts that actually hold the tokens.

The keyless endpoint allows about one request per second; set TONCENTER_API_KEY
for more.
"""
import base64
import os
from typing import Dict, List, Optional

import requests

from crypttrace import addresses, assets
from crypttrace.fetchers import http

BASE = "https://toncenter.com/api/v3"
NANO = 1_000_000_000
# page sizes toncenter accepts (checked live): fewer pages matter at ~1 request/second
TX_PAGE, JETTON_PAGE = 500, 1000
_KEY = os.environ.get("TONCENTER_API_KEY")
http.MIN_INTERVAL["toncenter.com"] = 0.12 if _KEY else 1.1

# jetton master (raw, lower-case) -> what the token calls itself, starting with the ones we know
_META: Dict[str, dict] = {t["contract"]: {"decimals": t.get("decimals", 9), "symbol": t["symbol"],
                                          "name": "", "scam": False}
                          for t in assets.tokens_for("ton").values()}


class TonError(RuntimeError):
    pass


def _get(path: str, params: Optional[dict] = None, timeout: int = 30) -> dict:
    headers = {"X-API-Key": _KEY} if _KEY else None
    try:
        data = http.request_json(f"{BASE}{path}", params or {}, timeout=timeout, headers=headers)
    except http.RateLimited as e:
        raise TonError(str(e) + " (tip: set TONCENTER_API_KEY for a higher limit)")
    except requests.RequestException as e:
        raise TonError(f"toncenter request failed: {e}")
    except ValueError as e:
        raise TonError(f"bad response from toncenter: {e}")
    if isinstance(data, dict) and "__status__" in data:
        raise TonError(f"toncenter answered HTTP {data['__status__']}")
    return data if isinstance(data, dict) else {}


def _pages(path: str, key: str, params: dict, limit: int, page: int) -> List[dict]:
    items: List[dict] = []
    offset = 0
    while len(items) < limit:
        n = min(page, limit - len(items))
        batch = _get(path, dict(params, limit=n, offset=offset, sort="desc")).get(key) or []
        items += batch
        if len(batch) < n:
            break
        offset += n
    return items


def _addr(raw: Optional[str]) -> str:
    return addresses.ton_friendly(raw or "") or (raw or "")


def _hex(tx_hash: str) -> str:
    """toncenter gives base64 hashes; explorers link by hex."""
    try:
        return base64.b64decode(tx_hash).hex()
    except (ValueError, TypeError):
        return tx_hash or ""


def balance(address: str) -> float:
    d = _get("/account", {"address": address})
    return int(d.get("balance") or 0) / NANO


def transfers(address: str, limit: int = 1000) -> List[Dict]:
    """TON moved in and out of `address`: its incoming message and outgoing ones."""
    me = _addr(address)
    rows = []
    for tx in _pages("/transactions", "transactions", {"account": address}, limit, TX_PAGE):
        ts, h = int(tx.get("now") or 0), _hex(tx.get("hash", ""))
        msgs = [tx.get("in_msg") or {}] + list(tx.get("out_msgs") or [])
        for m in msgs:
            src, dst = m.get("source"), m.get("destination")
            value = int(m.get("value") or 0) / NANO
            if not src or not dst or value <= 0:    # external messages carry no value
                continue
            src, dst = _addr(src), _addr(dst)
            if me not in (src, dst):
                continue
            # the sender's and the receiver's transactions have different hashes;
            # the message hash is the same on both sides (the store keys on it)
            rows.append({"from": src, "to": dst, "value": value, "timestamp": ts,
                         "hash": h, "symbol": "TON", "msg_hash": _hex(m.get("hash") or "")})
    return rows


def _meta(master: str) -> Optional[dict]:
    """Decimals, symbol, name and the indexer's scam flag for a jetton master."""
    if master not in _META:
        try:
            d = _get("/jetton/masters", {"address": master, "limit": 1})
            content = ((d.get("jetton_masters") or [{}])[0].get("jetton_content")) or {}
            # off-chain metadata (a URI) is resolved by the indexer into "metadata"
            info = next((i for m in (d.get("metadata") or {}).values()
                         for i in (m.get("token_info") or []) if i.get("type") == "jetton_masters"), {})
            _META[master] = {
                "decimals": int(content.get("decimals") or (info.get("extra") or {}).get("decimals")
                                or 9),                      # TEP-64 default is 9
                "symbol": info.get("symbol") or content.get("symbol") or "JETTON",
                "name": info.get("name") or content.get("name") or "",
                "scam": bool(info.get("is_scam")),
            }
        except (TonError, ValueError, TypeError):
            return None
    return _META[master]


def jetton_transfers(address: str, limit: int = 1000) -> List[Dict]:
    """Jetton (token) transfers to and from `address`, between owner wallets."""
    rows = []
    for t in _pages("/jetton/transfers", "jetton_transfers", {"owner_address": address}, limit, JETTON_PAGE):
        if t.get("aborted"):
            continue
        master = (t.get("jetton_master") or "").lower()
        meta = _meta(master)
        if meta is None:
            continue                                # unknown unit: don't guess
        try:
            value = int(t.get("amount") or 0) / (10 ** meta["decimals"])
        except (ValueError, TypeError):
            continue
        rows.append({"from": _addr(t.get("source")), "to": _addr(t.get("destination")),
                     "value": value, "timestamp": int(t.get("transaction_now") or 0),
                     "hash": _hex(t.get("transaction_hash", "")),
                     "symbol": meta["symbol"], "name": meta["name"], "contract": master,
                     "flagged": meta["scam"]})
    return rows
