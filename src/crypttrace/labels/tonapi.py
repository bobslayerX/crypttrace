"""TON account names from tonapi — exchanges, DEXes and known services.

tonapi names the hot wallets of exchanges ("Bybit 7", "Kucoin 1"), DEX routers
("STON.fi DEX") and services ("Fragment"), and flags scam accounts. That is
the TON equivalent of an explorer's address tags, so it is used the same way:
a label with its source, of kind "explorer-tag".

Two things are deliberately *not* trusted:
- names ending in .ton / .t.me — those are DNS names the owner gave himself
  ("crypto-exch-io.ton", or an impostor's "kucoin-1.ton");
- anything unknown to tonapi stays unknown — no guessing from interfaces alone,
  except that STON.fi / DeDust contracts are DEXes whatever they are called.

Lookups are cached on disk for a week (positive and negative), so a trace pays
for each address once. Only `enrich()` touches the network; `lookup()` reads
the cache, which keeps label lookups cheap everywhere else.
"""
import datetime as dt
import json
import os
import re
import time
from typing import Dict, Iterable, Optional

import requests

from crypttrace import addresses, config
from crypttrace.fetchers import http

API = "https://tonapi.io/v2/accounts/{}"
CACHE = config.DATA_DIR / "tonapi_names.json"
MAX_AGE = 7 * 24 * 3600
_KEY = os.environ.get("TONAPI_KEY")
http.MIN_INTERVAL["tonapi.io"] = 0.12 if _KEY else 1.1

# custodial platforms that hold KYC and can freeze: a deposit there is a lead
_EXCHANGES = re.compile(
    r"\b(binance|bybit|okx|okex|kucoin|htx|huobi|gate(\.io)?|mexc|bitget|kraken|coinbase|"
    r"bitfinex|bingx|bitmart|lbank|whitebit|exmo|coinex|poloniex|crypto\.com|bitpanda|"
    r"bithumb|upbit|cryptobot|crypto bot|xrocket|wallet in telegram|telegram wallet)\b", re.I)

_cache: Optional[Dict[str, dict]] = None


def _load() -> Dict[str, dict]:
    global _cache
    if _cache is None:
        try:
            _cache = json.loads(CACHE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            _cache = {}
    return _cache


def _save() -> None:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(_load(), ensure_ascii=False), encoding="utf-8")
        tmp.replace(CACHE)
    except OSError:
        pass


def classify(account: dict) -> Optional[dict]:
    """A label from one tonapi account record, or None if it names nothing we trust."""
    name = (account.get("name") or "").strip()
    ifaces = " ".join(account.get("interfaces") or [])
    self_named = bool(re.search(r"\.(ton|t\.me)$", name, re.I))
    if account.get("is_scam"):
        return {"name": f"{name or 'account'} (flagged as scam by tonapi)", "type": "scam"}
    if "stonfi" in ifaces or "dedust" in ifaces:
        return {"name": name or "DEX contract", "type": "dex"}
    if not name or self_named:
        return None
    if _EXCHANGES.search(name):
        memo = " (memo required)" if account.get("memo_required") else ""
        return {"name": f"{name}{memo}", "type": "exchange", "memo_required": bool(account.get("memo_required"))}
    return {"name": name, "type": "service"}


def lookup(address: str) -> Optional[dict]:
    """Cached tonapi label for a TON address, without touching the network."""
    key = addresses.ton_friendly(address) or address
    entry = _load().get(key)
    if not entry or not entry.get("label"):
        return None
    return {**entry["label"], "chain": "ton", "source_kind": "explorer-tag",
            "source": f"tonapi account name, fetched {entry.get('day', '')}"}


def enrich(addrs: Iterable[str]) -> None:
    """Fetch tonapi names for addresses not in the cache (or stale)."""
    cache, now, changed = _load(), time.time(), False
    for a in dict.fromkeys(addrs):
        key = addresses.ton_friendly(a or "")
        if not key or now - cache.get(key, {}).get("at", 0) < MAX_AGE:
            continue
        try:
            rec = http.request_json(API.format(key), {}, timeout=20,
                                    headers={"Authorization": f"Bearer {_KEY}"} if _KEY else None)
        except (http.RateLimited, requests.RequestException, ValueError):
            continue
        if not isinstance(rec, dict) or "__status__" in rec:
            continue
        cache[key] = {"at": now, "day": dt.date.today().isoformat(), "label": classify(rec)}
        changed = True
    if changed:
        _save()
