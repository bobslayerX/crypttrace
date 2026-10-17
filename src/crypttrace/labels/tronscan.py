"""Tron address tags from Tronscan — exchange wallets and risk warnings.

Tronscan tags exchange hot and cold wallets ("Binance-Cold 1", "OKX-Hot") and
puts red tags on addresses it flags as scams or phishing. Both become labels
of kind "explorer-tag", with Tronscan named as the source; a red tag makes the
address a scam. Grey tags and user feedback are not enough to call an address
anything.

Needs a free API key (TRONSCAN_API_KEY, created in a Tronscan account); without
one nothing is fetched and Tron labels come from the curated set alone.
Lookups are cached on disk for a week; only `enrich()` uses the network.
"""
import datetime as dt
import json
import time
from typing import Dict, Iterable, Optional

import requests

from crypttrace import config
from crypttrace.fetchers import http
from crypttrace.labels.names import EXCHANGES

API = "https://apilist.tronscanapi.com/api/accountv2"
CACHE = config.DATA_DIR / "tronscan_tags.json"
MAX_AGE = 7 * 24 * 3600
http.MIN_INTERVAL["apilist.tronscanapi.com"] = 0.25
_cache: Optional[Dict[str, dict]] = None


def _key() -> Optional[str]:
    return config.env("TRONSCAN_API_KEY") or None


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
    """A label from one Tronscan account record, or None if it names nothing."""
    red = (account.get("redTag") or "").strip()
    tag = (account.get("publicTag") or account.get("addressTag") or "").strip()
    if red:
        return {"name": f"{tag or red} (Tronscan: {red})", "type": "scam"}
    if not tag:
        return None
    if EXCHANGES.search(tag.replace("-", " ")):
        return {"name": tag, "type": "exchange"}
    return {"name": tag, "type": "service"}


def lookup(address: str) -> Optional[dict]:
    """Cached Tronscan label, without touching the network."""
    entry = _load().get(address)
    if not entry or not entry.get("label"):
        return None
    return {**entry["label"], "chain": "tron", "source_kind": "explorer-tag",
            "source": f"Tronscan address tag, fetched {entry.get('day', '')}"}


def enrich(addrs: Iterable[str]) -> None:
    """Fetch Tronscan tags for addresses not in the cache (or stale). No key, no fetch."""
    key = _key()
    if not key:
        return
    cache, now, changed = _load(), time.time(), False
    for a in dict.fromkeys(addrs):
        if not a or not a.startswith("T") or len(a) != 34 or now - cache.get(a, {}).get("at", 0) < MAX_AGE:
            continue
        try:
            rec = http.request_json(API, {"address": a}, timeout=20, headers={"TRON-PRO-API-KEY": key})
        except (http.RateLimited, requests.RequestException, ValueError):
            continue
        if not isinstance(rec, dict) or "__status__" in rec:
            continue
        cache[a] = {"at": now, "day": dt.date.today().isoformat(), "label": classify(rec)}
        changed = True
    if changed:
        _save()
