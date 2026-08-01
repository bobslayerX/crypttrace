"""Shared HTTP layer for the non-EVM fetchers: caching, throttling, 429 backoff.

Tracing walks many addresses, and each hop is an API call. Free endpoints
(TronGrid, mempool.space, public Solana RPC) rate-limit aggressively, so this
module:

  * caches responses in the same SQLite file the Etherscan fetcher uses, so a
    re-run — or an address seen twice in one trace — costs nothing;
  * spaces requests per host so we don't trip limits in the first place;
  * retries with exponential backoff when a 429 happens anyway.
"""
import json
import sqlite3
import threading
import time
from typing import Optional
from urllib.parse import urlencode, urlparse

import requests

from crypttrace import config

# minimum seconds between calls to the same host
MIN_INTERVAL = {
    "api.trongrid.io": 0.4,
    "mempool.space": 0.25,
    "api.mainnet-beta.solana.com": 0.3,
}
DEFAULT_INTERVAL = 0.25

_last_call = {}
_lock = threading.Lock()


class RateLimited(RuntimeError):
    pass


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(config.CACHE_DB)
    conn.execute("CREATE TABLE IF NOT EXISTS cache "
                 "(key TEXT PRIMARY KEY, ts INTEGER, payload TEXT)")
    return conn


def cache_get(key: str, max_age: int) -> Optional[dict]:
    try:
        conn = _db()
        row = conn.execute("SELECT ts, payload FROM cache WHERE key=?", (key,)).fetchone()
        conn.close()
    except sqlite3.Error:
        return None
    if not row:
        return None
    ts, payload = row
    if time.time() - ts > max_age:
        return None
    try:
        return json.loads(payload)
    except ValueError:
        return None


def cache_put(key: str, payload) -> None:
    try:
        conn = _db()
        conn.execute("INSERT OR REPLACE INTO cache(key, ts, payload) VALUES (?,?,?)",
                     (key, int(time.time()), json.dumps(payload)))
        conn.commit()
        conn.close()
    except (sqlite3.Error, TypeError):
        pass


def _throttle(host: str) -> None:
    with _lock:
        gap = MIN_INTERVAL.get(host, DEFAULT_INTERVAL)
        wait = gap - (time.time() - _last_call.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_call[host] = time.time()


def request_json(url: str, params: dict = None, *, body: dict = None,
                 cache_key: str = None, ttl: int = 3600, retries: int = 3,
                 timeout: int = 30, headers: dict = None):
    """GET (or POST when `body` is given) returning JSON, cached and rate-limited."""
    key = cache_key or (url + ("?" + urlencode(sorted(params.items())) if params else ""))
    hit = cache_get(key, ttl)
    if hit is not None:
        return hit

    host = urlparse(url).netloc
    delay = 1.0
    last_err = None
    for attempt in range(retries + 1):
        _throttle(host)
        try:
            if body is not None:
                r = requests.post(url, json=body, timeout=timeout, headers=headers)
            else:
                r = requests.get(url, params=params, timeout=timeout, headers=headers)
        except requests.RequestException as e:
            last_err = e
            if attempt < retries:
                time.sleep(delay)
                delay *= 2
                continue
            raise

        if r.status_code == 429:
            if attempt < retries:
                # honour Retry-After when the server sends it
                try:
                    delay = max(delay, float(r.headers.get("Retry-After", 0)))
                except ValueError:
                    pass
                time.sleep(delay)
                delay *= 2
                continue
            raise RateLimited(
                f"{host} rate limit reached. Wait a few seconds and retry, lower --depth/--branching, "
                "or set an API key for a higher quota.")

        if r.status_code in (400, 404):
            return {"__status__": r.status_code}

        r.raise_for_status()
        try:
            data = r.json()
        except ValueError as e:
            last_err = e
            raise
        cache_put(key, data)
        return data

    if last_err:
        raise last_err
    return None
