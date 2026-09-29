"""Address monitoring — the feature that actually helps recover funds.

The one window to freeze stolen crypto is the moment it reaches an exchange
deposit address. Victims can't watch a chain 24/7. `watch` keeps a list of
addresses, detects new activity, and raises a loud HIGH alert the instant funds
move toward an exchange (directly, or to a detected deposit address). Everything
else is a quieter movement notice.

It works on every supported chain and watches the native coin *and* the
stablecoins (USDT, USDC) — most thefts move stablecoins, and on Tron almost
nothing else. Each poll reads fresh data, never the local store's copy.

Honest limit: the tool tells you *when* to act; freezing funds still depends on
the exchange and law enforcement responding quickly.
"""
import json
from typing import Dict, List, Optional, Tuple

import requests

from crypttrace.labels import labels
from crypttrace import addresses, assets, chains, config, offramp, poisoning

WATCHLIST = config.DATA_DIR / "watchlist.json"


class WatchError(ValueError):
    pass


def _load() -> Dict[str, dict]:
    if WATCHLIST.exists():
        try:
            return json.loads(WATCHLIST.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            return {}
    return {}


def _save(d: Dict[str, dict]) -> None:
    WATCHLIST.parent.mkdir(parents=True, exist_ok=True)
    WATCHLIST.write_text(json.dumps(d, indent=2), encoding="utf-8")


_ALL_TOKENS = {"contract": None, "symbol": "*"}


def _key(row: dict) -> str:
    return "|".join(str(row.get(k, "")) for k in ("hash", "from", "to", "value", "symbol"))


def _rows(address: str, chain: str, limit: int) -> List[dict]:
    """Fresh native and stablecoin transfers, each tagged with the asset it belongs to.

    Tokens are read in one request and kept only when their contract is the real
    stablecoin's — counterfeit "USDT" sent by address poisoners must not alert."""
    rows = [{**r, "_asset": None} for r in chains.transfers(address, chain, limit, fresh=True)]
    if chain == "btc":
        return rows
    try:
        tokens = chains.transfers(address, chain, limit, asset=_ALL_TOKENS, fresh=True)
    except chains.ChainError:
        return rows              # the native history alone still gets watched
    stables = {t["contract"].lower(): dict(t) for t in assets.tokens_for(chain).values()
               if t.get("stable")}
    return rows + [{**r, "_asset": stables[(r.get("contract") or "").lower()]}
                   for r in tokens if (r.get("contract") or "").lower() in stables]


def _latest(rows: List[dict]) -> Tuple[int, List[str]]:
    """Newest timestamp and the keys of every transfer at that second."""
    last = max((int(r.get("timestamp") or 0) for r in rows), default=0)
    return last, [_key(r) for r in rows if int(r.get("timestamp") or 0) == last]


def add(address: str, chain: str = "eth", note: str = "") -> int:
    ok, why = addresses.validate(address, chain)
    if not ok:
        raise WatchError(f"not a valid {chain} address: {why}")
    last, keys = _latest(_rows(address, chain, 50))   # only alert on activity after now
    d = _load()
    d[chains.norm_addr(address, chain)] = {"chain": chain, "note": note,
                                          "last_ts": last, "last_keys": keys}
    _save(d)
    return last


def remove(address: str) -> bool:
    d = _load()
    for k in (address, address.lower()):
        if k in d:
            del d[k]
            _save(d)
            return True
    return False


def all_watched() -> Dict[str, dict]:
    return _load()


def _classify(me: str, row: dict, chain: str) -> dict:
    frm, to = row.get("from") or "", row.get("to") or ""
    val = row.get("value", 0) or 0
    asset = row.get("_asset")
    symbol = asset["symbol"] if asset else chains.symbol(chain)
    direction = "out" if frm == me else "in"
    other = to if direction == "out" else frm
    otype = labels.type_of(other)

    sev, reason = "info", "incoming funds" if direction == "in" else "funds moved out"
    if poisoning._is_bait(row, chain):
        # zero, dust or counterfeit: how poisoners plant look-alikes in a history
        sev, reason = "dust", "zero/dust transfer — likely address poisoning; never copy this sender"
    elif direction == "out" and otype == "exchange":
        sev, reason = "high", f"→ EXCHANGE {labels.label_of(other)} — possible cash-out (freeze window)"
    elif direction == "out" and otype in ("mixer", "sanctioned"):
        sev, reason = "high", f"→ {otype} {labels.label_of(other)}"
    elif direction == "out" and otype == "bridge":
        sev, reason = "move", f"→ bridge {labels.label_of(other)} (funds may leave this chain)"
    elif direction == "out" and val > 0:
        try:
            off = offramp.detect(other, chain, asset=asset, stablecoins=False)
        except chains.ChainError:
            off = None
        if off:
            sev, reason = "high", f"→ likely {off['company']} DEPOSIT address — possible cash-out"
        else:
            sev, reason = "move", "funds moved out"

    return {"direction": direction, "other": other, "otype": otype, "value": val,
            "symbol": symbol, "sev": sev, "reason": reason,
            "timestamp": int(row.get("timestamp") or 0), "hash": row.get("hash", ""),
            "explorer": chains.tx_url(row["hash"], chain) if row.get("hash") else ""}


def check(address: str, chain: str, since_ts: int, seen_keys: Optional[List[str]] = None,
          limit: int = 100) -> List[dict]:
    """New events since the baseline, newest first, each classified. A transfer in
    the same second as the baseline counts as new unless it was already seen."""
    me = chains.norm_addr(address, chain)
    seen = set(seen_keys or [])
    rows = [r for r in _rows(address, chain, limit)
            if int(r.get("timestamp") or 0) > since_ts
            or (int(r.get("timestamp") or 0) == since_ts and _key(r) not in seen)]
    rows.sort(key=lambda r: int(r.get("timestamp") or 0), reverse=True)
    return [dict(_classify(me, r, chain), _key=_key(r)) for r in rows]


def poll_once() -> List[dict]:
    """Check every watched address, update baselines, return all new alerts."""
    d = _load()
    alerts = []
    for addr, meta in d.items():
        chain = meta.get("chain", "eth")
        try:
            events = check(addr, chain, meta.get("last_ts", 0), meta.get("last_keys"))
        except chains.ChainError:
            continue
        if events:
            last = max(e["timestamp"] for e in events)
            keys = [e["_key"] for e in events if e["timestamp"] == last]
            if last == meta.get("last_ts"):
                keys += meta.get("last_keys", [])
            meta["last_ts"], meta["last_keys"] = last, keys
            for e in events:
                e.pop("_key", None)
                e["address"] = addr
                e["chain"] = chain
                e["note"] = meta.get("note", "")
                alerts.append(e)
    if alerts:
        _save(d)
    # highest severity first
    order = {"high": 0, "move": 1, "info": 2, "dust": 3}
    return sorted(alerts, key=lambda e: order.get(e["sev"], 3))


def telegram_notify(text: str) -> Optional[bool]:
    """Send an alert to Telegram if CRYPTTRACE_TG_TOKEN + CRYPTTRACE_TG_CHAT are set."""
    import os
    token = os.environ.get("CRYPTTRACE_TG_TOKEN")
    chat = os.environ.get("CRYPTTRACE_TG_CHAT")
    if not token or not chat:
        return None
    try:
        r = requests.get(f"https://api.telegram.org/bot{token}/sendMessage",
                         params={"chat_id": chat, "text": text}, timeout=15)
        return r.ok
    except requests.RequestException:
        return False
