"""Address monitoring — the feature that actually helps recover funds.

The one window to freeze stolen crypto is the moment it reaches an exchange
deposit address. Victims can't watch a chain 24/7. `watch` keeps a list of
addresses, detects new activity, and raises a loud HIGH alert the instant funds
move toward an exchange (directly, or to a detected deposit address). Everything
else is a quieter movement notice.

Honest limit: the tool tells you *when* to act; freezing funds still depends on
the exchange and law enforcement responding quickly.
"""
import json
import time
from typing import List, Dict, Optional

import requests

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config, offramp

WATCHLIST = config.DATA_DIR / "watchlist.json"


def _load() -> Dict[str, dict]:
    if WATCHLIST.exists():
        try:
            return json.loads(WATCHLIST.read_text())
        except (ValueError, OSError):
            return {}
    return {}


def _save(d: Dict[str, dict]) -> None:
    WATCHLIST.parent.mkdir(parents=True, exist_ok=True)
    WATCHLIST.write_text(json.dumps(d, indent=2))


def _latest_ts(address: str, chain: str) -> int:
    txs = etherscan.get_txs(address, chain, limit=1)
    return int(txs[0]["timeStamp"]) if txs else 0


def add(address: str, chain: str = "eth", note: str = "") -> int:
    d = _load()
    baseline = _latest_ts(address, chain)  # only alert on activity *after* now
    d[address.lower()] = {"chain": chain, "note": note, "last_ts": baseline}
    _save(d)
    return baseline


def remove(address: str) -> bool:
    d = _load()
    if address.lower() in d:
        del d[address.lower()]
        _save(d)
        return True
    return False


def all_watched() -> Dict[str, dict]:
    return _load()


def _classify(me: str, tx: dict, chain: str) -> dict:
    frm = tx.get("from", "").lower()
    to = tx.get("to", "").lower()
    val = int(tx.get("value", 0)) / config.WEI
    direction = "out" if frm == me else "in"
    other = to if direction == "out" else frm
    otype = labels.type_of(other)

    sev, reason = "info", "incoming funds" if direction == "in" else "funds moved out"
    if direction == "out" and otype == "exchange":
        sev, reason = "high", f"→ EXCHANGE {labels.label_of(other)} — possible cash-out (freeze window)"
    elif direction == "out" and otype in ("mixer", "sanctioned"):
        sev, reason = "high", f"→ {otype} {labels.label_of(other)}"
    elif direction == "out" and otype == "bridge":
        sev, reason = "move", f"→ bridge {labels.label_of(other)} (funds may leave this chain)"
    elif direction == "out" and val > 0:
        off = offramp.detect(other, chain)
        if off:
            sev, reason = "high", f"→ likely {off['exchange']} DEPOSIT address — possible cash-out"
        else:
            sev, reason = "move", "funds moved out"

    return {"direction": direction, "other": other, "otype": otype, "value": val,
            "sev": sev, "reason": reason, "timestamp": int(tx.get("timeStamp", "0")),
            "hash": tx.get("hash", "")}


def check(address: str, chain: str, since_ts: int, limit: int = 100) -> List[dict]:
    """New events (newer than since_ts), newest first, each classified."""
    me = address.lower()
    events = []
    for tx in etherscan.get_txs(address, chain, limit=limit):  # desc (newest first)
        ts = int(tx.get("timeStamp", "0"))
        if ts <= since_ts:
            break
        events.append(_classify(me, tx, chain))
    return events


def poll_once() -> List[dict]:
    """Check every watched address, update baselines, return all new alerts."""
    d = _load()
    alerts = []
    for addr, meta in d.items():
        try:
            events = check(addr, meta.get("chain", "eth"), meta.get("last_ts", 0))
        except etherscan.EtherscanError:
            continue
        if events:
            meta["last_ts"] = max(e["timestamp"] for e in events)
            for e in events:
                e["address"] = addr
                e["note"] = meta.get("note", "")
                alerts.append(e)
    if alerts:
        _save(d)
    # highest severity first
    order = {"high": 0, "move": 1, "info": 2}
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
