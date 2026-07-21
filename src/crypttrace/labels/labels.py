"""Local label database + risk scoring.

Labels are the single most valuable part of a forensics tool: they turn an
anonymous hex string into "Binance hot wallet" or "Tornado Cash". This ships a
small seed set; real deployments extend it from OFAC SDN, Chainabuse, etc.
via `crypttrace update-labels` (stub below).
"""
import json
from pathlib import Path
from typing import Optional, Dict

_HERE = Path(__file__).parent
_KNOWN: Dict[str, dict] = {}


def _load() -> None:
    global _KNOWN
    if _KNOWN:
        return
    raw = json.loads((_HERE / "known.json").read_text())
    # normalise keys to lowercase, drop malformed placeholders
    _KNOWN = {
        k.lower(): v for k, v in raw.items()
        if k.startswith("0x") and len(k) == 42
    }


# Risk weight per label type (0-100)
RISK = {
    "sanctioned": 100,
    "mixer": 90,
    "scam": 85,
    "bridge": 40,
    "exchange": 20,
    "unknown": 0,
}

TYPE_ICON = {
    "sanctioned": "\U0001F534",  # red
    "mixer": "\U0001F7E3",       # purple
    "scam": "\U0001F534",
    "bridge": "\U0001F309",      # bridge
    "exchange": "\U0001F7E2",    # green
    "unknown": "⚪",         # white
}


def lookup(address: str) -> Optional[dict]:
    _load()
    return _KNOWN.get(address.lower())


def label_of(address: str) -> str:
    hit = lookup(address)
    return hit["name"] if hit else ""


def type_of(address: str) -> str:
    hit = lookup(address)
    return hit["type"] if hit else "unknown"


def risk_score(address: str) -> int:
    return RISK.get(type_of(address), 0)


def icon(address: str) -> str:
    return TYPE_ICON.get(type_of(address), TYPE_ICON["unknown"])
