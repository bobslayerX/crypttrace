"""Local label database + risk scoring.

Labels are the single most valuable part of a forensics tool: they turn an
anonymous hex string into "Binance hot wallet" or "Tornado Cash".

Two layers are merged:
  1. known.json  — the curated seed set shipped with the tool (rich names).
  2. imported labels — downloaded by `crypttrace update-labels` from public
     sources (OFAC sanctions, etc.), cached in the user's data dir.
The seed set takes priority on conflicts, so its richer names win.
"""
import json
from pathlib import Path
from typing import Optional, Dict, List

import requests

from crypttrace import config

_HERE = Path(__file__).parent
_IMPORTED = config.DATA_DIR / "imported_labels.json"
_KNOWN: Dict[str, dict] = {}
_PARTIAL: List[dict] = []


# Public label sources. Each is fetched and merged on `update-labels`.
# "lines" format = one address per line (comments/blank lines skipped).
SOURCES: List[dict] = [
    {
        "name": "OFAC SDN — sanctioned ETH addresses",
        "url": ("https://raw.githubusercontent.com/0xB10C/"
                "ofac-sanctioned-digital-currency-addresses/lists/"
                "sanctioned_addresses_ETH.txt"),
        "format": "lines",
        "label": "OFAC SDN (sanctioned)",
        "type": "sanctioned",
    },
]


def _valid(addr: str) -> bool:
    """Accept address shapes from every supported chain, not just EVM."""
    a = addr.strip()
    if a.startswith("0x"):
        return len(a) == 42                       # EVM
    if a.startswith(("bc1", "tb1")):
        return 26 <= len(a) <= 62                 # Bitcoin bech32
    if a.startswith(("1", "3")):
        return 26 <= len(a) <= 35                 # Bitcoin legacy / p2sh
    if a.startswith("t"):
        return len(a) == 34                       # Tron (lower-cased 'T…')
    return 32 <= len(a) <= 44                     # Solana / other base58


def _load_partials() -> List[dict]:
    """Addresses published only in truncated form (e.g. 'bc1qq85v2c9…cu9r').

    Incident reports often abbreviate. Requiring BOTH prefix and suffix to match
    is specific enough to be safe, and lets the tool flag a wallet before the
    full string is public. Exact labels always take priority.
    """
    path = _HERE / "partial.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (ValueError, OSError):
        return []
    out = []
    for e in data.get("entries", []):
        pre, suf = e.get("prefix", ""), e.get("suffix", "")
        if len(pre) >= 8 and len(suf) >= 4:       # guard against loose patterns
            out.append(e)
    return out


def _load() -> None:
    global _KNOWN, _PARTIAL
    if _KNOWN:
        return
    merged: Dict[str, dict] = {}
    # imported first (lower priority)...
    if _IMPORTED.exists():
        try:
            raw = json.loads(_IMPORTED.read_text())
            merged.update({k.lower(): v for k, v in raw.items() if _valid(k.lower())})
        except (ValueError, OSError):
            pass
    # ...then curated seed overrides.
    seed = json.loads((_HERE / "known.json").read_text())
    merged.update({k.lower(): v for k, v in seed.items() if _valid(k.lower())})
    _KNOWN = merged
    _PARTIAL = _load_partials()


def _match_partial(address: str) -> Optional[dict]:
    a = address.strip().lower()
    for e in _PARTIAL:
        if a.startswith(e["prefix"].lower()) and a.endswith(e["suffix"].lower()):
            return {"name": e["name"], "type": e["type"], "partial": True,
                    "source": e.get("source", "")}
    return None


def update(timeout: int = 30) -> List[tuple]:
    """Fetch every source and merge results into the imported-labels cache.

    Returns a list of (source_name, count, error) tuples for reporting.
    """
    imported: Dict[str, dict] = {}
    if _IMPORTED.exists():
        try:
            imported = json.loads(_IMPORTED.read_text())
        except (ValueError, OSError):
            imported = {}

    results = []
    for src in SOURCES:
        try:
            resp = requests.get(src["url"], timeout=timeout)
            resp.raise_for_status()
        except requests.RequestException as e:
            results.append((src["name"], 0, str(e)))
            continue

        count = 0
        if src["format"] == "lines":
            for line in resp.text.splitlines():
                addr = line.strip().lower()
                if _valid(addr):
                    imported[addr] = {"name": src["label"], "type": src["type"]}
                    count += 1
        results.append((src["name"], count, None))

    _IMPORTED.parent.mkdir(parents=True, exist_ok=True)
    _IMPORTED.write_text(json.dumps(imported, indent=2))

    # invalidate cache so freshly imported labels take effect immediately
    global _KNOWN
    _KNOWN = {}
    return results


def count() -> int:
    """Total number of labelled addresses currently loaded."""
    _load()
    return len(_KNOWN)


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
    hit = _KNOWN.get(address.lower())
    if hit:
        return hit
    return _match_partial(address)


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
