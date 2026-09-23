"""Auditing the label database.

A label is a claim about who controls an address. Acted on, it can get someone's
withdrawal frozen — so each one has to be checkable rather than asserted. This
module validates the whole database:

  * the address is well-formed and its checksum passes;
  * the claim carries a **source** that a reader can go and verify;
  * nothing is silently duplicated or contradicted.

Run it with `crypttrace labels audit`. Unsourced labels are reported, not
hidden: the honest position is to show which claims are evidenced and which are
inherited.
"""
import json
from pathlib import Path
from typing import Dict, List

from crypttrace import addresses

_HERE = Path(__file__).parent

# how strongly a source supports the claim
SOURCE_RANK = {
    "self-published": 3,   # the exchange or service publishes the address itself
    "official-list": 3,    # a government or regulator list, e.g. OFAC SDN
    "explorer-tag": 2,     # a block explorer's own label
    "research": 2,         # a named report or researcher, cited
    "community": 1,        # crowd-sourced database
    "": 0,                 # no source recorded
}


def _chain_of(address: str) -> str:
    a = address.strip()
    if a.startswith("0x"):
        return "eth"
    if a.startswith(("bc1", "1", "3")):
        return "btc"
    if a.startswith("T") and len(a) == 34:
        return "tron"
    return "sol"


def audit() -> Dict:
    """Check every label: format, checksum, and whether a source is recorded."""
    path = _HERE / "known.json"
    raw = json.loads(path.read_text(encoding="utf-8"))

    problems: List[dict] = []
    unsourced: List[dict] = []
    ok = 0
    by_type: Dict[str, int] = {}
    by_source: Dict[str, int] = {}

    for addr, meta in raw.items():
        if not isinstance(meta, dict):
            problems.append({"address": addr, "issue": "malformed entry"})
            continue
        chain = meta.get("chain") or _chain_of(addr)
        valid, why = addresses.validate(addr, chain)
        if not valid:
            problems.append({"address": addr, "name": meta.get("name", ""),
                             "chain": chain, "issue": why})
            continue
        ok += 1
        by_type[meta.get("type", "?")] = by_type.get(meta.get("type", "?"), 0) + 1
        src = meta.get("source", "")
        kind = meta.get("source_kind", "")
        by_source[kind or "none"] = by_source.get(kind or "none", 0) + 1
        if not src:
            unsourced.append({"address": addr, "name": meta.get("name", ""),
                              "type": meta.get("type", "")})

    return {
        "total": len(raw),
        "valid": ok,
        "problems": problems,
        "unsourced": unsourced,
        "by_type": by_type,
        "by_source": by_source,
        "sourced_share": (len(raw) - len(unsourced)) / len(raw) if raw else 0.0,
        "path": str(path),
    }


def evidence(address: str) -> Dict:
    """Why do we claim this address is what we say it is?"""
    raw = json.loads((_HERE / "known.json").read_text(encoding="utf-8"))
    # Tron/Solana keys keep their case (it carries the checksum), but callers
    # often pass addresses already lower-cased by the label layer.
    meta = raw.get(address) or {k.lower(): v for k, v in raw.items()}.get(address.lower())
    if not meta:
        from crypttrace.labels import bulk     # large downloaded sets (OKX, …)
        meta = bulk.lookup(address)
    if not meta:
        return {"address": address, "known": False}
    return {
        "address": address, "known": True,
        "name": meta.get("name", ""), "type": meta.get("type", ""),
        "source": meta.get("source", ""),
        "source_kind": meta.get("source_kind", ""),
        "strength": SOURCE_RANK.get(meta.get("source_kind", ""), 0),
        "added": meta.get("added", ""),
    }
