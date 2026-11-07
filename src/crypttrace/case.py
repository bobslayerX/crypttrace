"""An investigation kept as a file: its addresses, their roles, notes, and what
changed since you last looked.

A case is one JSON file — by default ~/.crypttrace/cases/NAME.json, or any path
— so handing a case to a colleague is sending them the file. It holds:

  - addresses across chains, each with a role (victim, suspect, exchange, …)
    and a note;
  - a log of timestamped notes;
  - for each address, the last snapshot taken by `refresh`: native balance
    and the time of the latest transfer (tokens included where the chain has
    them). The next `refresh` compares against it, which is how a case tells
    you the money moved again.
"""
import datetime as dt
import json
import re
import time
from pathlib import Path
from typing import Callable, List, Optional

from crypttrace import addresses, chains, config

CASES_DIR = config.DATA_DIR / "cases"
ROLES = ("victim", "suspect", "intermediary", "exchange", "mixer", "bridge", "other")
FORMAT = 1
_ALL_TOKENS = {"contract": None, "symbol": "*"}


class CaseError(ValueError):
    pass


def path_for(name_or_path: str) -> Path:
    """A case named in the cases folder, or a .json file anywhere."""
    p = Path(name_or_path)
    if p.suffix.lower() == ".json" or p.parent != Path("."):
        return p
    if not re.fullmatch(r"[\w.-]{1,64}", name_or_path):
        raise CaseError("a case name is letters, digits, '.', '-' or '_' (up to 64)")
    return CASES_DIR / f"{name_or_path}.json"


def _now() -> int:
    return int(time.time())


def new(name: str, note: str = "") -> Path:
    p = path_for(name)
    if p.exists():
        raise CaseError(f"case already exists: {p}")
    case = {"crypttrace_case": FORMAT, "name": p.stem, "created": _now(), "updated": _now(),
            "addresses": [], "notes": []}
    if note:
        case["notes"].append({"at": _now(), "text": note})
    save(case, p)
    return p


def load(name: str) -> dict:
    p = path_for(name)
    try:
        case = json.loads(p.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise CaseError(f"no such case: {p}")
    except ValueError as e:
        raise CaseError(f"{p} is not a readable case file: {e}")
    if not isinstance(case, dict) or "crypttrace_case" not in case:
        raise CaseError(f"{p} is not a crypttrace case file")
    case["_path"] = str(p)
    return case


def save(case: dict, p: Optional[Path] = None) -> Path:
    p = Path(p or case["_path"])
    p.parent.mkdir(parents=True, exist_ok=True)
    data = {k: v for k, v in case.items() if not k.startswith("_")}
    data["updated"] = _now()
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)                       # a half-written case never replaces a good one
    return p


def all_cases() -> List[dict]:
    out = []
    for p in sorted(CASES_DIR.glob("*.json")):
        try:
            c = load(str(p))
        except CaseError:
            continue
        out.append({"name": c.get("name", p.stem), "path": str(p), "addresses": len(c.get("addresses", [])),
                    "notes": len(c.get("notes", [])), "updated": c.get("updated")})
    return out


def add(name: str, address: str, chain: str, role: str = "other", note: str = "") -> dict:
    chains.check(chain)
    if role not in ROLES:
        raise CaseError(f"role must be one of: {', '.join(ROLES)}")
    ok, why = addresses.validate(address, chain)
    if not ok:
        raise CaseError(f"not a valid {chain} address: {why}")
    case = load(name)
    key = chains.norm_addr(address, chain)
    for a in case["addresses"]:
        if a["chain"] == chain and a["address"] == key:
            a["role"] = role                # adding it again updates it
            if note:
                a["note"] = note
            save(case)
            return a
    entry = {"address": key, "chain": chain, "role": role, "note": note, "added": _now(), "snapshot": None}
    case["addresses"].append(entry)
    save(case)
    return entry


def remove(name: str, address: str, chain: Optional[str] = None) -> bool:
    case = load(name)
    before = len(case["addresses"])
    case["addresses"] = [a for a in case["addresses"]
                         if not (a["address"] == chains.norm_addr(address, a["chain"])
                                 and (chain is None or a["chain"] == chain))]
    if len(case["addresses"]) == before:
        return False
    save(case)
    return True


def note(name: str, text: str) -> dict:
    case = load(name)
    entry = {"at": _now(), "text": text}
    case["notes"].append(entry)
    save(case)
    return entry


def snapshot(address: str, chain: str) -> dict:
    """Native balance and the time of the latest transfer, read fresh."""
    snap = {"at": _now(), "balance": None, "last_seen": None, "error": None}
    try:
        snap["balance"] = chains.balance(address, chain)
        rows = list(chains.transfers(address, chain, 50, fresh=True))
        if not chains.is_utxo(chain):
            try:
                rows += chains.transfers(address, chain, 50, asset=_ALL_TOKENS, fresh=True)
            except chains.ChainError:
                pass
        stamps = [int(r.get("timestamp") or 0) for r in rows if r.get("timestamp")]
        snap["last_seen"] = max(stamps) if stamps else None
    except chains.ChainError as e:
        snap["error"] = str(e)
    return snap


def changes(prev: Optional[dict], cur: dict) -> List[str]:
    """What is different from the last snapshot, in words."""
    if cur.get("error"):
        return [f"could not be read: {cur['error']}"]
    if not prev or prev.get("error"):
        return ["first snapshot"]
    out = []
    a, b = prev.get("balance"), cur.get("balance")
    if a is not None and b is not None and abs(b - a) > max(1e-9, abs(a) * 1e-9):
        out.append(f"balance {a:,.8f} -> {b:,.8f} ({b - a:+,.8f})")
    if (cur.get("last_seen") or 0) > (prev.get("last_seen") or 0):
        when = dt.datetime.fromtimestamp(cur["last_seen"], dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        out.append(f"new activity, latest {when}")
    return out


def refresh(name: str, take: Callable[[str, str], dict] = snapshot) -> List[dict]:
    """Snapshot every address; report what changed since the last refresh."""
    case = load(name)
    report = []
    for a in case["addresses"]:
        cur = take(a["address"], a["chain"])
        diff = changes(a.get("snapshot"), cur)
        report.append({**{k: a[k] for k in ("address", "chain", "role")}, "changes": diff,
                       "moved": any(not d.startswith(("first", "could not")) for d in diff),
                       "balance": cur.get("balance"), "previous": a.get("snapshot")})
        if not cur.get("error"):
            a["snapshot"] = cur
    case.setdefault("refreshes", []).append(_now())
    save(case)
    return report
