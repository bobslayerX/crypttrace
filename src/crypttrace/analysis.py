"""Analytical views: *who* lost the money, and *when* it moved.

Two things a fund-flow graph shows but can't hand you as evidence:

  * the list of addresses that fed a consolidation wallet — in a mass theft
    that list is the set of victims, and it belongs in a spreadsheet attached
    to a police report, not only in a picture;
  * the timing of the movement. A theft executed by an automated tool looks
    completely different from an owner spending their own coins: hundreds of
    transfers inside minutes, rather than spread over months.
"""
import csv
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from crypttrace import chains
from crypttrace.labels import labels


def _ts(unix) -> str:
    try:
        return datetime.fromtimestamp(int(unix), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError, OSError):
        return "?"


def _direct(address: str, chain: str, asset: Optional[dict], limit: int,
            direction: str = "in") -> Dict[str, dict]:
    """Aggregate counterparties one hop away, keeping amounts and timestamps."""
    me = chains.norm_addr(address, chain)
    near, far = ("to", "from") if direction == "in" else ("from", "to")
    agg: Dict[str, dict] = {}
    for r in chains.transfers(address, chain, limit, asset=asset):
        if r.get(near) != me:
            continue
        other = r.get(far)
        val = r.get("value", 0) or 0
        if not other or val <= 0:
            continue
        rec = agg.setdefault(other, {"address": other, "value": 0.0, "txs": 0,
                                     "first_ts": None, "last_ts": None})
        rec["value"] += val
        rec["txs"] += 1
        ts = int(r.get("timestamp") or 0)
        rec["first_ts"] = ts if rec["first_ts"] is None else min(rec["first_ts"], ts)
        rec["last_ts"] = ts if rec["last_ts"] is None else max(rec["last_ts"], ts)
    return agg


def collect_sources(address: str, chain: str = "btc", depth: int = 1,
                    asset: Optional[dict] = None, limit: int = 1000,
                    max_addresses: int = 400) -> List[dict]:
    """Every address that fed `address`, walking back `depth` hops.

    In a mass-drain incident this is the victim list. Results carry the hop
    distance so direct senders can be told apart from earlier sources.
    """
    found: Dict[str, dict] = {}
    frontier = [chains.norm_addr(address, chain)]
    seen = {chains.norm_addr(address, chain)}

    for hop in range(1, depth + 1):
        next_frontier = []
        for node in frontier:
            if len(found) >= max_addresses:
                break
            try:
                sources = _direct(node, chain, asset, limit, "in")
            except chains.ChainError:
                continue
            for addr, rec in sources.items():
                key = chains.norm_addr(addr, chain)
                if key in found:
                    found[key]["value"] += rec["value"]
                    found[key]["txs"] += rec["txs"]
                    continue
                rec = dict(rec)
                rec["hop"] = hop
                rec["into"] = node
                rec["label"] = labels.label_of(addr)
                rec["type"] = labels.type_of(addr)
                found[key] = rec
                if key not in seen:
                    seen.add(key)
                    next_frontier.append(addr)
        frontier = next_frontier
        if not frontier or len(found) >= max_addresses:
            break

    return sorted(found.values(), key=lambda r: r["value"], reverse=True)


def export_csv(rows: List[dict], path: Path, chain: str, symbol: str) -> Path:
    """Write the source list to CSV — the form an exchange or police force wants."""
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = ["address", "hop", f"amount_sent_{symbol}", "transactions",
            "first_seen_utc", "last_seen_utc", "sent_into", "label", "explorer"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in rows:
            w.writerow([r["address"], r.get("hop", 1), round(r["value"], 8), r["txs"],
                        _ts(r.get("first_ts")), _ts(r.get("last_ts")),
                        r.get("into", ""), r.get("label", ""),
                        chains.explorer_url(r["address"], chain)])
    return path


# ---------- timing ----------

def tightest_window(timestamps: List[int], fraction: float = 0.8) -> Optional[Tuple[int, int, int, int]]:
    """Shortest time span containing `fraction` of the events.

    Returns (span_seconds, count, start_ts, end_ts). This is what separates an
    automated sweep from normal wallet use: hundreds of transfers inside minutes.
    """
    ts = sorted(t for t in timestamps if t)
    n = len(ts)
    if n < 2:
        return None
    need = max(2, int(n * fraction))
    best = None
    for i in range(0, n - need + 1):
        j = i + need - 1
        span = ts[j] - ts[i]
        if best is None or span < best[0]:
            best = (span, need, ts[i], ts[j])
    return best


def timeline(address: str, chain: str = "eth", asset: Optional[dict] = None,
             limit: int = 1000, buckets: int = 24) -> dict:
    """Bucketed in/out activity plus burst detection."""
    me = chains.norm_addr(address, chain)
    rows = chains.transfers(address, chain, limit, asset=asset)
    events = [{"ts": int(r.get("timestamp") or 0),
               "value": r.get("value", 0) or 0,
               "dir": "out" if r.get("from") == me else "in"} for r in rows]
    events = [e for e in events if e["ts"] > 0]
    if not events:
        return {"events": 0, "buckets": [], "burst": None,
                "first_ts": None, "last_ts": None, "in_total": 0.0, "out_total": 0.0}

    events.sort(key=lambda e: e["ts"])
    first, last = events[0]["ts"], events[-1]["ts"]
    span = max(1, last - first)
    width = max(1, span // buckets)

    grid = []
    for i in range(buckets):
        start = first + i * width
        end = start + width
        sel = [e for e in events if start <= e["ts"] < end or (i == buckets - 1 and e["ts"] == last)]
        grid.append({
            "start": start, "end": end, "count": len(sel),
            "in": sum(e["value"] for e in sel if e["dir"] == "in"),
            "out": sum(e["value"] for e in sel if e["dir"] == "out"),
        })

    return {
        "events": len(events),
        "buckets": grid,
        "burst": tightest_window([e["ts"] for e in events]),
        "first_ts": first, "last_ts": last,
        "in_total": sum(e["value"] for e in events if e["dir"] == "in"),
        "out_total": sum(e["value"] for e in events if e["dir"] == "out"),
    }


def describe_burst(burst, total_events: int) -> Optional[str]:
    """Plain-language read on the timing, if it looks automated."""
    if not burst:
        return None
    span, count, start, end = burst
    if span <= 0:
        return f"All {count} transfers share one timestamp — a single batched operation."
    minutes = span / 60
    rate = count / max(minutes, 0.01)
    when = f"{_ts(start)} → {_ts(end)} UTC"
    if minutes <= 90 and count >= 20:
        return (f"{count} of {total_events} transfers happened inside "
                f"{minutes:.0f} minutes ({when}), about {rate:.0f} per minute. "
                "That rate is characteristic of an automated tool spending keys it "
                "already holds, not of an owner moving their own funds.")
    if minutes <= 60 * 24:
        return (f"{count} of {total_events} transfers fall inside {minutes/60:.1f} hours ({when})."
                " Activity is concentrated rather than spread out.")
    return (f"Activity is spread over {minutes/60/24:.0f} days — no burst pattern, "
            "which is what ordinary wallet use looks like.")
