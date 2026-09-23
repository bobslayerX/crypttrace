"""Local store of normalized transfers.

Until now every command re-fetched from the network, so looking at the same
case from a second angle meant paying for the whole traversal again — and the
depth of an investigation was capped by how much could be held in memory during
one run.

This keeps what was already fetched in SQLite, in the same normalized shape the
rest of the tool uses. Three things follow from that:

  * re-analysis is instant and works with the network unplugged;
  * a trace can be resumed or extended instead of restarted;
  * addresses can be queried *across* each other in SQL, which is what a
    multi-address case needs — the merging we previously did by hand.

Rows are deduplicated by content, so fetching the same transaction from both
ends of it stores one copy.
"""
import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional

from crypttrace import config

DB_PATH: Path = config.DATA_DIR / "transfers.sqlite"

# how long stored data is considered current before we go back to the network
DEFAULT_MAX_AGE = 24 * 3600


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.execute("PRAGMA journal_mode=WAL")
    c.executescript("""
        CREATE TABLE IF NOT EXISTS transfers (
            id        TEXT PRIMARY KEY,
            chain     TEXT NOT NULL,
            tx_hash   TEXT,
            from_addr TEXT,
            to_addr   TEXT,
            value     REAL,
            symbol    TEXT,
            contract  TEXT,
            ts        INTEGER,
            fee_share REAL
        );
        CREATE INDEX IF NOT EXISTS ix_to   ON transfers(chain, to_addr);
        CREATE INDEX IF NOT EXISTS ix_from ON transfers(chain, from_addr);
        CREATE INDEX IF NOT EXISTS ix_ts   ON transfers(ts);

        CREATE TABLE IF NOT EXISTS fetched (
            chain      TEXT NOT NULL,
            address    TEXT NOT NULL,
            asset      TEXT NOT NULL DEFAULT '',
            fetched_at INTEGER,
            rows       INTEGER,
            complete   INTEGER,
            PRIMARY KEY (chain, address, asset)
        );
    """)
    return c


def _row_id(chain: str, r: dict) -> str:
    """Content hash — the same transfer seen from either side stores once."""
    key = "|".join([
        chain, str(r.get("hash", "")), str(r.get("from", "")), str(r.get("to", "")),
        str(r.get("symbol", "")), f"{float(r.get('value', 0)):.12f}",
    ])
    return hashlib.sha1(key.encode()).hexdigest()


def save(chain: str, address: str, rows: List[dict], asset_key: str = "",
         complete: bool = True) -> int:
    """Persist transfers and note that this address was fetched."""
    c = _conn()
    try:
        c.executemany(
            "INSERT OR REPLACE INTO transfers"
            "(id,chain,tx_hash,from_addr,to_addr,value,symbol,contract,ts,fee_share)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(_row_id(chain, r), chain, r.get("hash", ""), r.get("from", ""),
              r.get("to", ""), float(r.get("value", 0) or 0), r.get("symbol", ""),
              r.get("contract", ""), int(r.get("timestamp", 0) or 0),
              float(r.get("fee_share", 0) or 0)) for r in rows])
        c.execute("INSERT OR REPLACE INTO fetched(chain,address,asset,fetched_at,rows,complete)"
                  " VALUES (?,?,?,?,?,?)",
                  (chain, address, asset_key, int(time.time()), len(rows), int(complete)))
        c.commit()
        return len(rows)
    finally:
        c.close()


def age(chain: str, address: str, asset_key: str = "") -> Optional[int]:
    """Seconds since this address was last fetched, or None if never."""
    c = _conn()
    try:
        row = c.execute("SELECT fetched_at FROM fetched WHERE chain=? AND address=? AND asset=?",
                        (chain, address, asset_key)).fetchone()
    finally:
        c.close()
    return None if not row else int(time.time()) - row[0]


def is_fresh(chain: str, address: str, asset_key: str = "",
             max_age: int = DEFAULT_MAX_AGE) -> bool:
    a = age(chain, address, asset_key)
    return a is not None and a <= max_age


def load(chain: str, address: str, contract: str = "", native_symbol: str = "") -> List[dict]:
    """Every stored transfer touching this address, newest first."""
    c = _conn()
    cols = "SELECT from_addr,to_addr,value,symbol,contract,ts,tx_hash,fee_share FROM transfers"
    try:
        if contract == "*":
            # every token, whatever its contract (address-poisoning checks need fakes too)
            q = (f"{cols} WHERE chain=? AND (from_addr=? OR to_addr=?)"
                 " AND contract IS NOT NULL AND contract!='' ORDER BY ts DESC")
            args = (chain, address, address)
        elif contract:
            q = (f"{cols} WHERE chain=? AND (from_addr=? OR to_addr=?)"
                 " AND lower(contract)=lower(?) ORDER BY ts DESC")
            args = (chain, address, address, contract)
        else:
            # native asset: rows carry no contract. Older stores filed Solana
            # SPL rows without one too, so the symbol is checked as well.
            q = (f"{cols} WHERE chain=? AND (from_addr=? OR to_addr=?)"
                 " AND (contract IS NULL OR contract='')"
                 + (" AND symbol=?" if native_symbol else "") + " ORDER BY ts DESC")
            args = (chain, address, address) + ((native_symbol,) if native_symbol else ())
        # Stores written before 0.5.0 hold Tron Approval events read as transfers of
        # ~1e59 tokens (an unlimited allowance). No real transfer comes near 1e30.
        rows = [r for r in c.execute(q, args).fetchall() if (r[2] or 0) < 1e30]
    finally:
        c.close()
    out = []
    for f, t, v, sym, con, ts, h, fee in rows:
        r = {"from": f, "to": t, "value": v, "symbol": sym,
             "timestamp": ts, "hash": h}
        if con:
            r["contract"] = con
        if fee:
            r["fee_share"] = fee
        out.append(r)
    return out


# ---- queries that span addresses (what a multi-address case needs) ----

def sources_of(chain: str, addresses: List[str], min_value: float = 0.0) -> List[dict]:
    """Everyone who funded any of these addresses, aggregated — across a whole case."""
    if not addresses:
        return []
    marks = ",".join("?" * len(addresses))
    c = _conn()
    try:
        rows = c.execute(
            f"SELECT from_addr, SUM(value), COUNT(*), MIN(ts), MAX(ts)"
            f" FROM transfers WHERE chain=? AND to_addr IN ({marks})"
            f" AND value >= ? AND from_addr NOT IN ({marks})"
            f" GROUP BY from_addr ORDER BY SUM(value) DESC",
            (chain, *addresses, min_value, *addresses)).fetchall()
    finally:
        c.close()
    return [{"address": a, "value": v, "txs": n, "first_ts": lo, "last_ts": hi}
            for a, v, n, lo, hi in rows]


def path_exists(chain: str, src: str, dst: str, max_hops: int = 4) -> Optional[List[str]]:
    """Shortest stored path of transfers from src to dst — 'are these connected?'"""
    c = _conn()
    try:
        frontier = {src: [src]}
        seen = {src}
        for _ in range(max_hops):
            if not frontier:
                break
            marks = ",".join("?" * len(frontier))
            rows = c.execute(
                f"SELECT from_addr, to_addr FROM transfers"
                f" WHERE chain=? AND from_addr IN ({marks})",
                (chain, *frontier.keys())).fetchall()
            nxt = {}
            for f, t in rows:
                if not t or t in seen:
                    continue
                p = frontier[f] + [t]
                if t == dst:
                    return p
                seen.add(t)
                nxt[t] = p
            frontier = nxt
    finally:
        c.close()
    return None


def stats() -> Dict:
    c = _conn()
    try:
        transfers = c.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        addresses = c.execute("SELECT COUNT(*) FROM fetched").fetchone()[0]
        chains = c.execute("SELECT chain, COUNT(*) FROM transfers GROUP BY chain").fetchall()
        oldest = c.execute("SELECT MIN(fetched_at) FROM fetched").fetchone()[0]
    finally:
        c.close()
    return {"transfers": transfers, "addresses": addresses,
            "by_chain": dict(chains), "oldest_fetch": oldest,
            "path": str(DB_PATH),
            "size_bytes": DB_PATH.stat().st_size if DB_PATH.exists() else 0}


def clear() -> None:
    c = _conn()
    try:
        c.executescript("DELETE FROM transfers; DELETE FROM fetched;")
        c.commit()
    finally:
        c.close()
