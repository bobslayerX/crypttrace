"""Large address sets published by exchanges themselves, kept in SQLite.

OKX signs every address that holds customer funds for its proof of reserves —
over 300,000 of them, most of them per-customer *deposit* addresses. A deposit
address is the cash-out point: funds that land there are with an exchange that
knows the depositor. Labelling them outright catches a deposit the moment funds
arrive, before the exchange sweeps them onward — the window in which a freeze
request can still work. The behavioural off-ramp heuristic only sees the sweep.

That is far too many to ship in known.json or to load on every run, so the set
is downloaded on request (`crypttrace update-labels --okx`) into a SQLite file
and looked up one address at a time. Curated labels in known.json always win.
"""
import csv
import io
import re
import sqlite3
import time
import zipfile
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

import requests

from crypttrace import addresses, config

DB_PATH: Path = config.DATA_DIR / "bulk_labels.sqlite"

OKX_PAGE = "https://www.okx.com/proof-of-reserves/download"
_OKX_FILE = re.compile(r"https://static\.okx\.com/cdn/okx/por/chain/por_csv_(\d{10})_V(\d+)\.zip")

# OKX network name -> crypttrace chain (only the chains crypttrace can trace)
OKX_NETWORKS = {"BTC": "btc", "TRON": "tron", "SOL": "sol", "ETH": "eth", "BSC": "bsc",
                "POLYGON": "polygon", "ARBITRUM": "arbitrum", "OPTIMISM": "optimism",
                "BASE": "base"}

_conn: Optional[sqlite3.Connection] = None


def _db() -> Optional[sqlite3.Connection]:
    """Open the store lazily; None when no set has been downloaded."""
    global _conn
    if _conn is None:
        if not DB_PATH.exists():
            return None
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    return _conn


def _create(c: sqlite3.Connection) -> None:
    c.execute("CREATE TABLE IF NOT EXISTS labels (key TEXT PRIMARY KEY, chain TEXT, "
              "set_name TEXT) WITHOUT ROWID")
    c.execute("CREATE TABLE IF NOT EXISTS sets (set_name TEXT PRIMARY KEY, name TEXT, "
              "type TEXT, role TEXT, source TEXT, source_kind TEXT, snapshot TEXT, "
              "url TEXT, count INTEGER, imported_at INTEGER)")


def lookup(address: str) -> Optional[dict]:
    c = _db()
    if c is None:
        return None
    row = c.execute("SELECT s.name, s.type, s.role, s.source, s.source_kind, s.snapshot, l.chain "
                    "FROM labels l JOIN sets s USING (set_name) WHERE l.key = ?",
                    (address.strip().lower(),)).fetchone()
    if not row:
        return None
    name, typ, role, source, kind, snapshot, chain = row
    return {"name": name, "type": typ, "role": role, "source": source,
            "source_kind": kind, "added": snapshot, "chain": chain}


def sets() -> Dict[str, dict]:
    """What has been downloaded, for `labels audit`."""
    c = _db()
    if c is None:
        return {}
    cols = ["set_name", "name", "snapshot", "url", "count", "imported_at"]
    return {r[0]: dict(zip(cols, r)) for r in
            c.execute(f"SELECT {', '.join(cols)} FROM sets").fetchall()}


def latest_okx_url(timeout: int = 30) -> str:
    """The newest address file linked from OKX's proof-of-reserves download page."""
    html = requests.get(OKX_PAGE, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"}).text
    found = {(m.group(1), int(m.group(2))): m.group(0) for m in _OKX_FILE.finditer(html)}
    if not found:
        raise ValueError("no address file found on OKX's proof-of-reserves page")
    return found[max(found)]


def _okx_csv_name(zip_path: Path) -> str:
    with zipfile.ZipFile(zip_path) as z:
        return next(n for n in z.namelist() if n.lower().endswith(".csv"))


def _okx_rows(zip_path: Path):
    """Yield (network, address) from OKX's file: a totals table, a blank line,
    then one row per address with its network and ownership signature."""
    with zipfile.ZipFile(zip_path) as z:
        with z.open(_okx_csv_name(zip_path)) as raw:
            f = io.TextIOWrapper(raw, encoding="utf-8-sig", newline="")
            for line in f:
                if line.lower().startswith("coin,type,network"):
                    header = next(csv.reader([line]))
                    break
            else:
                raise ValueError("unexpected OKX file layout: no address table")
            idx = {h.strip().lower(): i for i, h in enumerate(header)}
            n_i, a_i, s_i = idx["network"], idx["address"], idx["signature1"]
            for row in csv.reader(f):
                if len(row) > max(n_i, a_i, s_i) and row[s_i].strip():   # signed only
                    yield row[n_i].strip().upper(), row[a_i].strip()


def import_okx(source: Optional[str] = None,
               progress: Optional[Callable[[str], None]] = None) -> Tuple[int, str]:
    """Download (or read a local copy of) OKX's signed address file and store it.

    Returns (addresses stored, snapshot). The previous OKX set is replaced in
    one transaction, so a failed import leaves the old one in place.
    """
    say = progress or (lambda m: None)
    url = source or latest_okx_url()
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)

    if Path(url).exists():
        zip_path, downloaded = Path(url), False
        # the source text can end up in a report; a local path would leak the user's name
        url = f"local copy {zip_path.name}"
    else:
        zip_path, downloaded = config.DATA_DIR / "okx_por.zip.part", True
        say(f"downloading {url}")
        with requests.get(url, stream=True, timeout=60,
                          headers={"User-Agent": "Mozilla/5.0"}) as r:
            r.raise_for_status()
            with open(zip_path, "wb") as fh:
                for chunk in r.iter_content(1 << 20):
                    fh.write(chunk)

    try:
        # the snapshot time is in the file name: okx_por_2026090800_V1.csv
        stamp = re.search(r"(\d{10})", _okx_csv_name(zip_path) + " " + url)
        snapshot = (f"{stamp[1][:4]}-{stamp[1][4:6]}-{stamp[1][6:8]}" if stamp
                    else "unknown date")
        say("reading addresses")
        rows, validators, bad = {}, 0, 0
        for network, addr in _okx_rows(zip_path):
            chain = OKX_NETWORKS.get(network)
            if not chain:
                continue
            key = addr.lower()
            if key in rows:
                continue
            if chain == "eth" and len(addr) == 98:
                validators += 1       # a staking validator's public key, not an address
                continue
            if not addresses.validate(addr, chain)[0]:
                bad += 1
                continue
            rows[key] = (key, chain, "okx")

        c = sqlite3.connect(DB_PATH)
        try:
            _create(c)
            with c:
                c.execute("DELETE FROM labels WHERE set_name = 'okx'")
                c.executemany("INSERT OR REPLACE INTO labels VALUES (?, ?, ?)", rows.values())
                c.execute("INSERT OR REPLACE INTO sets VALUES (?,?,?,?,?,?,?,?,?,?)", (
                    "okx", "OKX deposit address", "exchange", "deposit",
                    f"one of the ~{len(rows) // 1000}k addresses OKX signed ('I am an OKX "
                    f"address') in its proof-of-reserves snapshot {snapshot} ({url}); most are "
                    "customer deposit addresses. Signature not verified by crypttrace.",
                    "self-published", snapshot, url, len(rows), int(time.time())))
        finally:
            c.close()
    finally:
        if downloaded:
            zip_path.unlink(missing_ok=True)

    global _conn
    if _conn is not None:
        _conn.close()
    _conn = None
    say(f"stored {len(rows)} addresses"
        + (f", skipped {validators} ETH staking validator keys" if validators else "")
        + (f", skipped {bad} malformed" if bad else ""))
    return len(rows), snapshot
