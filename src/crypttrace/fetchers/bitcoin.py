"""Bitcoin fetcher via mempool.space — no API key required.

Bitcoin uses the UTXO model, not accounts: a transaction consumes previous
outputs and creates new ones, so there is no single "from" or "to". To fit the
same tracing engine used for EVM chains, transactions are normalized into
directional transfer rows:

  * if our address signed an input, each output that isn't ours is an outflow
    (outputs back to ourselves are change and are skipped);
  * otherwise, outputs paying us are inflows, attributed to the first input.

Bitcoin also enables the strongest clustering heuristic in blockchain forensics:
common-input-ownership. If several addresses sign inputs of the same
transaction, one party almost certainly controls all of them.
"""
from typing import List, Dict, Optional

import requests

BASE = "https://mempool.space/api"
SATS = 100_000_000


class BitcoinError(RuntimeError):
    pass


def _get(path: str, timeout: int = 30):
    """Cached, throttled GET against mempool.space."""
    from crypttrace.fetchers import http
    try:
        data = http.request_json(f"{BASE}{path}", timeout=timeout)
    except http.RateLimited as e:
        raise BitcoinError(str(e))
    except requests.RequestException as e:
        raise BitcoinError(f"mempool.space request failed: {e}")
    except ValueError as e:
        raise BitcoinError(f"bad response from mempool.space: {e}")
    if isinstance(data, dict) and "__status__" in data:
        if data["__status__"] == 400:
            raise BitcoinError("Bitcoin address rejected by mempool.space — check it is "
                               "exact (BTC addresses are case-sensitive).")
        raise BitcoinError("Address not found on the Bitcoin chain.")
    return data


def stats(address: str) -> Dict:
    """Authoritative totals straight from the chain index.

    These are the numbers our own parsing must agree with — the reference for
    checking that a trace didn't miscount or silently miss history.
    """
    d = _get(f"/address/{address}")
    cs = d.get("chain_stats", {}) or {}
    ms = d.get("mempool_stats", {}) or {}
    recv = (cs.get("funded_txo_sum", 0) + ms.get("funded_txo_sum", 0)) / SATS
    sent = (cs.get("spent_txo_sum", 0) + ms.get("spent_txo_sum", 0)) / SATS
    return {
        "received": recv,
        "sent": sent,
        "balance": recv - sent,
        "tx_count": (cs.get("tx_count", 0) + ms.get("tx_count", 0)),
        "funded_outputs": (cs.get("funded_txo_count", 0) + ms.get("funded_txo_count", 0)),
    }


def balance(address: str) -> float:
    return stats(address)["balance"]


def raw_txs(address: str, max_txs: int = 500) -> List[dict]:
    """Transactions touching this address, paging back through history.

    mempool.space returns ~50 per call. A single page is not enough for
    investigations: famous addresses get spammed with dust, which pushes the
    transactions that actually matter out of the recent window. So we follow
    the /txs/chain/:last_txid cursor until we have enough history.
    """
    out: List[dict] = []
    last: Optional[str] = None
    while len(out) < max_txs:
        path = f"/address/{address}/txs" if last is None \
            else f"/address/{address}/txs/chain/{last}"
        batch = _get(path)
        if not isinstance(batch, list) or not batch:
            break
        out.extend(batch)
        if len(batch) < 25:      # last page
            break
        nxt = batch[-1].get("txid")
        if not nxt or nxt == last:
            break
        last = nxt
    return out[:max_txs]


def _in_addrs(tx: dict) -> List[str]:
    out = []
    for v in tx.get("vin", []) or []:
        a = (v.get("prevout") or {}).get("scriptpubkey_address")
        if a:
            out.append(a)
    return out


def _in_pairs(tx: dict):
    """(address, value) for every input — a UTXO tx can be funded by many parties."""
    for v in tx.get("vin", []) or []:
        p = v.get("prevout") or {}
        a = p.get("scriptpubkey_address")
        if a:
            yield a, (p.get("value", 0) or 0) / SATS


def _out_pairs(tx: dict):
    for o in tx.get("vout", []) or []:
        a = o.get("scriptpubkey_address")
        if a:
            yield a, o.get("value", 0) / SATS


def transfers(address: str, limit: int = 1000) -> List[Dict]:
    """Normalized {from,to,value,timestamp,hash,symbol} rows.

    A Bitcoin transaction has no single sender: it can be funded by many inputs
    from different owners and pay many outputs. Attributing a whole transfer to
    the first input address — the naive shortcut — badly misreports
    consolidations, e.g. crediting one wallet with funds a hundred others
    supplied. So value is split in proportion to what each side actually
    contributed or received.
    """
    me = address
    rows: List[Dict] = []
    for tx in raw_txs(address, max_txs=max(limit, 200)):
        ts = int((tx.get("status") or {}).get("block_time") or 0)
        h = tx.get("txid", "")
        ins = list(_in_pairs(tx))
        outs = list(_out_pairs(tx))
        total_in = sum(v for _, v in ins)
        if total_in <= 0:
            continue

        if me in (a for a, _ in ins):
            # outgoing: our share of the inputs funds our share of each output
            mine_in = sum(v for a, v in ins if a == me)
            share = mine_in / total_in
            # The chain counts a spent output at full value; the recipient gets
            # less, because the miner fee comes out in between. Carry our share
            # of that fee so totals can be reconciled exactly rather than
            # hidden inside a tolerance.
            fee_share = (total_in - sum(v for _, v in outs)) * share
            for a, v in outs:
                if a == me or v <= 0:
                    continue                      # change back to self
                rows.append({"from": me, "to": a, "value": v * share,
                             "timestamp": ts, "hash": h, "symbol": "BTC",
                             "fee_share": fee_share})
        else:
            # incoming: credit every funder in proportion to what it put in
            mine_out = sum(v for a, v in outs if a == me)
            if mine_out <= 0:
                continue
            merged: Dict[str, float] = {}
            for a, v in ins:
                merged[a] = merged.get(a, 0.0) + v
            for a, v in merged.items():
                rows.append({"from": a, "to": me, "value": mine_out * (v / total_in),
                             "timestamp": ts, "hash": h, "symbol": "BTC"})
        if len(rows) >= limit:
            break
    return rows


def cluster(address: str) -> List[tuple]:
    """Common-input-ownership: addresses that co-signed inputs with `address`.

    Returns [(address, times_seen_together)] — likely the same owner's wallets.
    """
    peers: Dict[str, int] = {}
    for tx in raw_txs(address):
        ins = _in_addrs(tx)
        if address in ins and len(set(ins)) > 1:
            for a in set(ins):
                if a != address:
                    peers[a] = peers.get(a, 0) + 1
    return sorted(peers.items(), key=lambda kv: kv[1], reverse=True)
