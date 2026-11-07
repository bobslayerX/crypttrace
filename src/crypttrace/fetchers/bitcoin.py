"""UTXO chains — Bitcoin, Litecoin, Dogecoin — with no API key required.

Bitcoin reads mempool.space and Litecoin its twin litecoinspace.org (both
Esplora). Dogecoin has no public Esplora, so it reads BlockCypher, whose
answers are turned into the same shape; its free tier allows about 100
requests an hour, which is enough for a check and a few hops of tracing.

These chains use the UTXO model, not accounts: a transaction consumes previous
outputs and creates new ones, so there is no single "from" or "to". To fit the
same tracing engine used for EVM chains, transactions are normalized into
directional transfer rows:

  * if our address signed an input, each output that isn't ours is an outflow
    (outputs back to ourselves are change and are skipped);
  * otherwise, outputs paying us are inflows, attributed to the first input.

UTXO chains also enable the strongest clustering heuristic in blockchain
forensics: common-input-ownership. If several addresses sign inputs of the
same transaction, one party almost certainly controls all of them.
"""
import datetime as dt
from typing import List, Dict, Optional

import requests

NETWORKS = {
    "btc": {"name": "Bitcoin", "symbol": "BTC", "api": "esplora", "base": "https://mempool.space/api",
            "host": "mempool.space"},
    "ltc": {"name": "Litecoin", "symbol": "LTC", "api": "esplora", "base": "https://litecoinspace.org/api",
            "host": "litecoinspace.org"},
    "doge": {"name": "Dogecoin", "symbol": "DOGE", "api": "blockcypher",
             "base": "https://api.blockcypher.com/v1/doge/main", "host": "BlockCypher"},
}
UTXO_CHAINS = set(NETWORKS)
BASE = NETWORKS["btc"]["base"]
SATS = 100_000_000          # satoshis, litoshis and koinus alike
BLOCKCYPHER_MAX_TXS = 200   # history read per Dogecoin address: the free tier is ~100 calls an hour


class BitcoinError(RuntimeError):
    pass


def _net(chain: str) -> dict:
    if chain not in NETWORKS:
        raise BitcoinError(f"not a UTXO chain: {chain}")
    return NETWORKS[chain]


def _get(path: str, timeout: int = 30, chain: str = "btc", params: Optional[dict] = None):
    """Cached, throttled GET against the chain's explorer API."""
    from crypttrace.fetchers import http
    n = _net(chain)
    try:
        data = http.request_json(f"{n['base']}{path}", params or {}, timeout=timeout)
    except http.RateLimited as e:
        raise BitcoinError(str(e) + (" (BlockCypher's free tier allows about 100 requests an hour)"
                                     if n["api"] == "blockcypher" else ""))
    except requests.RequestException as e:
        raise BitcoinError(f"{n['host']} request failed: {e}")
    except ValueError as e:
        raise BitcoinError(f"bad response from {n['host']}: {e}")
    if isinstance(data, dict) and "__status__" in data:
        if data["__status__"] == 400:
            raise BitcoinError(f"{n['name']} address rejected by {n['host']} — check it is "
                               "exact (these addresses are case-sensitive).")
        raise BitcoinError(f"Address not found on the {n['name']} chain.")
    return data


def stats(address: str, chain: str = "btc") -> Dict:
    """Authoritative totals straight from the chain index.

    These are the numbers our own parsing must agree with — the reference for
    checking that a trace didn't miscount or silently miss history.
    """
    if _net(chain)["api"] == "blockcypher":
        d = _get(f"/addrs/{address}/balance", chain=chain)
        recv, sent = (d.get("total_received") or 0) / SATS, (d.get("total_sent") or 0) / SATS
        return {"received": recv, "sent": sent, "balance": recv - sent,
                "tx_count": d.get("final_n_tx") or d.get("n_tx") or 0, "funded_outputs": None}
    d = _get(f"/address/{address}", chain=chain)
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


def balance(address: str, chain: str = "btc") -> float:
    return stats(address, chain)["balance"]


def _bc_time(tx: dict) -> int:
    s = tx.get("confirmed") or tx.get("received") or ""
    try:
        return int(dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return 0


def _from_blockcypher(tx: dict) -> dict:
    """A BlockCypher transaction in Esplora's shape, so one parser serves every chain."""
    first = lambda xs: (xs or [None])[0]
    return {
        "txid": tx.get("hash", ""),
        "status": {"block_time": _bc_time(tx)},
        "vin": [{"prevout": {"scriptpubkey_address": first(i.get("addresses")),
                             "value": i.get("output_value") or 0}} for i in tx.get("inputs") or []],
        "vout": [{"scriptpubkey_address": first(o.get("addresses")), "value": o.get("value") or 0}
                 for o in tx.get("outputs") or []],
    }


def raw_txs(address: str, max_txs: int = 500, chain: str = "btc") -> List[dict]:
    """Transactions touching this address, paging back through history.

    The explorers return ~50 per call. A single page is not enough for
    investigations: famous addresses get spammed with dust, which pushes the
    transactions that actually matter out of the recent window. So we follow
    the cursor back until we have enough history.
    """
    out: List[dict] = []
    if _net(chain)["api"] == "blockcypher":
        seen, before = set(), None
        while len(out) < max_txs:
            params = {"limit": 50, "txlimit": 500}      # txlimit: inputs/outputs per tx (default 20)
            if before is not None:
                params["before"] = before
            d = _get(f"/addrs/{address}/full", chain=chain, params=params)
            batch = [t for t in (d.get("txs") or []) if t.get("hash") not in seen]
            if not batch:
                break
            for t in batch:
                seen.add(t.get("hash"))
                out.append(_from_blockcypher(t))
            heights = [t.get("block_height") for t in batch if (t.get("block_height") or -1) > 0]
            if not d.get("hasMore") or not heights:
                break
            before = min(heights)
        return out[:max_txs]
    last: Optional[str] = None
    while len(out) < max_txs:
        path = f"/address/{address}/txs" if last is None \
            else f"/address/{address}/txs/chain/{last}"
        batch = _get(path, chain=chain)
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


def _depth(limit: int, chain: str) -> int:
    """How many transactions of history to read for `limit` transfer rows."""
    depth = max(limit, 200)
    if _net(chain)["api"] == "blockcypher":
        depth = min(depth, BLOCKCYPHER_MAX_TXS)        # 4 calls of the ~100 an hour
    return depth


def change(address: str, limit: int = 1000, chain: str = "btc") -> Dict[str, float]:
    """What the address paid back to itself as change, over the same history
    `transfers` reads. Transfers leave change out — it is not money moving — but
    the chain's totals count it twice, so a check against them adds it back:
    in full to "received" (the change output is the address's), and in the
    address's share of the inputs to "sent" (when others funded the transaction
    too, only that share of what came back was the address's own spending)."""
    received = sent = 0.0
    for tx in raw_txs(address, max_txs=_depth(limit, chain), chain=chain):
        ins = list(_in_pairs(tx))
        mine_in = sum(v for a, v in ins if a == address)
        if mine_in <= 0:
            continue
        back = sum(v for a, v in _out_pairs(tx) if a == address)
        received += back
        sent += back * mine_in / sum(v for _, v in ins)
    return {"received": received, "sent": sent}


def transfers(address: str, limit: int = 1000, chain: str = "btc") -> List[Dict]:
    """Normalized {from,to,value,timestamp,hash,symbol} rows.

    A UTXO transaction has no single sender: it can be funded by many inputs
    from different owners and pay many outputs. Attributing a whole transfer to
    the first input address — the naive shortcut — badly misreports
    consolidations, e.g. crediting one wallet with funds a hundred others
    supplied. So value is split in proportion to what each side actually
    contributed or received.
    """
    me = address
    sym = _net(chain)["symbol"]
    rows: List[Dict] = []
    for tx in raw_txs(address, max_txs=_depth(limit, chain), chain=chain):
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
            # one row per recipient: several equal outputs to one address in one
            # transaction would otherwise be identical rows, and the store keeps one
            paid: Dict[str, float] = {}
            for a, v in outs:
                if a == me or v <= 0:
                    continue                      # change back to self
                paid[a] = paid.get(a, 0.0) + v
            for a, v in paid.items():
                rows.append({"from": me, "to": a, "value": v * share,
                             "timestamp": ts, "hash": h, "symbol": sym,
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
                             "timestamp": ts, "hash": h, "symbol": sym})
        if len(rows) >= limit:
            break
    return rows


def cluster(address: str, chain: str = "btc") -> List[tuple]:
    """Common-input-ownership: addresses that co-signed inputs with `address`.

    Returns [(address, times_seen_together)] — likely the same owner's wallets.
    """
    peers: Dict[str, int] = {}
    for tx in raw_txs(address, chain=chain):
        ins = _in_addrs(tx)
        if address in ins and len(set(ins)) > 1:
            for a in set(ins):
                if a != address:
                    peers[a] = peers.get(a, 0) + 1
    return sorted(peers.items(), key=lambda kv: kv[1], reverse=True)
