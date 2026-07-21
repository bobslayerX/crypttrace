"""Fund-flow tracing: follow outgoing value from an address N hops deep."""
from typing import Optional
from rich.tree import Tree
from rich.text import Text

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config, render


def _biggest_outflows(address: str, chain: str, top: int):
    """Return [(to_address, total_value, tx_count)] for outgoing native txs, ranked."""
    me = address.lower()
    txs = etherscan.get_txs(address, chain, limit=1000)
    agg = {}
    for tx in txs:
        if tx.get("from", "").lower() != me:
            continue
        to = tx.get("to", "").lower()
        if not to:
            continue
        val = int(tx.get("value", 0)) / config.WEI
        rec = agg.setdefault(to, [0.0, 0])
        rec[0] += val
        rec[1] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)
    return [(a, v, c) for a, (v, c) in ranked if v > 0][:top]


def _node_text(address: str, edge: Optional[tuple]) -> Text:
    """Address label, optionally prefixed with the inflow edge (value, tx count)."""
    if edge is None:
        return render.addr_label(address)
    val, cnt = edge
    return Text.assemble(Text(f"──{val:.4f} ({cnt} tx)──▶ "), render.addr_label(address))


def _expand(node: Tree, address: str, chain: str, depth: int, branching: int, seen: set) -> None:
    if depth <= 0:
        return
    if address.lower() in seen:
        node.add(Text("↳ already visited (cycle)", style="dim"))
        return
    seen.add(address.lower())

    # Trail ends at an identifiable entity — that's the OSINT handoff point.
    if labels.type_of(address) in ("exchange", "mixer", "sanctioned"):
        node.add(Text("↳ trail ends here (identifiable entity — subpoena / off-chain)", style="dim"))
        return

    for to, val, cnt in _biggest_outflows(address, chain, branching):
        child = node.add(_node_text(to, (val, cnt)))
        _expand(child, to, chain, depth - 1, branching, seen)


def build_tree(address: str, chain: str, depth: int, branching: int) -> Tree:
    root = Tree(_node_text(address, None))
    _expand(root, address, chain, depth, branching, set())
    return root
