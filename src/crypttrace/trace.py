"""Fund-flow tracing: follow outgoing value (native coin or a token) N hops deep."""
from typing import Optional
from rich.tree import Tree
from rich.text import Text

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config, render, assets, prices, offramp


def _native_outflows(address, chain, top):
    """Native-coin outflows for any supported chain (EVM, BTC, Tron, Solana)."""
    from crypttrace import chains
    return chains.outflows(address, chain, top)


def _token_outflows(address, chain, top, contract):
    me = address.lower()
    agg = {}
    for r in assets.token_transfers(address, chain, contract):
        if r["from"] != me:
            continue
        to = r["to"]
        if not to:
            continue
        rec = agg.setdefault(to, [0.0, 0]); rec[0] += r["value"]; rec[1] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)
    return [(a, v, c) for a, (v, c) in ranked if v > 0][:top]


def _outflows(address, chain, top, asset):
    if asset is None:
        return _native_outflows(address, chain, top)
    return _token_outflows(address, chain, top, asset["contract"])


class _Ctx:
    """Holds constant tracing context so it isn't threaded through every arg."""
    def __init__(self, chain, branching, asset, symbol, price):
        self.chain = chain
        self.branching = branching
        self.asset = asset
        self.symbol = symbol
        self.price = price


def _edge_text(ctx, to, val, cnt):
    usd = prices.fmt_usd(prices.usd(val, ctx.price))
    money = f"{val:.4f} {ctx.symbol}"
    tail = f" ≈{usd}" if ctx.price is not None else ""
    return Text.assemble(Text(f"──{money} ({cnt} tx){tail}──▶ "), render.addr_label(to))


def _record_finding(findings, ctx, to, val, cnt):
    if findings is None:
        return
    hit = labels.lookup(to)
    if not hit:
        return
    findings.append({"address": to, "type": hit["type"], "label": hit["name"],
                     "risk": labels.risk_score(to), "value_reached": round(val, 6),
                     "symbol": ctx.symbol, "usd_reached": prices.usd(val, ctx.price),
                     "tx_count": cnt})


def _expand(node, address, ctx, depth, seen, findings=None, is_root=False):
    if depth <= 0:
        return
    if address.lower() in seen:
        node.add(Text("↳ already visited (cycle)", style="dim")); return
    seen.add(address.lower())
    if not is_root and labels.type_of(address) in ("exchange", "mixer", "sanctioned"):
        node.add(Text("↳ trail ends here (identifiable entity — subpoena / off-chain)", style="dim"))
        return
    if not is_root and labels.type_of(address) == "bridge":
        node.add(Text("↳ bridge — funds leave this chain; run `crypttrace crosschain` "
                      "on the sender to find the destination chain", style="cyan"))
        return
    # Off-ramp heuristic: an unknown wallet that forwards most funds to an
    # exchange is a deposit address — the cash-out / KYC point. Native only.
    if not is_root and ctx.asset is None and labels.type_of(address) == "unknown":
        off = offramp.detect(address, ctx.chain)
        if off:
            pct = int(off["fraction"] * 100)
            node.add(Text(f"↳ off-ramp: ~{pct}% forwarded to {off['exchange']} "
                          f"— likely a deposit address (KYC point)", style="green"))
            if findings is not None:
                findings.append({"address": address, "type": "offramp",
                                 "label": f"{off['exchange']} deposit (off-ramp)",
                                 "risk": 30, "value_reached": round(off["forwarded"], 6),
                                 "symbol": ctx.symbol,
                                 "usd_reached": prices.usd(off["forwarded"], ctx.price),
                                 "tx_count": 0})
            return
    for to, val, cnt in _outflows(address, ctx.chain, ctx.branching, ctx.asset):
        _record_finding(findings, ctx, to, val, cnt)
        child = node.add(_edge_text(ctx, to, val, cnt))
        _expand(child, to, ctx, depth - 1, seen, findings)


def build(address, chain, depth, branching, asset=None):
    """Return (tree, findings). `asset` is None (native) or a descriptor from assets.resolve_asset."""
    if asset is None:
        from crypttrace import chains as _chains
        symbol = _chains.symbol(chain)
        price = prices.native_price(chain)
    else:
        symbol = asset["symbol"]
        price = prices.token_price(asset["contract"], chain, symbol)
    ctx = _Ctx(chain, branching, asset, symbol, price)

    root = Tree(render.addr_label(address))
    findings = []
    _expand(root, address, ctx, depth, set(), findings, is_root=True)
    return root, findings


def build_tree(address, chain, depth, branching, asset=None):
    tree, _ = build(address, chain, depth, branching, asset)
    return tree


def build_graph(address, chain, depth, branching, asset=None):
    """Return {nodes, edges, symbol} for graph visualization (web UI)."""
    if asset is None:
        from crypttrace import chains as _chains
        symbol = _chains.symbol(chain)
        price = prices.native_price(chain)
    else:
        symbol = asset["symbol"]
        price = prices.token_price(asset["contract"], chain, symbol)

    nodes = {}
    edges = []

    def _node(addr, is_root=False):
        key = addr.lower()
        if key not in nodes:
            nodes[key] = {
                "id": key,
                "short": addr[:10] + "…" + addr[-6:],
                "type": labels.type_of(addr),
                "label": labels.label_of(addr),
                "root": is_root,
                "terminal": False,
            }
        return nodes[key]

    def _walk(addr, d, seen, is_root):
        _node(addr, is_root)
        if d <= 0 or addr.lower() in seen:
            return
        seen.add(addr.lower())
        if not is_root and labels.type_of(addr) in ("exchange", "mixer", "sanctioned", "bridge"):
            nodes[addr.lower()]["terminal"] = True
            return
        for to, val, cnt in _outflows(addr, chain, branching, asset):
            _node(to)
            edges.append({"from": addr.lower(), "to": to.lower(),
                          "value": round(val, 4), "tx": cnt,
                          "usd": prices.usd(val, price)})
            _walk(to, d - 1, seen, False)

    _walk(address, depth, set(), True)
    return {"nodes": list(nodes.values()), "edges": edges, "symbol": symbol}
