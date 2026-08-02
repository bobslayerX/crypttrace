"""Fund-flow tracing: follow outgoing value (native coin or a token) N hops deep."""
from typing import Optional
from rich.tree import Tree
from rich.text import Text

from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import config, render, assets, prices, offramp


def _outflows(address, chain, top, asset, direction="out"):
    """Flows for one asset on any supported chain (native coin or a token)."""
    from crypttrace import chains
    return chains.flows(address, chain, top, direction, asset=asset)


class _Ctx:
    """Holds constant tracing context so it isn't threaded through every arg."""
    def __init__(self, chain, branching, asset, symbol, price, direction="out"):
        self.chain = chain
        self.branching = branching
        self.asset = asset
        self.symbol = symbol
        self.price = price
        self.direction = direction


def _edge_text(ctx, to, val, cnt):
    usd = prices.fmt_usd(prices.usd(val, ctx.price))
    money = f"{val:.4f} {ctx.symbol}"
    tail = f" ≈{usd}" if ctx.price is not None else ""
    arrow = "──▶ " if ctx.direction == "out" else "◀── "
    return Text.assemble(Text(f"──{money} ({cnt} tx){tail}{arrow}"), render.addr_label(to))


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
    for to, val, cnt in _outflows(address, ctx.chain, ctx.branching, ctx.asset, ctx.direction):
        _record_finding(findings, ctx, to, val, cnt)
        child = node.add(_edge_text(ctx, to, val, cnt))
        _expand(child, to, ctx, depth - 1, seen, findings)


def build(address, chain, depth, branching, asset=None, direction="out"):
    """Return (tree, findings). direction 'out' follows funds forward, 'in' traces their source."""
    if asset is None:
        from crypttrace import chains as _chains
        symbol = _chains.symbol(chain)
        price = prices.native_price(chain)
    else:
        symbol = asset["symbol"]
        price = prices.token_price(asset["contract"], chain, symbol)
    ctx = _Ctx(chain, branching, asset, symbol, price, direction)

    root = Tree(render.addr_label(address))
    findings = []
    _expand(root, address, ctx, depth, set(), findings, is_root=True)
    return root, findings


def build_tree(address, chain, depth, branching, asset=None, direction="out"):
    tree, _ = build(address, chain, depth, branching, asset, direction)
    return tree


def build_graph(address, chain, depth, branching, asset=None, direction="out"):
    """Return {nodes, edges, symbol} for graph visualization (web UI).

    direction 'out' follows where funds went; 'in' traces where they came from.
    """
    if asset is None:
        from crypttrace import chains as _chains
        symbol = _chains.symbol(chain)
        price = prices.native_price(chain)
    else:
        symbol = asset["symbol"]
        price = prices.token_price(asset["contract"], chain, symbol)

    # Bitcoin / Tron / Solana addresses are case-sensitive (base58); only EVM
    # addresses may be normalized to lowercase.
    from crypttrace import chains as _c
    _norm = (lambda a: a.lower()) if _c.is_evm(chain) else (lambda a: a)

    nodes = {}
    edges = []

    def _node(addr, hop, is_root=False):
        key = _norm(addr)
        if key not in nodes:
            nodes[key] = {
                "id": key,
                "short": addr[:10] + "…" + addr[-6:],
                "type": labels.type_of(addr),
                "label": labels.label_of(addr),
                "root": is_root,
                "terminal": False,
                # hop distance from the investigated address — the renderer uses
                # this as the layout level, which keeps the graph compact and
                # ordered instead of letting the library invent deep levels.
                "level": hop,
            }
        else:
            nodes[key]["level"] = min(nodes[key]["level"], hop)
        return nodes[key]

    def _walk(addr, d, seen, is_root, hop=0):
        _node(addr, hop, is_root)
        key = _norm(addr)
        if d <= 0 or key in seen:
            return
        seen.add(key)
        if not is_root and labels.type_of(addr) in ("exchange", "mixer", "sanctioned", "bridge"):
            nodes[key]["terminal"] = True
            return
        for to, val, cnt in _outflows(addr, chain, branching, asset, direction):
            _node(to, hop + 1)
            # arrows always point the way the money actually travelled
            src, dst = (key, _norm(to)) if direction == "out" else (_norm(to), key)
            edges.append({"from": src, "to": dst,
                          "value": round(val, 4), "tx": cnt,
                          "usd": prices.usd(val, price)})
            _walk(to, d - 1, seen, False, hop + 1)

    _walk(address, depth, set(), True, 0)
    return {"nodes": list(nodes.values()), "edges": edges,
            "symbol": symbol, "direction": direction}
