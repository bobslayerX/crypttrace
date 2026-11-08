"""Export a traced fund-flow graph for the tools analysts already use.

    GEXF     — Gephi's own format, and the one to use with it: the layout,
               colours, sizes and edge thickness are in its viz: elements,
               which Gephi applies on open.
    GraphML  — yEd, Cytoscape (and Gephi): nodes keep their label, kind, hop and
               explorer link; edges their amount, USD value, transfer count and
               exchange memo, so a layout can be coloured and sized by them.
               Gephi also reads the layout and look from it: each node carries
               a position (the web UI's left-to-right flow, one column per hop),
               a size and the web UI's colour for its kind, and each edge a
               weight from its value, so the file opens as a readable picture
               instead of a scatter of black dots.
    CSV      — one row per edge with both ends' labels and kinds: Maltego's
               "Import Graph from Table" (map `from` and `to` to a
               cryptocurrency-address entity), Neo4j's LOAD CSV, a spreadsheet.

Both take the dict `trace.build_graph` returns, the same graph the web UI draws.
"""
import csv
import io
import math
from collections import defaultdict
from typing import Dict, Tuple
from xml.sax.saxutils import escape, quoteattr

from crypttrace import chains

# the web UI's colours for each kind of address
COLORS = {"exchange": (63, 223, 135), "mixer": (196, 140, 255), "sanctioned": (255, 107, 96),
          "scam": (255, 107, 96), "bridge": (63, 216, 232), "dex": (77, 157, 255),
          "service": (77, 157, 255), "unknown": (147, 161, 181)}
NOTABLE = {"exchange", "mixer", "sanctioned", "scam", "bridge"}
X_STEP, Y_STEP = 360.0, 150.0

# x, y, size, r, g, b (nodes) and weight (edges) are the names Gephi's GraphML
# importer takes as position, size, colour and edge weight
NODE_KEYS = [("label", "string"), ("kind", "string"), ("hop", "int"), ("root", "boolean"),
             ("trail_ends", "boolean"), ("chain", "string"), ("explorer", "string"),
             ("x", "float"), ("y", "float"), ("size", "float"), ("r", "int"), ("g", "int"), ("b", "int")]
EDGE_KEYS = [("amount", "double"), ("symbol", "string"), ("usd", "double"), ("transfers", "int"),
             ("memo", "string"), ("weight", "double")]
CSV_HEAD = ["from", "from_label", "from_kind", "to", "to_label", "to_kind", "amount", "symbol",
            "usd", "transfers", "memo", "chain", "from_explorer", "to_explorer"]


def layout(graph: dict) -> Dict[str, Tuple[float, float]]:
    """Positions like the web UI's: one column per hop from the investigated
    address, money flowing left to right, and each column ordered by where its
    nodes' neighbours one hop closer sit, so lines cross as little as possible."""
    level = {n["id"]: n.get("level", 0) for n in graph.get("nodes", [])}
    closer = defaultdict(list)                  # node -> its neighbours one hop nearer the root
    for e in graph.get("edges", []):
        a, b = e["from"], e["to"]
        if level.get(a, 0) < level.get(b, 0):
            closer[b].append(a)
        elif level.get(b, 0) < level.get(a, 0):
            closer[a].append(b)
    columns = defaultdict(list)
    for i, lv in level.items():
        columns[lv].append(i)
    y: Dict[str, float] = {}
    for lv in sorted(columns):
        def anchor(i):
            ys = [y[p] for p in closer[i] if p in y]
            return sum(ys) / len(ys) if ys else 0.0
        order = sorted(columns[lv], key=lambda i: (anchor(i), i))
        for j, i in enumerate(order):
            y[i] = (j - (len(order) - 1) / 2) * Y_STEP
    # traced backwards the hops run against the money: mirror, so arrows still point right
    sign = -1 if graph.get("direction") == "in" else 1
    return {i: (sign * lv * X_STEP, -y[i]) for i, lv in level.items()}


def _node_attrs(n: dict, chain: str, pos: Tuple[float, float]) -> dict:
    kind = n.get("type") or "unknown"
    r, g, b = COLORS.get(kind, COLORS["unknown"])
    size = 40.0 if n.get("root") else 26.0 if kind in NOTABLE else 16.0
    return {"label": n.get("label") or n.get("short") or n["id"], "kind": kind,
            "hop": n.get("level", 0), "root": bool(n.get("root")), "trail_ends": bool(n.get("terminal")),
            "chain": chain, "explorer": chains.explorer_url(n["id"], chain),
            "x": round(pos[0], 1), "y": round(pos[1], 1), "size": size, "r": r, "g": g, "b": b}


def _edge_attrs(e: dict, symbol: str) -> dict:
    value = e.get("usd") if e.get("usd") is not None else (e.get("value") or 0)
    return {"amount": e.get("value") or 0, "symbol": symbol, "usd": e.get("usd"),
            "transfers": e.get("tx") or 0, "memo": e.get("memo") or "",
            # thickness by order of magnitude: $100 and $100M both stay drawable
            "weight": round(max(1.0, math.log10(1 + abs(value))), 2)}


def _val(v, kind: str) -> str:
    if v is None:
        return ""
    if kind == "boolean":
        return "true" if v else "false"
    return escape(str(v))


def to_graphml(graph: dict, chain: str) -> str:
    """GraphML 1.0, directed: money flows along the edges."""
    symbol = graph.get("symbol", "")
    pos = layout(graph)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">']
    for k, t in NODE_KEYS:
        out.append(f'  <key id="n_{k}" for="node" attr.name="{k}" attr.type="{t}"/>')
    for k, t in EDGE_KEYS:
        out.append(f'  <key id="e_{k}" for="edge" attr.name="{k}" attr.type="{t}"/>')
    out.append(f'  <graph id={quoteattr("crypttrace " + chain)} edgedefault="directed">')
    for n in graph.get("nodes", []):
        out.append(f'    <node id={quoteattr(n["id"])}>')
        for (k, t), v in zip(NODE_KEYS, _node_attrs(n, chain, pos[n["id"]]).values()):
            if v not in (None, ""):
                out.append(f'      <data key="n_{k}">{_val(v, t)}</data>')
        out.append("    </node>")
    for i, e in enumerate(graph.get("edges", [])):
        out.append(f'    <edge id="e{i}" source={quoteattr(e["from"])} target={quoteattr(e["to"])}>')
        for (k, t), v in zip(EDGE_KEYS, _edge_attrs(e, symbol).values()):
            if v not in (None, ""):
                out.append(f'      <data key="e_{k}">{_val(v, t)}</data>')
        out.append("    </edge>")
    out += ["  </graph>", "</graphml>", ""]
    return "\n".join(out)


def to_gexf(graph: dict, chain: str) -> str:
    """GEXF, Gephi's own format: the layout, colour, size and edge thickness go in
    its viz: elements, which Gephi always applies on open; the data rides along
    as attributes, ready for its filters and partitions."""
    symbol = graph.get("symbol", "")
    pos = layout(graph)
    node_cols = [("kind", "string"), ("hop", "integer"), ("root", "boolean"), ("trail_ends", "boolean"),
                 ("chain", "string"), ("explorer", "string")]
    edge_cols = [("amount", "double"), ("symbol", "string"), ("usd", "double"), ("transfers", "integer"),
                 ("memo", "string")]
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<gexf xmlns="http://www.gexf.net/1.2draft" xmlns:viz="http://www.gexf.net/1.2draft/viz" '
           'version="1.2">',
           f'  <meta><creator>crypttrace</creator><description>{escape(chain)} fund flow, '
           f'{escape(graph.get("direction", "out"))}</description></meta>',
           '  <graph defaultedgetype="directed" mode="static">',
           '    <attributes class="node">']
    out += [f'      <attribute id="{k}" title="{k}" type="{t}"/>' for k, t in node_cols]
    out += ['    </attributes>', '    <attributes class="edge">']
    out += [f'      <attribute id="{k}" title="{k}" type="{t}"/>' for k, t in edge_cols]
    out += ['    </attributes>', '    <nodes>']
    for n in graph.get("nodes", []):
        a = _node_attrs(n, chain, pos[n["id"]])
        out.append(f'      <node id={quoteattr(n["id"])} label={quoteattr(a["label"])}>')
        out.append("        <attvalues>" + "".join(
            f'<attvalue for="{k}" value={quoteattr(_val(a[k], t) if t == "boolean" else str(a[k]))}/>'
            for k, t in node_cols) + "</attvalues>")
        out.append(f'        <viz:size value="{a["size"]}"/>')
        out.append(f'        <viz:position x="{a["x"]}" y="{a["y"]}" z="0.0"/>')
        out.append(f'        <viz:color r="{a["r"]}" g="{a["g"]}" b="{a["b"]}" a="1.0"/>')
        out.append("      </node>")
    out += ['    </nodes>', '    <edges>']
    for i, e in enumerate(graph.get("edges", [])):
        a = _edge_attrs(e, symbol)
        label = f"{a['amount']:,.4f} {symbol}".rstrip()
        out.append(f'      <edge id="{i}" source={quoteattr(e["from"])} target={quoteattr(e["to"])} '
                   f'weight="{a["weight"]}" label={quoteattr(label)}>')
        out.append("        <attvalues>" + "".join(
            f'<attvalue for="{k}" value={quoteattr(str(a[k]))}/>' for k, _ in edge_cols
            if a[k] not in (None, "")) + "</attvalues>")
        out.append(f'        <viz:thickness value="{a["weight"]}"/>')
        out.append('        <viz:color r="150" g="160" b="175" a="1.0"/>')
        out.append("      </edge>")
    out += ['    </edges>', '  </graph>', '</gexf>', '']
    return "\n".join(out)


def to_csv(graph: dict, chain: str) -> str:
    """One row per edge, both ends described — what a link-analysis import wants."""
    symbol = graph.get("symbol", "")
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(CSV_HEAD)
    for e in graph.get("edges", []):
        a, b = nodes.get(e["from"], {"id": e["from"]}), nodes.get(e["to"], {"id": e["to"]})
        ea = _edge_attrs(e, symbol)
        w.writerow([e["from"], a.get("label") or "", a.get("type") or "unknown",
                    e["to"], b.get("label") or "", b.get("type") or "unknown",
                    ea["amount"], symbol, "" if ea["usd"] is None else ea["usd"], ea["transfers"],
                    ea["memo"], chain, chains.explorer_url(e["from"], chain), chains.explorer_url(e["to"], chain)])
    return buf.getvalue()


FORMATS = {"gexf": (to_gexf, "application/gexf+xml"), "graphml": (to_graphml, "application/graphml+xml"),
           "csv": (to_csv, "text/csv")}


def render(graph: dict, chain: str, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format '{fmt}' — use one of: {', '.join(FORMATS)}")
    return FORMATS[fmt][0](graph, chain)
