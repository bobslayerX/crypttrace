"""Export a traced fund-flow graph for the tools analysts already use.

    GraphML  — Gephi, yEd, Cytoscape: nodes keep their label, kind, hop and
               explorer link; edges their amount, USD value, transfer count and
               exchange memo, so a layout can be coloured and sized by them.
    CSV      — one row per edge with both ends' labels and kinds: Maltego's
               "Import Graph from Table" (map `from` and `to` to a
               cryptocurrency-address entity), Neo4j's LOAD CSV, a spreadsheet.

Both take the dict `trace.build_graph` returns, the same graph the web UI draws.
"""
import csv
import io
from xml.sax.saxutils import escape, quoteattr

from crypttrace import chains

NODE_KEYS = [("label", "string"), ("kind", "string"), ("hop", "int"), ("root", "boolean"),
             ("trail_ends", "boolean"), ("chain", "string"), ("explorer", "string")]
EDGE_KEYS = [("amount", "double"), ("symbol", "string"), ("usd", "double"), ("transfers", "int"),
             ("memo", "string")]
CSV_HEAD = ["from", "from_label", "from_kind", "to", "to_label", "to_kind", "amount", "symbol",
            "usd", "transfers", "memo", "chain", "from_explorer", "to_explorer"]


def _node_attrs(n: dict, chain: str) -> dict:
    return {"label": n.get("label") or n.get("short") or n["id"], "kind": n.get("type") or "unknown",
            "hop": n.get("level", 0), "root": bool(n.get("root")), "trail_ends": bool(n.get("terminal")),
            "chain": chain, "explorer": chains.explorer_url(n["id"], chain)}


def _edge_attrs(e: dict, symbol: str) -> dict:
    return {"amount": e.get("value") or 0, "symbol": symbol, "usd": e.get("usd"),
            "transfers": e.get("tx") or 0, "memo": e.get("memo") or ""}


def _val(v, kind: str) -> str:
    if v is None:
        return ""
    if kind == "boolean":
        return "true" if v else "false"
    return escape(str(v))


def to_graphml(graph: dict, chain: str) -> str:
    """GraphML 1.0, directed: money flows along the edges."""
    symbol = graph.get("symbol", "")
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">']
    for k, t in NODE_KEYS:
        out.append(f'  <key id="n_{k}" for="node" attr.name="{k}" attr.type="{t}"/>')
    for k, t in EDGE_KEYS:
        out.append(f'  <key id="e_{k}" for="edge" attr.name="{k}" attr.type="{t}"/>')
    out.append(f'  <graph id={quoteattr("crypttrace " + chain)} edgedefault="directed">')
    for n in graph.get("nodes", []):
        out.append(f'    <node id={quoteattr(n["id"])}>')
        for (k, t), v in zip(NODE_KEYS, _node_attrs(n, chain).values()):
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


FORMATS = {"graphml": (to_graphml, "application/graphml+xml"), "csv": (to_csv, "text/csv")}


def render(graph: dict, chain: str, fmt: str) -> str:
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format '{fmt}' — use one of: {', '.join(FORMATS)}")
    return FORMATS[fmt][0](graph, chain)
