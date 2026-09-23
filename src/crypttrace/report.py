"""Investigation reports: an HTML case file to hand over, plus Markdown and JSON.

The HTML file is the one a victim sends to an exchange or attaches to a police
report, so it is built for the person receiving it:

  * one file, nothing external — no scripts, fonts or CDN, so it opens in a
    locked-down browser or mail client, prints, and "opening it" tells nobody;
  * the fund-flow graph as a static SVG, each address linking to a block
    explorer, so every line can be checked independently;
  * the transfers along the trace with their transaction hashes — what an
    exchange's compliance team asks for first;
  * where every label comes from, how the tool checked its own arithmetic, and
    what the method cannot tell you.

The same data is written as JSON (for analysts) and Markdown. Everything is read
through the shared chain layer, so reports work on every supported chain.
"""
import hashlib
import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from crypttrace import __version__, chains, prices
from crypttrace import freeze as freeze_mod
from crypttrace import trace as trace_mod
from crypttrace.labels import labels

SOURCES = {"btc": "mempool.space", "tron": "TronGrid", "sol": "Solana JSON-RPC"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _ts(unix) -> str:
    try:
        return datetime.fromtimestamp(int(unix), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError, OSError):
        return "?"


def _tree_text(tree) -> str:
    """Render the rich trace tree to plain text (ANSI stripped)."""
    con = Console(record=True, width=100, file=None)
    with con.capture() as cap:
        con.print(tree)
    return cap.get()


def _headline(findings: list) -> str:
    types = {f["type"] for f in findings}
    if "sanctioned" in types:
        return ("Funds from this address reach a **sanctioned / known-criminal wallet** — "
                "escalate to law enforcement.")
    if "mixer" in types:
        return ("Funds from this address flow into a **mixer** (privacy pool), where on-chain "
                "tracing terminates. Recovery from here requires timing/amount heuristics or "
                "off-chain data.")
    if types & {"exchange", "offramp"}:
        return ("Funds from this address reach a **centralised exchange** — a KYC handoff point. "
                "Identifying the owner requires a legal request to that exchange.")
    return ("No labelled entities were reached within the traced depth. Increase --depth or "
            "extend the label database, then re-run.")


def _counterparties(me: str, rows: List[dict], top: int = 15) -> List[dict]:
    agg: Dict[str, list] = {}
    for r in rows:
        frm, to = r.get("from") or "", r.get("to") or ""
        other = to if frm == me else frm if to == me else ""
        if not other or other == me:
            continue
        rec = agg.setdefault(other, [0.0, 0.0, 0])
        rec[1 if frm == me else 0] += r.get("value", 0) or 0
        rec[2] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:top]
    return [{"address": a, "in": round(i, 6), "out": round(o, 6), "txs": n,
             "label": labels.label_of(a), "type": labels.type_of(a)}
            for a, (i, o, n) in ranked]


def _edge_evidence(graph: dict, chain: str, asset) -> None:
    """Attach the transactions behind each graph edge (hashes, first/last time).

    The history is already in the local store from the trace, so this costs no
    requests."""
    for e in graph["edges"]:
        try:
            rows = chains.transfers(e["from"], chain, 1000, asset=asset)
        except chains.ChainError:
            rows = []
        hits = sorted((r for r in rows if r.get("from") == e["from"] and r.get("to") == e["to"]),
                      key=lambda r: r.get("timestamp", 0))
        e["hashes"] = [r["hash"] for r in hits if r.get("hash")][:10]
        e["first_ts"] = hits[0].get("timestamp") if hits else None
        e["last_ts"] = hits[-1].get("timestamp") if hits else None


def collect(address: str, chain: str, depth: int, branching: int, asset=None) -> dict:
    """Everything a report shows, as plain data (also the JSON file)."""
    from crypttrace import assess as assess_mod, freeze as freeze_mod
    from crypttrace.labels import audit

    me = chains.norm_addr(address, chain)
    symbol = asset["symbol"] if asset else chains.symbol(chain)
    errors: List[str] = []

    balance, rows = None, []
    try:
        balance = chains.balance(address, chain)
    except chains.ChainError as e:
        errors.append(f"balance: {e}")
    try:
        rows = chains.transfers(address, chain, 1000, asset=asset)
    except chains.ChainError as e:
        errors.append(f"history: {e}")

    tree_text, findings, graph = "", [], {"nodes": [], "edges": [], "symbol": symbol}
    try:
        tree, found = trace_mod.build(address, chain, depth, branching, asset)
        tree_text = _tree_text(tree)
        best: Dict[str, dict] = {}
        for f in found:
            if f["address"] not in best or f["value_reached"] > best[f["address"]]["value_reached"]:
                best[f["address"]] = f
        findings = sorted(best.values(), key=lambda f: f["risk"], reverse=True)
        graph = trace_mod.build_graph(address, chain, depth, branching, asset)
        _edge_evidence(graph, chain, asset)
    except chains.ChainError as e:
        errors.append(f"trace: {e}")

    try:
        assessment = assess_mod.assess(address, chain, asset)
    except Exception as e:          # a report must still be written without it
        assessment = {"error": str(e)}
        errors.append(f"assessment: {e}")

    hit = labels.lookup(address)
    evidence = {n["id"]: audit.evidence(n["id"]) for n in graph["nodes"] if n.get("label")}
    if hit and me not in evidence:
        evidence[me] = audit.evidence(address)

    return {
        "tool": f"crypttrace v{__version__}",
        "generated": _now(),
        "subject": address, "chain": chain, "traced_asset": symbol,
        "trace_depth": depth, "trace_branching": branching,
        "data_source": SOURCES.get(chain, "Etherscan v2"),
        "summary": {
            "balance_native": None if balance is None else round(balance, 8),
            "native_symbol": chains.symbol(chain),
            "transfers_analysed": len(rows),
            "first_seen": _ts(rows[-1]["timestamp"]) if rows else None,
            "last_seen": _ts(rows[0]["timestamp"]) if rows else None,
            "label": hit["name"] if hit else None,
            "type": labels.type_of(address),
            "risk_score": labels.risk_score(address),
        },
        "assessment": assessment,
        "freeze": [] if labels.type_of(address) == "exchange" else freeze_mod.check(address, chain),
        "key_findings": findings,
        "graph": graph,
        "label_evidence": evidence,
        "top_counterparties": _counterparties(me, rows),
        "tree_text": tree_text,
        "errors": errors,
    }


def generate(address: str, chain: str, depth: int, branching: int,
             out_dir: Path, asset=None, guidance: Optional[dict] = None) -> Dict[str, Path]:
    """Write <case>.html, <case>.md and <case>.json; returns their paths."""
    data, raw, digest = build(address, chain, depth, branching, asset, guidance)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = case_name(address, chain)
    paths = {k: out_dir / f"{base}.{k}" for k in ("html", "md", "json")}
    # bytes, not text mode: on Windows text mode turns LF into CRLF, and the hash
    # printed in the HTML would no longer match the file next to it
    paths["json"].write_bytes(raw.encode("utf-8"))
    paths["md"].write_text(_render_md(data, paths["json"].name), encoding="utf-8")
    paths["html"].write_text(render_html(data, raw, digest, paths["json"].name), encoding="utf-8")
    return paths


def case_name(address: str, chain: str) -> str:
    return f"{chain}_{address[:10]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"


def build(address: str, chain: str, depth: int, branching: int, asset=None,
          guidance: Optional[dict] = None):
    """(data, raw JSON, its SHA-256) — the web UI renders the page from this in memory."""
    data = collect(address, chain, depth, branching, asset)
    if guidance:
        data["guidance"] = guidance
    raw = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    return data, raw, hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------ markdown

def _render_md(d: dict, json_name: str) -> str:
    s = d["summary"]
    a = d.get("assessment") or {}
    L = [f"# crypttrace investigation report\n\n",
         f"**Generated:** {d['generated']}  •  **Tool:** {d['tool']}  \n",
         f"**Subject:** `{d['subject']}`  •  **Chain:** {d['chain']}  •  "
         f"**Traced asset:** {d['traced_asset']}\n",
         "\n## Assessment\n", (a.get("assessment") or _headline(d["key_findings"])) + "\n"]
    if a.get("risk") is not None:
        L.append(f"\nRisk {a['risk']}/100, confidence {a.get('confidence')}.\n")
    for f in d.get("freeze") or []:
        if f.get("frozen"):
            L.append(f"\n**{freeze_mod.describe_frozen(f)}.**\n")
        elif f.get("actionable"):
            L.append(f"\n**{f['movable']:,.2f} {f['token']} is still at this address and not "
                     f"frozen.** {f['how']}\n")
    L += ["\n## Summary\n", "| Field | Value |\n|---|---|\n",
          f"| Balance | {s['balance_native']} {s['native_symbol']} |\n",
          f"| Transfers analysed | {s['transfers_analysed']} |\n",
          f"| First seen | {s['first_seen']} |\n", f"| Last seen | {s['last_seen']} |\n",
          f"| Label | {s['label'] or '—'} |\n", f"| Risk score | {s['risk_score']}/100 |\n",
          "\n## Key findings\n"]
    if d["key_findings"]:
        L.append("| Entity | Type | Risk | Value reached | ≈ USD |\n|---|---|---|---|---|\n")
        for f in d["key_findings"]:
            L.append(f"| {f['label']} | {f['type']} | {f['risk']}/100 | {f['value_reached']} "
                     f"{f.get('symbol', '')} | {prices.fmt_usd(f.get('usd_reached'))} |\n")
    else:
        L.append("_None within the traced depth._\n")
    L += ["\n## Top counterparties\n", "| Address | Label | In | Out | Txs |\n|---|---|---|---|---|\n"]
    for c in d["top_counterparties"]:
        L.append(f"| `{c['address']}` | {c['label'] or '—'} | {c['in']} | {c['out']} | {c['txs']} |\n")
    L += [f"\n## Fund-flow trace (depth {d['trace_depth']})\n",
          "```\n" + (d["tree_text"] or "").rstrip() + "\n```\n",
          "\n## Methodology & limitations\n", _METHOD + "\n",
          f"\n---\n_Raw structured data: `{json_name}` (same folder)._\n"]
    return "".join(L)


_METHOD = (
    "Data comes from the public blockchain. The trace follows the largest outgoing transfers "
    "from each address and stops at identifiable entities (exchanges, mixers, sanctioned "
    "wallets). Exchange deposit addresses are recognised either from lists exchanges publish "
    "themselves or by behaviour (forwarding most funds to one exchange), which is a strong "
    "lead, not proof. The blockchain is pseudonymous: reaching an address does not identify "
    "its owner — an exchange can, on a legal request. Mixers sever the trail. This report is "
    "an investigative aid, not proof of wrongdoing.")


# ---------------------------------------------------------------------- html

_TYPE_COLOUR = {"exchange": "#1f9d55", "offramp": "#1f9d55", "mixer": "#7c3aed",
                "sanctioned": "#dc2626", "scam": "#dc2626", "bridge": "#0891b2",
                "unknown": "#64748b"}


def _e(v) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def _link(url: str, text: str, mono: bool = True) -> str:
    cls = ' class="mono"' if mono else ""
    return f'<a href="{_e(url)}" target="_blank" rel="noopener"{cls}>{_e(text)}</a>'


def _amount(v, symbol="") -> str:
    if v is None:
        return "—"
    return f"{v:,.4f}".rstrip("0").rstrip(".") + (f" {symbol}" if symbol else "")


def _svg(graph: dict, chain: str) -> str:
    """Left-to-right layered drawing: one column per hop from the subject."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    if not nodes:
        return '<p class="muted">No transfers to draw at this depth.</p>'
    W, H, COL, ROW, PAD = 210, 46, 290, 74, 20
    levels: Dict[int, List[str]] = {}
    for n in graph["nodes"]:
        levels.setdefault(n.get("level", 0), []).append(n["id"])
    # order each column by where its parents sit, which keeps lines from crossing
    ypos: Dict[str, float] = {}
    for lvl in sorted(levels):
        def parent_y(nid):
            ys = [ypos[e["from"]] for e in graph["edges"] if e["to"] == nid and e["from"] in ypos]
            return sum(ys) / len(ys) if ys else 0
        levels[lvl].sort(key=parent_y)
        for i, nid in enumerate(levels[lvl]):
            ypos[nid] = i
    tallest = max(len(v) for v in levels.values())
    width = PAD * 2 + (max(levels) + 1) * COL - (COL - W)
    height = PAD * 2 + tallest * ROW
    xy = {}
    for lvl, ids in levels.items():
        top = PAD + (tallest - len(ids)) * ROW / 2
        for i, nid in enumerate(ids):
            xy[nid] = (PAD + lvl * COL, top + i * ROW)

    sym = graph.get("symbol", "")
    out = [f'<svg viewBox="0 0 {width} {height}" width="{width}" role="img" '
           f'aria-label="Fund-flow graph" xmlns="http://www.w3.org/2000/svg">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
           'markerHeight="7" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" '
           'fill="#94a3b8"/></marker></defs>']
    for e in graph["edges"]:
        if e["from"] not in xy or e["to"] not in xy:
            continue
        (x1, y1), (x2, y2) = xy[e["from"]], xy[e["to"]]
        sx, sy, tx, ty = x1 + W, y1 + H / 2, x2, y2 + H / 2
        mid = (sx + tx) / 2
        out.append(f'<path d="M{sx},{sy} C{mid},{sy} {mid},{ty} {tx - 2},{ty}" fill="none" '
                   f'stroke="#94a3b8" stroke-width="1.6" marker-end="url(#arr)"/>')
        label = f"{_amount(e['value'])} {sym} · {e['tx']} tx"
        out.append(f'<text x="{mid}" y="{(sy + ty) / 2 - 5}" text-anchor="middle" '
                   f'class="edge">{_e(label)}</text>')
    for nid, (x, y) in xy.items():
        n = nodes[nid]
        colour = _TYPE_COLOUR.get(n.get("type"), _TYPE_COLOUR["unknown"])
        title = (n.get("label") + "\n" if n.get("label") else "") + nid
        name = n.get("label") or ("subject" if n.get("root") else "unlabelled")
        out.append(f'<a href="{_e(chains.explorer_url(nid, chain))}" target="_blank" rel="noopener">'
                   f'<title>{_e(title)}</title>'
                   f'<rect x="{x}" y="{y}" width="{W}" height="{H}" rx="8" fill="{colour}" '
                   f'fill-opacity="0.12" stroke="{colour}" stroke-width="{3 if n.get("root") else 1.4}"/>'
                   f'<text x="{x + 10}" y="{y + 19}" class="nname">{_e(name[:30])}</text>'
                   f'<text x="{x + 10}" y="{y + 36}" class="naddr">{_e(n["short"])}</text></a>')
    out.append("</svg>")
    return "".join(out)


_CSS = """
:root{--fg:#0f172a;--muted:#64748b;--line:#e2e8f0;--bg:#fff;--card:#f8fafc;--red:#b91c1c;--green:#15803d}
@media (prefers-color-scheme:dark){:root{--fg:#e2e8f0;--muted:#94a3b8;--line:#334155;--bg:#0b1120;--card:#111827}}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg);
 max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:4px}
.muted{color:var(--muted)}.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px;word-break:break-all}
.box{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:10px 0}
.alert{border-color:var(--red)}.ok{border-color:var(--green)}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.num{text-align:right;white-space:nowrap}
.graph{overflow-x:auto;border:1px solid var(--line);border-radius:10px;padding:8px;background:var(--card)}
svg text{fill:var(--fg);font-family:system-ui,sans-serif}svg .edge{font-size:11px;fill:var(--muted)}
svg .nname{font-size:12px;font-weight:600}svg .naddr{font-size:11px;font-family:ui-monospace,Consolas,monospace}
a{color:#2563eb}ol li{margin-bottom:8px}.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;border:1px solid var(--line)}
@media print{:root{--fg:#000;--muted:#444;--line:#bbb;--bg:#fff;--card:#fff}
 body{max-width:none;padding:0}.graph{overflow:visible}a{color:inherit;text-decoration:none}}
"""


def render_html(d: dict, raw_json: str, digest: str, json_name: str) -> str:
    s, a, chain = d["summary"], d.get("assessment") or {}, d["chain"]
    sym = d["traced_asset"]
    P: List[str] = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Case file — {_e(d['subject'][:12])}…</title><style>{_CSS}</style></head><body>",
        "<h1>Crypto investigation case file</h1>",
        f"<p class='muted'>Generated {_e(d['generated'])} by {_e(d['tool'])} · chain {_e(chain)} · "
        f"traced asset {_e(sym)} · data from {_e(d['data_source'])}</p>",
        f"<div class='box'><b>Subject address</b><br>{_link(chains.explorer_url(d['subject'], chain), d['subject'])}"
        + (f"<br>Known as: <b>{_e(s['label'])}</b>" if s["label"] else "") + "</div>",
    ]

    # in short
    P.append("<h2>In short</h2>")
    P.append(f"<p>{_e(a.get('assessment') or _headline(d['key_findings']).replace('**', ''))}</p>")
    if a.get("risk") is not None:
        ver = (a.get("verification") or {}).get("status", "—")
        P.append(f"<p><span class='pill'>risk {a['risk']}/100</span> <span class='pill'>confidence "
                 f"{_e(a.get('confidence'))}</span> <span class='pill'>own arithmetic: {_e(ver)}</span></p>")

    # act now
    acts = []
    for f in d.get("freeze") or []:
        if f.get("frozen"):
            acts.append(f"<div class='box ok'><b>{_e(freeze_mod.describe_frozen(f))}.</b> Frozen "
                        "funds cannot be moved and can be returned to victims through a legal "
                        "process.</div>")
        elif f.get("actionable"):
            acts.append(f"<div class='box alert'><b>{f['movable']:,.2f} {_e(f['token'])} is still at this "
                        f"address and not frozen.</b> {_e(f['how'])} "
                        f"{_link(f['url'], f['issuer'] + ' policy', mono=False)}</div>")
    for sig in a.get("signals") or []:
        if sig["name"] in ("address poisoning", "paid a look-alike"):
            acts.append(f"<div class='box alert'><b>Address poisoning.</b> {_e(sig['observed'])} — "
                        f"{_e(sig['implication'])}.</div>")
    exch = sorted({labels.company(f["label"]) for f in d["key_findings"]
                   if f["type"] in ("exchange", "offramp")})
    if exch:
        acts.append(f"<div class='box'><b>The funds reach {_e(', '.join(exch))}.</b> An exchange knows "
                    "who owns the receiving account and can freeze it on request. Give its compliance "
                    "team the transaction hashes below.</div>")
    if acts:
        P.append("<h2>Act now</h2>" + "".join(acts))

    guidance = d.get("guidance")
    if guidance and guidance.get("steps"):
        P.append("<h2>What to do next</h2><ol>")
        for st in guidance["steps"]:
            P.append(f"<li><b>{_e(st['title'])}</b>{' <span class=pill>do this first</span>' if st.get('urgent') else ''}"
                     f"<br>{_e(st['body'])}</li>")
        P.append("</ol>")

    # graph
    P.append(f"<h2>Where the money went (depth {d['trace_depth']})</h2>")
    P.append("<p class='muted'>Each box links to the address on a block explorer; hover for the full "
             "address. Green: exchange · purple: mixer · red: sanctioned or scam · teal: bridge · "
             "grey: unlabelled.</p>")
    P.append(f"<div class='graph'>{_svg(d['graph'], chain)}</div>")

    # transfers with hashes
    edges = d["graph"]["edges"]
    if edges:
        P.append("<h2>Transfers along the trace</h2><table><tr><th>From</th><th>To</th>"
                 "<th>Amount</th><th>Txs</th><th>First / last (UTC)</th><th>Transactions</th></tr>")
        for e in edges:
            to_lbl = labels.label_of(e["to"])
            hashes = " ".join(_link(chains.tx_url(h, chain), h[:10] + "…") for h in e.get("hashes", []))
            P.append(f"<tr><td>{_link(chains.explorer_url(e['from'], chain), e['from'])}</td>"
                     f"<td>{_link(chains.explorer_url(e['to'], chain), e['to'])}"
                     + (f"<br><b>{_e(to_lbl)}</b>" if to_lbl else "") + "</td>"
                     f"<td class='num'>{_e(_amount(e['value'], sym))}</td><td class='num'>{e['tx']}</td>"
                     f"<td>{_e(_ts(e.get('first_ts')))}<br>{_e(_ts(e.get('last_ts')))}</td>"
                     f"<td>{hashes or '—'}</td></tr>")
        P.append("</table>")

    # signals
    if a.get("signals"):
        P.append("<h2>What the assessment rests on</h2><table><tr><th>Signal</th><th>Observed</th>"
                 "<th>Means</th><th>Confidence</th></tr>")
        for sig in a["signals"]:
            P.append(f"<tr><td>{_e(sig['name'])}</td><td>{_e(sig['observed'])}</td>"
                     f"<td>{_e(sig['implication'])}</td><td>{_e(sig['confidence'])}</td></tr>")
        P.append("</table>")
    for c in a.get("caveats") or []:
        P.append(f"<p class='muted'>Caveat: {_e(c)}</p>")

    # label evidence
    ev = [v for v in (d.get("label_evidence") or {}).values() if v.get("known")]
    if ev:
        P.append("<h2>Where each label comes from</h2><table><tr><th>Address</th><th>Label</th>"
                 "<th>Source</th><th>Kind</th></tr>")
        for v in ev:
            P.append(f"<tr><td>{_link(chains.explorer_url(v['address'], chain), v['address'])}</td>"
                     f"<td>{_e(v['name'])}</td><td>{_e(v['source']) or '<i>none recorded</i>'}</td>"
                     f"<td>{_e(v['source_kind']) or '—'}</td></tr>")
        P.append("</table>")

    # summary + counterparties
    P.append("<h2>Subject address</h2><table>")
    for k, v in [("Balance", f"{s['balance_native']} {s['native_symbol']}"),
                 ("Transfers analysed", s["transfers_analysed"]), ("First seen", s["first_seen"]),
                 ("Last seen", s["last_seen"]), ("Label", s["label"] or "—")]:
        P.append(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>")
    P.append("</table>")
    if d["top_counterparties"]:
        P.append(f"<h2>Largest counterparties</h2><table><tr><th>Address</th><th>Label</th>"
                 f"<th>In ({_e(sym)})</th><th>Out ({_e(sym)})</th><th>Txs</th></tr>")
        for c in d["top_counterparties"]:
            P.append(f"<tr><td>{_link(chains.explorer_url(c['address'], chain), c['address'])}</td>"
                     f"<td>{_e(c['label']) or '—'}</td><td class='num'>{_e(_amount(c['in']))}</td>"
                     f"<td class='num'>{_e(_amount(c['out']))}</td><td class='num'>{c['txs']}</td></tr>")
        P.append("</table>")

    P.append(f"<h2>Method and limits</h2><p>{_e(_METHOD)}</p>")
    if d.get("errors"):
        P.append("<p class='muted'>Parts that could not be read: " + _e("; ".join(d["errors"])) + "</p>")
    where = (f"saved next to this file as <span class='mono'>{_e(json_name)}</span>"
             if json_name else "embedded in this file")
    P.append(f"<p class='muted'>The raw data is {where} (SHA-256 of the JSON: "
             f"<span class='mono'>{digest}</span>) and embedded below for analysts.</p>")
    # JSON inside <script type=application/json> is data, never executed. Every "<" is
    # written as < (still valid JSON), so a crafted token or label name can neither
    # close the element nor push the parser into its "<!--<script" escaping states.
    P.append("<script type='application/json' id='case-data'>" + raw_json.replace("<", "\\u003c")
             + "</script></body></html>")
    return "".join(P)
