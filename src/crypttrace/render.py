"""Terminal rendering helpers (rich)."""
from datetime import datetime, timezone
from rich.table import Table
from rich.tree import Tree
from rich.text import Text

from crypttrace.labels import labels
from crypttrace import config, prices


def _ts(unix: str) -> str:
    try:
        return datetime.fromtimestamp(int(unix), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return "?"


def addr_label(address: str) -> Text:
    """Coloured address with icon + known label."""
    t = labels.type_of(address)
    color = {
        "sanctioned": "bold red", "mixer": "magenta", "scam": "bold red",
        "bridge": "cyan", "exchange": "green", "unknown": "white",
    }.get(t, "white")
    name = labels.label_of(address)
    short = address[:10] + "…" + address[-6:]
    txt = Text()
    txt.append(labels.icon(address) + " ")
    txt.append(short, style=color)
    if name:
        txt.append(f"  [{name}]", style=color + " dim")
    return txt


def profile_table(address: str, chain: str, balance: float, txs: list,
                  native_price=None) -> Table:
    t = Table(title=f"Profile — {address}  ({chain})", show_header=True, header_style="bold")
    t.add_column("Field")
    t.add_column("Value")
    bal_usd = prices.usd(balance, native_price)
    bal_str = f"{balance:.6f} (native)"
    if bal_usd is not None:
        bal_str += f"  ≈ {prices.fmt_usd(bal_usd)}"
    t.add_row("Balance", bal_str)
    t.add_row("Total txs (fetched)", str(len(txs)))
    if txs:
        t.add_row("First seen", _ts(txs[-1]["timeStamp"]))
        t.add_row("Last seen", _ts(txs[0]["timeStamp"]))
    hit = labels.lookup(address)
    if hit:
        t.add_row("Label", f"{hit['name']} ({hit['type']})")
    t.add_row("Risk score", f"{labels.risk_score(address)}/100")
    return t


def counterparties_table(address: str, txs: list, top: int = 10) -> Table:
    """Aggregate value moved per counterparty."""
    me = address.lower()
    agg = {}  # counterparty -> [in_value, out_value, count]
    for tx in txs:
        frm, to = tx.get("from", "").lower(), tx.get("to", "").lower()
        val = int(tx.get("value", 0)) / config.WEI
        other = to if frm == me else frm
        if not other:
            continue
        rec = agg.setdefault(other, [0.0, 0.0, 0])
        if frm == me:
            rec[1] += val  # outgoing
        else:
            rec[0] += val  # incoming
        rec[2] += 1
    rows = sorted(agg.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:top]

    t = Table(title="Top counterparties", header_style="bold")
    t.add_column("Address")
    t.add_column("In", justify="right")
    t.add_column("Out", justify="right")
    t.add_column("Txs", justify="right")
    for other, (vin, vout, cnt) in rows:
        t.add_row(addr_label(other), f"{vin:.4f}", f"{vout:.4f}", str(cnt))
    return t


def profile_rows_table(address: str, chain: str, balance: float, rows: list,
                       native_price=None, symbol: str = "") -> Table:
    """Profile built from normalized transfer rows (works on every chain)."""
    t = Table(title=f"Profile — {address}  ({chain})", show_header=True, header_style="bold")
    t.add_column("Field")
    t.add_column("Value")
    bal_usd = prices.usd(balance, native_price)
    bal_str = f"{balance:.8f} {symbol}".rstrip()
    if bal_usd is not None:
        bal_str += f"  ≈ {prices.fmt_usd(bal_usd)}"
    t.add_row("Balance", bal_str)
    t.add_row("Transfers (fetched)", str(len(rows)))
    if rows:
        t.add_row("First seen", _ts(str(rows[-1].get("timestamp", 0))))
        t.add_row("Last seen", _ts(str(rows[0].get("timestamp", 0))))
    hit = labels.lookup(address)
    if hit:
        t.add_row("Label", f"{hit['name']} ({hit['type']})")
    t.add_row("Risk score", f"{labels.risk_score(address)}/100")
    return t


def counterparties_rows_table(address: str, chain: str, rows: list, top: int = 10) -> Table:
    """Counterparties from normalized rows (works on every chain)."""
    me = address if chain in ("btc", "tron", "sol") else address.lower()
    agg = {}
    for r in rows:
        frm, to = r.get("from", ""), r.get("to", "")
        other = to if frm == me else frm
        if not other:
            continue
        rec = agg.setdefault(other, [0.0, 0.0, 0])
        if frm == me:
            rec[1] += r.get("value", 0.0)
        else:
            rec[0] += r.get("value", 0.0)
        rec[2] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:top]

    t = Table(title="Top counterparties", header_style="bold")
    t.add_column("Address")
    t.add_column("In", justify="right")
    t.add_column("Out", justify="right")
    t.add_column("Txs", justify="right")
    for other, (vin, vout, cnt) in ranked:
        t.add_row(addr_label(other), f"{vin:.4f}", f"{vout:.4f}", str(cnt))
    return t


def sources_table(rows: list, symbol: str, top: int = 25) -> Table:
    """Addresses that fed a wallet — in a mass theft, the victim list."""
    t = Table(title=f"Addresses that sent funds here (top {min(top, len(rows))} of {len(rows)})",
              header_style="bold")
    t.add_column("Address")
    t.add_column("Hop", justify="right")
    t.add_column(f"Sent ({symbol})", justify="right")
    t.add_column("Txs", justify="right")
    t.add_column("When (UTC)")
    for r in rows[:top]:
        t.add_row(addr_label(r["address"]), str(r.get("hop", 1)),
                  f"{r['value']:.8f}".rstrip("0").rstrip("."), str(r["txs"]),
                  _ts(str(r.get("first_ts") or 0)))
    return t


def timeline_chart(tl: dict, symbol: str, width: int = 42) -> Table:
    """Text histogram of activity over time."""
    t = Table(title="Activity over time", header_style="bold", box=None, pad_edge=False)
    t.add_column("From (UTC)")
    t.add_column("Transfers", justify="right")
    t.add_column("")
    t.add_column(f"In ({symbol})", justify="right")
    t.add_column(f"Out ({symbol})", justify="right")
    peak = max((b["count"] for b in tl["buckets"]), default=0) or 1
    for b in tl["buckets"]:
        if b["count"] == 0:
            continue
        bar = "█" * max(1, int(b["count"] / peak * width))
        t.add_row(_ts(str(b["start"])), str(b["count"]),
                  f"[cyan]{bar}[/cyan]",
                  f"{b['in']:.4f}" if b["in"] else "",
                  f"{b['out']:.4f}" if b["out"] else "")
    return t


def cluster_table(address: str, peers: list) -> Table:
    """Bitcoin common-input-ownership clustering results."""
    t = Table(title=f"Likely same-owner addresses — {address}", header_style="bold")
    t.add_column("Address")
    t.add_column("Co-signed inputs", justify="right")
    for a, n in peers:
        t.add_row(addr_label(a), str(n))
    return t


def crosschain_tree(address: str, chain: str, results: list) -> Tree:
    """Render bridge-outs and their likely cross-chain continuations."""
    root = Tree(Text.assemble(addr_label(address), Text(f"  (source chain: {chain})")))
    for r in results:
        out = r["bridge_out"]
        when = _ts(str(out["timestamp"]))
        bnode = root.add(Text(f"🌉 bridged {out['amount']:.4f} via {out['bridge']}  ({when})",
                              style="cyan"))
        if not r["arrivals"]:
            bnode.add(Text("↳ no matching arrival found on other chains "
                           "(try a wider --window / --tol, or funds bridged as a token)",
                           style="dim"))
            continue
        for a in r["arrivals"]:
            bnode.add(Text.assemble(
                Text(f"↳ likely continued on {a['chain'].upper()}: received "
                     f"{a['amount']:.4f} ", style="green"),
                Text(f"(+{a['delay_min']:.0f} min, from "),
                addr_label(a["from"]),
                Text(")"),
            ))
    return root


def funding_tree(address: str, hops: list) -> Tree:
    """Render a backward funding chain: target ← funder ← funder …"""
    root = Tree(addr_label(address))
    if not hops:
        root.add(Text("no inbound funding tx found (first-funded internally, or too old)",
                      style="dim"))
        return root
    node = root
    for h in hops:
        when = _ts(h["timestamp"])
        edge = Text(f"◀── funded by {h['value']:.4f} ETH  ({when})  ")
        node = node.add(Text.assemble(edge, addr_label(h["funder"])))
        if h["terminal"]:
            kind = h["funder_type"]
            note = {"exchange": "KYC identification point",
                    "mixer": "mixer — trail obscured",
                    "sanctioned": "sanctioned entity",
                    "bridge": "cross-chain bridge"}.get(kind, kind)
            node.add(Text(f"↳ chain ends at {kind} ({note})", style="dim"))
    return root


def holdings_table(address: str, chain: str, holdings: list) -> Table:
    """Token holdings with per-token and total USD value."""
    t = Table(title=f"Token holdings — {address}  ({chain})", header_style="bold")
    t.add_column("Token")
    t.add_column("Amount", justify="right")
    t.add_column("USD", justify="right")
    t.add_column("Txs", justify="right")
    total = 0.0
    for h in holdings:
        price = prices.token_price(h["contract"], chain, h["symbol"])
        usd = prices.usd(h["net"], price)
        if usd is not None:
            total += usd
        t.add_row(h["symbol"], f"{h['net']:.4f}", prices.fmt_usd(usd), str(h["txs"]))
    t.add_section()
    t.add_row("[bold]Total[/bold]", "", f"[bold]{prices.fmt_usd(total)}[/bold]", "")
    return t
