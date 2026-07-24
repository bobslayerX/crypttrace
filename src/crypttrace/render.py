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
