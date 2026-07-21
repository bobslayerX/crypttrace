"""Terminal rendering helpers (rich)."""
from datetime import datetime, timezone
from rich.table import Table
from rich.tree import Tree
from rich.text import Text

from crypttrace.labels import labels
from crypttrace import config


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


def profile_table(address: str, chain: str, balance: float, txs: list) -> Table:
    t = Table(title=f"Profile — {address}  ({chain})", show_header=True, header_style="bold")
    t.add_column("Field")
    t.add_column("Value")
    t.add_row("Balance", f"{balance:.6f} (native)")
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
