"""Generate a full investigation report (Markdown + JSON) for an address.

Runs the same analysis as `profile` + `trace`, then writes a self-contained
report to a folder the user can easily find (default: ~/crypttrace-reports).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from crypttrace import __version__, config
from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
from crypttrace import trace as trace_mod


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _ts(unix: str) -> str:
    try:
        return datetime.fromtimestamp(int(unix), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (ValueError, TypeError):
        return "?"


def _counterparties(address: str, txs: list, top: int = 15):
    me = address.lower()
    agg = {}
    for tx in txs:
        frm, to = tx.get("from", "").lower(), tx.get("to", "").lower()
        val = int(tx.get("value", 0)) / config.WEI
        other = to if frm == me else frm
        if not other:
            continue
        rec = agg.setdefault(other, [0.0, 0.0, 0])
        if frm == me:
            rec[1] += val
        else:
            rec[0] += val
        rec[2] += 1
    rows = sorted(agg.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:top]
    return [
        {"address": a, "in": round(vin, 6), "out": round(vout, 6), "txs": cnt,
         "label": labels.label_of(a), "type": labels.type_of(a)}
        for a, (vin, vout, cnt) in rows
    ]


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
    if "exchange" in types:
        return ("Funds from this address reach a **centralised exchange** — a KYC handoff point. "
                "Identifying the owner requires a legal request to that exchange.")
    return ("No labelled entities were reached within the traced depth. Increase --depth or "
            "extend the label database, then re-run.")


def generate(address: str, chain: str, depth: int, branching: int,
             out_dir: Path) -> Path:
    balance = etherscan.get_balance(address, chain)
    txs = etherscan.get_txs(address, chain, limit=1000)
    tree, findings = trace_mod.build(address, chain, depth, branching)

    # de-duplicate findings by address, keep highest value_reached
    uniq = {}
    for f in findings:
        cur = uniq.get(f["address"])
        if cur is None or f["value_reached"] > cur["value_reached"]:
            uniq[f["address"]] = f
    findings = sorted(uniq.values(), key=lambda f: f["risk"], reverse=True)

    counterparties = _counterparties(address, txs)
    hit = labels.lookup(address)

    data = {
        "tool": f"crypttrace v{__version__}",
        "generated": _now(),
        "subject": address,
        "chain": chain,
        "trace_depth": depth,
        "trace_branching": branching,
        "summary": {
            "balance_native": round(balance, 6),
            "txs_analysed": len(txs),
            "first_seen": _ts(txs[-1]["timeStamp"]) if txs else None,
            "last_seen": _ts(txs[0]["timeStamp"]) if txs else None,
            "label": hit["name"] if hit else None,
            "type": labels.type_of(address),
            "risk_score": labels.risk_score(address),
        },
        "key_findings": findings,
        "top_counterparties": counterparties,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{chain}_{address[:10]}_{stamp}"
    json_path = out_dir / f"{base}.json"
    md_path = out_dir / f"{base}.md"

    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    md_path.write_text(_render_md(data, _tree_text(tree), json_path.name), encoding="utf-8")
    return md_path


def _render_md(d: dict, tree_text: str, json_name: str) -> str:
    s = d["summary"]
    L = []
    L.append(f"# crypttrace investigation report\n")
    L.append(f"**Generated:** {d['generated']}  •  **Tool:** {d['tool']}  \n")
    L.append(f"**Subject:** `{d['subject']}`  •  **Chain:** {d['chain']}\n")

    L.append(f"\n## Assessment\n")
    L.append(_headline(d["key_findings"]) + "\n")

    L.append(f"\n## Summary\n")
    L.append(f"| Field | Value |\n|---|---|\n")
    L.append(f"| Balance | {s['balance_native']} (native) |\n")
    L.append(f"| Transactions analysed | {s['txs_analysed']} |\n")
    L.append(f"| First seen | {s['first_seen']} |\n")
    L.append(f"| Last seen | {s['last_seen']} |\n")
    L.append(f"| Label | {s['label'] or '—'} |\n")
    L.append(f"| Risk score | {s['risk_score']}/100 |\n")

    L.append(f"\n## Key findings\n")
    if d["key_findings"]:
        L.append("Labelled entities reached while tracing funds outward from the subject:\n\n")
        L.append("| Entity | Type | Risk | Value reached |\n|---|---|---|---|\n")
        for f in d["key_findings"]:
            L.append(f"| {f['label']} | {f['type']} | {f['risk']}/100 | {f['value_reached']} |\n")
    else:
        L.append("_None within the traced depth._\n")

    L.append(f"\n## Top counterparties\n")
    L.append("| Address | Label | In | Out | Txs |\n|---|---|---|---|---|\n")
    for c in d["top_counterparties"]:
        L.append(f"| `{c['address']}` | {c['label'] or '—'} | {c['in']} | {c['out']} | {c['txs']} |\n")

    L.append(f"\n## Fund-flow trace (depth {d['trace_depth']})\n")
    L.append("```\n" + tree_text.rstrip() + "\n```\n")

    L.append(f"\n## Methodology & limitations\n")
    L.append(
        "Data is sourced from the public blockchain via Etherscan. Tracing follows the largest "
        "outgoing transfers from each address and stops at identifiable entities (exchanges, "
        "mixers, sanctioned wallets). Note: the blockchain is pseudonymous — reaching an address "
        "does not identify its owner. Mixers sever the on-chain trail; exchanges require a legal "
        "request to attribute ownership. This report is an investigative aid, not proof of "
        "wrongdoing.\n")

    L.append(f"\n---\n_Raw structured data: `{json_name}` (same folder)._\n")
    return "".join(L)
