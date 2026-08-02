"""One-command investigation for people who aren't investigators.

`crypttrace investigate <address>` runs the whole analysis — profile, trace,
first-funder, off-ramp — then answers the question a victim actually has:
*what do I do now?*

The guidance is deliberately conservative. Recovering stolen crypto is rare and
depends on exchanges and law enforcement, not on this tool. Overpromising to
someone who just lost money would be its own kind of harm, so the wording says
what is realistically possible and what isn't.
"""
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from crypttrace import chains, prices, report as report_mod, trace as trace_mod
from crypttrace import funder as funder_mod, offramp as offramp_mod
from crypttrace.labels import labels


def _dedupe(findings: List[dict]) -> List[dict]:
    best: Dict[str, dict] = {}
    for f in findings:
        cur = best.get(f["address"])
        if cur is None or f["value_reached"] > cur["value_reached"]:
            best[f["address"]] = f
    return sorted(best.values(), key=lambda f: f["risk"], reverse=True)


def analyse(address: str, chain: str = "eth", asset: Optional[dict] = None,
            depth: int = 3, branching: int = 3) -> dict:
    """Run every check and return a structured result (no printing)."""
    result = {
        "address": address, "chain": chain,
        "asset": asset["symbol"] if asset else chains.symbol(chain),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "errors": [],
    }

    hit = labels.lookup(address)
    result["label"] = hit["name"] if hit else None
    result["type"] = labels.type_of(address)
    result["risk"] = labels.risk_score(address)

    try:
        result["balance"] = chains.balance(address, chain)
        rows = chains.transfers(address, chain, limit=1000, asset=asset)
        result["transfers"] = len(rows)
        result["first_seen"] = rows[-1]["timestamp"] if rows else None
        result["last_seen"] = rows[0]["timestamp"] if rows else None
    except chains.ChainError as e:
        result["errors"].append(str(e))
        result["balance"], result["transfers"] = 0.0, 0

    try:
        tree, findings = trace_mod.build(address, chain, depth, branching, asset)
        result["tree"] = tree
        result["findings"] = _dedupe(findings)
    except chains.ChainError as e:
        result["errors"].append(str(e))
        result["tree"], result["findings"] = None, []

    # where did the money end up?
    types = {f["type"] for f in result["findings"]}
    result["exchanges"] = [f for f in result["findings"] if f["type"] in ("exchange", "offramp")]
    result["mixers"] = [f for f in result["findings"] if f["type"] == "mixer"]
    result["sanctioned"] = [f for f in result["findings"] if f["type"] == "sanctioned"]
    result["bridges"] = [f for f in result["findings"] if f["type"] == "bridge"]

    try:
        result["funding"] = funder_mod.funding_chain(address, chain, 6)
    except chains.ChainError as e:
        result["errors"].append(str(e))
        result["funding"] = []

    try:
        result["offramp"] = offramp_mod.detect(address, chain) if chains.is_evm(chain) else None
    except Exception:
        result["offramp"] = None

    result["guidance"] = build_guidance(result)
    return result


def _service_name(label: str) -> str:
    """'Binance 14 (hot wallet)' -> 'Binance' — victims need the company, not our label."""
    import re
    name = re.sub(r"\(.*?\)", "", label)          # drop parentheticals
    name = name.split(" deposit")[0].split(":")[0]
    name = re.sub(r"\s+\d+\s*$", "", name.strip())  # drop trailing wallet numbers
    return name.strip() or label


def build_guidance(r: dict) -> dict:
    """Turn findings into plain-language next steps."""
    steps: List[dict] = []
    exchanges = r["exchanges"]
    ex_names = sorted({_service_name(f["label"]) for f in exchanges}) if exchanges else []

    if exchanges:
        headline = ("Good news, relatively speaking: the trail reaches a "
                    "cryptocurrency exchange. That is the single best outcome for a "
                    "victim, because exchanges verify their customers' identity.")
        steps.append({
            "title": f"Contact {', '.join(ex_names)} immediately",
            "body": ("Exchanges can freeze funds and know who owns the receiving account, "
                     "but only they can act on it — and only quickly. Find their support "
                     "page and ask to be put through to the compliance / law-enforcement "
                     "team; say the words \"stolen funds\" and \"deposit address\". "
                     "Attach the report this tool just saved."),
            "urgent": True,
        })
    elif r["mixers"]:
        headline = ("The funds were sent into a mixer (a privacy service). On-chain the "
                    "trail effectively ends there — this is the hardest outcome, and "
                    "tracing further is not reliably possible with public data.")
    elif r["sanctioned"]:
        headline = ("The funds moved to wallets on international sanctions lists, which "
                    "usually means an organised group. Law enforcement is the only "
                    "realistic route here — but such cases are actively investigated.")
    elif r["bridges"]:
        headline = ("The funds were moved to another blockchain through a bridge. The "
                    "trail continues on the destination chain rather than ending.")
        steps.append({
            "title": "Continue the trace on the other chain",
            "body": "Run: crypttrace crosschain <address> --window 48",
            "urgent": False,
        })
    else:
        headline = ("The funds have not yet reached an exchange or mixer within the "
                    "traced depth — they are sitting in wallets, or moved further than "
                    "this trace looked.")
        steps.append({
            "title": "Look deeper",
            "body": "Run the trace again with a larger --depth (4 or 5).",
            "urgent": False,
        })

    # always-applicable steps
    steps.append({
        "title": "Report it to the police",
        "body": ("File a report even if it feels pointless — exchanges usually need a "
                 "police reference number before they can release account details, so "
                 "this is often what unlocks everything else. In the US file at "
                 "ic3.gov; in the UK at Action Fraud; elsewhere, your national police "
                 "cybercrime unit."),
        "urgent": True,
    })
    steps.append({
        "title": "Report the addresses publicly",
        "body": ("Submit the thief's addresses to chainabuse.com. It is free, and it "
                 "warns others plus feeds the databases exchanges consult."),
        "urgent": False,
    })
    steps.append({
        "title": "Keep watching the money",
        "body": (f"Run: crypttrace watch add {r['address']} --chain {r['chain']}\n"
                 "then: crypttrace watch run\n"
                 "If the funds later move to an exchange, that is your moment to act — "
                 "the tool will alert you loudly."),
        "urgent": False,
    })
    steps.append({
        "title": "Preserve your evidence",
        "body": ("Keep the saved report, plus screenshots of the original transaction, "
                 "any messages from the scammer, and the wallet you used. Do not delete "
                 "the wallet."),
        "urgent": False,
    })

    warning = ("Nobody can 'hack back' your coins. Anyone who contacts you offering to "
               "recover your funds for an upfront fee is running a second scam aimed at "
               "victims of the first — this is extremely common. Real help comes from "
               "exchanges, police and licensed lawyers, and never arrives via a DM.")

    expectation = ("Being honest: most stolen crypto is not recovered. What decides it is "
                   "speed and whether the money touches a regulated exchange. This tool "
                   "gives you the evidence and the timing — it cannot move funds or "
                   "identify a person by itself.")

    return {"headline": headline, "steps": steps,
            "warning": warning, "expectation": expectation}


def guidance_markdown(r: dict) -> str:
    g = r["guidance"]
    L = ["\n## What to do next\n\n", g["headline"] + "\n\n"]
    for i, s in enumerate(g["steps"], 1):
        mark = " **(urgent)**" if s.get("urgent") else ""
        L.append(f"{i}. **{s['title']}**{mark}  \n   {s['body']}\n\n")
    L.append(f"\n> **Warning about 'recovery services'.** {g['warning']}\n")
    L.append(f"\n> **Realistic expectations.** {g['expectation']}\n")
    return "".join(L)


def save_case(r: dict, out_dir: Path, asset: Optional[dict] = None) -> Path:
    """Write the full report plus the guidance the victim can act on."""
    md_path = report_mod.generate(r["address"], r["chain"], 3, 3, out_dir, asset)
    try:
        with open(md_path, "a", encoding="utf-8") as fh:
            fh.write(guidance_markdown(r))
    except OSError:
        pass
    return md_path
