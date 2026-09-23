"""crypttrace CLI — OSINT crypto investigation from your terminal.

Give it a suspicious address; it pulls the public on-chain history, labels
known entities (exchanges, mixers, sanctioned wallets), and traces where the
funds went.
"""
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import typer
from rich.console import Console

from crypttrace import __version__, config
from crypttrace.fetchers import etherscan
from crypttrace.labels import labels
import time

from crypttrace import render, trace as trace_mod, report as report_mod, assets, prices, funder as funder_mod, offramp as offramp_mod, bridges as bridges_mod, watch as watch_mod

ASSET_OPT = typer.Option(
    "eth", "--asset", "-a",
    help="Asset to trace: eth (default), a token symbol (usdt, usdc, dai, weth…), or a 0x contract",
)

app = typer.Typer(add_completion=False, help=__doc__)

# Output redirected to a file or run from Task Scheduler on Windows gets the ANSI
# code page (e.g. cp1251), and the first arrow or emoji would crash the command.
for _stream in (sys.stdout, sys.stderr):
    if _stream and (getattr(_stream, "encoding", "") or "").lower().replace("-", "") != "utf8":
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

console = Console()


@app.callback()
def _main(
    fresh: bool = typer.Option(False, "--fresh",
                               help="Ignore stored data and re-fetch from the network"),
    offline: bool = typer.Option(False, "--offline",
                                 help="Work only from locally stored data, no network"),
):
    """Options that apply to every command."""
    # --fresh re-fetches but still stores the result; it doesn't disable the store
    chains_mod.FORCE_FRESH = fresh
    chains_mod.OFFLINE = offline

from crypttrace import chains as chains_mod

CHAIN_OPT = typer.Option("eth", "--chain", "-c",
                         help=f"One of: {chains_mod.ALL_CHAINS}")


@app.command()
def investigate(
    address: str = typer.Argument(..., help="The address your funds were sent to"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(3, "--depth", "-d", help="How many hops to follow"),
    out: Path = typer.Option(Path.home() / "crypttrace-reports", "--out", "-o",
                             help="Where to save the case file"),
):
    """Start here. Runs the whole investigation and tells you what to do next."""
    from crypttrace import investigate as inv
    from rich.panel import Panel

    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    console.print(Panel.fit(
        f"[bold]Investigating[/bold] {address}\n[dim]chain: {chain}[/dim]",
        border_style="cyan"))

    with console.status("Reading the blockchain and following the money…"):
        r = inv.analyse(address, chain, asset_desc, depth, 3)

    if r["errors"]:
        for e in r["errors"]:
            console.print(f"[yellow]![/yellow] {e}")

    # --- what we found ---
    console.print("\n[bold]What we found[/bold]")
    bal = f"{r['balance']:.6f} {chains_mod.symbol(chain)}"
    usd = prices.usd(r["balance"], prices.native_price(chain))
    if usd is not None:
        bal += f"  ≈ {prices.fmt_usd(usd)}"
    console.print(f"  Balance still on this address: {bal}")
    console.print(f"  Transfers analysed: {r['transfers']}")
    if r["label"]:
        console.print(f"  This address is known: [bold red]{r['label']}[/bold red]")

    if r["tree"] is not None and r["findings"]:
        console.print("\n[bold]Where the money went[/bold]")
        console.print(r["tree"])
    elif r["tree"] is not None:
        console.print("\n[dim]No onward movement to known services found at this depth.[/dim]")

    if r["findings"]:
        console.print("\n[bold]Key destinations[/bold]")
        for f in r["findings"]:
            colour = {"exchange": "green", "offramp": "green", "mixer": "magenta",
                      "sanctioned": "red", "bridge": "cyan"}.get(f["type"], "white")
            amount = f"{f['value_reached']} {f.get('symbol','')}"
            if f.get("usd_reached") is not None:
                amount += f" ≈ {prices.fmt_usd(f['usd_reached'])}"
            console.print(f"  [{colour}]{f['label']}[/{colour}] — {amount}")

    # --- guidance ---
    g = r["guidance"]
    console.print(Panel(g["headline"], title="[bold]In plain terms[/bold]",
                        border_style="cyan", padding=(1, 2)))

    console.print("\n[bold]What to do next[/bold]\n")
    for i, s in enumerate(g["steps"], 1):
        tag = " [bold red](do this first)[/bold red]" if s.get("urgent") else ""
        console.print(f"[bold]{i}. {s['title']}[/bold]{tag}")
        for line in s["body"].split("\n"):
            console.print(f"   {line}")
        console.print()

    console.print(Panel(g["warning"], title="[bold red]Beware of recovery scams[/bold red]",
                        border_style="red", padding=(1, 2)))
    console.print(Panel(g["expectation"], title="[bold]Realistic expectations[/bold]",
                        border_style="yellow", padding=(1, 2)))

    try:
        path = inv.save_case(r, out, asset_desc)
        console.print(f"\n[green]✓ Case file saved:[/green] {path}")
        console.print("[dim]  Send this file to the exchange and attach it to your police report.[/dim]")
    except Exception as e:
        console.print(f"[yellow]Could not save the case file:[/yellow] {e}")


@app.command()
def profile(
    address: str = typer.Argument(..., help="Address to investigate (0x…)"),
    chain: str = CHAIN_OPT,
):
    """Summary of an address: balance, activity window, label, top counterparties."""
    try:
        bal = chains_mod.balance(address, chain)
        rows = chains_mod.transfers(address, chain, limit=1000)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    console.print(render.profile_rows_table(address, chain, bal, rows,
                                            prices.native_price(chain),
                                            chains_mod.symbol(chain)))
    if rows:
        console.print(render.counterparties_rows_table(address, chain, rows))
    else:
        console.print("[dim]No transactions found for this address on this chain.[/dim]")


@app.command()
def trace(
    address: str = typer.Argument(..., help="Starting address (0x…)"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(3, "--depth", "-d", help="How many hops to follow"),
    branching: int = typer.Option(3, "--branching", "-b",
                                  help="Top-N outflows to follow per address"),
    direction: str = typer.Option("out", "--direction", "-D",
                                  help="'out' = where funds went, 'in' = where they came from"),
):
    """Trace where funds moved, hop by hop, as a coloured tree (ETH or a token)."""
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if direction not in ("out", "in"):
        console.print("[red]Error:[/red] --direction must be 'out' or 'in'")
        raise typer.Exit(1)
    try:
        tree = trace_mod.build_tree(address, chain, depth, branching, asset_desc, direction)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    console.print(tree)
    console.print(
        "\n[dim]Legend: \U0001F7E2 exchange  \U0001F7E3 mixer  \U0001F534 sanctioned/scam"
        "  \U0001F309 bridge  ⚪ unknown[/dim]"
    )


@app.command()
def tokens(
    address: str = typer.Argument(..., help="Address to inspect (0x…)"),
    chain: str = CHAIN_OPT,
):
    """Show an address's token holdings (approx from transfer history) with USD."""
    try:
        holdings = chains_mod.token_holdings(address, chain)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if not holdings:
        console.print("[dim]No token transfers found for this address on this chain.[/dim]")
        return
    console.print(render.holdings_table(address, chain, holdings))


@app.command()
def report(
    address: str = typer.Argument(..., help="Address to investigate (0x…)"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(3, "--depth", "-d", help="How many hops to trace"),
    branching: int = typer.Option(3, "--branching", "-b", help="Top-N outflows per address"),
    out: Path = typer.Option(
        Path.home() / "crypttrace-reports", "--out", "-o",
        help="Folder to save the report in",
    ),
):
    """Run a full investigation and save a Markdown + JSON report to disk."""
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    try:
        with console.status("Gathering on-chain data and tracing funds…"):
            md_path = report_mod.generate(address, chain, depth, branching, out, asset_desc)
    except etherscan.EtherscanError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    console.print(f"[green]✓ Report saved:[/green] {md_path}")
    console.print(f"[dim]  Raw data (JSON) saved alongside it in the same folder.[/dim]")


@app.command()
def crosschain(
    address: str = typer.Argument(..., help="Address that may have bridged funds (0x…)"),
    chain: str = CHAIN_OPT,
    window: int = typer.Option(48, "--window", "-w", help="Hours after a bridge-out to search"),
    tol: float = typer.Option(0.05, "--tol", help="Amount tolerance (0.05 = 5%, for bridge fees)"),
):
    """Follow funds across bridges: find likely arrivals of the same address on other chains."""
    try:
        results = bridges_mod.trace_cross(address, chain, tol=tol, window_h=window)
    except etherscan.EtherscanError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if not results:
        console.print("[dim]No transfers into known bridge contracts found for this "
                      "address on this chain.[/dim]")
        return
    console.print(render.crosschain_tree(address, chain, results))
    console.print("\n[dim]Cross-chain links are heuristic (same-address arrival by amount+time), "
                  "not proof. Verify each candidate before relying on it.[/dim]")


@app.command()
def poisoning(
    address: str = typer.Argument(..., help="Your wallet, or the address the money went to"),
    chain: str = CHAIN_OPT,
    limit: int = typer.Option(1000, "--limit", help="How much history to read"),
):
    """Address poisoning: look-alike addresses planted in a wallet's history."""
    from crypttrace import poisoning as poison_mod
    from datetime import timezone
    when = lambda ts: datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") \
        if ts else "?"
    try:
        pairs = poison_mod.lookalikes(address, chain, limit)
        lured = poison_mod.baited_payments(address, chain, limit)
        spam = poison_mod.campaign(address, chain, limit)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    paid = [p for p in pairs if p["sent_to_lookalike"] > 0]
    for p in paid:
        console.print(f"[bold red]✗ Money went to a look-alike:[/bold red] "
                      f"{p['sent_to_lookalike']:.4f} {'/'.join(p['symbols'])} sent to it")
        console.print(f"    real address   {p['genuine']}")
        console.print(f"    look-alike     {p['lookalike']}")
        console.print(f"    same first {p['matching']['prefix']} and last "
                      f"{p['matching']['suffix']} characters; first seen {when(p['lookalike_first_seen'])}")
    if paid:
        console.print("  This is address poisoning. Run [bold]crypttrace investigate "
                      f"{paid[0]['lookalike']} --chain {chain}[/bold] to follow the money.\n")

    planted = [p for p in pairs if p["sent_to_lookalike"] <= 0]
    if planted:
        console.print(f"[yellow]![/yellow] {len(planted)} look-alike address(es) planted in this "
                      "history — never copy an address from here:")
        for p in planted[:10]:
            console.print(f"    {poison_mod.short(p['lookalike'], chain)} imitates "
                          f"{poison_mod.short(p['genuine'], chain)}  [dim]({p['resemblance']} "
                          f"match, {p['bait_transfers']} bait transfer(s), "
                          f"{when(p['lookalike_first_seen'])})[/dim]")
        console.print()

    for x in lured:
        tag = f"imitating [bold]{x['imitates']}[/bold]" if x["imitates"] \
            else "[dim](the imitated address was not found in the payer's recent history)[/dim]"
        console.print(f"[bold red]✗ Lured payment:[/bold red] {x['payer']} paid "
                      f"{x['paid']:.2f} {x['symbol']} on {when(x['paid_ts'])}, after this "
                      f"address lured it ({x['lure']}) — {tag}")
    if spam:
        console.print(f"[bold red]✗ Poisoning campaign:[/bold red] this address sent "
                      f"{spam['bait_transfers']} zero/dust/counterfeit transfers to "
                      f"{spam['targets']} different wallets.")

    if not (pairs or lured or spam):
        console.print("[green]No look-alike addresses or poisoning pattern found[/green] "
                      f"[dim]in the last {limit} transfers.[/dim]")


@app.command()
def offramp(
    address: str = typer.Argument(..., help="Address to check"),
    chain: str = CHAIN_OPT,
):
    """Check whether an address is an exchange deposit address (cash-out / off-ramp)."""
    try:
        hit = offramp_mod.detect(address, chain)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if hit:
        pct = int(hit["fraction"] * 100)
        console.print(
            f"[green]➜ Likely off-ramp:[/green] this address forwarded ~{pct}% of outgoing "
            f"funds ({hit['forwarded']:.4f} {hit['symbol']}) to [bold]{hit['exchange']}[/bold].\n"
            f"  It is probably a deposit address at {hit['company']} — a KYC identification point."
        )
    else:
        console.print("[dim]No exchange-forwarding pattern detected. "
                      "Not an obvious off-ramp (or funds moved as tokens).[/dim]")


@app.command()
def funder(
    address: str = typer.Argument(..., help="Address to trace funding for (0x…)"),
    chain: str = CHAIN_OPT,
    hops: int = typer.Option(6, "--hops", "-H", help="How far back to follow the funding chain"),
):
    """Follow who funded a wallet's first gas, backward, toward a KYC/exchange point."""
    try:
        chain_hops = funder_mod.funding_chain(address, chain, hops)
    except etherscan.EtherscanError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    console.print(render.funding_tree(address, chain_hops))
    if chain_hops and chain_hops[-1]["terminal"] and chain_hops[-1]["funder_type"] == "exchange":
        console.print("\n[green]➜ Funding chain reaches an exchange — a KYC identification "
                      "point. A legal request to that exchange can reveal the owner.[/green]")


@app.command()
def label(
    address: str = typer.Argument(..., help="Address to look up"),
):
    """Look up what an address is (from the local label DB) and its risk score."""
    hit = labels.lookup(address)
    if hit:
        console.print(f"{labels.icon(address)} [bold]{hit['name']}[/bold] "
                      f"— type: {hit['type']}, risk: {labels.risk_score(address)}/100")
    else:
        console.print(f"⚪ [dim]Unknown address[/dim] — no label, risk 0/100")


labels_app = typer.Typer(help="Inspect the label database and the evidence behind it.")
app.add_typer(labels_app, name="labels")


@labels_app.command("audit")
def labels_audit():
    """Check every label: address validity, checksum, and whether a source is recorded."""
    from crypttrace.labels import audit as audit_mod
    a = audit_mod.audit()

    console.print(f"  entries          : [bold]{a['total']}[/bold]")
    console.print(f"  well-formed      : {a['valid']}")
    console.print(f"  with a source    : {a['total']-len(a['unsourced'])} "
                  f"({a['sourced_share']*100:.0f}%)")

    if a["by_source"]:
        console.print("\n  [bold]evidence behind the claims[/bold]")
        titles = {"self-published": "published by the service itself",
                  "official-list": "official/regulator list",
                  "explorer-tag": "block-explorer tag",
                  "research": "named research or own tracing",
                  "community": "crowd-sourced", "none": "no source recorded"}
        for kind, n in sorted(a["by_source"].items(), key=lambda kv: -kv[1]):
            console.print(f"     {titles.get(kind, kind):<34} {n}")

    if a["problems"]:
        console.print(f"\n  [bold red]invalid addresses: {len(a['problems'])}[/bold red]")
        for p in a["problems"][:10]:
            console.print(f"     {p['address'][:24]}… — {p['issue']}")
    else:
        console.print("\n  [green]every address passes its checksum[/green]")

    if a["unsourced"]:
        console.print(f"\n  [yellow]{len(a['unsourced'])} labels carry no source[/yellow] "
                      "— they are inherited, not evidenced. Treat them as weaker.")
        for u in a["unsourced"][:8]:
            console.print(f"     [dim]{u['name']} ({u['type']})[/dim]")

    from crypttrace.labels import bulk
    downloaded = bulk.sets()
    if downloaded:
        console.print("\n  [bold]downloaded exchange address sets[/bold] (self-published, "
                      "checked on import)")
        for s in downloaded.values():
            console.print(f"     {s['name']:<34} {s['count']:>8}   snapshot {s['snapshot']}")
    else:
        console.print("\n  [dim]No exchange address sets downloaded. "
                      "`crypttrace update-labels --okx` adds OKX's ~300k deposit addresses.[/dim]")


@labels_app.command("why")
def labels_why(
    address: str = typer.Argument(..., help="Address to explain"),
):
    """Why does the tool claim this address is what it says? Shows the evidence."""
    from crypttrace.labels import audit as audit_mod
    e = audit_mod.evidence(address)
    if not e["known"]:
        console.print("[dim]No label for this address — the tool makes no claim about it.[/dim]")
        console.print("[dim]Unlabelled does not mean innocent; it means unknown.[/dim]")
        raise typer.Exit()
    console.print(f"  claim   : [bold]{e['name']}[/bold] ({e['type']})")
    console.print(f"  source  : {e['source'] or '[yellow]none recorded[/yellow]'}")
    console.print(f"  kind    : {e['source_kind'] or '—'}  (strength {e['strength']}/3)")
    if e.get("added"):
        console.print(f"  added   : {e['added']}")
    if not e["source"]:
        console.print("\n  [yellow]This claim is not evidenced in the database.[/yellow] "
                      "Verify it independently before acting on it.")


@labels_app.command("check")
def labels_check(
    address: str = typer.Argument(..., help="Address to validate"),
    chain: str = CHAIN_OPT,
):
    """Validate an address and its checksum, without touching the network."""
    from crypttrace import addresses as addr_mod
    if addr_mod.looks_like_txid(address):
        console.print("[yellow]That is a 64-character hex string — a transaction id, "
                      "not an address.[/yellow]")
        raise typer.Exit(1)
    ok, why = addr_mod.validate(address, chain)
    style = "green" if ok else "red"
    console.print(f"[{style}]{'valid' if ok else 'invalid'}[/{style}] — {why}")
    if not ok:
        raise typer.Exit(1)


@app.command(name="update-labels")
def update_labels(
    okx: bool = typer.Option(False, "--okx",
                             help="Also download OKX's signed address list (~80 MB): "
                                  "labels its ~300k deposit addresses directly"),
    okx_file: Optional[Path] = typer.Option(None, "--okx-file",
                                            help="Import an OKX proof-of-reserves zip you "
                                                 "already downloaded, instead of fetching it"),
):
    """Download the latest label lists (OFAC sanctions, etc.) into the local DB."""
    from crypttrace.labels import bulk
    console.print("Updating label database…")
    for name, cnt, err in labels.update():
        if err:
            console.print(f"  [red]✗[/red] {name}: {err}")
        else:
            console.print(f"  [green]✓[/green] {name}: [bold]{cnt}[/bold] addresses")
    if okx or okx_file:
        try:
            n, snap = bulk.import_okx(str(okx_file) if okx_file else None,
                                      progress=lambda m: console.print(f"  [dim]OKX: {m}[/dim]"))
            console.print(f"  [green]✓[/green] OKX signed addresses (snapshot {snap}): "
                          f"[bold]{n}[/bold] addresses")
        except (requests.RequestException, ValueError, OSError, zipfile.BadZipFile) as e:
            console.print(f"  [red]✗[/red] OKX signed addresses: {e}")
    console.print(f"[green]Done.[/green] {labels.count()} curated and imported labels loaded"
                  + (f", plus {sum(s['count'] for s in bulk.sets().values())} exchange addresses"
                     if bulk.sets() else "") + ".")
    console.print(f"[dim]Cache: {config.DATA_DIR / 'imported_labels.json'}[/dim]")


@app.command()
def victims(
    address: str = typer.Argument(..., help="The address funds were consolidated into"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(1, "--depth", "-d", help="How many hops back to collect sources"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="CSV file to write"),
    top: int = typer.Option(25, "--top", help="How many rows to print"),
    min_value: Optional[float] = typer.Option(
        None, "--min-value", help="Ignore transfers below this amount (default: per-chain dust level)"),
    include_dust: bool = typer.Option(False, "--include-dust", help="Keep dust-sized transfers"),
):
    """List every address that fed this wallet — in a mass theft, the victim list."""
    from crypttrace import analysis
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    floor = 0.0 if include_dust else min_value
    try:
        with console.status("Walking the money backwards…"):
            rows = analysis.collect_sources(address, chain, depth, asset_desc,
                                            min_value=floor)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    if not rows:
        console.print("[dim]No incoming transfers found — nothing fed this address.[/dim]")
        return

    sym = asset_desc["symbol"] if asset_desc else chains_mod.symbol(chain)
    console.print(render.sources_table(rows, sym, top))
    total = sum(r["value"] for r in rows)
    console.print(f"\n[bold]{len(rows)}[/bold] addresses sent a total of "
                  f"[bold]{total:.8f} {sym}[/bold] into this wallet.")

    # This list is about to become evidence — say whether it reconciles.
    from crypttrace import verify as verify_mod
    v = verify_mod.reconcile(address, chain, asset_desc)
    style = _verdict_style(v["status"])
    console.print(f"[{style}]{v['status'].upper()}[/{style}] — {verify_mod.headline(v)}")
    for n in v["notes"][:2]:
        console.print(f"  [dim]• {n}[/dim]")

    path = out or (Path.home() / "crypttrace-reports" /
                   f"sources_{chain}_{address[:12]}_{datetime.now():%Y%m%d_%H%M%S}.csv")
    try:
        analysis.export_csv(rows, path, chain, sym)
        console.print(f"[green]✓ CSV saved:[/green] {path}")
        console.print("[dim]  Attach this to an exchange request or police report.[/dim]")
    except OSError as e:
        console.print(f"[yellow]Could not write CSV:[/yellow] {e}")


@app.command()
def timeline(
    address: str = typer.Argument(..., help="Address to analyse"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    buckets: int = typer.Option(24, "--buckets", "-b", help="Number of time buckets"),
    min_value: Optional[float] = typer.Option(
        None, "--min-value", help="Ignore transfers below this amount (default: per-chain dust level)"),
    include_dust: bool = typer.Option(False, "--include-dust", help="Keep dust-sized transfers"),
):
    """When did the money move? Reveals automated sweeps vs ordinary use."""
    from crypttrace import analysis
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    floor = 0.0 if include_dust else min_value
    try:
        with console.status("Reading transfer history…"):
            tl = analysis.timeline(address, chain, asset_desc, buckets=buckets,
                                   min_value=floor)
    except (chains_mod.ChainError, etherscan.EtherscanError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    if not tl["events"]:
        console.print("[dim]No dated transfers found for this address.[/dim]")
        return

    sym = asset_desc["symbol"] if asset_desc else chains_mod.symbol(chain)
    console.print(render.timeline_chart(tl, sym))
    console.print(f"\n  first activity : {render._ts(str(tl['first_ts']))} UTC")
    console.print(f"  last activity  : {render._ts(str(tl['last_ts']))} UTC")
    console.print(f"  transfers      : {tl['events']}")
    console.print(f"  received / sent: {tl['in_total']:.6f} / {tl['out_total']:.6f} {sym}")
    if tl.get("dust_skipped"):
        console.print(f"  [dim]dust ignored   : {tl['dust_skipped']} tiny transfers "
                      f"(spam sent to well-known addresses; use --include-dust to keep)[/dim]")

    note = analysis.describe_burst(tl["burst"], tl["events"])
    if note:
        style = "bold yellow" if "automated" in note else "dim"
        console.print(f"\n[{style}]{note}[/{style}]")


@app.command()
def assess(
    address: str = typer.Argument(..., help="Address to assess"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(2, "--depth", "-d", help="How far to look at onward flows"),
):
    """What does the evidence support? A stated conclusion, with its reasoning."""
    from crypttrace import assess as assess_mod
    from rich.panel import Panel
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    with console.status("Gathering evidence…"):
        a = assess_mod.assess(address, chain, asset_desc, depth)

    if a.get("error"):
        console.print(f"[red]Error:[/red] {a['error']}")
        raise typer.Exit(1)

    colour = "red" if a["risk"] >= 60 else "yellow" if a["risk"] >= 25 else "green"
    console.print(Panel(a["assessment"], title="[bold]Assessment[/bold]",
                        border_style=colour, padding=(1, 2)))

    if a["signals"]:
        console.print("\n[bold]What this rests on[/bold]\n")
        for s in a["signals"]:
            c = {"high": "green", "medium": "yellow", "low": "dim"}[s["confidence"]]
            console.print(f"  [bold]{s['name']}[/bold]  [{c}]{s['confidence']} confidence[/{c}]")
            console.print(f"    observed : {s['observed']}")
            console.print(f"    means    : {s['implication']}")
            console.print()

    console.print(f"  risk       : [{colour}]{a['risk']}/100[/{colour}]")
    console.print(f"  confidence : {a['confidence']}")
    console.print(f"  arithmetic : {a['verification']['status']}")

    if a["caveats"]:
        console.print("\n[bold yellow]Read this before quoting the above[/bold yellow]")
        for c in a["caveats"]:
            console.print(f"  • {c}")


def _verdict_style(status: str) -> str:
    return {"verified": "green", "consistent": "cyan", "partial": "yellow",
            "mismatch": "bold red", "unchecked": "dim"}.get(status, "dim")


@app.command()
def verify(
    address: str = typer.Argument(..., help="Address to cross-check"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    limit: int = typer.Option(1000, "--limit", help="How many transfers to read"),
):
    """Check the tool's own totals against the chain. Run this before trusting a report."""
    from crypttrace import verify as verify_mod
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    with console.status("Re-deriving totals and comparing with the chain…"):
        v = verify_mod.reconcile(address, chain, asset_desc, limit)

    sym = asset_desc["symbol"] if asset_desc else chains_mod.symbol(chain)
    style = _verdict_style(v["status"])
    console.print(f"\n[{style}]{v['status'].upper()}[/{style}]  {verify_mod.headline(v)}\n")

    if v["checks"]:
        t = render.Table(title="Cross-check against the chain", header_style="bold")
        t.add_column("Figure"); t.add_column("Computed", justify="right")
        t.add_column("Chain", justify="right"); t.add_column("", justify="center")
        for c in v["checks"]:
            t.add_row(c["name"], f"{c['computed']:.8f} {sym}",
                      f"{c['chain']:.8f} {sym}", "✓" if c["ok"] else "✗")
        console.print(t)

    console.print(f"\n  transfers analysed : {v['analysed']}")
    if v.get("chain_tx_count") is not None:
        console.print(f"  transactions on chain: {v['chain_tx_count']}")
    for n in v["notes"]:
        console.print(f"  [dim]• {n}[/dim]")


@app.command()
def cluster(
    address: str = typer.Argument(..., help="Bitcoin address (bc1…/1…/3…)"),
):
    """Bitcoin only: find addresses likely owned by the same person (common-input-ownership)."""
    from crypttrace.fetchers import bitcoin
    try:
        peers = bitcoin.cluster(address)
    except bitcoin.BitcoinError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if not peers:
        console.print("[dim]No co-spending found — this address never signed inputs "
                      "alongside others (or has too little history).[/dim]")
        return
    console.print(render.cluster_table(address, peers))
    console.print("\n[dim]Heuristic: addresses that co-sign inputs of one transaction are "
                  "almost always controlled by the same party. Strong lead, not proof.[/dim]")


store_app = typer.Typer(help="Inspect and manage locally stored chain data.")
app.add_typer(store_app, name="store")


@store_app.command("info")
def store_info():
    """What is held locally — re-analysis of this data needs no network."""
    from crypttrace import store as store_mod
    s = store_mod.stats()
    console.print(f"  transfers stored : [bold]{s['transfers']}[/bold]")
    console.print(f"  addresses fetched: [bold]{s['addresses']}[/bold]")
    for ch, n in sorted(s["by_chain"].items(), key=lambda kv: -kv[1]):
        console.print(f"     {ch:<10} {n}")
    console.print(f"  file             : {s['path']}")
    console.print(f"  size             : {s['size_bytes']/1024:.0f} KB")
    if s["addresses"]:
        console.print("\n[dim]Add --offline to any command to work from this alone.[/dim]")


@store_app.command("clear")
def store_clear(
    yes: bool = typer.Option(False, "--yes", "-y", help="Don't ask for confirmation"),
):
    """Delete everything stored locally (chain data can always be re-fetched)."""
    from crypttrace import store as store_mod
    if not yes:
        s = store_mod.stats()
        confirm = typer.confirm(f"Delete {s['transfers']} stored transfers?")
        if not confirm:
            console.print("[dim]Kept.[/dim]")
            raise typer.Exit()
    store_mod.clear()
    console.print("[green]✓ Local store cleared.[/green]")


@store_app.command("link")
def store_link(
    src: str = typer.Argument(..., help="Start address"),
    dst: str = typer.Argument(..., help="Address to look for"),
    chain: str = CHAIN_OPT,
    hops: int = typer.Option(4, "--hops", "-H", help="Maximum hops to search"),
):
    """Are two addresses connected in the data already collected?"""
    from crypttrace import store as store_mod
    path = store_mod.path_exists(chain, src, dst, hops)
    if not path:
        console.print("[dim]No path found in stored data. Trace both addresses first, "
                      "or raise --hops.[/dim]")
        raise typer.Exit(1)
    console.print(f"[green]Connected in {len(path)-1} hop(s):[/green]\n")
    for i, a in enumerate(path):
        console.print(("  " * i) + ("└─▶ " if i else "") + a)


@app.command()
def chains():
    """List supported chains."""
    console.print("[bold]EVM[/bold] (Etherscan v2, needs ETHERSCAN_API_KEY):")
    for name, cid in config.CHAINS.items():
        console.print(f"  {name:<10} chainid {cid}")
    console.print("\n[bold]Non-EVM[/bold] (no API key needed):")
    console.print("  btc        Bitcoin — mempool.space (UTXO)")
    console.print("  tron       Tron — TronGrid (TRX + USDT-TRC20)")
    console.print("  sol        Solana — public JSON-RPC")


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to serve on"),
):
    """Launch the local web UI (interactive graph) in your browser."""
    try:
        from crypttrace import webapp
    except ImportError:
        console.print("[red]Flask is not installed.[/red] Run: pip install 'crypttrace[web]'  "
                      "(or pip install flask)")
        raise typer.Exit(1)
    info = webapp.where()
    console.print(f"[green]crypttrace web UI[/green] → http://{host}:{port}  (Ctrl-C to stop)")
    console.print(f"[dim]serving: {info['index_html']}[/dim]")
    console.print(f"[dim]         {info['size']} bytes, modified {info['modified']}[/dim]")
    if not info["editable"]:
        console.print("[yellow]![/yellow] Running from an installed copy, not your source tree — "
                      "edits to src/ will NOT appear.\n"
                      "  Fix with: [bold]pip uninstall -y crypttrace && pip install -e \".[web]\"[/bold]")
    webapp.serve(host=host, port=port)


# ---- watch: monitor addresses and alert on movement / cash-out ----
watch_app = typer.Typer(help="Monitor addresses and alert when funds move (esp. to an exchange).")
app.add_typer(watch_app, name="watch")


@watch_app.command("add")
def watch_add(
    address: str = typer.Argument(..., help="Address to watch (0x…)"),
    chain: str = CHAIN_OPT,
    note: str = typer.Option("", "--note", "-n", help="A label for this case, e.g. 'my stolen ETH'"),
):
    """Add an address to the watchlist (alerts only on activity from now on)."""
    watch_mod.add(address, chain, note)
    console.print(f"[green]✓ Watching[/green] {address} ({chain})"
                  + (f" — {note}" if note else ""))


@watch_app.command("list")
def watch_list():
    """Show the watchlist."""
    d = watch_mod.all_watched()
    if not d:
        console.print("[dim]Watchlist is empty. Add one with `crypttrace watch add 0x…`[/dim]")
        return
    for addr, m in d.items():
        console.print(f"  {addr}  ({m.get('chain','eth')})"
                      + (f"  — {m['note']}" if m.get("note") else ""))


@watch_app.command("remove")
def watch_remove(address: str = typer.Argument(..., help="Address to stop watching")):
    """Remove an address from the watchlist."""
    if watch_mod.remove(address):
        console.print(f"[green]✓ Removed[/green] {address}")
    else:
        console.print("[dim]Address was not on the watchlist.[/dim]")


def _render_alert(e: dict) -> None:
    icon = {"high": "🚨", "move": "🔔", "info": "•"}.get(e["sev"], "•")
    style = {"high": "bold red", "move": "yellow", "info": "dim"}.get(e["sev"], "white")
    when = render._ts(str(e["timestamp"]))
    line = (f"{icon} [{style}]{e['sev'].upper()}[/{style}]  {e['address'][:12]}…"
            + (f" ({e['note']})" if e.get("note") else "")
            + f"  {e['value']:.4f}  {e['reason']}  [dim]{when}[/dim]")
    if e["sev"] == "high":
        console.bell()  # audible bell for cash-out events
    console.print(line)


@watch_app.command("run")
def watch_run(
    interval: int = typer.Option(300, "--interval", "-i", help="Seconds between checks"),
    once: bool = typer.Option(False, "--once", help="Check a single time and exit (good for cron)"),
    telegram: bool = typer.Option(False, "--telegram", help="Also send alerts to Telegram "
                                  "(set CRYPTTRACE_TG_TOKEN and CRYPTTRACE_TG_CHAT)"),
):
    """Poll the watchlist and alert on new activity. Loud alert on likely cash-out."""
    if not watch_mod.all_watched():
        console.print("[dim]Watchlist is empty. Add one with `crypttrace watch add 0x…`[/dim]")
        raise typer.Exit(1)

    def _pass():
        alerts = watch_mod.poll_once()
        if not alerts:
            console.print(f"[dim]{render._ts(str(int(time.time())))} — no new activity[/dim]")
            return
        for e in alerts:
            _render_alert(e)
            if telegram and e["sev"] in ("high", "move"):
                msg = f"crypttrace {e['sev'].upper()}: {e['address']} {e['value']:.4f} {e['reason']}"
                watch_mod.telegram_notify(msg)

    if once:
        _pass()
        return
    console.print(f"[green]Watching {len(watch_mod.all_watched())} address(es)[/green] "
                  f"every {interval}s. Ctrl-C to stop.")
    try:
        while True:
            _pass()
            time.sleep(interval)
    except KeyboardInterrupt:
        console.print("\n[dim]Stopped.[/dim]")


if __name__ == "__main__":
    app()
