"""crypttrace CLI — OSINT crypto investigation from your terminal.

Give it a suspicious address; it pulls the public on-chain history, labels
known entities (exchanges, mixers, sanctioned wallets), and traces where the
funds went.
"""
from datetime import datetime
from pathlib import Path
from typing import Optional

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
console = Console()

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
def offramp(
    address: str = typer.Argument(..., help="Address to check (0x…)"),
    chain: str = CHAIN_OPT,
):
    """Check whether an address is an exchange deposit address (cash-out / off-ramp)."""
    try:
        hit = offramp_mod.detect(address, chain)
    except etherscan.EtherscanError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    if hit:
        pct = int(hit["fraction"] * 100)
        console.print(
            f"[green]➜ Likely off-ramp:[/green] this address forwarded ~{pct}% of outgoing "
            f"funds ({hit['forwarded']:.4f}) to [bold]{hit['exchange']}[/bold].\n"
            f"  It is probably a {hit['exchange']} deposit address — a KYC identification point."
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


@app.command(name="update-labels")
def update_labels():
    """Download the latest label lists (OFAC sanctions, etc.) into the local DB."""
    console.print("Updating label database…")
    for name, cnt, err in labels.update():
        if err:
            console.print(f"  [red]✗[/red] {name}: {err}")
        else:
            console.print(f"  [green]✓[/green] {name}: [bold]{cnt}[/bold] addresses")
    console.print(f"[green]Done.[/green] {labels.count()} labelled addresses now loaded.")
    console.print(f"[dim]Cache: {config.DATA_DIR / 'imported_labels.json'}[/dim]")


@app.command()
def victims(
    address: str = typer.Argument(..., help="The address funds were consolidated into"),
    chain: str = CHAIN_OPT,
    asset: str = ASSET_OPT,
    depth: int = typer.Option(1, "--depth", "-d", help="How many hops back to collect sources"),
    out: Optional[Path] = typer.Option(None, "--out", "-o", help="CSV file to write"),
    top: int = typer.Option(25, "--top", help="How many rows to print"),
):
    """List every address that fed this wallet — in a mass theft, the victim list."""
    from crypttrace import analysis
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    try:
        with console.status("Walking the money backwards…"):
            rows = analysis.collect_sources(address, chain, depth, asset_desc)
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
):
    """When did the money move? Reveals automated sweeps vs ordinary use."""
    from crypttrace import analysis
    try:
        asset_desc = assets.resolve_asset(asset, chain)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    try:
        with console.status("Reading transfer history…"):
            tl = analysis.timeline(address, chain, asset_desc, buckets=buckets)
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

    note = analysis.describe_burst(tl["burst"], tl["events"])
    if note:
        style = "bold yellow" if "automated" in note else "dim"
        console.print(f"\n[{style}]{note}[/{style}]")


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
    console.print(f"[green]crypttrace web UI[/green] → http://{host}:{port}  (Ctrl-C to stop)")
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
