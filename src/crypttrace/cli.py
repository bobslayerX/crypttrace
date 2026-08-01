"""crypttrace CLI — OSINT crypto investigation from your terminal.

Give it a suspicious address; it pulls the public on-chain history, labels
known entities (exchanges, mixers, sanctioned wallets), and traces where the
funds went.
"""
from pathlib import Path

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
        asset_desc = assets.resolve_asset(asset)
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
    """Show an address's ERC-20 token holdings (approx from transfer history) with USD."""
    try:
        holdings = assets.token_holdings(address, chain)
    except etherscan.EtherscanError as e:
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
        asset_desc = assets.resolve_asset(asset)
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
