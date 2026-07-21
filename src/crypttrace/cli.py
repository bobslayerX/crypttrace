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
from crypttrace import render, trace as trace_mod, report as report_mod, assets, prices, funder as funder_mod

ASSET_OPT = typer.Option(
    "eth", "--asset", "-a",
    help="Asset to trace: eth (default), a token symbol (usdt, usdc, dai, weth…), or a 0x contract",
)

app = typer.Typer(add_completion=False, help=__doc__)
console = Console()

CHAIN_OPT = typer.Option("eth", "--chain", "-c", help=f"One of: {list(config.CHAINS)}")


@app.command()
def profile(
    address: str = typer.Argument(..., help="Address to investigate (0x…)"),
    chain: str = CHAIN_OPT,
):
    """Summary of an address: balance, activity window, label, top counterparties."""
    try:
        bal = etherscan.get_balance(address, chain)
        txs = etherscan.get_txs(address, chain, limit=1000)
    except etherscan.EtherscanError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    console.print(render.profile_table(address, chain, bal, txs, prices.native_price(chain)))
    if txs:
        console.print(render.counterparties_table(address, txs))
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
):
    """Trace where funds moved, hop by hop, as a coloured tree (ETH or a token)."""
    try:
        asset_desc = assets.resolve_asset(asset)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)
    try:
        tree = trace_mod.build_tree(address, chain, depth, branching, asset_desc)
    except etherscan.EtherscanError as e:
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
def chains():
    """List supported chains."""
    for name, cid in config.CHAINS.items():
        console.print(f"  {name}  (chainid {cid})")


if __name__ == "__main__":
    app()
