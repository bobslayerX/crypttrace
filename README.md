# crypttrace

OSINT crypto-investigation CLI. Give it a suspicious address; it pulls the
public on-chain history, labels known entities (exchanges, mixers, sanctioned
wallets), scores risk, and traces where the funds moved — all in your terminal.

Built for the common investigation flow: *someone got their crypto stolen, here's
the wallet, where did the money go?*

## Install

```bash
cd crypttrace
pip install -e .
export ETHERSCAN_API_KEY=xxxx   # free key: https://etherscan.io/myapikey
```

One Etherscan v2 key works across all supported EVM chains (eth, bsc, polygon,
arbitrum, optimism, base).

## Usage

```bash
# What is this address? (uses the local label DB, works offline)
crypttrace label 0x28c6c06298d514db089934071355e5743bf21d60

# Full profile: balance, activity window, risk, top counterparties
crypttrace profile 0xADDRESS --chain eth

# Follow the money N hops deep, rendered as a coloured tree
crypttrace trace 0xADDRESS --chain eth --depth 4 --branching 3

# Trace a token instead of native ETH (most thefts are stablecoins)
crypttrace trace 0xADDRESS --asset usdt --depth 4

# Token holdings of an address, valued in USD
crypttrace tokens 0xADDRESS

# Who funded this wallet's first gas? Follow it back toward an exchange/KYC point
crypttrace funder 0xADDRESS --hops 6

# Full investigation report saved to disk (Markdown + JSON)
crypttrace report 0xADDRESS --chain eth --asset usdt --depth 3

# Download the latest label lists (OFAC sanctions, etc.)
crypttrace update-labels

# Supported chains
crypttrace chains
```

### Labels

The tool ships a small curated seed set (major exchanges, Tornado Cash, bridges,
notable hacks). Run `crypttrace update-labels` to pull authoritative public
lists — currently the OFAC SDN sanctioned-address list — and merge them into the
local database (cached in `~/.crypttrace/`). The curated seed always wins on
conflicts, so its richer names are preserved. Add more sources in
`labels/labels.py` → `SOURCES`.

### Assets & USD values

By default the tracer follows the chain's native coin (ETH). Pass `--asset` to
follow an ERC-20 token instead — a known symbol (`usdt`, `usdc`, `dai`, `weth`,
`wbtc`) or any `0x` contract address. Since most thefts today move stablecoins,
token tracing is essential. Amounts are shown with approximate USD values
(stablecoins pinned to $1, others priced via CoinGecko; if offline, USD shows as
`—`). The `tokens` command lists an address's token holdings valued in USD.

### First-funder (deanonymization)

`crypttrace funder` follows a wallet's *funding* link backward: whoever sent it
its first gas, then whoever funded that funder, and so on. A fresh laundering
wallet has to be bootstrapped from somewhere, and the chain frequently
terminates at a centralised-exchange withdrawal — a KYC identification point
where a legal request can reveal the owner. This is a core primitive for tying
"unrelated" wallets back to one controller. (Uses external transactions;
wallets first funded by an internal contract call need internal-tx data, a
planned extension.)

### Reports

`crypttrace report` runs the full analysis and writes a self-contained report to
`~/crypttrace-reports/` (override with `--out`). Each run produces two files: a
readable Markdown report (assessment, summary, key findings, counterparties, the
full fund-flow trace and a methodology note) and a `.json` with the raw
structured data for further processing.

Example trace output:

```
⚪ 0xaaaa…0001  (victim)
├── ──50.00 (1 tx)──▶ ⚪ 0xbbbb…0002
│   └── ──48.00 (1 tx)──▶ 🟣 Tornado Cash: Router
│       └── ↳ trail ends here (identifiable entity — subpoena / off-chain)
└── ──10.00 (1 tx)──▶ 🟢 Binance 14 (hot wallet)
    └── ↳ trail ends here (identifiable entity — subpoena / off-chain)
```

Legend: 🟢 exchange · 🟣 mixer · 🔴 sanctioned/scam · 🌉 bridge · ⚪ unknown

## How it works

The blockchain is public — every transaction is queryable. `crypttrace`:

1. Fetches an address's full tx history via Etherscan (cached in SQLite so
   repeated traces don't re-hit the API).
2. Matches addresses against a local label DB (`labels/known.json`) —
   exchanges, Tornado Cash, bridges, sanctioned wallets.
3. For `trace`, follows the largest outgoing transfers recursively, stopping
   when it reaches an identifiable entity (exchange/mixer/sanctioned) — that's
   the OSINT handoff point.

## Honest limitations

- **Pseudonymity.** You see funds land on `0xABC`, not who owns it. The tool
  brings the trail to a *point of identification* (usually an exchange with
  KYC). The final name comes from a legal request to that exchange, not from
  the chain.
- **Mixers break the trail.** Tornado Cash / privacy pools sever the on-chain
  link. Recovery there needs timing/amount heuristics and isn't guaranteed.
- **Labels are only as good as the DB.** The seed set here is small. Real use
  means importing OFAC SDN, Chainabuse, and exchange deposit-address sets.

## Layout

```
src/crypttrace/
  cli.py            # typer CLI: profile / trace / label / chains
  config.py         # chains, API key, paths
  fetchers/
    etherscan.py    # Etherscan v2 client + SQLite cache
  labels/
    known.json      # seed label DB
    labels.py       # lookup + risk scoring
  trace.py          # recursive fund-flow tree
  render.py         # rich terminal rendering
```

## Roadmap ideas

- `watch` command: alert (telegram/webhook) when a watched address moves funds
- `report --pdf`: export the report to PDF for an exchange/police filing
- Cross-chain: follow value through bridges into other networks
- ERC-20 / stablecoin tracing (data already fetched via `get_token_txs`)
- Entity clustering: gas-funding heuristic, common-input-ownership (BTC)
- More label sources: Chainabuse, CryptoScamDB, exchange deposit-address sets
