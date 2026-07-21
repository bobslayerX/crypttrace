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

# Supported chains
crypttrace chains
```

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
- `report` command: export a trace to PDF for an exchange/police filing
- Cross-chain: follow value through bridges into other networks
- ERC-20 / stablecoin tracing (data already fetched via `get_token_txs`)
- Entity clustering: gas-funding heuristic, common-input-ownership (BTC)
- `update-labels`: pull OFAC SDN + community scam lists automatically
