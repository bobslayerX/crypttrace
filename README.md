# crypttrace

[![selftest](https://github.com/bobslayerX/crypttrace/actions/workflows/selftest.yml/badge.svg)](https://github.com/bobslayerX/crypttrace/actions/workflows/selftest.yml)
[![PyPI](https://img.shields.io/pypi/v/crypttrace)](https://pypi.org/project/crypttrace/)
[![Python](https://img.shields.io/pypi/pyversions/crypttrace)](https://pypi.org/project/crypttrace/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

Open-source OSINT toolkit for crypto investigations. Give it a suspicious
address; it pulls the public on-chain history, labels known entities (exchanges,
mixers, sanctioned wallets), scores risk, and maps where the funds moved —
across Ethereum, Bitcoin, Tron, Solana and more.

Built for the investigation that actually happens: *someone's crypto was stolen,
here's the wallet — where did the money go, and where can it still be stopped?*

Works as a terminal tool **and** as a local web app with an interactive
fund-flow graph.

![crypttrace tracing the AFX Trade exploit](https://raw.githubusercontent.com/bobslayerX/crypttrace/main/assets/graph-outflow.png)

*Real case: the AFX Trade exploiter (July 2026, $24.15M). crypttrace follows the
stolen ETH out of the attacker's wallet — 12,467 ETH (~$23.3M) to a holding
address, then split across three wallets and split again. Classic layering,
mapped in seconds.*

---

## Install

```bash
pipx install "crypttrace[web]"     # or: pip install "crypttrace[web]"
```

`[web]` also installs Flask for the web UI; leave it off for the terminal tool
alone. Python 3.9 or newer. To work on the code instead:

```bash
git clone https://github.com/bobslayerX/crypttrace
cd crypttrace
pip install -e ".[web]"
python selftest.py                 # offline checks, no API keys needed
```

### API keys — what's actually required

| | Needed? | How to get it |
|---|---|---|
| **EVM chains** (Ethereum, BSC, Polygon, Arbitrum, Optimism, Base) | **Required** | Free key at [etherscan.io/myapikey](https://etherscan.io/myapikey). One v2 key covers all EVM chains. |
| **Bitcoin, Tron, Solana** | **Not required** | Work out of the box via public endpoints. |

```bash
export ETHERSCAN_API_KEY=xxxx           # required for EVM chains only
```

On Windows (PowerShell):

```powershell
$env:ETHERSCAN_API_KEY = "xxxx"                            # this window only
[Environment]::SetEnvironmentVariable("ETHERSCAN_API_KEY", "xxxx", "User")   # permanently
```

**About the keyless chains:** Bitcoin, Tron and Solana work with no signup at
all, but their free public endpoints are **rate-limited**. crypttrace handles
this for you — it caches every response, spaces requests out, and retries with
backoff when a limit is hit. For deep traces you can raise the ceiling with your
own credentials (all optional):

```bash
export TRONGRID_API_KEY=xxxx            # optional: higher TronGrid quota
export CRYPTTRACE_SOLANA_RPC=https://…  # optional: your own (faster) Solana RPC
```

(In PowerShell: `$env:TRONGRID_API_KEY = "xxxx"` and so on.)

## Supported chains

| Chain | `--chain` | Data source | Model |
|---|---|---|---|
| Ethereum, BSC, Polygon, Arbitrum, Optimism, Base | `eth` `bsc` `polygon` `arbitrum` `optimism` `base` | Etherscan v2 | account |
| Bitcoin | `btc` | mempool.space | UTXO |
| Tron (TRX + USDT-TRC20) | `tron` | TronGrid | account |
| Solana (SOL + SPL) | `sol` | public JSON-RPC | account |

Every network is normalized to the same transfer shape, so `profile`, `trace`,
`funder`, `report` and the web graph behave identically everywhere. Bitcoin
additionally unlocks `cluster`. Tron matters for everyday victim cases — most
romance / "pig butchering" scams move USDT-TRC20 because fees are near zero.

---

## Web UI

```bash
crypttrace serve            # then open http://127.0.0.1:8000
```

Paste an address, pick a chain and direction, and get an interactive fund-flow
graph: nodes coloured by what they are, arrows showing where value went, click a
node for its full profile, click a transfer line to open it on the block
explorer. A side panel shows the profile, first-funder chain, off-ramp check
and whether USDT/USDC at the address is frozen. Tabs add the assessment, the
timeline, the list of who sent funds here, and address poisoning (look-alikes
planted in the wallet's history, and payments lured by this address). **Case
file** downloads the same one-page HTML report `crypttrace report` writes.
Everything runs on your machine — nothing is uploaded anywhere.

This exists so non-technical victims can use the tool at all: a form and a
picture, instead of command-line flags.

**Both directions of the same investigation.** Forward — where the stolen money
went:

![Tracing stolen funds forward](https://raw.githubusercontent.com/bobslayerX/crypttrace/main/assets/graph-outflow.png)

Backward — how that wallet was funded in the first place, which is how you tie
an anonymous wallet to something identifiable:

![Tracing a wallet's funding backward](https://raw.githubusercontent.com/bobslayerX/crypttrace/main/assets/graph-inflow.png)

## If your crypto was stolen — start here

```bash
crypttrace investigate 0xADDRESS_THE_FUNDS_WENT_TO
```

One command. It follows the money, works out where it ended up, saves a case
file you can send to an exchange or attach to a police report, and then explains
**in plain language what to do next** — which exchange to contact, where to file,
how to keep watching the money, and how to avoid the "recovery services" that
target victims a second time.

It is also honest with you: most stolen crypto is not recovered, and what
matters is speed and whether the funds touch a regulated exchange. The tool
gives you evidence and timing — it cannot move funds or name a person by itself.

**Stolen USDT or USDC?** Check at once whether it is still sitting at the
thief's address — Tether and Circle can freeze it there, and only there:
`crypttrace freeze THEIR_ADDRESS --chain tron`. `investigate` does this too
and puts it first.

**Sent money to an address that looked right?** That is usually address
poisoning — see below. Check your own wallet with
`crypttrace poisoning YOUR_ADDRESS`.

## Commands

```bash
# The one-command investigation (recommended starting point)
crypttrace investigate 0xADDRESS --chain eth

# What is this address? (local label DB, works offline)
crypttrace label 0x28c6c06298d514db089934071355e5743bf21d60

# Balance, activity window, risk, top counterparties — on any chain
crypttrace profile 0xADDRESS --chain eth
crypttrace profile bc1qADDRESS --chain btc

# Follow the money, hop by hop, as a coloured tree
crypttrace trace 0xADDRESS --depth 4 --branching 3

# Trace backwards instead: where did this wallet's funds come FROM?
crypttrace trace 0xADDRESS --direction in

# Trace a token rather than the native coin (most thefts are stablecoins)
crypttrace trace 0xADDRESS --asset usdt --depth 4

# Token holdings, valued in USD
crypttrace tokens 0xADDRESS

# Who bootstrapped this wallet's first gas? Follow it toward a KYC point
crypttrace funder 0xADDRESS --hops 6

# Is the USDT/USDC at this address frozen by Tether/Circle — and who can freeze it?
crypttrace freeze TADDRESS --chain tron

# Address poisoning: look-alike addresses planted in a wallet's history
crypttrace poisoning TADDRESS --chain tron

# Is this an exchange deposit address (i.e. the cash-out point)?
crypttrace offramp 0xADDRESS

# Bitcoin only: find other wallets owned by the same person
crypttrace cluster bc1qADDRESS

# Who fed this wallet? In a mass theft, that's the victim list → CSV
crypttrace victims bc1qADDRESS --chain btc --depth 1 -o victims.csv

# When did the money move? Spots automated sweeps vs ordinary use
crypttrace timeline bc1qADDRESS --chain btc

# Follow funds across bridges into other chains
crypttrace crosschain 0xADDRESS --window 48

# Watch addresses; alert loudly the moment funds head for an exchange
crypttrace watch add 0xADDRESS --note "my stolen ETH"
crypttrace watch run --interval 300     # or --once for cron / Task Scheduler

# Full investigation as a case file to send: one HTML page (plus Markdown + JSON)
crypttrace report 0xADDRESS --depth 3

# Refresh label lists (OFAC sanctions, …)
crypttrace update-labels

# …and add OKX's ~300k signed deposit addresses (downloads ~80 MB once)
crypttrace update-labels --okx

# Launch the web UI / list chains
crypttrace serve
crypttrace chains
```

Example trace output:

```
🔴 0x098B716B…3E2f96  [Ronin Bridge Exploiter (Lazarus)]
├── ──33568.15 ETH (1 tx) ≈$63.8M──▶ 🔴 0x35fb6f6d…26d4b1  [OFAC SDN (sanctioned)]
│   └── ↳ trail ends here (identifiable entity — subpoena / off-chain)
└── ──25127.51 ETH (1 tx) ≈$47.7M──▶ ⚪ 0xf7b31119…5cf1be
    └── ──4100.00 ETH (41 tx) ≈$7.8M──▶ 🟣 Tornado Cash: 0.1 ETH
        └── ↳ trail ends here (identifiable entity — subpoena / off-chain)
```

Legend: 🟢 exchange · 🟣 mixer · 🔴 sanctioned/scam · 🌉 bridge · ⚪ unknown

---

## Capabilities in depth

### Tracing (forward and backward)

`trace` follows the largest transfers recursively and stops at identifiable
entities — that's the OSINT handoff point. `--direction out` (default) answers
"where did the money go"; `--direction in` answers "where did this wallet's
money come from", which is how you vet a suspicious address or find a victim's
source of funds.

### Watch & alerts — catching the cash-out

The only window to freeze stolen funds is the moment they reach an exchange
deposit. Victims can't monitor a chain 24/7. `watch` keeps a list of addresses,
detects new activity and raises a **loud HIGH alert** the instant funds move
toward an exchange (directly, or to a detected deposit address); quieter notices
for other movement. It only alerts on activity *after* an address is added, and
never double-alerts.

```bash
crypttrace watch add 0xADDRESS --note "victim funds"
crypttrace watch list
crypttrace watch run --interval 300     # continuous
crypttrace watch run --once             # single check, for scheduled tasks
```

Optional Telegram alerts: set `CRYPTTRACE_TG_TOKEN` and `CRYPTTRACE_TG_CHAT`,
then pass `--telegram`.

### Stablecoin freezes

Tether and Circle can freeze USDT and USDC at any address. For a victim of a
stablecoin theft that is the one lever that actually stops the money — while it
is still there. `crypttrace freeze` reads the issuers' own contracts (USDT's
`isBlackListed`, USDC's `isBlacklisted`, balances; token-account state on
Solana) on Ethereum, Tron and Solana, and answers three things: how much is
there, whether it is already frozen, and if not, who can freeze it:

- **Tether** freezes USDT at the request of law enforcement, often before a
  court case — so the route is the police, quickly
  ([policy](https://tether.to/en/legal/?tab=law-enforcement-requests)).
- **Circle** freezes USDC only on a legal order such as a court order
  ([terms](https://www.circle.com/legal/usdc-terms)), which takes longer.

No API key is needed: Ethereum is read through a public node (set
`CRYPTTRACE_ETH_RPC` to use your own). `investigate` runs the check on the
address the money went to and makes it the first step; the web UI shows it in
the side panel; a freeze also counts in the assessment. A check that fails is
reported as unknown, never as "not frozen". Other chains carry bridged or
third-party versions of these tokens that the issuers cannot freeze in the same
way, so they are not checked.

### Address poisoning

Wallets show addresses shortened — `TDDD34…rCr9Ps`. A poisoner generates an
address with the same first and last characters and plants it in the victim's
history with a zero-value transfer, a speck of dust or a counterfeit token. The
next time the victim copies "the address I paid last time", they copy the
attacker's. It is common on Tron and Ethereum, and it needs no hacking at all.

`crypttrace poisoning` looks at it from both ends:

- **Your wallet:** pairs of addresses in your history that share their visible
  characters, which one arrived later with bait, and — the part that matters —
  whether you then sent real money to it.
- **The address your money went to:** who paid it real money right after it
  lured them, and which address it was imitating, read from the payer's own
  history. `investigate` and the assessment run this automatically.

Tested on a documented Tron case from August 2026: from the victim's wallet it
finds the 2,527,862 USDT sent to `TDDDHi…rCr9Ps`, a look-alike of
`TDDD34…rCr9Ps`, an address the wallet had paid 8.4M USDT in all. From the
attacker's side it finds the same payment and two more victims of $2.4M and
$2.0M, each lured by a look-alike created three to twelve minutes earlier.

Cheap look-alikes match only one or two characters at each end, which happens
by chance; those are reported only when they arrived as bait after the real
address was in use.

### Off-ramp detection

Laundered funds reaching an exchange land on a per-user *deposit address* —
there are millions, so none appear in any label list. `offramp` spots them by
behaviour: an address forwarding most of its outgoing value to a labelled
exchange is almost certainly a deposit address, i.e. the cash-out point where
that exchange holds the depositor's KYC. `trace` applies the same heuristic
automatically, turning an anonymous intermediary into "→ Binance deposit (KYC
point)". It works on every supported chain; on Tron and Solana, where deposits
are usually swept as stablecoins, it checks USDT and USDC as well as the native
coin.

### First-funder (deanonymization)

`funder` follows a wallet's funding link backward: whoever sent its first gas,
then whoever funded that funder. A fresh laundering wallet must be bootstrapped
from somewhere, and the chain frequently terminates at an exchange withdrawal —
an identification point. A core primitive for tying "unrelated" wallets to one
controller. (Uses external transactions; wallets first funded by an internal
contract call need internal-tx data — a planned extension.)

### Victim lists and timing analysis

Two things a graph shows but can't hand you as evidence.

`victims` walks the money backwards from a consolidation wallet and lists every
address that fed it — amounts, transaction counts, first/last seen, explorer
links — and writes it to **CSV**. After a mass drain that list *is* the set of
victims, in the form an exchange's compliance team or a police report can
actually use.

`timeline` answers *when*. It buckets activity into a histogram and finds the
tightest window containing most of the transfers. This separates a theft from
ordinary wallet use: hundreds of transfers inside minutes is an automated tool
spending keys it already holds, whereas a real owner's activity is spread over
months. The tool says so in plain language rather than leaving you to eyeball it.

```
crypttrace victims  bc1qADDRESS --chain btc --depth 2 -o victims.csv
crypttrace timeline bc1qADDRESS --chain btc --buckets 24
```

![The victim list for one branch of the Coldcard sweep in the web UI](https://raw.githubusercontent.com/bobslayerX/crypttrace/main/assets/web-victims.jpg)

A worked example — 1,169 swept addresses, 1,082.58 BTC, with the commands to
reproduce it — is in [`cases/coldcard-2026`](cases/coldcard-2026).

**Dust is filtered by default.** Addresses that become publicly known get spammed
with tiny transfers, which otherwise bury the transactions that matter and can
flip the timing verdict entirely. Each chain has a dust threshold; override with
`--min-value`, or keep everything with `--include-dust`. Bitcoin history is
paged rather than read one page deep, so an old sweep isn't hidden behind recent
spam.

### Bitcoin clustering (common-input-ownership)

Bitcoin's UTXO model enables the strongest clustering heuristic in blockchain
forensics: if several addresses sign the inputs of one transaction, one party
almost certainly controls all of them. `cluster` surfaces those co-signers,
turning a single address into a set of wallets belonging to the same owner. A
strong lead, not proof.

### Cross-chain tracing (bridges)

When funds cross a bridge the trail ends at the bridge contract and reappears on
another chain, with no free deterministic link between the two. `crosschain`
uses a behavioural heuristic that catches many real cases: launderers frequently
bridge to the *same address* they control on the destination chain, so after a
transfer into a known bridge the tool searches every other supported chain for
an inbound transfer to that address of a similar amount (bridges take a fee)
within a time window. Matches are reported with amount and delay — a strong
**lead, not proof**. Recognised bridges: Wormhole, the canonical Optimism /
Arbitrum / Base bridges, Across, Synapse and Celer cBridge (extend the
`"bridge"` entries in `labels/known.json`).

### Assets & USD values

The tracer follows the chain's native coin by default. `--asset` switches to a
token — most thefts and scams move stablecoins, so this is usually what you
want:

```bash
crypttrace trace 0xADDRESS --asset usdt                   # USDT on Ethereum
crypttrace trace TADDRESS  --chain tron --asset usdt      # USDT-TRC20 on Tron
crypttrace tokens TADDRESS --chain tron
```

Token contracts differ per chain, so the registry is chain-aware: `usdt` on Tron
resolves to `TR7NHqje…jLj6t`, on Ethereum to `0xdac17f95…31ec7`. Known symbols
are `usdt`, `usdc`, `dai`, `weth`, `wbtc` on EVM and `usdt`, `usdc` on
Tron/Solana; you can also pass any contract address directly.

Matching is by **exact contract**, which matters: attackers routinely airdrop
fake tokens named "USDT" to poison wallets, and those are ignored rather than
traced. Native coins and tokens are also kept strictly separate — summing TRX
with USDT would be meaningless.

Amounts carry approximate USD values (stablecoins pinned to $1, others priced
via CoinGecko). If pricing is unavailable, USD shows as `—` rather than a guess.

### Labels

Ships a curated seed set (major exchanges, Tornado Cash, bridges, notable
hacks). `update-labels` pulls authoritative public lists — currently the OFAC
SDN sanctioned-address list — and merges them into the local DB in
`~/.crypttrace/`. The curated seed wins on conflicts, so richer names survive.
Add sources in `labels/labels.py` → `SOURCES`.

On Bitcoin, Tron and Solana the labels cover the reserve wallets of Binance,
OKX and HTX, plus Bybit's older 2022 list — each taken from the address list the
exchange publishes itself for proof-of-reserves. That is what lets `offramp`
flag deposit addresses on those chains. Funds sent to an exchange not on that
list still show as `unknown`. Every label records where it came from — see
`crypttrace labels audit`.

**Deposit addresses, labelled outright.** OKX signs every address that holds
customer funds — over 300,000, nearly all of them per-customer deposit addresses
— and publishes the list with its proof of reserves. `crypttrace update-labels
--okx` downloads the latest one into `~/.crypttrace/` (about 18 MB once
imported). With it, funds landing on an OKX deposit address are identified the
moment they arrive, before OKX sweeps them onward — which is when a freeze
request still has something to freeze. Without it, `offramp` only recognises a
deposit address after it has forwarded the money. Rows without OKX's signature
are ignored, and every address is checked before it is stored.

### Reports

`report` runs the full analysis and writes a **case file** to
`~/crypttrace-reports/` (override with `--out`); `investigate` saves the same
file with the victim's next steps in it. The case file is one HTML page, made
for whoever receives it — an exchange's compliance team, the police, a lawyer:

- the conclusion in plain words, and what to do now: stablecoins still at the
  address and who can freeze them, the exchanges the money reached, address
  poisoning;
- the fund-flow graph, each address linking to a block explorer;
- every transfer along the trace with its transaction hashes — the first thing
  an exchange asks for;
- where each label comes from, how the tool checked its own arithmetic, and
  what the method cannot tell you.

It has no scripts and loads nothing from the internet, so it opens in any
browser or mail client, prints (or saves as PDF) cleanly, and opening it tells
no one. The raw data is embedded for analysts and written next to it as JSON,
with its SHA-256 printed on the page; a Markdown version is written too.

### Self-verification

A forensics tool that quietly miscounts is worse than no tool: the output looks
authoritative and ends up in reports. `verify` re-derives the totals from what
the tool parsed and compares them against the figures the chain index reports
independently.

```
crypttrace verify bc1qADDRESS --chain btc
```

It reports one of:

| Status | Meaning |
|---|---|
| **verified** | Gross totals match the chain independently. |
| **consistent** | Balance reconciles, but this chain publishes no independent gross totals, so attribution is only partly checked. |
| **partial** | Only part of the address's history was read — totals are a floor, not the whole picture. |
| **mismatch** | Computed totals disagree with the chain. Don't rely on the output until it's explained. |

`victims` runs this automatically, because that list is the output most likely
to be quoted as evidence; the web UI shows the same status as a badge.

This exists because the tool *did* once miscount — attributing a whole
multi-input Bitcoin transaction to its first input address, crediting one
wallet with 89 BTC it never handled. That was caught by hand against a block
explorer; the check now catches it automatically.

### Caching & rate limits

Every API response is cached in SQLite under `~/.crypttrace/`, so re-running a
trace — or revisiting an address within one trace — costs no requests. Non-EVM
fetchers additionally throttle per host and retry with exponential backoff on
HTTP 429, so free endpoints degrade gracefully instead of erroring out.

---

## Honest limitations

Read this before relying on the tool — and before promising anything to a
victim.

- **Pseudonymity.** You see that funds landed on `0xABC`, not who owns it. The
  tool brings a trail to a *point of identification* (usually an exchange with
  KYC). The name comes from a legal request to that exchange, not from the chain.
- **Mixers break the trail.** Tornado Cash and privacy pools sever the on-chain
  link. Anything past them is heuristic and not guaranteed.
- **Heuristics are leads, not proof.** Off-ramp detection, cross-chain matching
  and Bitcoin clustering are strong signals that can coincide by chance. Verify
  before acting on them.
- **Labels are only as good as the database.** Unlabelled ≠ innocent.
- **Recovery depends on others.** crypttrace can tell you *when* and *where* to
  act; freezing funds depends on exchanges and law enforcement responding.

## Layout

```
src/crypttrace/
  cli.py           # Typer CLI — every command
  chains.py        # unified multi-chain adapter (one transfer shape for all)
  config.py        # chains, keys, paths
  fetchers/
    etherscan.py   # EVM (Etherscan v2) + SQLite cache
    bitcoin.py     # Bitcoin UTXO (mempool.space) + clustering
    tron.py        # Tron / TRC20 (TronGrid) + base58 conversion
    solana.py      # Solana JSON-RPC
    http.py        # shared cache, throttling, 429 backoff
  labels/
    known.json     # curated label DB, one source per claim
    partial.json   # addresses known only in truncated form
    labels.py      # lookup, risk scoring, source imports
    audit.py       # checksum + provenance audit of the label DB
  addresses.py     # per-chain address validation (checksums)
  store.py         # local SQLite store of every transfer read
  trace.py         # fund-flow tree + graph builder
  investigate.py   # one-command victim workflow
  analysis.py      # victim lists, timeline, burst detection
  assess.py        # reasoned assessment with evidence and confidence
  verify.py        # reconcile computed totals against the chain
  funder.py        # first-funder heuristic
  offramp.py       # exchange-deposit detection
  bridges.py       # cross-chain matching
  watch.py         # watchlist + alerts
  report.py        # Markdown + JSON reports
  prices.py        # USD valuation
  render.py        # rich terminal rendering
  webapp.py        # Flask backend for the web UI
  web/index.html   # single-page frontend (interactive graph)
selftest.py        # offline end-to-end checks, run by CI
cases/             # worked investigations with their data
```

## Roadmap

- More exchanges on Bitcoin, Tron and Solana (now: Binance, OKX, HTX, Bybit),
  and refreshing these lists as the exchanges republish them
- Internal transactions (completes `funder` and contract-mediated transfers)
- Per-mint filtering for Solana SPL tokens
- More label sources: Chainabuse, CryptoScamDB, exchange deposit-address sets
- Spam/dust token filtering in `tokens`
- Entity clustering on EVM via the gas-funding heuristic

## Contributing

Label data is the highest-leverage contribution: exchange wallets, known scam
and drainer addresses, bridges. Add them to `labels/known.json` with a `chain`,
a `source` a reader can check and a `source_kind` (`self-published`,
`official-list`, `explorer-tag`, `research`, `community`), then run
`crypttrace labels audit` and `python selftest.py` before opening a PR.
Accuracy matters more than volume — a wrong label is worse than no label.

## Licence

MIT — see [LICENSE](LICENSE).

*Use responsibly. This is an investigative aid, not evidence of wrongdoing, and
not a substitute for law enforcement.*
