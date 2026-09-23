# Changelog

## 0.7.0

### Added
- **HTML case file.** `report` and `investigate` now save one self-contained
  HTML page to send to an exchange or attach to a police report: the conclusion,
  what to do now (freeze, exchange, address poisoning), the fund-flow graph,
  every transfer along the trace with its transaction hashes, where each label
  comes from, and the method's limits. No scripts or external resources, so it
  opens anywhere and prints to PDF; the raw JSON is embedded and its SHA-256
  printed. Markdown and JSON are still written next to it.

### Fixed
- `report` failed with "unsupported chain" on Bitcoin, Tron and Solana, and so
  `investigate` could not save a case file there — including for the Tron USDT
  victims it is meant for. Reports now read through the shared chain layer.
- Tron approvals already stored by versions before 0.5.0 (as ~10^59-token
  transfers) are no longer served from the local store.
- `investigate`'s case file now uses the depth you asked for, not always 3.
- Freeze wording: an empty blacklisted address is described as blacklisted, not
  "0.00 frozen", and dust left at an address no longer triggers a freeze request.

## 0.6.0

### Added
- **Stablecoin freezes** — `crypttrace freeze ADDRESS`: how much USDT/USDC is at
  an address, whether Tether or Circle has already frozen it, and if not, what
  each issuer needs to freeze it. Read from the issuers' own contracts on
  Ethereum, Tron and Solana, with no API key. `investigate` makes it the first
  step when stablecoins are still movable, the web UI shows it in the side
  panel, and a freeze counts as a signal in the assessment.

## 0.5.0

### Added
- **Address poisoning** — `crypttrace poisoning ADDRESS`. On a wallet: look-alike
  addresses planted in its history and any money sent to one. On the address the
  money went to: payments made right after it lured the payer, and the address it
  imitates. Also part of `assess`, `investigate` and the web UI's assessment.
  Checked against a documented $9.4M Tron campaign, where it finds the victims
  and the imitated addresses.

### Fixed
- **Tron:** token history read `Approval` events as transfers, so an unlimited
  USDT approval showed up as a transfer of about 10^59 USDT and wrecked totals,
  traces and assessments for any address that had ever approved a contract.
- **Solana:** after a token query, SOL history served from the local store
  included SPL token rows, adding token amounts to SOL balances and flows. Stores
  already affected are read correctly too. Solana token history is now cached
  instead of re-fetched every time.

## 0.4.0

### Added
- `crypttrace update-labels --okx` downloads OKX's proof-of-reserves address
  list — over 300,000 addresses OKX signed, nearly all of them customer deposit
  addresses — and labels them directly. A deposit is recognised as soon as funds
  arrive, not only after OKX sweeps it. The set lives in SQLite under
  `~/.crypttrace/` (about 18 MB), is looked up per address, and never overrides
  a curated label. `--okx-file` imports a copy you downloaded yourself.
  `offramp` treats these as deposits, not exchange wallets, so a wallet that
  merely paid *into* one is not mistaken for a deposit address itself.
- `labels audit` lists downloaded sets; `labels why` explains their labels.

## 0.3.0

### Added
- **Exchange labels on Bitcoin, Tron and Solana beyond Binance:** 133 reserve
  wallets of OKX, HTX and Bybit, each from the address list the exchange
  publishes itself. OKX's are its largest wallets (each holding at least 0.5% of
  a coin's reserve on that chain) out of a signed list of ~310k addresses.
- `offramp` on Tron and Solana also checks USDT and USDC, which is how deposits
  there are usually swept; `trace` checks the asset being traced.

### Fixed
- `crypttrace trace` stopped with "unsupported chain" on Bitcoin, Tron and
  Solana as soon as it reached an unlabelled wallet: the off-ramp check read
  Etherscan directly. It now goes through the shared chain layer, so `offramp`,
  `investigate` and the web UI work on every chain.
- `investigate` told victims to contact "Binance reserve wallet" instead of
  "Binance".

## 0.2.0 — first release on PyPI

Everything built since the project started in July 2026, now installable with
`pipx install "crypttrace[web]"`.

### Added
- **Chains:** Ethereum and the EVM chains (BSC, Polygon, Arbitrum, Optimism,
  Base) through Etherscan v2; Bitcoin, Tron and Solana with no API key needed.
- **Tracing:** `trace` forward or backward (`--direction in`), for native coins
  or tokens (`--asset usdt`), stopping at identifiable entities.
- **`investigate`:** one command for victims — follows the money, saves a case
  file and explains what to do next in plain language.
- **Web UI** (`crypttrace serve`): interactive fund-flow graph, timeline,
  victim list with CSV download, assessment tab.
- **Analysis:** `funder` (first-funder chain), `offramp` (exchange deposit
  detection), `cluster` (Bitcoin common-input ownership), `crosschain` (bridge
  matching), `victims` (CSV of everyone who fed a wallet), `timeline` (burst
  detection), `assess` (reasoned conclusion with evidence and confidence).
- **Self-verification:** `verify` reconciles computed totals against the chain;
  `victims` runs it automatically.
- **Labels:** curated seed set with a recorded source per claim,
  `labels audit` / `labels why`, OFAC SDN import via `update-labels`, and
  Binance reserve wallets on Bitcoin, Tron and Solana from Binance's own
  proof-of-reserves list.
- **`watch`:** alerts when watched funds move, loudly when they head for an
  exchange; optional Telegram.
- **Local store:** every response cached in SQLite; `--offline` works from it.
- Case study: [`cases/coldcard-2026`](cases/coldcard-2026) — the victim list for
  the July 2026 Coldcard sweep.

### Fixed
- Timeline and assessment under-reported bursts: the count was 80% of all
  transfers rather than the transfers actually inside the window, so 78 swept
  in one batch read as "All 63 transfers share one timestamp".
- The CLI crashed on Windows when output was redirected or run from Task
  Scheduler (`UnicodeEncodeError` on the ANSI code page).
- Solana labels whose address starts with `1`, `3` or `T` were silently dropped
  when the label database loaded.
- Web UI: every value from the backend is now HTML-escaped (token symbols come
  from the chain and can be anything), and addresses are URL-encoded in API
  requests.
