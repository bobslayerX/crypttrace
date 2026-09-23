# Changelog

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
