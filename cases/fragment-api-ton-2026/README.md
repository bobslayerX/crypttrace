# Case: fragment-api seed leak, 29–30 September 2026 (TON)

From 29 September 2026, 18:49 UTC, a bot emptied 200 TON wallets into one
collector. The wallets' seed phrases had been entered into fragment-api, a
third-party service for buying Telegram Stars through Fragment (not Fragment
itself); its owner says the service's server was breached. The service's own
wallet, `fragmentapi.ton`, was emptied too.

This folder holds the victim list crypttrace produced, the cash-out path with
every transaction, and the script that rebuilds the list from the chain.

The addresses in this folder are public on-chain data. Nothing here identifies a
person: `.ton` and `t.me` names that point at victims' wallets are left out, and
so are the Telegram usernames among the stolen NFTs.

## Files

| File | What it is |
|---|---|
| `victims.csv` | **The victim list.** One row per wallet: TON and USDT lost, other jettons and NFTs taken, time of the first sweep, explorer link. 200 wallets, 10,080.38 TON, 29,493.70 USDT, 19 NFTs, as of 2026-09-30 17:30 UTC. |
| `cashout.csv` | Every step from the collector to the exchanges, with transaction links. |
| `build_victims.py` | Rebuilds `victims.csv` from the chain; `--until now` adds anything swept since. |

## What happened

| | |
|---|---|
| Collector | `UQDiqkA78AG6tqpWPP3WeQs4EvvOIXZyXAg4JZwjNq9Tqwnm` |
| Wallets swept | 200 (plus later top-ups of the same wallets, swept again) |
| Taken | 10,080.38 TON, 29,493.70 USDT, about 40 other jettons, 19 NFTs (Telegram usernames, domains) |
| Main wave | 29.09 18:49–19:30 UTC: 157 wallets in 41 minutes; stragglers until 30.09 15:18 |

Each wallet was emptied with 2–6 signed transactions a few seconds apart —
jettons first, then NFTs, then all the TON. Nobody approves six transactions a
minute by hand across a hundred wallets at once, so the keys themselves had
leaked. At least 152 of the 200 had paid the Fragment wallet before (tonapi
names it "Fragment") — buyers of Stars and Premium, as the service's users
would be.

The collector was never funded on its own: its first transaction is the first
victim's money arriving. There is no earlier wallet of the attacker's to follow
backwards.

## Where the money went

1. **7,737.84 TON** (29.09 19:41), **28,877.77 USDT** (20:43) and **2,020.76 TON**
   (30.09 12:54) each went to a fresh one-off address that forwarded it within
   8 minutes to `crypto-exch-io.ton` / `crypto-exch-io-token.ton`. These are
   deposit addresses of an exchange service: the gas to sweep the USDT one came
   from the service's own gas wallet. The service's funds consolidate at a
   wallet tonapi names "Kucoin 1".
2. **30.09 16:34–16:39** the collector sent everything left — 320.86 TON,
   615.93 USDT, 494 tsTON, all the other jettons and 15 NFTs — to a second
   wallet, `UQCuquK3ZOsWuGCh21eFC_SrmB6pezbtKP_Mm2kJDactC5Wb`, created for it.
3. **16:49–16:50** it swapped the tsTON and the USDT for TON on STON.fi.
4. **16:53** it sent **1,280 TON straight to "Kucoin 1" with the comment
   `2093842166`**. That wallet requires a memo (tonapi: `memo_required`) and
   its other deposits carry 10-digit numeric memos like this one: it is the
   deposit tag of one KuCoin account.

`.ton` names are chosen by their owners; the KuCoin name is tonapi's. Only the
exchange can confirm who holds the account behind the memo.

## Reproducing it

```bash
python build_victims.py
crypttrace timeline UQDiqkA78AG6tqpWPP3WeQs4EvvOIXZyXAg4JZwjNq9Tqwnm --chain ton
crypttrace trace UQDiqkA78AG6tqpWPP3WeQs4EvvOIXZyXAg4JZwjNq9Tqwnm --chain ton --depth 2
crypttrace trace UQDiqkA78AG6tqpWPP3WeQs4EvvOIXZyXAg4JZwjNq9Tqwnm --chain ton --asset usdt
```

The victim list is built by `build_victims.py` rather than `crypttrace victims`:
on TON, the collector also receives comments (people writing to the attacker),
dust from look-alike addresses and gas refunds from jetton wallets and NFT
items, and `victims` would count their senders too. The script keeps only
plain transfers, jettons and NFTs.

## Corrections to the first public list

A list of 197 wallets circulated on 29.09. Checked against the chain:

- 182 of its wallets are in `victims.csv`; 18 victims were missing (14 small
  wallets swept 20:32–21:03, one re-swept for 1,522.85 TON on 30.09 03:51, and
  three swept on 30.09 afternoon).
- Four entries are not victims: two spam senders and two 0.0001-TON dust
  senders from look-alike addresses.
- 6,024 USDT attributed to `UQAbI5KA8uCW2B-1X25DK2h00Q8dn79AjY9EKY36RMWlSfkU`
  never reached the attacker: 5,965 USDT went at 19:29 to a wallet with months
  of ordinary history, most likely the owner moving it to safety.
- Three `.ton`/`t.me` names in it now resolve to other wallets; the rows here
  use the wallets the transfers actually came from.
