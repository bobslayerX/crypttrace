# Case: Coldcard exploit, 30 July 2026 (Bitcoin)

On 30 July 2026, between 01:10 and 01:51 UTC, funds were swept out of 1,169
Bitcoin addresses into four collector wallets controlled by the attacker. This
folder holds the victim list crypttrace produced for that sweep, and the raw
exports it was built from.

The addresses in this folder are public on-chain data. Nothing here identifies a
person.

## Files

| File | What it is |
|---|---|
| `victims_consolidated.csv` | **The final list.** One row per swept address: amount lost, sweep time, which collector received it, explorer link. 1,169 addresses, 1,082.58269619 BTC. |
| `raw/branch-A.csv` | `crypttrace victims` output for the relay wallet (branch A). |
| `raw/branch-B.csv` | `crypttrace victims` output for collector B. |
| `raw/branch-C.csv` | `crypttrace victims --depth 2` from the 89 BTC pile: collectors C1 and C2 and everything that fed them. |

## The four branches

| Branch | Collector | Addresses swept | BTC | Sweep window (UTC) |
|---|---|---:|---:|---|
| A | `bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0` (relay) | 500 | 594.47722484 | 01:36 – 01:51 |
| B | `bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn` | 491 | 398.48587857 | 01:32 |
| C1 | `bc1qdaarag7729c2n4l2wnyt3hkhfpcs66n98z7uuh` | 100 | 88.85045709 | 01:10 |
| C2 | `bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4` | 78 | 0.76913569 | 01:10 |

C1 and C2 both forward into the 89 BTC pile
(`bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q`). Where each address label comes
from — public research, a victim report, or crypttrace's own tracing — is
recorded in `src/crypttrace/labels/known.json`; run
`crypttrace labels why <address>` to see it.

## Reproducing it

```bash
crypttrace victims bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0 --chain btc --depth 1 -o branch-A.csv
crypttrace victims bc1qc779m8gec84k3t0ffvu0pps94zheht7lr7ueyn --chain btc --depth 1 -o branch-B.csv
crypttrace victims bc1q8jy96fe5lf8vfugydnte3cguk92gpev7kwtp3q --chain btc --depth 2 -o branch-C.csv
crypttrace timeline bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0 --chain btc
```

`victims` checks its totals against the chain before writing (see
*Self-verification* in the main README), so a run that disagrees with these
numbers will say so.
