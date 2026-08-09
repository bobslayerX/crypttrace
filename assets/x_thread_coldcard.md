# X thread — Coldcard exploit fund-flow mapping

Post as a thread. Each tweet is under 280 characters. Attach the suggested
media to the tweet it sits under; attach the CSV link in the final tweet
(X does not accept .csv uploads — link to the file on GitHub instead).

---

**1/**

I mapped the full flow of funds from the Coldcard exploit — and rebuilt the
victim list nobody published.

1,169 addresses. 1,082.58 BTC.

If you held a Coldcard, you can now check whether you were hit.

Everything below came from public chain data + my open-source tool 🧵

*[media: flow graph screenshot]*

---

**2/**

Recap: on 30 July an attacker drained ~1,082 BTC (~$70M) from Coldcard
wallets in 41 minutes.

Root cause was a firmware bug that made seed generation predictable. It sat
in open-source code since March 2021.

---

**3/**

Researchers published 4 addresses holding the proceeds. That tells you where
the money *sits* — not who lost it.

So I traced backwards from those addresses instead of forwards.

The structure turned out to be: victims → **4 collectors** → 3 vaults.

---

**4/**

The important part:

One collector was swept clean to a zero balance — so it never appeared in any
public list of "addresses holding stolen funds."

491 victims sent their coins through it.

Anyone checking the published addresses would never find them.

---

**5/**

Another address is listed publicly as holding "32.45 BTC".

594.48 BTC actually passed through it. It's a relay: it received the sweep
from 500 wallets, forwarded 562.02 BTC onward, and the 32.45 is just what was
left behind.

594.477 − 562.020 = 32.458 ✔️

---

**6/**

Timing, per branch:

01:10 → 178 wallets
01:32 → 491 wallets (all inside a single minute)
01:36–01:51 → 500 wallets in four waves

My tool flagged it automatically: 400 of 501 transfers inside 14 minutes,
~28/minute.

*[media: timeline screenshot]*

---

**7/**

There's a signature in the amounts.

Every victim had exactly **3,300 sats** deducted, regardless of size:
1.0 → 0.999967
0.5 → 0.499967
0.15 → 0.149967

3,300 sats = ~110 vB at 30 sat/vB. A hardcoded fee, 30–75x the going rate
that week. Speed over cost.

---

**8/**

None of it has moved.

All 1,082 BTC still sit untouched across three addresses. I have them on a
watchlist — the moment they head for an exchange is the only realistic window
to freeze anything.

---

**9/**

One thing I won't hide: my own tool got it wrong first.

It credited a wallet with sending 89 BTC. That wallet had handled 0.77 BTC in
its entire life.

I was attributing multi-input Bitcoin transactions to the first input address.

---

**10/**

Fixed it to split value across all inputs proportionally, re-ran everything,
and the numbers now reconcile with the chain to the satoshi
(branch B: 398.485879 BTC in the tool, 398.485879 on-chain).

Lesson: always verify a forensics tool against the source.

---

**11/**

Tool is free and open source — Bitcoin, Ethereum, Tron, Solana and EVM chains,
CLI + local web UI:

github.com/bobslayerX/crypttrace

Consolidated victim list (1,169 addresses, amounts, timestamps):
github.com/bobslayerX/crypttrace/blob/main/assets/coldcard_victims_consolidated.csv

*[media: victims table screenshot]*

---

## Notes

- Tweet 1 is the hook — the graph image matters most there.
- Don't merge tweets 9 and 10. Admitting and fixing the bug is what makes the
  rest credible to this audience.
- Accounts worth engaging after posting (do not spam-tag them in the thread
  itself): researchers who covered the incident, and the Coldcard vendor.
- If asked "why does your count differ from 1,196?": ours is unique addresses
  after dust filtering; a handful of wallets were swept twice, and tiny dust
  senders are excluded.
