"""Rebuild victims.csv for the fragment-api drain straight from the TON chain.

    python build_victims.py                  # everything up to the case cut-off
    python build_victims.py --until now      # include anything swept since

A wallet counts as a victim when it sent the collector at least one of:
  - a plain TON transfer (no comment, no contract opcode) of 0.001 TON or more,
  - a jetton (USDT or any other),
  - an NFT.
Left out, because they are not thefts: comments people send the collector
(0.01 TON with a message), 0.0001-TON dust from look-alike addresses, and the
notifications and gas refunds that jetton wallets and NFT items send back.
"""
import argparse
import csv
import datetime as dt
from collections import defaultdict

from crypttrace import addresses, assets
from crypttrace.fetchers import http, ton

COLLECTOR = "UQDiqkA78AG6tqpWPP3WeQs4EvvOIXZyXAg4JZwjNq9Tqwnm"
CUTOFF = "2026-09-30T17:30:00+00:00"
USDT = assets.resolve_asset("usdt", "ton")["contract"]


def ts(value: str) -> int:
    if value == "now":
        return int(dt.datetime.now(dt.timezone.utc).timestamp())
    return int(dt.datetime.fromisoformat(value).timestamp())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="victims.csv")
    ap.add_argument("--until", default=CUTOFF, help="ISO time or 'now'")
    until = ts(ap.parse_args().until)
    out = ap.parse_args().out
    http.FRESH = True
    me = addresses.ton_friendly(COLLECTOR)
    v = defaultdict(lambda: {"ton": 0.0, "usdt": 0.0, "jettons": set(), "nfts": 0,
                             "first": None, "txs": 0})

    def hit(addr: str, when: int) -> dict:
        row = v[addr]
        row["first"] = when if row["first"] is None else min(row["first"], when)
        row["txs"] += 1
        return row

    for t in ton._pages("/transactions", "transactions", {"account": me}, 5000, ton.TX_PAGE):
        m, when = t.get("in_msg") or {}, int(t.get("now") or 0)
        if not m.get("source") or when > until:
            continue
        comment = ((m.get("message_content") or {}).get("decoded") or {}).get("comment")
        value = int(m.get("value") or 0) / ton.NANO
        if m.get("opcode") not in (None, "0x00000000") or comment or value < 0.001:
            continue
        hit(addresses.ton_friendly(m["source"]), when)["ton"] += value

    for r in ton.jetton_transfers(me, 5000):
        if r["to"] != me or r["from"] == me or r["timestamp"] > until:
            continue
        row = hit(r["from"], r["timestamp"])
        if r["contract"] == USDT:
            row["usdt"] += r["value"]
        else:
            row["jettons"].add(r["contract"])

    nfts = ton._get("/nft/transfers", {"owner_address": me, "limit": 1000}).get("nft_transfers") or []
    for n in nfts:
        when = int(n.get("transaction_now") or 0)
        if addresses.ton_friendly(n.get("new_owner") or "") == me and when <= until:
            hit(addresses.ton_friendly(n["old_owner"]), when)["nfts"] += 1

    fmt = lambda t: dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["address", "ton_lost", "usdt_lost", "other_jettons", "nfts",
                    "first_drain_utc", "transfers", "explorer"])
        for a, r in sorted(v.items(), key=lambda kv: (kv[1]["first"], kv[0])):
            w.writerow([a, f"{r['ton']:.9f}", f"{r['usdt']:.6f}", len(r["jettons"]), r["nfts"],
                        fmt(r["first"]), r["txs"], f"https://tonviewer.com/{a}"])
    print(f"{len(v)} wallets, {sum(r['ton'] for r in v.values()):,.2f} TON, "
          f"{sum(r['usdt'] for r in v.values()):,.2f} USDT, "
          f"{sum(r['nfts'] for r in v.values())} NFTs -> {out}")


if __name__ == "__main__":
    main()
