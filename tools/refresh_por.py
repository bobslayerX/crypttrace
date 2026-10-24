"""Refresh the exchange proof-of-reserves labels in known.json — a maintainer tool.

Exchanges republish their reserve-wallet lists: Binance continuously, HTX and
MEXC monthly. This compares the current list with the labels taken from the
previous one and, with --write, applies the difference:

  - an address newly listed is added, with the same name and kind of source as
    the rest of that exchange's labels;
  - an address no longer listed keeps its label (the wallet was the exchange's,
    and old funds still lead there) but its source says it was not in the
    latest list, so possibly retired.

    python tools/refresh_por.py binance htx              # show what changed
    python tools/refresh_por.py binance htx --write      # and apply it
    python tools/refresh_por.py --mexc MEXC_PoR_Audit_20261009.pdf [--write]
    python tools/refresh_por.py --bybit Bybit_PoR_Audit_2026_Sep_23.pdf [--write]

MEXC's and Bybit's lists are the "Verified wallets" table of their monthly
Hacken audits, PDFs linked from mexc.com/proof-of-reserve/audit-report and
bybit.com/en/app/user/audit-report (download them yourself; MEXC refuses
scripts). Run `crypttrace labels audit` and selftest.py after --write, then
review the diff before committing.
"""
import argparse
import csv
import datetime as dt
import itertools
import json
import re
import sys
import zlib
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from crypttrace import addresses  # noqa: E402

KNOWN = ROOT / "src" / "crypttrace" / "labels" / "known.json"
EVM_NAMES = {"eth": "Ethereum", "bsc": "BNB Chain", "arbitrum": "Arbitrum", "base": "Base",
             "optimism": "Optimism", "polygon": "Polygon"}
RETIRED = "possibly retired"

# how each exchange's labels are recognised in known.json, by their source
FAMILIES = {
    "binance": "binance.com/bapi/apex/v1/public/apex/market/por/address",
    "htx": "github.com/huobiapi/Tool-Node.js-VerifyAddress",
    "mexc": "MEXC proof-of-reserves audit by Hacken",
    "bybit": "Bybit proof-of-reserves audit by Hacken",
}
# an exchange's older list: its labels are renewed where the current list still has
# the wallet, and marked possibly retired where it does not
LEGACY = {"bybit": "static.bycustody.com/download/app/bybit_por_202212.csv"}


def entry(address: str, chain: str, name: str, source: str) -> dict:
    """One listed wallet. EVM addresses are one label for every EVM chain."""
    evm = chain in EVM_NAMES
    if chain == "ton":                # one spelling for TON: the canonical "UQ…" lookups use
        address = addresses.ton_friendly(address) or address
    return {"key": address.lower() if evm else address, "chain": None if evm else chain,
            "name": name, "source": source}


# ------------------------------------------------------------------ Binance
BINANCE_NET = {"BTC": "btc", "TRX": "tron", "SOL": "sol", "TON": "ton", "ETH": "eth", "BSC": "bsc",
               "ARBITRUM": "arbitrum", "MATIC": "polygon", "BASE": "base", "OPTIMISM": "optimism"}


def binance(items: List[dict], today: str) -> List[dict]:
    """Entries from Binance's PoR feed (the `data` list of the API answer)."""
    day = lambda ms: dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).strftime("%Y-%m-%d")
    src = f"Binance proof-of-reserves address list ({FAMILIES['binance']}), fetched {today}"
    by: Dict[tuple, dict] = {}
    for i in items:
        chain = BINANCE_NET.get(i.get("network"))
        if not chain or not addresses.validate(i["address"], chain)[0]:
            continue
        evm = chain in EVM_NAMES
        k = (i["address"].lower(), None) if evm else (i["address"], chain)
        e = by.setdefault(k, {"chain": chain, "address": i["address"], "nets": [],
                              "since": i["createTime"], "cust": ""})
        e["nets"].append(EVM_NAMES.get(chain, chain))
        e["since"] = min(e["since"], i["createTime"])
        e["cust"] = e["cust"] or i.get("thirdPartyCustodianName") or ""
    out = []
    for e in by.values():
        name = "Binance reserve wallet" + (f" (custodied by {e['cust']})" if e["cust"] else "")
        listed = (f"; listed for {', '.join(n for n in EVM_NAMES.values() if n in e['nets'])}"
                  if e["chain"] in EVM_NAMES else "")
        out.append(entry(e["address"], e["chain"], name,
                         f"{src}{listed}; listed since {day(e['since'])}" if not listed
                         else f"{src}{listed} since {day(e['since'])}"))
    return out


def fetch_binance(today: str) -> List[dict]:
    import requests
    r = requests.get("https://www.binance.com/bapi/apex/v1/public/apex/market/por/address",
                     timeout=30, headers={"User-Agent": "Mozilla/5.0"})
    r.raise_for_status()
    return binance(r.json()["data"], today)


# ------------------------------------------------------------------ HTX
def htx_chain(coin: str) -> Optional[str]:
    c = coin.upper()
    if c == "BTC":
        return "btc"
    if c == "TRX" or c.endswith("TRC20") or c == "JSTRX":
        return "tron"
    if c in ("SOL", "BTC-SOL"):
        return "sol"
    if c in ("ETH", "STETH") or c.endswith("ERC20") or c.startswith("ERC20"):
        return "eth"
    return None                  # DOGE, XRP and other chains crypttrace does not read


def htx(text: str, snapshot: str, is_contract=lambda a: False) -> List[dict]:
    """Entries from HTX's huobi_por.csv: its second table lists the addresses."""
    lines = text.lstrip("﻿").splitlines()
    start = next(k for k, l in enumerate(lines) if l.startswith("coin,address,"))
    src = (f"HTX proof-of-reserves snapshot {snapshot} on HTX's official GitHub "
           f"({FAMILIES['htx']}, snapshot/huobi_por.csv)")
    by: Dict[str, dict] = {}
    for r in csv.DictReader(lines[start:]):
        chain, a = htx_chain(r["coin"]), (r.get("address") or "").strip()
        if not chain or not addresses.validate(a, chain)[0]:
            continue
        key = a.lower() if chain == "eth" else a
        signed = (r.get("signature") or "").strip() not in ("", "-", "_")
        e = by.setdefault(key, {"chain": chain, "address": a, "signed": False})
        e["signed"] |= signed
    out = []
    for e in by.values():
        if e["chain"] == "eth" and is_contract(e["address"]):
            continue             # a contract holding reserves is shared, not the exchange's wallet
        how = ("listed with an ownership signature (not verified by crypttrace)" if e["signed"]
               else "listed without a signature")
        out.append(entry(e["address"], e["chain"], "HTX reserve wallet", f"{src}; {how}"))
    return out


def fetch_htx() -> List[dict]:
    import subprocess
    repo = "repos/huobiapi/Tool-Node.js-VerifyAddress"
    text = subprocess.check_output(["gh", "api", f"{repo}/contents/snapshot/huobi_por.csv",
                                    "-H", "Accept: application/vnd.github.raw"], text=True,
                                   encoding="utf-8")
    msg = subprocess.check_output(["gh", "api", f"{repo}/commits?path=snapshot/huobi_por.csv&per_page=1",
                                   "--jq", ".[0].commit.message"], text=True)
    m = re.search(r"(20\d{2})(\d{2})(\d{2})", msg)
    snapshot = f"{m.group(1)}-{m.group(2)}-{m.group(3)}" if m else "(date not given)"

    def is_contract(a):
        from crypttrace.fetchers import etherscan
        code = etherscan._call("eth", {"module": "proxy", "action": "eth_getCode", "address": a,
                                       "tag": "latest"}).get("result") or "0x"
        return len(code) > 2
    return htx(text, snapshot, is_contract)


# ------------------------------------------------------------------ MEXC (PDF)
def pdf_lines(data: bytes) -> List[str]:
    """Text of a PDF, one string per text object — enough for a table of addresses.
    Reads ToUnicode CMaps; stdlib only."""
    objs = {int(m.group(1)): m.group(2)
            for m in re.finditer(rb"(\d+)\s+0\s+obj(.*?)endobj", data, re.S)}

    def stream(body):
        m = re.search(rb"stream\r?\n(.*)\r?\nendstream", body, re.S)
        if not m:
            return b""
        raw = m.group(1)
        return zlib.decompressobj().decompress(raw) if b"/FlateDecode" in body else raw

    def cmap(text):
        mp = {}
        for blk in re.findall(rb"beginbfchar(.*?)endbfchar", text, re.S):
            for a, b in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", blk):
                mp[int(a, 16)] = bytes.fromhex(b.decode()).decode("utf-16-be", "replace")
        for blk in re.findall(rb"beginbfrange(.*?)endbfrange", text, re.S):
            for a, b, c in re.findall(rb"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", blk):
                for i in range(int(b, 16) - int(a, 16) + 1):
                    mp[int(a, 16) + i] = chr(int(c, 16) + i)
        return mp

    fonts = {}
    for n, body in objs.items():
        m = re.search(rb"/ToUnicode\s+(\d+)\s+0\s+R", body)
        if m and b"/Font" in body:
            fonts[n] = (cmap(stream(objs[int(m.group(1))])), 2 if b"/Type0" in body else 1)
    tok = re.compile(rb"/([A-Za-z0-9_.+-]+)\s+[-\d.]+\s+Tf|<([0-9A-Fa-f\s]*)>|(T\*|ET|')")
    out: List[str] = []
    for n in sorted(objs):
        body = objs[n]
        if not re.search(rb"/Type\s*/Page[^s]", body):
            continue
        res = body
        rm = re.search(rb"/Resources\s+(\d+)\s+0\s+R", body)
        if rm:
            res = objs[int(rm.group(1))]
        names = {}
        fd = re.search(rb"/Font\s*<<(.*?)>>", res, re.S)
        if fd:
            names = {k: int(v) for k, v in re.findall(rb"/([A-Za-z0-9_.+-]+)\s+(\d+)\s+0\s+R", fd.group(1))}
        cs = re.search(rb"/Contents\s*(\[[^\]]*\]|\d+\s+0\s+R)", body)
        refs = [int(x) for x in re.findall(rb"(\d+)\s+0\s+R", cs.group(1))] if cs else []
        content = b"\n".join(stream(objs[r]) for r in refs if r in objs)
        cur, line = None, []
        for m in tok.finditer(content):
            if m.group(1):
                cur = fonts.get(names.get(m.group(1)))
            elif m.group(2) is not None and cur:
                h, w = re.sub(rb"\s", b"", m.group(2)), cur[1] * 2
                line.append("".join(cur[0].get(int(h[i:i + w], 16), "") for i in range(0, len(h), w)))
            elif m.group(3) and line:
                out.append("".join(line).strip())
                line = []
    return [l for l in out if l]


MEXC_NET = {"bitcoin": "btc", "ethereum": "eth", "bsc": "bsc", "arbitrum": "arbitrum", "base": "base",
            "optimism": "optimism", "polygon": "polygon", "solana": "sol", "tron": "tron", "ton": "ton"}
LIGATURES = {"ﬀ": "ff", "ﬁ": "fi", "ﬂ": "fl", "ﬃ": "ffi", "ﬄ": "ffl"}


def readings(text: str) -> List[str]:
    """A ligature glyph in extracted text either stands for its letters or repeats
    the letters printed before it; every reading, for the validator to choose from."""
    segs, ligs = [""], []
    for ch in text:
        if ch in LIGATURES:
            ligs.append(ch)
            segs.append("")
        else:
            segs[-1] += ch
    out = []
    for pick in itertools.product((False, True), repeat=len(ligs)):
        out.append(segs[0] + "".join((LIGATURES[l] if p else "") + s
                                     for p, l, s in zip(pick, ligs, segs[1:])))
    return list(dict.fromkeys(out))


HACKEN_PAGES = {"MEXC": "mexc.com/proof-of-reserve/audit-report",
                "Bybit": "bybit.com/en/app/user/audit-report"}


def hacken(lines: List[str], exchange: str, snapshot: str, report: str) -> List[dict]:
    """Entries from the "Verified wallets" table of a Hacken proof-of-reserves audit:
    Network, then Address (an address may wrap onto the next line). An address
    counts only if exactly one reading passes its chain's validator — nothing is
    completed or guessed. An EVM address listed for several networks is one label
    naming them all."""
    start = next(i for i in range(len(lines) - 1)
                 if lines[i] == "Network" and lines[i + 1] == "Address")
    src = (f"{exchange} proof-of-reserves audit by Hacken, 'Verified wallets' table (ownership proven by a "
           f"test transaction from each address); {report}, listed at "
           f"{HACKEN_PAGES[exchange]}; snapshot {snapshot}")
    found: Dict[tuple, dict] = {}
    skipped = []
    i = start
    while i < len(lines) - 1:
        chain = MEXC_NET.get(lines[i].strip().lower())
        if not chain:
            i += 1
            continue
        cand = [lines[i + 1].strip(), lines[i + 1].strip() + (lines[i + 2].strip() if i + 2 < len(lines) else "")]
        good = list(dict.fromkeys(v for c in cand for v in readings(c) if addresses.validate(v, chain)[0]))
        if len(good) == 1:
            evm = chain in EVM_NAMES
            k = (good[0].lower(), None) if evm else (good[0], chain)
            f = found.setdefault(k, {"address": good[0], "chain": chain, "nets": []})
            if evm and EVM_NAMES[chain] not in f["nets"]:
                f["nets"].append(EVM_NAMES[chain])
        else:
            skipped.append((chain, cand[0], len(good)))
        i += 2
    for s in skipped:
        print(f"  {exchange}: skipped {s[0]} {s[1]!r} ({s[2]} valid readings)", file=sys.stderr)
    out = []
    for f in found.values():
        listed = (f"; listed for {', '.join(n for n in EVM_NAMES.values() if n in f['nets'])}"
                  if f["nets"] else "")
        out.append(entry(f["address"], f["chain"], f"{exchange} reserve wallet", src + listed))
    return out


def mexc(lines: List[str], snapshot: str, report: str) -> List[dict]:
    return hacken(lines, "MEXC", snapshot, report)


def bybit(lines: List[str], snapshot: str, report: str) -> List[dict]:
    return hacken(lines, "Bybit", snapshot, report)


def report_date(name: str) -> str:
    """Snapshot date from a report's file name: ..._20261009.pdf or ..._2026_Sep_23.pdf."""
    m = re.search(r"(20\d{2})(\d{2})(\d{2})", name)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    m = re.search(r"(20\d{2})_([A-Za-z]{3})_(\d{1,2})", name)
    if m:
        return dt.datetime.strptime(f"{m.group(1)} {m.group(2)} {m.group(3)}", "%Y %b %d").date().isoformat()
    return "(date not given)"


# ------------------------------------------------------------------ diff + apply
def _key(k: str) -> str:
    return k.lower() if k.startswith("0x") else k


def diff(known: Dict[str, dict], family: str, listed: List[dict]):
    """(new entries, keys of this family's labels that the list no longer has,
    entries renewing a label taken from the exchange's older list)."""
    marker, legacy = FAMILIES[family], LEGACY.get(family)
    have = {_key(k): v for k, v in known.items()}
    new = [e for e in listed if _key(e["key"]) not in have]
    by_key = {_key(e["key"]): e for e in listed}
    renew = [by_key[k] for k, v in have.items() if legacy and legacy in (v.get("source") or "") and k in by_key]
    gone = [k for k, v in have.items()
            if (marker in (v.get("source") or "") or (legacy and legacy in (v.get("source") or "")))
            and k not in by_key and RETIRED not in (v.get("source") or "")]
    return new, gone, renew


def _replace(lines: List[str], key: str, edit) -> None:
    i = next(n for n, l in enumerate(lines) if l.startswith(f"  {json.dumps(key)}:"))
    k, _, rest = lines[i].partition(": ")
    comma = rest.endswith(",")
    lines[i] = f"{k}: {json.dumps(edit(json.loads(rest.rstrip(','))), ensure_ascii=False)}" + ("," if comma else "")


def apply(text: str, family: str, new: List[dict], gone: List[str], today: str, latest: str,
          renew: List[dict] = ()) -> str:
    """known.json text with new entries placed after the family's last label, the
    gone ones marked, and labels from an older list renewed from the current one.
    Edits lines in place so the file's grouping and order survive."""
    lines = text.replace("\r\n", "\n").split("\n")
    marker = FAMILIES[family]
    for e in renew:                   # same wallet, current list: its name and source, its old date
        _replace(lines, e["key"], lambda v, e=e: {
            "name": e["name"], "type": "exchange", **({"chain": e["chain"]} if e["chain"] else {}),
            "source": e["source"], "source_kind": "self-published", "added": v.get("added", today)})
    for k in gone:
        i = next(n for n, l in enumerate(lines) if l.startswith(f"  {json.dumps(k)}:"))
        key, _, rest = lines[i].partition(": ")
        comma = rest.endswith(",")
        v = json.loads(rest.rstrip(","))
        v["source"] += f"; not in the {latest} list, so {RETIRED}"
        lines[i] = f"{key}: {json.dumps(v, ensure_ascii=False)}" + ("," if comma else "")
    if new:
        add = []
        for e in new:
            v = {"name": e["name"], "type": "exchange"}
            if e["chain"]:
                v["chain"] = e["chain"]
            v.update(source=e["source"], source_kind="self-published", added=today)
            add.append(f"  {json.dumps(e['key'])}: {json.dumps(v, ensure_ascii=False)},")
        at = max((n for n, l in enumerate(lines) if marker in l), default=None)
        if at is None:                       # first labels of this exchange: a new group at the end
            close = max(n for n, l in enumerate(lines) if l.strip() == "}")
            if not lines[close - 1].rstrip().endswith(","):
                lines[close - 1] += ","
            add[-1] = add[-1].rstrip(",")
            lines[close:close] = [""] + add
        else:
            if not lines[at].rstrip().endswith(","):         # it was the file's last entry
                lines[at] += ","
                add[-1] = add[-1].rstrip(",")
            lines[at + 1:at + 1] = add
    out = "\n".join(lines)
    json.loads(out)                                          # still valid JSON
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("exchanges", nargs="*", choices=["binance", "htx"], help="lists to fetch")
    ap.add_argument("--mexc", metavar="PDF", help="MEXC's Hacken PoR audit PDF, downloaded")
    ap.add_argument("--bybit", metavar="PDF", help="Bybit's Hacken PoR audit PDF, downloaded")
    ap.add_argument("--write", action="store_true", help="apply the changes to known.json")
    args = ap.parse_args()
    today = dt.date.today().isoformat()
    text = KNOWN.read_text(encoding="utf-8").replace("\r\n", "\n")
    jobs = []
    for ex in args.exchanges:
        jobs.append((ex, fetch_binance(today) if ex == "binance" else fetch_htx(),
                     today if ex == "binance" else None))
    for family, pdf, read in (("mexc", args.mexc, mexc), ("bybit", args.bybit, bybit)):
        if pdf:
            name = Path(pdf).name
            snap = report_date(name)
            jobs.append((family, read(pdf_lines(Path(pdf).read_bytes()), snap, name), snap))
    for family, listed, latest in jobs:
        if family == "htx":
            latest = re.search(r"snapshot (\S+) on", listed[0]["source"]).group(1) if listed else today
        new, gone, renew = diff(json.loads(text), family, listed)
        print(f"{family}: {len(listed)} listed, {len(new)} new, {len(gone)} no longer listed"
              + (f", {len(renew)} renewed from the older list" if renew else ""))
        for e in new:
            print(f"  + {e['chain'] or 'evm':8} {e['key']}  {e['name']}")
        for e in renew:
            print(f"  = {e['chain'] or 'evm':8} {e['key']}  {e['name']}")
        for k in gone:
            print(f"  - {k}")
        if args.write:
            text = apply(text, family, new, gone, today, latest, renew)
    if args.write:
        with open(KNOWN, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        print("known.json updated — run `crypttrace labels audit` and selftest.py, then review the diff")
    return 0


if __name__ == "__main__":
    sys.exit(main())
