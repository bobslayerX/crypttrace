"""Self-test for the work added in this session.

Run it with:  python selftest.py

It uses synthetic data shaped like the Coldcard sweep, so nothing here touches
the network or your API keys. Every check prints what it expected and what it
got, and the script exits non-zero if anything fails — so a green run means the
new code actually behaves as described, not just that it imports.
"""
import sys
import tempfile
import os
from datetime import datetime, timezone

os.environ.setdefault("CRYPTTRACE_HOME", tempfile.mkdtemp(prefix="crypttrace-selftest-"))

FAILED = []
PASSED = []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append(name)
        print(f"  FAIL  {name}   {detail}")


def section(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


# ---------------------------------------------------------------- imports
section("1. Does everything import?")
try:
    from crypttrace import addresses, assess, chains, store, verify
    from crypttrace.labels import labels, audit
    from crypttrace.fetchers import bitcoin
    import crypttrace.cli  # noqa: F401
    check("all modules import", True)
    # explorer-tag sources reach the network (and use a key if one is set): not in a selftest
    from crypttrace.labels import tonapi as _tonapi, tronscan as _tronscan
    _tonapi.enrich = _tronscan.enrich = lambda addrs: None
except Exception as e:  # pragma: no cover
    print(f"  FAIL  import error: {type(e).__name__}: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)


# ---------------------------------------------------------------- addresses
section("2. Address validation (checksums, no network)")

ok, why = addresses.validate("bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "btc")
check("real bech32 address accepted", ok, why)

ok, why = addresses.validate("bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9X", "btc")
check("bech32 with one character changed is rejected", not ok, why)

ok, why = addresses.validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "btc")
check("legacy base58 address accepted", ok, why)

ok, why = addresses.validate("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", "btc")
check("legacy address with bad checksum rejected", not ok, why)

ok, why = addresses.validate("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "tron")
check("Tron USDT contract accepted", ok, why)

ok, why = addresses.validate("0x2f2974fAbc54dbA33442261211c06BD20E0FEefc", "eth")
check("EVM address accepted", ok, why)

ok, _ = addresses.validate("bc1qq85v2c926eg6pgxhwp6q7lf6cnsz80qs3fcu9r", "eth")
check("Bitcoin address rejected on the eth chain", not ok)

check("transaction id recognised as not-an-address",
      addresses.looks_like_txid(
          "4b277ba298830ea538086114803b9487558bb093b5083e383e94db687fbe9090"))


# ---------------------------------------------------------------- labels
section("3. Label database: validity and evidence")
a = audit.audit()
print(f"        entries: {a['total']}, well-formed: {a['valid']}, "
      f"with a source: {a['total']-len(a['unsourced'])}")
check("every stored address passes its checksum", not a["problems"],
      str(a["problems"][:3]))
check("at least some labels carry a source", len(a["unsourced"]) < a["total"])

e = audit.evidence("bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0")
check("evidence is retrievable for a labelled address", e["known"] and bool(e["source"]),
      str(e))
print(f"        source: {e.get('source','')[:80]}")

e2 = audit.evidence("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
check("unlabelled address makes no claim", not e2["known"])

# exchange labels on the non-EVM chains, from Binance's own reserve list
for addr, chain in [("34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo", "btc"),
                    ("TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9", "tron"),
                    ("38xCLm9kSExfGU1GdyVuX4vop7SZns9kU2mQyTmmMdUP", "sol")]:
    check(f"{chain} exchange wallet is labelled", labels.type_of(addr) == "exchange",
          labels.label_of(addr) or "no label")
# a Solana key starting with '3' looks like a Bitcoin address by prefix alone
check("Solana label starting with '3' survives loading",
      labels.label_of("3JR4ETCTVqnysiARm9LvuigzuXnDydbWXYYYpgZzzhDi") != "")
# ...and from the lists OKX, HTX and Bybit publish themselves
for addr, who in [("1CY7fykRLWXeSbKB885Kr4KjQxmDdvW923", "OKX"),
                  ("C68a6RCGLiPskbPYtAcsCjhG8tfTWYcoB4JjCrXFdqyo", "OKX"),
                  ("TCw6YaWm3y6DvxY7M8hrCDnrJGeGMumzGJ", "OKX"),
                  ("143gLvWYUojXaWZRrxquRKpVNTkhmr415B", "HTX"),
                  ("8NBEbxLknGv5aRYefFrW2qFXoDZyi9fSHJNiJRvEcMBE", "HTX"),
                  ("TQVxjVy2sYt4at45ezD7VG4H6nQZtsua5C", "Bybit")]:
    check(f"{who} wallet {addr[:8]}… is labelled as an exchange",
          labels.type_of(addr) == "exchange" and labels.label_of(addr).startswith(who),
          labels.label_of(addr) or "no label")

# victims are told which company to contact, not our wallet label
names = {l: labels.company(l) for l in ("Binance reserve wallet (custodied by Ceffu)",
                                       "OKX reserve wallet", "Bybit (2022 reserve list)",
                                       "Binance 14 (hot wallet)")}
check("exchange labels reduce to the company name",
      list(names.values()) == ["Binance", "OKX", "Bybit", "Binance"], str(names))

e3 = audit.evidence("TMuA6YqfCeX8EhbfYEg5y7S4DqzSJireY9".lower())
check("evidence found for a case-sensitive address given in lower case",
      e3["known"] and e3["source_kind"] == "self-published", str(e3)[:160])


# ---------------------------------------------------------------- store
section("4. Local store: caching, dedup, offline")

CALLS = {"n": 0}
COLLECTOR = "bc1qnk4zh9qcnap2mycp56qjrgza3cc8ylrh8fecp0"
T0 = int(datetime(2026, 7, 30, 1, 36, tzinfo=timezone.utc).timestamp())

VICTIMS = []
for i in range(60):
    # round amounts minus a constant 0.000033 — the Coldcard fingerprint
    base = [1.0, 0.5, 0.15, 0.2, 2.0][i % 5]
    VICTIMS.append({"from": f"bc1qvictim{i:034d}", "to": COLLECTOR,
                    "value": round(base - 0.000033, 8), "timestamp": T0 + (i * 13),
                    "hash": f"sweep{i}", "symbol": "BTC"})

def fake_transfers(addr, limit=1000):
    CALLS["n"] += 1
    return VICTIMS if addr == COLLECTOR else []

bitcoin.transfers = fake_transfers
bitcoin.stats = lambda a: {"received": sum(v["value"] for v in VICTIMS), "sent": 0.0,
                           "balance": sum(v["value"] for v in VICTIMS),
                           "tx_count": len(VICTIMS), "funded_outputs": len(VICTIMS)}
bitcoin.balance = lambda a: bitcoin.stats(a)["balance"]

store.clear()
chains.FORCE_FRESH = False
chains.OFFLINE = False

r1 = chains.transfers(COLLECTOR, "btc")
n1 = CALLS["n"]
check("first call fetches and returns data", len(r1) == 60 and n1 == 1,
      f"rows={len(r1)} calls={n1}")

r2 = chains.transfers(COLLECTOR, "btc")
check("second call served from the store, no fetch", CALLS["n"] == n1,
      f"calls went from {n1} to {CALLS['n']}")
check("stored data matches what was fetched", len(r2) == len(r1))

before = store.stats()["transfers"]
chains.transfers(COLLECTOR, "btc", fresh=True)
after = store.stats()["transfers"]
check("re-fetching the same data creates no duplicates", before == after,
      f"{before} -> {after}")

chains.OFFLINE = True
def dead(*a, **k):
    raise bitcoin.BitcoinError("network is unavailable")
bitcoin.transfers = dead
r3 = chains.transfers(COLLECTOR, "btc")
check("analysis still works with the network down", len(r3) == 60, f"rows={len(r3)}")
chains.OFFLINE = False
bitcoin.transfers = fake_transfers

src = store.sources_of("btc", [COLLECTOR])
check("cross-address query returns every funder", len(src) == 60, f"got {len(src)}")


# ---------------------------------------------------------------- verify
section("5. Verification against the chain")
v = verify.reconcile(COLLECTOR, "btc")
print(f"        status: {v['status']} — {verify.headline(v)}")
check("totals reconcile with the chain", v["status"] in ("verified", "partial"),
      str(v.get("notes")))

bitcoin.stats = lambda a: {"received": 0.77, "sent": 0.0, "balance": 0.77,
                           "tx_count": len(VICTIMS), "funded_outputs": len(VICTIMS)}
vbad = verify.reconcile(COLLECTOR, "btc")
print(f"        with wrong chain totals: {vbad['status']}")
check("a discrepancy is caught, not smoothed over", vbad["status"] == "mismatch",
      str(vbad.get("notes")))
bitcoin.stats = lambda a: {"received": sum(v2["value"] for v2 in VICTIMS), "sent": 0.0,
                           "balance": sum(v2["value"] for v2 in VICTIMS),
                           "tx_count": len(VICTIMS), "funded_outputs": len(VICTIMS)}


# ---------------------------------------------------------------- assess
section("6. Assessment: does it reach the right conclusion?")

fee = assess.constant_fee_signature([v2["value"] for v2 in VICTIMS])
print(f"        constant-fee detector: {fee}")
check("the hardcoded fee is detected automatically", fee is not None and
      abs(fee["fee"] - 0.000033) < 1e-9, str(fee))

normal = [0.37182, 1.90211, 0.04417, 12.5502, 3.11119, 0.88321, 5.4409, 0.20177]
check("ordinary amounts do not trigger it",
      assess.constant_fee_signature(normal) is None)

# 78 sweeps in one batch plus one later transfer — shaped like collector C2.
# The window used to report 80% of the total (63) instead of what it held.
from crypttrace import analysis
batch = [T0] * 78 + [T0 + 1860]
w = analysis.tightest_window(batch)
check("burst window counts every transfer inside it", w and w[1] == 78, str(w))
verdict = analysis.describe_burst(w, len(batch))
check("a batch that is not everything is not called 'all'",
      verdict.startswith("78 of 79"), verdict)
check("the assessment's burst agrees with the timeline's",
      assess.burst(batch) == w, f"{assess.burst(batch)} vs {w}")

a = assess.assess(COLLECTOR, "btc")
print("\n        ASSESSMENT:")
for line in a["assessment"].split(". "):
    if line.strip():
        print(f"          {line.strip()}.")
print(f"\n        risk {a['risk']}/100, confidence {a['confidence']}")
print(f"        signals: {[s['name'] for s in a['signals']]}")

names = {s["name"] for s in a["signals"]}
check("automation is reported as a signal",
      "automated collection" in names or "burst of activity" in names, str(names))
check("holding behaviour is noticed", "funds held" in names, str(names))
check("every signal carries evidence",
      all(s["evidence"] for s in a["signals"]))
check("a conclusion is stated in words", len(a["assessment"]) > 80)

# ---------------------------------------------------------------- web
section("7. Web layer: the same conclusions through HTTP")
try:
    from crypttrace import webapp
    client = webapp.create_app().test_client()

    r = client.get("/")
    check("the page is served", r.status_code == 200)
    check("the page is never cached", "no-store" in r.headers.get("Cache-Control", ""))

    body = r.data.decode("utf-8")
    check("the Assessment tab exists in the UI", 'data-view="assess"' in body)

    r = client.get(f"/api/assess?address={COLLECTOR}&chain=btc")
    j = r.get_json()
    check("assessment endpoint answers", r.status_code == 200 and "assessment" in j,
          str(j)[:160])
    if r.status_code == 200:
        print(f"        risk {j['risk']}/100, confidence {j['confidence']}, "
              f"{len(j['signals'])} signal(s)")
        check("the web assessment carries its signals", len(j["signals"]) > 0)

    r = client.get(f"/api/evidence?address={COLLECTOR}")
    j = r.get_json()
    check("evidence endpoint explains a label", j.get("known") and bool(j.get("source")),
          str(j)[:160])

    r = client.get(f"/api/verify?address={COLLECTOR}&chain=btc")
    check("verification endpoint answers", r.status_code == 200 and
          "status" in r.get_json())

    r = client.get("/api/assess?address=nonsense&chain=btc")
    check("bad input is refused in JSON, not an HTML crash page",
          r.status_code == 400 and "error" in r.get_json())
except ImportError:
    print("  SKIP  Flask is not installed — run: pip install -e \".[web]\"")

store.clear()

# ---------------------------------------------------------------- cli output
section("8. CLI output when stdout is not a UTF-8 console")
# Redirected output on Windows uses the ANSI code page (cp1251 on a Russian
# system); an arrow or emoji used to crash the command outright.
import subprocess
env = dict(os.environ, PYTHONIOENCODING="cp1251")
run = subprocess.run(
    [sys.executable, "-c", "from crypttrace.cli import app; app()",
     "label", "0x28c6c06298d514db089934071355e5743bf21d60"],
    capture_output=True, env=env, timeout=120)
out = run.stdout.decode("utf-8", "replace")
check("labelled output survives a cp1251 stdout", run.returncode == 0 and "Binance" in out,
      (run.stderr.decode("utf-8", "replace") or out)[-200:])

# ---------------------------------------------------------------- off-ramp
section("9. Off-ramp detection off Ethereum")
# It used to read Etherscan directly, so on Bitcoin/Tron/Solana it raised
# "unsupported chain" and took `crypttrace trace` down with it.
from crypttrace import offramp
DEPOSIT = "TM1zzNDZD2DPASbKcgdVoTYhfmYgtfwx9R"      # an OKX deposit address
OKX_HOT = "TXkCx2gaEWrtU3g88aYxrqHxeWYXX5UUtL"      # an OKX reserve wallet
real_transfers = chains.transfers

def tron_sweeps(addr, chain="eth", limit=1000, asset=None, **kw):
    if chain == "tron" and addr == DEPOSIT and asset and asset.get("symbol") == "USDT":
        return [{"from": DEPOSIT, "to": OKX_HOT, "value": 5000.0, "timestamp": T0, "hash": "s1"},
                {"from": DEPOSIT, "to": OKX_HOT, "value": 1200.0, "timestamp": T0 + 60, "hash": "s2"}]
    return []

chains.transfers = tron_sweeps
try:
    try:
        hit = offramp.detect(DEPOSIT, "tron")
    except Exception as e:
        hit = {"exchange": "", "symbol": "", "error": repr(e)}
    check("a Tron address sweeping USDT into OKX is an off-ramp",
          bool(hit) and hit.get("company") == "OKX" and hit["symbol"] == "USDT", str(hit))
    chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: [
        {"from": OKX_HOT, "to": "TCw6YaWm3y6DvxY7M8hrCDnrJGeGMumzGJ", "value": 1.0, "timestamp": T0, "hash": "i"}] \
        if addr == OKX_HOT else []
    check("an exchange's own wallet is never called a deposit address",
          offramp.detect(OKX_HOT, "tron") is None)
    chains.transfers = tron_sweeps
    try:
        offramp.detect("bc1qh0l7q0mca3ln7wsl9luwns0jc9jhgrtft025l4", "btc")
        check("off-ramp check runs on Bitcoin instead of raising", True)
    except Exception as e:
        check("off-ramp check runs on Bitcoin instead of raising", False, repr(e))
    try:
        from crypttrace import webapp
        j = webapp.create_app().test_client().get(
            f"/api/offramp?address={DEPOSIT}&chain=tron").get_json()
        check("the web UI gets the Tron off-ramp too",
              bool(j.get("offramp")) and j["offramp"]["exchange"].startswith("OKX"), str(j)[:160])
    except ImportError:
        print("  SKIP  Flask is not installed")
finally:
    chains.transfers = real_transfers

# ---------------------------------------------------------------- bulk sets
section("10. OKX's signed address list (update-labels --okx)")
# A miniature of OKX's real file: totals, a blank line, then one row per
# address with its network and signature. Nothing is downloaded.
import zipfile
from crypttrace.labels import bulk
OKX_BTC = "bc1q005s059684s5m8hdq7u7hahq9hje5yy34y2m3uwzz5lh7p5ucl9q0ntn93"
okx_csv = "\n".join([
    "coin,amount", "BTC,146359", "",
    "coin,Type,Network,Snapshot Height,address,amount,message,signature1,signature2,"
    "redeem script/ public key,EOA1,EOA2",
    f"USDT-TRC20,Non Staking,TRON,85840149,{DEPOSIT},10,I am an OKX address,SIG,,,,",
    f"TRX,Non Staking,TRON,85840149,{OKX_HOT},500000000,I am an OKX address,SIG,,,,",
    f"BTC,Non Staking,BTC,965949,{OKX_BTC},0.5,I am an OKX address,SIG,,,,",
    "ETH,Native Staking,ETH,25876316,0x" + "ab" * 48 + ",32,I am an OKX address,SIG,,,,",
    "BTC,Non Staking,BTC,965949,1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb,1,I am an OKX address,SIG,,,,",
    "TRX,Non Staking,TRON,85840149,TL9szsuUPSBv6DUfqC64J88gaN7s26QJwq,1,I am an OKX address,,,,,",
]) + "\n"
okx_zip = os.path.join(os.environ["CRYPTTRACE_HOME"], "okx_por_test.zip")
with zipfile.ZipFile(okx_zip, "w") as z:
    z.writestr("okx_por_2026090800_V1.csv", okx_csv)

messages = []
n, snap = bulk.import_okx(okx_zip, progress=messages.append)
check("signed, well-formed addresses are stored; keys and bad checksums are not",
      n == 3, f"stored {n}; {messages}")
check("the snapshot date is read from the file", snap == "2026-09-08", snap)
check("staking validator keys are reported as such, not as malformed",
      any("1 ETH staking validator keys" in m and "1 malformed" in m for m in messages),
      str(messages))
check("an OKX deposit address is labelled on arrival, without the heuristic",
      labels.type_of(DEPOSIT) == "exchange" and labels.is_deposit(DEPOSIT)
      and labels.company(labels.label_of(DEPOSIT)) == "OKX", str(labels.lookup(DEPOSIT)))
check("curated labels still win over the downloaded set",
      labels.label_of(OKX_HOT) == "OKX reserve wallet", labels.label_of(OKX_HOT))
check("an unsigned row is not trusted",
      labels.lookup("TL9szsuUPSBv6DUfqC64J88gaN7s26QJwq") is None)
ev = audit.evidence(OKX_BTC)
check("labels why explains a downloaded label",
      ev["known"] and ev["source_kind"] == "self-published" and "OKX" in ev["source"], str(ev)[:160])

# Paying *into* someone's deposit address makes this wallet a depositor, not a
# deposit address; only exchange-owned wallets count as the off-ramp target.
THIEF = "TPayerPayerPayerPayerPayerPayer111"          # synthetic
def thief_pays_in(addr, chain="eth", limit=1000, asset=None, **kw):
    if chain == "tron" and addr == THIEF and asset is None:
        return [{"from": THIEF, "to": DEPOSIT, "value": 9000.0, "timestamp": T0, "hash": "t1"}]
    return []
chains.transfers = thief_pays_in
try:
    check("a wallet paying into a deposit address is not called a deposit address",
          offramp.detect(THIEF, "tron") is None)
finally:
    chains.transfers = real_transfers

# ---------------------------------------------------------------- poisoning
section("11. Address poisoning")
from crypttrace import poisoning
from crypttrace.fetchers import tron as tron_fetch

USDT_ETH = "0xdac17f958d2ee523a2206206994597c13d831ec7"
VICTIM = "0x" + "9" * 40
GENUINE = "0x1234" + "a" * 32 + "5678"
LOOKALIKE = "0x1234" + "b" * 32 + "5678"          # same first 4 and last 4
t_paid, t_bait, t_loss = T0, T0 + 600, T0 + 3600

def usdt(frm, to, v, ts, contract=USDT_ETH):
    return {"from": frm, "to": to, "value": v, "timestamp": ts, "hash": f"{frm[-4:]}{ts}",
            "symbol": "USDT", "contract": contract}

EVM_ROWS = [usdt(VICTIM, GENUINE, 1000.0, t_paid),
            usdt(VICTIM, LOOKALIKE, 0.0, t_bait),        # transferFrom(victim, look-alike, 0)
            usdt(VICTIM, LOOKALIKE, 5000.0, t_loss)]     # the copy-paste mistake

def evm_history(addr, chain="eth", limit=1000, asset=None, **kw):
    if not asset:
        return []
    return [r for r in EVM_ROWS if addr in (r["from"], r["to"])]

chains.transfers = evm_history
try:
    pairs = poisoning.lookalikes(VICTIM, "eth")
    check("victim side: the look-alike and the money sent to it are found",
          len(pairs) == 1 and pairs[0]["lookalike"] == LOOKALIKE
          and pairs[0]["genuine"] == GENUINE and pairs[0]["sent_to_lookalike"] == 5000.0,
          str(pairs)[:200])
    lured = poisoning.baited_payments(LOOKALIKE, "eth")
    check("attacker side: the victim's payment is traced to the zero-value bait",
          len(lured) == 1 and lured[0]["payer"] == VICTIM and lured[0]["imitates"] == GENUINE,
          str(lured)[:200])
    try:
        from crypttrace import webapp as _web
        j = _web.create_app().test_client().get(
            f"/api/poisoning?address={VICTIM}&chain=eth").get_json()
        check("the web UI's Poisoning tab gets the same look-alike",
              [p["lookalike"] for p in j.get("lookalikes", [])] == [LOOKALIKE], str(j)[:160])
    except ImportError:
        print("  SKIP  Flask is not installed")
    check("a counterfeit USDT is bait whatever its amount",
          poisoning._is_bait(usdt(LOOKALIKE, VICTIM, 5000.0, T0, contract="0x" + "c" * 40), "eth"))
finally:
    chains.transfers = real_transfers

# Tron: the cheap look-alike (first and last two characters) arrives as TRX dust
TV = "TVictimVictimVictimVictimVictim111"          # synthetic
TG, TL = "TM1zzNDZD2DPASbKcgdVoTYhfmYgtfwx9R", "TMyUjSnEgD6BuAbdyFT71uHgDqyrRgBx9R"
TN = "TMabcdefghijkmnopqrstuvwxyzABCDx9R"           # matches as weakly, but no bait
OPER, FRESH = "TWkvffFDMsqbmTLkMHMABmw452Hyq98cdn", "TDDDHi26zb2NhGRH6gwEa414RAvNrCr9Ps"
def trx(frm, to, v, ts):
    return {"from": frm, "to": to, "value": v, "timestamp": ts, "hash": f"{frm[-3:]}{ts}", "symbol": "TRX"}
TRON_ROWS = [trx(TV, TG, 800.0, T0), trx(TL, TV, 0.000001, T0 + 60), trx(TV, TN, 300.0, T0 + 120),
             trx(OPER, FRESH, 0.0, T0), {**usdt(OPER, FRESH, 1.01, T0 + 30,
                                                "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t")}]
def tron_history(addr, chain="eth", limit=1000, asset=None, **kw):
    rows = [r for r in TRON_ROWS if addr in (r["from"], r["to"])]
    return [r for r in rows if bool(r.get("contract")) == bool(asset)]
chains.transfers = tron_history
try:
    pairs = poisoning.lookalikes(TV, "tron")
    check("a two-character look-alike planted with dust is flagged",
          [(p["genuine"], p["lookalike"], p["resemblance"]) for p in pairs] == [(TG, TL, "weak")],
          str(pairs)[:200])
    check("an operator topping up a fresh address is not a victim's payment",
          poisoning.baited_payments(FRESH, "tron") == [])
    # two OKX wallets: a small top-up, then a large payment back
    OKX_A, OKX_B = "TXkCx2gaEWrtU3g88aYxrqHxeWYXX5UUtL", "TCw6YaWm3y6DvxY7M8hrCDnrJGeGMumzGJ"
    chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: [
        trx(OKX_A, OKX_B, 5.0, T0), trx(OKX_B, OKX_A, 900000.0, T0 + 60)] if asset is None else []
    check("an exchange paying its own wallets is not a lured payment",
          poisoning.baited_payments(OKX_A, "tron") == [])
finally:
    chains.transfers = real_transfers

# TronGrid lists Approval events next to transfers; an allowance is not a payment
real_get = tron_fetch._get
tron_fetch._get = lambda path, params=None, timeout=30: {"data": [
    {"type": "Transfer", "from": OPER, "to": FRESH, "value": "1010000", "block_timestamp": 1000,
     "transaction_id": "a", "token_info": {"symbol": "USDT", "decimals": 6, "address": "TR7NH"}},
    {"type": "Approval", "from": FRESH, "to": OPER, "value": str(2 ** 256 - 1), "block_timestamp": 2000,
     "transaction_id": "b", "token_info": {"symbol": "USDT", "decimals": 6, "address": "TR7NH"}}]}
try:
    got = tron_fetch.token_transfers(FRESH)
    check("Tron approvals are not read as 10^59 USDT transfers",
          len(got) == 1 and got[0]["value"] == 1.01, str(got)[:160])
    # ...and ones already sitting in a store written by an older version are not served
    store.save("tron", FRESH, [{"from": FRESH, "to": OPER, "value": (2 ** 256 - 1) / 1e6,
                                "timestamp": 2, "hash": "old", "symbol": "USDT",
                                "contract": "tr7nh"}], "tr7nh", True)
    served = store.load(chain="tron", address=FRESH, contract="tr7nh")
    check("an approval stored by an older version is not served as a transfer",
          all(r["value"] < 1e30 for r in served), str(served)[:160])
finally:
    tron_fetch._get = real_get

# Solana: a token query must not leak SPL rows into the SOL history. The SPL row
# carries no contract here — the shape stores written by 0.4.0 and earlier hold.
from crypttrace.fetchers import solana as sol_fetch
SA = "5tzFkiKscXHK5ZXCGbXZxdw7gTjjD1mBwuoFbhUvuAi9"
real_sol = sol_fetch.transfers
sol_fetch.transfers = lambda a, limit=1000: [
    {"from": "X" * 43 + "1", "to": SA, "value": 2.0, "timestamp": 1, "hash": "s", "symbol": "SOL"},
    {"from": "Y" * 43 + "1", "to": SA, "value": 5000.0, "timestamp": 2, "hash": "t", "symbol": "SPL"}]
try:
    from crypttrace import assets as assets_mod
    chains.transfers(SA, "sol")                              # SOL history now stored
    chains.transfers(SA, "sol", asset=assets_mod.resolve_asset("usdc", "sol"))
    again = chains.transfers(SA, "sol")                      # served from the store
    check("SOL history stays SOL after a token query", [r["symbol"] for r in again] == ["SOL"],
          str(again))
finally:
    sol_fetch.transfers = real_sol

# ---------------------------------------------------------------- freezes
section("12. Stablecoin freezes (Tether / Circle)")
from crypttrace import freeze
from crypttrace import investigate as inv_mod
real_eth, real_tron, real_sol_accts = freeze._eth_call, freeze._tron_call, freeze._sol_accounts

# what the issuers' contracts answer, keyed by (selector or signature)
freeze._eth_call = lambda contract, sel, addr: {
    ("0xdac17f958d2ee523a2206206994597c13d831ec7", "0xe47d6060"): 1,              # USDT frozen
    ("0xdac17f958d2ee523a2206206994597c13d831ec7", "0x70a08231"): 12_449_010_000,
}.get((contract, sel), 0)
freeze._tron_call = lambda contract, sig, addr: 2_540_102_090_000 \
    if sig == "balanceOf(address)" and contract.startswith("TR7NH") else 0
freeze._sol_accounts = lambda owner, mint: [{"state": "frozen", "amount": 900.0},
                                            {"state": "initialized", "amount": 100.0}] \
    if mint.startswith("EPjF") else []
try:
    eth = {e["token"]: e for e in freeze.check("0x" + "7" * 40, "eth")}
    check("a frozen USDT balance is reported as frozen, with the amount",
          eth["USDT"]["frozen"] and eth["USDT"]["frozen_amount"] == 12449.01
          and eth["USDC"]["frozen"] is False and eth["USDC"]["balance"] == 0, str(eth)[:200])
    trx = {e["token"]: e for e in freeze.check(TG, "tron")}
    check("an unfrozen USDT balance is movable, with who can freeze it",
          trx["USDT"]["frozen"] is False and trx["USDT"]["movable"] == 2540102.09
          and trx["USDT"]["issuer"] == "Tether", str(trx)[:200])
    sol = {e["token"]: e for e in freeze.check(SA, "sol")}
    check("on Solana only the frozen token accounts count as frozen",
          sol["USDC"]["frozen"] and sol["USDC"]["frozen_amount"] == 900.0
          and sol["USDC"]["movable"] == 100.0, str(sol)[:200])
    check("chains without issuer-frozen stablecoins are not checked",
          freeze.check(COLLECTOR, "btc") == [] and freeze.check("0x" + "7" * 40, "bsc") == [])

    base = {"address": TG, "chain": "tron", "exchanges": [], "mixers": [], "sanctioned": [],
            "bridges": [], "findings": []}
    steps = inv_mod.build_guidance({**base, "freeze": trx.values()})["steps"]
    check("investigate puts 'ask for a freeze' first while the money is still there",
          steps[0]["urgent"] and "Ask for a freeze" in steps[0]["title"]
          and "Tether" in steps[0]["body"], steps[0]["title"])
    steps = inv_mod.build_guidance({**base, "freeze": eth.values()})["steps"]
    check("and says so when it is already frozen",
          steps[0]["title"] == "12,449.01 USDT here is frozen by Tether", steps[0]["title"])
    empty = {**eth["USDT"], "frozen_amount": 0.0}
    check("an empty blacklisted address is not described as '0.00 frozen'",
          freeze.describe_frozen(empty).startswith("This address is blacklisted by Tether"),
          freeze.describe_frozen(empty))
    dust = [{**trx["USDT"], "balance": 0.004, "movable": 0.004, "actionable": False}]
    check("dust left at an address does not trigger a freeze request",
          not any("freeze" in s["title"].lower()
                  for s in inv_mod.build_guidance({**base, "freeze": dust})["steps"]))

    def unreachable(*a):
        raise freeze.FreezeError("node down")
    freeze._eth_call = unreachable
    down = freeze.check("0x" + "7" * 40, "eth")
    check("an unreadable freeze is reported as unknown, never as 'not frozen'",
          all(e["frozen"] is None and e["error"] for e in down), str(down)[:160])
finally:
    freeze._eth_call, freeze._tron_call, freeze._sol_accounts = real_eth, real_tron, real_sol_accts

# ---------------------------------------------------------------- reports
section("13. The HTML case file")
import hashlib, re as _re
from crypttrace import report, prices
SUBJ, HOP, BINANCE_COLD = "bc1qsubject" + "0" * 31, "bc1qhop" + "0" * 35, "34xp4vRoCGJym3xR7yCVPFHoCNxv4Twseo"
REPORT_ROWS = [{"from": SUBJ, "to": HOP, "value": 1.5, "timestamp": T0, "hash": "aa" * 32, "symbol": "BTC"},
               {"from": HOP, "to": BINANCE_COLD, "value": 1.4, "timestamp": T0 + 600,
                "hash": "bb" * 32, "symbol": "BTC"}]
def report_history(addr, chain="eth", limit=1000, asset=None, **kw):
    return [] if asset else [r for r in REPORT_ROWS if addr in (r["from"], r["to"])]
real_price = prices.native_price
chains.transfers, prices.native_price = report_history, (lambda c="eth": None)
try:
    out_dir = os.path.join(os.environ["CRYPTTRACE_HOME"], "reports")
    paths = report.generate(SUBJ, "btc", 3, 3, __import__("pathlib").Path(out_dir))
    page = paths["html"].read_text(encoding="utf-8")
    check("report writes an HTML case file on Bitcoin, plus Markdown and JSON",
          all(p.exists() for p in paths.values()), str(paths))
    check("the case file loads nothing from outside and runs no script",
          not _re.search(r"<(script|link|img)[^>]+(src|href)=[\"']https?://", page)
          and not _re.search(r"<script(?![^>]*application/json)", page))
    check("the graph and the transaction links are in it",
          page.count("<rect") == 3 and "mempool.space/tx/" + "bb" * 32 in page
          and "Binance" in page, f"{page.count('<rect')} boxes")
    digest = _re.search(r"SHA-256 of the JSON: <span class='mono'>([0-9a-f]{64})", page).group(1)
    check("the SHA-256 printed in the page is the JSON file's",
          hashlib.sha256(paths["json"].read_bytes()).hexdigest() == digest)

    import json as _json
    data = _json.loads(paths["json"].read_text(encoding="utf-8"))
    data["summary"]["label"] = "<img src=x onerror=alert(1)>"
    data["key_findings"][0]["label"] = "</script><script>alert(2)</script>"
    raw = _json.dumps(data)
    hostile = report.render_html(data, raw, "0" * 64, "x.json")
    check("labels and token names cannot inject markup into the case file",
          "<img src=x" not in hostile and "&lt;img src=x" in hostile)
    check("data embedded for analysts cannot close its script element",
          "</script><script>alert(2)" not in hostile)
    try:
        from crypttrace import webapp as _web
        resp = _web.create_app().test_client().get(f"/api/report?address={SUBJ}&chain=btc&depth=3")
        check("the web UI hands over the same case file as a download",
              resp.status_code == 200 and resp.mimetype == "text/html"
              and "attachment" in resp.headers.get("Content-Disposition", "")
              and resp.get_data(as_text=True).count("<rect") == 3,
              f"{resp.status_code} {resp.headers.get('Content-Disposition')}")
    except ImportError:
        print("  SKIP  Flask is not installed")
finally:
    chains.transfers, prices.native_price = real_transfers, real_price

# ---------------------------------------------------------------- Tron paging
section("15. Tron history beyond one page; look-alikes that copy only the ending")
pages = {"n": 0}
def paged(path, params=None, timeout=30):
    pages["n"] += 1
    start = int((params or {}).get("fingerprint") or 0)
    size = 200 if start < 400 else 70                 # the third page is the last, short one
    data = [{"type": "Transfer", "from": OPER, "to": FRESH, "value": "1000000",
             "block_timestamp": (10_000 - start - i) * 1000, "transaction_id": f"p{start + i}",
             "token_info": {"symbol": "USDT", "decimals": 6, "address": "TR7NH"}}
            for i in range(size)]
    return {"data": data, "meta": {"fingerprint": str(start + size)}}
real_get = tron_fetch._get
tron_fetch._get = paged
try:
    got = tron_fetch.token_transfers(FRESH, 1000)
    check("Tron history is read page by page, not just the newest 200",
          len(got) == 470 and pages["n"] == 3 and len({r["hash"] for r in got}) == 470,
          f"{len(got)} rows in {pages['n']} requests")
    pages["n"] = 0
    check("paging stops at the limit asked for",
          len(tron_fetch.token_transfers(FRESH, 300)) == 300 and pages["n"] == 2)
finally:
    tron_fetch._get = real_get

# the third victim of the documented campaign: only the last six characters matched
REAL, TAIL_FAKE = "TFnRntZX6WYTrcWhatJJ7EgMXoNcE1doqb", "TAuaRAcfefpiwgrFAYNy7otjZytVE1doqb"
check("a look-alike copying only the last six characters is strong",
      poisoning.resemblance(REAL, TAIL_FAKE, "tron") == "strong")
check("five shared final characters alone are not",
      poisoning.resemblance(REAL, "TQ" + "z" * 26 + "Z1doqb", "tron") is None)   # shares "1doqb"

# Solana: an SPL transfer names token accounts; the wallets behind them and the
# mint come from the transaction's token balances
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
OWNER_A, OWNER_B = "WalletAWalletAWalletAWalletAWalletA11111111", "WalletBWalletBWalletBWalletBWalletB11111111"
ACC_A, ACC_B = "TokenAccAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "TokenAccBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
fake_tx = {"blockTime": 1700000000, "meta": {
    "innerInstructions": [],
    "postTokenBalances": [
        {"accountIndex": 1, "owner": OWNER_A, "mint": USDC_MINT, "uiTokenAmount": {"decimals": 6}},
        {"accountIndex": 2, "owner": OWNER_B, "mint": USDC_MINT, "uiTokenAmount": {"decimals": 6}}]},
    "transaction": {"message": {"accountKeys": [{"pubkey": OWNER_A}, {"pubkey": ACC_A}, {"pubkey": ACC_B}],
        "instructions": [
            {"program": "spl-token", "parsed": {"type": "transfer", "info": {
                "source": ACC_A, "destination": ACC_B, "authority": OWNER_A, "amount": "25000000"}}},
            {"program": "spl-token", "parsed": {"type": "transferChecked", "info": {
                "source": ACC_A, "destination": ACC_B, "authority": OWNER_A, "mint": USDC_MINT,
                "tokenAmount": {"uiAmountString": "1.5", "decimals": 6}}}}]}}}
real_rpc = sol_fetch._rpc
sol_fetch._rpc = lambda method, params, timeout=30: fake_tx
try:
    parsed = sol_fetch._parse_tx("sig1")
    check("SPL transfers are between wallets, not token accounts",
          all(r["from"] == OWNER_A and r["to"] == OWNER_B for r in parsed), str(parsed)[:200])
    check("each SPL transfer carries its mint and symbol",
          all(r["contract"] == USDC_MINT and r["symbol"] == "USDC" for r in parsed))
    check("a plain SPL 'transfer' is scaled by the mint's decimals",
          [r["value"] for r in parsed] == [25.0, 1.5], str([r["value"] for r in parsed]))
finally:
    sol_fetch._rpc = real_rpc

# ---------------------------------------------------------------- TON
section("16. TON: addresses, toncenter, labels, poisoning; fresh reads")
from crypttrace.fetchers import ton as ton_fetch, http as http_mod
BN_UQ = "UQD4uGNdB4a3f52mYOZf0x1nCmdd1DAvrLppL0a1cetTYCQx"      # Binance, self-published
BN_RAW = "0:F8B8635D0786B77F9DA660E65FD31D670A675DD4302FACBA692F46B571EB5360"
BN_EQ = addresses.ton_friendly(BN_RAW, bounceable=True)
check("the three spellings of a TON account are one address",
      addresses.ton_friendly(BN_RAW) == addresses.ton_friendly(BN_EQ) == BN_UQ
      and chains.norm_addr(BN_EQ, "ton") == BN_UQ)
check("a TON address with one character changed fails its checksum",
      not addresses.validate(BN_UQ[:-1] + ("A" if BN_UQ[-1] != "A" else "B"), "ton")[0])
check("TON labels are found whichever spelling is typed",
      all(labels.type_of(a) == "exchange" for a in (BN_UQ, BN_EQ, BN_RAW)))
from crypttrace import assets
USDT_TON = assets.resolve_asset("usdt", "ton")
check("USDT on TON resolves to Tether's jetton master",
      USDT_TON["contract"] == "0:b113a994b5024a16719f69139328eb759596c38a25f59028b146fecdc3621dfe")

OTHER_RAW = "0:" + "ab" * 32
def toncenter(path, params=None, timeout=30):
    if path == "/transactions":
        return {"transactions": [
            {"now": 1700000000, "hash": "AAECAw==",
             "in_msg": {"source": OTHER_RAW, "destination": BN_RAW, "value": "2500000000"},
             "out_msgs": [{"source": BN_RAW, "destination": OTHER_RAW, "value": "1"}]},
            {"now": 1700000100, "hash": "BAUGBw==",
             "in_msg": {"source": None, "destination": BN_RAW, "value": "0"}, "out_msgs": []}]}
    if path == "/jetton/transfers":
        return {"jetton_transfers": [
            {"source": OTHER_RAW, "destination": BN_RAW, "amount": "297500000",
             "jetton_master": USDT_TON["contract"].upper(), "transaction_hash": "CAkKCw==",
             "transaction_now": 1700000200, "aborted": False},
            {"source": OTHER_RAW, "destination": BN_RAW, "amount": "5", "aborted": True,
             "jetton_master": USDT_TON["contract"], "transaction_hash": "x", "transaction_now": 1}]}
    return {}
real_ton_get = ton_fetch._get
ton_fetch._get = toncenter
try:
    nat = ton_fetch.transfers(BN_UQ, 10)
    check("TON transfers come in TON, between canonical addresses; external messages dropped",
          [(r["from"] == addresses.ton_friendly(OTHER_RAW), r["to"] == BN_UQ, r["value"]) for r in nat][:1]
          == [(True, True, 2.5)] and len(nat) == 2 and nat[1]["value"] == 1e-9, str(nat)[:200])
    check("TON transaction hashes are hex, for explorer links", nat[0]["hash"] == "00010203")
    jt = ton_fetch.jetton_transfers(BN_UQ, 10)
    check("USDT on TON: 6 decimals, owner wallets, aborted transfers dropped",
          [(r["symbol"], r["value"], r["to"]) for r in jt] == [("USDT", 297.5, BN_UQ)], str(jt)[:200])
    calls = []
    def ton_paged(path, params=None, timeout=30):
        calls.append(params["offset"])
        left = max(0, 700 - params["offset"])
        return {"transactions": [{"now": 1, "hash": "", "in_msg": {}, "out_msgs": []}] * min(params["limit"], left)}
    ton_fetch._get = ton_paged
    got = ton_fetch._pages("/transactions", "transactions", {}, 1000, ton_fetch.TX_PAGE)
    check("toncenter history is read page after page", len(got) == 700 and calls == [0, 500], str(calls))
    # one transfer, two transactions: the sender's and the receiver's
    msg = {"source": OTHER_RAW, "destination": BN_RAW, "value": "7000000000", "hash": "DQ4PEA=="}
    both_sides = [{"transactions": [{"now": 1700000500, "hash": "ERITFA==", "in_msg": {}, "out_msgs": [msg]}]},
                  {"transactions": [{"now": 1700000500, "hash": "FRYXGA==", "in_msg": msg, "out_msgs": []}]}]
    ton_fetch._get = lambda path, params=None, timeout=30: both_sides.pop(0) if both_sides else {}
    store.save("ton", addresses.ton_friendly(OTHER_RAW), ton_fetch.transfers(OTHER_RAW, 10))
    store.save("ton", BN_UQ, ton_fetch.transfers(BN_UQ, 10))
    seen = [r for r in store.load("ton", BN_UQ) if r["value"] == 7.0]
    check("a TON transfer read from both ends is stored once", len(seen) == 1, str(seen))
finally:
    ton_fetch._get = real_ton_get

check("TON look-alikes are compared as wallets show them (after 'UQ')",
      poisoning._body(BN_RAW, "ton") == BN_UQ[2:] and poisoning._suffix_chars(BN_UQ, "ton") == 6)

# fresh reads (watch, --fresh) must not be answered from the HTTP cache
real_cache_get, real_requests_get = http_mod.cache_get, http_mod.requests.get
class _Resp:
    status_code, headers = 200, {}
    def raise_for_status(self): pass
    def json(self): return {"answer": "fresh"}
http_mod.cache_get = lambda key, max_age: {"answer": "stale"}
http_mod.requests.get = lambda *a, **k: _Resp()
try:
    stale = http_mod.request_json("https://example.invalid/x", {"q": 1})
    http_mod.FRESH = True
    fresh = http_mod.request_json("https://example.invalid/x", {"q": 1})
    check("a fresh read skips the HTTP cache", stale["answer"] == "stale" and fresh["answer"] == "fresh")
finally:
    http_mod.FRESH = False
    http_mod.cache_get, http_mod.requests.get = real_cache_get, real_requests_get

# funder: dust is not funding
from crypttrace import funder as funder_mod
FUNDED = "TFundedFundedFundedFundedFunded11"
chains.transfers = lambda addr, chain="eth", limit=1000, oldest_first=False, **kw: [
    {"from": TL, "to": FUNDED, "value": 0.000001, "timestamp": 1, "hash": "d"},
    {"from": OPER, "to": FUNDED, "value": 50.0, "timestamp": 2, "hash": "f"}] if addr == FUNDED else []
try:
    ff = funder_mod.first_funder(FUNDED, "tron")
    check("the first funder is the first real payment, not a speck of dust",
          ff and ff["funder"] == OPER, str(ff))
finally:
    chains.transfers = real_transfers

# ---------------------------------------------------------------- watch
section("14. watch on Tron: stablecoins, exchanges, dust")
from crypttrace import watch
USDT_TRON = "tr7nhqjekqxgtci8q8zy4pl8otszgjlj6t"
W = "TWatchedWatchedWatchedWatched1111"                 # synthetic
def trc(frm, to, v, ts, contract=USDT_TRON, sym="USDT"):
    return {"from": frm, "to": to, "value": v, "timestamp": ts, "hash": f"{frm[-3:]}{to[-3:]}{ts}{v}",
            "symbol": sym, "contract": contract}
def native_trx(frm, to, v, ts):
    return {"from": frm, "to": to, "value": v, "timestamp": ts, "hash": f"n{frm[-3:]}{ts}", "symbol": "TRX"}
WATCH_ROWS = {"native": [native_trx("TFunderFunderFunderFunderFunder111", W, 50.0, T0)], "tokens": []}
def watch_history(addr, chain="eth", limit=1000, asset=None, **kw):
    return list(WATCH_ROWS["tokens" if asset else "native"]) if addr == W else []
chains.transfers = watch_history
try:
    try:
        watch.add("t" + W[1:].lower(), "tron")
        check("a mistyped address is refused before it is watched", False)
    except watch.WatchError:
        check("a mistyped address is refused before it is watched", True)
    real_validate = watch.addresses.validate
    watch.addresses.validate = lambda a, c: (True, "")   # W is synthetic
    watch.add(W, "tron", "case")
    check("a Tron address is stored with its case intact", W in watch.all_watched())
    WATCH_ROWS["tokens"] = [
        trc(W, OKX_HOT, 900.0, T0 + 100),                                # into an OKX wallet
        trc(W, OKX_HOT, 50.0, T0 + 100),                                 # same second, not lost
        trc(TL, W, 2500.0, T0 + 90, contract="tfakeusdtcontract"),       # counterfeit USDT
        trc("TSomeoneSomeoneSomeoneSomeone1111", W, 120.0, T0 + 80),     # real incoming
    ]
    WATCH_ROWS["native"].append(native_trx(TL, W, 0.000001, T0 + 70))          # poisoning dust
    got = watch.poll_once()
    sev = sorted((e["sev"], e["symbol"], e["value"]) for e in got)
    check("money leaving for an exchange raises HIGH, in USDT",
          ("high", "USDT", 900.0) in sev and ("high", "USDT", 50.0) in sev, str(sev))
    check("counterfeit USDT does not raise an alert",
          not any(e["value"] == 2500.0 for e in got), str(sev))
    check("dust is marked as poisoning, not as funds",
          ("dust", "TRX", 0.000001) in sev and ("info", "USDT", 120.0) in sev, str(sev))
    check("the same events are not reported twice", watch.poll_once() == [])
    watch.addresses.validate = real_validate
finally:
    chains.transfers = real_transfers

# ---------------------------------------------------------------- spam tokens
section("17. Spam and counterfeit tokens")
from crypttrace import spam, prices, render
USDT_TON_RAW = assets.resolve_asset("usdt", "ton")["contract"]
FAKE = "0:" + "fa" * 32
check("the real USDT on TON is never spam, whatever it calls itself",
      spam.verdict("ton", USDT_TON_RAW, "USD₮", "Tether USD") is None)
check("a jetton named USDT that is not Tether's is a counterfeit",
      "counterfeit USDT" in (spam.verdict("ton", FAKE, "$USD₮") or ""))
check("a name that is a link is spam",
      "gramevent.org" in (spam.verdict("ton", FAKE, "GRAM AT GRAMEVENT.ORG", "GRAM AIRDROP") or "").lower())
check("look-alike Cyrillic letters do not hide the link",
      "usdtunlock.com" in (spam.verdict("ton", FAKE, "USDT - usdtunloсk.соm") or ""))   # с, о, м are Cyrillic
check("a Telegram handle as the name is spam", spam.verdict("ton", FAKE, "@BTC25") is not None)
check("the indexer's scam flag is honoured", spam.verdict("ton", FAKE, "CAT", flagged=True) is not None)
check("a jetton named after the chain's own coin is a counterfeit",
      "counterfeit TON" in (spam.verdict("ton", FAKE, "TON") or ""))
check("ordinary tokens are left alone",
      spam.verdict("ton", FAKE, "NOT", "Notcoin") is None and spam.verdict("tron", "tabc", "SUNDOG") is None)
check("USDT on a chain without a registry entry is not called a counterfeit",
      spam.verdict("bsc", "0x" + "12" * 20, "USDT", "Tether USD") is None)
check("a fake USDT is not priced at $1; the real one is",
      prices.token_price("0x" + "ab" * 20, "eth", "USDT") is None
      and prices.token_price(assets.resolve_asset("usdt", "eth")["contract"], "eth", "USDT") == 1.0)
held = [{"symbol": "USDT", "name": "", "contract": USDT_TON_RAW, "net": 10.0, "txs": 1, "spam": None},
        {"symbol": "$USD₮", "name": "", "contract": FAKE, "net": 1e6, "txs": 1,
         "spam": spam.verdict("ton", FAKE, "$USD₮")}]
from rich.console import Console as _Console
_c = _Console(record=True, width=160)
_c.print(render.holdings_table(BN_UQ, "ton", held))
text = " ".join(_c.export_text().split())
check("tokens hides counterfeits and keeps them out of the total",
      "$USD₮" not in text and "1 spam or counterfeit token(s) hidden" in text and "$10.00" in text, text[-300:])

# ---------------------------------------------------------------- exchange memos
section("18. Exchange deposits with a memo; tonapi names")
from crypttrace.labels import tonapi as tonapi_mod
from crypttrace import trace
import time
real_enrich = tonapi_mod.enrich
tonapi_mod.enrich = lambda addrs: None                    # no network in the selftest
KUCOIN_TON = "UQCA1BI4QRZ8qYmskSRDzJmkucGodYRTZCf_b9hckjla6Yug"
DRAINER = addresses.ton_friendly("0:" + "dd" * 32)
try:
    def memo_center(path, params=None, timeout=30):
        if path == "/transactions":
            return {"transactions": [{"now": 1700000900, "hash": "AQID", "in_msg": {}, "out_msgs": [
                {"source": "0:" + "dd" * 32, "destination": KUCOIN_TON, "value": "1280000000000", "hash": "BAUG",
                 "message_content": {"decoded": {"type": "text_comment", "comment": "2093842166\x00"}}}]}]}
        if path == "/jetton/transfers":
            return {"jetton_transfers": [{"source": "0:" + "dd" * 32, "destination": KUCOIN_TON, "amount": "5000000",
                    "jetton_master": USDT_TON_RAW, "transaction_hash": "BwgJ", "transaction_now": 1700000950,
                    "decoded_forward_payload": {"type": "text_comment", "comment": "777"}}]}
        return {}
    ton_fetch._get = memo_center
    nat, jt = ton_fetch.transfers(DRAINER, 10), ton_fetch.jetton_transfers(DRAINER, 10)
    check("transfer comments are read as memos (TON and jettons), padding stripped",
          nat and nat[0].get("memo") == "2093842166" and jt and jt[0].get("memo") == "777", str(nat + jt)[:200])
    ton_fetch._get = real_ton_get
    store.save("ton", DRAINER, nat)
    check("memos survive the local store", [r.get("memo") for r in store.load("ton", DRAINER)] == ["2093842166"])

    chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: \
        (nat if asset is None else []) if addr == DRAINER else []
    deps = chains.exchange_deposits(DRAINER, "ton")
    check("a deposit with a memo to an exchange wallet is reported with its memo",
          [(d["memo"], d["value"], d["txs"]) for d in deps] == [("2093842166", 1280.0, 1)], str(deps))
    check("such a deposit is not mistaken for an exchange deposit *address* (off-ramp)",
          offramp.detect(DRAINER, "ton") is None)
    _tree, fnd = trace.build(DRAINER, "ton", 1, 3)
    check("trace puts the memo on the exchange finding",
          any(f.get("memo") == "2093842166" for f in fnd), str(fnd)[:200])
    chains.transfers = real_transfers

    check("tonapi: an exchange's own name is a label, with memo_required",
          tonapi_mod.classify({"name": "Kucoin 1", "memo_required": True})["type"] == "exchange")
    check("tonapi: a self-chosen .ton name is not a label",
          tonapi_mod.classify({"name": "crypto-exch-io.ton", "interfaces": ["wallet_v3r2"]}) is None)
    check("tonapi: a scam flag wins over any name",
          tonapi_mod.classify({"name": "kucoin-1.ton", "is_scam": True})["type"] == "scam")
    check("tonapi: STON.fi and DeDust contracts are DEXes",
          tonapi_mod.classify({"name": "", "interfaces": ["stonfi_router_v2"]})["type"] == "dex")
    tonapi_mod._load()[addresses.ton_friendly("0:" + "be" * 32)] = {
        "at": time.time(), "day": "2026-10-12", "label": {"name": "Bybit 7", "type": "exchange"}}
    hit = labels.lookup(addresses.ton_friendly("0:" + "be" * 32))
    check("cached tonapi names are labels with their source",
          hit and hit["type"] == "exchange" and hit["source_kind"] == "explorer-tag", str(hit))
finally:
    tonapi_mod.enrich = real_enrich
    ton_fetch._get = real_ton_get
    chains.transfers = real_transfers

# ---------------------------------------------------------------- TON victims
section("19. Victims on TON: notes, gas refunds and NFTs")
from crypttrace import analysis as an_mod, verify as verify_mod
check("contract plumbing and notes are told apart from payments",
      ton_fetch.kind_of("0xd53276db", "", 0.04) == "service"
      and ton_fetch.kind_of("0x00000000", "hello attacker", 0.01) == "message"
      and ton_fetch.kind_of(None, "", 3446.99) == ""
      and ton_fetch.kind_of("0x00000000", "2500 Telegram Stars", 31.75) == "")
COL = addresses.ton_friendly("0:" + "c0" * 32)
VIC, NOTE, REF, NFTV = (addresses.ton_friendly("0:" + h * 32) for h in ("a1", "a2", "a3", "a4"))
victim_rows = [
    {"from": VIC, "to": COL, "value": 50.0, "timestamp": 10, "hash": "v"},
    {"from": NOTE, "to": COL, "value": 0.01, "timestamp": 11, "hash": "n", "memo": "scammer", "kind": "message"},
    {"from": REF, "to": COL, "value": 0.04, "timestamp": 12, "hash": "r", "kind": "service"},
]
real_nfts = ton_fetch.nft_transfers
chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: \
    (victim_rows if asset is None else []) if addr == COL else []
ton_fetch.nft_transfers = lambda addr, limit=1000: [
    {"from": NFTV, "to": COL, "value": 1.0, "symbol": "NFT", "timestamp": 13, "hash": "x", "item": "i1", "contract": "c"},
    {"from": VIC, "to": COL, "value": 1.0, "symbol": "NFT", "timestamp": 14, "hash": "y", "item": "i2", "contract": "c"}]
try:
    got = {r["address"]: r for r in an_mod.collect_sources(COL, "ton", 1, None, min_value=0.0)}
    check("notes and gas refunds are not victims", NOTE not in got and REF not in got, str(list(got))[:200])
    check("NFTs taken are counted, and an NFT-only victim is listed",
          got.get(VIC, {}).get("nfts") == 1 and got.get(NFTV, {}).get("nfts") == 1
          and got[NFTV]["value"] == 0.0, str(got)[:300])
finally:
    chains.transfers = real_transfers
    ton_fetch.nft_transfers = real_nfts

def aborted_center(path, params=None, timeout=30):
    if path == "/nft/transfers":
        return {"nft_transfers": [
            {"old_owner": "0:" + "a4" * 32, "new_owner": "0:" + "c0" * 32, "transaction_aborted": True,
             "transaction_now": 5, "transaction_hash": "AQ==", "nft_address": "0:" + "11" * 32},
            {"old_owner": "0:" + "a4" * 32, "new_owner": "0:" + "c0" * 32, "transaction_aborted": False,
             "transaction_now": 6, "transaction_hash": "Ag==", "nft_address": "0:" + "12" * 32}]}
    return {}
ton_fetch._get = aborted_center
try:
    check("a failed (aborted) NFT transfer is not an NFT taken", len(ton_fetch.nft_transfers(COL, 10)) == 1)
finally:
    ton_fetch._get = real_ton_get

# net vs balance on TON allows each outgoing transaction its fee
out_rows = [{"from": COL, "to": VIC, "value": 1.0, "timestamp": i, "hash": f"o{i}"} for i in range(10)]
chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: \
    [{"from": VIC, "to": COL, "value": 10.1, "timestamp": 0, "hash": "in"}] + out_rows
real_balance = chains.balance
chains.balance = lambda addr, chain="eth": 0.0
try:
    v = verify_mod.reconcile(COL, "ton")
    check("ten outgoing TON transactions may cost 0.1 TON in fees without a mismatch",
          v["status"] != "mismatch", str(v)[:200])
finally:
    chains.transfers = real_transfers
    chains.balance = real_balance

# ---------------------------------------------------------------- drain check
section("20. Was I drained?")
from crypttrace import drain as drain_mod
ME, THIEFW, SHOP = "TVictimVictimVictimVictimVictim111", "TDrainerDrainerDrainerDrainer11111", "TShopShopShopShopShopShopShopSh111"
OTHERS = [f"TOtherVictimOtherVictimOther{i:05d}" for i in range(12)]
T1 = 1790000000
hist = {
    ME: [{"from": SHOP, "to": ME, "value": 500.0, "timestamp": T1 - 9000, "hash": "buy", "symbol": "TRX"},
         {"from": ME, "to": SHOP, "value": 20.0, "timestamp": T1 - 8000, "hash": "pay", "symbol": "TRX"},
         {"from": ME, "to": THIEFW, "value": 300.0, "timestamp": T1, "hash": "d1", "symbol": "USDT", "contract": assets.resolve_asset("usdt", "tron")["contract"].lower()},
         {"from": ME, "to": THIEFW, "value": 50.0, "timestamp": T1 + 4, "hash": "d2", "symbol": "SUN", "contract": "sun"},
         {"from": ME, "to": THIEFW, "value": 479.9, "timestamp": T1 + 9, "hash": "d3", "symbol": "TRX"},
         {"from": SHOP, "to": ME, "value": 40.0, "timestamp": T1 + 7200, "hash": "topup", "symbol": "TRX"},
         {"from": ME, "to": THIEFW, "value": 39.9, "timestamp": T1 + 7230, "hash": "d4", "symbol": "TRX"}],
    THIEFW: [{"from": o, "to": THIEFW, "value": 100.0, "timestamp": T1 + 60 * i, "hash": f"o{i}", "symbol": "TRX"}
             for i, o in enumerate(OTHERS)],
}
def fake_hist(addr, chain="eth", limit=1000, asset=None, **kw):
    rows = hist.get(addr, [])
    tok = asset is not None
    return [r for r in rows if (r.get("contract") is not None) == tok and (ME in (r["from"], r["to"]) if addr == ME else True)]
saved = (chains.transfers, chains.balance, chains.token_holdings)
chains.transfers = fake_hist
chains.balance = lambda addr, chain="eth": 0.0 if addr == ME else 1e6
chains.token_holdings = lambda addr, chain="eth", limit=1000: []
try:
    r = drain_mod.check(ME, "tron")
    check("a burst of signed transfers that empties the wallet is a drain",
          r["verdict"] == "drained" and r["to"] == THIEFW and set(r["assets"]) == {"USDT", "SUN", "TRX"}, str(r)[:300])
    check("the same receiver emptying many wallets in that hour is called a mass drain",
          r["other_wallets_same_hour"] >= 10 and any("mass drain" in x for x in r["reasons"]))
    check("money taken again after a top-up shows the key is still in use",
          r["resweeps"] == 1 and any("still has the key" in x for x in r["reasons"]))
    chains.balance = lambda addr, chain="eth": 480.0
    check("a wallet that still holds its money is not called drained",
          drain_mod.check(ME, "tron")["verdict"] == "no_drain")
finally:
    chains.transfers, chains.balance, chains.token_holdings = saved

# ---------------------------------------------------------------- evidence pack
section("21. Evidence pack for the exchange and the police")
from crypttrace import evidence as ev_mod
VW, COLW, NEXTW, HOTW = "UQvictimvictim", "UQcollector", "UQsecondwallet", "UQkucoinhot"
fake_check = {"address": VW, "chain": "ton", "verdict": "drained", "reasons": [], "to": COLW,
              "to_label": "drainer", "to_type": "scam", "start": 1790707913, "end": 1790707953, "transfers": 2,
              "assets": {"TON": 3447.0}, "nfts": 0, "other_wallets_same_hour": 175, "resweeps": 1,
              "drain_txs": [{"timestamp": 1790707913, "value": 3447.0, "symbol": "TON", "hash": "aa11"}],
              "next": [{"exchange_address": HOTW, "exchange": "KuCoin hot wallet (memo required)", "memo": "2093842166",
                        "value": 1280.0, "txs": 1, "symbol": "TON", "last_ts": 1790787182, "hash": "bb22",
                        "from": NEXTW}]}
real_check = drain_mod.check
drain_mod.check = lambda address, chain, limit=1000: dict(fake_check)
chains.transfers = lambda addr, chain="eth", limit=1000, asset=None, **kw: \
    [{"from": COLW, "to": NEXTW, "value": 320.86, "timestamp": 1790786366, "hash": "cc33"}] if addr == COLW else []
try:
    doc = ev_mod.build(VW, "ton")
    en, ru = ev_mod.render_markdown(doc, "en"), ev_mod.render_html(doc, "ru")
    check("the pack names the exchange account by its memo and asks to freeze it",
          "2093842166" in en and "freeze the account identified by deposit memo 2093842166" in en)
    check("the path links every hop to its transaction",
          all(h in en for h in ("aa11", "bb22", "cc33")) and f"{VW} → {COLW} → {NEXTW} → {HOTW}" in en)
    check("the police version is in Russian and points to the exchange's portal",
          "Хищение криптовалюты" in ru and "kucoin.com/legal/requests" in ru)
    check("a mass drain and a re-sweep are stated", "175 other wallets" in en and "still holds the wallet's key" in en)
    check("the victim's details are left blank, not invented", "Name: ____" in en and "UQvictimvictim" in en)
    drain_mod.check = lambda address, chain, limit=1000: {"address": VW, "chain": "ton", "verdict": "no_drain",
                                                          "reasons": []}
    check("no drain, no evidence pack", "No drain was found" in ev_mod.render_markdown(ev_mod.build(VW, "ton")))
finally:
    drain_mod.check = real_check
    chains.transfers = real_transfers

# ---------------------------------------------------------------- tronscan tags
section("22. Tron labels from Tronscan")
from crypttrace.labels import tronscan as ts_mod
check("a Tronscan exchange tag is an exchange label",
      ts_mod.classify({"addressTag": "Binance-Cold 1", "publicTag": "Binance-Cold 1"}) == {"name": "Binance-Cold 1", "type": "exchange"}
      and ts_mod.classify({"addressTag": "Okex 1"})["type"] == "exchange")
check("a red tag makes the address a scam, whatever else it says",
      ts_mod.classify({"addressTag": "Some Name", "redTag": "Phishing"})["type"] == "scam")
check("no tag, no label; a contract's own name is not a tag",
      ts_mod.classify({"name": "TetherToken", "addressTag": "", "redTag": ""}) is None)
TAGGED = "TTaggedTaggedTaggedTaggedTagged111"
ts_mod._load()[TAGGED] = {"at": time.time(), "day": "2026-10-17", "label": {"name": "Bybit-Hot", "type": "exchange"}}
hit = labels.lookup(TAGGED)
check("cached Tronscan tags are labels with their source",
      hit and hit["type"] == "exchange" and hit["source_kind"] == "explorer-tag" and "Tronscan" in hit["source"])
import importlib
real_req = http_mod.request_json
def no_network(*a, **k):
    raise AssertionError("network used")
http_mod.request_json = no_network
try:
    importlib.reload(ts_mod)                   # the real enrich, not the selftest stub
    ts_mod._key = lambda: None
    ts_mod.enrich(["TNoKeyNoKeyNoKeyNoKeyNoKeyNoKey111"])
    check("without a Tronscan key nothing is fetched", True)
except AssertionError as e:
    check("without a Tronscan key nothing is fetched", False, str(e))
finally:
    http_mod.request_json = real_req
    ts_mod.enrich = lambda addrs: None

# ---------------------------------------------------------------- EVM internal transactions
section("23. EVM: internal transactions; failed calls")
from crypttrace import funder as funder23
from crypttrace.fetchers import etherscan as es23
POOL = "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc"
WD = "0x" + "fb" * 20
real_txs, real_int = es23.get_txs, es23.get_internal_txs
es23.get_txs = lambda address, chain="eth", limit=1000, sort="desc": [
    {"from": WD, "to": "0x" + "aa" * 20, "value": str(5 * 10 ** 16), "timeStamp": "200", "hash": "0xpay", "isError": "0"},
    {"from": WD, "to": "0x" + "bb" * 20, "value": str(10 ** 18), "timeStamp": "150", "hash": "0xfail", "isError": "1"}]
es23.get_internal_txs = lambda address, chain="eth", limit=1000, sort="desc": [
    {"from": POOL, "to": WD, "value": str(97922978921300000), "timeStamp": "100", "hash": "0xwithdraw", "isError": "0"},
    {"from": POOL, "to": WD, "value": "0", "timeStamp": "120", "hash": "0xzero", "isError": "0"}]
chains.transfers = real_transfers
saved_store = chains.USE_STORE
chains.USE_STORE = False
try:
    rows = chains.transfers(WD, "eth", 100)
    check("ETH a contract sent (a mixer withdrawal) is a transfer", any(r["hash"] == "0xwithdraw" and r.get("internal") for r in rows))
    check("a failed call moved nothing, a zero internal call is no transfer",
          not any(r["hash"] in ("0xfail", "0xzero") for r in rows), str([r["hash"] for r in rows]))
    ff = funder23.first_funder(WD, "eth")
    check("the first funder can be a contract: here Tornado Cash", ff and ff["funder"] == POOL, str(ff))
finally:
    es23.get_txs, es23.get_internal_txs = real_txs, real_int
    chains.USE_STORE = saved_store
check("the 0.1 ETH Tornado pool is labelled as such", labels.label_of(POOL) == "Tornado Cash: 0.1 ETH")

# ---------------------------------------------------------------- gas-funding clusters
section("24. EVM clustering by gas funding")
from crypttrace import gascluster
F, A1, A2, A3, NOT_SIB = ("0x" + c * 40 for c in "f123a")
BRIDGE, VICT = "0x" + "b" * 40, "0x" + "e" * 40
t = 1_700_000_000
hist24 = {
    A1: [{"from": F, "to": A1, "value": 0.05, "timestamp": t, "hash": "h1"}],
    A2: [{"from": F, "to": A2, "value": 0.06, "timestamp": t + 600, "hash": "h2"}],
    A3: [{"from": F, "to": A3, "value": 0.04, "timestamp": t + 1200, "hash": "h3"}],
    NOT_SIB: [{"from": "0x" + "9" * 40, "to": NOT_SIB, "value": 1.0, "timestamp": t - 99, "hash": "h0"},
              {"from": F, "to": NOT_SIB, "value": 0.05, "timestamp": t + 50, "hash": "h4"}],
    F: [{"from": F, "to": a, "value": v, "timestamp": ts, "hash": h} for a, v, ts, h in
        ((A1, 0.05, t, "h1"), (A2, 0.06, t + 600, "h2"), (A3, 0.04, t + 1200, "h3"), (NOT_SIB, 0.05, t + 50, "h4"))],
    VICT: [{"from": BRIDGE, "to": VICT, "value": 100.0, "timestamp": t, "hash": "hb", "internal": True}],
}
chains.transfers = lambda addr, chain="eth", limit=1000, oldest_first=False, asset=None, **kw: \
    sorted(hist24.get(addr, []), key=lambda r: r["timestamp"], reverse=not oldest_first) if asset is None else []
try:
    r = gascluster.cluster(A1, "eth")
    sibs = {s["address"] for s in r["siblings"]}
    check("wallets set up by the same wallet are siblings", sibs == {A2, A3}, str(sibs))
    check("a wallet funded first by someone else is not a sibling", NOT_SIB not in sibs)
    check("same-day funding with similar amounts is a strong link", r["strength"] == "strong", r["strength"])
    r = gascluster.cluster(VICT, "eth")
    check("a first funding from a contract links nothing",
          not r["siblings"] and "contract" in r["note"], r["note"])
    rc = gascluster.cluster(F, "eth")
    check("wallets this one funded first are its children",
          {c["address"] for c in rc["children"]} == {A1, A2, A3}, str([c["address"] for c in rc["children"]]))
finally:
    chains.transfers = real_transfers

# ---------------------------------------------------------------- Solana depth
section("25. Solana: paged signatures, failed and v1 transactions")
SOLW = "SoLWaLLeTSoLWaLLeTSoLWaLLeTSoLWaLLeT111"
calls25 = {"pages": [], "versions": set()}
def rpc25(method, params, timeout=30):
    if method == "getSignaturesForAddress":
        opts = params[1]
        calls25["pages"].append(opts.get("before"))
        start = 0 if not opts.get("before") else int(opts["before"][1:]) + 1
        n = min(opts["limit"], 130 - start)
        return [{"signature": f"s{start + i}", "err": ({"x": 1} if (start + i) % 10 == 3 else None)}
                for i in range(max(0, n))]
    if method == "getTransaction":
        calls25["versions"].add(params[1].get("maxSupportedTransactionVersion"))
        sig = params[0]
        return {"blockTime": 1, "meta": {"err": {"InstructionError": 1} if sig == "s5" else None},
                "transaction": {"message": {"accountKeys": [], "instructions": [
                    {"program": "system", "parsed": {"type": "transfer", "info": {
                        "source": SOLW, "destination": "dest", "lamports": 10 ** 9}}}]}}}
real_rpc25, real_sig_page, real_max = sol_fetch._rpc, sol_fetch.SIG_PAGE, sol_fetch.MAX_TXS
sol_fetch._rpc, sol_fetch.SIG_PAGE, sol_fetch.MAX_TXS = rpc25, 50, 100
try:
    sigs = sol_fetch._signatures(SOLW, 100)
    check("signatures are read page after page, failed ones left out",
          len(sigs) == 100 and len(calls25["pages"]) >= 2 and not any(int(x[1:]) % 10 == 3 for x in sigs),
          f"{len(sigs)} sigs, pages {calls25['pages'][:4]}")
    rows = sol_fetch.transfers(SOLW, 20)
    check("a failed transaction moved nothing", "s5" not in {r["hash"] for r in rows} and len(rows) >= 15)
    check("version-1 transactions are asked for", calls25["versions"] == {1}, str(calls25["versions"]))
finally:
    sol_fetch._rpc, sol_fetch.SIG_PAGE, sol_fetch.MAX_TXS = real_rpc25, real_sig_page, real_max

# ---------------------------------------------------------------- first funder from the start
section("26. first funder: history read from its start")
OLDW = "TOldOldOldOldOldOldOldOldOldOld111"            # synthetic
GENESIS, RECENT = "TGenesisGenesisGenesisGenesis1111", "TRecentRecentRecentRecentRecent11"
asked26 = []
def tron26(address, limit=200, oldest=False):
    asked26.append(oldest)
    return ([{"from": GENESIS, "to": OLDW, "value": 100.0, "timestamp": 1_600_000_000, "hash": "first", "symbol": "TRX"}]
            if oldest else
            [{"from": RECENT, "to": OLDW, "value": 5.0, "timestamp": 1_790_000_000 + i, "hash": f"n{i}", "symbol": "TRX"}
             for i in range(limit)])
real_tron26 = tron_fetch.transfers
tron_fetch.transfers = tron26
chains.transfers = real_transfers
try:
    store.clear()
    chains.transfers(OLDW, "tron", 200)                  # stores the latest 200: not the whole history
    ff = funder_mod.first_funder(OLDW, "tron")
    check("a busy wallet's first funder comes from the start of its history, not the latest page",
          ff and ff["funder"] == GENESIS and asked26 == [False, True], f"{ff} {asked26}")
    check("a start-of-history read is not filed as the stored history",
          not any(r["hash"] == "first" for r in store.load(chain="tron", address=OLDW)))
    store.save("tron", OLDW, [{"from": RECENT, "to": OLDW, "value": 7.0, "timestamp": 5, "hash": "all", "symbol": "TRX"}],
               complete=True)
    asked26.clear()
    ff = funder_mod.first_funder(OLDW, "tron")
    check("a complete stored history answers without the network",
          ff and ff["hash"] == "all" and asked26 == [], f"{ff} {asked26}")
finally:
    tron_fetch.transfers = real_tron26
    store.clear()

# ---------------------------------------------------------------- Etherscan errors
section("27. Etherscan: an error is not an empty wallet")
from crypttrace import config as config27
from crypttrace.fetchers import etherscan as es27
class Resp27:
    def __init__(self, payload): self.payload = payload
    def raise_for_status(self): pass
    def json(self): return self.payload
NOT_ON_PLAN = {"status": "0", "message": "NOTOK",
               "result": "Free API access is not supported for this chain. Please upgrade your api plan "
                         "for full chain coverage. https://etherscan.io/apis"}
answers27 = []
real_get27, real_key27, real_sleep27 = es27.requests.get, config27.ETHERSCAN_API_KEY, es27.time.sleep
es27.requests.get = lambda url, params=None, timeout=30: Resp27(answers27.pop(0))
config27.ETHERSCAN_API_KEY, es27.time.sleep = "selftest-key", (lambda s: None)
W27 = "0x" + "27" * 20
try:
    answers27[:] = [NOT_ON_PLAN]
    try:
        es27.get_balance(W27, "bsc")
        said = "no error"
    except es27.EtherscanError as e:
        said = str(e)
    check("a chain the free plan leaves out is reported, not shown as an empty wallet",
          "paid" in said and "bsc" in said, said)
    answers27[:] = [{"status": "1", "message": "OK", "result": "5000000000000000000"}]
    check("the refusal was not cached", es27.get_balance(W27, "bsc") == 5.0)
    answers27[:] = [{"status": "0", "message": "No transactions found", "result": []}]
    check("'No transactions found' is still an empty history", es27.get_txs("0x" + "28" * 20, "eth") == [])
    answers27[:] = [{"status": "0", "message": "NOTOK", "result": "Invalid API Key"}]
    try:
        es27.get_txs("0x" + "29" * 20, "eth")
        said = "no error"
    except es27.EtherscanError as e:
        said = str(e)
    check("any other Etherscan error is raised too", "Invalid API Key" in said, said)
    es27._cache_put("eth:" + "&".join(f"{k}={v}" for k, v in sorted({
        "chainid": 1, "module": "account", "action": "txlist", "address": "0x" + "30" * 20,
        "startblock": "0", "endblock": "99999999", "page": "1", "offset": "1000", "sort": "desc"}.items())),
        NOT_ON_PLAN)
    answers27[:] = [{"status": "1", "message": "OK", "result": [{"hash": "0xok"}]}]
    check("an error cached by an older version is not served",
          es27.get_txs("0x" + "30" * 20, "eth") == [{"hash": "0xok"}])
finally:
    es27.requests.get, config27.ETHERSCAN_API_KEY, es27.time.sleep = real_get27, real_key27, real_sleep27

from crypttrace import bridges as bridges27
def txs27(address, chain="eth", limit=1000, sort="desc"):
    if chain == "base":
        raise es27.EtherscanError("Etherscan's free plan does not cover base")
    return []
real_txs27 = bridges27.etherscan.get_txs
bridges27.etherscan.get_txs = txs27
try:
    unread27 = {}
    bridges27.find_arrivals(W27, "eth", 1.0, 0, unread=unread27)
    check("crosschain names a chain it could not search instead of counting it as searched",
          list(unread27) == ["base"], str(unread27))
finally:
    bridges27.etherscan.get_txs = real_txs27

# ---------------------------------------------------------------- MEXC reserve wallets
section("29. MEXC reserve wallets and its law-enforcement portal")
from crypttrace import evidence as evidence29
MEXC_TRON = "TEPSrSYPDSQ7yXpMFPq91Fb1QEWpMkRGfn"          # from MEXC's Hacken PoR audit, 2026-10-09
MEXC_ETH = "0xd67f25ef2399a0c769b1a35634c5ce77166714db"
check("MEXC's audited reserve wallets are labelled, on Tron and EVM alike",
      labels.label_of(MEXC_TRON) == labels.label_of(MEXC_ETH) == "MEXC reserve wallet"
      and labels.type_of(MEXC_TRON) == "exchange")
check("an evidence pack for funds that reached MEXC names its law-enforcement portal",
      evidence29.LE_PORTALS.get(labels.company(labels.label_of(MEXC_TRON))) ==
      "https://www.mexc.com/support/ticket/submit/law-enforcement-requests")

# ---------------------------------------------------------------- result
print("\n" + "=" * 72)
print(f"RESULT: {len(PASSED)} passed, {len(FAILED)} failed")
print("=" * 72)
if FAILED:
    for f in FAILED:
        print(f"  failed: {f}")
    sys.exit(1)
print("Everything described in this session behaves as claimed.")
