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

# ---------------------------------------------------------------- result
print("\n" + "=" * 72)
print(f"RESULT: {len(PASSED)} passed, {len(FAILED)} failed")
print("=" * 72)
if FAILED:
    for f in FAILED:
        print(f"  failed: {f}")
    sys.exit(1)
print("Everything described in this session behaves as claimed.")
