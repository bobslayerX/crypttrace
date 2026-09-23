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

# ---------------------------------------------------------------- result
print("\n" + "=" * 72)
print(f"RESULT: {len(PASSED)} passed, {len(FAILED)} failed")
print("=" * 72)
if FAILED:
    for f in FAILED:
        print(f"  failed: {f}")
    sys.exit(1)
print("Everything described in this session behaves as claimed.")
