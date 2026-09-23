"""Stablecoin freezes — has the issuer already frozen the money, and who can?

Tether (USDT) and Circle (USDC) can freeze their tokens at any address. For a
victim that is the one mechanism that actually stops stolen stablecoins, and it
works only while the money is still sitting there. So the useful answers are:
how much USDT/USDC is at this address, is it already frozen, and if not, who
can freeze it and what they need.

Everything is read from the issuers' own contracts, not from third-party lists:

  * Ethereum — USDT's isBlackListed / USDC's isBlacklisted and balanceOf, via
    a public JSON-RPC node (no API key; set CRYPTTRACE_ETH_RPC to use your own);
  * Tron     — the same calls through TronGrid;
  * Solana   — the state of the owner's token accounts, which the issuer freezes
    one account at a time ("frozen").

Other chains carry bridged or third-party versions of these tokens that the
issuers cannot freeze in the same way, so they are not checked.
"""
import os
from typing import Dict, List

import requests

from crypttrace import addresses, assets
from crypttrace.fetchers import solana

ETH_RPC = os.environ.get("CRYPTTRACE_ETH_RPC", "https://ethereum-rpc.publicnode.com")
TRON_API = "https://api.trongrid.io"

# selector of the issuer's own "is this address frozen?" function
_EVM_FROZEN = {"USDT": "0xe47d6060",   # isBlackListed(address)
               "USDC": "0xfe575a87"}   # isBlacklisted(address)
_BALANCE_OF = "0x70a08231"             # balanceOf(address)
_TRON_FROZEN = {"USDT": "isBlackListed(address)", "USDC": "isBlacklisted(address)"}

ISSUERS = {
    "USDT": {"issuer": "Tether",
             "how": ("Tether freezes USDT at the request of law enforcement, often before "
                     "a court case. Give the police this address and ask them to request a "
                     "freeze from Tether."),
             "url": "https://tether.to/en/legal/?tab=law-enforcement-requests"},
    "USDC": {"issuer": "Circle",
             "how": ("Circle freezes USDC only on a legal order — a court order, a sanctions "
                     "designation or a request from authorities with jurisdiction over it. "
                     "Expect to need a court order; ask the police or a lawyer."),
             "url": "https://www.circle.com/legal/usdc-terms"},
}

SUPPORTED = ("eth", "tron", "sol")
MIN_ACTIONABLE = 1.0          # USDT/USDC below this is dust


class FreezeError(RuntimeError):
    pass


def _eth_call(contract: str, selector: str, address: str) -> int:
    data = selector + address.lower().replace("0x", "").rjust(64, "0")
    try:
        r = requests.post(ETH_RPC, timeout=30, json={
            "jsonrpc": "2.0", "id": 1, "method": "eth_call",
            "params": [{"to": contract, "data": data}, "latest"]}).json()
    except (requests.RequestException, ValueError) as e:
        raise FreezeError(f"Ethereum node unreachable: {e}")
    if "result" not in r:
        raise FreezeError(f"Ethereum node refused the call: {r.get('error')}")
    return int(r["result"] or "0x0", 16)


def _tron_call(contract: str, signature: str, address: str) -> int:
    raw = addresses._b58_decode(address)            # 0x41 + 20 bytes + checksum
    if not raw or len(raw) != 25:
        raise FreezeError("not a Tron address")
    headers = {"TRON-PRO-API-KEY": os.environ["TRONGRID_API_KEY"]} \
        if os.environ.get("TRONGRID_API_KEY") else {}
    try:
        r = requests.post(f"{TRON_API}/wallet/triggerconstantcontract", timeout=30,
                          headers=headers, json={
                              # a read-only call: the caller does not matter, and
                              # an unactivated address can be refused as the caller
                              "owner_address": contract, "contract_address": contract,
                              "function_selector": signature,
                              "parameter": raw[1:21].hex().rjust(64, "0"), "visible": True}).json()
    except (requests.RequestException, ValueError) as e:
        raise FreezeError(f"TronGrid unreachable: {e}")
    out = (r.get("constant_result") or [None])[0]
    if out is None:
        raise FreezeError(f"TronGrid refused the call: {r.get('result') or r}")
    return int(out or "0", 16)


def _sol_accounts(owner: str, mint: str) -> List[dict]:
    try:
        r = solana._rpc("getTokenAccountsByOwner",
                        [owner, {"mint": mint}, {"encoding": "jsonParsed"}])
    except solana.SolanaError as e:
        raise FreezeError(str(e))
    out = []
    for v in (r.get("value") if isinstance(r, dict) else r) or []:
        info = v["account"]["data"]["parsed"]["info"]
        out.append({"state": info.get("state"),
                    "amount": float(info["tokenAmount"].get("uiAmountString") or 0)})
    return out


def _one(address: str, chain: str, symbol: str, contract: str) -> Dict:
    if chain == "eth":
        frozen = _eth_call(contract, _EVM_FROZEN[symbol], address) == 1
        balance = _eth_call(contract, _BALANCE_OF, address) / 1e6
        frozen_amount = balance if frozen else 0.0
    elif chain == "tron":
        frozen = _tron_call(contract, _TRON_FROZEN[symbol], address) == 1
        balance = _tron_call(contract, "balanceOf(address)", address) / 1e6
        frozen_amount = balance if frozen else 0.0
    else:                                             # sol: frozen per token account
        accts = _sol_accounts(address, contract)
        balance = sum(a["amount"] for a in accts)
        frozen_amount = sum(a["amount"] for a in accts if a["state"] == "frozen")
        frozen = any(a["state"] == "frozen" for a in accts)
    movable = balance - frozen_amount
    return {"token": symbol, "balance": balance, "frozen": frozen,
            "frozen_amount": frozen_amount, "movable": movable,
            # leftover dust is not worth a freeze request, or a victim's panic
            "actionable": movable >= MIN_ACTIONABLE}


def describe_frozen(e: Dict) -> str:
    """'4,021.97 USDT here is frozen by Tether', or the blacklisting alone when empty."""
    if (e.get("frozen_amount") or 0) >= MIN_ACTIONABLE:
        return f"{e['frozen_amount']:,.2f} {e['token']} here is frozen by {e['issuer']}"
    return f"This address is blacklisted by {e['issuer']} (no {e['token']} left on it)"


def check(address: str, chain: str) -> List[Dict]:
    """One entry per issuer stablecoin on this chain; empty where none applies.

    Each entry: token, issuer, balance, frozen, frozen_amount, movable (what can
    still leave), how (what the issuer needs), url, and error if it could not be
    read. A failed read is reported, never guessed.
    """
    if chain not in SUPPORTED:
        return []
    from crypttrace import chains
    out = []
    for sym in ("usdt", "usdc"):
        tok = assets.tokens_for(chain).get(sym)
        if not tok:
            continue
        symbol = tok["symbol"]
        entry = {"token": symbol, **ISSUERS[symbol]}
        try:
            if chains.OFFLINE:
                raise FreezeError("not checked: working offline")
            entry.update(_one(address, chain, symbol, tok["contract"]))
        except (FreezeError, KeyError, TypeError, ValueError) as e:
            entry.update({"balance": None, "frozen": None, "frozen_amount": None,
                          "movable": None, "actionable": None, "error": str(e)})
        out.append(entry)
    return out

