"""Unified multi-chain adapter.

Every supported network — EVM (Etherscan v2), Bitcoin (UTXO, mempool.space),
Tron (TronGrid) and Solana (JSON-RPC) — is normalized to the same transfer row:

    {"from", "to", "value", "timestamp", "hash", "symbol", "contract"?}

so the tracing engine, profiles and the web graph work identically everywhere.

Native coins and tokens are kept strictly separate: summing 5 TRX with 250 USDT
would be meaningless, so a caller always asks for one asset at a time.
"""
from typing import List, Dict, Optional

from crypttrace import config
from crypttrace.fetchers import etherscan, bitcoin, tron, solana

EVM_CHAINS = set(config.CHAINS)
NON_EVM = {"btc", "tron", "sol"}
ALL_CHAINS = sorted(EVM_CHAINS | NON_EVM)

SYMBOL = {"eth": "ETH", "bsc": "BNB", "polygon": "MATIC", "arbitrum": "ETH",
          "optimism": "ETH", "base": "ETH", "btc": "BTC", "tron": "TRX", "sol": "SOL"}

EXPLORER = {
    "eth": "https://etherscan.io/address/{}", "bsc": "https://bscscan.com/address/{}",
    "polygon": "https://polygonscan.com/address/{}", "arbitrum": "https://arbiscan.io/address/{}",
    "optimism": "https://optimistic.etherscan.io/address/{}", "base": "https://basescan.org/address/{}",
    "btc": "https://mempool.space/address/{}", "tron": "https://tronscan.org/#/address/{}",
    "sol": "https://solscan.io/account/{}",
}

_UPSTREAM_ERRORS = (etherscan.EtherscanError, bitcoin.BitcoinError,
                    tron.TronError, solana.SolanaError)


class ChainError(RuntimeError):
    pass


def is_evm(chain: str) -> bool:
    return chain in EVM_CHAINS


def case_sensitive(chain: str) -> bool:
    """Bitcoin/Tron/Solana use base58 — address case is significant."""
    return chain in NON_EVM


def norm_addr(address: str, chain: str) -> str:
    return address if case_sensitive(chain) else address.lower()


def symbol(chain: str) -> str:
    return SYMBOL.get(chain, "?")


def explorer_url(address: str, chain: str) -> str:
    return EXPLORER.get(chain, EXPLORER["eth"]).format(address)


def check(chain: str) -> None:
    if chain not in ALL_CHAINS:
        raise ChainError(f"unsupported chain '{chain}'. Options: {ALL_CHAINS}")


def balance(address: str, chain: str = "eth") -> float:
    check(chain)
    try:
        if is_evm(chain):
            return etherscan.get_balance(address, chain)
        if chain == "btc":
            return bitcoin.balance(address)
        if chain == "tron":
            return tron.balance(address)
        if chain == "sol":
            return solana.balance(address)
    except _UPSTREAM_ERRORS as e:
        raise ChainError(str(e))
    return 0.0


# ---------- normalized row builders ----------

def _evm_native(address: str, chain: str, limit: int) -> List[Dict]:
    rows = []
    for tx in etherscan.get_txs(address, chain, limit=limit):
        try:
            val = int(tx.get("value", 0)) / config.WEI
        except (TypeError, ValueError):
            val = 0.0
        rows.append({"from": tx.get("from", "").lower(), "to": tx.get("to", "").lower(),
                     "value": val, "timestamp": int(tx.get("timeStamp", "0") or 0),
                     "hash": tx.get("hash", ""), "symbol": symbol(chain)})
    return rows


def _evm_token(address: str, chain: str, contract: Optional[str], limit: int) -> List[Dict]:
    rows = []
    want = (contract or "").lower()
    for t in etherscan.get_token_txs(address, chain, limit=limit):
        c = (t.get("contractAddress") or "").lower()
        if want and c != want:
            continue
        try:
            dec = int(t.get("tokenDecimal") or 18)
            val = int(t.get("value", 0)) / (10 ** dec)
        except (TypeError, ValueError):
            continue
        rows.append({"from": t.get("from", "").lower(), "to": t.get("to", "").lower(),
                     "value": val, "timestamp": int(t.get("timeStamp", "0") or 0),
                     "hash": t.get("hash", ""), "symbol": t.get("tokenSymbol", "?"),
                     "contract": c})
    return rows


def _tron_token(address: str, contract: Optional[str], limit: int) -> List[Dict]:
    rows = tron.token_transfers(address, limit)
    if contract:
        want = contract.lower()
        rows = [r for r in rows if (r.get("contract") or "").lower() == want]
    return rows


def _sol_rows(address: str, limit: int, token: bool, contract: Optional[str]) -> List[Dict]:
    rows = solana.transfers(address, limit)
    if token:
        rows = [r for r in rows if r.get("symbol") != "SOL"]
        if contract:
            rows = [r for r in rows if r.get("mint") in (None, contract)
                    or (r.get("contract") or "") == contract]
    else:
        rows = [r for r in rows if r.get("symbol") == "SOL"]
    return rows


def transfers(address: str, chain: str = "eth", limit: int = 1000,
              oldest_first: bool = False, asset: Optional[dict] = None) -> List[Dict]:
    """Normalized transfers for one asset (native by default), newest first."""
    check(chain)
    contract = asset.get("contract") if asset else None
    try:
        if is_evm(chain):
            rows = _evm_token(address, chain, contract, limit) if asset \
                else _evm_native(address, chain, limit)
        elif chain == "btc":
            if asset:
                raise ChainError("Bitcoin has no tokens.")
            rows = bitcoin.transfers(address, limit)
        elif chain == "tron":
            # keep TRX and TRC20 strictly separate
            rows = _tron_token(address, contract, limit) if asset \
                else tron.transfers(address, limit)
        elif chain == "sol":
            rows = _sol_rows(address, limit, bool(asset), contract)
        else:
            rows = []
    except _UPSTREAM_ERRORS as e:
        raise ChainError(str(e))
    rows.sort(key=lambda r: r.get("timestamp", 0), reverse=not oldest_first)
    return rows


def flows(address: str, chain: str, top: int, direction: str = "out",
          limit: int = 1000, asset: Optional[dict] = None):
    """Aggregated value per counterparty: [(other, total, tx_count)].

    direction='out' — where this address SENT funds (follow the money forward).
    direction='in'  — where its funds CAME FROM (trace the source backward).
    """
    me = norm_addr(address, chain)
    near, far = ("from", "to") if direction == "out" else ("to", "from")
    agg: Dict[str, list] = {}
    for r in transfers(address, chain, limit, asset=asset):
        if r.get(near) != me:
            continue
        other = r.get(far)
        if not other or r.get("value", 0) <= 0:
            continue
        rec = agg.setdefault(other, [0.0, 0])
        rec[0] += r["value"]
        rec[1] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)
    return [(a, v, c) for a, (v, c) in ranked][:top]


def outflows(address: str, chain: str, top: int, limit: int = 1000, asset=None):
    return flows(address, chain, top, "out", limit, asset)


def inflows(address: str, chain: str, top: int, limit: int = 1000, asset=None):
    return flows(address, chain, top, "in", limit, asset)


def token_holdings(address: str, chain: str = "eth", limit: int = 1000) -> List[Dict]:
    """Approximate token holdings from transfer history (net in − out per token)."""
    check(chain)
    if chain == "btc":
        return []
    me = norm_addr(address, chain)
    try:
        if is_evm(chain):
            rows = _evm_token(address, chain, None, limit)
        elif chain == "tron":
            rows = _tron_token(address, None, limit)
        else:
            rows = _sol_rows(address, limit, True, None)
    except _UPSTREAM_ERRORS as e:
        raise ChainError(str(e))

    agg: Dict[str, dict] = {}
    for r in rows:
        key = r.get("contract") or r.get("symbol", "?")
        rec = agg.setdefault(key, {"symbol": r.get("symbol", "?"), "contract": key,
                                   "net": 0.0, "txs": 0})
        if r.get("to") == me:
            rec["net"] += r.get("value", 0.0)
        if r.get("from") == me:
            rec["net"] -= r.get("value", 0.0)
        rec["txs"] += 1
    return sorted([h for h in agg.values() if h["net"] > 1e-9],
                  key=lambda h: h["net"], reverse=True)
