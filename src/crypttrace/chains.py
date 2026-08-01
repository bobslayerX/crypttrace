"""Unified multi-chain adapter.

Every supported network — EVM (Etherscan v2), Bitcoin (UTXO, mempool.space),
Tron (TronGrid) and Solana (JSON-RPC) — is normalized to the same transfer row:

    {"from", "to", "value", "timestamp", "hash", "symbol"}

so the tracing engine, profiles and the web graph work identically everywhere.
"""
from typing import List, Dict

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


class ChainError(RuntimeError):
    pass


def is_evm(chain: str) -> bool:
    return chain in EVM_CHAINS


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
    except (etherscan.EtherscanError, bitcoin.BitcoinError,
            tron.TronError, solana.SolanaError) as e:
        raise ChainError(str(e))
    return 0.0


def _evm_rows(address: str, chain: str, limit: int) -> List[Dict]:
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


def transfers(address: str, chain: str = "eth", limit: int = 1000,
              oldest_first: bool = False) -> List[Dict]:
    """Normalized transfers for any supported chain (newest first by default)."""
    check(chain)
    try:
        if is_evm(chain):
            rows = _evm_rows(address, chain, limit)
        elif chain == "btc":
            rows = bitcoin.transfers(address, limit)
        elif chain == "tron":
            rows = tron.transfers(address, limit) + tron.token_transfers(address, limit)
        elif chain == "sol":
            rows = solana.transfers(address, limit)
        else:
            rows = []
    except (etherscan.EtherscanError, bitcoin.BitcoinError,
            tron.TronError, solana.SolanaError) as e:
        raise ChainError(str(e))
    rows.sort(key=lambda r: r.get("timestamp", 0), reverse=not oldest_first)
    return rows


def outflows(address: str, chain: str, top: int, limit: int = 1000):
    """Aggregated outgoing value per destination: [(to, total, tx_count)]."""
    me = address if chain in ("btc", "tron", "sol") else address.lower()
    agg: Dict[str, list] = {}
    for r in transfers(address, chain, limit):
        if r.get("from") != me:
            continue
        to = r.get("to")
        if not to or r.get("value", 0) <= 0:
            continue
        rec = agg.setdefault(to, [0.0, 0])
        rec[0] += r["value"]
        rec[1] += 1
    ranked = sorted(agg.items(), key=lambda kv: kv[1][0], reverse=True)
    return [(a, v, c) for a, (v, c) in ranked][:top]
