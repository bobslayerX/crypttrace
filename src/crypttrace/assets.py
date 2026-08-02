"""Asset registry — which token to follow, per chain.

Most thefts and scams move stablecoins, not native coins, so tracing has to be
able to follow a specific token. Contract addresses differ per chain, so the
registry is keyed by chain. All addresses below are the official ones and were
verified against block explorers — a wrong contract would silently trace the
wrong asset (fake "USDT" tokens are routinely airdropped to poison wallets).
"""
from typing import Optional, Dict

# chain -> symbol -> {contract, symbol, stable}
TOKENS: Dict[str, Dict[str, dict]] = {
    "eth": {
        "usdt": {"contract": "0xdac17f958d2ee523a2206206994597c13d831ec7", "symbol": "USDT", "stable": True},
        "usdc": {"contract": "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", "symbol": "USDC", "stable": True},
        "dai":  {"contract": "0x6b175474e89094c44da98b954eedeac495271d0f", "symbol": "DAI", "stable": True},
        "busd": {"contract": "0x4fabb145d64652a948d72533023f6e7a623c7c53", "symbol": "BUSD", "stable": True},
        "weth": {"contract": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2", "symbol": "WETH", "stable": False},
        "wbtc": {"contract": "0x2260fac5e5542a773aa44fbcfedf7c193bc2c599", "symbol": "WBTC", "stable": False},
    },
    # Tron: where most everyday scams (romance / "pig butchering") move money.
    "tron": {
        "usdt": {"contract": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "symbol": "USDT", "stable": True},
        "usdc": {"contract": "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8", "symbol": "USDC", "stable": True},
    },
    "sol": {
        "usdc": {"contract": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "symbol": "USDC", "stable": True},
        "usdt": {"contract": "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", "symbol": "USDT", "stable": True},
    },
}

# chains where token tracing is supported at all
TOKEN_CHAINS = set(TOKENS) | {"bsc", "polygon", "arbitrum", "optimism", "base"}


def tokens_for(chain: str) -> Dict[str, dict]:
    """Known token symbols for a chain (EVM sidechains reuse the eth registry
    only for symbol names — pass an explicit contract for those)."""
    return TOKENS.get(chain, {})


def resolve_asset(asset: Optional[str], chain: str = "eth") -> Optional[dict]:
    """Turn an --asset value into an asset descriptor, or None for the native coin.

    Accepts 'eth'/'native'/None, a known symbol on that chain, or a raw contract
    address (0x… on EVM, base58 on Tron/Solana).
    """
    if asset is None or asset.lower() in ("eth", "native", "btc", "trx", "sol", "bnb", "matic"):
        return None

    a = asset.lower()
    known = TOKENS.get(chain, {})
    if a in known:
        return dict(known[a])

    # raw contract address
    if chain in ("tron", "sol"):
        if len(asset) >= 32 and not asset.startswith("0x"):
            return {"contract": asset, "symbol": asset[:6].upper(), "stable": False}
    elif a.startswith("0x") and len(a) == 42:
        return {"contract": a, "symbol": asset.upper()[:8], "stable": False}

    if chain == "btc":
        raise ValueError("Bitcoin has no tokens — omit --asset (or use --asset btc).")

    opts = ", ".join(known) or "none registered"
    raise ValueError(f"Unknown asset '{asset}' on {chain}. Known symbols: {opts}. "
                     f"You can also pass a contract address.")
