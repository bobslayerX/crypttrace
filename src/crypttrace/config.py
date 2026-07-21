"""Configuration and shared constants."""
import os
from pathlib import Path

# Data dir for cache + labels (created on first run)
DATA_DIR = Path(os.environ.get("CRYPTTRACE_HOME", Path.home() / ".crypttrace"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CACHE_DB = DATA_DIR / "cache.sqlite"

# Etherscan v2 API. One key works across all EVM chains via chainid param.
# Get a free key at https://etherscan.io/myapikey and export it:
#   export ETHERSCAN_API_KEY=xxxx
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "")
ETHERSCAN_BASE = "https://api.etherscan.io/v2/api"

# Supported EVM chains: name -> chainid
CHAINS = {
    "eth": 1,
    "bsc": 56,
    "polygon": 137,
    "arbitrum": 42161,
    "optimism": 10,
    "base": 8453,
}

WEI = 10 ** 18
