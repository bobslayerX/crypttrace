"""Configuration and shared constants."""
import os
import sys
from pathlib import Path


def env(name: str, default: str = "") -> str:
    """An environment variable — falling back, on Windows, to the user environment, so a key
    saved with [Environment]::SetEnvironmentVariable(..., "User") works in an already-open shell."""
    value = os.environ.get(name)
    if not value and sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as reg:
                value = winreg.QueryValueEx(reg, name)[0]
        except OSError:
            value = None
    return (value or default).strip()

# Data dir for cache + labels (created on first run)
DATA_DIR = Path(os.environ.get("CRYPTTRACE_HOME", Path.home() / ".crypttrace"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CACHE_DB = DATA_DIR / "cache.sqlite"

# Etherscan v2 API. One key works across all EVM chains via chainid param.
# Get a free key at https://etherscan.io/myapikey and export it:
#   export ETHERSCAN_API_KEY=xxxx
ETHERSCAN_API_KEY = env("ETHERSCAN_API_KEY")
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
