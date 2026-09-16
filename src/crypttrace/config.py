"""Configuration and shared constants."""
import os
from pathlib import Path

# Data dir for cache + labels (created on first run)
DATA_DIR = Path(os.environ.get("CRYPTTRACE_HOME", Path.home() / ".crypttrace"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

CACHE_DB = DATA_DIR / "cache.sqlite"

# Etherscan v2 API. One key works across all EVM chains via chainid param.
# Get a free key at https://etherscan.io/myapikey. Resolution order:
#   1. ETHERSCAN_API_KEY env
#   2. ~/.crypttrace/etherscan_api_key (plain key, or KEY=value)
#   3. .env in the current working directory
def _load_etherscan_key() -> str:
    env = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if env:
        return env
    candidates = [DATA_DIR / "etherscan_api_key", Path(".env")]
    for path in candidates:
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                name, _, value = line.partition("=")
                if name.strip() == "ETHERSCAN_API_KEY":
                    return value.strip().strip('"').strip("'")
            elif path.name == "etherscan_api_key":
                return line
    return ""


ETHERSCAN_API_KEY = _load_etherscan_key()
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
