"""Spam and counterfeit tokens — what `tokens` hides by default.

Anyone can mint a token and send it to any address, so a wallet's token list
fills up with two kinds of junk:

- counterfeits: a token called "USDT" or "TON" that is not the real contract,
  sent so the balance looks bigger or to bait a victim into a fake swap;
- link bait: the name *is* the advert — "GRAM AT GRAMEVENT.ORG",
  "USDT - usdtunlock.com" — pointing at a phishing site.

Neither is worth money, and pricing them as the real thing would put a fake
million dollars into a case file. A token is judged by its contract against the
registry in assets.py, and by its name after undoing look-alike letters
(Cyrillic "с" for Latin "c" is how "usdtunloсk.соm" dodges a naive filter).
"""
import re
from typing import Optional

from crypttrace import assets

# Cyrillic and Greek letters that look like Latin ones, and ₮ for T
_LOOKALIKE = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "У": "Y", "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "Ο": "O", "α": "a", "Α": "A", "ε": "e", "Ε": "E", "ν": "v", "Τ": "T",
    "₮": "T",
})

_URL = re.compile(
    r"(https?://|www\.|t\.me/|\b[a-z0-9-]{2,}\.(com|org|net|io|xyz|click|app|site|top|info|"
    r"cc|me|gg|pro|live|vip|fun|online|link|claim|finance|exchange|network|tech|store|"
    r"shop|club|world|space|website|biz|us|co)\b)", re.I)
_HANDLE = re.compile(r"(^|\s)@[a-z0-9_]{4,}", re.I)
_BAIT = re.compile(r"\b(claim|unlock|airdrop|reward|voucher|visit|bonus|giveaway)\b", re.I)

# a token named after the chain's own coin is never that coin
_NATIVE = {"eth": "ETH", "tron": "TRX", "ton": "TON"}


def plain(text: str) -> str:
    """Text with look-alike letters replaced by the Latin ones they imitate."""
    return (text or "").translate(_LOOKALIKE)


def _ticker(symbol: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", plain(symbol).upper())


def verdict(chain: str, contract: str, symbol: str, name: str = "",
            flagged: bool = False) -> Optional[str]:
    """Why this token is junk, or None if nothing marks it as such."""
    contract = (contract or "").lower()
    known = {t["contract"].lower(): t for t in assets.tokens_for(chain).values()}
    if contract and contract in known:
        return None
    if flagged:
        return "flagged as scam by the indexer"
    text = plain(f"{symbol} {name}")
    link = _URL.search(text) or _HANDLE.search(text)
    if link:
        return f"link in its name ({link.group(0).strip()})"
    if _BAIT.search(text):
        return f"bait word in its name ({_BAIT.search(text).group(0)})"
    tick = _ticker(symbol)
    for t in known.values():
        if tick and tick == _ticker(t["symbol"]):
            return f"counterfeit {t['symbol']} (not the real contract)"
    if tick and tick == _NATIVE.get(chain):
        return f"counterfeit {_NATIVE[chain]} (the coin itself is not a token)"
    return None
