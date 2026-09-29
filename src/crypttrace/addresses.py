"""Address validation — checksums, not guesses.

Every address format in use carries a checksum precisely so that a mistyped or
corrupted address can be rejected rather than acted upon. A forensics tool has
no excuse for skipping that check: a single wrong character turns a claim about
one wallet into a claim about a different, usually non-existent one.

This validates without any network access or third-party library, so it works
on user input, on label files, and in tests.
"""
import hashlib
from typing import Optional, Tuple

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# ---------------------------------------------------------------- bech32

def _bech32_polymod(values) -> int:
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def check_bech32(addr: str, expected_hrp: str = "bc") -> Tuple[bool, str]:
    """Validate a bech32 / bech32m address (BIP-173 / BIP-350)."""
    if addr.lower() != addr and addr.upper() != addr:
        return False, "mixed case is not allowed in bech32"
    a = addr.lower()
    pos = a.rfind("1")
    if pos < 1 or pos + 7 > len(a) or len(a) > 90:
        return False, "malformed: bad separator position or length"
    hrp, data = a[:pos], a[pos + 1:]
    if expected_hrp and hrp != expected_hrp:
        return False, f"wrong network prefix '{hrp}' (expected '{expected_hrp}')"
    if any(c not in BECH32_CHARSET for c in data):
        return False, "contains characters not in the bech32 alphabet"
    const = _bech32_polymod(_hrp_expand(hrp) + [BECH32_CHARSET.find(c) for c in data])
    if const == 1:
        return True, "bech32 checksum valid"
    if const == 0x2bc830a3:
        return True, "bech32m checksum valid"
    return False, "checksum does not match — the address is mistyped or invented"


# ---------------------------------------------------------------- base58check

def _b58_decode(s: str) -> Optional[bytes]:
    n = 0
    for ch in s:
        idx = B58_ALPHABET.find(ch)
        if idx < 0:
            return None
        n = n * 58 + idx
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def check_base58check(addr: str, expect_prefix: Optional[bytes] = None) -> Tuple[bool, str]:
    """Validate a base58check address (legacy Bitcoin, Tron)."""
    raw = _b58_decode(addr)
    if raw is None:
        return False, "contains characters not in the base58 alphabet"
    if len(raw) < 5:
        return False, "too short to contain a checksum"
    payload, checksum = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        return False, "checksum does not match — the address is mistyped or invented"
    if expect_prefix and not payload.startswith(expect_prefix):
        return False, f"unexpected version byte {payload[:1].hex()}"
    return True, "base58check checksum valid"


# ---------------------------------------------------------------- per chain

def validate(address: str, chain: str) -> Tuple[bool, str]:
    """Is this a well-formed address for this chain? Checks the checksum where one exists."""
    a = (address or "").strip()
    if not a:
        return False, "empty address"

    if chain in ("eth", "bsc", "polygon", "arbitrum", "optimism", "base"):
        if not a.startswith("0x") or len(a) != 42:
            return False, "EVM addresses are 0x followed by 40 hex characters"
        if any(c not in "0123456789abcdefABCDEF" for c in a[2:]):
            return False, "contains non-hexadecimal characters"
        # EIP-55 mixed-case addresses carry a checksum; all-one-case ones don't
        body = a[2:]
        if body != body.lower() and body != body.upper():
            return (True, "valid hex (EIP-55 capitalisation present but unverified)")
        return True, "valid hex address (no checksum in this format)"

    if chain == "btc":
        if a.startswith(("bc1", "tb1")):
            return check_bech32(a, "bc" if a.startswith("bc1") else "tb")
        if a.startswith(("1", "3")):
            return check_base58check(a)
        return False, "not a recognised Bitcoin address format"

    if chain == "tron":
        if not a.startswith("T") or len(a) != 34:
            return False, "Tron addresses start with T and are 34 characters"
        return check_base58check(a, b"\x41")

    if chain == "sol":
        if not (32 <= len(a) <= 44):
            return False, "Solana addresses are 32–44 base58 characters"
        raw = _b58_decode(a)
        if raw is None:
            return False, "contains characters not in the base58 alphabet"
        if len(raw) != 32:
            return False, "does not decode to a 32-byte public key"
        return True, "valid 32-byte key (Solana addresses carry no checksum)"

    if chain == "ton":
        if ":" in a:
            return (True, "valid raw TON address (the raw form carries no checksum)") \
                if ton_parse(a) else (False, "raw TON addresses are workchain:64 hex characters")
        if len(a) != 48:
            return False, "TON addresses are 48 characters (EQ…/UQ…) or workchain:hex"
        return (True, "TON checksum valid") if ton_parse(a) else \
            (False, "checksum does not match — the address is mistyped or invented")

    return False, f"unknown chain '{chain}'"


# ---------------------------------------------------------------- TON
# One account, several spellings: raw "0:<64 hex>", and 48-character base64 forms
# that are bounceable ("EQ…") or not ("UQ…"), each ending in a CRC16 of the rest.
# Everything is compared in one canonical spelling: non-bounceable, url-safe —
# the form wallets show, and so the one a poisoner imitates.

def _crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else crc << 1
            crc &= 0xFFFF
    return crc


def ton_parse(address: str) -> Optional[Tuple[int, bytes]]:
    """(workchain, 32-byte account id) from any TON spelling, or None."""
    import base64
    import re
    a = (address or "").strip()
    m = re.fullmatch(r"(-?\d+):([0-9a-fA-F]{64})", a)
    if m:
        return int(m.group(1)), bytes.fromhex(m.group(2))
    if len(a) != 48:
        return None
    try:
        raw = base64.b64decode(a.replace("-", "+").replace("_", "/"), validate=True)
    except (ValueError, TypeError):
        return None
    if len(raw) != 36 or (raw[0] & 0x7F) not in (0x11, 0x51):
        return None
    if _crc16_xmodem(raw[:34]) != int.from_bytes(raw[34:], "big"):
        return None
    wc = raw[1] - 256 if raw[1] > 127 else raw[1]
    return wc, raw[2:34]


def ton_friendly(address: str, bounceable: bool = False) -> Optional[str]:
    """The canonical 48-character spelling (non-bounceable "UQ…" by default)."""
    import base64
    p = ton_parse(address)
    if not p:
        return None
    wc, account = p
    body = bytes([0x11 if bounceable else 0x51, wc & 0xFF]) + account
    return base64.urlsafe_b64encode(body + _crc16_xmodem(body).to_bytes(2, "big")).decode()


def looks_like_txid(value: str) -> bool:
    """64 hex characters — a transaction id, which people paste in by mistake."""
    v = (value or "").strip()
    return len(v) == 64 and all(c in "0123456789abcdefABCDEF" for c in v)
