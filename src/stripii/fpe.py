"""Format-preserving encryption (NIST SP 800-38G, algorithm FF1).

Placeholders are the right default for a language model, but they are wrong for
anything that validates what it receives. A test harness, a downstream parser or
a Luhn check all reject ``[[CREDIT_CARD_1]]`` while happily accepting another
valid-looking sixteen-digit number. FF1 gives you the second thing: a card
number encrypts to a *different card-shaped number*, reversibly, under a key.

FF1 is the conservative choice of the two modes in SP 800-38G. FF3 was weakened
by later cryptanalysis and reissued as FF3-1 with a shortened tweak; FF1 was not
affected.

This is a real cipher, not obfuscation, and it inherits the caveat the standard
itself makes: with a small domain the ciphertext space is small too, so an
attacker who can ask for many encryptions can build a codebook. Use it for
account-shaped data that has to stay account-shaped, not as a substitute for
redaction.
"""

from __future__ import annotations

import string

#: SP 800-38G requires radix**minlen >= 1,000,000 -- below that the domain is
#: too small for the construction to mean anything.
MIN_DOMAIN = 1_000_000
#: Number of Feistel rounds. Fixed by the specification.
ROUNDS = 10

DIGITS = string.digits
ALNUM_UPPER = string.digits + string.ascii_uppercase


class FPEError(ValueError):
    """Raised when an input cannot be enciphered in a format-preserving way."""


def _aes_ecb_encrypt_block(key: bytes, block: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except (KeyboardInterrupt, SystemExit):  # pragma: no cover
        raise
    except BaseException as exc:  # a broken build raises from its Rust bindings
        raise FPEError(
            "format-preserving encryption needs a working 'cryptography' install "
            f"({type(exc).__name__}: {exc}). Install it with: pip install 'stripii[crypto]'"
        ) from exc
    # ECB on a single block is exactly what SP 800-38G specifies here: it is
    # the block-cipher call inside CBC-MAC, not a mode used to encrypt data.
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _prf(key: bytes, data: bytes) -> bytes:
    """CBC-MAC over AES with a zero IV, as SP 800-38G defines PRF."""
    if len(data) % 16:
        raise FPEError("PRF input must be a whole number of blocks")
    state = b"\x00" * 16
    for offset in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(state, data[offset:offset + 16], strict=True))
        state = _aes_ecb_encrypt_block(key, block)
    return state


def _num(numerals: str, alphabet: str) -> int:
    radix = len(alphabet)
    value = 0
    for char in numerals:
        value = value * radix + alphabet.index(char)
    return value


def _str(value: int, length: int, alphabet: str) -> str:
    radix = len(alphabet)
    out = []
    for _ in range(length):
        value, remainder = divmod(value, radix)
        out.append(alphabet[remainder])
    return "".join(reversed(out))


def _check(text: str, alphabet: str) -> None:
    radix = len(alphabet)
    n = len(text)
    if any(c not in alphabet for c in text):
        raise FPEError("input contains characters outside the alphabet")
    if radix**n < MIN_DOMAIN:
        raise FPEError(
            f"domain too small: radix**length must be at least {MIN_DOMAIN:,} "
            f"(SP 800-38G); got {radix}**{n}"
        )


def _feistel(key: bytes, text: str, tweak: bytes, alphabet: str, *, decrypt: bool) -> str:
    """FF1 encryption (SP 800-38G algorithm 7) and its inverse (algorithm 8)."""
    _check(text, alphabet)
    radix = len(alphabet)
    n = len(text)
    u = n // 2
    v = n - u
    a, b = text[:u], text[u:]

    # b_len = ceil(ceil(v * log2(radix)) / 8); d = 4 * ceil(b_len / 4) + 4
    b_len = ((radix**v - 1).bit_length() + 7) // 8
    d = 4 * ((b_len + 3) // 4) + 4

    t = len(tweak)
    p = (
        bytes([1, 2, 1])
        + radix.to_bytes(3, "big")
        + bytes([10, u % 256])
        + n.to_bytes(4, "big")
        + t.to_bytes(4, "big")
    )
    pad = (-t - b_len - 1) % 16

    def round_value(i: int, half: str) -> int:
        q = tweak + b"\x00" * pad + bytes([i]) + _num(half, alphabet).to_bytes(b_len, "big")
        r = _prf(key, p + q)
        stream = bytearray(r)
        counter = 1
        while len(stream) < d:
            xored = bytes(x ^ y for x, y in zip(r, counter.to_bytes(16, "big"), strict=True))
            stream += _aes_ecb_encrypt_block(key, xored)
            counter += 1
        return int.from_bytes(bytes(stream[:d]), "big")

    if decrypt:
        for i in range(ROUNDS - 1, -1, -1):
            m = u if i % 2 == 0 else v
            y = round_value(i, a)
            c = (_num(b, alphabet) - y) % radix**m
            b = a
            a = _str(c, m, alphabet)
    else:
        for i in range(ROUNDS):
            m = u if i % 2 == 0 else v
            y = round_value(i, b)
            c = (_num(a, alphabet) + y) % radix**m
            a = b
            b = _str(c, m, alphabet)
    return a + b


def encrypt(key: bytes, text: str, *, tweak: bytes = b"", alphabet: str = DIGITS) -> str:
    """Encipher ``text`` into a different string of the same length and alphabet."""
    return _feistel(key, text, tweak, alphabet, decrypt=False)


def decrypt(key: bytes, text: str, *, tweak: bytes = b"", alphabet: str = DIGITS) -> str:
    """Invert :func:`encrypt` under the same key and tweak."""
    return _feistel(key, text, tweak, alphabet, decrypt=True)
