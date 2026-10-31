"""FF1 format-preserving encryption, checked against the NIST sample vectors.

An FPE implementation that is subtly wrong still produces plausible-looking
output, so "it round-trips" is not evidence of correctness. These are the
published sample vectors from NIST SP 800-38G.
"""

from __future__ import annotations

import pytest

from stripii import fpe

from .conftest import requires_crypto

pytestmark = requires_crypto

KEY_128 = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3C")
KEY_192 = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F")
KEY_256 = bytes.fromhex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94")
TWEAK = bytes.fromhex("39383736353433323130")

# (label, key, tweak, plaintext, expected ciphertext)
NIST_VECTORS = [
    ("AES-128, no tweak", KEY_128, b"", "0123456789", "2433477484"),
    ("AES-128, with tweak", KEY_128, TWEAK, "0123456789", "6124200773"),
    ("AES-192, no tweak", KEY_192, b"", "0123456789", "2830668132"),
    ("AES-256, no tweak", KEY_256, b"", "0123456789", "6657667009"),
]


@pytest.mark.parametrize(
    ("label", "key", "tweak", "plaintext", "expected"), NIST_VECTORS
)
def test_matches_the_nist_sample_vectors(label, key, tweak, plaintext, expected):
    assert fpe.encrypt(key, plaintext, tweak=tweak) == expected


@pytest.mark.parametrize(
    ("label", "key", "tweak", "plaintext", "expected"), NIST_VECTORS
)
def test_decrypt_inverts_encrypt(label, key, tweak, plaintext, expected):
    assert fpe.decrypt(key, expected, tweak=tweak) == plaintext


def test_output_stays_in_the_input_alphabet_and_length():
    out = fpe.encrypt(KEY_128, "0123456789")
    assert len(out) == 10
    assert out.isdigit()


def test_alphanumeric_radix_round_trips():
    ciphered = fpe.encrypt(KEY_128, "ABCD123456", alphabet=fpe.ALNUM_UPPER)
    assert ciphered != "ABCD123456"
    assert fpe.decrypt(KEY_128, ciphered, alphabet=fpe.ALNUM_UPPER) == "ABCD123456"


def test_a_different_tweak_gives_a_different_ciphertext():
    assert fpe.encrypt(KEY_128, "0123456789") != fpe.encrypt(
        KEY_128, "0123456789", tweak=TWEAK
    )


def test_the_domain_minimum_is_enforced():
    """SP 800-38G requires radix**length >= 1,000,000."""
    with pytest.raises(fpe.FPEError, match="domain too small"):
        fpe.encrypt(KEY_128, "12345")


def test_characters_outside_the_alphabet_are_rejected():
    with pytest.raises(fpe.FPEError, match="outside the alphabet"):
        fpe.encrypt(KEY_128, "01234X6789")


def test_encryption_is_a_bijection_on_a_sample():
    """Distinct inputs must give distinct outputs, or the map is not reversible."""
    values = [f"{n:010d}" for n in range(300)]
    ciphered = [fpe.encrypt(KEY_128, v) for v in values]
    assert len(set(ciphered)) == len(values)
    assert all(fpe.decrypt(KEY_128, c) == v for c, v in zip(ciphered, values, strict=True))
