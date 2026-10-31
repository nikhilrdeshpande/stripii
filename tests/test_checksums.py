"""Checksum validators: a real identifier passes, a tampered one does not."""

from __future__ import annotations

import pytest

from stripii import checksums as ck

# Each case is (function, valid_example, invalid_example).
CASES = [
    (ck.luhn, "4111 1111 1111 1111", "4111 1111 1111 1112"),
    (ck.luhn, "5500005555555559", "5500005555555558"),
    (ck.aba_routing, "021000021", "021000022"),
    (ck.npi, "1234567893", "1234567890"),
    (ck.dea, "BX1234563", "BX1234564"),
    (ck.iban, "GB82 WEST 1234 5698 7654 32", "GB82 WEST 1234 5698 7654 33"),
    (ck.vin, "1HGCM82633A004352", "1HGCM82633A004353"),
    (ck.nhs_number, "943 476 5919", "943 476 5918"),
    (ck.gstin, "27AAPFU0939F1ZV", "27AAPFU0939F1ZX"),
    (ck.pan_india, "ABCPD1234E", "ABCZD1234E"),
]


@pytest.mark.parametrize(("func", "valid", "invalid"), CASES)
def test_checksum_accepts_valid_rejects_tampered(func, valid, invalid):
    assert func(valid) is True
    assert func(invalid) is False


@pytest.mark.parametrize(
    "value", ["", "1", "abc", "12345678901234567890123456789012345"]
)
def test_checksums_reject_junk_without_raising(value):
    for func, *_ in CASES:
        assert func(value) is False


def _verhoeff_with_check_digit(payload: str) -> str:
    """Generate a valid Verhoeff number so the validator is tested, not a guess."""
    inverse = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    check = 0
    for index, char in enumerate(reversed(payload)):
        check = ck._VERHOEFF_D[check][ck._VERHOEFF_P[(index + 1) % 8][ord(char) - 48]]
    return payload + str(inverse[check])


@pytest.mark.parametrize("payload", ["23661728306", "99988877766", "41234567890"])
def test_verhoeff_round_trip(payload):
    number = _verhoeff_with_check_digit(payload)
    assert ck.verhoeff(number) is True
    tampered = number[:-1] + str((int(number[-1]) + 1) % 10)
    assert ck.verhoeff(tampered) is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("123-45-6789", True),
        ("000-45-6789", False),   # area 000 is never issued
        ("666-45-6789", False),   # area 666 is never issued
        ("900-45-6789", False),   # 900-999 reserved
        ("123-00-6789", False),   # group 00 is never issued
        ("123-45-0000", False),   # serial 0000 is never issued
    ],
)
def test_ssn_structural_rules(value, expected):
    assert ck.ssn_structurally_valid(value) is expected


def test_vin_rejects_ambiguous_letters():
    # I, O and Q are excluded from VINs precisely because they look like 1 and 0.
    assert ck.vin("1HGCM8263IA004352") is False
