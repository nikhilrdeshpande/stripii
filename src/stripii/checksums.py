"""Checksum validators.

Most identifier formats that matter for privacy carry a check digit. Validating
it is what separates "nine digits" from "an actual routing number", and it is
the cheapest way to keep false positives out of a redaction tool that people
are supposed to trust.
"""

from __future__ import annotations

import re

_DIGITS = re.compile(r"\D")


def digits_only(value: str) -> str:
    return _DIGITS.sub("", value)


def luhn(number: str) -> bool:
    """ISO/IEC 7812 mod-10. Used by payment cards and (with a prefix) NPIs."""
    digits = digits_only(number)
    if len(digits) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = ord(char) - 48
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def aba_routing(number: str) -> bool:
    """ABA/RTN mod-10 with 3-7-1 weights (Federal Reserve routing symbol)."""
    digits = digits_only(number)
    if len(digits) != 9:
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    total = sum(w * (ord(c) - 48) for w, c in zip(weights, digits, strict=True))
    return total % 10 == 0


def npi(number: str) -> bool:
    """CMS National Provider Identifier: Luhn over '80840' + the first 9 digits."""
    digits = digits_only(number)
    if len(digits) != 10:
        return False
    return luhn("80840" + digits)


def dea(value: str) -> bool:
    """DEA registration number: 2 letters + 7 digits, mod-10 check digit.

    check = (d1 + d3 + d5) + 2 * (d2 + d4 + d6)  ->  last digit of the sum.
    """
    value = value.replace(" ", "").replace("-", "").upper()
    if len(value) != 9 or not value[:2].isalpha() or not value[2:].isdigit():
        return False
    d = [ord(c) - 48 for c in value[2:]]
    total = (d[0] + d[2] + d[4]) + 2 * (d[1] + d[3] + d[5])
    return total % 10 == d[6]


#: IBAN length per country (SWIFT IBAN registry). The mod-97 check alone passes
#: about one random alphanumeric string in 97, so without the length check an
#: Indian invoice number -- India has no IBANs at all -- validated as one.
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16,
    "BG": 22, "BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22,
    "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20,
    "EG": 29, "ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22,
    "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30,
    "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21,
    "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
    "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33,
    "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27,
    "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29,
    "VA": 22, "VG": 24, "XK": 20,
}


def iban(value: str) -> bool:
    """ISO 13616 / ISO 7064 mod-97-10, plus the country's registered length."""
    compact = re.sub(r"[\s-]", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", compact):
        return False
    if IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(
        str(ord(c) - 55) if c.isalpha() else c for c in rearranged
    )
    return int(numeric) % 97 == 1


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff(number: str) -> bool:
    """Verhoeff checksum, used by India's Aadhaar."""
    digits = digits_only(number)
    if not digits:
        return False
    check = 0
    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][ord(char) - 48]]
    return check == 0


_VIN_TRANSLIT = {
    **{str(i): i for i in range(10)},
    "A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6, "G": 7, "H": 8,
    "J": 1, "K": 2, "L": 3, "M": 4, "N": 5, "P": 7, "R": 9,
    "S": 2, "T": 3, "U": 4, "V": 5, "W": 6, "X": 7, "Y": 8, "Z": 9,
}
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin(value: str) -> bool:
    """North American VIN check digit (position 9)."""
    value = value.strip().upper()
    if len(value) != 17 or any(c in "IOQ" for c in value):
        return False
    try:
        total = sum(
            _VIN_TRANSLIT[c] * w for c, w in zip(value, _VIN_WEIGHTS, strict=True)
        )
    except KeyError:
        return False
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return value[8] == expected


def ssn_structurally_valid(value: str) -> bool:
    """Reject SSNs the SSA never issues (area 000/666/900-999, group 00, serial 0000)."""
    digits = digits_only(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


def gstin(value: str) -> bool:
    """India GSTIN: 15 chars, mod-36 check character over the first 14."""
    value = value.strip().upper()
    if not re.fullmatch(r"\d{2}[A-Z]{5}\d{4}[A-Z][A-Z0-9]Z[A-Z0-9]", value):
        return False
    alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    total = 0
    for index, char in enumerate(value[:14]):
        factor = 2 if index % 2 else 1
        product = alphabet.index(char) * factor
        total += product // 36 + product % 36
    check = (36 - total % 36) % 36
    return alphabet[check] == value[14]


def nhs_number(value: str) -> bool:
    """UK NHS number: 10 digits, mod-11 with weights 10..2."""
    digits = digits_only(value)
    if len(digits) != 10:
        return False
    total = sum((10 - i) * (ord(c) - 48) for i, c in enumerate(digits[:9]))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    if check == 10:
        return False
    return check == ord(digits[9]) - 48


def pan_india(value: str) -> bool:
    """India PAN has no check digit; validate the structural grammar instead.

    Positions 1-3 are a series, position 4 is the holder type and position 5 is
    the first letter of the surname (or entity name).
    """
    value = value.strip().upper()
    return bool(re.fullmatch(r"[A-Z]{3}[ABCFGHLJPTE][A-Z]\d{4}[A-Z]", value))


# --------------------------------------------------------------------------
# check-digit generation
#
# Format-preserving encryption keeps the shape of a value but not its check
# digit: enciphering all sixteen digits of a card yields sixteen digits that
# fail Luhn, which defeats the point of using FPE instead of a placeholder.
# Enciphering the body and recomputing the check digit keeps the result valid,
# and stays reversible -- the body is bijective under FF1, and the check digit
# is a function of the body.
# --------------------------------------------------------------------------

def luhn_check_digit(body: str) -> str:
    """The digit that makes ``body + digit`` pass Luhn."""
    for candidate in range(10):
        if luhn(body + str(candidate)):
            return str(candidate)
    raise AssertionError("unreachable: one of ten digits always satisfies Luhn")


def aba_check_digit(body: str) -> str:
    """The ninth digit that makes an eight-digit routing body validate."""
    digits = digits_only(body)
    if len(digits) != 8:
        raise ValueError("ABA routing body must be 8 digits")
    weights = (3, 7, 1, 3, 7, 1, 3, 7)
    total = sum(w * (ord(c) - 48) for w, c in zip(weights, digits, strict=True))
    return str((10 - total % 10) % 10)


def verhoeff_check_digit(body: str) -> str:
    """The digit that makes ``body + digit`` pass Verhoeff."""
    inverse = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)
    check = 0
    for index, char in enumerate(reversed(digits_only(body))):
        check = _VERHOEFF_D[check][_VERHOEFF_P[(index + 1) % 8][ord(char) - 48]]
    return str(inverse[check])
