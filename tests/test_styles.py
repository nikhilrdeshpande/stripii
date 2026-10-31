"""Surrogate and format-preserving-encryption replacement styles."""

from __future__ import annotations

import datetime as dt

import pytest

from stripii import Action, Policy, Scrubber
from stripii.checksums import (
    aba_routing,
    luhn,
    ssn_structurally_valid,
    verhoeff,
)
from stripii.surrogates import EMAIL_DOMAINS, Surrogator

from .conftest import requires_crypto

KEY = b"k" * 32


@pytest.fixture
def surrogator():
    return Surrogator(KEY)


def _policy(action: Action) -> Policy:
    return Policy(name="t", default_action=action, min_score=0.4)


# --------------------------------------------------------------------------
# surrogates
# --------------------------------------------------------------------------

def test_surrogates_are_deterministic(surrogator):
    first = surrogator.surrogate("PERSON", "Margaret Whitfield")
    assert first == surrogator.surrogate("PERSON", "Margaret Whitfield")
    assert first == surrogator.surrogate("PERSON", "margaret   whitfield")


def test_a_different_key_gives_a_different_surrogate(surrogator):
    other = Surrogator(b"j" * 32)
    assert surrogator.surrogate("PERSON", "Margaret Whitfield") != other.surrogate(
        "PERSON", "Margaret Whitfield"
    )


def test_different_people_get_different_surrogates(surrogator):
    assert surrogator.surrogate("PERSON", "Margaret Whitfield") != surrogator.surrogate(
        "PERSON", "Robert Chen"
    )


def test_a_surrogate_name_keeps_the_token_count(surrogator):
    assert len(surrogator.surrogate("PERSON", "Bob").split()) == 1
    assert len(surrogator.surrogate("PERSON", "Robert Chen").split()) == 2
    assert len(surrogator.surrogate("PERSON", "Margaret Ellen Whitfield").split()) == 3


# -- the safety property: surrogates come from reserved ranges --------------

def test_surrogate_emails_use_a_reserved_domain(surrogator):
    """RFC 2606 reserves example.*, so a surrogate can never be someone's address."""
    for value in ["a@hospital.org", "b@bank.co.uk", "c@clinic.net"]:
        assert surrogator.surrogate("EMAIL", value).split("@")[1] in EMAIL_DOMAINS


def test_surrogate_phones_use_the_fictional_555_block(surrogator):
    number = surrogator.surrogate("PHONE", "(217) 555-0142")
    assert "555-01" in number


def test_surrogate_ssns_are_from_a_never_issued_range(surrogator):
    """Area 900-999 has never been issued, so this cannot be a real SSN."""
    surrogate = surrogator.surrogate("SSN", "412-88-9031")
    assert surrogate.startswith("9")
    assert not ssn_structurally_valid(surrogate)


def test_surrogate_cards_are_luhn_valid_test_bin(surrogator):
    """Valid enough to pass a format check, but in a known test range."""
    surrogate = surrogator.surrogate("CREDIT_CARD", "4532 0151 1283 0366")
    assert luhn(surrogate)
    assert surrogate.startswith("4111")


def test_date_shifting_preserves_intervals(surrogator):
    """A constant offset is what makes shifted dates still clinically useful."""
    first = dt.date.fromisoformat(surrogator.surrogate("DATE", "2025-01-05"))
    second = dt.date.fromisoformat(surrogator.surrogate("DATE", "2025-03-11"))
    assert (second - first).days == (dt.date(2025, 3, 11) - dt.date(2025, 1, 5)).days


def test_date_surrogate_keeps_the_original_format(surrogator):
    assert surrogator.surrogate("DATE", "03/14/1934").count("/") == 2
    assert surrogator.surrogate("DATE", "2025-08-02").count("-") == 2


def test_an_unparseable_date_has_no_surrogate(surrogator):
    assert surrogator.surrogate("DATE", "sometime last spring") is None


def test_default_generator_keeps_the_shape(surrogator):
    surrogate = surrogator.surrogate("MRN", "AB-4471982")
    assert surrogate != "AB-4471982"
    assert len(surrogate) == len("AB-4471982")
    assert surrogate[2] == "-"
    assert surrogate[:2].isalpha() and surrogate[3:].isdigit()


# -- through the engine ----------------------------------------------------

def test_surrogate_style_produces_natural_text():
    result, _ = Scrubber(_policy(Action.SURROGATE), hash_key=KEY).scrub(
        "Patient Name: Margaret Whitfield"
    )
    assert "[[" not in result.text
    assert "Margaret Whitfield" not in result.text


def test_surrogate_output_is_reversible_through_the_vault():
    text = "Patient Name: Margaret Whitfield\nEmail: m.w@hospital.org"
    result, vault = Scrubber(_policy(Action.SURROGATE), hash_key=KEY).scrub(text)
    assert Scrubber.restore(result.text, vault) == text


def test_the_same_person_gets_one_surrogate_throughout():
    result, _ = Scrubber(_policy(Action.SURROGATE), hash_key=KEY).scrub(
        "Patient Name: Margaret Whitfield\nDr. Chen saw Margaret Whitfield again."
    )
    names = [r.text for r in result.replacements if r.detection.entity == "PERSON"]
    assert names.count(names[0]) == 2


# --------------------------------------------------------------------------
# format-preserving encryption
# --------------------------------------------------------------------------

@requires_crypto
def test_encrypt_keeps_length_and_separators():
    result, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub("SSN: 412-88-9031")
    out = result.text.removeprefix("SSN: ")
    assert out != "412-88-9031"
    assert len(out) == len("412-88-9031")
    assert out[3] == "-" and out[6] == "-"
    assert out.replace("-", "").isdigit()


@requires_crypto
def test_encrypted_cards_stay_luhn_valid():
    """FPE preserves the digit count but not the check digit, unless you fix it."""
    result, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(
        "card 4111 1111 1111 1111"
    )
    card = result.text.removeprefix("card ")
    assert card != "4111 1111 1111 1111"
    assert luhn(card)


@requires_crypto
def test_encrypted_routing_numbers_stay_aba_valid():
    result, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(
        "Routing Number: 021000021"
    )
    routing = result.text.removeprefix("Routing Number: ")
    assert routing != "021000021"
    assert aba_routing(routing)


@requires_crypto
def test_encrypted_aadhaar_stays_verhoeff_valid():
    result, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(
        "Aadhaar 2366 1728 3069"
    )
    number = result.text.removeprefix("Aadhaar ")
    assert number != "2366 1728 3069"
    assert verhoeff(number)


@requires_crypto
def test_encryption_is_stable_under_the_same_key():
    text = "SSN: 412-88-9031"
    first, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(text)
    second, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(text)
    third, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=b"j" * 32).scrub(text)
    assert first.text == second.text != third.text


@requires_crypto
def test_a_value_too_short_to_encipher_falls_back_to_a_placeholder():
    """SP 800-38G needs radix**length >= 1,000,000; CVV 837 is far below it."""
    result, _ = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub("CVV 837")
    assert "[[CVV_1]]" in result.text


@requires_crypto
def test_encrypted_output_is_reversible_through_the_vault():
    text = "SSN: 412-88-9031"
    result, vault = Scrubber(_policy(Action.ENCRYPT), hash_key=KEY).scrub(text)
    assert Scrubber.restore(result.text, vault) == text
