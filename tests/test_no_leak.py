"""The tests that matter: nothing identifying survives, nothing useful is lost.

Everything else in this suite checks a mechanism. These check the promise.
"""

from __future__ import annotations

import pytest

from .conftest import (
    FINANCE_IDENTIFIERS,
    FINANCE_MUST_KEEP,
    HEALTH_IDENTIFIERS,
    HEALTH_MUST_KEEP,
)


@pytest.mark.parametrize("identifier", HEALTH_IDENTIFIERS)
def test_health_profile_removes_every_identifier(scrub, health_text, identifier):
    scrubbed, _, _ = scrub(health_text, "health")
    assert identifier not in scrubbed


@pytest.mark.parametrize("content", HEALTH_MUST_KEEP)
def test_health_profile_preserves_clinical_content(scrub, health_text, content):
    scrubbed, _, _ = scrub(health_text, "health")
    assert content in scrubbed


@pytest.mark.parametrize("identifier", FINANCE_IDENTIFIERS)
def test_finance_profile_removes_every_identifier(scrub, finance_text, identifier):
    scrubbed, _, _ = scrub(finance_text, "finance")
    assert identifier not in scrubbed


@pytest.mark.parametrize("content", FINANCE_MUST_KEEP)
def test_finance_profile_preserves_transactions(scrub, finance_text, content):
    scrubbed, _, _ = scrub(finance_text, "finance")
    assert content in scrubbed


def test_paranoid_profile_removes_health_identifiers(scrub, health_text):
    scrubbed, _, _ = scrub(health_text, "paranoid")
    for identifier in HEALTH_IDENTIFIERS:
        assert identifier not in scrubbed


def test_hipaa_date_generalisation_keeps_the_year(scrub, health_text):
    scrubbed, _, _ = scrub(health_text, "health")
    # Safe Harbor permits the year, and only the year.
    assert "1934" in scrubbed
    assert "03/14/1934" not in scrubbed


def test_hipaa_ages_over_89_are_aggregated(scrub, health_text):
    scrubbed, _, _ = scrub(health_text, "health")
    assert "90+" in scrubbed
    assert "91 years old" not in scrubbed


def test_hipaa_zip_truncated_to_three_digits(scrub, health_text):
    scrubbed, _, _ = scrub(health_text, "health")
    assert "627**" in scrubbed


def test_restricted_zip_prefix_is_zeroed(scrub):
    # 036 is one of the 17 prefixes HHS requires be reported as 000.
    scrubbed, _, _ = scrub("Mailing address: Agawam, MA 03601", "health")
    assert "036" not in scrubbed
    assert "000**" in scrubbed
