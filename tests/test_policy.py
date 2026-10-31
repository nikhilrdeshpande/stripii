"""Profiles, overrides and JSON policy files."""

from __future__ import annotations

import json

import pytest

from stripii import Action, Policy, Scrubber, get_profile
from stripii.policy import PROFILES, RESTRICTED_ZIP_PREFIXES


@pytest.mark.parametrize("name", sorted(PROFILES))
def test_every_profile_is_usable_and_documented(name):
    policy = get_profile(name)
    assert policy.description
    result, _ = Scrubber(policy).scrub("Patient Name: Jane Smith, SSN 412-88-9031")
    assert isinstance(result.text, str)


def test_unknown_profile_names_the_alternatives():
    with pytest.raises(KeyError, match="health"):
        get_profile("nope")


def test_profile_lookup_is_case_insensitive():
    assert get_profile("HEALTH").name == "health"


def test_health_and_finance_disagree_about_dates():
    """The whole point of having profiles."""
    assert get_profile("health").action_for("DATE") is Action.GENERALIZE
    assert get_profile("finance").action_for("DATE") is Action.KEEP


def test_secrets_profile_ignores_everything_but_credentials():
    result, _ = Scrubber(get_profile("secrets")).scrub(
        "Patient Name: Jane Smith\nAWS_KEY=AKIAIOSFODNN7EXAMPLE"
    )
    assert "Jane Smith" in result.text
    assert "AKIAIOSFODNN7EXAMPLE" not in result.text


def test_disabled_entities_are_kept():
    policy = Policy(name="t", default_action=Action.REDACT, disabled=frozenset({"EMAIL"}))
    assert policy.action_for("EMAIL") is Action.KEEP
    result, _ = Scrubber(policy).scrub("mail jane@example.com")
    assert "jane@example.com" in result.text


def test_policy_round_trips_through_a_dict():
    original = get_profile("health")
    rebuilt = Policy.from_dict(original.to_dict())
    assert rebuilt.actions == original.actions
    assert rebuilt.default_action == original.default_action
    assert rebuilt.min_score == original.min_score


def test_policy_file_extends_a_profile(tmp_path):
    path = tmp_path / "clinic.json"
    path.write_text(json.dumps({
        "name": "clinic",
        "extends": "health",
        "actions": {"DATE": "keep"},
        "min_score": 0.35,
    }))
    policy = Policy.load(path)
    assert policy.name == "clinic"
    assert policy.action_for("DATE") is Action.KEEP
    # inherited from the health profile rather than reset to the default
    assert policy.action_for("AGE_OVER_89") is Action.GENERALIZE
    assert policy.min_score == 0.35


def test_policy_file_rejects_an_unknown_action(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"name": "bad", "actions": {"EMAIL": "obliterate"}}))
    with pytest.raises(ValueError, match="obliterate"):
        Policy.load(path)


def test_restricted_zip_prefixes_match_the_hhs_list():
    # 17 three-digit prefixes with populations at or below 20,000.
    assert len(RESTRICTED_ZIP_PREFIXES) == 17
    assert "036" in RESTRICTED_ZIP_PREFIXES
    assert "941" not in RESTRICTED_ZIP_PREFIXES
