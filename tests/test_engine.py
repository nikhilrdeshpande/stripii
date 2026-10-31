"""Overlap resolution, the five actions, and reversibility."""

from __future__ import annotations

import pytest

from stripii import Action, Detection, Policy, Scrubber, get_profile, resolve_overlaps


def det(entity, start, end, score, raw="x"):
    return Detection(entity=entity, start=start, end=end, raw=raw, detector="t", score=score)


def test_overlap_resolution_prefers_confidence_then_length():
    chosen = resolve_overlaps([
        det("A", 0, 10, 0.5),
        det("B", 2, 6, 0.9),
        det("C", 20, 30, 0.4),
    ])
    assert [d.entity for d in chosen] == ["B", "C"]


def test_overlap_resolution_prefers_longer_at_equal_confidence():
    chosen = resolve_overlaps([det("SHORT", 0, 4, 0.7), det("LONG", 0, 9, 0.7)])
    assert [d.entity for d in chosen] == ["LONG"]


def test_non_overlapping_detections_all_survive():
    chosen = resolve_overlaps([det("A", 0, 3, 0.5), det("B", 3, 6, 0.5)])
    assert len(chosen) == 2


def test_email_inside_a_url_still_gets_redacted():
    """URL is kept by the default profile; the email inside it must not be."""
    scrubbed, _, _ = _scrub("see https://x.example.com/?to=jane@example.com now")
    assert "jane@example.com" not in scrubbed
    assert "https://x.example.com" in scrubbed


def _scrub(text, profile="default"):
    result, vault = Scrubber(get_profile(profile)).scrub(text)
    return result.text, result, vault


# --------------------------------------------------------------------------
# actions
# --------------------------------------------------------------------------

def _policy(**actions):
    return Policy(name="t", default_action=Action.KEEP, actions=actions, min_score=0.3)


def test_mask_keeps_the_last_four_and_the_separators():
    scrubber = Scrubber(_policy(CREDIT_CARD=Action.MASK))
    result, _ = scrubber.scrub("card 4111 1111 1111 1111")
    assert result.text == "card **** **** **** 1111"


def test_mask_stars_everything_when_the_value_is_short():
    scrubber = Scrubber(_policy(CVV=Action.MASK))
    result, _ = scrubber.scrub("CVV 837")
    assert result.text == "CVV ***"


def test_hash_is_stable_within_a_run_and_keyed():
    scrubber = Scrubber(_policy(EMAIL=Action.HASH), hash_key=b"k" * 32)
    result, _ = scrubber.scrub("a@example.com and a@example.com and b@example.com")
    first, second, third = [r.text for r in result.replacements]
    assert first == second != third
    other = Scrubber(_policy(EMAIL=Action.HASH), hash_key=b"j" * 32)
    assert other.scrub("a@example.com")[0].replacements[0].text != first


def test_keep_leaves_text_untouched():
    result, _ = Scrubber(_policy()).scrub("SSN: 412-88-9031")
    assert result.text == "SSN: 412-88-9031"
    assert result.total == 0


def test_generalize_falls_back_to_redaction_when_it_cannot_coarsen():
    """A date with no year has nothing to generalise to, so it is redacted."""
    scrubber = Scrubber(_policy(DATE=Action.GENERALIZE))
    result, _ = scrubber.scrub("seen on 03/14/34 for review")
    assert "03/14/34" not in result.text


def test_below_min_score_is_reported_but_not_replaced():
    policy = Policy(name="t", default_action=Action.REDACT, min_score=0.99)
    result, _ = Scrubber(policy).scrub("Patient Name: Margaret Whitfield")
    assert result.total == 0
    assert any(d.entity == "PERSON" for d in result.skipped)


# --------------------------------------------------------------------------
# placeholders and reversibility
# --------------------------------------------------------------------------

def test_the_same_person_gets_the_same_placeholder_everywhere():
    scrubbed, _, _ = _scrub(
        "Patient Name: Margaret Whitfield\nDr. Chen saw Margaret Whitfield again."
    )
    assert scrubbed.count("[[PERSON_1]]") == 2


def test_different_people_get_different_placeholders():
    scrubbed, _, _ = _scrub("Patient Name: Margaret Whitfield\nAttending: Dr. Robert Chen")
    assert "[[PERSON_1]]" in scrubbed
    assert "[[PERSON_2]]" in scrubbed


def test_restore_returns_the_original_values():
    text = "Contact jane.doe@example.com or call (415) 555-0132."
    scrubbed, _, vault = _scrub(text)
    assert Scrubber.restore(scrubbed, vault) == text


def test_restore_is_not_confused_by_placeholder_prefixes():
    """[[PERSON_1]] must not be substituted inside [[PERSON_11]]."""
    from stripii import Vault

    vault = Vault()
    template = "[[{entity}_{n}]]"
    for index in range(1, 12):
        vault.placeholder_for("PERSON", f"Person Number {index}", template)
    assert Scrubber.restore("[[PERSON_11]]", vault) == "Person Number 11"


def test_masked_values_are_not_written_to_the_vault():
    """'****1111' is not unique, so restoring it would corrupt the text."""
    _, _, vault = _scrub("card 4111 1111 1111 1111", "finance")
    assert not any("*" in key for key in vault.mapping)


def test_generalized_values_are_not_written_to_the_vault():
    _, _, vault = _scrub("Date of Birth: 03/14/1934", "health")
    assert "1934" not in vault.mapping


def test_restore_after_generalization_does_not_rewrite_unrelated_years():
    _, _, vault = _scrub("Admitted 2025-01-05 and discharged 2025-03-11", "health")
    assert Scrubber.restore("Both events happened in 2025.", vault) == (
        "Both events happened in 2025."
    )


def test_a_shared_vault_keeps_placeholders_consistent_across_documents():
    from stripii import Vault

    scrubber = Scrubber(get_profile("default"))
    vault = Vault()
    first, _ = scrubber.scrub("Patient Name: Margaret Whitfield", vault)
    second, _ = scrubber.scrub("Follow-up for Margaret Whitfield", vault)
    assert "[[PERSON_1]]" in first.text
    assert "[[PERSON_1]]" in second.text


def test_scrub_does_not_mutate_the_input():
    text = "SSN: 412-88-9031"
    Scrubber(get_profile("default")).scrub(text)
    assert text == "SSN: 412-88-9031"


@pytest.mark.parametrize("text", ["", "   ", "\n\n", "no personal data at all"])
def test_harmless_input_is_returned_unchanged(text):
    scrubbed, result, _ = _scrub(text)
    assert scrubbed == text
    assert result.total == 0


def test_counts_and_total_agree():
    _, result, _ = _scrub("Email a@b.com and c@d.com, call (415) 555-0132")
    assert sum(result.counts.values()) == result.total


def test_custom_placeholder_template():
    policy = Policy(name="t", default_action=Action.REDACT, placeholder="<{entity}-{n}>")
    result, _ = Scrubber(policy).scrub("Email: jane@example.com")
    assert "<EMAIL-1>" in result.text


def test_apostrophe_and_hyphen_names_are_matched_whole():
    for name in ["Sean O'Brien", "Anne-Marie Dupont", "D'Angelo Russell"]:
        scrubbed, _, _ = _scrub(f"Patient Name: {name}")
        assert name not in scrubbed
        assert scrubbed == "Patient Name: [[PERSON_1]]"


# --------------------------------------------------------------------------
# context hints (for values scrubbed in isolation)
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("hint", "value", "entity"),
    [
        ("account_number", "483920175", "BANK_ACCOUNT"),
        ("routing_number", "021000021", "US_ROUTING"),
        ("medical_record_number", "4471982", "MRN"),
        ("member number", "XHP449182736", "HEALTH_PLAN_ID"),
        ("patient_name", "Margaret Whitfield", "PERSON"),
        ("ssn", "412889031", "SSN"),
    ],
)
def test_a_context_hint_identifies_a_bare_value(hint, value, entity):
    """A CSV cell has no context of its own; its column header is the context."""
    scrubber = Scrubber(get_profile("paranoid"))
    result, _ = scrubber.scrub(value, context_hint=hint)
    assert result.total == 1
    assert result.replacements[0].detection.entity == entity


def test_the_same_value_is_left_alone_without_a_hint():
    scrubber = Scrubber(get_profile("finance"))
    assert scrubber.scrub("483920175")[0].total == 0


def test_the_hint_never_appears_in_the_output():
    scrubber = Scrubber(get_profile("paranoid"))
    result, _ = scrubber.scrub("142", context_hint="glucose_mg_dl")
    assert result.text == "142"


def test_hint_offsets_map_back_to_the_original_text():
    scrubber = Scrubber(get_profile("paranoid"))
    result, _ = scrubber.scrub("acct 483920175 ok", context_hint="account_number")
    assert result.text.startswith("acct ")
    assert result.text.endswith(" ok")
    detection = result.replacements[0].detection
    assert "acct 483920175 ok"[detection.start:detection.end] == detection.raw


def test_underscores_in_a_field_name_are_read_as_word_breaks():
    scrubber = Scrubber(get_profile("paranoid"))
    assert scrubber.scrub("4471982", context_hint="medical_record_number")[0].total == 1
    assert scrubber.scrub("4471982", context_hint="medicalrecordnumber")[0].total == 0


@pytest.mark.parametrize("hint", [None, "", "   ", "___"])
def test_an_empty_hint_is_the_same_as_no_hint(hint):
    scrubber = Scrubber(get_profile("finance"))
    assert scrubber.scrub("483920175", context_hint=hint)[0].total == 0


def test_the_english_word_list_is_bundled_and_lower_case():
    """Propagation must behave the same on every OS, not only where a system list exists."""
    from stripii.engine import _BUNDLED_WORDS, _english_words

    assert _BUNDLED_WORDS.exists()
    words = _english_words()
    assert len(words) > 100_000
    assert {"rose", "mark", "test", "case"} <= words
    assert all(w.islower() for w in words)
