"""The scorer, and a recall floor that fails CI if coverage regresses."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stripii import Scrubber, get_profile
from stripii.benchmark import (
    Document,
    Span,
    _matches,
    build_document,
    evaluate,
    load_corpus,
    load_i2b2,
    load_jsonl,
    render,
    write_corpus,
)
from stripii.types import Detection

CORPUS = Path(__file__).resolve().parents[1] / "benchmarks" / "synthetic.jsonl"


def det(entity, start, end, score=0.9):
    return Detection(entity, start, end, "x", "t", score)


# --------------------------------------------------------------------------
# match modes
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("prediction", "strict", "relaxed", "binary"),
    [
        (det("PERSON", 10, 20), True, True, True),      # exact, same type
        (det("PERSON", 10, 18), False, True, True),     # partial, same type
        (det("MRN", 10, 20), False, False, True),       # exact, wrong type
        (det("MRN", 12, 25), False, False, True),       # partial, wrong type
        (det("PERSON", 30, 40), False, False, False),   # no overlap
        (det("PERSON", 20, 30), False, False, False),   # abuts, does not overlap
    ],
)
def test_match_modes_differ_as_documented(prediction, strict, relaxed, binary):
    gold = Span(10, 20, "PERSON")
    assert _matches(gold, prediction, "strict") is strict
    assert _matches(gold, prediction, "relaxed") is relaxed
    assert _matches(gold, prediction, "binary") is binary


def test_an_unknown_mode_is_rejected():
    with pytest.raises(ValueError, match="mode must be"):
        evaluate(Scrubber(get_profile("health")), [], mode="fuzzy")


# --------------------------------------------------------------------------
# scoring arithmetic
# --------------------------------------------------------------------------

def test_a_perfect_run_scores_one():
    document = build_document("d", "Email: {{EMAIL:jane@example.com}}")
    report = evaluate(Scrubber(get_profile("health")), [document])
    assert report.overall.precision == 1.0
    assert report.overall.recall == 1.0
    assert report.overall.f1 == 1.0


def test_a_missed_span_is_a_false_negative():
    # An entity that is disabled cannot be found, so recall must be zero.
    policy = get_profile("secrets")  # keeps everything except credentials
    document = build_document("d", "Email: {{EMAIL:jane@example.com}}")
    report = evaluate(Scrubber(policy), [document])
    assert report.overall.recall == 0.0
    assert report.overall.false_negatives == 1
    assert report.missed and report.missed[0][2] == "jane@example.com"


def test_an_unannotated_detection_is_a_false_positive():
    document = Document("d", "Email: jane@example.com", spans=[])
    report = evaluate(Scrubber(get_profile("health")), [document])
    assert report.overall.false_positives >= 1
    assert report.overall.precision == 0.0


def test_one_prediction_cannot_satisfy_two_gold_spans():
    """Otherwise a single sloppy span would paper over a genuine miss."""
    document = Document(
        "d",
        "aaaa bbbb",
        spans=[Span(0, 4, "PERSON"), Span(5, 9, "PERSON")],
    )

    class OneBigSpan:
        name = entity = "PERSON"

        def detect(self, text):
            return [det("PERSON", 0, 9)]

    report = evaluate(Scrubber(get_profile("paranoid"), [OneBigSpan()]), document and [document])
    assert report.overall.true_positives == 1
    assert report.overall.false_negatives == 1


def test_scoring_uses_the_resolved_output_not_every_candidate():
    """A routing number is also a plausible account number; only one is emitted.

    Scoring the unresolved candidate set counts the discarded alternative as a
    false positive that never reaches the page.
    """
    document = build_document(
        "d",
        "Account Number: {{BANK_ACCOUNT:483920175}}\n"
        "Routing Number: {{US_ROUTING:021000021}}",
    )
    scrubber = Scrubber(get_profile("health"))
    candidates = [d for d in scrubber.scan(document.text) if d.score >= 0.4]
    # the routing number is claimed by two different detectors
    assert sum(1 for d in candidates if d.raw == "021000021") == 2

    report = evaluate(scrubber, [document], mode="binary")
    assert report.overall.false_positives == 0
    assert report.overall.recall == 1.0


# --------------------------------------------------------------------------
# corpus IO
# --------------------------------------------------------------------------

def test_build_document_offsets_are_exact():
    document = build_document("d", "Hi {{PERSON:Jane Smith}}, call {{PHONE:555-0142}}.")
    assert document.text == "Hi Jane Smith, call 555-0142."
    for span in document.spans:
        assert document.text[span.start:span.end] in ("Jane Smith", "555-0142")


def test_corpus_round_trips(tmp_path):
    documents = [build_document("a", "x {{EMAIL:a@example.com}}")]
    path = tmp_path / "c.jsonl"
    assert write_corpus(documents, path) == 1
    loaded = load_jsonl(path)
    assert loaded[0].text == documents[0].text
    assert loaded[0].spans == documents[0].spans


def test_blank_lines_in_a_corpus_are_skipped(tmp_path):
    path = tmp_path / "c.jsonl"
    path.write_text('{"id":"a","text":"hi","spans":[]}\n\n\n')
    assert len(load_jsonl(path)) == 1


def test_i2b2_xml_is_read_with_its_tag_vocabulary(tmp_path):
    """The real corpora need a DUA, so this exercises the reader on a stub."""
    (tmp_path / "rec.xml").write_text(
        '<deIdi2b2><TEXT>Jane Smith came in.</TEXT>'
        '<TAGS><NAME id="P0" start="0" end="10" text="Jane Smith" TYPE="PATIENT"/>'
        '<PROFESSION id="X1" start="11" end="15" text="came" TYPE="PROFESSION"/>'
        "</TAGS></deIdi2b2>"
    )
    documents = load_i2b2(tmp_path)
    assert len(documents) == 1
    # PATIENT maps to PERSON; PROFESSION has no counterpart and is dropped
    assert documents[0].spans == [Span(0, 10, "PERSON")]


def test_load_corpus_picks_the_reader_from_the_path(tmp_path):
    (tmp_path / "a.xml").write_text("<deIdi2b2><TEXT>x</TEXT><TAGS/></deIdi2b2>")
    assert len(load_corpus(tmp_path)) == 1


def test_render_produces_a_table():
    document = build_document("d", "Email: {{EMAIL:jane@example.com}}")
    text = render(evaluate(Scrubber(get_profile("health")), [document]), show_missed=3)
    assert "EMAIL" in text
    assert "MICRO" in text


# --------------------------------------------------------------------------
# the regression floor
# --------------------------------------------------------------------------

def test_the_shipped_corpus_is_present_and_annotated():
    documents = load_jsonl(CORPUS)
    assert len(documents) >= 60
    assert sum(len(d.spans) for d in documents) >= 500
    # the distractor documents carry no annotations at all
    assert any(not d.spans for d in documents)


@pytest.mark.parametrize(
    ("profile", "floor"), [("health", 0.88), ("paranoid", 0.88), ("tokenized", 0.88)]
)
def test_recall_does_not_regress(profile, floor):
    """A detector change that quietly loses coverage should fail here."""
    report = evaluate(Scrubber(get_profile(profile)), load_jsonl(CORPUS), mode="binary")
    assert report.overall.recall >= floor, (
        f"{profile} recall fell to {report.overall.recall:.3f}; "
        f"see benchmarks/README.md"
    )


def test_precision_does_not_regress():
    """The distractor documents exist to make this number mean something."""
    report = evaluate(Scrubber(get_profile("health")), load_jsonl(CORPUS), mode="binary")
    assert report.overall.precision >= 0.95


def test_report_serialises_to_json():
    report = evaluate(Scrubber(get_profile("health")), load_jsonl(CORPUS), mode="binary")
    payload = json.loads(json.dumps(report.to_dict()))
    assert payload["overall"]["recall"] > 0.8
    assert "PERSON" in payload["per_entity"]
